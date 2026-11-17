/**
 * HPKE - Hybrid Public Key Encryption  -  RFC 9180
 *
 * The missing category. Everything else in this library either agrees on a
 * key (ECDH, X25519) or signs (ECDSA, EdDSA, Schnorr); RSA-OAEP is the only
 * thing here that actually ENCRYPTS to a public key, and it is limited to a
 * few hundred bytes and carries a 256-byte ciphertext.
 *
 * HPKE encrypts arbitrary data to a public key by combining three pieces this
 * library already has: an ephemeral key agreement, a KDF, and an AEAD. The
 * sender generates a throwaway key pair, agrees a secret with the recipient's
 * long-term key, derives an AEAD key from it, and ships the ephemeral public
 * key alongside the ciphertext.
 *
 * It is used by TLS Encrypted Client Hello, by Message Layer Security, by
 * Oblivious HTTP, and by Apple's private relay - all since 2022, which makes
 * it the newest thing in this library by a decade.
 *
 * WHY IT IS A STANDARD RATHER THAN AN OBVIOUS RECIPE
 * The obvious recipe - ECDH then HKDF then AES-GCM - is what everyone built
 * before 2020 under the name ECIES, and every implementation did it slightly
 * differently: some hashed the ephemeral public key into the KDF and some did
 * not, some bound the recipient's key and some did not, salts and info
 * strings varied. Those differences are not cosmetic. Omitting the ephemeral
 * key from the KDF input, in particular, breaks the security proof and has
 * caused real attacks. RFC 9180 fixes every one of those choices, which is
 * why it exists and why this file follows it exactly rather than reinventing
 * the shape.
 *
 * IMPLEMENTED HERE: mode_base, the anonymous-sender case. The PSK and
 * authenticated modes share all the machinery below and differ only in what
 * goes into the key schedule; they are a small addition when needed.
 *
 * This file holds the MECHANISM and knows nothing about any particular
 * curve, hash or cipher - it imports only kdf.js and bytes.js. The registered
 * suites live in hpke.js, the same split as commons/ecdsa.js against nist.js
 * and commons/eddsa.js against ed25519.js.
 */

import { hkdf_extract, hkdf_expand } from '../kdf.js';
import { concat, be16, lp16, ascii } from './bytes.js';
import { require_rng } from './primes.js';

/* ---------------- suite identifiers ---------------- */
/*
 * Every derivation is bound to the exact suite in use through these labelled
 * prefixes. That is what stops a ciphertext produced under one combination of
 * algorithms from being reinterpreted under another - cross-suite confusion,
 * which is a real attack against protocols that negotiate their algorithms.
 */

var HPKE_V1 = /* @__PURE__ */ ascii('HPKE-v1');
var KEM_LBL = /* @__PURE__ */ ascii('KEM');
var HPKE_LBL = /* @__PURE__ */ ascii('HPKE');

/*
 * Note the argument order into kdf.js: hkdf_extract takes (hash, ikm, salt)
 * and hkdf_expand takes (hash, prk, length, info) - key material first and
 * length before info, which is this library's convention throughout but NOT
 * the order RFC 5869 writes them in. Getting it backwards here produced a
 * nonce of the wrong length rather than a wrong nonce, which is the lucky
 * version of that mistake.
 */
export function labeled_extract(hash, suite_id, salt, label, ikm) {
    return hkdf_extract(hash, concat([HPKE_V1, suite_id, ascii(label), ikm]), salt);
}

export function labeled_expand(hash, suite_id, prk, label, info, len) {
    var body = concat([be16(len), HPKE_V1, suite_id, ascii(label), info]);
    return hkdf_expand(hash, prk, len, body);
}


/**
 * LabeledDerive, for a SINGLE-STAGE KDF - an XOF with no extract/expand
 * split (draft-ietf-hpke-pq §5, over the HPKE revision's one-stage
 * functions): Derive(ikm ‖ "HPKE-v1" ‖ suite_id ‖ lp(label) ‖ I2OSP(L, 2) ‖ context, L).
 *
 * @param {function} xof  (msg, len) -> bytes
 */
export function labeled_derive(xof, suite_id, ikm, label, context, len) {
    return xof(concat([ikm, HPKE_V1, suite_id, lp16(ascii(label)), be16(len), context]), len);
}

/** The suite id a KEM's own derivations are bound to: "KEM" ‖ I2OSP(kem_id, 2). */
export function kem_suite_id(id) { return concat([KEM_LBL, be16(id)]); }

/**
 * Build an HPKE suite.
 *
 * @param {object} kem   a DHKEM: { id, hash, Nsecret, Npk, Nsk, dh, derive_pub, gen }
 *                       or any other KEM (RFC 9180 §4's Encap/Decap):
 *                       { id, Nsecret, Nenc, Npk, Nsk, encap(pk, rng) -> { shared_secret, enc },
 *                         decap(enc, sk) -> shared_secret, derive_pub(sk) }
 *
 * ⭐ A NON-DH KEM PLUGS IN DIRECTLY. RFC 9180 defines HPKE over an abstract
 *    KEM; DHKEM is just the one it also specifies. Post-quantum KEMs (ML-KEM,
 *    X-Wing - draft-ietf-hpke-pq) provide Encap/Decap themselves and their
 *    shared secret goes straight into the key schedule, with no
 *    ExtractAndExpand. The suite_id still carries the KEM id, so a ciphertext
 *    under one KEM is never reinterpreted under another.
 * @param {object} kdf   two-stage: { id, hash } (HKDF); single-stage: { id, xof(msg, len), Nh }
 * @param {object} aead  { id, Nk, Nn, seal, open }
 */
export function suite(kem, kdf, aead) {
    var kem_suite = kem_suite_id(kem.id);
    var hpke_suite = concat([HPKE_LBL, be16(kem.id), be16(kdf.id), be16(aead.id)]);

    /**
     * ExtractAndExpand - the KEM's own derivation.
     *
     * kem_context is the ephemeral public key FOLLOWED BY the recipient's.
     * Both are in there deliberately: binding the ephemeral key is what the
     * pre-RFC ECIES implementations kept omitting, and binding the
     * recipient's is what stops a shared secret from being replayed toward a
     * different recipient.
     */
    function extract_and_expand(dh, kem_context) {
        if (typeof kem.decap === 'function') { throw new Error('hpke: ExtractAndExpand is DHKEM only'); }
        var eae = labeled_extract(kem.hash, kem_suite, new Uint8Array(0), 'eae_prk', dh);
        return labeled_expand(kem.hash, kem_suite, eae, 'shared_secret', kem_context, kem.Nsecret);
    }

    /**
     * The key schedule: turn a shared secret into an AEAD key, a base nonce
     * and an exporter secret.
     */
    function key_schedule(shared_secret, info) {
        /* mode_base is 0; the psk and auth modes differ only here */
        var mode = new Uint8Array([0]), psk = new Uint8Array(0), psk_id = new Uint8Array(0);
        info = info || new Uint8Array(0);
        if (kdf.xof) {
            /* a single-stage KDF: one LabeledDerive gives key, base nonce and
               exporter secret together, over length-prefixed inputs */
            var secrets = concat([lp16(psk), lp16(shared_secret)]);
            var context = concat([mode, lp16(psk_id), lp16(info)]);
            var all = labeled_derive(kdf.xof, hpke_suite, secrets, 'secret', context, aead.Nk + aead.Nn + kdf.Nh);
            return { key: all.slice(0, aead.Nk), base_nonce: all.slice(aead.Nk, aead.Nk + aead.Nn), exporter: all.slice(aead.Nk + aead.Nn) };
        }
        var psk_id_hash = labeled_extract(kdf.hash, hpke_suite, new Uint8Array(0), 'psk_id_hash', psk_id);
        var info_hash = labeled_extract(kdf.hash, hpke_suite, new Uint8Array(0), 'info_hash', info);
        var ks_context = concat([mode, psk_id_hash, info_hash]);

        var secret = labeled_extract(kdf.hash, hpke_suite, shared_secret, 'secret', psk);

        return {
            key:      labeled_expand(kdf.hash, hpke_suite, secret, 'key', ks_context, aead.Nk),
            base_nonce: labeled_expand(kdf.hash, hpke_suite, secret, 'base_nonce', ks_context, aead.Nn),
            exporter: labeled_expand(kdf.hash, hpke_suite, secret, 'exp', ks_context, kdf.hash.DIGEST_SIZE)
        };
    }

    /**
     * The nonce for message n: the base nonce xored with the sequence number.
     *
     * A counter rather than fresh randomness, because the key is used once per
     * context and a repeated (key, nonce) pair destroys every AEAD here. The
     * counter makes repetition impossible rather than unlikely.
     */
    function nonce_for(base, seq) {
        var n = new Uint8Array(base);
        var v = seq;
        for (var i = n.length - 1; i >= 0 && v > 0; i--) {
            n[i] ^= v & 0xff;
            v = Math.floor(v / 256);
        }
        return n;
    }

    /* RFC 9180 §4: Encap / Decap, for a DHKEM or any other KEM */
    function encap(pk_r, rng) {
        if (typeof kem.encap === 'function') { return kem.encap(pk_r, rng); }
        var eph = kem.gen(rng);
        var dh = kem.dh(eph.sk, pk_r);
        return { shared_secret: extract_and_expand(dh, concat([eph.pk, pk_r])), enc: eph.pk };
    }
    function decap(enc, sk_r) {
        if (typeof kem.decap === 'function') { return kem.decap(enc, sk_r); }
        var pk_r = kem.derive_pub(sk_r);
        var dh = kem.dh(sk_r, enc);
        return extract_and_expand(dh, concat([enc, pk_r]));
    }

    /*
     * The two halves of a context. seal() and open() used to repeat their
     * bodies - encap, key schedule, AEAD at sequence 0 - and the exporter was
     * written out once per side; each one-shot call is now the first message
     * of a context, which is exactly what RFC 9180 section 6.1 defines it as.
     */
    function exporter(ks) {
        return function (context, len) {
            return kdf.xof ? labeled_derive(kdf.xof, hpke_suite, ks.exporter, 'sec', context, len)
                           : labeled_expand(kdf.hash, hpke_suite, ks.exporter, 'sec', context, len);
        };
    }

    /* rng (n => n random bytes) omitted or null draws from the platform; pass null to give info */
    function sender_context(pk_r, rng, info) {
        rng = require_rng('hpke.seal_context', rng);
        var e = encap(pk_r, rng);
        var ks = key_schedule(e.shared_secret, info);
        var seq = 0;
        return {
            enc: e.enc,
            seal: function (msg, aad) {
                var out = aead.seal(ks.key, nonce_for(ks.base_nonce, seq), msg, aad || new Uint8Array(0));
                seq++;
                return out;
            },
            export: exporter(ks)
        };
    }

    /* the half of open_context that needs no secret */
    function open_from_shared(shared, info) {
        var ks = key_schedule(shared, info);
        var seq = 0;
        return {
            open: function (ct, aad) {
                var out = aead.open(ks.key, nonce_for(ks.base_nonce, seq), ct, aad || new Uint8Array(0));
                seq++;
                return out;
            },
            export: exporter(ks)
        };
    }

    var API = {
        /**
         * Encrypt to a public key.
         *
         * @param  {Uint8Array} pk_r  the recipient's public key
         * @param  {Uint8Array} msg
         * @param  {function}   [rng]   n => n random bytes; omitted or null
         *                              draws fresh ones from the platform
         *                              (pass null to give info or aad)
         * @param  {Uint8Array} [info]  application context, bound into the key
         * @param  {Uint8Array} [aad]
         * @return {{enc: Uint8Array, ct: Uint8Array}}
         *         enc is the ephemeral public key - send it with the ciphertext
         */
        seal: function (pk_r, msg, rng, info, aad) {
            rng = require_rng('hpke.seal', rng);
            var c = sender_context(pk_r, rng, info);
            return { enc: c.enc, ct: c.seal(msg, aad) };
        },

        /**
         * @param  {Uint8Array} sk_r  the recipient's secret key
         * @param  {Uint8Array} enc   the ephemeral public key from seal
         * @return {Uint8Array|null}  null when authentication fails
         */
        open: function (sk_r, enc, ct, info, aad) {
            return open_from_shared(decap(enc, sk_r), info).open(ct, aad);
        },

        /**
         * A multi-message context, for sending many messages under one
         * agreement. The sequence number must advance in lockstep on both
         * sides; that is the caller's job and the reason this is explicit
         * rather than hidden.
         */
        seal_context: sender_context,

        /**
         * ⭐ THE SAME THING, WITH THE DH RESULT SUPPLIED.
         *
         * `dh` is the ONLY step that touches the private key. Everything
         * after it - ExtractAndExpand, the key schedule, the AEAD - is
         * deterministic derivation from that one value and from public
         * inputs, so a receiver whose key is SHARED across parties can
         * compute the point jointly and hand it in here.
         *
         * That makes a threshold receiver interoperable: the sender runs
         * ordinary HPKE and does not need to know the other side is split at
         * all. Which is what TLS Encrypted Client Hello, MLS and Oblivious
         * HTTP would need to talk to one.
         *
         * ⚠ `dh_output` IS A SHARED SECRET AND IS NOT AUTHENTICATED HERE.
         *   open_context derives it from a key it holds; this trusts the
         *   caller's protocol to have produced it correctly. A wrong value
         *   does not fail here - it produces a key schedule that decrypts to
         *   nothing, which surfaces as an AEAD failure with no indication of
         *   where it came from.
         *
         * @param {Uint8Array} dh_output  the KEM shared secret, sk*pk
         * @param {Uint8Array} pk_r       the receiver's PUBLIC key
         */
        open_context_with_dh: function (dh_output, enc, pk_r, info) {
            if (typeof kem.decap === 'function') {
                throw new Error('hpke: open_context_with_dh is for DHKEM suites only');
            }
            var shared = extract_and_expand(dh_output, concat([enc, pk_r]));
            return open_from_shared(shared, info);
        },

        /**
         * And the KEM derivation on its own, for a caller assembling the
         * pieces differently. RFC 9180 section 4.1.
         */
        extract_and_expand: extract_and_expand,

        open_context: function (sk_r, enc, info) {
            return open_from_shared(decap(enc, sk_r), info);
        },

        /** The suite's KEM and its key generation, for callers that need a key pair. */
        kem: kem
    };

    return API;
}
