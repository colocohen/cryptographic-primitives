/**
 * HPKE - Hybrid Public Key Encryption  -  RFC 9180
 *
 * Encrypt arbitrary data to a public key, by combining an ephemeral key
 * agreement, a KDF and an AEAD. Used by TLS Encrypted Client Hello, Message
 * Layer Security, Oblivious HTTP and Apple Private Relay.
 *
 * The construction itself is in commons/hpke.js and knows nothing about any
 * particular algorithm. This file supplies the registered suites - the same
 * split as commons/ecdsa.js against nist.js.
 *
 * Start with x25519_sha256_chacha20poly1305 unless a profile says otherwise;
 * it is what TLS ECH and OHTTP use.
 *
 * The identifiers below are IANA-registered code points, not arbitrary
 * numbers: they appear on the wire in TLS Encrypted Client Hello and in
 * Oblivious HTTP, so a wrong one produces a suite that no peer will accept.
 */

import { suite, labeled_extract, labeled_expand, labeled_derive, kem_suite_id } from './commons/hpke.js';
import * as x25519 from './x25519.js';
import * as x448 from './x448.js';
import { p256, p384, p521 } from './nist.js';
import { sha256, sha384, sha512 } from './sha2.js';
import { aes_gcm_encrypt, aes_gcm_decrypt } from './aes.js';
import { chacha20poly1305_encrypt, chacha20poly1305_decrypt } from './chacha.js';
import { ml_kem512, ml_kem768, ml_kem1024 } from './ml_kem.js';
import { mlkem768_x25519, mlkem768_p256, mlkem1024_p384 } from './hybrid_kem.js';
import { shake128, shake256, turboshake128, turboshake256 } from './sha3.js';
import { require_rng } from './commons/primes.js';

/* ---------------- KEMs ---------------- */

/*
 * The two Montgomery-curve DHKEMs differ only in sizes, hash and which
 * checked function they call - they were two hand-written objects, the
 * NIST ones below were already a factory.
 *
 * @param {function} checked  (sk, pk) -> shared secret, or null for a
 *                            low-order peer key
 */
/*
 * DeriveKeyPair for a DHKEM (RFC 9180 §7.1.3), through the KEM's own
 * HKDF: dkp_prk = LabeledExtract("", "dkp_prk", ikm), then the "sk" output
 * (X25519, X448) or "candidate" outputs under a counter until one is a
 * valid scalar (the NIST curves, top byte masked).
 */
function dkp_prk(id, hash, ikm) { return labeled_extract(hash, kem_suite_id(id), new Uint8Array(0), 'dkp_prk', ikm); }

function xdh_kem(id, hash, nsecret, n, get_public_key, checked) {
    return {
        id: id, hash: hash, Nsecret: nsecret, Npk: n, Nsk: n,
        /* rng (n => n random bytes) omitted or null draws from the platform, here and in every KEM's gen and encap */
        gen: function (rng) {
            rng = require_rng('hpke.gen', rng);
            var sk = rng(n);
            return { sk: sk, pk: get_public_key(sk) };
        },
        derive_key_pair: function (ikm) {
            var sk = labeled_expand(hash, kem_suite_id(id), dkp_prk(id, hash, ikm), 'sk', new Uint8Array(0), n);
            return { sk: sk, pk: get_public_key(sk) };
        },
        derive_pub: get_public_key,
        dh: function (sk, pk) {
            var s = checked(sk, pk);
            /* a low-order peer key forces the secret to zero, which both sides
               can compute - RFC 9180 requires rejecting it */
            if (s === null) { throw new Error('hpke: peer sent a low-order point'); }
            return s;
        }
    };
}

/** DHKEM(X25519, HKDF-SHA256) - code point 0x0020, by far the most used. */
export var DHKEM_X25519 = /* @__PURE__ */ xdh_kem(0x0020, sha256, 32, 32,
    x25519.get_public_key, x25519.x25519_checked);

/** DHKEM(X448, HKDF-SHA512) - code point 0x0021. */
export var DHKEM_X448 = /* @__PURE__ */ xdh_kem(0x0021, sha512, 64, 56,
    x448.get_public_key, x448.x448_checked);

/**
 * @param {number} bitmask  applied to the top byte before the range check
 *
 * The bitmask is RFC 9180's, and P-521 is why it exists. Its order is 521
 * bits inside a 66-byte encoding, so seven bits at the top are always zero -
 * and a raw random 66 bytes lands above the order about 127 times out of 128.
 * Rejection sampling alone would fail almost every time; masking first makes
 * the rejection rate negligible. P-256 and P-384 fill their bytes exactly and
 * take a mask of 0xff, which does nothing.
 */
function nist_kem(id, curve, hash, nsecret, npk, bitmask) {
    return {
        id: id, hash: hash, Nsecret: nsecret, Npk: npk, Nsk: curve.BYTES,
        bitmask: bitmask,
        gen: function (rng) {
            rng = require_rng('hpke.gen', rng);
            for (var i = 0; i < 256; i++) {
                var sk = rng(curve.BYTES);
                sk[0] &= bitmask;
                if (curve.is_valid_secret(sk)) { return { sk: sk, pk: curve.get_public_key(sk, false) }; }
            }
            throw new Error('hpke: key generation failed');
        },
        derive_key_pair: function (ikm) {
            var prk = dkp_prk(id, hash, ikm);
            for (var counter = 0; counter < 256; counter++) {
                var sk = labeled_expand(hash, kem_suite_id(id), prk, 'candidate', new Uint8Array([counter]), curve.BYTES);
                sk[0] &= bitmask;
                if (curve.is_valid_secret(sk)) { return { sk: sk, pk: curve.get_public_key(sk, false) }; }
            }
            throw new Error('hpke: DeriveKeyPair failed');
        },
        derive_pub: function (sk) { return curve.get_public_key(sk, false); },
        dh: function (sk, pk) { return curve.ecdh(sk, pk); }
    };
}

/* The NIST KEMs use UNCOMPRESSED points - 65 bytes for P-256, not 33. RFC
   9180 fixes that, and sending a compressed key produces a shared secret the
   peer will not reproduce. */
export var DHKEM_P256 = /* @__PURE__ */ nist_kem(0x0010, p256, sha256, 32, 65, 0xff);
export var DHKEM_P384 = /* @__PURE__ */ nist_kem(0x0011, p384, sha384, 48, 97, 0xff);
export var DHKEM_P521 = /* @__PURE__ */ nist_kem(0x0012, p521, sha512, 64, 133, 0x01);

/* ---------------- post-quantum KEMs (draft-ietf-hpke-pq) ---------------- */
/*
 * ⭐ THESE ARE NOT DHKEMs. They provide Encap/Decap themselves, and their
 *    shared secret goes into the key schedule directly. The private key is
 *    kept in SEED form (64 bytes for ML-KEM, 32 for the hybrids), as the
 *    draft specifies; the expanded key is recomputed when needed.
 *
 * DeriveKeyPair is SHAKE256's LabeledDerive under the KEM's suite id, to
 * the seed (draft-ietf-hpke-pq §3, §4).
 *
 * An encapsulation key failing FIPS 203's check throws - HPKE's EncapError.
 */
function seed_of(id, ikm, len) { return labeled_derive(shake256, kem_suite_id(id), ikm, 'DeriveKeyPair', new Uint8Array(0), len); }

function mlkem_kem(id, K) {
    return {
        id: id, Nsecret: 32, Nenc: K.CT_BYTES, Npk: K.EK_BYTES, Nsk: 64,
        gen: function (rng) {
            rng = require_rng('hpke.gen', rng);
            var sk = rng(64);
            return { sk: sk, pk: K.keygen(sk).ek };
        },
        derive_key_pair: function (ikm) { var sk = seed_of(id, ikm, 64); return { sk: sk, pk: K.keygen(sk).ek }; },
        derive_pub: function (sk) { return K.keygen(sk).ek; },
        encap: function (pk, rng) {
            rng = require_rng('hpke.encap', rng);
            var e = K.encaps(pk, rng(32));
            return { shared_secret: e.ss, enc: e.ct };
        },
        decap: function (enc, sk) {
            var dk = K.keygen(sk).dk;
            try { return K.decaps(dk, enc); } finally { dk.fill(0); }
        }
    };
}
export var ML_KEM_512  = /* @__PURE__ */ mlkem_kem(0x0040, ml_kem512);
export var ML_KEM_768  = /* @__PURE__ */ mlkem_kem(0x0041, ml_kem768);
export var ML_KEM_1024 = /* @__PURE__ */ mlkem_kem(0x0042, ml_kem1024);

/* the PQ/T hybrids of hybrid_kem.js (draft-irtf-cfrg-concrete-hybrid-kems) */
function hybrid(id, K) {
    return {
        id: id, Nsecret: 32, Nenc: K.CT_BYTES, Npk: K.PK_BYTES, Nsk: K.SK_BYTES,
        gen: function (rng) { return K.keygen(rng); },
        derive_key_pair: function (ikm) {
            var seed = seed_of(id, ikm, K.SK_BYTES);
            try { return K.keygen_derand(seed); } finally { seed.fill(0); }
        },
        derive_pub: K.public_key,
        encap: function (pk, rng) {
            var e = K.encaps(pk, rng);
            return { shared_secret: e.ss, enc: e.ct };
        },
        decap: function (enc, sk) { return K.decaps(sk, enc); }
    };
}

/**
 * X-Wing (ML-KEM-768 + X25519) - code point 0x647a, registered as
 * "MLKEM768-X25519". The hybrid to reach for: breaking it needs breaking
 * both halves.
 */
export var XWING = /* @__PURE__ */ hybrid(0x647a, mlkem768_x25519);
/** MLKEM768-P256 - 0x0050. */
export var MLKEM768_P256 = /* @__PURE__ */ hybrid(0x0050, mlkem768_p256);
/** MLKEM1024-P384 - 0x0051. */
export var MLKEM1024_P384 = /* @__PURE__ */ hybrid(0x0051, mlkem1024_p384);

/* ---------------- KDFs ---------------- */

export var HKDF_SHA256 = { id: 0x0001, hash: sha256 };
export var HKDF_SHA384 = { id: 0x0002, hash: sha384 };
export var HKDF_SHA512 = { id: 0x0003, hash: sha512 };

/*
 * The single-stage KDFs of draft-ietf-hpke-pq §5: an XOF used once per
 * derivation (LabeledDerive), no extract/expand split. TurboSHAKE with
 * domain byte 0x1f (RFC 9861). A suite that uses SHA-3 throughout, as ML-KEM
 * does inside.
 */
function xof_kdf(id, xof, nh) { return { id: id, Nh: nh, xof: function (m, len) { return xof(m, len); } }; }
export var SHAKE128_KDF      = /* @__PURE__ */ xof_kdf(0x0010, shake128, 32);
export var SHAKE256_KDF      = /* @__PURE__ */ xof_kdf(0x0011, shake256, 64);
export var TURBOSHAKE128_KDF = /* @__PURE__ */ xof_kdf(0x0012, function (m, len) { return turboshake128(m, len, 0x1f); }, 32);
export var TURBOSHAKE256_KDF = /* @__PURE__ */ xof_kdf(0x0013, function (m, len) { return turboshake256(m, len, 0x1f); }, 64);

/* ---------------- AEADs ---------------- */

/* one shape for all three (the two AES-GCM entries were identical but for
   id and key size); every registered AEAD here has a 12-byte nonce */
function aead(id, nk, encrypt, decrypt) {
    return {
        id: id, Nk: nk, Nn: 12,
        seal: function (k, n, m, aad) { return encrypt(k, n, m, aad); },
        open: function (k, n, c, aad) { return decrypt(k, n, c, aad); }
    };
}

export var AES_128_GCM = /* @__PURE__ */ aead(0x0001, 16, aes_gcm_encrypt, aes_gcm_decrypt);
export var AES_256_GCM = /* @__PURE__ */ aead(0x0002, 32, aes_gcm_encrypt, aes_gcm_decrypt);
export var CHACHA20_POLY1305 = /* @__PURE__ */ aead(0x0003, 32, chacha20poly1305_encrypt, chacha20poly1305_decrypt);

/* ---------------- the common suites ---------------- */

/** X25519 + HKDF-SHA256 + ChaCha20-Poly1305. What TLS ECH and OHTTP use. */
export var x25519_sha256_chacha20poly1305 =
    /* @__PURE__ */ suite(DHKEM_X25519, HKDF_SHA256, CHACHA20_POLY1305);

export var x25519_sha256_aes128gcm =
    /* @__PURE__ */ suite(DHKEM_X25519, HKDF_SHA256, AES_128_GCM);

export var p256_sha256_aes128gcm =
    /* @__PURE__ */ suite(DHKEM_P256, HKDF_SHA256, AES_128_GCM);

export var p521_sha512_aes256gcm =
    /* @__PURE__ */ suite(DHKEM_P521, HKDF_SHA512, AES_256_GCM);

export var x448_sha512_chacha20poly1305 =
    /* @__PURE__ */ suite(DHKEM_X448, HKDF_SHA512, CHACHA20_POLY1305);

/** X-Wing + HKDF-SHA256 + ChaCha20-Poly1305: hybrid post-quantum HPKE. */
export var xwing_sha256_chacha20poly1305 =
    /* @__PURE__ */ suite(XWING, HKDF_SHA256, CHACHA20_POLY1305);

/** X-Wing + HKDF-SHA256 + AES-256-GCM. */
export var xwing_sha256_aes256gcm =
    /* @__PURE__ */ suite(XWING, HKDF_SHA256, AES_256_GCM);
