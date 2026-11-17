/**
 * Hybrid post-quantum KEMs - ML-KEM and an elliptic curve together
 * (draft-irtf-cfrg-concrete-hybrid-kems, over the framework of
 * draft-irtf-cfrg-hybrid-kems; commons/hybrid_kem.js).
 *
 *     mlkem768_x25519   ML-KEM-768 + X25519    = X-Wing (xwing.js)     pk 1216  ct 1120
 *     mlkem768_p256     ML-KEM-768 + P-256                             pk 1249  ct 1153
 *     mlkem1024_p384    ML-KEM-1024 + P-384                            pk 1665  ct 1665
 *
 * Secret keys are 32-byte seeds, shared secrets 32 bytes; SHAKE256 expands
 * the seed and SHA3-256 combines. Breaking one needs breaking ML-KEM AND the
 * curve: a quantum computer gets past the curve and still faces Module-LWE,
 * and a flaw in the young lattice standard still leaves the curve.
 *
 * WHICH ONE. X25519 is the default, as in TLS (X25519MLKEM768); the NIST
 * curves are for a profile that requires them (FIPS, CNSA 2.0 at category 5).
 * In HPKE these are KEMs 0x647a, 0x0050 and 0x0051 (hpke.js).
 *
 * TLS 1.3 USES A DIFFERENT HYBRID of the same parts (RFC 10024, below): the
 * two shares and the two secrets are only CONCATENATED, because TLS's own
 * key schedule hashes the result together with the whole transcript. Those
 * three - x25519mlkem768, secp256r1mlkem768, secp384r1mlkem1024 - are the
 * key_share groups, not KEMs to use on their own.
 */
import { ml_kem768, ml_kem1024 } from './ml_kem.js';
import { x25519, x25519_checked, get_public_key } from './x25519.js';
import { p256, p384, P256_CURVE, P384_CURVE } from './nist.js';
import { sha3_256, shake256 } from './sha3.js';
import { bytes_to_bigint, concat } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';
import { hybrid_kem } from './commons/hybrid_kem.js';

/* ---------------- the nominal groups (concrete-hybrid-kems §3.1) ---------------- */

/* Curve25519: the seed is the scalar, X25519 the exponentiation */
var CURVE25519 = {
    SEED: 32, ELEM: 32,
    scalar: function (seed) { return new Uint8Array(seed); },
    element: get_public_key,
    shared: function (sk, p) { return x25519(sk, p); }
};

/*
 * P-256 and P-384: RandomScalar takes the first Nscalar-byte chunk of the
 * seed that is a valid scalar (0 < s < n), so the seed is several chunks -
 * four for P-256, where one is rejected with probability below 2^-32; one
 * for P-384, below 2^-192. Elements are uncompressed SEC1 points; the shared
 * secret is the x-coordinate.
 */
function nist_group(curve, n, nscalar, nseed, nelem) {
    return {
        SEED: nseed, ELEM: nelem,
        scalar: function (seed) {
            for (var off = 0; off + nscalar <= seed.length; off += nscalar) {
                var c = seed.subarray(off, off + nscalar), v = bytes_to_bigint(c);
                if (v !== 0n && v < n) { return new Uint8Array(c); }
            }
            throw new Error('hybrid_kem: rejection sampling failed');
        },
        element: function (sk) { return curve.get_public_key(sk, false); },
        shared: function (sk, p) { return curve.ecdh(sk, p); },
        /* an uncompressed point on the curve (decode_point returns null off it) */
        check: function (p) { try { return p.length === nelem && p[0] === 4 && curve.decode_point(p) !== null; } catch (e) { return false; } }
    };
}
var P256G = /* @__PURE__ */ nist_group(p256, P256_CURVE.n, 32, 128, 65);
var P384G = /* @__PURE__ */ nist_group(p384, P384_CURVE.n, 48, 48, 97);

function prg(seed, len) { return shake256(seed, len); }

/* "\./" over "/^\" - the X-Wing label */
var XWING_LABEL = new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);

export var mlkem768_x25519 = /* @__PURE__ */ hybrid_kem({
    name: 'xwing', label: XWING_LABEL, pq: ml_kem768, group: CURVE25519, prg: prg, kdf: sha3_256
});
export var mlkem768_p256 = /* @__PURE__ */ hybrid_kem({
    name: 'mlkem768_p256', label: new TextEncoder().encode('MLKEM768-P256'), pq: ml_kem768, group: P256G, prg: prg, kdf: sha3_256
});
export var mlkem1024_p384 = /* @__PURE__ */ hybrid_kem({
    name: 'mlkem1024_p384', label: new TextEncoder().encode('MLKEM1024-P384'), pq: ml_kem1024, group: P384G, prg: prg, kdf: sha3_256
});

/* ---------------- TLS 1.3: RFC 10024's concatenation hybrids ---------------- */
/*
 * The client's key_share is its two public halves, the server's the ML-KEM
 * ciphertext and its own curve share, and the shared secret both secrets -
 * in an order that is the group's, not one rule:
 *
 *                         client share      server share   shared secret      group
 *   X25519MLKEM768        ek ‖ x25519       ct ‖ x25519    ss_ML ‖ ss_X  64   0x11ec
 *   SecP256r1MLKEM768     p256 ‖ ek         p256 ‖ ct      ss_EC ‖ ss_ML 64   0x11eb
 *   SecP384r1MLKEM1024    p384 ‖ ek         p384 ‖ ct      ss_EC ‖ ss_ML 80   0x11ed
 *
 * (ML-KEM first for X25519MLKEM768 for its history; the NIST hybrids put the
 * FIPS-approved curve first.) The checks are the RFC's: FIPS 203's key
 * check on the server, the ciphertext length on the client, every point
 * validated and X25519's all-zero output refused on both - each a throw,
 * TLS's illegal_parameter.
 *
 * The client's secret is the ML-KEM seed (d ‖ z, 64 bytes) followed by the
 * curve scalar: keygen_derand takes it in that form, and encaps_derand the
 * ML-KEM randomness (32) then the server's curve scalar.
 */
function tls_hybrid(o) {
    var pq = o.pq, c = o.curve, PQ_SEED = 64;
    var SK_BYTES = PQ_SEED + c.SK, SHARE = pq.EK_BYTES + c.PK, REPLY = pq.CT_BYTES + c.PK;
    function bytes_of(v, len, what) {
        if (!(v instanceof Uint8Array) || v.length !== len) { throw new Error(o.name + ': ' + what + ' must be ' + len + ' bytes'); }
    }
    /* split a two-part value into its (ML-KEM, curve) halves, whichever comes first */
    function halves(v, pq_len) {
        return o.pq_first ? { pq: v.subarray(0, pq_len), ec: v.subarray(pq_len) }
                          : { ec: v.subarray(0, c.PK), pq: v.subarray(c.PK) };
    }
    function join(pq_part, ec_part) { return o.pq_first ? concat([pq_part, ec_part]) : concat([ec_part, pq_part]); }

    function keygen_derand(sk) {
        bytes_of(sk, SK_BYTES, 'secret key');
        var kp = pq.keygen(sk.subarray(0, PQ_SEED));
        kp.dk.fill(0);
        return { sk: new Uint8Array(sk), share: join(kp.ek, c.public(sk.subarray(PQ_SEED))) };
    }
    function encaps_derand(share, rnd) {
        bytes_of(share, SHARE, 'client key_share');
        bytes_of(rnd, 32 + c.SK, 'randomness');
        var hs = halves(share, pq.EK_BYTES), e = rnd.subarray(32);
        var m = pq.encaps(hs.pq, rnd.subarray(0, 32));            /* FIPS 203's key check throws inside */
        var ss_ec = c.shared(e, hs.ec);
        try { return { share: join(m.ct, c.public(e)), ss: join(m.ss, ss_ec) }; } finally { m.ss.fill(0); ss_ec.fill(0); }
    }
    return {
        GROUP: o.group, SK_BYTES: SK_BYTES, CLIENT_SHARE_BYTES: SHARE, SERVER_SHARE_BYTES: REPLY, SS_BYTES: 32 + c.SS,

        /** The client: a key share and the secret to keep. */
        keygen_derand: keygen_derand,
        keygen: function (rng) {
            rng = require_rng(o.name + '.keygen', rng);
            for (var i = 0; i < 64; i++) {
                var sk = concat([rng(PQ_SEED), rng(c.SK)]);
                if (c.valid(sk.subarray(PQ_SEED))) { return keygen_derand(sk); }
            }
            throw new Error(o.name + ': key generation failed');
        },

        /** The server: its key share and the shared secret, from the client's share. */
        encaps_derand: encaps_derand,
        encaps: function (share, rng) {
            rng = require_rng(o.name + '.encaps', rng);
            for (var i = 0; i < 64; i++) {
                var r = concat([rng(32), rng(c.SK)]);
                if (c.valid(r.subarray(32))) { try { return encaps_derand(share, r); } finally { r.fill(0); } }
            }
            throw new Error(o.name + ': randomness failed');
        },

        /** The client again: the shared secret, from the server's share. */
        decaps: function (sk, reply) {
            bytes_of(sk, SK_BYTES, 'secret key');
            bytes_of(reply, REPLY, 'server key_share');
            var hs = halves(reply, pq.CT_BYTES), dk = pq.keygen(sk.subarray(0, PQ_SEED)).dk;
            try {
                var ss_pq = pq.decaps(dk, hs.pq), ss_ec = c.shared(sk.subarray(PQ_SEED), hs.ec);
                try { return join(ss_pq, ss_ec); } finally { ss_pq.fill(0); ss_ec.fill(0); }
            } finally { dk.fill(0); }
        }
    };
}

var TLS_X25519 = {
    SK: 32, PK: 32, SS: 32,
    valid: function () { return true; },
    public: get_public_key,
    shared: function (sk, p) {
        var s = x25519_checked(sk, p);
        if (s === null) { throw new Error('x25519mlkem768: the X25519 secret is all zero'); }
        return s;
    }
};
function tls_nist(curve, n, size) {
    return {
        SK: size, PK: 2 * size + 1, SS: size,
        valid: function (sk) { var v = bytes_to_bigint(sk); return v !== 0n && v < n; },
        public: function (sk) { return curve.get_public_key(sk, false); },
        shared: function (sk, p) {
            if (p.length !== 2 * size + 1 || p[0] !== 4) { throw new Error('tls hybrid: the curve share must be an uncompressed point'); }
            return curve.ecdh(sk, p);
        }
    };
}

export var x25519mlkem768 = /* @__PURE__ */ tls_hybrid({ name: 'x25519mlkem768', group: 0x11ec, pq: ml_kem768, curve: TLS_X25519, pq_first: true });
export var secp256r1mlkem768 = /* @__PURE__ */ tls_hybrid({ name: 'secp256r1mlkem768', group: 0x11eb, pq: ml_kem768, curve: tls_nist(p256, P256_CURVE.n, 32), pq_first: false });
export var secp384r1mlkem1024 = /* @__PURE__ */ tls_hybrid({ name: 'secp384r1mlkem1024', group: 0x11ed, pq: ml_kem1024, curve: tls_nist(p384, P384_CURVE.n, 48), pq_first: false });
