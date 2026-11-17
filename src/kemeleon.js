/**
 * Kemeleon  -  draft-irtf-cfrg-kemeleon-02
 *
 * ML-KEM encapsulation keys and ciphertexts AS RANDOM-LOOKING BYTE STRINGS:
 * what Elligator does for a Diffie-Hellman share, for ML-KEM. An observer
 * who sees a Kemeleon-encoded key or ciphertext cannot tell it from uniform
 * bytes (under module LWE), which is what obfuscated key exchange and the
 * KEM-based PAKEs (pqpake.js) need.
 *
 * THE ENCODING. An encapsulation key is k polynomials t[i] over Z_q (q = 3329,
 * 256 coefficients) plus a 32-byte seed rho. Each polynomial is read as one
 * integer in base q,
 *
 *     r = a[0] + a[1] q + ... + a[255] q^255            r < q^256 < 2^2996
 *
 * and lifted by a random multiple of q^256 (Tibouchi's Elligator Squared
 * technique): r + m q^256 with m uniform in [0, floor((2^(2996+t) - r)/q^256)]
 * is within 2^-t of uniform on 2996 + t bits. rho is already uniform and is
 * kept as it is. Decoding is r mod q^256 and the base-q digits.
 *
 * A ciphertext's coefficients are COMPRESSED and so not uniform mod q; the
 * encoding first decompresses each and picks a random preimage of the
 * compression (SamplePreimage), which is uniform mod q, then encodes as above.
 *
 * TWO VARIANTS (section 4 and section 5.1):
 *
 *   encode_ek / encode_ctxt        never fail; one integer per polynomial
 *   encode_ek_r / encode_ctxt_r    smaller - all k*256 coefficients in one
 *                                  integer - but they FAIL with constant
 *                                  probability (table 2 of the draft) and
 *                                  the caller retries with a fresh key or
 *                                  ciphertext; that retry is observable
 *
 * THE STATISTICAL PARAMETER t is 76 in the draft (384 bytes per polynomial,
 * the size ML-KEM itself uses); any 76 + 8x is allowed, and pqpake.js takes
 * t = 132 (391 bytes). The draft does not fix the byte order of each integer;
 * this module writes them LITTLE-ENDIAN, as draft-vos-cfrg-pqpake does for
 * its ML-BUA-sKEM, and the rejection variant big-endian, as section 5.1.1's
 * pseudocode reads "network byte order".
 *
 * THE RANDOMNESS MUST STAY SECRET (section 6.2): anyone who knows it can
 * decode and re-encode a value and so tell an encoding from random bytes.
 */

import { PARAMS as ML_KEM_PARAMS, compress, decompress, ml_kem512, ml_kem768, ml_kem1024 } from './ml_kem.js';
import { pack_bits, unpack_bits } from './commons/bitpack.js';
import { bytes_to_bigint, bigint_to_bytes, bytes_to_bigint_le, bigint_to_bytes_le, concat } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';

var Q = 3329, N = 256;
var QB = 3329n;
var QN = /* @__PURE__ */ QB ** 256n;
var B = 2996;   /* ceil(n * log2 q): the bits of q^256 */

function modq(x) { return ((x % Q) + Q) % Q; }

/* base-q digits <-> one integer, least significant digit first */
function to_int(a, from, count) {
    var r = 0n;
    for (var i = from + count - 1; i >= from; i--) { r = r * QB + BigInt(a[i]); }
    return r;
}
function from_int(r, count, out, from) {
    var x = r;
    for (var i = 0; i < count; i++) { out[from + i] = Number(x % QB); x /= QB; }
}

/*
 * A uniform integer in [0, M], from rng: (W random bits) mod (M + 1), with W
 * 128 bits wider than M so the reduction's bias is below 2^-128. W is FIXED
 * by the caller from the largest M it can see, so the number of bytes drawn
 * never depends on the secret value being encoded.
 */
function uniform_upto(M, wbytes, rng) {
    return bytes_to_bigint_le(rng(wbytes)) % (M + 1n);
}

/**
 * The encoding of one ML-KEM parameter set.
 *
 * @param {number} level  512, 768 or 1024
 * @param {number} [t]    statistical distance parameter, 76 + 8x [76]
 */
export function kemeleon(level, t) {
    var p = ML_KEM_PARAMS[level];
    if (!p) { throw new Error('kemeleon: ML-KEM level must be 512, 768 or 1024'); }
    var KEM = { 512: ml_kem512, 768: ml_kem768, 1024: ml_kem1024 }[level];
    var T = t === undefined ? 76 : t;
    if (T < 76 || (T - 76) % 8 !== 0) { throw new Error('kemeleon: t must be 76 + 8x'); }
    var k = p.k, du = p.du, dv = p.dv;
    var POLY = (B + T) / 8;                           /* bytes per encoded polynomial */
    var TOP = 1n << BigInt(B + T);
    var MMAX = TOP / QN;                              /* the largest m can be */
    var MBYTES = Math.ceil((MMAX.toString(2).length + 128) / 8);
    var EK_BYTES = 384 * k + 32, CT_BYTES = 32 * (du * k + dv);

    /* VectorEncode: m is drawn from rng, or given (a test vector's kemeleon_m) */
    function vector_encode(a, from, m_in, rng) {
        var r = to_int(a, from, N);
        var M = (TOP - r) / QN;
        var m = m_in !== undefined ? BigInt(m_in) : uniform_upto(M, MBYTES, rng);
        if (m < 0n || m > M) { throw new Error('kemeleon: m out of range'); }
        return bigint_to_bytes_le(r + m * QN, POLY);
    }
    function vector_decode(bytes, out, from) {
        from_int(bytes_to_bigint_le(bytes) % QN, N, out, from);
    }

    /* the k polynomials of t, as 12-bit coefficients, and rho */
    function split_ek(ek) {
        if (!(ek instanceof Uint8Array) || ek.length !== EK_BYTES) { throw new Error('kemeleon: wrong encapsulation key length'); }
        var s = KEM.split_ek(ek);
        return { a: s.t, rho: s.rho };
    }
    function join_ek(a, rho) { return KEM.join_ek(a, rho); }

    /* SamplePreimage (section 4.1): a uniform x mod q with Compress_d(x) = c, u = Decompress_d(c) */
    function sample_preimage(d, u, c, rng) {
        function pick(lo, hi) { return lo + Number(bytes_to_bigint_le(rng(8)) % BigInt(hi - lo + 1)); }
        var r;
        if (d === 10) {
            if (compress(modq(u + 2), d) === c) { r = pick(-1, 2); }
            else if (compress(modq(u - 2), d) === c) { r = pick(-2, 1); }
            else { r = pick(-1, 1); }
        } else if (d === 11) {
            if (compress(modq(u + 1), d) === c) { r = pick(0, 1); }
            else if (compress(modq(u - 1), d) === c) { r = pick(-1, 0); }
            else { r = 0; }
        } else if (d === 5) {
            r = u === 0 ? pick(-52, 52) : u <= 1560 ? pick(-51, 52) : pick(-52, 51);
        } else if (d === 4) {
            r = u === 0 ? pick(-104, 104) : u <= 1456 ? pick(-103, 104) : pick(-104, 103);
        } else {
            throw new Error('kemeleon: no preimage sampler for d = ' + d);
        }
        return modq(u + r);
    }

    /* the ciphertext's coefficients, compressed, and their uniform preimages */
    function ct_coeffs(ct) {
        if (!(ct instanceof Uint8Array) || ct.length !== CT_BYTES) { throw new Error('kemeleon: wrong ciphertext length'); }
        var c = new Int32Array((k + 1) * N);
        for (var i = 0; i < k; i++) { unpack_bits(ct, 32 * du * i, N, du, c.subarray(N * i)); }
        unpack_bits(ct, 32 * du * k, N, dv, c.subarray(N * k));
        return c;
    }
    function preimages(c, count, rng) {
        var u = new Int32Array(count);
        for (var i = 0; i < count; i++) {
            var d = i < k * N ? du : dv;
            u[i] = sample_preimage(d, decompress(c[i], d), c[i], rng);
        }
        return u;
    }
    /* Compress_du of the k polynomials of c_1, written into ct */
    function pack_c1(u, ct) {
        var cc = new Int32Array(N);
        for (var i = 0; i < k; i++) {
            for (var j = 0; j < N; j++) { cc[j] = compress(u[N * i + j], du); }
            pack_bits(cc, du, ct, 32 * du * i);
        }
    }

    /* ---------------- the rejection-sampling variant (section 5.1) ---------------- */

    /* b = floor(log2(q^(k n))) for the vector of `polys` polynomials; the integer takes ceil(b / 8) bytes */
    function r_bits(polys) { return (QB ** BigInt(polys * N)).toString(2).length - 1; }
    var RB = r_bits(k), RBYTES = Math.ceil(RB / 8);

    function vector_encode_r(a, rng) {
        var r = to_int(a, 0, k * N);
        if ((r >> BigInt(RB)) !== 0n) { return null; }          /* msb(r) = 1: reject */
        var bytes = bigint_to_bytes(r, RBYTES);
        var x = 8 - (RB % 8);
        bytes[0] |= rng(1)[0] & ((0xff << (8 - x)) & 0xff);      /* IntegerRandomizeUnused */
        return bytes;
    }
    function vector_decode_r(bytes, out) {
        var b = new Uint8Array(bytes), x = 8 - (RB % 8);
        b[0] &= 0xff >> x;                                       /* IntegerClearUnused */
        from_int(bytes_to_bigint(b), k * N, out, 0);
    }

    var API = {
        level: level, t: T,
        /** the bytes encode_ek draws for each polynomial's m, which it reads little-endian */
        M_BYTES: MBYTES,
        /** the sizes of section 4.4 (t = 76) or larger */
        EK_BYTES: POLY * k + 32,
        CT_BYTES: POLY * (k + 1),
        EK_R_BYTES: RBYTES + 32,
        CT_R_BYTES: RBYTES + 32 * dv,

        /**
         * EncodeEk. Never fails.
         *
         * @param {Uint8Array} ek   an ML-KEM encapsulation key
         * @param {function}   [rng]  the secret randomness; omitted or null
         *                            draws it from the platform
         * @param {Array}      [ms] the k values of m, instead of rng - test vectors only
         */
        encode_ek: function (ek, rng, ms) {
            if (!ms) { rng = require_rng('kemeleon.encode_ek', rng); }
            var s = split_ek(ek), parts = [];
            for (var i = 0; i < k; i++) { parts.push(vector_encode(s.a, N * i, ms && ms[i], rng)); }
            parts.push(s.rho);
            return concat(parts);
        },

        /**
         * DecodeEk. EVERY byte string of EK_BYTES decodes to a valid key - the
         * property the KEM-based PAKEs need ("binary").
         */
        decode_ek: function (eek) {
            if (!(eek instanceof Uint8Array) || eek.length !== API.EK_BYTES) { throw new Error('kemeleon: wrong encoded key length'); }
            var a = new Int32Array(k * N);
            for (var i = 0; i < k; i++) { vector_decode(eek.subarray(POLY * i, POLY * (i + 1)), a, N * i); }
            return join_ek(a, eek.subarray(POLY * k));
        },

        /** EncodeCtxt. Never fails. */
        encode_ctxt: function (ct, rng) {
            rng = require_rng('kemeleon.encode_ctxt', rng);
            var u = preimages(ct_coeffs(ct), (k + 1) * N, rng), parts = [];
            for (var i = 0; i <= k; i++) { parts.push(vector_encode(u, N * i, undefined, rng)); }
            return concat(parts);
        },

        /** DecodeCtxt. */
        decode_ctxt: function (ec) {
            if (!(ec instanceof Uint8Array) || ec.length !== API.CT_BYTES) { throw new Error('kemeleon: wrong encoded ciphertext length'); }
            var u = new Int32Array((k + 1) * N);
            for (var i = 0; i <= k; i++) { vector_decode(ec.subarray(POLY * i, POLY * (i + 1)), u, N * i); }
            var ct = new Uint8Array(CT_BYTES);
            pack_c1(u, ct);
            var cv = new Int32Array(N);
            for (var j = 0; j < N; j++) { cv[j] = compress(u[k * N + j], dv); }
            pack_bits(cv, dv, ct, 32 * du * k);
            return ct;
        },

        /** EncodeEkR: smaller, or NULL - the caller generates a fresh key and retries. */
        encode_ek_r: function (ek, rng) {
            rng = require_rng('kemeleon.encode_ek_r', rng);
            var s = split_ek(ek), r = vector_encode_r(s.a, rng);
            return r === null ? null : concat([r, s.rho]);
        },

        decode_ek_r: function (eek) {
            if (!(eek instanceof Uint8Array) || eek.length !== API.EK_R_BYTES) { throw new Error('kemeleon: wrong encoded key length'); }
            var a = new Int32Array(k * N);
            vector_decode_r(eek.subarray(0, RBYTES), a);
            return join_ek(a, eek.subarray(RBYTES));
        },

        /**
         * EncodeCtxtR: c_1 through the rejection encoding, c_2 kept as it is
         * but each zero coefficient rejected with probability 1/ceil(q/2^dv),
         * which makes it uniform. NULL means re-encapsulate and retry.
         */
        encode_ctxt_r: function (ct, rng) {
            rng = require_rng('kemeleon.encode_ctxt_r', rng);
            var c = ct_coeffs(ct), u = preimages(c, k * N, rng);
            var r = vector_encode_r(u, rng);
            if (r === null) { return null; }
            var den = BigInt(Math.ceil(Q / (1 << dv)));
            for (var j = 0; j < N; j++) {
                if (c[k * N + j] === 0 && bytes_to_bigint_le(rng(8)) % den === 0n) { return null; }
            }
            return concat([r, ct.subarray(32 * du * k)]);
        },

        decode_ctxt_r: function (ec) {
            if (!(ec instanceof Uint8Array) || ec.length !== API.CT_R_BYTES) { throw new Error('kemeleon: wrong encoded ciphertext length'); }
            var u = new Int32Array(k * N);
            vector_decode_r(ec.subarray(0, RBYTES), u);
            var ct = new Uint8Array(CT_BYTES);
            pack_c1(u, ct);
            ct.set(ec.subarray(RBYTES), 32 * du * k);
            return ct;
        }
    };
    return API;
}
