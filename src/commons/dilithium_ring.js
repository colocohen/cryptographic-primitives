/**
 * The ring Z_8380417[X]/(X^256 + 1), the arithmetic underneath ML-DSA
 *
 * Same shape as commons/kyber_ring.js and a different modulus, which is
 * enough to change the answer to every implementation question - including
 * one that the C reference gets right and JavaScript cannot copy.
 *
 * NO MONTGOMERY REDUCTION HERE, AND THAT IS DELIBERATE.
 *
 * Every C implementation of Dilithium uses Montgomery arithmetic with
 * R = 2^32, because a division by q is expensive and a shift is not. Ported
 * directly it is WRONG in JavaScript: the reduction computes a - t*q where t
 * is a full int32 and q is 23 bits, so the product reaches 2^54 - past the
 * 2^53 where a double is still exact. The first version of this file did
 * exactly that, measured 127.6 K NTT/s, and failed every round trip.
 *
 * The correct approach here is the opposite of the C one. If coefficients are
 * kept reduced in [0, q), the product of two of them is at most 2^46, which
 * is comfortably exact, so a plain modulo works and Montgomery's whole reason
 * for existing disappears.
 *
 * MEASURED, with coefficients kept reduced:
 *
 *     Int32Array, conditional add/sub    68.8 K NTT/s
 *     Float64Array, conditional          59.7
 *     Int32Array, % everywhere           27.0
 *
 * Replacing the two modulos on the butterfly's add and subtract with a
 * comparison is worth 2.5x on its own: the values are already within one q of
 * the range, so a conditional correction is all that is needed.
 *
 * FOUR LAYERS OF THIS LIBRARY, FOUR DIFFERENT ANSWERS, all measured:
 *
 *     64-bit hashes    hi/lo int32 pairs   BigInt lost 5-12x
 *     256-bit fields   BigInt              manual limbs lost 4.4x
 *     12-bit ML-KEM    Int16Array          beat Int32Array by 3x
 *     23-bit ML-DSA    Int32Array, no Montgomery
 */

import { bit_reverse } from './bitpack.js';

export var Q = 8380417;          /* 2^23 - 2^13 + 1 */
export var N = 256;
export var D = 13;               /* bits dropped from t in the public key */

/**
 * Reduce into [0, q).
 *
 * commons/kyber_ring.js has a function of the same name and the same three lines, over a
 * DIFFERENT modulus. They are not shareable without passing q into a
 * per-coefficient loop, and "reduce modulo a constant" is an expression
 * rather than a mechanism - the criterion this library uses for what belongs
 * in commons. The same reasoning applies to poly_reduce below.
 *
 * Compare commons/gf256.js, where gmul IS shared and takes the polynomial as
 * an argument: that one is a real algorithm with three callers, not a modulo.
 */
export function to_positive(a) {
    var r = a % Q;
    return r < 0 ? r + Q : r;
}

/**
 * Twiddle factors: powers of 1753, a primitive 512th root of unity modulo q,
 * in bit-reversed order and PLAIN form - not Montgomery, per the note above.
 *
 * GENERATED, NOT TRANSCRIBED. The published table is 256 entries, and this
 * project has been burned three times by hand-copied constants. Generation
 * uses BigInt because 1753^255 overflows a double long before the modulo;
 * that cost is paid once at load.
 */
export var ZETAS = /* @__PURE__ */ (function () {
    var z = new Int32Array(N);
    var q = BigInt(Q);
    for (var i = 0; i < N; i++) {
        var r = bit_reverse(i, 8);
        var v = 1n;
        for (var k = 0; k < r; k++) { v = (v * 1753n) % q; }
        z[i] = Number(v);
    }
    return z;
}());

/**
 * The forward NTT, in place.
 *
 * Eight layers, not Kyber's seven: q is 1 modulo 512 here, so X^256+1 splits
 * all the way into linear factors and the transform is COMPLETE. That is why
 * multiplication in the transformed domain is plain pointwise below, where
 * Kyber needed a quadratic base case.
 */
export function ntt(a) {
    var k = 0;
    for (var len = 128; len > 0; len >>= 1) {
        for (var start = 0; start < N; start += 2 * len) {
            var zeta = ZETAS[++k];
            for (var j = start; j < start + len; j++) {
                /* the product is at most 2^46 - exact in a double */
                var t = (zeta * a[j + len]) % Q;
                var u = a[j];
                /* both operands are already in range, so one comparison
                   replaces a modulo - worth 2.5x, measured */
                a[j + len] = u - t < 0 ? u - t + Q : u - t;
                a[j] = u + t >= Q ? u + t - Q : u + t;
            }
        }
    }
}

/**
 * The inverse NTT, in place, including the scaling by n^-1.
 *
 * Eight layers, not Kyber's seven: q is 1 modulo 512 here, so X^256+1 splits
 * all the way into linear factors and the transform is COMPLETE. That is why
 * multiplication in the transformed domain is plain pointwise below, where
 * Kyber needed a quadratic base case.
 */
export function ntt_inverse(a) {
    var k = N;
    for (var len = 1; len < N; len <<= 1) {
        for (var start = 0; start < N; start += 2 * len) {
            var zeta = Q - ZETAS[--k];
            for (var j = start; j < start + len; j++) {
                var u = a[j], v = a[j + len];
                a[j] = u + v >= Q ? u + v - Q : u + v;
                var d2 = u - v < 0 ? u - v + Q : u - v;
                a[j + len] = (zeta * d2) % Q;
            }
        }
    }
    /* n^-1 mod q, applied once at the end */
    for (var i = 0; i < N; i++) { a[i] = (N_INV * a[i]) % Q; }
}

/* 256^-1 mod q, computed rather than transcribed */
var N_INV = /* @__PURE__ */ (function () {
    var e = Q - 2, base = 256, r = 1;
    /* modular exponentiation with a 46-bit product bound */
    while (e > 0) {
        if (e & 1) { r = (r * base) % Q; }
        base = (base * base) % Q;
        e = Math.floor(e / 2);
    }
    return r;
}());

/** Pointwise multiplication in the NTT domain. */
export function poly_mul(r, a, b) {
    for (var i = 0; i < N; i++) { r[i] = (a[i] * b[i]) % Q; }
}

export function poly_add(r, a, b) {
    for (var i = 0; i < N; i++) { var t = a[i] + b[i]; r[i] = t >= Q ? t - Q : t; }
}

export function poly_sub(r, a, b) {
    for (var i = 0; i < N; i++) { var t = a[i] - b[i]; r[i] = t < 0 ? t + Q : t; }
}

export function poly_reduce(a) { for (var i = 0; i < N; i++) { a[i] = to_positive(a[i]); } }
export function poly_new() { return new Int32Array(N); }

/*
 * For commons/module_lattice.js: candidates are 23 bits, one per 3 bytes,
 * five SHAKE128 blocks first; products are already reduced, so a sum of them
 * needs nothing more.
 */
export var UNIFORM_BITS = 23, UNIFORM_BLOCKS = 5;
export function dot_finish() {}

/**
 * Multiply every coefficient by 2^D, for reconstructing t from t1.
 *
 * Exported and unused for a while, while ml_dsa.js verify and
 * ml_dsa_threshold.js each wrote `to_positive(t1 << D)` inline; both now call
 * this (through ml_dsa's t1_hat). No reduction is needed: t1 is 10 bits, and
 * 1023 * 2^13 = 8380416 is q - 1.
 */
export function poly_shift_left(a) {
    for (var i = 0; i < N; i++) { a[i] <<= D; }
}

/**
 * A copy of a, reduced into [0, q) and transformed - the operation callers
 * otherwise spelled `Int32Array.from(x); ntt(x)` (seven times in ml_dsa.js)
 * or with to_positive first (ml_dsa.js t0, and ml_dsa_threshold.js's
 * to_ntt, for signed vectors). The reduction is what lets one helper serve
 * both: on a polynomial already in [0, q) it changes nothing.
 */
export function ntt_copy(a) {
    var t = new Int32Array(N);
    for (var i = 0; i < N; i++) { t[i] = to_positive(a[i]); }
    ntt(t);
    return t;
}

/** ntt_copy over a vector of polynomials. */
export function vec_ntt(v) {
    var out = [];
    for (var i = 0; i < v.length; i++) { out.push(ntt_copy(v[i])); }
    return out;
}

/** @return {boolean} true when any coefficient exceeds the bound */
export function poly_chknorm(a, bound) {
    if (bound > (Q - 1) / 8) { return true; }
    for (var i = 0; i < N; i++) {
        if (smod_abs(a[i]) >= bound) { return true; }
    }
    return false;
}

/** The centred representative of a, in (-q/2, q/2]. */
export function smod(a) {
    var r = to_positive(a);
    return r > (Q >> 1) ? r - Q : r;
}

function smod_abs(a) { var v = smod(a); return v < 0 ? -v : v; }
