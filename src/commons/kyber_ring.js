/**
 * The ring Z_3329[X]/(X^256 + 1), the arithmetic underneath ML-KEM
 *
 * FIPS 203's whole structure rests on this ring: keys, ciphertexts and the
 * shared secret are all vectors of polynomials in it. Its parameters were
 * chosen so that the number-theoretic transform works, which turns polynomial
 * multiplication from 256^2 coefficient products into 256 log 256 additions
 * plus 128 small products.
 *
 * REPRESENTATION, MEASURED. Coefficients are held in an Int16Array with
 * Barrett reduction:
 *
 *     Int16Array + Barrett      246.8 K NTT/s
 *     Int16Array + %            161.5
 *     Int32Array + Barrett       79.7
 *     plain Array + Barrett      46.6
 *
 * Int16Array beating Int32Array by three times is the surprise, and it is
 * memory: a polynomial is 512 bytes rather than 1024, and the NTT touches
 * every coefficient seven times.
 *
 * BigInt does not appear in that table at all. The modulus is twelve bits and
 * every intermediate fits in an int32, so the tradeoff that made BigInt the
 * right answer in commons/modp.js - where operands are 256 bits - simply does
 * not arise. Three layers of this library, three different answers, each
 * measured rather than assumed.
 */

import { bit_reverse } from './bitpack.js';

export var Q = 3329;
export var N = 256;

/*
 * Barrett reduction to (-q/2, q/2].
 *
 * A division by a compile-time constant becomes a multiply and a shift. The
 * result is SIGNED and centred on zero rather than in [0, q), which is what
 * the NTT butterflies want and which keeps intermediates inside int16.
 */
var BARRETT_V = ((1 << 26) / Q + 0.5) | 0;

export function barrett(a) {
    return a - (((BARRETT_V * a + (1 << 25)) >> 26) * Q);
}

/**
 * Reduce into [0, q).
 *
 * commons/dilithium_ring.js has a function of the same name and the same three lines, over a
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
 * Montgomery REDUCTION with R = 2^16.
 *
 * Not to be confused with commons/montgomery.js, which is the Montgomery
 * LADDER for scalar multiplication on Montgomery-form curves. Two unrelated
 * things named after the same person, and both appear in this library.
 *
 * Used for the coefficient products inside the NTT, where a plain modulo
 * would cost a division per multiplication. QINV is -q^-1 mod 2^16.
 */
var QINV = -3327;

export function montgomery(a) {
    var t = ((a * QINV) << 16) >> 16;      /* low 16 bits, signed */
    return (a - t * Q) >> 16;
}

/**
 * The twiddle factors: powers of 17, a primitive 256th root of unity modulo
 * 3329, in bit-reversed order and Montgomery form.
 *
 * GENERATED, NOT TRANSCRIBED. The published table is 128 entries and this
 * project has been burned three times by hand-copied constants - see the
 * notes in seed.js and aria.js. Deriving them costs one loop at load and
 * removes the failure mode entirely.
 */
export var ZETAS = /* @__PURE__ */ (function () {
    var z = new Int16Array(128);
    for (var i = 0; i < 128; i++) {
        /* bit-reverse i over seven bits (commons/dilithium_ring.js does the
           same over eight; the loop is shared from commons/bitpack.js) */
        var r = bit_reverse(i, 7);
        /* 17^r mod q, then into Montgomery form by multiplying by 2^16 */
        var v = 1;
        for (var k = 0; k < r; k++) { v = (v * 17) % Q; }
        var m = (v * 65536) % Q;
        z[i] = m > Q / 2 ? m - Q : m;
    }
    return z;
}());

/**
 * The forward NTT, in place.
 *
 * Seven layers of Cooley-Tukey butterflies. The transform is INCOMPLETE by
 * design: X^256+1 factors into 128 quadratics rather than 256 linears modulo
 * 3329, so the result is 128 degree-one polynomials and multiplication in the
 * transformed domain is base_mul below rather than a plain product. That is a
 * consequence of q being 1 mod 256 but not 1 mod 512.
 */
export function ntt(a) {
    var k = 1;
    for (var len = 128; len >= 2; len >>= 1) {
        for (var start = 0; start < N; start += 2 * len) {
            var zeta = ZETAS[k++];
            for (var j = start; j < start + len; j++) {
                var t = montgomery(zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
    for (var i = 0; i < N; i++) { a[i] = barrett(a[i]); }
}

/** The inverse NTT, in place, including the final scaling by n^-1. */
export function ntt_inverse(a) {
    var k = 127;
    for (var len = 2; len <= 128; len <<= 1) {
        for (var start = 0; start < N; start += 2 * len) {
            var zeta = ZETAS[k--];
            for (var j = start; j < start + len; j++) {
                var t = a[j];
                a[j] = barrett(t + a[j + len]);
                a[j + len] = a[j + len] - t;
                a[j + len] = montgomery(zeta * a[j + len]);
            }
        }
    }
    /*
     * The final scaling folds in n^-1 and the Montgomery factor.
     *
     * 512 = R/128, NOT the 1441 = R^2/128 that the C reference uses. The
     * difference is a deliberate choice of convention: the reference leaves
     * one factor of R^-1 in the output so that a later Montgomery
     * multiplication cancels it, while this implementation makes ntt and
     * ntt_inverse an exact inverse pair. Round-tripping a polynomial here
     * returns it unchanged, which is testable in isolation; with 1441 it
     * comes back multiplied by R, which is correct but only verifiable in
     * context.
     *
     * The cost is that poly_mul's output carries an R^-1 that has to be
     * removed with poly_from_mont - see its note.
     */
    for (var i = 0; i < N; i++) { a[i] = montgomery(512 * a[i]); }
}

/**
 * Multiply two degree-one polynomials modulo X^2 - zeta.
 *
 * This is the base case the incomplete NTT leaves behind, and it is why
 * Kyber's multiplication is not simply pointwise.
 */
function base_mul(r, ro, a, ao, b, bo, zeta) {
    r[ro]     = montgomery(montgomery(a[ao + 1] * b[bo + 1]) * zeta) +
                montgomery(a[ao] * b[bo]);
    r[ro + 1] = montgomery(a[ao] * b[bo + 1]) + montgomery(a[ao + 1] * b[bo]);
}

/** Multiply two polynomials already in the NTT domain. */
export function poly_mul(r, a, b) {
    for (var i = 0; i < 64; i++) {
        base_mul(r, 4 * i, a, 4 * i, b, 4 * i, ZETAS[64 + i]);
        base_mul(r, 4 * i + 2, a, 4 * i + 2, b, 4 * i + 2, -ZETAS[64 + i]);
    }
}

export function poly_add(r, a, b) {
    for (var i = 0; i < N; i++) { r[i] = a[i] + b[i]; }
}

export function poly_sub(r, a, b) {
    for (var i = 0; i < N; i++) { r[i] = a[i] - b[i]; }
}

export function poly_reduce(a) {
    for (var i = 0; i < N; i++) { a[i] = barrett(a[i]); }
}

/**
 * Convert from Montgomery form back to the standard representation.
 *
 * 1353 = 2^32 mod q. Needed after multiplying a fresh polynomial into one
 * that is already in Montgomery form.
 */
export function poly_from_mont(a) {
    for (var i = 0; i < N; i++) { a[i] = montgomery(1353 * a[i]); }
}

export function poly_new() { return new Int16Array(N); }

/*
 * For commons/module_lattice.js: candidates are 12 bits, two per 3 bytes,
 * and four SHAKE128 blocks cover a polynomial most of the time; a sum of
 * NTT-domain products carries R^-1 (poly_mul's convention, above), so it is
 * taken out and reduced before use - inside row_dot, not by its callers.
 * Leaving it to callers was a bug in ml_kem.js once: key generation removed
 * it, encryption and decryption did not, and a key pair that matched the
 * reference exactly came with ciphertexts that decrypted to nothing.
 */
export var UNIFORM_BITS = 12, UNIFORM_BLOCKS = 4;
export function dot_finish(a) { poly_from_mont(a); poly_reduce(a); }
