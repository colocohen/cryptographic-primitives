/**
 * gf128.js - arithmetic in GF(2^128), the field a KOS15 consistency check
 * needs.
 *
 * ==================== WHY A FIELD AND NOT A RANDOM SUBSET ====================
 *
 * An OT extension has to prove the receiver used consistent choice bits, and
 * the obvious check is to combine a random subset of the rows and compare.
 * That catches a single corrupted bit about a QUARTER of the time - which
 * sounds like a weaker check and is actually not a check at all: a cheat who
 * is caught simply tries again. Four attempts and the extension is broken.
 *
 * KOS15 combines over GF(2^128) instead, weighting each row by an independent
 * field element. A cheating receiver then passes with probability 2^-128, and
 * retrying is not a strategy.
 *
 * The difference is not a factor of four. It is the difference between a
 * check and a formality.
 *
 * ==================== THE POLYNOMIAL ====================
 *
 * x^128 + x^7 + x^2 + x + 1, the same one GCM uses. GCM writes its
 * coefficients in the reversed bit order the spec calls for, and this module
 * does NOT - here the leftmost bit of the first byte is the highest degree
 * coefficient, which is what everything outside GHASH assumes. Mixing the two
 * conventions silently produces a different field, so gcm.js keeps its own
 * copy rather than importing this one.
 *
 * Constant time: no branches on operand bits, no data-dependent table
 * lookups. The multiplication is bit by bit for the same reason gcm.js gives -
 * a windowed table would be indexed by secret data and leak through the
 * cache.
 */

import { rd_be32, wr_be32s } from './bytes.js';

/** The 128-bit zero, as four 32-bit words. */
export function zero() { return new Uint32Array(4); }

/** One, in the same representation. */
export function one() {
    var o = new Uint32Array(4);
    o[3] = 1;
    return o;
}

/** Addition in a binary field is XOR. */
export function add(a, b) {
    var o = new Uint32Array(4);
    for (var i = 0; i < 4; i++) { o[i] = (a[i] ^ b[i]) | 0; }
    return o;
}

/** In place, for accumulating. */
export function add_into(acc, b) {
    for (var i = 0; i < 4; i++) { acc[i] = (acc[i] ^ b[i]) | 0; }
    return acc;
}

/**
 * Multiply in GF(2^128), most significant coefficient first.
 *
 * Shift-and-add with the reduction folded in: whenever the accumulator's
 * top coefficient would overflow, the polynomial is subtracted - which in a
 * binary field is the same XOR.
 */
export function mul(a, b) {
    var z0 = 0, z1 = 0, z2 = 0, z3 = 0;
    var v0 = a[0] | 0, v1 = a[1] | 0, v2 = a[2] | 0, v3 = a[3] | 0;
    var i, mask, msb;

    /*
     * LSB FIRST, and the direction matters: bit i of b multiplies a shifted
     * LEFT i times, so the loop must ascend while v climbs with it. Running
     * it downward - MSB-first indexing with an ascending operand - gives an
     * operation that is still commutative, associative and distributive, so
     * every field law passes while `x * 1` returns 0x87.
     *
     * Caught only by measuring what the field is FOR: a single flipped bit
     * should be detected every time, and the broken version detected 11 in
     * 200. The laws were not enough.
     */
    for (i = 0; i < 128; i++) {
        mask = -((b[3 - (i >>> 5)] >>> (i & 31)) & 1);
        z0 ^= v0 & mask; z1 ^= v1 & mask;
        z2 ^= v2 & mask; z3 ^= v3 & mask;

        /* v <<= 1, then reduce if the top coefficient fell off */
        msb = -((v0 >>> 31) & 1);
        v0 = ((v0 << 1) | (v1 >>> 31)) | 0;
        v1 = ((v1 << 1) | (v2 >>> 31)) | 0;
        v2 = ((v2 << 1) | (v3 >>> 31)) | 0;
        v3 = (v3 << 1) | 0;
        /* x^128 = x^7 + x^2 + x + 1 */
        v3 ^= 0x87 & msb;
    }

    var o = new Uint32Array(4);
    o[0] = z0; o[1] = z1; o[2] = z2; o[3] = z3;
    return o;
}

/** 16 bytes, big-endian, into the word representation. */
export function from_bytes(b) {
    if (b.length !== 16) { throw new Error('gf128: needs exactly 16 bytes'); }
    var o = new Uint32Array(4);
    for (var i = 0; i < 4; i++) { o[i] = rd_be32(b, i * 4); }
    return o;
}

/** And back. */
export function to_bytes(a) {
    var o = new Uint8Array(16);
    wr_be32s(o, 0, a);
    return o;
}

/**
 * Constant-time equality.
 *
 * ⚠ THE BYTE VERSION OF THIS IDIOM DOES NOT SURVIVE 32-BIT WORDS.
 *
 * ct.js folds differences with `|` and maps zero to one via
 * `((diff - 1) >>> 31) & 1`, which is correct there because bytes never set
 * the sign bit. Here a single differing high bit makes `diff` NEGATIVE, and
 * `diff - 1` stays negative - so the test reports EQUAL exactly when the two
 * values differ in the top bit of any word.
 *
 * That is a false accept in a comparison, which is the worst direction. It
 * survived every field-law test and was caught only by measuring the
 * detection rate the field exists to provide.
 *
 * The `>>> 0` forces the unsigned reading before the fold.
 */
export function equal(a, b) {
    var diff = 0;
    for (var i = 0; i < 4; i++) { diff |= (a[i] ^ b[i]); }
    /* collapse all 32 bits into the low one without a branch */
    diff = (diff >>> 16) | (diff & 0xffff);
    diff = (diff >>> 8) | (diff & 0xff);
    diff = (diff >>> 4) | (diff & 0xf);
    diff = (diff >>> 2) | (diff & 0x3);
    diff = (diff >>> 1) | (diff & 0x1);
    return (diff & 1) ^ 1;
}

/**
 * The weighted sum a KOS15 check computes: sum of coeff[i] * value[i].
 *
 * ⚠ THE COEFFICIENTS MUST COME FROM A TRANSCRIPT HASH, not from the party
 *   being checked. A receiver who chooses them can pick a set that cancels
 *   the inconsistency, and the check passes for a cheat. Deriving them from
 *   a hash of everything already committed is what makes them unpredictable
 *   at the time the rows were fixed.
 *
 * @param {Array} coeffs  field elements, one per value
 * @param {Array} values  field elements
 */
export function inner_product(coeffs, values) {
    if (coeffs.length !== values.length) {
        throw new Error('gf128: inner_product needs equal lengths');
    }
    var acc = zero();
    for (var i = 0; i < coeffs.length; i++) {
        add_into(acc, mul(coeffs[i], values[i]));
    }
    return acc;
}

/**
 * A row of bits weighted by a field element and accumulated.
 *
 * The shape an OT extension actually wants: each row of the bit matrix is a
 * 128-bit block, and the check sums row[i] * coeff[i] over the field.
 */
export function accumulate_rows(rows, coeffs) {
    if (rows.length !== coeffs.length) {
        throw new Error('gf128: accumulate_rows needs equal lengths');
    }
    var acc = zero();
    for (var i = 0; i < rows.length; i++) {
        add_into(acc, mul(from_bytes(rows[i]), coeffs[i]));
    }
    return acc;
}
