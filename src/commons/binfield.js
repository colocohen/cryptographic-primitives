/**
 * GF(2^k) for k = 128, 192, 256 (and 384, 576, 768) in the plain polynomial basis
 *
 * An element is a polynomial over GF(2) of degree < k, bit i the coefficient
 * of x^i, held as k/32 little-endian 32-bit words (word 0 = bits 0..31) and
 * serialised little-endian. The moduli are the ones the VOLE-in-the-head
 * signatures fix (FAEST, SDitH):
 *
 *   GF(2^128): x^128 + x^7 + x^2 + x + 1
 *   GF(2^192): x^192 + x^7 + x^2 + x + 1
 *   GF(2^256): x^256 + x^10 + x^5 + x^2 + 1
 *
 * and, for FAEST's leaf hashes over 3 lambda bits,
 *
 *   GF(2^384): x^384 + x^12 + x^3 + x^2 + 1
 *   GF(2^576): x^576 + x^13 + x^4 + x^3 + 1
 *   GF(2^768): x^768 + x^19 + x^17 + x^4 + 1
 *
 * This is NOT the bit-reflected GF(2^128) of GHASH (gf128.js): same modulus
 * at 128 bits, opposite bit order.
 *
 * Elements live at an offset inside a Uint32Array, so vectors are one flat
 * array with stride W = k/32; every operation takes (array, offset) pairs and
 * may alias its inputs.
 */

var LOW = { 128: 0x87, 192: 0x87, 256: 0x425, 384: 0x100d, 576: 0x2019, 768: 0xa0011 };
var FIELDS = {};

/** The field with 2^bits elements (bits = 128, 192, 256, 384, 576 or 768). */
export function binary_field(bits) {
    if (FIELDS[bits]) { return FIELDS[bits]; }
    var low = LOW[bits];
    if (!low) { throw new Error('binfield: 128, 192, 256, 384, 576 or 768 bits'); }
    var W = bits / 32, B = bits / 8, NIB = bits / 4, TW = W + 1;
    var T = new Uint32Array(16 * TW), acc = new Uint32Array(2 * W + 1), LB = [];
    for (var k = 0; k < 31; k++) { if ((low >> k) & 1) { LB.push(k); } }

    /* out = a * b */
    function mul(out, oo, a, ao, b, bo) {
        var i, j, t, n, c;
        for (j = 0; j < TW; j++) { T[j] = 0; T[TW + j] = j < W ? a[ao + j] : 0; }
        for (t = 2; t < 16; t++) {
            if (t & 1) { for (j = 0; j < TW; j++) { T[t * TW + j] = T[(t - 1) * TW + j] ^ T[TW + j]; } }
            else {
                for (j = TW - 1, c = t >> 1; j > 0; j--) { T[t * TW + j] = (T[c * TW + j] << 1) | (T[c * TW + j - 1] >>> 31); }
                T[t * TW] = T[c * TW] << 1;
            }
        }
        acc.fill(0);
        for (i = NIB - 1; i >= 0; i--) {
            for (j = 2 * W; j > 0; j--) { acc[j] = (acc[j] << 4) | (acc[j - 1] >>> 28); }
            acc[0] <<= 4;
            n = (b[bo + (i >> 3)] >>> ((i & 7) << 2)) & 15;
            if (n) { for (j = 0, t = n * TW; j < TW; j++) { acc[j] ^= T[t + j]; } }
        }
        reduce(out, oo);
    }
    /* out = acc mod p, acc holding up to 2W words */
    function reduce(out, oo) {
        for (var i = 2 * W - 1; i >= W; i--) {
            var v = acc[i];
            if (!v) { continue; }
            acc[i] = 0;
            for (var q = 0; q < LB.length; q++) {
                var s = LB[q];
                acc[i - W] ^= v << s;
                if (s) { acc[i - W + 1] ^= v >>> (32 - s); }
            }
        }
        for (var j = 0; j < W; j++) { out[oo + j] = acc[j]; }
    }
    /* out = a * x^s, 0 <= s < 32 * W */
    function mul_xpow(out, oo, a, ao, s) {
        var ws = s >>> 5, bs = s & 31, i;
        acc.fill(0);
        for (i = 0; i < W; i++) {
            acc[i + ws] ^= a[ao + i] << bs;
            if (bs) { acc[i + ws + 1] ^= a[ao + i] >>> (32 - bs); }
        }
        reduce(out, oo);
    }
    function add(out, oo, a, ao, b, bo) { for (var j = 0; j < W; j++) { out[oo + j] = a[ao + j] ^ b[bo + j]; } }
    function copy(out, oo, a, ao) { for (var j = 0; j < W; j++) { out[oo + j] = a[ao + j]; } }
    function is_zero(a, ao) { var z = 0; for (var j = 0; j < W; j++) { z |= a[ao + j]; } return z === 0; }
    /* out = a^(2^bits - 2), the inverse of a nonzero a */
    function inv(out, oo, a, ao) {
        var r = new Uint32Array(W), s = new Uint32Array(W);
        r[0] = 1;
        copy(s, 0, a, ao);
        for (var e = 1; e < bits; e++) { mul(s, 0, s, 0, s, 0); mul(r, 0, r, 0, s, 0); }
        copy(out, oo, r, 0);
    }
    /* out = a^p */
    /* out = a^p, p a number or a bigint (exponents up to 2^bits) */
    function pow(out, oo, a, ao, p) {
        var r = new Uint32Array(W), s = new Uint32Array(W), e = BigInt(p), one = BigInt(1);
        r[0] = 1; copy(s, 0, a, ao);
        for (; e > 0; e >>= one) {
            if (e & one) { mul(r, 0, r, 0, s, 0); }
            if (e > one) { mul(s, 0, s, 0, s, 0); }
        }
        copy(out, oo, r, 0);
    }
    /* n elements from bytes (B each) and back */
    function from_bytes(bytes, off, n, out, oo) {
        out = out || new Uint32Array(n * W); oo = oo || 0;
        for (var i = 0; i < n * W; i++) {
            var p = off + 4 * i;
            out[oo + i] = bytes[p] | (bytes[p + 1] << 8) | (bytes[p + 2] << 16) | (bytes[p + 3] << 24);
        }
        return out;
    }
    function to_bytes(a, ao, n, out, off) {
        out = out || new Uint8Array(n * B); off = off || 0;
        for (var i = 0; i < n * W; i++) {
            var v = a[ao + i], p = off + 4 * i;
            out[p] = v & 0xff; out[p + 1] = (v >>> 8) & 0xff; out[p + 2] = (v >>> 16) & 0xff; out[p + 3] = v >>> 24;
        }
        return out;
    }
    return (FIELDS[bits] = {
        BITS: bits, W: W, BYTES: B,
        mul: mul, mul_xpow: mul_xpow, add: add, copy: copy, is_zero: is_zero, inv: inv, pow: pow,
        from_bytes: from_bytes, to_bytes: to_bytes
    });
}
