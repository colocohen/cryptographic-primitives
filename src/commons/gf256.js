/**
 * Arithmetic in GF(2^8), and the S-boxes built from it
 *
 * Extracted when ARIA arrived: its first substitution box IS the AES S-box,
 * and its third is the AES inverse. That is not a coincidence of values - the
 * ARIA specification says to use AES's box - so it is a real dependency and
 * belongs in one place.
 *
 * The field is GF(2^8) modulo x^8 + x^4 + x^3 + x + 1, the AES polynomial.
 *
 * Every table here is DERIVED rather than transcribed. A 256-entry table
 * copied by hand is 256 chances to be wrong, and exactly one wrong entry in
 * an earlier version of aes.js survived the AES-128 test vector - the byte
 * 0x01 is simply never substituted there - and was caught only by AES-192.
 * The bijection check at the bottom would have caught it immediately.
 */

/** The AES reduction polynomial, x^8+x^4+x^3+x+1, as its low byte. */
export var POLY_AES = 0x1b;

/** Whirlpool's field, x^8+x^4+x^3+x^2+1. A DIFFERENT field. */
export var POLY_WHIRLPOOL = 0x1d;

/**
 * Kuznyechik's field: x^8 + x^7 + x^6 + x + 1.
 *
 * A third field with the same name and different arithmetic, which is why
 * gmul takes the polynomial rather than assuming one. Kuznyechik's linear
 * layer is an LFSR over this field rather than a fixed matrix, so the
 * multiplication is by a different constant at every position.
 */
export var POLY_GOST = 0xc3;

/**
 * Multiplication in GF(2^8), with the reduction polynomial given explicitly.
 *
 * The polynomial is a parameter and not a constant because this library uses
 * two of them: AES, ARIA and SM4 work modulo x^8+x^4+x^3+x+1, while
 * Whirlpool works modulo x^8+x^4+x^3+x^2+1. Those differ in one bit, produce
 * completely different results, and were originally two functions both called
 * gmul in two different files.
 *
 * That is the third time this shape has appeared here - add64 in argon2.js and
 * checksum.js differ in argument order, rd32 differed in byte order across
 * seven files. Byte order was resolved by giving the two conventions
 * different NAMES in commons/bytes.js; this one is resolved by making the
 * difference an argument, because a caller passing the wrong polynomial gets
 * a wrong answer either way and at least has to type which one it means.
 */
export function gmul(a, b, poly) {
    var p = 0;
    for (var i = 0; i < 8; i++) {
        if (b & 1) { p ^= a; }
        var hi = a & 0x80;
        a = (a << 1) & 0xff;
        if (hi) { a ^= poly; }
        b >>= 1;
    }
    return p;
}

/* Log and antilog over the generator 3, used to find inverses */
var LOG = new Uint8Array(256);
var ALOG = new Uint8Array(256);
(function () {
    var x = 1;
    for (var i = 0; i < 255; i++) { ALOG[i] = x; LOG[x] = i; x = gmul(x, 3, POLY_AES); }
}());

/**
 * The multiplicative inverse, with 0 mapping to 0.
 *
 * The modulo is not decoration: LOG[1] is 0, so 255 - LOG[1] is 255, and ALOG
 * only holds indices 0..254. Reading past it returns zero and makes the
 * inverse of 1 come out as 0 - which is the bug described above.
 */
export function inv(a) {
    return (a === 0) ? 0 : ALOG[(255 - LOG[a]) % 255];
}

/**
 * Build an S-box as inv(x) put through an affine transform.
 *
 * @param {number[]} rots  which left-rotations of the inverse to xor together
 * @param {number}   c     the constant added afterwards
 */
export function affine_sbox(rots, c) {
    var box = new Uint8Array(256);
    for (var i = 0; i < 256; i++) {
        var v = inv(i), s = 0;
        for (var r = 0; r < rots.length; r++) {
            var n = rots[r];
            s ^= ((v << n) | (v >>> (8 - n))) & 0xff;
        }
        box[i] = s ^ c;
    }
    return box;
}

/**
 * Build an S-box as inv(x) put through a general affine map.
 *
 * Needed because not every affine transform is a rotation of the input. AES's
 * is - its matrix is circulant, so xoring five rotations reproduces it - but
 * ARIA's second S-box is not, and deriving it that way produces a table that
 * is a valid bijection and completely wrong. The matrix is the honest form.
 *
 * @param {number[]} rows  eight bytes, each a matrix row, most significant
 *                         bit first
 * @param {number}   c     the constant added afterwards
 */
export function matrix_sbox(rows, c) {
    var box = new Uint8Array(256);
    for (var x = 0; x < 256; x++) {
        var v = inv(x), y = 0;
        for (var i = 0; i < 8; i++) {
            /* parity of (row AND v) becomes output bit 7-i */
            var t = rows[i] & v, p = 0;
            while (t) { p ^= t & 1; t >>= 1; }
            y |= p << (7 - i);
        }
        box[x] = y ^ c;
    }
    return box;
}

/** Invert a bijective S-box. */
export function invert_sbox(box) {
    var out = new Uint8Array(256);
    for (var i = 0; i < 256; i++) { out[box[i]] = i; }
    return out;
}

/** Throws unless the table is a permutation of 0..255. */
export function check_bijection(box, name) {
    var seen = new Uint8Array(256), i;
    for (i = 0; i < 256; i++) { seen[box[i]] = 1; }
    for (i = 0; i < 256; i++) {
        if (!seen[i]) { throw new Error(name + ': S-box is not a bijection'); }
    }
}

/**
 * The AES S-box: inv(x) xored with four rotations of itself, plus 0x63.
 * ARIA calls this SB1 and its inverse SB3.
 */
export var AES_SBOX = /* @__PURE__ */ (function () {
    var b = affine_sbox([0, 1, 2, 3, 4], 0x63);
    check_bijection(b, 'aes');
    return b;
}());

export var AES_INV_SBOX = /* @__PURE__ */ invert_sbox(AES_SBOX);
