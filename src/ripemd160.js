/**
 * RIPEMD-160
 *
 * Designed in Europe in 1996 as an alternative to SHA-1, at a time when there
 * were concerns about NSA influence on the SHA design.
 *
 * Structurally unusual: two parallel lines of 80 rounds each, with entirely
 * different constants, permutations and rotations, merging only at the end.
 * That is built-in defence - an attack has to break both at once.
 *
 * Not broken. No known collision. But it has also not been analysed as deeply
 * as SHA-2, so it is not the choice for a new system.
 *
 * Main use: address derivation in Bitcoin and its descendants -
 *   public_key -> SHA-256 -> RIPEMD-160 -> 20 bytes
 * and all of BIP32/BIP44 rests on this.
 *
 * Little-endian, like MD5.
 */

import { md_hash, md_create } from './commons/merkle_damgard.js';

var BLOCK_SIZE  = 64;
var DIGEST_SIZE = 20;

var IV = new Int32Array([
    0x67452301|0, 0xefcdab89|0, 0x98badcfe|0, 0x10325476|0, 0xc3d2e1f0|0
]);

/* Message word index per round - left line */
var RL = new Int32Array([
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
]);

/* Message word index per round - right line */
var RR = new Int32Array([
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
]);

/* Rotation amount per round - left line */
var SL = new Int32Array([
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
]);

/* Rotation amount per round - right line */
var SR = new Int32Array([
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
]);

/* One constant per group of 16 rounds */
var KL = new Int32Array([0x00000000|0, 0x5a827999|0, 0x6ed9eba1|0, 0x8f1bbcdc|0, 0xa953fd4e|0]);
var KR = new Int32Array([0x50a28be6|0, 0x5c4dd124|0, 0x6d703ef3|0, 0x7a6d76e9|0, 0x00000000|0]);

/**
 * The five boolean functions, selected by round number.
 * The right line runs them in reverse order - j versus 4-j.
 */
function bool_fn(j, x, y, z) {
    if (j < 16) { return x ^ y ^ z; }
    if (j < 32) { return (x & y) | (~x & z); }
    if (j < 48) { return (x | ~y) ^ z; }
    if (j < 64) { return (x & z) | (y & ~z); }
    return x ^ (y | ~z);
}

/**
 * Compresses one 64-byte block from buf[off..off+63] into H.
 * Words are read little-endian.
 */
function compress(H, buf, off, W) {
    var i, t, s, k;

    for (i = 0; i < 16; i++) {
        W[i] = ((buf[off + 3] << 24) | (buf[off + 2] << 16) |
                (buf[off + 1] << 8) | buf[off]) | 0;
        off += 4;
    }

    /* left line */
    var al = H[0], bl = H[1], cl = H[2], dl = H[3], el = H[4];
    /* right line - starts from the same values, then diverges completely */
    var ar = H[0], br = H[1], cr = H[2], dr = H[3], er = H[4];

    for (i = 0; i < 80; i++) {
        k = KL[(i / 16) | 0];
        t = (((al + bool_fn(i, bl, cl, dl)) | 0) + W[RL[i]]) | 0;
        t = (t + k) | 0;
        s = SL[i];
        t = (((t << s) | (t >>> (32 - s))) + el) | 0;
        al = el; el = dl;
        dl = ((cl << 10) | (cl >>> 22)) | 0;
        cl = bl; bl = t;

        k = KR[(i / 16) | 0];
        t = (((ar + bool_fn(79 - i, br, cr, dr)) | 0) + W[RR[i]]) | 0;
        t = (t + k) | 0;
        s = SR[i];
        t = (((t << s) | (t >>> (32 - s))) + er) | 0;
        ar = er; er = dr;
        dr = ((cr << 10) | (cr >>> 22)) | 0;
        cr = br; br = t;
    }

    /* Merge the two lines - shifted by one relative to each other */
    t    = (((H[1] + cl) | 0) + dr) | 0;
    H[1] = (((H[2] + dl) | 0) + er) | 0;
    H[2] = (((H[3] + el) | 0) + ar) | 0;
    H[3] = (((H[4] + al) | 0) + br) | 0;
    H[4] = (((H[0] + bl) | 0) + cr) | 0;
    H[0] = t;
}

var PARAMS = {
    compress:      compress,
    iv:            IV,
    w_size:        16,
    block_size:    64,
    len_field:     8,
    digest_size:   20,
    little_endian: true
};

/**
 * @param  {Uint8Array} msg
 * @return {Uint8Array} 20 bytes
 */
export var ripemd160 = /* @__PURE__ */ (function () {
    function ripemd160(msg) { return md_hash(PARAMS, msg); }
    ripemd160.BLOCK_SIZE = 64;
    ripemd160.DIGEST_SIZE = 20;
    ripemd160.create = ripemd160_create;
    return ripemd160;
}());

/**
 * The same hash, fed in pieces: update() as often as needed, digest() once;
 * copy() forks the state. See md_create in commons/merkle_damgard.js.
 */
export function ripemd160_create() { return md_create(PARAMS); }
