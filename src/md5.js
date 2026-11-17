/**
 * MD5  -  RFC 1321
 *
 * Thoroughly broken. Collisions are produced in seconds on a laptop.
 * Present here for compatibility only - file checksums, ETags, legacy
 * protocols. Never for signatures, passwords, or integrity against an
 * adversary.
 *
 * Note: MD5 is little-endian, unlike the entire SHA family.
 */

import { md_hash, md_create } from './commons/merkle_damgard.js';

var BLOCK_SIZE  = 64;
var DIGEST_SIZE = 16;

var IV = new Int32Array([
    0x67452301|0, 0xefcdab89|0, 0x98badcfe|0, 0x10325476|0
]);

/* K[i] = floor(2^32 * abs(sin(i+1))) */
var K = new Int32Array([
    0xd76aa478|0, 0xe8c7b756|0, 0x242070db|0, 0xc1bdceee|0,
    0xf57c0faf|0, 0x4787c62a|0, 0xa8304613|0, 0xfd469501|0,
    0x698098d8|0, 0x8b44f7af|0, 0xffff5bb1|0, 0x895cd7be|0,
    0x6b901122|0, 0xfd987193|0, 0xa679438e|0, 0x49b40821|0,
    0xf61e2562|0, 0xc040b340|0, 0x265e5a51|0, 0xe9b6c7aa|0,
    0xd62f105d|0, 0x02441453|0, 0xd8a1e681|0, 0xe7d3fbc8|0,
    0x21e1cde6|0, 0xc33707d6|0, 0xf4d50d87|0, 0x455a14ed|0,
    0xa9e3e905|0, 0xfcefa3f8|0, 0x676f02d9|0, 0x8d2a4c8a|0,
    0xfffa3942|0, 0x8771f681|0, 0x6d9d6122|0, 0xfde5380c|0,
    0xa4beea44|0, 0x4bdecfa9|0, 0xf6bb4b60|0, 0xbebfbc70|0,
    0x289b7ec6|0, 0xeaa127fa|0, 0xd4ef3085|0, 0x04881d05|0,
    0xd9d4d039|0, 0xe6db99e5|0, 0x1fa27cf8|0, 0xc4ac5665|0,
    0xf4292244|0, 0x432aff97|0, 0xab9423a7|0, 0xfc93a039|0,
    0x655b59c3|0, 0x8f0ccc92|0, 0xffeff47d|0, 0x85845dd1|0,
    0x6fa87e4f|0, 0xfe2ce6e0|0, 0xa3014314|0, 0x4e0811a1|0,
    0xf7537e82|0, 0xbd3af235|0, 0x2ad7d2bb|0, 0xeb86d391|0
]);

/* Rotation amount per round */
var S = new Int32Array([
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]);

/**
 * Compresses one 64-byte block from buf[off..off+63] into H.
 * Words are read little-endian.
 */
function compress(H, buf, off, W) {
    var i, f, g, t, s;

    for (i = 0; i < 16; i++) {
        W[i] = ((buf[off + 3] << 24) | (buf[off + 2] << 16) |
                (buf[off + 1] << 8) | buf[off]) | 0;
        off += 4;
    }

    var a = H[0], b = H[1], c = H[2], d = H[3];

    for (i = 0; i < 64; i++) {
        if (i < 16)      { f = (b & c) | (~b & d);     g = i; }
        else if (i < 32) { f = (d & b) | (~d & c);     g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;              g = (3 * i + 5) & 15; }
        else             { f = c ^ (b | ~d);           g = (7 * i) & 15; }

        t = (((((a + f) | 0) + K[i]) | 0) + W[g]) | 0;
        s = S[i];

        a = d;
        d = c;
        c = b;
        b = (b + (((t << s) | (t >>> (32 - s))) | 0)) | 0;
    }

    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
}

var PARAMS = {
    compress:      compress,
    iv:            IV,
    w_size:        16,
    block_size:    64,
    len_field:     8,
    digest_size:   16,
    little_endian: true
};

/**
 * @param  {Uint8Array} msg
 * @return {Uint8Array} 16 bytes
 */
export var md5 = /* @__PURE__ */ (function () {
    function md5(msg) { return md_hash(PARAMS, msg); }
    md5.BLOCK_SIZE = 64;
    md5.DIGEST_SIZE = 16;
    md5.create = md5_create;
    return md5;
}());

/**
 * The same hash, fed in pieces: update() as often as needed, digest() once;
 * copy() forks the state. See md_create in commons/merkle_damgard.js.
 */
export function md5_create() { return md_create(PARAMS); }
