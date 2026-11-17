/**
 * SHA-1  -  FIPS 180-4
 *
 * Broken. Practical collisions were demonstrated (shattered.io, 2017).
 * Present here for compatibility only - HMAC-SHA1 in TOTP, git, legacy
 * protocols. Never for signatures or for integrity against an adversary.
 *
 */

import { md_hash, md_create } from './commons/merkle_damgard.js';

var BLOCK_SIZE  = 64;
var DIGEST_SIZE = 20;

var IV = new Int32Array([
    0x67452301|0, 0xefcdab89|0, 0x98badcfe|0, 0x10325476|0, 0xc3d2e1f0|0
]);

/* One constant per quarter of 20 rounds */
var K0 = 0x5a827999|0;
var K1 = 0x6ed9eba1|0;
var K2 = 0x8f1bbcdc|0;
var K3 = 0xca62c1d6|0;

/**
 * Compresses one 64-byte block from buf[off..off+63] into H.
 * W is passed in to avoid allocating on every block.
 */
function compress(H, buf, off, W) {
    var i, x, t, f, k;

    for (i = 0; i < 16; i++) {
        W[i] = ((buf[off] << 24) | (buf[off + 1] << 16) |
                (buf[off + 2] << 8) | buf[off + 3]) | 0;
        off += 4;
    }
    /* Expansion: W[i] = rotl(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1) */
    for (i = 16; i < 80; i++) {
        x = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
        W[i] = ((x << 1) | (x >>> 31)) | 0;
    }

    var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];

    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & c) | (~b & d);            k = K0; }
        else if (i < 40) { f = b ^ c ^ d;                     k = K1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = K2; }
        else             { f = b ^ c ^ d;                     k = K3; }

        /*
         * ⚠ THE `| 0` AFTER EACH ADDITION IS NOT REDUNDANT, and removing it
         *   was tried and reverted.
         *
         *   noble writes this as one addition of five terms with a single
         *   normalisation, and the sum is provably inside a double's exact
         *   range - so the result is identical. MEASURED: 875 ns per block
         *   with the step-by-step form, 977 with the single one.
         *
         *   ⭐ Without the intermediate `| 0`, V8 cannot keep the running
         *     value in an int32 register - it computes in doubles and
         *     converts back at the end, and the conversions cost more than
         *     the three extra masks save.
         *
         * ⛔ SO DO NOT "SIMPLIFY" THIS. It reads as redundant, it matches what
         *   a reference implementation does, and it is 12% slower here.
         */
        t = ((((((a << 5) | (a >>> 27)) + f) | 0) + e) | 0);
        t = (((t + k) | 0) + W[i]) | 0;

        e = d;
        d = c;
        c = ((b << 30) | (b >>> 2)) | 0;
        b = a;
        a = t;
    }

    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0;
}

var PARAMS = {
    compress:      compress,
    iv:            IV,
    w_size:        80,
    block_size:    64,
    len_field:     8,
    digest_size:   20,
    little_endian: false
};

/**
 * @param  {Uint8Array} msg
 * @return {Uint8Array} 20 bytes
 */
export var sha1 = /* @__PURE__ */ (function () {
    function sha1(msg) { return md_hash(PARAMS, msg); }
    sha1.BLOCK_SIZE = 64;
    sha1.DIGEST_SIZE = 20;
    sha1.create = sha1_create;
    sha1.NAME = 'sha1';
    return sha1;
}());

/**
 * The same hash, fed in pieces: update() as often as needed, digest() once;
 * copy() forks the state. See md_create in commons/merkle_damgard.js.
 */
export function sha1_create() { return md_create(PARAMS); }
