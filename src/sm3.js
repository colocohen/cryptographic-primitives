/**
 * SM3  -  GB/T 32905-2016
 *
 * China's national hash standard, published by the OSCCA in 2010 and
 * mandatory for government and financial systems there. Where a Western
 * design would reach for SHA-256, Chinese regulation reaches for this.
 *
 * It is Merkle-Damgard with a 256-bit output and 512-bit blocks, so it plugs
 * into the same framework as SHA-256 and MD5 - only the compression function
 * differs. Structurally it sits between SHA-256 and the SHA-1 family: the
 * message schedule expands to 68 plus 64 words rather than 64, and each round
 * updates two chains at once.
 *
 * Security: no attacks better than generic on the full 64 rounds. It is
 * younger and less analysed than SHA-256, which is the honest caveat, but
 * nothing suggests weakness.
 *
 * It is also the hash inside SM2 signatures, so anything targeting Chinese
 * standards needs it before it needs anything else.
 */

import { md_hash, md_create } from './commons/merkle_damgard.js';
import { rotl32 } from './commons/bytes.js';

var BLOCK_SIZE  = 64;
var DIGEST_SIZE = 32;

/* Unlike SHA-2, these are arbitrary values rather than roots of primes */
var IV = new Int32Array([
    0x7380166f|0, 0x4914b2b9|0, 0x172442d7|0, 0xda8a0600|0,
    0xa96f30bc|0, 0x163138aa|0, 0xe38dee4d|0, 0xb0fb0e4e|0
]);

/* Two round constants, rotated by the round number */
var T0 = 0x79cc4519|0;
var T1 = 0x7a879d8a|0;

var W  = new Int32Array(68);
var W1 = new Int32Array(64);

/** P0 and P1 are the two diffusion permutations, used in different places. */
function p0(x) { return (x ^ rotl32(x, 9) ^ rotl32(x, 17)) | 0; }
function p1(x) { return (x ^ rotl32(x, 15) ^ rotl32(x, 23)) | 0; }

/**
 * Compresses one 64-byte block from buf[off..off+63] into H.
 *
 * The scratch array passed by md_hash is ignored - SM3 needs two schedules of
 * different lengths, so they are module-level here instead.
 */
function compress(H, buf, off) {
    var i, ss1, ss2, tt1, tt2, t;

    for (i = 0; i < 16; i++) {
        W[i] = ((buf[off] << 24) | (buf[off + 1] << 16) |
                (buf[off + 2] << 8) | buf[off + 3]) | 0;
        off += 4;
    }
    for (i = 16; i < 68; i++) {
        t = W[i - 16] ^ W[i - 9] ^ rotl32(W[i - 3], 15);
        W[i] = (p1(t) ^ rotl32(W[i - 13], 7) ^ W[i - 6]) | 0;
    }
    /* the second schedule is just adjacent words xored - it feeds the other chain */
    for (i = 0; i < 64; i++) { W1[i] = W[i] ^ W[i + 4]; }

    var a = H[0], b = H[1], c = H[2], d = H[3];
    var e = H[4], f = H[5], g = H[6], h = H[7];

    for (i = 0; i < 64; i++) {
        /* the constant rotates with the round, and switches value at 16 */
        var tj = (i < 16) ? rotl32(T0, i) : rotl32(T1, i & 31);

        ss1 = rotl32((((rotl32(a, 12) + e) | 0) + tj) | 0, 7);
        ss2 = ss1 ^ rotl32(a, 12);

        /* both boolean functions change form after round 16 */
        var ff = (i < 16) ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c));
        var gg = (i < 16) ? (e ^ f ^ g) : ((e & f) | (~e & g));

        tt1 = (((((ff + d) | 0) + ss2) | 0) + W1[i]) | 0;
        tt2 = (((((gg + h) | 0) + ss1) | 0) + W[i]) | 0;

        d = c;
        c = rotl32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rotl32(f, 19);
        f = e;
        e = p0(tt2);
    }

    /* SM3 xors the result in rather than adding it, unlike SHA-2 */
    H[0] ^= a; H[1] ^= b; H[2] ^= c; H[3] ^= d;
    H[4] ^= e; H[5] ^= f; H[6] ^= g; H[7] ^= h;
}

var PARAMS = {
    compress:      compress,
    iv:            IV,
    w_size:        68,
    block_size:    64,
    len_field:     8,
    digest_size:   32,
    little_endian: false
};

/**
 * @param  {Uint8Array} msg
 * @return {Uint8Array} 32 bytes
 */
export var sm3 = /* @__PURE__ */ (function () {
    function sm3(msg) { return md_hash(PARAMS, msg); }
    sm3.BLOCK_SIZE  = BLOCK_SIZE;
    sm3.DIGEST_SIZE = DIGEST_SIZE;
    sm3.create = sm3_create;
    return sm3;
}());

/**
 * The same hash, fed in pieces: update() as often as needed, digest() once;
 * copy() forks the state. See md_create in commons/merkle_damgard.js.
 */
export function sm3_create() { return md_create(PARAMS); }
