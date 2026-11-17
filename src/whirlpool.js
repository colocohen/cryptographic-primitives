/**
 * Whirlpool  -  ISO/IEC 10118-3
 *
 * Barreto and Rijmen, 2000, and revised twice before settling in 2003. One of
 * the designers is a co-author of AES, and it shows: Whirlpool is built on a
 * dedicated block cipher with the same substitution-permutation shape, run in
 * Miyaguchi-Preneel mode to turn it into a hash.
 *
 * 512-bit digest, 512-bit blocks, ten rounds over an 8x8 byte matrix.
 *
 * NOT BROKEN. There is no attack on the full function after twenty-five
 * years, and its 512-bit output leaves an enormous margin. It nevertheless
 * lost: SHA-2 was already deployed, SHA-3 arrived with a competition behind
 * it, and Whirlpool ended up standardised, respected, and used almost
 * nowhere. TrueCrypt and its descendants are the main survivors.
 *
 * WHY IT IS HERE: OpenSSL has it, so data hashed with it exists, and a
 * library claiming to be complete cannot skip a standing ISO standard.
 *
 * THE S-BOX IS DERIVED, NOT TRANSCRIBED. Whirlpool defines it through three
 * 4-bit mini-boxes rather than as a table, which means 256 entries collapse
 * to 48 - and those 48 can be checked against the first few published values.
 * That is the opposite situation from SEED, whose tables had to be
 * parsed out of their RFCs because nothing generates them.
 *
 * Its 8-bit S-box carries the usual cache-timing caveat, though for a hash
 * with no secret input that matters only when it is keyed, as in HMAC.
 */

import { md_hash, md_create } from './commons/merkle_damgard.js';
import { gmul, POLY_WHIRLPOOL } from './commons/gf256.js';

var BLOCK_SIZE  = 64;
var DIGEST_SIZE = 64;
var ROUNDS = 10;

/*
 * Whirlpool's field is x^8+x^4+x^3+x^2+1, NOT the AES polynomial - one bit
 * apart and completely different results. commons/gf256.js takes the
 * polynomial as an argument for exactly this reason.
 */

/*
 * The S-box, built from three 4-bit boxes exactly as the specification
 * defines it. E is a permutation of the nibbles, R is a second one applied to
 * their difference, and the whole thing is a small three-round structure -
 * which is why 256 bytes can be written as 48.
 */
var SBOX = /* @__PURE__ */ (function () {
    var E = [0x1,0xB,0x9,0xC,0xD,0x6,0xF,0x3,0xE,0x8,0x7,0x4,0xA,0x2,0x5,0x0];
    var R = [0x7,0xC,0xB,0xD,0xE,0x4,0x9,0xF,0x6,0x3,0x8,0xA,0x2,0x5,0x1,0x0];
    var Einv = new Uint8Array(16);
    for (var i = 0; i < 16; i++) { Einv[E[i]] = i; }

    var s = new Uint8Array(256);
    for (i = 0; i < 256; i++) {
        var y = E[i >>> 4];
        var z = Einv[i & 0xf];
        var t = R[y ^ z];
        s[i] = (E[y ^ t] << 4) | Einv[z ^ t];
    }

    var seen = new Uint8Array(256);
    for (i = 0; i < 256; i++) { seen[s[i]] = 1; }
    for (i = 0; i < 256; i++) {
        if (!seen[i]) { throw new Error('whirlpool: S-box is not a bijection'); }
    }
    return s;
}());

/* The diffusion matrix is circulant with these coefficients */
var CIR = [1, 1, 4, 1, 8, 5, 2, 9];

/*
 * Round constants come from the S-box itself: round r takes bytes
 * 8(r-1)..8r-1 as its first row and zeros elsewhere. Nothing extra to store.
 */
var RC = /* @__PURE__ */ (function () {
    var rc = [];
    for (var r = 1; r <= ROUNDS; r++) {
        var row = new Uint8Array(64);
        for (var j = 0; j < 8; j++) { row[j] = SBOX[8 * (r - 1) + j]; }
        rc.push(row);
    }
    return rc;
}());

var t_state = new Uint8Array(64);

/**
 * One round of the internal cipher: substitute, shift columns, mix rows,
 * add the key. Identical in structure to AES, on an 8x8 matrix rather than
 * 4x4 and with its own field and coefficients.
 */
/*
 * CIRTAB[k*256 + b] = gmul(b, CIR[k]) - eight rows of 256, built once.
 *
 * ⚠ The table depends only on CIR and the polynomial, both compile-time
 *   constants, so there is no key-dependent indexing here and no timing
 *   concern: Whirlpool has no secret input.
 */
var CIRTAB = /* @__PURE__ */ (function () {
    var t = new Uint8Array(8 * 256);
    for (var k = 0; k < 8; k++) {
        for (var b = 0; b < 256; b++) {
            t[k * 256 + b] = gmul(b, CIR[k], POLY_WHIRLPOOL);
        }
    }
    return t;
}());

function round(a, k) {
    var i, j, x, v;

    /* gamma: substitute every byte */
    for (i = 0; i < 64; i++) { a[i] = SBOX[a[i]]; }

    /* pi: column j moves down by j rows */
    for (i = 0; i < 64; i++) { t_state[i] = a[i]; }
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            a[i * 8 + j] = t_state[(((i - j) % 8 + 8) % 8) * 8 + j];
        }
    }

    /*
     * theta: multiply each row by the circulant matrix.
     *
     * ⭐ THROUGH A TABLE, and the naive form is why this mattered. CIR is
     *   CONSTANT, so gmul(byte, CIR[k]) has only 8*256 possible results -
     *   but computed inline it ran gmul's eight-iteration loop 512 times per
     *   round, 10 rounds, twice per block. About 82,000 iterations for 64
     *   bytes.
     *
     *   MEASURED BEFORE: 0.1 MB/s, against sha256's 91. Not "less
     *   optimised" - two orders of magnitude, and enough that anyone hashing
     *   a real file would conclude the library was broken.
     */
    for (i = 0; i < 64; i++) { t_state[i] = a[i]; }
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            v = 0;
            for (x = 0; x < 8; x++) {
                v ^= CIRTAB[((((j - x) % 8) + 8) % 8) * 256 + t_state[i * 8 + x]];
            }
            a[i * 8 + j] = v;
        }
    }

    /* sigma: add the round key */
    for (i = 0; i < 64; i++) { a[i] ^= k[i]; }
}

var st_k = new Uint8Array(64);
var st_s = new Uint8Array(64);

/**
 * Miyaguchi-Preneel: the chaining value is the KEY, the message block is the
 * plaintext, and the new chaining value is the ciphertext xored with BOTH the
 * message and the old chaining value.
 *
 * Xoring the message back in is what makes the compression function one-way -
 * without it the block cipher could simply be run backwards.
 */
function compress(H, buf, off) {
    var i, r;

    /* H arrives as sixteen big-endian words; the cipher works on bytes */
    for (i = 0; i < 16; i++) {
        st_k[i * 4]     = (H[i] >>> 24) & 0xff; st_k[i * 4 + 1] = (H[i] >>> 16) & 0xff;
        st_k[i * 4 + 2] = (H[i] >>> 8) & 0xff;  st_k[i * 4 + 3] = H[i] & 0xff;
    }
    for (i = 0; i < 64; i++) { st_s[i] = buf[off + i] ^ st_k[i]; }

    for (r = 0; r < ROUNDS; r++) {
        /* the key schedule is the same round function with a constant */
        round(st_k, RC[r]);
        round(st_s, st_k);
    }

    for (i = 0; i < 16; i++) {
        var w = ((st_s[i * 4] << 24) | (st_s[i * 4 + 1] << 16) |
                 (st_s[i * 4 + 2] << 8) | st_s[i * 4 + 3]) | 0;
        var m = ((buf[off + i * 4] << 24) | (buf[off + i * 4 + 1] << 16) |
                 (buf[off + i * 4 + 2] << 8) | buf[off + i * 4 + 3]) | 0;
        H[i] ^= w ^ m;
    }
}

var PARAMS = {
    compress:      compress,
    iv:            new Int32Array(16),   /* Whirlpool starts from all zeros */
    w_size:        1,
    block_size:    64,
    /* the length field is 256 bits, though only the low 64 are ever nonzero */
    len_field:     32,
    digest_size:   64,
    little_endian: false
};

/**
 * @param  {Uint8Array} msg
 * @return {Uint8Array} 64 bytes
 */
export var whirlpool = /* @__PURE__ */ (function () {
    function whirlpool(msg) { return md_hash(PARAMS, msg); }
    whirlpool.BLOCK_SIZE  = BLOCK_SIZE;
    whirlpool.DIGEST_SIZE = DIGEST_SIZE;
    whirlpool.create = whirlpool_create;
    return whirlpool;
}());

/**
 * The same hash, fed in pieces: update() as often as needed, digest() once;
 * copy() forks the state. See md_create in commons/merkle_damgard.js.
 */
export function whirlpool_create() { return md_create(PARAMS); }
