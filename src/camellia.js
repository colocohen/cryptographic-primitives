/**
 * Camellia  -  RFC 3713, ISO/IEC 18033-3
 *
 * Japan's contribution to the block-cipher standards, from NTT and Mitsubishi
 * in 2000. It was the other finalist alongside Rijndael in several European
 * and Japanese evaluations, and it is in TLS ciphersuites, in the Japanese
 * government's CRYPTREC list, and in ISO.
 *
 * 128-bit blocks and 128, 192 or 256-bit keys, matching AES exactly - it was
 * designed as a drop-in alternative. Security has held up: no attack better
 * than generic on the full cipher after twenty-five years.
 *
 * STRUCTURALLY IT IS NOT AES. Camellia is a Feistel network - 18 rounds for a
 * 128-bit key, 24 for the longer ones - with an extra FL/FL-inverse layer
 * spliced in every six rounds. Those layers are not Feistel and not
 * involutive; they exist specifically to break the regularity that makes
 * pure Feistel ciphers easier to attack.
 *
 * Everything runs on 64-bit halves, which here means int32 pairs throughout,
 * the same as sha512.js and blake2b. That is most of the length of this file.
 *
 * THE SAME CACHE-TIMING CAVEAT AS AES AND SM4. Four 8-bit S-boxes indexed by
 * secret data. There is no hardware instruction anywhere and Web Crypto does
 * not expose it, so a software implementation is the only option - which is
 * an argument for ChaCha20-Poly1305 wherever the choice is actually free.
 */

import { bind_modes } from './commons/cipher_modes.js';
import { check_bijection } from './commons/gf256.js';
import { rd_be32, wr_be32s } from './commons/bytes.js';

var BLOCK = 16;

/*
 * SBOX1 is transcribed from RFC 3713. It is derivable - inversion in GF(2^8)
 * with a specific affine map - but the construction is involved enough that a
 * transcription plus the bijection check below is the safer trade. That check
 * is here because exactly one wrong S-box entry in aes.js survived the
 * AES-128 vector and was only caught by AES-192.
 */
var SBOX1 = new Uint8Array([
0x70,0x82,0x2c,0xec,0xb3,0x27,0xc0,0xe5,0xe4,0x85,0x57,0x35,0xea,0x0c,0xae,0x41,
0x23,0xef,0x6b,0x93,0x45,0x19,0xa5,0x21,0xed,0x0e,0x4f,0x4e,0x1d,0x65,0x92,0xbd,
0x86,0xb8,0xaf,0x8f,0x7c,0xeb,0x1f,0xce,0x3e,0x30,0xdc,0x5f,0x5e,0xc5,0x0b,0x1a,
0xa6,0xe1,0x39,0xca,0xd5,0x47,0x5d,0x3d,0xd9,0x01,0x5a,0xd6,0x51,0x56,0x6c,0x4d,
0x8b,0x0d,0x9a,0x66,0xfb,0xcc,0xb0,0x2d,0x74,0x12,0x2b,0x20,0xf0,0xb1,0x84,0x99,
0xdf,0x4c,0xcb,0xc2,0x34,0x7e,0x76,0x05,0x6d,0xb7,0xa9,0x31,0xd1,0x17,0x04,0xd7,
0x14,0x58,0x3a,0x61,0xde,0x1b,0x11,0x1c,0x32,0x0f,0x9c,0x16,0x53,0x18,0xf2,0x22,
0xfe,0x44,0xcf,0xb2,0xc3,0xb5,0x7a,0x91,0x24,0x08,0xe8,0xa8,0x60,0xfc,0x69,0x50,
0xaa,0xd0,0xa0,0x7d,0xa1,0x89,0x62,0x97,0x54,0x5b,0x1e,0x95,0xe0,0xff,0x64,0xd2,
0x10,0xc4,0x00,0x48,0xa3,0xf7,0x75,0xdb,0x8a,0x03,0xe6,0xda,0x09,0x3f,0xdd,0x94,
0x87,0x5c,0x83,0x02,0xcd,0x4a,0x90,0x33,0x73,0x67,0xf6,0xf3,0x9d,0x7f,0xbf,0xe2,
0x52,0x9b,0xd8,0x26,0xc8,0x37,0xc6,0x3b,0x81,0x96,0x6f,0x4b,0x13,0xbe,0x63,0x2e,
0xe9,0x79,0xa7,0x8c,0x9f,0x6e,0xbc,0x8e,0x29,0xf5,0xf9,0xb6,0x2f,0xfd,0xb4,0x59,
0x78,0x98,0x06,0x6a,0xe7,0x46,0x71,0xba,0xd4,0x25,0xab,0x42,0x88,0xa2,0x8d,0xfa,
0x72,0x07,0xb9,0x55,0xf8,0xee,0xac,0x0a,0x36,0x49,0x2a,0x68,0x3c,0x38,0xf1,0xa4,
0x40,0x28,0xd3,0x7b,0xbb,0xc9,0x43,0xc1,0x15,0xe3,0xad,0xf4,0x77,0xc7,0x80,0x9e
]);

check_bijection(SBOX1, 'camellia');

/* The other three boxes are rotations of the first - generated, not copied */
var SBOX2 = /* @__PURE__ */ (function () {
    var t = new Uint8Array(256);
    for (var i = 0; i < 256; i++) { t[i] = ((SBOX1[i] << 1) | (SBOX1[i] >>> 7)) & 0xff; }
    return t;
}());
var SBOX3 = /* @__PURE__ */ (function () {
    var t = new Uint8Array(256);
    for (var i = 0; i < 256; i++) { t[i] = ((SBOX1[i] >>> 1) | (SBOX1[i] << 7)) & 0xff; }
    return t;
}());
var SBOX4 = /* @__PURE__ */ (function () {
    var t = new Uint8Array(256);
    for (var i = 0; i < 256; i++) { t[i] = SBOX1[((i << 1) | (i >>> 7)) & 0xff]; }
    return t;
}());

/* Sigma: the key-schedule constants, as hi/lo pairs */
var SIGMA = new Int32Array([
    0xa09e667f|0, 0x3bcc908b|0,
    0xb67ae858|0, 0x4caa73b2|0,
    0xc6ef372f|0, 0xe94f82be|0,
    0x54ff53a5|0, 0xf1d36f1c|0,
    0x10e527fa|0, 0xde682d1d|0,
    0xb05688c2|0, 0xb3e6c1fd|0
]);

/* Scratch for the F output, so it does not allocate per round */
var f_hi = 0, f_lo = 0;

/**
 * The round function: xor the key, substitute all eight bytes through four
 * different S-boxes, then mix with a fixed linear layer.
 */
function F(in_hi, in_lo, k_hi, k_lo) {
    var xh = in_hi ^ k_hi, xl = in_lo ^ k_lo;

    var t1 = SBOX1[(xh >>> 24) & 0xff];
    var t2 = SBOX2[(xh >>> 16) & 0xff];
    var t3 = SBOX3[(xh >>> 8) & 0xff];
    var t4 = SBOX4[xh & 0xff];
    var t5 = SBOX2[(xl >>> 24) & 0xff];
    var t6 = SBOX3[(xl >>> 16) & 0xff];
    var t7 = SBOX4[(xl >>> 8) & 0xff];
    var t8 = SBOX1[xl & 0xff];

    var y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
    var y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
    var y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
    var y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
    var y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
    var y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
    var y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
    var y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

    f_hi = ((y1 << 24) | (y2 << 16) | (y3 << 8) | y4) | 0;
    f_lo = ((y5 << 24) | (y6 << 16) | (y7 << 8) | y8) | 0;
}

var fl_hi = 0, fl_lo = 0;

/**
 * FL - not a Feistel round and not an involution. It is inserted every six
 * rounds specifically to break the regular structure that makes long Feistel
 * networks easier to attack.
 */
function FL(x_hi, x_lo, k_hi, k_lo) {
    var t = x_hi & k_hi;
    fl_lo = x_lo ^ (((t << 1) | (t >>> 31)) | 0);
    fl_hi = x_hi ^ (fl_lo | k_lo);
}

/** The inverse, applied on the other side of each layer. */
function FLINV(y_hi, y_lo, k_hi, k_lo) {
    fl_hi = y_hi ^ (y_lo | k_lo);
    var t = fl_hi & k_hi;
    fl_lo = y_lo ^ (((t << 1) | (t >>> 31)) | 0);
}

/** Rotate a 128-bit value left by n bits, as four 32-bit words. */
function rotl128(w, n, out) {
    var word = (n / 32) | 0, bit = n % 32;
    for (var i = 0; i < 4; i++) {
        var a = w[(word + i) & 3], b = w[(word + i + 1) & 3];
        out[i] = bit === 0 ? a : (((a << bit) | (b >>> (32 - bit))) | 0);
    }
}

/**
 * The key schedule.
 *
 * KL and KR come from the key; KA and KB are derived by running the round
 * function over them. Every subkey is then a rotation of one of those four -
 * which is why the schedule is cheap but also why related-key properties get
 * more scrutiny here than in a cipher with an irreversible schedule.
 */
function expand_key(key) {
    var kl = new Int32Array(4), kr = new Int32Array(4);
    var i;

    if (key.length === 16) {
        for (i = 0; i < 4; i++) { kl[i] = rd_be32(key, i * 4); }
    } else if (key.length === 24) {
        for (i = 0; i < 4; i++) { kl[i] = rd_be32(key, i * 4); }
        kr[0] = rd_be32(key, 16); kr[1] = rd_be32(key, 20);
        kr[2] = ~kr[0]; kr[3] = ~kr[1];
    } else if (key.length === 32) {
        for (i = 0; i < 4; i++) { kl[i] = rd_be32(key, i * 4); }
        for (i = 0; i < 4; i++) { kr[i] = rd_be32(key, 16 + i * 4); }
    } else {
        throw new Error('camellia: key must be 16, 24 or 32 bytes');
    }

    var d1h = kl[0] ^ kr[0], d1l = kl[1] ^ kr[1];
    var d2h = kl[2] ^ kr[2], d2l = kl[3] ^ kr[3];

    F(d1h, d1l, SIGMA[0], SIGMA[1]); d2h ^= f_hi; d2l ^= f_lo;
    F(d2h, d2l, SIGMA[2], SIGMA[3]); d1h ^= f_hi; d1l ^= f_lo;
    d1h ^= kl[0]; d1l ^= kl[1]; d2h ^= kl[2]; d2l ^= kl[3];
    F(d1h, d1l, SIGMA[4], SIGMA[5]); d2h ^= f_hi; d2l ^= f_lo;
    F(d2h, d2l, SIGMA[6], SIGMA[7]); d1h ^= f_hi; d1l ^= f_lo;

    var ka = new Int32Array([d1h, d1l, d2h, d2l]);

    var kb = new Int32Array(4);
    if (key.length !== 16) {
        d1h = ka[0] ^ kr[0]; d1l = ka[1] ^ kr[1];
        d2h = ka[2] ^ kr[2]; d2l = ka[3] ^ kr[3];
        F(d1h, d1l, SIGMA[8], SIGMA[9]);  d2h ^= f_hi; d2l ^= f_lo;
        F(d2h, d2l, SIGMA[10], SIGMA[11]); d1h ^= f_hi; d1l ^= f_lo;
        kb[0] = d1h; kb[1] = d1l; kb[2] = d2h; kb[3] = d2l;
    }

    /* Each subkey is a rotation of KL, KR, KA or KB by a fixed amount. */
    var sk = [];
    var tmp = new Int32Array(4);
    function push(src, rot, take_high) {
        rotl128(src, rot, tmp);
        sk.push(take_high ? [tmp[0], tmp[1]] : [tmp[2], tmp[3]]);
    }

    if (key.length === 16) {
        push(kl, 0, true);   push(kl, 0, false);      /* kw1 kw2 */
        push(ka, 0, true);   push(ka, 0, false);      /* k1 k2 */
        push(kl, 15, true);  push(kl, 15, false);     /* k3 k4 */
        push(ka, 15, true);  push(ka, 15, false);     /* k5 k6 */
        push(ka, 30, true);                            /* ke1 */
        push(ka, 30, false);                           /* ke2 */
        push(kl, 45, true);  push(kl, 45, false);     /* k7 k8 */
        push(ka, 45, true);  push(kl, 60, false);     /* k9 k10 */
        push(ka, 60, true);  push(ka, 60, false);     /* k11 k12 */
        push(kl, 77, true);                            /* ke3 */
        push(kl, 77, false);                           /* ke4 */
        push(kl, 94, true);  push(kl, 94, false);     /* k13 k14 */
        push(ka, 94, true);  push(ka, 94, false);     /* k15 k16 */
        push(kl, 111, true); push(kl, 111, false);    /* k17 k18 */
        push(ka, 111, true); push(ka, 111, false);    /* kw3 kw4 */
    } else {
        push(kl, 0, true);   push(kl, 0, false);      /* kw1 kw2 */
        push(kb, 0, true);   push(kb, 0, false);      /* k1 k2 */
        push(kr, 15, true);  push(kr, 15, false);     /* k3 k4 */
        push(ka, 15, true);  push(ka, 15, false);     /* k5 k6 */
        push(kr, 30, true);  push(kr, 30, false);     /* ke1 ke2 */
        push(kb, 30, true);  push(kb, 30, false);     /* k7 k8 */
        push(kl, 45, true);  push(kl, 45, false);     /* k9 k10 */
        push(ka, 45, true);  push(ka, 45, false);     /* k11 k12 */
        push(kl, 60, true);  push(kl, 60, false);     /* ke3 ke4 */
        push(kr, 60, true);  push(kr, 60, false);     /* k13 k14 */
        push(kb, 60, true);  push(kb, 60, false);     /* k15 k16 */
        push(kl, 77, true);  push(kl, 77, false);     /* k17 k18 */
        push(ka, 77, true);  push(ka, 77, false);     /* ke5 ke6 */
        push(kr, 94, true);  push(kr, 94, false);     /* k19 k20 */
        push(ka, 94, true);  push(ka, 94, false);     /* k21 k22 */
        push(kl, 111, true); push(kl, 111, false);    /* k23 k24 */
        push(kb, 111, true); push(kb, 111, false);    /* kw3 kw4 */
    }
    return { sk: sk, rounds: key.length === 16 ? 18 : 24 };
}

/** One block. Decryption is the same path with the subkeys reversed. */
function crypt_block(ks, src, off, out, out_off, reverse) {
    var sk = ks.sk, rounds = ks.rounds;
    var n = sk.length;

    /*
     * Subkey order forward:
     *     kw1 kw2 | k1..k6 | ke1 ke2 | k7..k12 | ke3 ke4 | k13..k18 | kw3 kw4
     * and for decryption the whole sequence reverses - EXCEPT that the two
     * whitening pairs keep their internal order. Decryption pre-whitens with
     * (kw3, kw4) in that order, not (kw4, kw3). A plain reversal gets every
     * round key right and both whitening pairs backwards, which encrypts
     * correctly and decrypts to garbage.
     */
    function K(i) {
        if (!reverse) { return sk[i]; }
        if (i === 0) { return sk[n - 2]; }
        if (i === 1) { return sk[n - 1]; }
        if (i === n - 2) { return sk[0]; }
        if (i === n - 1) { return sk[1]; }
        return sk[n - 1 - i];
    }

    var d1h = rd_be32(src, off),     d1l = rd_be32(src, off + 4);
    var d2h = rd_be32(src, off + 8), d2l = rd_be32(src, off + 12);

    /* pre-whitening */
    var k = K(0), k2 = K(1);
    d1h ^= k[0]; d1l ^= k[1];
    d2h ^= k2[0]; d2l ^= k2[1];

    var idx = 2;
    var groups = rounds / 6;
    for (var g = 0; g < groups; g++) {
        for (var r = 0; r < 6; r++) {
            var kk = K(idx++);
            F(d1h, d1l, kk[0], kk[1]);
            var th = d2h ^ f_hi, tl = d2l ^ f_lo;
            d2h = d1h; d2l = d1l;
            d1h = th;  d1l = tl;
        }
        if (g !== groups - 1) {
            /* the FL layer, and its inverse on the other half */
            /*
             * Identical in both directions, which is not obvious and cost a
             * debugging session to establish.
             *
             * Each swap-round leaves the two halves transposed relative to the
             * RFC's non-swapping formulation, and over six rounds those cancel
             * - but the ciphertext is read into (d1, d2) already transposed,
             * so at every FL boundary decryption holds encryption's halves the
             * other way round. Undoing FL(d1_in) therefore means applying FL
             * to the half that now sits in d1, with the reversed key. The
             * transposition and the inversion cancel exactly.
             *
             * The intuitive version - swapping FL and FLINV for decryption -
             * encrypts correctly and decrypts to garbage.
             */
            var kea = K(idx++), keb = K(idx++);
            FL(d1h, d1l, kea[0], kea[1]);    d1h = fl_hi; d1l = fl_lo;
            FLINV(d2h, d2l, keb[0], keb[1]); d2h = fl_hi; d2l = fl_lo;
        }
    }

    /* post-whitening, and the halves come out swapped */
    var kw3 = K(idx++), kw4 = K(idx++);
    var oh1 = d2h ^ kw3[0], ol1 = d2l ^ kw3[1];
    var oh2 = d1h ^ kw4[0], ol2 = d1l ^ kw4[1];

    /* bytes.js's writer, as SEED and SM4 use; this was a fifth hand copy of
       the loop (measured ~3% slower on 16 KiB of CTR, taken for the one
       implementation) */
    wr_be32s(out, out_off, [oh1, ol1, oh2, ol2]);
}

function blocks(key, reverse) {
    var ks = expand_key(key);
    return function (src, off, out, out_off) {
        crypt_block(ks, src, off, out, out_off, reverse);
    };
}

/* ==================== the modes ==================== */

/*
 * Generated by commons/cipher_modes.js from the block function above.
 * aria.js held the same wrappers, identical apart from the name.
 */
var M = bind_modes('camellia', BLOCK, blocks);

/**
 * ECB - single blocks only: identical plaintext blocks give identical
 * ciphertext, so this is not a way to encrypt a message.
 */
export var camellia_ecb_encrypt = M.ecb_encrypt;
export var camellia_ecb_decrypt = M.ecb_decrypt;
/* ECB under a key set once: encrypt(data), decrypt(data) - see aes.js. */
export var camellia_ecb_create = M.ecb_create;

/**
 * CBC with PKCS#7 unless no_pad. Decryption returns null on bad padding
 * rather than throwing - see commons/block_modes.js.
 */
export var camellia_cbc_encrypt = M.cbc_encrypt;
export var camellia_cbc_decrypt = M.cbc_decrypt;

/**
 * CTR: the whole 16-byte IV is the counter, incremented big-endian.
 */
export var camellia_ctr = M.ctr;

/**
 * Camellia-GCM, RFC 5528.
 *
 * THE NONCE MUST NOT REPEAT under one key. GCM fails completely rather than
 * gracefully on reuse - see the note in commons/gcm.js. GMAC is GCM with no
 * plaintext and needs a fresh nonce on every call too.
 */
export var camellia_gcm_encrypt = M.gcm_encrypt;
export var camellia_gcm_decrypt = M.gcm_decrypt;

/**
 * The same modes under one key for many messages - the key schedule (and
 * GCM's hash key and table) computed once. Each message takes its own
 * nonce, which MUST NOT repeat under the key.
 *
 *     var ctx = camellia_gcm_create(key);
 *     ctx.encrypt(nonce, plaintext, aad)  ->  ciphertext || tag
 *     ctx.decrypt(nonce, sealed, aad)     ->  plaintext, or null
 *
 * camellia_ccm_create and camellia_eax_create take tag_len as a fourth argument, as
 * their one-shot forms do. camellia_ctr_create(key, iv) is CTR fed in pieces:
 * update(data) returns data xor the next bytes of keystream, in either
 * direction.
 */
export var camellia_gcm_create = M.gcm_create;
export var camellia_ccm_create = M.ccm_create;
export var camellia_eax_create = M.eax_create;
export var camellia_ctr_create = M.ctr_create;
export var camellia_gmac = M.gmac;
export var camellia_gmac_verify = M.gmac_verify;

/**
 * Camellia-CCM, RFC 5528. `tag_len` is 4 to 16 bytes, even, default 16.
 */
export var camellia_ccm_encrypt = M.ccm_encrypt;
export var camellia_ccm_decrypt = M.ccm_decrypt;

/**
 * CMAC, NIST SP 800-38B. The verifier is constant time - never compare a tag
 * with ===.
 */
export var camellia_cmac = M.cmac;
export var camellia_cmac_verify = M.cmac_verify;
export var camellia_cmac_create = M.cmac_create;

/**
 * Key wrap: KW is RFC 3394 (a multiple of 8 bytes, at least 16), KWP is
 * RFC 5649 (any length). Unwrapping returns null when the check fails.
 */
export var camellia_kw_wrap = M.kw_wrap;
export var camellia_kw_unwrap = M.kw_unwrap;
export var camellia_kwp_wrap = M.kwp_wrap;
export var camellia_kwp_unwrap = M.kwp_unwrap;
/* EAX (commons/eax.js) is defined over any 128-bit block cipher; the factory
   builds it for every one, so every one exports it */
export var camellia_eax_encrypt = M.eax_encrypt;
export var camellia_eax_decrypt = M.eax_decrypt;
