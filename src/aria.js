/**
 * ARIA  -  RFC 5794, KS X 1213
 *
 * South Korea's national block cipher since 2004, developed by KISA with
 * academic and government input. The name is an acronym for the three groups
 * involved. It succeeded SEED as the Korean standard and is what Korean
 * government systems are required to use.
 *
 * 128-bit blocks and 128, 192 or 256-bit keys, matching AES - like Camellia
 * it was built to be a drop-in alternative. 12, 14 or 16 rounds.
 *
 * WHAT MAKES IT UNUSUAL: it is an INVOLUTIONAL substitution-permutation
 * network. Odd rounds substitute through one set of S-boxes and even rounds
 * through their inverses, and the diffusion layer is its own inverse. The
 * consequence is that encryption and decryption share the entire data path -
 * only the round keys differ, and even those are derived from each other.
 * AES needs a separate inverse cipher; ARIA does not.
 *
 * Its first S-box IS the AES S-box, by specification, and the third is the
 * AES inverse. The second and fourth are a different affine map over the same
 * field inverse. All four come out of commons/gf256.js rather than being
 * transcribed.
 *
 * THE SAME CACHE-TIMING CAVEAT AS AES, SM4 AND CAMELLIA: 8-bit S-boxes
 * indexed by secret data, no hardware instruction, nothing in Web Crypto.
 */

import { bind_modes } from './commons/cipher_modes.js';
import { xor_bytes } from './commons/bytes.js';
import { AES_SBOX, AES_INV_SBOX, invert_sbox, check_bijection }
    from './commons/gf256.js';

var BLOCK = 16;

/* SB1 and SB3 are AES's pair; SB2 and SB4 use a different affine transform */
var SB1 = AES_SBOX;
var SB3 = AES_INV_SBOX;
/*
 * SB2 from RFC 5794, transcribed.
 *
 * Unlike SB1 it cannot be derived from rotations of the field inverse - its
 * affine matrix is not circulant - and the matrix as published is easy to
 * transpose or bit-reverse by accident. Two attempts at deriving it produced
 * perfectly valid bijections that were not SB2, which is exactly the failure
 * a bijection check cannot catch. The table is transcribed and validated by
 * the differential tests instead: a wrong entry cannot produce output that
 * matches another implementation.
 */
var SB2 = new Uint8Array([
0xe2,0x4e,0x54,0xfc,0x94,0xc2,0x4a,0xcc,0x62,0x0d,0x6a,0x46,0x3c,0x4d,0x8b,0xd1,
0x5e,0xfa,0x64,0xcb,0xb4,0x97,0xbe,0x2b,0xbc,0x77,0x2e,0x03,0xd3,0x19,0x59,0xc1,
0x1d,0x06,0x41,0x6b,0x55,0xf0,0x99,0x69,0xea,0x9c,0x18,0xae,0x63,0xdf,0xe7,0xbb,
0x00,0x73,0x66,0xfb,0x96,0x4c,0x85,0xe4,0x3a,0x09,0x45,0xaa,0x0f,0xee,0x10,0xeb,
0x2d,0x7f,0xf4,0x29,0xac,0xcf,0xad,0x91,0x8d,0x78,0xc8,0x95,0xf9,0x2f,0xce,0xcd,
0x08,0x7a,0x88,0x38,0x5c,0x83,0x2a,0x28,0x47,0xdb,0xb8,0xc7,0x93,0xa4,0x12,0x53,
0xff,0x87,0x0e,0x31,0x36,0x21,0x58,0x48,0x01,0x8e,0x37,0x74,0x32,0xca,0xe9,0xb1,
0xb7,0xab,0x0c,0xd7,0xc4,0x56,0x42,0x26,0x07,0x98,0x60,0xd9,0xb6,0xb9,0x11,0x40,
0xec,0x20,0x8c,0xbd,0xa0,0xc9,0x84,0x04,0x49,0x23,0xf1,0x4f,0x50,0x1f,0x13,0xdc,
0xd8,0xc0,0x9e,0x57,0xe3,0xc3,0x7b,0x65,0x3b,0x02,0x8f,0x3e,0xe8,0x25,0x92,0xe5,
0x15,0xdd,0xfd,0x17,0xa9,0xbf,0xd4,0x9a,0x7e,0xc5,0x39,0x67,0xfe,0x76,0x9d,0x43,
0xa7,0xe1,0xd0,0xf5,0x68,0xf2,0x1b,0x34,0x70,0x05,0xa3,0x8a,0xd5,0x79,0x86,0xa8,
0x30,0xc6,0x51,0x4b,0x1e,0xa6,0x27,0xf6,0x35,0xd2,0x6e,0x24,0x16,0x82,0x5f,0xda,
0xe6,0x75,0xa2,0xef,0x2c,0xb2,0x1c,0x9f,0x5d,0x6f,0x80,0x0a,0x72,0x44,0x9b,0x6c,
0x90,0x0b,0x5b,0x33,0x7d,0x5a,0x52,0xf3,0x61,0xa1,0xf7,0xb0,0xd6,0x3f,0x7c,0x6d,
0xed,0x14,0xe0,0xa5,0x3d,0x22,0xb3,0xf8,0x89,0xde,0x71,0x1a,0xaf,0xba,0xb5,0x81
]);
check_bijection(SB2, 'aria SB2');

var SB4 = /* @__PURE__ */ invert_sbox(SB2);

/* Key-schedule constants: the first 384 bits of the fractional part of 1/PI */
var C = [
    new Uint8Array([0x51,0x7c,0xc1,0xb7,0x27,0x22,0x0a,0x94,0xfe,0x13,0xab,0xe8,0xfa,0x9a,0x6e,0xe0]),
    new Uint8Array([0x6d,0xb1,0x4a,0xcc,0x9e,0x21,0xc8,0x20,0xff,0x28,0xb1,0xd5,0xef,0x5d,0xe2,0xb0]),
    new Uint8Array([0xdb,0x92,0x37,0x1d,0x21,0x26,0xe9,0x70,0x03,0x24,0x97,0x75,0x04,0xe8,0xc9,0x0e])
];

/** Substitution layer for odd rounds. */
function sl1(x) {
    for (var i = 0; i < 16; i += 4) {
        x[i]     = SB1[x[i]];
        x[i + 1] = SB2[x[i + 1]];
        x[i + 2] = SB3[x[i + 2]];
        x[i + 3] = SB4[x[i + 3]];
    }
}

/** Substitution layer for even rounds - the same boxes, inverted and rotated. */
function sl2(x) {
    for (var i = 0; i < 16; i += 4) {
        x[i]     = SB3[x[i]];
        x[i + 1] = SB4[x[i + 1]];
        x[i + 2] = SB1[x[i + 2]];
        x[i + 3] = SB2[x[i + 3]];
    }
}

var a_tmp = new Uint8Array(16);

/**
 * The diffusion layer: a fixed 16x16 binary matrix over GF(2).
 *
 * It is INVOLUTIONAL - applying it twice is the identity - which is what lets
 * decryption reuse the forward data path. Every output byte is the xor of
 * exactly seven input bytes.
 */
function A(x) {
    var t = a_tmp;
    t[0]  = x[3]^x[4]^x[6]^x[8]^x[9]^x[13]^x[14];
    t[1]  = x[2]^x[5]^x[7]^x[8]^x[9]^x[12]^x[15];
    t[2]  = x[1]^x[4]^x[6]^x[10]^x[11]^x[12]^x[15];
    t[3]  = x[0]^x[5]^x[7]^x[10]^x[11]^x[13]^x[14];
    t[4]  = x[0]^x[2]^x[5]^x[8]^x[11]^x[14]^x[15];
    t[5]  = x[1]^x[3]^x[4]^x[9]^x[10]^x[14]^x[15];
    t[6]  = x[0]^x[2]^x[7]^x[9]^x[10]^x[12]^x[13];
    t[7]  = x[1]^x[3]^x[6]^x[8]^x[11]^x[12]^x[13];
    t[8]  = x[0]^x[1]^x[4]^x[7]^x[10]^x[13]^x[15];
    t[9]  = x[0]^x[1]^x[5]^x[6]^x[11]^x[12]^x[14];
    t[10] = x[2]^x[3]^x[5]^x[6]^x[8]^x[13]^x[15];
    t[11] = x[2]^x[3]^x[4]^x[7]^x[9]^x[12]^x[14];
    t[12] = x[1]^x[2]^x[6]^x[7]^x[9]^x[11]^x[12];
    t[13] = x[0]^x[3]^x[6]^x[7]^x[8]^x[10]^x[13];
    t[14] = x[0]^x[3]^x[4]^x[5]^x[9]^x[11]^x[14];
    t[15] = x[1]^x[2]^x[4]^x[5]^x[8]^x[10]^x[15];
    for (var i = 0; i < 16; i++) { x[i] = t[i]; }
}

/** Odd round: xor the key, substitute with SL1, diffuse. */
function FO(out, x, k) { xor_bytes(out, x, k, 16); sl1(out); A(out); }
/** Even round: the same with SL2. */
function FE(out, x, k) { xor_bytes(out, x, k, 16); sl2(out); A(out); }

/** Rotate a 128-bit value right by n bits. */
function rotr128(src, n, out) {
    var byte_shift = (n >>> 3), bit = n & 7;
    for (var i = 0; i < 16; i++) {
        var a = src[(i - byte_shift + 32) % 16];
        var b = src[(i - byte_shift - 1 + 32) % 16];
        out[i] = bit === 0 ? a : (((a >>> bit) | (b << (8 - bit))) & 0xff);
    }
}

/**
 * The key schedule.
 *
 * Four 128-bit words W0..W3 come from a three-round Feistel over the key, and
 * every round key is the xor of two of them with one rotated. Which constant
 * seeds which round depends on the key length - a detail that is easy to get
 * backwards and produces a cipher that works only for 128-bit keys.
 */
function expand_key(key) {
    var kl = new Uint8Array(16), kr = new Uint8Array(16);
    var rounds, ck1, ck2, ck3, i;

    if (key.length === 16)      { rounds = 12; ck1 = C[0]; ck2 = C[1]; ck3 = C[2]; }
    else if (key.length === 24) { rounds = 14; ck1 = C[1]; ck2 = C[2]; ck3 = C[0]; }
    else if (key.length === 32) { rounds = 16; ck1 = C[2]; ck2 = C[0]; ck3 = C[1]; }
    else { throw new Error('aria: key must be 16, 24 or 32 bytes'); }

    for (i = 0; i < 16; i++) { kl[i] = key[i]; }
    for (i = 16; i < key.length; i++) { kr[i - 16] = key[i]; }

    var w0 = kl;
    var w1 = new Uint8Array(16), w2 = new Uint8Array(16), w3 = new Uint8Array(16);

    FO(w1, w0, ck1); xor_bytes(w1, w1, kr, 16);
    FE(w2, w1, ck2); xor_bytes(w2, w2, w0, 16);
    FO(w3, w2, ck3); xor_bytes(w3, w3, w1, 16);

    var n = rounds + 1;
    var ek = [];
    var r = new Uint8Array(16);
    var W = [w0, w1, w2, w3];

    /* Each group of four round keys uses one rotation amount */
    var rots = [19, 31, 67, 97, 109];
    for (var g = 0; g < 5 && ek.length < n; g++) {
        for (var j = 0; j < 4 && ek.length < n; j++) {
            var e = new Uint8Array(16);
            rotr128(W[(j + 1) & 3], rots[g], r);
            xor_bytes(e, W[j], r, 16);
            ek.push(e);
        }
    }
    return { ek: ek, rounds: rounds };
}

/**
 * Decryption keys are the encryption keys reversed, with the diffusion layer
 * applied to all but the first and last. That is the involution paying off:
 * no inverse cipher, just a transformed schedule.
 */
function decrypt_keys(ks) {
    var n = ks.ek.length;
    var dk = [];
    for (var i = 0; i < n; i++) {
        var e = new Uint8Array(ks.ek[n - 1 - i]);
        if (i > 0 && i < n - 1) { A(e); }
        dk.push(e);
    }
    return { ek: dk, rounds: ks.rounds };
}

var st_a = new Uint8Array(16);
var st_b = new Uint8Array(16);

function crypt_block(ks, src, off, out, out_off) {
    var ek = ks.ek, rounds = ks.rounds;
    var i;
    for (i = 0; i < 16; i++) { st_a[i] = src[off + i]; }

    for (i = 0; i < rounds - 1; i++) {
        if ((i & 1) === 0) { FO(st_b, st_a, ek[i]); }
        else               { FE(st_b, st_a, ek[i]); }
        for (var j = 0; j < 16; j++) { st_a[j] = st_b[j]; }
    }

    /* the final round substitutes but does not diffuse */
    xor_bytes(st_a, st_a, ek[rounds - 1], 16);
    sl2(st_a);
    xor_bytes(st_a, st_a, ek[rounds], 16);

    for (i = 0; i < 16; i++) { out[out_off + i] = st_a[i]; }
}

function blocks(key, decrypting) {
    var ks = expand_key(key);
    if (decrypting) { ks = decrypt_keys(ks); }
    return function (src, off, out, out_off) {
        crypt_block(ks, src, off, out, out_off);
    };
}

/* ==================== the modes ==================== */

/*
 * Generated by commons/cipher_modes.js from the block function above. These
 * wrappers were written out in full here and again, identically apart from
 * the name, in camellia.js, seed.js, sm4.js and aes.js.
 */
var M = bind_modes('aria', BLOCK, blocks);

/**
 * ECB - single blocks only: identical plaintext blocks give identical
 * ciphertext, so this is not a way to encrypt a message.
 */
export var aria_ecb_encrypt = M.ecb_encrypt;
export var aria_ecb_decrypt = M.ecb_decrypt;
/* ECB under a key set once: encrypt(data), decrypt(data) - see aes.js. */
export var aria_ecb_create = M.ecb_create;

/**
 * CBC with PKCS#7 unless no_pad. Decryption returns null on bad padding
 * rather than throwing - see commons/block_modes.js.
 */
export var aria_cbc_encrypt = M.cbc_encrypt;
export var aria_cbc_decrypt = M.cbc_decrypt;

/**
 * CTR: the whole 16-byte IV is the counter, incremented big-endian.
 */
export var aria_ctr = M.ctr;

/**
 * ARIA-GCM, RFC 6209.
 *
 * THE NONCE MUST NOT REPEAT under one key. GCM fails completely rather than
 * gracefully on reuse - see the note in commons/gcm.js. GMAC is GCM with no
 * plaintext and needs a fresh nonce on every call too.
 */
export var aria_gcm_encrypt = M.gcm_encrypt;
export var aria_gcm_decrypt = M.gcm_decrypt;

/**
 * The same modes under one key for many messages - the key schedule (and
 * GCM's hash key and table) computed once. Each message takes its own
 * nonce, which MUST NOT repeat under the key.
 *
 *     var ctx = aria_gcm_create(key);
 *     ctx.encrypt(nonce, plaintext, aad)  ->  ciphertext || tag
 *     ctx.decrypt(nonce, sealed, aad)     ->  plaintext, or null
 *
 * aria_ccm_create and aria_eax_create take tag_len as a fourth argument, as
 * their one-shot forms do. aria_ctr_create(key, iv) is CTR fed in pieces:
 * update(data) returns data xor the next bytes of keystream, in either
 * direction.
 */
export var aria_gcm_create = M.gcm_create;
export var aria_ccm_create = M.ccm_create;
export var aria_eax_create = M.eax_create;
export var aria_ctr_create = M.ctr_create;
export var aria_gmac = M.gmac;
export var aria_gmac_verify = M.gmac_verify;

/**
 * ARIA-CCM, RFC 6209. `tag_len` is 4 to 16 bytes, even, default 16.
 */
export var aria_ccm_encrypt = M.ccm_encrypt;
export var aria_ccm_decrypt = M.ccm_decrypt;

/**
 * CMAC, NIST SP 800-38B. The verifier is constant time - never compare a tag
 * with ===.
 */
export var aria_cmac = M.cmac;
export var aria_cmac_verify = M.cmac_verify;
export var aria_cmac_create = M.cmac_create;

/**
 * Key wrap: KW is RFC 3394 (a multiple of 8 bytes, at least 16), KWP is
 * RFC 5649 (any length). Unwrapping returns null when the check fails.
 */
export var aria_kw_wrap = M.kw_wrap;
export var aria_kw_unwrap = M.kw_unwrap;
export var aria_kwp_wrap = M.kwp_wrap;
export var aria_kwp_unwrap = M.kwp_unwrap;
/* EAX (commons/eax.js) is defined over any 128-bit block cipher; the factory
   builds it for every one, so every one exports it */
export var aria_eax_encrypt = M.eax_encrypt;
export var aria_eax_decrypt = M.eax_decrypt;
