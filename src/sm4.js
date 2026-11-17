/**
 * SM4  -  GB/T 32907-2016
 *
 * China's national block cipher, and the counterpart to AES in Chinese
 * regulation. 128-bit blocks, 128-bit keys, 32 rounds.
 *
 * It is an unbalanced Feistel network: each round transforms one quarter of
 * the state using the other three, so encryption and decryption run the SAME
 * code with the round keys reversed. AES needs a separate inverse S-box and
 * inverse MixColumns; SM4 needs neither, which makes it noticeably smaller in
 * hardware and simpler to get right.
 *
 * Security: no attacks better than generic on the full 32 rounds after twenty
 * years of public analysis. It is a respectable design; it is standardised
 * where it is for sovereignty reasons rather than technical ones.
 *
 * THE SAME CACHE-TIMING CAVEAT AS AES APPLIES. SM4 has an 8-bit S-box indexed
 * by secret data, so a software implementation leaks through cache behaviour
 * exactly as AES does. Unlike AES there is no hardware instruction to fall
 * back to outside recent Chinese and ARM parts, and Web Crypto does not
 * expose it at all. Where the choice is free, ChaCha20-Poly1305 has no tables.
 *
 * The modes - ECB, CBC, CTR, GCM, CCM, GMAC, CMAC, KW and KWP - are the
 * shared ones from commons/, bound to this block function by
 * commons/cipher_modes.js. (This note once said only ECB and CBC were
 * offered; the rest arrived one at a time, which is how SM4 came to be the
 * last of the four 128-bit ciphers to get key wrap.)
 */

import { bind_modes } from './commons/cipher_modes.js';
import { check_bijection } from './commons/gf256.js';
import { rd_be32, wr_be32s , rotl32 } from './commons/bytes.js';

var BLOCK = 16;
var ROUNDS = 32;

/*
 * The S-box is a published table rather than a derived one. Unlike AES, whose
 * box is an inverse in GF(2^8) plus an affine map and can be generated in a
 * dozen lines, SM4's is specified directly - there is nothing to derive it
 * from, so it is transcribed. That makes a typo possible, which is why the
 * bijection check below runs at load.
 */
var SBOX = new Uint8Array([
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
]);

check_bijection(SBOX, 'sm4');

/* Key schedule constants: FK seeds the schedule, CK varies per round */
var FK = new Int32Array([0xa3b1bac6|0, 0x56aa3350|0, 0x677d9197|0, 0xb27022dc|0]);

var CK = /* @__PURE__ */ (function () {
    /* CK[i] byte j is (4i + j) * 7 mod 256 - generated, not transcribed */
    var c = new Int32Array(32);
    for (var i = 0; i < 32; i++) {
        var w = 0;
        for (var j = 0; j < 4; j++) { w = ((w << 8) | (((4 * i + j) * 7) & 0xff)) | 0; }
        c[i] = w;
    }
    return c;
}());

/** Substitute all four bytes of a word. */
function tau(a) {
    return ((SBOX[(a >>> 24) & 0xff] << 24) | (SBOX[(a >>> 16) & 0xff] << 16) |
            (SBOX[(a >>> 8) & 0xff] << 8) | SBOX[a & 0xff]) | 0;
}

/** L for the data path, and L' for the key schedule - different rotations. */
function t_data(a) {
    var b = tau(a);
    return (b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)) | 0;
}
function t_key(a) {
    var b = tau(a);
    return (b ^ rotl32(b, 13) ^ rotl32(b, 23)) | 0;
}

/**
 * @param  {Uint8Array} key  exactly 16 bytes
 * @return {Int32Array} 32 round keys
 */
function expand_key(key) {
    if (key.length !== 16) { throw new Error('sm4: key must be 16 bytes'); }
    var k = new Int32Array(4);
    for (var i = 0; i < 4; i++) { k[i] = rd_be32(key, i * 4) ^ FK[i]; }

    var rk = new Int32Array(ROUNDS);
    for (i = 0; i < ROUNDS; i++) {
        var t = k[1] ^ k[2] ^ k[3] ^ CK[i];
        var v = k[0] ^ t_key(t);
        k[0] = k[1]; k[1] = k[2]; k[2] = k[3]; k[3] = v;
        rk[i] = v;
    }
    return rk;
}

/**
 * One block. The round keys run forward to encrypt and backward to decrypt -
 * the Feistel structure means there is only one code path.
 */
function crypt_block(rk, src, off, out, out_off, reverse) {
    var x0 = rd_be32(src, off), x1 = rd_be32(src, off + 4);
    var x2 = rd_be32(src, off + 8), x3 = rd_be32(src, off + 12);
    var i, t;

    for (i = 0; i < ROUNDS; i++) {
        t = x0 ^ t_data(x1 ^ x2 ^ x3 ^ rk[reverse ? (ROUNDS - 1 - i) : i]);
        x0 = x1; x1 = x2; x2 = x3; x3 = t;
    }

    /* the output words come out in reverse order - part of the spec */
    wr_be32s(out, out_off, [x3, x2, x1, x0]);
}

/** Bind the key schedule into a one-block callback for the shared modes. */
function blocks(key, reverse) {
    var rk = expand_key(key);
    return function (src, off, out, out_off) {
        crypt_block(rk, src, off, out, out_off, reverse);
    };
}

/* ==================== the modes ==================== */

/*
 * Generated by commons/cipher_modes.js from the block function above. SM4
 * once lacked KW and KWP while ARIA, Camellia and SEED had them; with one
 * binding for all of them that cannot recur.
 */
var M = bind_modes('sm4', BLOCK, blocks);

/**
 * ECB - single blocks only: identical plaintext blocks give identical
 * ciphertext, so this is not a way to encrypt a message.
 */
export var sm4_ecb_encrypt = M.ecb_encrypt;
export var sm4_ecb_decrypt = M.ecb_decrypt;
/* ECB under a key set once: encrypt(data), decrypt(data) - see aes.js. */
export var sm4_ecb_create = M.ecb_create;

/**
 * CBC with PKCS#7 unless no_pad. Decryption returns null on bad padding
 * rather than throwing - see commons/block_modes.js.
 */
export var sm4_cbc_encrypt = M.cbc_encrypt;
export var sm4_cbc_decrypt = M.cbc_decrypt;

/**
 * CTR: the whole 16-byte IV is the counter, incremented big-endian.
 */
export var sm4_ctr = M.ctr;

/**
 * SM4-GCM, RFC 8998 - the Chinese TLS 1.3 profile.
 *
 * THE NONCE MUST NOT REPEAT under one key. GCM fails completely rather than
 * gracefully on reuse - see the note in commons/gcm.js. GMAC is GCM with no
 * plaintext and needs a fresh nonce on every call too.
 */
export var sm4_gcm_encrypt = M.gcm_encrypt;
export var sm4_gcm_decrypt = M.gcm_decrypt;

/**
 * The same modes under one key for many messages - the key schedule (and
 * GCM's hash key and table) computed once. Each message takes its own
 * nonce, which MUST NOT repeat under the key.
 *
 *     var ctx = sm4_gcm_create(key);
 *     ctx.encrypt(nonce, plaintext, aad)  ->  ciphertext || tag
 *     ctx.decrypt(nonce, sealed, aad)     ->  plaintext, or null
 *
 * sm4_ccm_create and sm4_eax_create take tag_len as a fourth argument, as
 * their one-shot forms do. sm4_ctr_create(key, iv) is CTR fed in pieces:
 * update(data) returns data xor the next bytes of keystream, in either
 * direction.
 */
export var sm4_gcm_create = M.gcm_create;
export var sm4_ccm_create = M.ccm_create;
export var sm4_eax_create = M.eax_create;
export var sm4_ctr_create = M.ctr_create;
export var sm4_gmac = M.gmac;
export var sm4_gmac_verify = M.gmac_verify;

/**
 * SM4-CCM, RFC 8998. `tag_len` is 4 to 16 bytes, even, default 16.
 */
export var sm4_ccm_encrypt = M.ccm_encrypt;
export var sm4_ccm_decrypt = M.ccm_decrypt;

/**
 * CMAC, NIST SP 800-38B. The verifier is constant time - never compare a tag
 * with ===.
 */
export var sm4_cmac = M.cmac;
export var sm4_cmac_verify = M.cmac_verify;
export var sm4_cmac_create = M.cmac_create;

/**
 * Key wrap: KW is RFC 3394 (a multiple of 8 bytes, at least 16), KWP is
 * RFC 5649 (any length). Unwrapping returns null when the check fails.
 */
export var sm4_kw_wrap = M.kw_wrap;
export var sm4_kw_unwrap = M.kw_unwrap;
export var sm4_kwp_wrap = M.kwp_wrap;
export var sm4_kwp_unwrap = M.kwp_unwrap;
/* EAX (commons/eax.js) is defined over any 128-bit block cipher; the factory
   builds it for every one, so every one exports it */
export var sm4_eax_encrypt = M.eax_encrypt;
export var sm4_eax_decrypt = M.eax_decrypt;
