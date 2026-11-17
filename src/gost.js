/**
 * Kuznyechik and Magma  -  GOST R 34.12-2015, RFC 7801 and RFC 8891
 *
 * The two Russian federal block ciphers. Together with streebog.js they close
 * the set of national standards this library covers: SM4 is Chinese, ARIA and
 * SEED Korean, Camellia Japanese.
 *
 * KUZNYECHIK ("grasshopper") is the modern one: a 128-bit block with a
 * 256-bit key and ten rounds of substitute-then-diffuse. Its linear layer is
 * unusual - not a fixed matrix like AES's MixColumns but SIXTEEN STEPS OF AN
 * LFSR over GF(2^8), which is compact in hardware and awkward in software.
 *
 * MAGMA is the old one, and its history is the interesting part. It is GOST
 * 28147-89, published in 1989 with a 64-BIT BLOCK and a 256-BIT KEY - at a
 * time when DES shipped with 56 bits of key. A simple 32-round Feistel
 * network has held up for over thirty years.
 *
 * ITS ORIGINAL WEAKNESS WAS NOT THE ALGORITHM. The 1989 standard left the
 * S-boxes UNSPECIFIED and parameterisable: each organisation received its
 * own table, which meant the security of any given deployment was unknowable
 * from the standard alone, and a weak table could be issued deliberately.
 * The 2015 revision fixes one table for everyone, which is what makes Magma
 * analysable at all. Only that fixed table is implemented here.
 *
 * THE 64-BIT BLOCK IS A REAL LIMIT REGARDLESS. Birthday collisions appear
 * after about 2^32 blocks - 32 gigabytes - and the Sweet32 attacks showed
 * that is reachable in practice against a long-lived connection. Magma is
 * here for interoperability with existing data; Kuznyechik is the one to use.
 *
 * The substitution Kuznyechik uses lives in commons/gost.js along with the
 * note on its unexplained structure, which applies to Streebog equally.
 *
 * ON THE MODES. GOST R 34.13-2015 defines its own generalisations: its CBC
 * takes an initialisation REGISTER that may be several blocks long and shifts
 * by one block per step, and its CTR takes a HALF-BLOCK nonce that is
 * extended with a counter. With a one-block IV the first reduces exactly to
 * ordinary CBC, and with nonce||zeros the second reduces to ordinary CTR -
 * which is what the modes below provide, through commons/cipher_modes.js.
 * The longer-register variants are not implemented; a caller that needs them
 * is talking to a Russian-profile peer and should say so explicitly rather
 * than have it happen by passing a longer IV.
 */

import { GOST_PI, GOST_PI_INV } from './commons/gost.js';
import { gmul, POLY_GOST } from './commons/gf256.js';
import { bind_modes } from './commons/cipher_modes.js';
import { xor_bytes, rd_be32u, wr_be32 } from './commons/bytes.js';

/* ---------------- Kuznyechik ---------------- */

var BLOCK = 16;

/*
 * The LFSR coefficients, RFC 7801 section 4.2.
 *
 * NOTE ON A KNOWN ERRATUM: the RFC's formula reads "148*delta(a_15) +
 * 32*delta(a_15)" - the same index twice. The second is a_14. Implementing
 * the text literally gives a transform that is not invertible, so the mistake
 * is self-announcing, but it is worth naming.
 */
var LFSR_C = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1];

/*
 * ⭐ THE SIXTEEN COEFFICIENTS ARE CONSTANT, so every product they take part
 *   in can be tabulated: MULTAB[i][b] is gmul(b, LFSR_C[i]).
 *
 *   R folded a whole block with sixteen field multiplications and L ran R
 *   sixteen times, so one L cost 256 multiplications and a nine-round block
 *   cost about 2,300. Measured before: 0.1 MB/s - the slowest thing in the
 *   library by a wide margin.
 *
 * ⚠ THE TABLE IS 4 KiB AND BUILT AT LOAD, which is the same trade whirlpool
 *   took earlier: a fixed startup cost against a per-block one. Nothing here
 *   is key-dependent, so the table leaks nothing and can be shared.
 */
var MULTAB = /* @__PURE__ */ (function () {
    var t = [];
    for (var i = 0; i < 16; i++) {
        var row = new Uint8Array(256);
        for (var b = 0; b < 256; b++) { row[b] = gmul(b, LFSR_C[i], POLY_GOST); }
        t.push(row);
    }
    return t;
}());

/*
 * The LFSR fold over bytes 0..14: the sum of LFSR_C[i] * a[i]. R adds byte
 * 15's term to it; R_inv uses it to recover the byte R shifted out. Both used
 * to spell the fifteen lookups out.
 *
 * ⭐ table lookups, not field multiplications - see MULTAB above
 */
function fold15(a) {
    return MULTAB[0][a[0]] ^ MULTAB[1][a[1]] ^ MULTAB[2][a[2]] ^ MULTAB[3][a[3]] ^
           MULTAB[4][a[4]] ^ MULTAB[5][a[5]] ^ MULTAB[6][a[6]] ^ MULTAB[7][a[7]] ^
           MULTAB[8][a[8]] ^ MULTAB[9][a[9]] ^ MULTAB[10][a[10]] ^ MULTAB[11][a[11]] ^
           MULTAB[12][a[12]] ^ MULTAB[13][a[13]] ^ MULTAB[14][a[14]];
}

/** One LFSR step: fold the whole block into one byte and shift. */
function R(a) {
    var x = fold15(a) ^ MULTAB[15][a[15]];
    for (var j = 15; j > 0; j--) { a[j] = a[j - 1]; }
    a[0] = x;
}

function R_inv(a) {
    var x = a[0];
    for (var j = 0; j < 15; j++) { a[j] = a[j + 1]; }
    a[15] = x;
    /*
     * The last coefficient is 1, so recovering the shifted-out byte is a
     * plain xor rather than a division. (A multiplication by 1 through the
     * field used to be written here first and then overwritten.)
     */
    a[15] = fold15(a) ^ x;
}

/*
 * ⭐ L AS A SINGLE TABLE LOOKUP PER BYTE.
 *
 *   L is sixteen R steps, and R is linear over GF(2), so the whole of L is a
 *   linear map on the block: the output is the xor of sixteen 16-byte rows,
 *   one per input byte. LTAB[i][b] is L applied to a block that is `b` at
 *   position i and zero elsewhere.
 *
 *   With R already tabulated the block cost went from 0.1 MB/s to 1.8; this
 *   removes the remaining sixteen-fold loop.
 *
 * ⚠ 64 KiB OF TABLE, built by running the ORIGINAL R sixteen times on each
 *   basis vector - so the table is generated by the code it replaces rather
 *   than transcribed, and a mistake in it would have to be a mistake in R.
 *
 * ⛔ L_inv IS NOT TABULATED THE SAME WAY. It is used only by CBC and ECB
 *   decryption, and building a second 64 KiB table for it would double the
 *   startup cost for a path that is not on any hot loop measured here.
 */
var LTAB = /* @__PURE__ */ (function () {
    var t = [];
    var scratch = new Uint8Array(16);
    for (var i = 0; i < 16; i++) {
        var row = [];
        for (var b = 0; b < 256; b++) {
            for (var z = 0; z < 16; z++) { scratch[z] = 0; }
            scratch[i] = b;
            for (var r = 0; r < 16; r++) { R(scratch); }
            row.push(new Uint8Array(scratch));
        }
        t.push(row);
    }
    return t;
}());

function L(a) {
    var o0 = 0, o1 = 0, o2 = 0, o3 = 0, o4 = 0, o5 = 0, o6 = 0, o7 = 0;
    var o8 = 0, o9 = 0, o10 = 0, o11 = 0, o12 = 0, o13 = 0, o14 = 0, o15 = 0;
    for (var i = 0; i < 16; i++) {
        var v = LTAB[i][a[i]];
        o0 ^= v[0];   o1 ^= v[1];   o2 ^= v[2];   o3 ^= v[3];
        o4 ^= v[4];   o5 ^= v[5];   o6 ^= v[6];   o7 ^= v[7];
        o8 ^= v[8];   o9 ^= v[9];   o10 ^= v[10]; o11 ^= v[11];
        o12 ^= v[12]; o13 ^= v[13]; o14 ^= v[14]; o15 ^= v[15];
    }
    a[0] = o0;   a[1] = o1;   a[2] = o2;   a[3] = o3;
    a[4] = o4;   a[5] = o5;   a[6] = o6;   a[7] = o7;
    a[8] = o8;   a[9] = o9;   a[10] = o10; a[11] = o11;
    a[12] = o12; a[13] = o13; a[14] = o14; a[15] = o15;
}
function L_inv(a) { for (var i = 0; i < 16; i++) { R_inv(a); } }

function S(a)     { for (var i = 0; i < 16; i++) { a[i] = GOST_PI[a[i]]; } }
function S_inv(a) { for (var i = 0; i < 16; i++) { a[i] = GOST_PI_INV[a[i]]; } }

/* a ^= b over one block - bytes.js's xor_bytes, written in place */
function xor16(a, b) { xor_bytes(a, a, b, 16); }

/**
 * The key schedule: ten round keys from thirty-two Feistel rounds.
 *
 * The round constants are L applied to the numbers 1 to 32, which means the
 * schedule reuses the cipher's own diffusion rather than introducing new
 * material.
 */
function expand_key(key) {
    if (key.length !== 32) { throw new Error('kuznyechik: key must be 32 bytes'); }
    var rk = [];
    var k1 = key.slice(0, 16), k2 = key.slice(16);
    rk.push(k1, k2);

    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 8; j++) {
            var c = new Uint8Array(16);
            c[15] = 8 * i + j + 1;
            L(c);
            var t = Uint8Array.from(k1);
            xor16(t, c);
            S(t); L(t);
            xor16(t, k2);
            k2 = k1; k1 = t;
        }
        rk.push(Uint8Array.from(k1), Uint8Array.from(k2));
    }
    return rk;
}

function encrypt_block(rk, src, off, out, out_off) {
    var b = new Uint8Array(16);
    for (var i = 0; i < 16; i++) { b[i] = src[off + i]; }
    for (var r = 0; r < 9; r++) {
        xor16(b, rk[r]);
        S(b); L(b);
    }
    xor16(b, rk[9]);
    for (var j = 0; j < 16; j++) { out[out_off + j] = b[j]; }
}

function decrypt_block(rk, src, off, out, out_off) {
    var b = new Uint8Array(16);
    for (var i = 0; i < 16; i++) { b[i] = src[off + i]; }
    xor16(b, rk[9]);
    for (var r = 8; r >= 0; r--) {
        L_inv(b); S_inv(b);
        xor16(b, rk[r]);
    }
    for (var j = 0; j < 16; j++) { out[out_off + j] = b[j]; }
}

function blocks(key, decrypting) {
    var rk = expand_key(key);
    return function (src, off, out, out_off) {
        if (decrypting) { decrypt_block(rk, src, off, out, out_off); }
        else { encrypt_block(rk, src, off, out, out_off); }
    };
}

/* ==================== Kuznyechik: the modes ====================
 *
 * Generated by commons/cipher_modes.js, exactly as for AES, ARIA, Camellia,
 * SEED and SM4 - same names, same arguments, same null/throw rules.
 *
 * ⚠ THIS FILE USED TO HAVE ITS OWN WRAPPERS, and they had drifted from every
 *   other cipher: ECB PADDED (16 bytes in, 32 out, where every other ECB here
 *   is raw blocks), CBC always padded with no `no_pad`, no IV check, and none
 *   of the 128-bit modes the others get. And the padding was PKCS#7, which is
 *   not GOST's: GOST R 34.13-2015 section 4.1 defines its own (procedure 2 is
 *   0x80 then zeros). A caller wanting a Russian-profile peer's padding must
 *   apply procedure 1/2/3 itself and use no_pad, as with any other cipher.
 */
/** @param {Uint8Array} key  32 bytes */
var KZ = bind_modes('kuznyechik', BLOCK, blocks);

export var kuznyechik_ecb_encrypt = KZ.ecb_encrypt;
export var kuznyechik_ecb_decrypt = KZ.ecb_decrypt;
/* ECB under a key set once: encrypt(data), decrypt(data) - see aes.js. */
export var kuznyechik_ecb_create = KZ.ecb_create;
export var kuznyechik_cbc_encrypt = KZ.cbc_encrypt;
export var kuznyechik_cbc_decrypt = KZ.cbc_decrypt;
export var kuznyechik_ctr = KZ.ctr;
/* CTR fed in pieces (and keyed AEAD contexts) - see aes.js. */
export var kuznyechik_ctr_create = KZ.ctr_create;
export var kuznyechik_gcm_encrypt = KZ.gcm_encrypt;
export var kuznyechik_gcm_decrypt = KZ.gcm_decrypt;
export var kuznyechik_gcm_create = KZ.gcm_create;
export var kuznyechik_ccm_create = KZ.ccm_create;
export var kuznyechik_eax_create = KZ.eax_create;
export var kuznyechik_gmac = KZ.gmac;
export var kuznyechik_gmac_verify = KZ.gmac_verify;
export var kuznyechik_ccm_encrypt = KZ.ccm_encrypt;
export var kuznyechik_ccm_decrypt = KZ.ccm_decrypt;
/** CMAC - which is GOST R 34.13-2015's MAC mode (section 5.6) for a full-length tag. */
export var kuznyechik_cmac = KZ.cmac;
export var kuznyechik_cmac_verify = KZ.cmac_verify;
export var kuznyechik_cmac_create = KZ.cmac_create;
export var kuznyechik_kw_wrap = KZ.kw_wrap;
export var kuznyechik_kw_unwrap = KZ.kw_unwrap;
export var kuznyechik_kwp_wrap = KZ.kwp_wrap;
export var kuznyechik_kwp_unwrap = KZ.kwp_unwrap;
/* EAX (commons/eax.js) is defined over any 128-bit block cipher; the factory
   builds it for every one, so every one exports it */
export var kuznyechik_eax_encrypt = KZ.eax_encrypt;
export var kuznyechik_eax_decrypt = KZ.eax_decrypt;

/* ---------------- Magma ---------------- */

/*
 * The eight 4-bit S-boxes, RFC 8891 section 4.1 - the FIXED set the 2015
 * revision introduced. See the note above on why they were not always fixed.
 */
var MAGMA_SBOX = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
];

/** The 32-bit round function, precomputed as four 8-bit tables. */
var MAGMA_T = /* @__PURE__ */ (function () {
    var t = [];
    for (var i = 0; i < 4; i++) {
        var row = new Uint8Array(256);
        for (var b = 0; b < 256; b++) {
            row[b] = (MAGMA_SBOX[2 * i + 1][b >> 4] << 4) | MAGMA_SBOX[2 * i][b & 0x0f];
        }
        t.push(row);
    }
    return t;
}());

/** g(k, a) = t(a + k mod 2^32) rotated left by 11. */
function magma_g(k, a) {
    /* the addition is modulo 2^32 and must not go through a signed int */
    var s = ((a >>> 0) + (k >>> 0)) % 4294967296;
    var v = ((MAGMA_T[3][(s >>> 24) & 0xff] << 24) |
             (MAGMA_T[2][(s >>> 16) & 0xff] << 16) |
             (MAGMA_T[1][(s >>> 8) & 0xff] << 8) |
             MAGMA_T[0][s & 0xff]) >>> 0;
    return ((v << 11) | (v >>> 21)) >>> 0;
}

function magma_keys(key) {
    if (key.length !== 32) { throw new Error('magma: key must be 32 bytes'); }
    var k = new Array(8);
    for (var i = 0; i < 8; i++) {
        k[i] = rd_be32u(key, 4 * i);
    }
    return k;
}

/**
 * Thirty-two Feistel rounds.
 *
 * The key order is what makes encryption and decryption the same code: the
 * first twenty-four rounds cycle K1..K8 three times, and the last eight run
 * K8..K1. Decryption is the exact reverse of that sequence.
 */
function magma_block(k, hi, lo, decrypting) {
    var order = [];
    var i;
    if (decrypting) {
        for (i = 0; i < 8; i++) { order.push(i); }
        for (var r = 0; r < 3; r++) { for (i = 7; i >= 0; i--) { order.push(i); } }
    } else {
        for (var r2 = 0; r2 < 3; r2++) { for (i = 0; i < 8; i++) { order.push(i); } }
        for (i = 7; i >= 0; i--) { order.push(i); }
    }

    var a = hi, b = lo;
    for (i = 0; i < 32; i++) {
        var t = (a ^ magma_g(k[order[i]], b)) >>> 0;
        a = b; b = t;
    }
    /* the final swap is omitted, which is why the halves come back exchanged */
    return [b, a];
}

function magma_blocks(key, decrypting) {
    var k = magma_keys(key);
    return function (src, off, out, out_off) {
        var r = magma_block(k, rd_be32u(src, off), rd_be32u(src, off + 4), decrypting);
        wr_be32(out, out_off, r[0]);
        wr_be32(out, out_off + 4, r[1]);
    };
}

var MAGMA_BLOCK = 8;

/**
 * Magma's modes, from the same factory as DES and Blowfish (64-bit block:
 * ECB, CBC, CTR). The key is 32 bytes.
 *
 * THE 64-BIT BLOCK CAPS SAFE USE at well under 2^32 blocks under one key.
 * See the note at the top of this file.
 */
var MG = bind_modes('magma', MAGMA_BLOCK, magma_blocks);

export var magma_ecb_encrypt = MG.ecb_encrypt;
export var magma_ecb_decrypt = MG.ecb_decrypt;
/* ECB under a key set once: encrypt(data), decrypt(data) - see aes.js. */
export var magma_ecb_create = MG.ecb_create;
export var magma_cbc_encrypt = MG.cbc_encrypt;
export var magma_cbc_decrypt = MG.cbc_decrypt;
export var magma_ctr = MG.ctr;
/* CTR fed in pieces (and keyed AEAD contexts) - see aes.js. */
export var magma_ctr_create = MG.ctr_create;
