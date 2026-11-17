/**
 * RC2  -  RFC 2268
 *
 * Ron Rivest, 1987, published in 1998 after being reverse-engineered and
 * posted anonymously. It exists here for S/MIME, for PKCS#12 key stores, and
 * for a long tail of Microsoft file formats that still use it.
 *
 * 64-bit blocks and a key of 1 to 128 bytes, plus a separate "effective key
 * length" parameter.
 *
 * THAT SECOND PARAMETER IS THE UNUSUAL PART, and it is a historical artifact
 * worth understanding: RC2 lets a caller supply a long key while declaring a
 * shorter EFFECTIVE strength, and the key schedule then deliberately throws
 * away the extra entropy. It existed so that software could ship with 40-bit
 * effective keys to satisfy 1990s US export rules while still looking like it
 * used a longer key. Anything encrypted under a 40-bit effective key is
 * trivially breakable today regardless of how long the supplied key was.
 *
 * The default effective length is the key length in bits, which is what
 * almost every modern caller wants.
 *
 * STATUS: a related-key attack exists, and the 64-bit block brings the same
 * Sweet32 limit as 3DES and Blowfish. Read old data with it.
 *
 * PITABLE below was extracted programmatically from RFC 2268.
 */

import { bind_modes } from './commons/cipher_modes.js';
import { check_bijection } from './commons/gf256.js';

var BLOCK = 8;

/* A fixed random permutation of 0..255, used only in the key schedule */
var PITABLE = new Uint8Array([
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
]);

/* the same bijection check the S-boxes elsewhere get, from commons/gf256.js -
   this file had its own copy of the loop */
check_bijection(PITABLE, 'rc2 PITABLE');

/**
 * The key schedule.
 *
 * Two passes over a 128-byte buffer through PITABLE, with a mask applied in
 * between that is what actually enforces the effective key length. Reducing
 * that length does not shorten the key - it forces most of the expanded key
 * to be a deterministic function of a smaller part of it.
 *
 * @param {Uint8Array} key
 * @param {number}     [effective_bits]  defaults to the full key length
 */
function expand_key(key, effective_bits) {
    if (key.length < 1 || key.length > 128) {
        throw new Error('rc2: key must be 1 to 128 bytes');
    }
    var t1 = (effective_bits === undefined) ? key.length * 8 : effective_bits;
    if (t1 < 1 || t1 > 1024) { throw new Error('rc2: effective key length must be 1 to 1024 bits'); }

    var L = new Uint8Array(128);
    L.set(key, 0);
    var t = key.length;
    var i;

    for (i = t; i < 128; i++) {
        L[i] = PITABLE[(L[i - 1] + L[i - t]) & 0xff];
    }

    /* the mask keeps only as many bits of L[128-t8] as the effective length allows */
    var t8 = (t1 + 7) >>> 3;
    var tm = 0xff >>> ((8 - (t1 & 7)) & 7);
    L[128 - t8] = PITABLE[L[128 - t8] & tm];
    for (i = 127 - t8; i >= 0; i--) {
        L[i] = PITABLE[L[i + 1] ^ L[i + t8]];
    }

    /* the 64 round keys are the buffer read as little-endian 16-bit words */
    var K = new Int32Array(64);
    for (i = 0; i < 64; i++) { K[i] = L[i * 2] | (L[i * 2 + 1] << 8); }
    return K;
}

function rotl16(x, n) { return ((x << n) | (x >>> (16 - n))) & 0xffff; }

/**
 * Eighteen rounds in two kinds: sixteen MIX rounds, with a MASH round after
 * the fifth and the eleventh. MASH adds a key selected by the data itself,
 * which is the only data-dependent step in the cipher.
 */
function crypt_block(K, src, off, out, out_off, decrypting) {
    var r0 = src[off]     | (src[off + 1] << 8);
    var r1 = src[off + 2] | (src[off + 3] << 8);
    var r2 = src[off + 4] | (src[off + 5] << 8);
    var r3 = src[off + 6] | (src[off + 7] << 8);
    var j, i;

    function mix() {
        r0 = rotl16((r0 + K[j++] + (r3 & r2) + (~r3 & r1)) & 0xffff, 1);
        r1 = rotl16((r1 + K[j++] + (r0 & r3) + (~r0 & r2)) & 0xffff, 2);
        r2 = rotl16((r2 + K[j++] + (r1 & r0) + (~r1 & r3)) & 0xffff, 3);
        r3 = rotl16((r3 + K[j++] + (r2 & r1) + (~r2 & r0)) & 0xffff, 5);
    }
    function unmix() {
        r3 = ((rotl16(r3, 11) - K[--j] - (r2 & r1) - (~r2 & r0)) & 0xffff);
        r2 = ((rotl16(r2, 13) - K[--j] - (r1 & r0) - (~r1 & r3)) & 0xffff);
        r1 = ((rotl16(r1, 14) - K[--j] - (r0 & r3) - (~r0 & r2)) & 0xffff);
        r0 = ((rotl16(r0, 15) - K[--j] - (r3 & r2) - (~r3 & r1)) & 0xffff);
    }
    function mash() {
        r0 = (r0 + K[r3 & 63]) & 0xffff;
        r1 = (r1 + K[r0 & 63]) & 0xffff;
        r2 = (r2 + K[r1 & 63]) & 0xffff;
        r3 = (r3 + K[r2 & 63]) & 0xffff;
    }
    function unmash() {
        r3 = (r3 - K[r2 & 63]) & 0xffff;
        r2 = (r2 - K[r1 & 63]) & 0xffff;
        r1 = (r1 - K[r0 & 63]) & 0xffff;
        r0 = (r0 - K[r3 & 63]) & 0xffff;
    }

    if (!decrypting) {
        j = 0;
        for (i = 0; i < 5; i++) { mix(); }
        mash();
        for (i = 0; i < 6; i++) { mix(); }
        mash();
        for (i = 0; i < 5; i++) { mix(); }
    } else {
        j = 64;
        for (i = 0; i < 5; i++) { unmix(); }
        unmash();
        for (i = 0; i < 6; i++) { unmix(); }
        unmash();
        for (i = 0; i < 5; i++) { unmix(); }
    }

    out[out_off]     = r0 & 0xff; out[out_off + 1] = (r0 >>> 8) & 0xff;
    out[out_off + 2] = r1 & 0xff; out[out_off + 3] = (r1 >>> 8) & 0xff;
    out[out_off + 4] = r2 & 0xff; out[out_off + 5] = (r2 >>> 8) & 0xff;
    out[out_off + 6] = r3 & 0xff; out[out_off + 7] = (r3 >>> 8) & 0xff;
}

/*
 * THE KEY IS THE BYTES, OR { key, effective_bits }.
 *
 * RFC 2268's effective key length is a property of the KEY SCHEDULE, so it
 * travels with the key - which puts RC2 on exactly the (key, iv, data,
 * no_pad) shape every other cipher has, generated by commons/cipher_modes.js.
 * It used to be an extra positional argument wedged between data and no_pad,
 * the one reason RC2 had hand-written wrappers. A bare key gets T1 = 8 * its
 * length, the RFC's usual choice.
 */
function blocks(key, decrypting) {
    var bytes = key instanceof Uint8Array ? key : key && key.key;
    if (!(bytes instanceof Uint8Array)) { throw new TypeError('rc2: key must be bytes or { key, effective_bits }'); }
    var eb = key instanceof Uint8Array ? undefined : key.effective_bits;
    if (eb !== undefined && !Number.isInteger(eb)) {
        throw new TypeError('rc2: effective_bits must be an integer (1 to 1024)');
    }
    var K = expand_key(bytes, eb);
    return function (src, off, out, out_off) {
        crypt_block(K, src, off, out, out_off, decrypting);
    };
}

var M = bind_modes('rc2', BLOCK, blocks);

export var rc2_ecb_encrypt = M.ecb_encrypt;
export var rc2_ecb_decrypt = M.ecb_decrypt;
/* ECB under a key set once: encrypt(data), decrypt(data) - see aes.js. */
export var rc2_ecb_create = M.ecb_create;
/** CBC with PKCS#7 unless no_pad; decryption returns null on bad padding. */
export var rc2_cbc_encrypt = M.cbc_encrypt;
export var rc2_cbc_decrypt = M.cbc_decrypt;
export var rc2_ctr = M.ctr;
/* CTR fed in pieces (and keyed AEAD contexts) - see aes.js. */
export var rc2_ctr_create = M.ctr_create;
