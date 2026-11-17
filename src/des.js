/**
 * DES and Triple DES  -  FIPS 46-3, SP 800-67
 *
 * DES ALONE IS BROKEN AND MUST NOT BE USED. Its key is 56 bits, which was
 * brute-forced publicly in 1998 by a $250,000 machine in 56 hours and is now
 * within reach of a hobbyist FPGA in hours. It is here to read old data and
 * to speak to old systems, nothing else.
 *
 * TRIPLE DES IS DEPRECATED, not broken. NIST disallowed it for new
 * encryption after 2023. The reason is not the key length - three keys give
 * about 112 bits of security, which is fine - but the 64-BIT BLOCK. Birthday
 * collisions among ciphertext blocks start leaking plaintext relationships
 * after about 2^32 blocks, which is 32 GB under one key. The Sweet32 attack
 * turned that into a practical break of long-lived HTTPS and OpenVPN
 * sessions. Any use here needs a hard limit on data per key.
 *
 * It survives anyway in payment systems - EMV, PIN blocks, key ceremonies -
 * and in a great deal of stored data, which is why it is here.
 *
 * The design is a 16-round Feistel network wrapped in two bit permutations
 * that serve no cryptographic purpose at all; IP and its inverse were there
 * to make 1970s hardware wiring convenient. This implementation permutes bit
 * by bit, which is honest and slow. A table-driven version would be far
 * faster and is not worth writing for a cipher nobody should be choosing.
 */

import { bind_modes } from './commons/cipher_modes.js';

var BLOCK = 8;

/* Initial permutation and its inverse. Both are 1-indexed, as published. */
var IP = [
58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7];

var FP = [
40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25];

/* Expansion 32 -> 48, and the permutation applied after the S-boxes */
var E = [
32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
 8, 9,10,11,12,13, 12,13,14,15,16,17,
16,17,18,19,20,21, 20,21,22,23,24,25,
24,25,26,27,28,29, 28,29,30,31,32, 1];

var P = [
16, 7,20,21,29,12,28,17,  1,15,23,26, 5,18,31,10,
 2, 8,24,14,32,27, 3, 9, 19,13,30, 6,22,11, 4,25];

/* Key permutations. PC1 drops the eight parity bits; PC2 picks 48 of 56. */
var PC1 = [
57,49,41,33,25,17, 9,  1,58,50,42,34,26,18,
10, 2,59,51,43,35,27, 19,11, 3,60,52,44,36,
63,55,47,39,31,23,15,  7,62,54,46,38,30,22,
14, 6,61,53,45,37,29, 21,13, 5,28,20,12, 4];

var PC2 = [
14,17,11,24, 1, 5,  3,28,15, 6,21,10,
23,19,12, 4,26, 8, 16, 7,27,20,13, 2,
41,52,31,37,47,55, 30,40,51,45,33,48,
44,49,39,56,34,53, 46,42,50,36,29,32];

var SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

/* The eight S-boxes, four rows of sixteen each */
var S = [
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
  0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
  3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
  1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
[ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
  3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
[ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
  4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
[ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
  6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
  1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
  2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]];

/*
 * Structural checks.
 *
 * None of these tables can be derived - they are arbitrary design choices
 * from 1975 - so they have to be transcribed, and transcription is where this
 * project has been burned repeatedly. These assertions catch the realistic
 * failure modes before a single block is encrypted: a permutation that is not
 * a permutation, an S-box row that repeats a value, a table of the wrong
 * length. They cost one pass at load.
 */
/*
 * Runs at load, not on demand - it is an IIFE, which is why a scan for
 * uncalled functions will point at it. The tables below are permutations by
 * definition, and a transcription error in one would produce a cipher that
 * encrypts and decrypts consistently with itself and agrees with nobody.
 * Checking costs microseconds once.
 */
(function verify_tables() {
    function is_perm(t, n, name) {
        if (t.length !== n) { throw new Error('des: ' + name + ' has ' + t.length + ' entries, want ' + n); }
        var seen = {};
        for (var i = 0; i < n; i++) {
            if (t[i] < 1 || t[i] > n) { throw new Error('des: ' + name + ' entry out of range'); }
            if (seen[t[i]]) { throw new Error('des: ' + name + ' repeats ' + t[i]); }
            seen[t[i]] = 1;
        }
    }
    is_perm(IP, 64, 'IP');
    is_perm(FP, 64, 'FP');
    is_perm(P, 32, 'P');

    /* IP and FP must undo each other */
    for (var i = 0; i < 64; i++) {
        if (IP[FP[i] - 1] !== i + 1) { throw new Error('des: FP is not the inverse of IP'); }
    }

    /* E maps 32 bits to 48 with each source used at least once */
    if (E.length !== 48) { throw new Error('des: E must have 48 entries'); }
    var used = new Uint8Array(33);
    for (i = 0; i < 48; i++) { used[E[i]] = 1; }
    for (i = 1; i <= 32; i++) { if (!used[i]) { throw new Error('des: E omits bit ' + i); } }

    /* PC1 selects 56 distinct bits, and must skip every parity bit */
    if (PC1.length !== 56) { throw new Error('des: PC1 must have 56 entries'); }
    var seen1 = {};
    for (i = 0; i < 56; i++) {
        if (seen1[PC1[i]]) { throw new Error('des: PC1 repeats ' + PC1[i]); }
        if (PC1[i] % 8 === 0) { throw new Error('des: PC1 includes parity bit ' + PC1[i]); }
        seen1[PC1[i]] = 1;
    }

    if (PC2.length !== 48) { throw new Error('des: PC2 must have 48 entries'); }
    var seen2 = {};
    for (i = 0; i < 48; i++) {
        if (PC2[i] < 1 || PC2[i] > 56) { throw new Error('des: PC2 entry out of range'); }
        if (seen2[PC2[i]]) { throw new Error('des: PC2 repeats ' + PC2[i]); }
        seen2[PC2[i]] = 1;
    }

    /* every S-box row is a permutation of 0..15 */
    for (var b = 0; b < 8; b++) {
        if (S[b].length !== 64) { throw new Error('des: S' + (b + 1) + ' must have 64 entries'); }
        for (var r = 0; r < 4; r++) {
            var mark = new Uint8Array(16);
            for (var c = 0; c < 16; c++) { mark[S[b][r * 16 + c]] = 1; }
            for (c = 0; c < 16; c++) {
                if (!mark[c]) {
                    throw new Error('des: S' + (b + 1) + ' row ' + r + ' is not a permutation');
                }
            }
        }
    }

    var total = 0;
    for (i = 0; i < 16; i++) { total += SHIFTS[i]; }
    if (total !== 28) { throw new Error('des: key shifts must total 28'); }
}());

/** Read bit n (1-indexed, most significant first) from a byte array. */
function getbit(a, off, n) {
    return (a[off + ((n - 1) >>> 3)] >>> (7 - ((n - 1) & 7))) & 1;
}

/** Apply a bit permutation to a bit array. */
function permute(src, table) {
    var out = new Uint8Array(table.length);
    for (var i = 0; i < table.length; i++) { out[i] = src[table[i] - 1]; }
    return out;
}

function bytes_to_bits(a, off, n) {
    var b = new Uint8Array(n);
    for (var i = 0; i < n; i++) { b[i] = getbit(a, off, i + 1); }
    return b;
}

function bits_to_bytes(b, out, off) {
    for (var i = 0; i < b.length; i += 8) {
        var v = 0;
        for (var j = 0; j < 8; j++) { v = (v << 1) | b[i + j]; }
        out[off + (i >>> 3)] = v;
    }
}

/**
 * The key schedule: split into two 28-bit halves, rotate both by a per-round
 * amount, then select 48 bits. The parity bits dropped by PC1 are why a
 * 64-bit DES key carries only 56 bits of entropy.
 */
function expand_key(key, off) {
    var bits = bytes_to_bits(key, off, 64);
    var cd = permute(bits, PC1);
    var c = cd.subarray(0, 28), d = cd.subarray(28, 56);
    var rk = [];
    var i, j;

    for (i = 0; i < 16; i++) {
        var s = SHIFTS[i];
        var nc = new Uint8Array(28), nd = new Uint8Array(28);
        for (j = 0; j < 28; j++) { nc[j] = c[(j + s) % 28]; nd[j] = d[(j + s) % 28]; }
        c = nc; d = nd;
        var joined = new Uint8Array(56);
        joined.set(c, 0); joined.set(d, 28);
        rk.push(permute(joined, PC2));
    }
    return rk;
}

function feistel(r_bits, k) {
    var e = permute(r_bits, E);
    var i, j;
    for (i = 0; i < 48; i++) { e[i] ^= k[i]; }

    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) {
        var o = i * 6;
        /* the outer two bits pick the row, the inner four the column */
        var row = (e[o] << 1) | e[o + 5];
        var col = (e[o + 1] << 3) | (e[o + 2] << 2) | (e[o + 3] << 1) | e[o + 4];
        var v = S[i][row * 16 + col];
        for (j = 0; j < 4; j++) { out[i * 4 + j] = (v >>> (3 - j)) & 1; }
    }
    return permute(out, P);
}

function des_block(rk, src, off, out, out_off, reverse) {
    var bits = permute(bytes_to_bits(src, off, 64), IP);
    var l = bits.subarray(0, 32), r = bits.subarray(32, 64);
    var i, j;

    for (i = 0; i < 16; i++) {
        var k = rk[reverse ? (15 - i) : i];
        var f = feistel(r, k);
        var nl = new Uint8Array(r);
        for (j = 0; j < 32; j++) { f[j] ^= l[j]; }
        l = nl; r = f;
    }

    /* the halves are swapped before the final permutation */
    var pre = new Uint8Array(64);
    pre.set(r, 0); pre.set(l, 32);
    bits_to_bytes(permute(pre, FP), out, out_off);
}

/**
 * Triple DES in EDE order: encrypt with K1, DECRYPT with K2, encrypt with K3.
 *
 * The middle decryption is not a security measure - it exists so that setting
 * all three keys equal reduces exactly to single DES, which let 3DES hardware
 * stay backward compatible.
 */
function blocks3(key, reverse) {
    var k1, k2, k3;
    if (key.length === 24) {
        k1 = expand_key(key, 0); k2 = expand_key(key, 8); k3 = expand_key(key, 16);
    } else if (key.length === 16) {
        /* two-key 3DES: K3 = K1. About 80 bits of security against
           meet-in-the-middle, and disallowed by NIST since 2015. */
        k1 = expand_key(key, 0); k2 = expand_key(key, 8); k3 = k1;
    } else if (key.length === 8) {
        k1 = k2 = k3 = expand_key(key, 0);
    } else {
        throw new Error('des3: key must be 8, 16 or 24 bytes');
    }

    var t1 = new Uint8Array(BLOCK), t2 = new Uint8Array(BLOCK);
    return function (src, off, out, out_off) {
        if (!reverse) {
            des_block(k1, src, off, t1, 0, false);
            des_block(k2, t1, 0, t2, 0, true);
            des_block(k3, t2, 0, out, out_off, false);
        } else {
            des_block(k3, src, off, t1, 0, true);
            des_block(k2, t1, 0, t2, 0, false);
            des_block(k1, t2, 0, out, out_off, true);
        }
    };
}

function blocks1(key, reverse) {
    if (key.length !== 8) { throw new Error('des: key must be 8 bytes'); }
    var rk = expand_key(key, 0);
    return function (src, off, out, out_off) {
        des_block(rk, src, off, out, out_off, reverse);
    };
}

/*
 * The modes, generated by commons/cipher_modes.js. CBC pads with PKCS#7
 * unless no_pad and returns null on bad padding.
 *
 * ⚠ THESE WRAPPERS ONCE OMITTED THE ALIGNMENT CHECK the other ciphers had:
 *   no_pad with 13 bytes returned 13 bytes of ciphertext that nothing could
 *   decrypt. Shared wrappers cannot drift that way.
 */

/* ---------------- single DES ---------------- */

var M1 = bind_modes('des', BLOCK, blocks1);

export var des_ecb_encrypt = M1.ecb_encrypt;
export var des_ecb_decrypt = M1.ecb_decrypt;
/* ECB under a key set once: encrypt(data), decrypt(data) - see aes.js. */
export var des_ecb_create = M1.ecb_create;
export var des_cbc_encrypt = M1.cbc_encrypt;
export var des_cbc_decrypt = M1.cbc_decrypt;
export var des_ctr = M1.ctr;   /* built by the factory like des3_ctr; it was simply not exported */
/* CTR fed in pieces (and keyed AEAD contexts) - see aes.js. */
export var des_ctr_create = M1.ctr_create;

/* ---------------- Triple DES ---------------- */

var M3 = bind_modes('des3', BLOCK, blocks3);

export var des3_ecb_encrypt = M3.ecb_encrypt;
export var des3_ecb_decrypt = M3.ecb_decrypt;
/* ECB under a key set once: encrypt(data), decrypt(data) - see aes.js. */
export var des3_ecb_create = M3.ecb_create;
export var des3_cbc_encrypt = M3.cbc_encrypt;
export var des3_cbc_decrypt = M3.cbc_decrypt;
export var des3_ctr = M3.ctr;
/* CTR fed in pieces (and keyed AEAD contexts) - see aes.js. */
export var des3_ctr_create = M3.ctr_create;
