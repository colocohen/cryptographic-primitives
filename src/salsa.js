/**
 * Salsa20, XSalsa20 and secretbox
 *
 * Bernstein's 2005 stream cipher, and the direct ancestor of ChaCha20. ChaCha
 * came three years later as a refinement: same cost, better diffusion per
 * round. For anything new, reach for ChaCha20 in chacha.js.
 *
 * This file exists for compatibility, and the compatibility is not marginal.
 * NaCl, libsodium and TweetNaCl all built crypto_secretbox on
 * XSalsa20-Poly1305, so a very large amount of stored and in-flight data is
 * in this format. ChaCha20 cannot read any of it.
 *
 * WHAT XSALSA20 SOLVED, AND WHY IT MATTERS HERE
 * Salsa20's nonce is 8 bytes - far too small to choose at random. XSalsa20
 * widens it to 24 by first deriving a subkey with HSalsa20, and 24 bytes is
 * wide enough that random selection is safe without any counter. That is the
 * same trick XChaCha20 uses, and XSalsa20 is where it was invented.
 *
 * The core is shared with scrypt through commons/salsa.js: scrypt runs the
 * same rounds eight times instead of twenty.
 */

import { salsa_core, hsalsa_core } from './commons/salsa.js';
import { poly1305 } from './chacha.js';
import { equal } from './commons/ct.js';
import { keystream_create } from './commons/block_modes.js';
import { rd_le32, wr_le32s } from './commons/bytes.js';

var BLOCK = 64;

/* "expand 32-byte k", split across the four corner words */
var C0 = 0x61707865 | 0, C1 = 0x3320646e | 0,
    C2 = 0x79622d32 | 0, C3 = 0x6b206574 | 0;

var st = new Int32Array(16);
var out16 = new Int32Array(16);
var ks = new Uint8Array(BLOCK);

/**
 * Salsa20's state layout scatters the constants to the diagonal rather than
 * grouping them at the front the way ChaCha20 does.
 */
function load_state(key, nonce, n_off, ctr_lo, ctr_hi) {
    st[0]  = C0;
    st[1]  = rd_le32(key, 0);  st[2]  = rd_le32(key, 4);
    st[3]  = rd_le32(key, 8);  st[4]  = rd_le32(key, 12);
    st[5]  = C1;
    st[6]  = rd_le32(nonce, n_off);     st[7]  = rd_le32(nonce, n_off + 4);
    st[8]  = ctr_lo;                 st[9]  = ctr_hi;
    st[10] = C2;
    st[11] = rd_le32(key, 16); st[12] = rd_le32(key, 20);
    st[13] = rd_le32(key, 24); st[14] = rd_le32(key, 28);
    st[15] = C3;
}

function keystream_block(key, nonce, n_off, ctr_lo, ctr_hi) {
    load_state(key, nonce, n_off, ctr_lo, ctr_hi);
    salsa_core(st, out16, 20);
    /*
     * Written out rather than bytes.js's wr_le32s, which does the same thing:
     * this runs once per 64 bytes of stream, and the call measured 5-7%
     * slower on 64 KiB of salsa20.
     */
    for (var i = 0; i < 16; i++) {
        var w = out16[i];
        ks[i * 4]     = w & 0xff;          ks[i * 4 + 1] = (w >>> 8) & 0xff;
        ks[i * 4 + 2] = (w >>> 16) & 0xff; ks[i * 4 + 3] = (w >>> 24) & 0xff;
    }
}

/**
 * Salsa20 stream cipher.
 *
 * Encryption and decryption are the same operation - it only xors a
 * keystream - and it provides no integrity whatever. Flipping a ciphertext
 * bit flips the same plaintext bit. Use secretbox below unless a protocol
 * specifically asks for the bare stream.
 *
 * The counter is 64-bit here, unlike ChaCha20's 32-bit one, so overflow is
 * not a practical concern.
 *
 * @param  {Uint8Array} key    32 bytes
 * @param  {Uint8Array} nonce  8 bytes - too small to choose at random
 * @param  {Uint8Array} data
 * @param  {number}     [counter=0]
 * @return {Uint8Array}
 */
export function salsa20(key, nonce, data, counter) {
    if (key.length !== 32) { throw new Error('salsa20: key must be 32 bytes'); }
    if (nonce.length !== 8) { throw new Error('salsa20: nonce must be 8 bytes'); }

    var lo = (counter === undefined) ? 0 : (counter >>> 0);
    var hi = 0;
    var out = new Uint8Array(data.length);
    var i, j, n;

    for (i = 0; i < data.length; i += BLOCK) {
        keystream_block(key, nonce, 0, lo | 0, hi | 0);
        n = data.length - i; if (n > BLOCK) { n = BLOCK; }
        for (j = 0; j < n; j++) { out[i + j] = data[i + j] ^ ks[j]; }
        lo = (lo + 1) >>> 0;
        if (lo === 0) { hi = (hi + 1) >>> 0; }
    }
    for (i = 0; i < BLOCK; i++) { ks[i] = 0; }
    return out;
}

/**
 * HSalsa20 - the key derivation behind XSalsa20.
 *
 * Runs the twenty rounds but skips the add-back and returns eight specific
 * words. That omission is what makes it one-way.
 *
 * @param  {Uint8Array} key    32 bytes
 * @param  {Uint8Array} nonce  16 bytes
 * @return {Uint8Array} a 32-byte subkey
 */
export function hsalsa20(key, nonce) {
    if (key.length !== 32) { throw new Error('hsalsa20: key must be 32 bytes'); }
    if (nonce.length !== 16) { throw new Error('hsalsa20: nonce must be 16 bytes'); }

    load_state(key, nonce, 0, rd_le32(nonce, 8), rd_le32(nonce, 12));

    var words = new Int32Array(8);
    hsalsa_core(st, words);

    var out = new Uint8Array(32);
    wr_le32s(out, 0, words);
    for (var i = 0; i < 8; i++) { words[i] = 0; }
    return out;
}

/**
 * XSalsa20 - Salsa20 with a 24-byte nonce.
 *
 * The first 16 bytes derive a subkey through HSalsa20; the last 8 become the
 * ordinary Salsa20 nonce. 24 bytes is wide enough to choose at random.
 */
export function xsalsa20(key, nonce, data, counter) {
    if (nonce.length !== 24) { throw new Error('xsalsa20: nonce must be 24 bytes'); }
    var subkey = hsalsa20(key, nonce.subarray(0, 16));
    var out = salsa20(subkey, nonce.subarray(16, 24), data, counter);
    for (var i = 0; i < 32; i++) { subkey[i] = 0; }
    return out;
}

/* ================= secretbox ================= */
/*
 * XSalsa20-Poly1305, as NaCl's crypto_secretbox.
 *
 * The construction differs from ChaCha20-Poly1305 in two ways worth knowing:
 *
 *   1. The Poly1305 key is the FIRST 32 bytes of the keystream, and the
 *      plaintext is encrypted starting at byte 32 of that same stream - not
 *      from a separate counter block. Same idea, different bookkeeping.
 *   2. There is no associated data. NaCl's secretbox authenticates the
 *      ciphertext and nothing else. Anything that needs AAD wants
 *      xchacha20poly1305 instead.
 *
 * The tag comes FIRST in the output, unlike the AEADs in chacha.js where it
 * trails. That is NaCl's layout and changing it would defeat the point.
 */

var ZEROS = new Uint8Array(32);

function seal_stream(key, nonce, data) {
    /*
     * Encrypt 32 zero bytes followed by the data. The first 32 output bytes
     * are the keystream itself, which becomes the one-time Poly1305 key; the
     * rest is the ciphertext.
     */
    var padded = new Uint8Array(32 + data.length);
    padded.set(data, 32);
    var s = xsalsa20(key, nonce, padded);
    for (var i = 0; i < 32 + data.length; i++) { padded[i] = 0; }
    return s;
}

/**
 * @param  {Uint8Array} key    32 bytes
 * @param  {Uint8Array} nonce  24 bytes
 * @param  {Uint8Array} plaintext
 * @return {Uint8Array} 16-byte tag followed by the ciphertext
 */
export function secretbox(key, nonce, plaintext) {
    if (key.length !== 32) { throw new Error('secretbox: key must be 32 bytes'); }
    if (nonce.length !== 24) { throw new Error('secretbox: nonce must be 24 bytes'); }

    var s = seal_stream(key, nonce, plaintext);
    var otk = s.subarray(0, 32);
    var ct = s.subarray(32);

    var tag = poly1305(otk, ct);

    var out = new Uint8Array(16 + ct.length);
    out.set(tag, 0);
    out.set(ct, 16);

    for (var i = 0; i < s.length; i++) { s[i] = 0; }
    return out;
}

/**
 * Returns null on authentication failure - not a thrown error, and never a
 * partial plaintext. The tag is checked before anything is released.
 *
 * @return {Uint8Array|null}
 */
export function secretbox_open(key, nonce, sealed) {
    if (key.length !== 32) { throw new Error('secretbox: key must be 32 bytes'); }
    if (nonce.length !== 24) { throw new Error('secretbox: nonce must be 24 bytes'); }
    if (sealed.length < 16) { return null; }

    var tag = sealed.subarray(0, 16);
    var ct = sealed.subarray(16);

    /* Regenerate the same keystream to recover the one-time key */
    var s = seal_stream(key, nonce, new Uint8Array(ct.length));
    var otk = s.subarray(0, 32);

    var expected = poly1305(otk, ct);
    if (equal(expected, tag) !== 1) {
        for (var i = 0; i < s.length; i++) { s[i] = 0; }
        return null;
    }

    var out = new Uint8Array(ct.length);
    for (i = 0; i < ct.length; i++) { out[i] = ct[i] ^ s[32 + i]; }
    for (i = 0; i < s.length; i++) { s[i] = 0; }
    return out;
}

/** NaCl's name for the same thing. */
export var xsalsa20poly1305_encrypt = secretbox;
export var xsalsa20poly1305_decrypt = secretbox_open;

/* ---------------- Incremental ---------------- */
/*
 * Salsa20 and XSalsa20 fed in pieces: update(data) returns data xor the next
 * bytes of keystream, either direction; copy() forks the position. The
 * counter is the 64-bit block counter, as in the one-shot forms.
 */
export function salsa20_create(key, nonce, counter) {
    var k = new Uint8Array(key), n = new Uint8Array(nonce);
    var start = counter === undefined ? 0 : counter;
    salsa20(k, n, new Uint8Array(0), start);   /* the one-shot form's argument checks, now */
    return keystream_create(function (data, index) {
        return salsa20(k, n, data, start + index);
    }, 64);
}

export function xsalsa20_create(key, nonce, counter) {
    if (nonce.length !== 24) { throw new Error('xsalsa20: nonce must be 24 bytes'); }
    var subkey = hsalsa20(key, nonce.subarray(0, 16));
    var s = salsa20_create(subkey, nonce.subarray(16, 24), counter);
    subkey.fill(0);
    return s;
}
