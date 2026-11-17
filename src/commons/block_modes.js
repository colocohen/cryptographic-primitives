/**
 * Modes of operation, generic over any block cipher
 *
 * ECB, CBC, CTR and PKCS#7 do not care which cipher sits underneath them -
 * they only need a function that transforms one block. Extracted when SM4
 * arrived and reimplemented all four exactly as aes.js already had them, with
 * Camellia, ARIA, SEED and Triple DES lined up to do the same again.
 *
 * Each function takes a `crypt` callback of the shape
 *
 *     crypt(src, src_off, out, out_off)
 *
 * so the caller keeps its own key schedule in a closure and this file never
 * sees a key. What stays with each cipher is its block function and its key
 * expansion; what lives here is the plumbing around them.
 *
 * DELIBERATELY NOT HERE: GCM, CCM, OCB, SIV, XTS and the rest. Those are not
 * plumbing - each depends on properties of the cipher (a 128-bit block, a
 * specific field, an inverse function) and each carries its own security
 * argument. Generalising them would suggest they can be paired with any
 * cipher, which is not true and not safe to imply. The bindings of those modes
 * to the 128-bit ciphers that may use them are in commons/cipher_modes.js,
 * which refuses to offer them for any other block size.
 */

import { inc_be, check_room, overlaps_elsewhere } from './bytes.js';

/* ---------------- PKCS#7 ---------------- */

/**
 * Pad to the next block boundary with n bytes of value n.
 *
 * Aligned input still gets a whole extra block. Without that, a message
 * ending in a byte that looks like padding could not be told apart from a
 * padded one.
 */
export function pkcs7_pad(data, block) {
    var pad = block - (data.length % block);
    var out = new Uint8Array(data.length + pad);
    out.set(data, 0);
    for (var i = data.length; i < out.length; i++) { out[i] = pad; }
    return out;
}

/**
 * Strip PKCS#7, returning null if it is malformed.
 *
 * Null rather than a thrown error, and one indistinguishable failure for
 * every kind of malformation: a padding error that can be told apart from any
 * other rejection is a padding oracle. That mitigates but does not fix the
 * problem - the real fix is to authenticate the ciphertext.
 */
export function pkcs7_unpad(data, block) {
    if (data.length === 0 || data.length % block !== 0) { return null; }
    var pad = data[data.length - 1];
    if (pad < 1 || pad > block || pad > data.length) { return null; }
    for (var i = data.length - pad; i < data.length; i++) {
        if (data[i] !== pad) { return null; }
    }
    return data.subarray(0, data.length - pad);
}

/* ---------------- ECB ---------------- */

/**
 * Raw block-by-block, with no chaining.
 *
 * Identical plaintext blocks produce identical ciphertext blocks, so the
 * structure of the data survives encryption. Not a general-purpose mode -
 * see the note in aes.js on the narrow cases where it is appropriate.
 */
export function ecb(crypt, data, block, name) {
    if (data.length % block !== 0) {
        throw new Error(name + ': data must be a multiple of ' + block + ' bytes');
    }
    var out = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i += block) { crypt(data, i, out, i); }
    return out;
}

/*
 * ECB into out from `offset`, its length returned: each block is read whole
 * before it is written, so out may be the data's own memory at the same
 * place; overlapping it anywhere else, the blocks are made whole first.
 */
export function ecb_into(crypt, data, block, name, out, offset) {
    if (data.length % block !== 0) {
        throw new Error(name + ': data must be a multiple of ' + block + ' bytes');
    }
    check_room(name + '_into', out, offset, data.length);
    if (overlaps_elsewhere(out, offset, data.length, data)) { out.set(ecb(crypt, data, block, name), offset); return data.length; }
    for (var i = 0; i < data.length; i += block) { crypt(data, i, out, offset + i); }
    return data.length;
}

/* ---------------- CBC ---------------- */

/*
 * ⛔ THE CHECKS LIVE HERE, not only in each cipher's wrapper. Nine cipher files
 *   wrap these functions and the wrappers drifted: DES, 3DES and RC2 with
 *   no_pad passed 13 bytes straight through and got back 13 bytes of
 *   ciphertext nothing could decrypt (the last block read past the input as
 *   undefined), and Kuznyechik / Magma took a 5-byte IV without a word.
 */
function check_iv(iv, block) {
    if (!(iv instanceof Uint8Array) || iv.length !== block) {
        throw new Error('block_modes: iv must be ' + block + ' bytes');
    }
}
function check_aligned(data, block) {
    if (data.length % block !== 0) {
        throw new Error('block_modes: data must be a multiple of ' + block + ' bytes');
    }
}

/** @param {function} encrypt  one-block ENCRYPTION, both ways round */
export function cbc_encrypt(encrypt, iv, data, block) {
    check_iv(iv, block); check_aligned(data, block);
    var out = new Uint8Array(data.length);
    var prev = new Uint8Array(iv);
    var blk = new Uint8Array(block);
    var i, j;
    for (i = 0; i < data.length; i += block) {
        for (j = 0; j < block; j++) { blk[j] = data[i + j] ^ prev[j]; }
        encrypt(blk, 0, out, i);
        for (j = 0; j < block; j++) { prev[j] = out[i + j]; }
    }
    for (i = 0; i < block; i++) { blk[i] = 0; prev[i] = 0; }
    return out;
}

/** @param {function} decrypt  one-block DECRYPTION */
export function cbc_decrypt(decrypt, iv, data, block) {
    check_iv(iv, block); check_aligned(data, block);
    var out = new Uint8Array(data.length);
    var prev = new Uint8Array(iv);
    var i, j;
    for (i = 0; i < data.length; i += block) {
        decrypt(data, i, out, i);
        for (j = 0; j < block; j++) { out[i + j] ^= prev[j]; }
        /* the feedback is the CIPHERTEXT, so it must be read before it is
           overwritten when input and output are the same buffer */
        for (j = 0; j < block; j++) { prev[j] = data[i + j]; }
    }
    for (i = 0; i < block; i++) { prev[i] = 0; }
    return out;
}

/* ---------------- CTR ---------------- */

/**
 * The counter-mode core: encrypt the counter, xor the keystream into the
 * data, step the counter, repeat. Any length works; the last block is
 * partial.
 *
 * THE STEP IS THE CALLER'S, because the modes disagree about what a counter
 * is, and each convention is fixed by its standard:
 *
 *     ctr() below    the whole block, big-endian
 *     GCM-SIV        the FIRST four bytes, little-endian
 *     CTR_DRBG       the whole block, but stepped BEFORE each encryption
 *
 * and two that keep their own copy of the loop for speed - see the note at
 * gctr in gcm.js:
 *
 *     GCM            the last four bytes, big-endian
 *     CCM            the last q bytes, big-endian
 *
 * Each had its own copy before, which is why the note here used to say that
 * only the whole-block convention lived in this file.
 *
 * ⚠ `counter` IS USED IN PLACE and stepped only BETWEEN blocks, so after the
 *   call it holds the last value encrypted. Callers that want to keep their
 *   IV pass a copy, and wipe it; CTR_DRBG, which steps first and must be
 *   left on the last value used, steps once itself and passes V.
 *
 * @param {function}   encrypt  (src, src_off, out, out_off), one block
 * @param {Uint8Array} counter  `block` bytes, modified
 * @param {Uint8Array} data
 * @param {number}     block
 * @param {function}   step     step(field), in place
 * @param {Uint8Array} [out]    written in place if given; else allocated
 * @param {Uint8Array} [field]  what step is applied to - a view of the
 *                              counter's stepped bytes; the whole counter if
 *                              omitted, so a partial counter needs no
 *                              closure per call.
 * @return {Uint8Array} out
 */
export function ctr_stream(encrypt, counter, data, block, step, out, field) {
    var o = out || new Uint8Array(data.length);
    var f = field || counter;
    var ks = new Uint8Array(block);
    var i, j, n;
    for (i = 0; i < data.length; i += block) {
        if (i) { step(f); }
        encrypt(counter, 0, ks, 0);
        n = data.length - i; if (n > block) { n = block; }
        for (j = 0; j < n; j++) { o[i + j] = data[i + j] ^ ks[j]; }
    }
    for (i = 0; i < block; i++) { ks[i] = 0; }
    return o;
}

/**
 * Encrypt a counter, xor the result. Encryption and decryption are the same
 * operation, no padding is needed, and any length works.
 *
 * The counter is the whole block, incremented big-endian with bytes.js's
 * inc_be.
 */
export function ctr(encrypt, iv, data, block) {
    check_iv(iv, block);
    var counter = new Uint8Array(iv);
    var out = ctr_stream(encrypt, counter, data, block, inc_be);
    for (var i = 0; i < block; i++) { counter[i] = 0; }
    return out;
}

/**
 * A keystream cipher fed in pieces: update(data) returns data xor the next
 * len bytes of keystream, and may be called any number of times with any
 * lengths. Encryption and decryption are the same call, so one instance
 * serves both directions. copy() forks the position.
 *
 * ⭐ ALIGNED RUNS GO STRAIGHT TO THE CIPHER. Only a partial block at either
 *   end of a call goes through the saved keystream block; whole blocks in
 *   the middle are handed to xor_from in one run, as the one-shot form does.
 *
 * @param {function(Uint8Array, number): Uint8Array} xor_from
 *        xor_from(data, index): data xor keystream starting at block `index`;
 *        data is a whole number of blocks
 * @param {number} block  bytes per keystream block
 */
export function keystream_create(xor_from, block) {
    return keystream_instance(xor_from, block, 0, new Uint8Array(block));
}

function keystream_instance(xor_from, block, pos, ks) {
    var zero = new Uint8Array(block);
    var self = {
        update: function (data) {
            var len = data.length, out = new Uint8Array(len), off = 0, j;
            var used = pos % block;
            if (used !== 0) {
                var take = Math.min(block - used, len);
                for (j = 0; j < take; j++) { out[j] = data[j] ^ ks[used + j]; }
                off = take;
                pos += take;
            }
            var full = Math.floor((len - off) / block) * block;
            if (full > 0) {
                out.set(xor_from(data.subarray(off, off + full), pos / block), off);
                off += full;
                pos += full;
            }
            if (off < len) {
                ks.set(xor_from(zero, pos / block));
                for (j = 0; off + j < len; j++) { out[off + j] = data[off + j] ^ ks[j]; }
                pos += len - off;
            }
            return out;
        },
        copy: function () { return keystream_instance(xor_from, block, pos, new Uint8Array(ks)); },
        wipe: function () { ks.fill(0); }
    };
    return self;
}

/**
 * CTR fed in pieces, over keystream_create: the counter for block `index`
 * is the IV plus index, added big-endian across the whole block as ctr()
 * increments it.
 */
export function ctr_create(encrypt, iv, block) {
    check_iv(iv, block);
    var start = new Uint8Array(iv);
    return keystream_create(function (data, index) {
        var counter = new Uint8Array(start);
        add_be(counter, index);
        var out = ctr_stream(encrypt, counter, data, block, inc_be);
        counter.fill(0);
        return out;
    }, block);
}

/* counter += n, big-endian over the whole array, wrapping like inc_be */
function add_be(c, n) {
    for (var i = c.length - 1; i >= 0 && n > 0; i--) {
        var v = c[i] + (n % 256);
        n = Math.floor(n / 256);
        if (v > 255) { v -= 256; n += 1; }
        c[i] = v;
    }
}
