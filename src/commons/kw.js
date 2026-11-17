/**
 * kw.js - the AES Key Wrap construction, over any 128-bit block cipher.
 *
 * RFC 3394 for KW and RFC 5649 for KWP, which adds padding so a key of any
 * length can be wrapped rather than only multiples of eight bytes.
 *
 * ==================== WHY A DEDICATED MODE ====================
 *
 * Wrapping a key is not the same problem as encrypting a message, and using
 * a normal AEAD for it needs a nonce - which the wrapping context often has
 * nowhere to put, and which is catastrophic to repeat. KW is deterministic
 * and needs none: it gets its integrity from the six-pass structure below,
 * where every output block depends on every input block, so a single altered
 * byte destroys the recovered integrity check.
 *
 * ==================== THE INTEGRITY CHECK IS THE POINT ====================
 *
 * Unwrapping ends by comparing the recovered A against a fixed constant. If
 * it differs the whole result is discarded, and it MUST be discarded rather
 * than returned - a caller handed a plaintext plus a flag will eventually
 * use the plaintext. That is why unwrap returns null rather than an object
 * with a validity field.
 *
 * The comparison is constant time for the usual reason: an attacker who can
 * time it learns how much of a forged wrapper was right.
 *
 * aes.js carried this alone until ARIA, Camellia and SEED needed it too -
 * all 128-bit block ciphers, all with their own vectors, and three more
 * copies is how a fix reaches one and not the rest.
 */

import { wipe, equal } from './ct.js';
import { wr_be32, rd_be32u } from './bytes.js';

var BLOCK = 16;

/** RFC 3394's default initial value. */
export var KW_IV = /* @__PURE__ */ new Uint8Array(
    [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);

/** RFC 5649's, whose low four bytes carry the unpadded length. */
export var KWP_PREFIX = /* @__PURE__ */ new Uint8Array([0xa6, 0x59, 0x59, 0xa6]);

/**
 * XOR the step counter t into an 8-byte value, big-endian at the low end.
 *
 * The wrap and unwrap halves of kw_core each carried this loop. Math.floor
 * rather than >>> because n * 6 can in principle pass 2^32.
 */
function xor_step(a, t) {
    for (var k = 7; k >= 0 && t > 0; k--) { a[k] ^= t & 0xff; t = Math.floor(t / 256); }
}

/**
 * The six-pass shuffle, forwards or backwards.
 *
 * @param {function} encrypt  (src, src_off, out, out_off)
 * @param {function} decrypt  the same shape; only needed when unwrapping
 */
function kw_core(encrypt, decrypt, a, r, n, unwrap) {
    var b = new Uint8Array(BLOCK);
    var i, j, k;

    if (!unwrap) {
        for (j = 0; j <= 5; j++) {
            for (i = 1; i <= n; i++) {
                for (k = 0; k < 8; k++) { b[k] = a[k]; b[8 + k] = r[(i - 1) * 8 + k]; }
                encrypt(b, 0, b, 0);
                for (k = 0; k < 8; k++) { a[k] = b[k]; }
                /* the round counter is xored in big-endian at the low end */
                xor_step(a, n * j + i);
                for (k = 0; k < 8; k++) { r[(i - 1) * 8 + k] = b[8 + k]; }
            }
        }
    } else {
        for (j = 5; j >= 0; j--) {
            for (i = n; i >= 1; i--) {
                for (k = 0; k < 8; k++) { b[k] = a[k]; }
                xor_step(b, n * j + i);
                for (k = 0; k < 8; k++) { b[8 + k] = r[(i - 1) * 8 + k]; }
                decrypt(b, 0, b, 0);
                for (k = 0; k < 8; k++) { a[k] = b[k]; }
                for (k = 0; k < 8; k++) { r[(i - 1) * 8 + k] = b[8 + k]; }
            }
        }
    }
    wipe(b);
}

/** RFC 3394. The data must be a whole number of 8-byte blocks, at least two. */
export function kw_wrap(encrypt, data) {
    if (data.length < 16 || data.length % 8 !== 0) {
        throw new Error('kw: data must be a multiple of 8 bytes, at least 16');
    }
    var a = new Uint8Array(KW_IV);
    var r = new Uint8Array(data);
    kw_core(encrypt, null, a, r, data.length / 8, false);

    var out = new Uint8Array(8 + data.length);
    out.set(a, 0); out.set(r, 8);
    return out;
}

/** @return {Uint8Array|null} null when the integrity check fails */
export function kw_unwrap(encrypt, decrypt, wrapped) {
    if (wrapped.length < 24 || wrapped.length % 8 !== 0) { return null; }
    var a = new Uint8Array(wrapped.subarray(0, 8));
    var r = new Uint8Array(wrapped.subarray(8));
    kw_core(encrypt, decrypt, a, r, r.length / 8, true);

    if (equal(a, KW_IV) !== 1) { wipe(r); return null; }
    return r;
}

/**
 * RFC 5649, which wraps a key of ANY length.
 *
 * The initial value carries the true length in its low four bytes, and the
 * data is zero-padded to a multiple of eight. A single 8-byte block is
 * handled by one plain block encryption rather than the six-pass loop, which
 * needs at least two.
 */
export function kwp_wrap(encrypt, data) {
    if (data.length === 0) { throw new Error('kwp: nothing to wrap'); }
    var padded = Math.ceil(data.length / 8) * 8;
    var a = new Uint8Array(8);
    a.set(KWP_PREFIX, 0);
    wr_be32(a, 4, data.length);

    var r = new Uint8Array(padded);
    r.set(data, 0);

    if (padded === 8) {
        var b = new Uint8Array(BLOCK);
        b.set(a, 0); b.set(r, 8);
        encrypt(b, 0, b, 0);
        return b;
    }
    kw_core(encrypt, null, a, r, padded / 8, false);
    var out = new Uint8Array(8 + padded);
    out.set(a, 0); out.set(r, 8);
    return out;
}

/** @return {Uint8Array|null} null when the check or the length is wrong */
export function kwp_unwrap(encrypt, decrypt, wrapped) {
    if (wrapped.length < 16 || wrapped.length % 8 !== 0) { return null; }
    var a, r;

    if (wrapped.length === 16) {
        var b = new Uint8Array(wrapped);
        decrypt(b, 0, b, 0);
        a = b.subarray(0, 8);
        r = b.subarray(8);
    } else {
        a = new Uint8Array(wrapped.subarray(0, 8));
        r = new Uint8Array(wrapped.subarray(8));
        kw_core(encrypt, decrypt, a, r, r.length / 8, true);
    }

    if (equal(a.subarray(0, 4), KWP_PREFIX) !== 1) { return null; }
    var len = rd_be32u(a, 4);
    /*
     * The declared length must land inside the last block. A longer value
     * would read past the buffer and a shorter one would leave padding that
     * was never checked, either of which lets a forged wrapper through.
     */
    if (len > r.length || len <= r.length - 8) { return null; }
    for (var i = len; i < r.length; i++) {
        if (r[i] !== 0) { return null; }
    }
    return r.slice(0, len);
}
