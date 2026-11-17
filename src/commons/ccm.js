/**
 * CCM  -  Counter with CBC-MAC, NIST SP 800-38C
 *
 * Generic over any 128-bit block cipher. AES-CCM is the famous instance -
 * WPA2, Bluetooth LE, TLS, Zigbee - but SM4-CCM is RFC 8998 alongside SM4-GCM,
 * and ARIA-CCM is RFC 6209. This file was inside aes.js until it became clear
 * that nothing in it is about AES.
 *
 * CCM is CBC-MAC for authentication followed by CTR for confidentiality, with
 * the tag encrypted under counter zero. It predates GCM and is slower - the
 * data is processed TWICE, once for each half - but it needs only the forward
 * block function and no finite-field multiplication, which is why it won in
 * constrained hardware.
 *
 * ITS AWKWARDNESS IS THE LENGTH ENCODING. The nonce and the message length
 * share fifteen bytes: a longer nonce leaves fewer bytes for the length and
 * therefore caps the message. That trade is fixed at encryption time and has
 * to be agreed by both sides, which is why CCM implementations disagree so
 * often about what nonce lengths they accept.
 *
 * The block cipher enters as a closure - block(src, off, out, out_off),
 * ENCRYPTION ONLY, in both directions. Same shape as commons/gcm.js and
 * commons/block_modes.js.
 */

import { equal, wipe } from './ct.js';
import { cbc_mac } from './cmac.js';

var BLOCK = 16;

function ccm_check(nonce_len, tag_len, pt_len) {
    if (nonce_len < 7 || nonce_len > 13) {
        throw new Error('ccm: nonce must be 7 to 13 bytes');
    }
    if (tag_len < 4 || tag_len > 16 || (tag_len & 1)) {
        throw new Error('ccm: tag length must be 4, 6, 8, 10, 12, 14 or 16');
    }
    var q = 15 - nonce_len;
    /* q bytes hold the length, so anything longer simply cannot be encoded */
    if (q < 8 && pt_len >= Math.pow(2, 8 * q)) {
        throw new Error('ccm: plaintext too long for a ' + nonce_len +
                        '-byte nonce - at most ' + (Math.pow(2, 8 * q) - 1) + ' bytes');
    }
    return q;
}

/**
 * Write v big-endian into the last q bytes of a 16-byte block.
 *
 * B0 carries the message length there and every counter block A_i carries i,
 * and the two loops had been written separately. Math.floor rather than >>>
 * because q can be 8 and the value can exceed 2^32.
 */
function put_q(b, q, v) {
    for (var i = 15; i >= 16 - q; i--) { b[i] = v & 0xff; v = Math.floor(v / 256); }
}

/**
 * The length of the associated data is itself length-prefixed, with a
 * variable-width encoding. Without it, moving bytes between the AAD and the
 * message could leave the MAC unchanged.
 */
function ccm_aad_header(n) {
    var b;
    if (n < 0xff00) {
        b = new Uint8Array(2);
        b[0] = (n >>> 8) & 0xff; b[1] = n & 0xff;
    } else if (n <= 0xffffffff) {
        b = new Uint8Array(6);
        b[0] = 0xff; b[1] = 0xfe;
        b[2] = (n >>> 24) & 0xff; b[3] = (n >>> 16) & 0xff;
        b[4] = (n >>> 8) & 0xff;  b[5] = n & 0xff;
    } else {
        b = new Uint8Array(10);
        b[0] = 0xff; b[1] = 0xff;
        var v = n;
        for (var i = 9; i >= 2; i--) { b[i] = v & 0xff; v = Math.floor(v / 256); }
    }
    return b;
}

/** CBC-MAC over B0, the encoded associated data, and the plaintext. */
function ccm_mac(block, nonce, q, aad, pt, tag_len) {
    var x = new Uint8Array(BLOCK);
    var blk = new Uint8Array(BLOCK);
    var i;

    /* B0: flags, nonce, then the message length in the remaining q bytes */
    blk[0] = (aad.length ? 0x40 : 0) | (((tag_len - 2) / 2) << 3) | (q - 1);
    for (i = 0; i < nonce.length; i++) { blk[1 + i] = nonce[i]; }
    put_q(blk, q, pt.length);

    block(blk, 0, x, 0);

    /* the CBC-MAC itself is the shared one in cmac.js, zero-padding the tail */
    if (aad.length) {
        var h = ccm_aad_header(aad.length);
        var buf = new Uint8Array(h.length + aad.length);
        buf.set(h, 0); buf.set(aad, h.length);
        cbc_mac(block, buf, x);
        wipe(buf);
    }
    if (pt.length) { cbc_mac(block, pt, x); }

    wipe(blk);
    return x;
}

/** Counter block A_i: flags, nonce, then i in the remaining q bytes. */
function ccm_ctr_block(nonce, q, i) {
    var a = new Uint8Array(BLOCK);
    a[0] = q - 1;
    for (var j = 0; j < nonce.length; j++) { a[1 + j] = nonce[j]; }
    put_q(a, q, i);
    return a;
}

/*
 * Its own counter loop, not block_modes.js's ctr_stream: on the shared core
 * CCM itself ran 5% faster, but AES-GCM - which does not touch this code -
 * measured 3-4% slower, the effect described at gctr in gcm.js.
 */
function ccm_apply(block, nonce, q, data) {
    var out = new Uint8Array(data.length);
    var ks = new Uint8Array(BLOCK);
    var i, j, n;
    for (i = 0; i < data.length; i += BLOCK) {
        /* the keystream starts at counter 1 - counter 0 is reserved to mask
           the tag, which is what keeps the tag independent of the ciphertext */
        var a = ccm_ctr_block(nonce, q, (i / BLOCK) + 1);
        block(a, 0, ks, 0);
        n = data.length - i; if (n > BLOCK) { n = BLOCK; }
        for (j = 0; j < n; j++) { out[i + j] = data[i + j] ^ ks[j]; }
    }
    wipe(ks);
    return out;
}

/**
 * @param  {Uint8Array} key    16, 24 or 32 bytes
 * @param  {Uint8Array} nonce  7 to 13 bytes. Shorter nonce, longer messages.
 * @param  {Uint8Array} plaintext
 * @param  {Uint8Array} [aad]
 * @param  {number}     [tag_len=16]
 * @return {Uint8Array} ciphertext followed by the tag
 */
export function ccm_encrypt(block, nonce, plaintext, aad, tag_len) {
    var t = (tag_len === undefined) ? 16 : tag_len;
    var q = ccm_check(nonce.length, t, plaintext.length);
    var a = aad || new Uint8Array(0);

    var mac = ccm_mac(block, nonce, q, a, plaintext, t);
    var s0 = new Uint8Array(BLOCK);
    block(ccm_ctr_block(nonce, q, 0), 0, s0, 0);

    var ct = ccm_apply(block, nonce, q, plaintext);

    var out = new Uint8Array(ct.length + t);
    out.set(ct, 0);
    for (var i = 0; i < t; i++) { out[ct.length + i] = mac[i] ^ s0[i]; }
    wipe(mac); wipe(s0);
    return out;
}

/** @return {Uint8Array|null} */
export function ccm_decrypt(block, nonce, sealed, aad, tag_len) {
    var t = (tag_len === undefined) ? 16 : tag_len;
    if (sealed.length < t) { return null; }

    var ct_len = sealed.length - t;
    var q = ccm_check(nonce.length, t, ct_len);
    var a = aad || new Uint8Array(0);

    var ct = sealed.subarray(0, ct_len);
    var tag = sealed.subarray(ct_len);
    var pt = ccm_apply(block, nonce, q, ct);

    var mac = ccm_mac(block, nonce, q, a, pt, t);
    var s0 = new Uint8Array(BLOCK);
    block(ccm_ctr_block(nonce, q, 0), 0, s0, 0);

    var expected = new Uint8Array(t);
    for (var i = 0; i < t; i++) { expected[i] = mac[i] ^ s0[i]; }
    wipe(mac); wipe(s0);

    /* the MAC covers the plaintext, so as with SIV it can only be checked
       after decrypting - and nothing leaves this function unless it matches */
    if (equal(expected, tag) !== 1) { wipe(pt); return null; }
    return pt;
}

