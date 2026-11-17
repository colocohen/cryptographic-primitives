/**
 * cmac.js - CMAC over any 128-bit block cipher, per NIST SP 800-38B.
 *
 * aes.js carried its own copy from the beginning, which was fine while AES
 * was the only caller - and kept its own copy of dbl128 after the move, until
 * that was exported below. ARIA, Camellia, SEED and SM4 are all 128-bit block
 * ciphers with their own CMAC test vectors, and a copy in each of them is how
 * a fix reaches one and not the others.
 *
 * ==================== THE TWO SUBKEYS ARE THE WHOLE TRICK ====================
 *
 * A plain CBC-MAC over a variable-length message is forgeable: given the tag
 * for M, an attacker computes the tag for M || (M xor tag) without the key.
 * CMAC breaks that by treating the last block differently, and by using a
 * DIFFERENT subkey depending on whether the message needed padding.
 *
 * If both cases used one subkey, a message of exactly one block and the same
 * message with 0x80 padding stripped would collide - so the padding would
 * carry no information and the length extension would come back.
 */

import { wipe, equal } from './ct.js';

var BLOCK = 16;

/**
 * Double in GF(2^128), in place.
 *
 * The reduction is folded in under a mask rather than a branch: the carry is
 * derived from the key, so branching on it would leak through timing.
 *
 * EXPORTED because aes.js had its own copy - character for character the same
 * - for OCB's L table and SIV's S2V. Two copies of a reduction constant is how
 * one of them gets "fixed" alone. XTS's tweak doubling in aes.js is NOT this
 * function: it is the same multiplication with the block read little-endian
 * (xts_shift(t) is reverse(dbl128(reverse(t)))), and stays where it is.
 */
export function dbl128(b) {
    var carry = b[0] >>> 7;
    for (var i = 0; i < 15; i++) {
        b[i] = ((b[i] << 1) | (b[i + 1] >>> 7)) & 0xff;
    }
    b[15] = (b[15] << 1) & 0xff;
    b[15] ^= 0x87 & (-carry);
}

/**
 * Raw CBC-MAC: for each 16-byte block, x = E(x xor block), updating x in place.
 *
 * A final partial block is ZERO-PADDED, which is what CCM's CBC-MAC wants; CMAC
 * and FF1 only ever pass whole blocks, so for them the padding never arises.
 *
 * ⚠ NOT A MAC ON ITS OWN. Plain CBC-MAC is forgeable over variable-length
 *   messages - see the note at the top of this file. Every caller wraps it in
 *   something that fixes the length or the last block: CMAC's subkeys, CCM's
 *   B0 length field, FF1's fixed-shape input.
 *
 * It was written four times before this - here, in ccm.js, in ff1.js and in
 * drbg.js's BCC - each with its own scratch handling.
 *
 * @param {function}   encrypt  (src, src_off, out, out_off)
 * @param {Uint8Array} data
 * @param {Uint8Array} [x]      the chaining value, 16 bytes; zero if omitted
 * @param {number}     [len]    how much of data to absorb; all of it if omitted
 * @return {Uint8Array} x
 */
export function cbc_mac(encrypt, data, x, len) {
    var y = x || new Uint8Array(BLOCK);
    var end = (len === undefined) ? data.length : len;
    var tmp = new Uint8Array(BLOCK);
    for (var o = 0; o < end; o += BLOCK) {
        var n = end - o; if (n > BLOCK) { n = BLOCK; }
        for (var k = 0; k < BLOCK; k++) { tmp[k] = y[k] ^ (k < n ? data[o + k] : 0); }
        encrypt(tmp, 0, y, 0);
    }
    wipe(tmp);
    return y;
}

/**
 * @param {function} encrypt  (src, src_off, out, out_off), 16 bytes each -
 *                            the shape every block cipher here already uses
 * @return {Array} the two subkeys
 */
export function subkeys(encrypt) {
    var l = new Uint8Array(BLOCK);
    encrypt(new Uint8Array(BLOCK), 0, l, 0);
    var k1 = new Uint8Array(l); dbl128(k1);
    var k2 = new Uint8Array(k1); dbl128(k2);
    wipe(l);
    return [k1, k2];
}

/**
 * CMAC over a message of any length, including empty.
 *
 * @param {function} encrypt  (src, src_off, out, out_off)
 * @param {Uint8Array} msg
 * @return {Uint8Array} the 16-byte tag
 */
export function cmac(encrypt, msg) {
    var ks = subkeys(encrypt);
    var k1 = ks[0], k2 = ks[1];

    var n = Math.ceil(msg.length / BLOCK);
    var complete = (msg.length > 0) && (msg.length % BLOCK === 0);
    if (n === 0) { n = 1; }

    var last = new Uint8Array(BLOCK);
    var i;

    if (complete) {
        for (i = 0; i < BLOCK; i++) { last[i] = msg[(n - 1) * BLOCK + i] ^ k1[i]; }
    } else {
        /* pad with 0x80 then zeros, and use the OTHER subkey - that is what
           stops a padded short message colliding with an unpadded full one */
        var rem = msg.length - (n - 1) * BLOCK;
        for (i = 0; i < rem; i++) { last[i] = msg[(n - 1) * BLOCK + i]; }
        last[rem] = 0x80;
        for (i = 0; i < BLOCK; i++) { last[i] ^= k2[i]; }
    }

    /* CBC-MAC over everything but the last block, zero IV, then the last */
    var x = cbc_mac(encrypt, msg, null, (n - 1) * BLOCK);
    cbc_mac(encrypt, last, x);

    wipe(k1); wipe(k2); wipe(last);
    return x;
}

/** Constant-time comparison - never compare a tag with ===. */
export function cmac_verify(encrypt, msg, tag) {
    return equal(cmac(encrypt, msg), tag) === 1;
}

/**
 * CMAC under a key set once, fed in pieces: the subkeys are computed here,
 * and every message after that costs only its blocks. The shape of every MAC
 * context here (hmac_create, kmac128_create): update(msg), copy(), digest().
 * For many messages under one key, keep this one and copy() it per message.
 *
 * ⚠ THE LAST BLOCK IS HELD BACK. Whether it is whole decides which subkey
 *   finishes it, and that is known only at digest() - so update() absorbs a
 *   block only once more input has arrived behind it.
 *
 * @param {function} encrypt  (src, src_off, out, out_off)
 * @return {{ update: function(Uint8Array), copy: function, digest: function(): Uint8Array }}
 */
export function cmac_create(encrypt) {
    var ks = subkeys(encrypt);
    return cmac_state(encrypt, ks[0], ks[1], new Uint8Array(BLOCK), new Uint8Array(BLOCK), 0);
}

/* x: the CBC-MAC chain so far; held, held_len: the bytes not yet absorbed (at most a block) */
function cmac_state(encrypt, k1, k2, x, held, held_len) {
    var done = false, scratch = new Uint8Array(BLOCK);
    function absorb_held() {
        for (var k = 0; k < BLOCK; k++) { held[k] ^= x[k]; }
        encrypt(held, 0, x, 0);
        held_len = 0;
    }
    var self = {
        update: function (msg) {
            if (done) { throw new Error('cmac: digest() was already called'); }
            var i = 0, len = msg.length;
            /* fill the held block; it is absorbed only once input follows it */
            if (held_len < BLOCK) {
                var fill = Math.min(BLOCK - held_len, len);
                for (var f = 0; f < fill; f++) { held[held_len + f] = msg[f]; }
                held_len += fill; i = fill;
            }
            if (i === len) { return self; }
            absorb_held();
            /* whole blocks straight from msg, all but one that may be the last */
            for (; len - i > BLOCK; i += BLOCK) {
                for (var k = 0; k < BLOCK; k++) { scratch[k] = x[k] ^ msg[i + k]; }
                encrypt(scratch, 0, x, 0);
            }
            for (var r = 0; i < len; r++, i++) { held[r] = msg[i]; }
            held_len = r;
            return self;
        },
        copy: function () {
            return cmac_state(encrypt, k1, k2, new Uint8Array(x), new Uint8Array(held), held_len);
        },
        digest: function () {
            if (done) { throw new Error('cmac: digest() was already called'); }
            done = true;
            var last = new Uint8Array(BLOCK), i;
            for (i = 0; i < held_len; i++) { last[i] = held[i]; }
            if (held_len === BLOCK) {
                for (i = 0; i < BLOCK; i++) { last[i] ^= k1[i]; }
            } else {
                last[held_len] = 0x80;
                for (i = 0; i < BLOCK; i++) { last[i] ^= k2[i]; }
            }
            cbc_mac(encrypt, last, x);
            wipe(last); wipe(held); wipe(scratch);
            return x;
        }
    };
    return self;
}
