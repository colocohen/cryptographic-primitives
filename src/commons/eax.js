/**
 * eax.js - EAX mode, over any 128-bit block cipher.
 *
 * An AEAD built from CTR and CMAC and nothing else, which is what makes it
 * worth having: a device that already has a block cipher gets authenticated
 * encryption without a second primitive, and the security proof reduces to
 * the cipher alone.
 *
 * ==================== THE THREE OMACs ARE THE DESIGN ====================
 *
 * EAX computes CMAC three times over the same key, tagged by a leading
 * counter block:
 *
 *     N = CMAC(0 || nonce)      the CTR starting value
 *     H = CMAC(1 || header)     over the associated data
 *     C = CMAC(2 || ciphertext)
 *     tag = N xor H xor C
 *
 * THE TAGS ARE WHAT MAKES IT SAFE. Without them the same key would MAC three
 * different kinds of string, and a nonce could be replayed as a header or as
 * a ciphertext - so an attacker could move a value between the three
 * positions and the tag would not change. That is domain separation, and it
 * is the whole reason the leading block exists.
 *
 * ==================== AND THE NONCE MAY BE ANY LENGTH ====================
 *
 * Unlike GCM, which special-cases 96 bits and hashes anything else, EAX runs
 * every nonce through CMAC, so all lengths are equally supported and none is
 * a special path that might be wrong. Wycheproof's vectors run from zero
 * bits to 2056 for that reason.
 */

import { cmac } from './cmac.js';
import { ctr } from './block_modes.js';
import { wipe, equal } from './ct.js';

var BLOCK = 16;

/** CMAC over `t || data`, where t is a full block holding a small integer. */
function omac(encrypt, t, data) {
    var buf = new Uint8Array(BLOCK + data.length);
    buf[BLOCK - 1] = t;
    buf.set(data, BLOCK);
    var out = cmac(encrypt, buf);
    wipe(buf);
    return out;
}

/**
 * @param {function} encrypt  (src, src_off, out, out_off), 16 bytes
 * @param {Uint8Array} nonce  any length, including empty
 * @return {Uint8Array} ciphertext followed by the 16-byte tag
 */
export function eax_encrypt(encrypt, nonce, plaintext, aad, tag_len) {
    var tl = (tag_len === undefined) ? 16 : tag_len;
    if (tl < 1 || tl > 16) { throw new Error('eax: tag length must be 1 to 16'); }

    var N = omac(encrypt, 0, nonce);
    var H = omac(encrypt, 1, aad || new Uint8Array(0));

    /* CTR starting from N, which is why the nonce needs no fixed length */
    var ct = ctr(encrypt, N, plaintext, BLOCK);
    var C = omac(encrypt, 2, ct);

    var out = new Uint8Array(ct.length + tl);
    out.set(ct, 0);
    for (var i = 0; i < tl; i++) {
        out[ct.length + i] = N[i] ^ H[i] ^ C[i];
    }
    wipe(N); wipe(H); wipe(C);
    return out;
}

/** @return {Uint8Array|null} null when authentication fails */
export function eax_decrypt(encrypt, nonce, sealed, aad, tag_len) {
    var tl = (tag_len === undefined) ? 16 : tag_len;
    if (tl < 1 || tl > 16) { return null; }
    if (sealed.length < tl) { return null; }

    var ct = sealed.subarray(0, sealed.length - tl);
    var got = sealed.subarray(sealed.length - tl);

    var N = omac(encrypt, 0, nonce);
    var H = omac(encrypt, 1, aad || new Uint8Array(0));
    var C = omac(encrypt, 2, ct);

    var want = new Uint8Array(tl);
    for (var i = 0; i < tl; i++) { want[i] = N[i] ^ H[i] ^ C[i]; }

    /*
     * Constant time, and the plaintext is not produced until the tag has
     * been accepted - returning it alongside a validity flag is how a caller
     * ends up using unauthenticated data.
     */
    if (equal(want, got) !== 1) {
        wipe(N); wipe(H); wipe(C); wipe(want);
        return null;
    }

    var pt = ctr(encrypt, N, ct, BLOCK);
    wipe(N); wipe(H); wipe(C); wipe(want);
    return pt;
}
