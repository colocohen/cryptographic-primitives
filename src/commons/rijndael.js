/**
 * Rijndael with a 192- or 256-bit block
 *
 * AES is Rijndael with the block fixed at 128 bits; the original cipher
 * also takes 6 or 8 columns (Nb = 6, 8), with the same round function, a key
 * schedule that runs until it has produced Nb words per round, max(Nk, Nb) + 6
 * rounds, and for Nb = 8 ShiftRows offsets 1, 3, 4 instead of 1, 2, 3.
 * aes.js keeps the 128-bit block; this is for the schemes that need the wide
 * ones - MQOM and FAEST use Rijndael-256 as a 256-bit block cipher and as an
 * even-Mansour permutation.
 *
 * Table-driven, like aes.js and aes_round.js, with the same cache-timing
 * caveat: the table index depends on the data.
 */

import { AES_SBOX } from './gf256.js';
import { AES_T0 } from './aes_round.js';
import { rotr32 } from './bytes.js';

var SBOX = AES_SBOX, T0 = AES_T0;
var T1 = /* @__PURE__ */ T0.map(function (v) { return rotr32(v, 8); });
var T2 = /* @__PURE__ */ T0.map(function (v) { return rotr32(v, 16); });
var T3 = /* @__PURE__ */ T0.map(function (v) { return rotr32(v, 24); });
var RCON = /* @__PURE__ */ (function () {
    var r = new Uint8Array(32), c = 1;
    for (var i = 1; i < 32; i++) { r[i] = c; c = ((c << 1) ^ (c & 0x80 ? 0x11b : 0)) & 0xff; }
    return r;
}());

function sub_word(t) {
    return (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
}

/**
 * The round keys for a 16-, 24- or 32-byte key and a block of nb columns
 * (4, 6 or 8).
 *
 * @return {{w: Int32Array, nr: number, nb: number}}
 */
export function rijndael_key(key, nb) {
    var nk = key.length / 4;
    if ((nk !== 4 && nk !== 6 && nk !== 8) || (nb !== 4 && nb !== 6 && nb !== 8)) {
        throw new Error('rijndael: key of 16, 24 or 32 bytes and a block of 4, 6 or 8 columns');
    }
    var nr = Math.max(nk, nb) + 6, total = nb * (nr + 1), w = new Int32Array(total), i;
    for (i = 0; i < nk; i++) { w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]; }
    for (i = nk; i < total; i++) {
        var t = w[i - 1];
        if (i % nk === 0) { t = sub_word((t << 8) | (t >>> 24)) ^ (RCON[i / nk] << 24); }
        else if (nk > 6 && i % nk === 4) { t = sub_word(t); }
        w[i] = w[i - nk] ^ t;
    }
    return { w: w, nr: nr, nb: nb };
}

var S = new Int32Array(8), U = new Int32Array(8);
var SHIFT = {
    4: [[0, 1, 2, 3], [1, 2, 3, 0], [2, 3, 0, 1], [3, 0, 1, 2]],
    6: [[0, 1, 2, 3, 4, 5], [1, 2, 3, 4, 5, 0], [2, 3, 4, 5, 0, 1], [3, 4, 5, 0, 1, 2]],
    8: [[0, 1, 2, 3, 4, 5, 6, 7], [1, 2, 3, 4, 5, 6, 7, 0], [3, 4, 5, 6, 7, 0, 1, 2], [4, 5, 6, 7, 0, 1, 2, 3]]
};

/** Encrypt the block of 4 * ks.nb bytes at src[off..] into out[out_off..]; out may alias src. */
export function rijndael_encrypt(ks, src, off, out, out_off) {
    var nb = ks.nb, w = ks.w, nr = ks.nr, sh = SHIFT[nb], s1 = sh[1], s2 = sh[2], s3 = sh[3], s = S, u = U, t, c, r, k;
    for (c = 0; c < nb; c++) {
        k = off + 4 * c;
        s[c] = ((src[k] << 24) | (src[k + 1] << 16) | (src[k + 2] << 8) | src[k + 3]) ^ w[c];
    }
    for (r = 1; r < nr; r++) {
        k = r * nb;
        for (c = 0; c < nb; c++) {
            u[c] = T0[s[c] >>> 24] ^ T1[(s[s1[c]] >>> 16) & 0xff] ^ T2[(s[s2[c]] >>> 8) & 0xff] ^ T3[s[s3[c]] & 0xff] ^ w[k + c];
        }
        t = s; s = u; u = t;
    }
    k = nr * nb;
    for (c = 0; c < nb; c++) {
        u[c] = ((SBOX[s[c] >>> 24] << 24) | (SBOX[(s[s1[c]] >>> 16) & 0xff] << 16) |
                (SBOX[(s[s2[c]] >>> 8) & 0xff] << 8) | SBOX[s[s3[c]] & 0xff]) ^ w[k + c];
    }
    for (c = 0; c < nb; c++) {
        k = out_off + 4 * c;
        out[k] = u[c] >>> 24; out[k + 1] = (u[c] >>> 16) & 0xff; out[k + 2] = (u[c] >>> 8) & 0xff; out[k + 3] = u[c] & 0xff;
    }
}
