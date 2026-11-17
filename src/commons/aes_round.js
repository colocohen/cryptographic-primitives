/**
 * A single AES round, as a primitive
 *
 * SubBytes, ShiftRows, MixColumns and AddRoundKey applied once. Ten of these
 * (with a modified last one) make AES-128; on its own it is a 128-bit
 * permutation with excellent diffusion and no key schedule.
 *
 * IT EXISTS AS A SEPARATE FILE BECAUSE MODERN CIPHERS BUILD ON THE ROUND, NOT
 * ON THE CIPHER. AES-NI exposes exactly this - `aesenc` is one round - and a
 * family of designs took that as their building block: AEGIS, MORUS, Tiaoxin,
 * Rocca. They get AES's cryptanalytic pedigree and hardware acceleration
 * without paying for a full ten-round encryption per block.
 *
 * A CAUTION THAT APPLIES TO EVERY CALLER. This is a TABLE-DRIVEN
 * implementation, so it has the same cache-timing exposure as aes.js and for
 * the same reason: the table index depends on the data. On hardware with
 * AES-NI the round is a single constant-time instruction and the concern
 * vanishes; in software it does not. Anything built on this inherits it.
 */

import { AES_SBOX, gmul, POLY_AES } from './gf256.js';
import { rd_be32, wr_be32, rotr32 } from './bytes.js';

/*
 * The T-table: the S-box substitution and the MixColumns multiplication
 * folded into one 32-bit lookup, which is the standard software AES
 * optimisation. Derived at load from AES_SBOX rather than shipped as 1024
 * constants.
 *
 * EXPORTED AS AES_T0 for aes.js, which derived the identical table with the
 * identical loop. aes.js goes on to materialise T1..T3 as rotations for speed;
 * this file deliberately does not, and rotates T0 at each use instead - one
 * 1 KiB table spans sixteen cache lines rather than sixty-four, which is less
 * for a cache-timing observer to resolve in a primitive AEGIS runs eight times
 * per 32 bytes.
 */
export var AES_T0 = /* @__PURE__ */ (function () {
    var t = new Int32Array(256);
    for (var i = 0; i < 256; i++) {
        var s = AES_SBOX[i];
        var s2 = gmul(s, 2, POLY_AES);
        var s3 = gmul(s, 3, POLY_AES);
        /* one column of the MixColumns matrix: [2,1,1,3] */
        t[i] = ((s2 << 24) | (s << 16) | (s << 8) | s3) | 0;
    }
    return t;
}());
var T0 = AES_T0;

/**
 * out = MixColumns(ShiftRows(SubBytes(input))) XOR round_key
 *
 * All three arguments are 16-byte arrays; `out` may alias `input`.
 *
 * The ShiftRows offsets appear as the byte selection below rather than as a
 * separate permutation step - column j of the output reads bytes from
 * columns j, j+1, j+2, j+3, which is exactly what ShiftRows does.
 */
export function aes_round(input, rk, out) {
    var s0 = rd_be32(input, 0), s1 = rd_be32(input, 4);
    var s2 = rd_be32(input, 8), s3 = rd_be32(input, 12);

    var c0 = T0[(s0 >>> 24) & 0xff] ^ rotr32(T0[(s1 >>> 16) & 0xff], 8) ^
             rotr32(T0[(s2 >>> 8) & 0xff], 16) ^ rotr32(T0[s3 & 0xff], 24);
    var c1 = T0[(s1 >>> 24) & 0xff] ^ rotr32(T0[(s2 >>> 16) & 0xff], 8) ^
             rotr32(T0[(s3 >>> 8) & 0xff], 16) ^ rotr32(T0[s0 & 0xff], 24);
    var c2 = T0[(s2 >>> 24) & 0xff] ^ rotr32(T0[(s3 >>> 16) & 0xff], 8) ^
             rotr32(T0[(s0 >>> 8) & 0xff], 16) ^ rotr32(T0[s1 & 0xff], 24);
    var c3 = T0[(s3 >>> 24) & 0xff] ^ rotr32(T0[(s0 >>> 16) & 0xff], 8) ^
             rotr32(T0[(s1 >>> 8) & 0xff], 16) ^ rotr32(T0[s2 & 0xff], 24);

    wr_be32(out, 0,  c0 ^ rd_be32(rk, 0));
    wr_be32(out, 4,  c1 ^ rd_be32(rk, 4));
    wr_be32(out, 8,  c2 ^ rd_be32(rk, 8));
    wr_be32(out, 12, c3 ^ rd_be32(rk, 12));
}
