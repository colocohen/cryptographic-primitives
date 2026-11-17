/**
 * The Salsa20 core
 *
 * Extracted because two callers need it at different round counts:
 *
 *     salsa.js    Salsa20/20 - the stream cipher
 *     scrypt.js   Salsa20/8  - the mixing step inside BlockMix
 *
 * Same double-round, same constants, same everything but how many times it
 * runs. scrypt's reduced count is deliberate: it needs diffusion, not
 * encryption, and its security comes from the memory-hard structure around
 * the core rather than from the core itself.
 *
 * The quarter-round here is NOT the one in commons/arx32.js. Salsa and ChaCha
 * are both Bernstein's and both ARX, but Salsa rotates by 7/9/13/18 and
 * updates its words in a different order. ChaCha's 16/12/8/7 layout came
 * later precisely because it diffuses better at the same cost. The two do not
 * unify without bending both.
 */

/**
 * Salsa20 core: `rounds` rounds over 16 words, then add the input back.
 *
 * The add-back is what makes the core non-invertible - without it the state
 * could be run backwards, and the keystream would leak the key.
 *
 * @param {Int32Array} x       16 input words
 * @param {Int32Array} out     16 output words. May be the same array as x.
 * @param {number}     rounds  20 for the cipher, 8 for scrypt
 */
export function salsa_core(x, out, rounds) {
    var j0=x[0],  j1=x[1],  j2=x[2],  j3=x[3];
    var j4=x[4],  j5=x[5],  j6=x[6],  j7=x[7];
    var j8=x[8],  j9=x[9],  j10=x[10], j11=x[11];
    var j12=x[12], j13=x[13], j14=x[14], j15=x[15];

    var x0=j0, x1=j1, x2=j2, x3=j3, x4=j4, x5=j5, x6=j6, x7=j7;
    var x8=j8, x9=j9, x10=j10, x11=j11, x12=j12, x13=j13, x14=j14, x15=j15;
    var u, i;

    for (i = 0; i < rounds; i += 2) {
        /* column round */
        u = (x0 + x12) | 0;  x4  ^= (u << 7)  | (u >>> 25);
        u = (x4 + x0) | 0;   x8  ^= (u << 9)  | (u >>> 23);
        u = (x8 + x4) | 0;   x12 ^= (u << 13) | (u >>> 19);
        u = (x12 + x8) | 0;  x0  ^= (u << 18) | (u >>> 14);

        u = (x5 + x1) | 0;   x9  ^= (u << 7)  | (u >>> 25);
        u = (x9 + x5) | 0;   x13 ^= (u << 9)  | (u >>> 23);
        u = (x13 + x9) | 0;  x1  ^= (u << 13) | (u >>> 19);
        u = (x1 + x13) | 0;  x5  ^= (u << 18) | (u >>> 14);

        u = (x10 + x6) | 0;  x14 ^= (u << 7)  | (u >>> 25);
        u = (x14 + x10) | 0; x2  ^= (u << 9)  | (u >>> 23);
        u = (x2 + x14) | 0;  x6  ^= (u << 13) | (u >>> 19);
        u = (x6 + x2) | 0;   x10 ^= (u << 18) | (u >>> 14);

        u = (x15 + x11) | 0; x3  ^= (u << 7)  | (u >>> 25);
        u = (x3 + x15) | 0;  x7  ^= (u << 9)  | (u >>> 23);
        u = (x7 + x3) | 0;   x11 ^= (u << 13) | (u >>> 19);
        u = (x11 + x7) | 0;  x15 ^= (u << 18) | (u >>> 14);

        /* row round */
        u = (x0 + x3) | 0;   x1  ^= (u << 7)  | (u >>> 25);
        u = (x1 + x0) | 0;   x2  ^= (u << 9)  | (u >>> 23);
        u = (x2 + x1) | 0;   x3  ^= (u << 13) | (u >>> 19);
        u = (x3 + x2) | 0;   x0  ^= (u << 18) | (u >>> 14);

        u = (x5 + x4) | 0;   x6  ^= (u << 7)  | (u >>> 25);
        u = (x6 + x5) | 0;   x7  ^= (u << 9)  | (u >>> 23);
        u = (x7 + x6) | 0;   x4  ^= (u << 13) | (u >>> 19);
        u = (x4 + x7) | 0;   x5  ^= (u << 18) | (u >>> 14);

        u = (x10 + x9) | 0;  x11 ^= (u << 7)  | (u >>> 25);
        u = (x11 + x10) | 0; x8  ^= (u << 9)  | (u >>> 23);
        u = (x8 + x11) | 0;  x9  ^= (u << 13) | (u >>> 19);
        u = (x9 + x8) | 0;   x10 ^= (u << 18) | (u >>> 14);

        u = (x15 + x14) | 0; x12 ^= (u << 7)  | (u >>> 25);
        u = (x12 + x15) | 0; x13 ^= (u << 9)  | (u >>> 23);
        u = (x13 + x12) | 0; x14 ^= (u << 13) | (u >>> 19);
        u = (x14 + x13) | 0; x15 ^= (u << 18) | (u >>> 14);
    }

    out[0]=(x0+j0)|0;    out[1]=(x1+j1)|0;    out[2]=(x2+j2)|0;    out[3]=(x3+j3)|0;
    out[4]=(x4+j4)|0;    out[5]=(x5+j5)|0;    out[6]=(x6+j6)|0;    out[7]=(x7+j7)|0;
    out[8]=(x8+j8)|0;    out[9]=(x9+j9)|0;    out[10]=(x10+j10)|0; out[11]=(x11+j11)|0;
    out[12]=(x12+j12)|0; out[13]=(x13+j13)|0; out[14]=(x14+j14)|0; out[15]=(x15+j15)|0;
}

/**
 * The same rounds WITHOUT the add-back, returning the eight words HSalsa20
 * keeps. Dropping the add-back is exactly what turns a keystream generator
 * into a one-way key derivation.
 *
 * @param {Int32Array} x    16 input words
 * @param {Int32Array} out  8 output words
 */
export function hsalsa_core(x, out) {
    var t = new Int32Array(16), i;
    for (i = 0; i < 16; i++) { t[i] = x[i]; }

    /* run the rounds, then undo the add-back that salsa_core performs */
    salsa_core(x, t, 20);
    for (i = 0; i < 16; i++) { t[i] = (t[i] - x[i]) | 0; }

    var take = [0, 5, 10, 15, 6, 7, 8, 9];
    for (i = 0; i < 8; i++) { out[i] = t[take[i]]; }
    for (i = 0; i < 16; i++) { t[i] = 0; }
}
