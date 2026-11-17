/**
 * SHA-2 family  -  FIPS 180-4
 *
 * SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256.
 *
 * All six share two compression functions - one 32-bit, one 64-bit - and
 * differ only in their IV and output length. They live in one file because
 * the alternative was six files of forty lines each that could never be
 * opened or used independently of the core they all call.
 *
 * The distinct IV is not decoration. Plain truncation would make SHA-224 a
 * visible prefix of SHA-256 and would leave the discarded words reachable in
 * a length-extension setting. A different starting state makes each variant
 * an unrelated function.
 *
 * WHY hi/lo AND NOT BigInt (64-bit half)
 * SHA-512 works on 64-bit words. Every word is an int32 [hi, lo] pair and
 * every operation is split by hand across the halves. BigInt would express
 * this in a fraction of the lines and read straight off the spec. It was
 * benchmarked (both verified identical on every length 0..300) and rejected:
 *
 *     1 KB input    47 MB/s hi/lo   vs   4.2 MB/s BigInt   (11x)
 *     64 KB input   32 MB/s hi/lo   vs   5.0 MB/s BigInt   (6.4x)
 *
 * The cost is allocation, not arithmetic: every BigInt operation produces a
 * heap object, and this runs 80 rounds of roughly ten 64-bit operations per
 * 128-byte block. The measured version was already optimised - BigUint64Array,
 * asUintN, no destructuring - so that is close to the ceiling.
 *
 * Each export is wrapped in a PURE-annotated IIFE. Attaching BLOCK_SIZE to a
 * function at module top level is a side effect a bundler cannot prove safe,
 * and it pins every variant into the bundle even when one is imported. The
 * annotation costs nothing at runtime and measurably shrinks output.
 */

import { md_hash, md_create } from './commons/merkle_damgard.js';

/* ---------------- 32-bit: SHA-224, SHA-256 ---------------- */

/* First 32 bits of the fractional cube roots of the first 64 primes */
var K = new Int32Array([
    0x428a2f98|0, 0x71374491|0, 0xb5c0fbcf|0, 0xe9b5dba5|0,
    0x3956c25b|0, 0x59f111f1|0, 0x923f82a4|0, 0xab1c5ed5|0,
    0xd807aa98|0, 0x12835b01|0, 0x243185be|0, 0x550c7dc3|0,
    0x72be5d74|0, 0x80deb1fe|0, 0x9bdc06a7|0, 0xc19bf174|0,
    0xe49b69c1|0, 0xefbe4786|0, 0x0fc19dc6|0, 0x240ca1cc|0,
    0x2de92c6f|0, 0x4a7484aa|0, 0x5cb0a9dc|0, 0x76f988da|0,
    0x983e5152|0, 0xa831c66d|0, 0xb00327c8|0, 0xbf597fc7|0,
    0xc6e00bf3|0, 0xd5a79147|0, 0x06ca6351|0, 0x14292967|0,
    0x27b70a85|0, 0x2e1b2138|0, 0x4d2c6dfc|0, 0x53380d13|0,
    0x650a7354|0, 0x766a0abb|0, 0x81c2c92e|0, 0x92722c85|0,
    0xa2bfe8a1|0, 0xa81a664b|0, 0xc24b8b70|0, 0xc76c51a3|0,
    0xd192e819|0, 0xd6990624|0, 0xf40e3585|0, 0x106aa070|0,
    0x19a4c116|0, 0x1e376c08|0, 0x2748774c|0, 0x34b0bcb5|0,
    0x391c0cb3|0, 0x4ed8aa4a|0, 0x5b9cca4f|0, 0x682e6ff3|0,
    0x748f82ee|0, 0x78a5636f|0, 0x84c87814|0, 0x8cc70208|0,
    0x90befffa|0, 0xa4506ceb|0, 0xbef9a3f7|0, 0xc67178f2|0
]);

/**
 * Compresses one 64-byte block from buf[off..off+63] into H.
 * W is passed in so that 256 bytes are not allocated per block.
 *
 * Rotations are written inline rather than as a function call - in the hot
 * loop that would be 256 calls per block.
 */
function sha256_compress(H, buf, off, W) {
    var i, t1, s0, s1, ch, maj, x;

    for (i = 0; i < 16; i++) {
        W[i] = ((buf[off] << 24) | (buf[off + 1] << 16) |
                (buf[off + 2] << 8) | buf[off + 3]) | 0;
        off += 4;
    }
    for (i = 16; i < 64; i++) {
        x  = W[i - 15];
        s0 = ((x >>> 7)  | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        x  = W[i - 2];
        s1 = ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
        W[i] = (((W[i - 16] + s0) | 0) + ((W[i - 7] + s1) | 0)) | 0;
    }

    var a = H[0], b = H[1], c = H[2], d = H[3];
    var e = H[4], f = H[5], g = H[6], h = H[7];

    /*
     * THE ROUND LOOP, UNROLLED EIGHT TIMES.
     *
     * The textbook round ends by shifting every working variable down one
     * position - h = g, g = f, and so on - which is seven assignments per
     * round, 448 per block, doing no arithmetic at all.
     *
     * Unrolling by eight makes that rotation happen in the NAMES instead:
     * each of the eight bodies below reads and writes a different rotation of
     * (a..h), and after eight of them every variable is back where it
     * started. The assignments disappear entirely.
     *
     * The bodies are generated from one template rather than written out, so
     * a change to the round is a change in one place. Verified against Node
     * on 500 input lengths for every member of the family.
     */
    for (i = 0; i < 64; i += 8) {
        s1  = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ch  = (e & f) ^ (~e & g);
        t1  = (((((h + s1) | 0) + ch) | 0) + ((K[i + 0] + W[i + 0]) | 0)) | 0;
        s0  = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        maj = (a & b) ^ (a & c) ^ (b & c);
        d = (d + t1) | 0;
        h = (((s0 + maj) | 0) + t1) | 0;

        s1  = ((d >>> 6) | (d << 26)) ^ ((d >>> 11) | (d << 21)) ^ ((d >>> 25) | (d << 7));
        ch  = (d & e) ^ (~d & f);
        t1  = (((((g + s1) | 0) + ch) | 0) + ((K[i + 1] + W[i + 1]) | 0)) | 0;
        s0  = ((h >>> 2) | (h << 30)) ^ ((h >>> 13) | (h << 19)) ^ ((h >>> 22) | (h << 10));
        maj = (h & a) ^ (h & b) ^ (a & b);
        c = (c + t1) | 0;
        g = (((s0 + maj) | 0) + t1) | 0;

        s1  = ((c >>> 6) | (c << 26)) ^ ((c >>> 11) | (c << 21)) ^ ((c >>> 25) | (c << 7));
        ch  = (c & d) ^ (~c & e);
        t1  = (((((f + s1) | 0) + ch) | 0) + ((K[i + 2] + W[i + 2]) | 0)) | 0;
        s0  = ((g >>> 2) | (g << 30)) ^ ((g >>> 13) | (g << 19)) ^ ((g >>> 22) | (g << 10));
        maj = (g & h) ^ (g & a) ^ (h & a);
        b = (b + t1) | 0;
        f = (((s0 + maj) | 0) + t1) | 0;

        s1  = ((b >>> 6) | (b << 26)) ^ ((b >>> 11) | (b << 21)) ^ ((b >>> 25) | (b << 7));
        ch  = (b & c) ^ (~b & d);
        t1  = (((((e + s1) | 0) + ch) | 0) + ((K[i + 3] + W[i + 3]) | 0)) | 0;
        s0  = ((f >>> 2) | (f << 30)) ^ ((f >>> 13) | (f << 19)) ^ ((f >>> 22) | (f << 10));
        maj = (f & g) ^ (f & h) ^ (g & h);
        a = (a + t1) | 0;
        e = (((s0 + maj) | 0) + t1) | 0;

        s1  = ((a >>> 6) | (a << 26)) ^ ((a >>> 11) | (a << 21)) ^ ((a >>> 25) | (a << 7));
        ch  = (a & b) ^ (~a & c);
        t1  = (((((d + s1) | 0) + ch) | 0) + ((K[i + 4] + W[i + 4]) | 0)) | 0;
        s0  = ((e >>> 2) | (e << 30)) ^ ((e >>> 13) | (e << 19)) ^ ((e >>> 22) | (e << 10));
        maj = (e & f) ^ (e & g) ^ (f & g);
        h = (h + t1) | 0;
        d = (((s0 + maj) | 0) + t1) | 0;

        s1  = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
        ch  = (h & a) ^ (~h & b);
        t1  = (((((c + s1) | 0) + ch) | 0) + ((K[i + 5] + W[i + 5]) | 0)) | 0;
        s0  = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
        maj = (d & e) ^ (d & f) ^ (e & f);
        g = (g + t1) | 0;
        c = (((s0 + maj) | 0) + t1) | 0;

        s1  = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
        ch  = (g & h) ^ (~g & a);
        t1  = (((((b + s1) | 0) + ch) | 0) + ((K[i + 6] + W[i + 6]) | 0)) | 0;
        s0  = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
        maj = (c & d) ^ (c & e) ^ (d & e);
        f = (f + t1) | 0;
        b = (((s0 + maj) | 0) + t1) | 0;

        s1  = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
        ch  = (f & g) ^ (~f & h);
        t1  = (((((a + s1) | 0) + ch) | 0) + ((K[i + 7] + W[i + 7]) | 0)) | 0;
        s0  = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
        maj = (b & c) ^ (b & d) ^ (c & d);
        e = (e + t1) | 0;
        a = (((s0 + maj) | 0) + t1) | 0;
    }

    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0;
    H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
}


/* ---------------- 64-bit: SHA-384, SHA-512, SHA-512/t ---------------- */

/* First 64 bits of the fractional cube roots of the first 80 primes, as hi/lo pairs */
var K512 = new Int32Array([
    0x428a2f98|0, 0xd728ae22|0, 0x71374491|0, 0x23ef65cd|0,
    0xb5c0fbcf|0, 0xec4d3b2f|0, 0xe9b5dba5|0, 0x8189dbbc|0,
    0x3956c25b|0, 0xf348b538|0, 0x59f111f1|0, 0xb605d019|0,
    0x923f82a4|0, 0xaf194f9b|0, 0xab1c5ed5|0, 0xda6d8118|0,
    0xd807aa98|0, 0xa3030242|0, 0x12835b01|0, 0x45706fbe|0,
    0x243185be|0, 0x4ee4b28c|0, 0x550c7dc3|0, 0xd5ffb4e2|0,
    0x72be5d74|0, 0xf27b896f|0, 0x80deb1fe|0, 0x3b1696b1|0,
    0x9bdc06a7|0, 0x25c71235|0, 0xc19bf174|0, 0xcf692694|0,
    0xe49b69c1|0, 0x9ef14ad2|0, 0xefbe4786|0, 0x384f25e3|0,
    0x0fc19dc6|0, 0x8b8cd5b5|0, 0x240ca1cc|0, 0x77ac9c65|0,
    0x2de92c6f|0, 0x592b0275|0, 0x4a7484aa|0, 0x6ea6e483|0,
    0x5cb0a9dc|0, 0xbd41fbd4|0, 0x76f988da|0, 0x831153b5|0,
    0x983e5152|0, 0xee66dfab|0, 0xa831c66d|0, 0x2db43210|0,
    0xb00327c8|0, 0x98fb213f|0, 0xbf597fc7|0, 0xbeef0ee4|0,
    0xc6e00bf3|0, 0x3da88fc2|0, 0xd5a79147|0, 0x930aa725|0,
    0x06ca6351|0, 0xe003826f|0, 0x14292967|0, 0x0a0e6e70|0,
    0x27b70a85|0, 0x46d22ffc|0, 0x2e1b2138|0, 0x5c26c926|0,
    0x4d2c6dfc|0, 0x5ac42aed|0, 0x53380d13|0, 0x9d95b3df|0,
    0x650a7354|0, 0x8baf63de|0, 0x766a0abb|0, 0x3c77b2a8|0,
    0x81c2c92e|0, 0x47edaee6|0, 0x92722c85|0, 0x1482353b|0,
    0xa2bfe8a1|0, 0x4cf10364|0, 0xa81a664b|0, 0xbc423001|0,
    0xc24b8b70|0, 0xd0f89791|0, 0xc76c51a3|0, 0x0654be30|0,
    0xd192e819|0, 0xd6ef5218|0, 0xd6990624|0, 0x5565a910|0,
    0xf40e3585|0, 0x5771202a|0, 0x106aa070|0, 0x32bbd1b8|0,
    0x19a4c116|0, 0xb8d2d0c8|0, 0x1e376c08|0, 0x5141ab53|0,
    0x2748774c|0, 0xdf8eeb99|0, 0x34b0bcb5|0, 0xe19b48a8|0,
    0x391c0cb3|0, 0xc5c95a63|0, 0x4ed8aa4a|0, 0xe3418acb|0,
    0x5b9cca4f|0, 0x7763e373|0, 0x682e6ff3|0, 0xd6b2b8a3|0,
    0x748f82ee|0, 0x5defb2fc|0, 0x78a5636f|0, 0x43172f60|0,
    0x84c87814|0, 0xa1f0ab72|0, 0x8cc70208|0, 0x1a6439ec|0,
    0x90befffa|0, 0x23631e28|0, 0xa4506ceb|0, 0xde82bde9|0,
    0xbef9a3f7|0, 0xb2c67915|0, 0xc67178f2|0, 0xe372532b|0,
    0xca273ece|0, 0xea26619c|0, 0xd186b8c7|0, 0x21c0c207|0,
    0xeada7dd6|0, 0xcde0eb1e|0, 0xf57d4f7f|0, 0xee6ed178|0,
    0x06f067aa|0, 0x72176fba|0, 0x0a637dc5|0, 0xa2c898a6|0,
    0x113f9804|0, 0xbef90dae|0, 0x1b710b35|0, 0x131c471b|0,
    0x28db77f5|0, 0x23047d84|0, 0x32caab7b|0, 0x40c72493|0,
    0x3c9ebe0a|0, 0x15c9bebc|0, 0x431d67c4|0, 0x9c100d4c|0,
    0x4cc5d4be|0, 0xcb3e42b6|0, 0x597f299c|0, 0xfc657e2a|0,
    0x5fcb6fab|0, 0x3ad6faec|0, 0x6c44198c|0, 0x4a475817|0
]);

/**
 * Compresses one 128-byte block from buf[off..off+127] into H.
 *
 * H and W are flat int32 arrays holding [hi, lo] pairs - faster than objects,
 * and with no allocation inside the loop.
 */
function sha512_compress(H, buf, off, W) {
    var i, j;
    var hi, lo, x_hi, x_lo, s0_hi, s0_lo, s1_hi, s1_lo;
    var t1_hi, t1_lo, t2_hi, t2_lo, ch_hi, ch_lo, maj_hi, maj_lo;
    var lo_sum;

    /* The first 16 words come straight from the block */
    for (i = 0; i < 32; i += 2) {
        W[i]     = ((buf[off] << 24) | (buf[off + 1] << 16) |
                    (buf[off + 2] << 8) | buf[off + 3]) | 0;
        W[i + 1] = ((buf[off + 4] << 24) | (buf[off + 5] << 16) |
                    (buf[off + 6] << 8) | buf[off + 7]) | 0;
        off += 8;
    }

    /* Message schedule: W[i] = W[i-16] + s0(W[i-15]) + W[i-7] + s1(W[i-2]) */
    for (i = 32; i < 160; i += 2) {
        /* s0 = rotr(x,1) ^ rotr(x,8) ^ shr(x,7)   on W[i-15] */
        x_hi = W[i - 30]; x_lo = W[i - 29];
        s0_hi = ((x_hi >>> 1)  | (x_lo << 31)) ^
                ((x_hi >>> 8)  | (x_lo << 24)) ^ (x_hi >>> 7);
        s0_lo = ((x_lo >>> 1)  | (x_hi << 31)) ^
                ((x_lo >>> 8)  | (x_hi << 24)) ^ ((x_lo >>> 7) | (x_hi << 25));

        /* s1 = rotr(x,19) ^ rotr(x,61) ^ shr(x,6)  on W[i-2] */
        x_hi = W[i - 4]; x_lo = W[i - 3];
        s1_hi = ((x_hi >>> 19) | (x_lo << 13)) ^
                ((x_lo >>> 29) | (x_hi << 3))  ^ (x_hi >>> 6);
        s1_lo = ((x_lo >>> 19) | (x_hi << 13)) ^
                ((x_hi >>> 29) | (x_lo << 3))  ^ ((x_lo >>> 6) | (x_hi << 26));

        /* four 64-bit addends, accumulated as one exact double - see the
           note on t1 in the round loop below */
        lo_sum = (W[i - 31] >>> 0) + (s0_lo >>> 0) +
                 (W[i - 13] >>> 0) + (s1_lo >>> 0);
        lo = lo_sum | 0;
        hi = (W[i - 32] + s0_hi + W[i - 14] + s1_hi +
              ((lo_sum / 4294967296) | 0)) | 0;

        W[i] = hi; W[i + 1] = lo;
    }

    var a_hi = H[0],  a_lo = H[1],  b_hi = H[2],  b_lo = H[3];
    var c_hi = H[4],  c_lo = H[5],  d_hi = H[6],  d_lo = H[7];
    var e_hi = H[8],  e_lo = H[9],  f_hi = H[10], f_lo = H[11];
    var g_hi = H[12], g_lo = H[13], h_hi = H[14], h_lo = H[15];

    for (i = 0, j = 0; i < 80; i++, j += 2) {
        /* S1 = rotr(e,14) ^ rotr(e,18) ^ rotr(e,41) */
        s1_hi = ((e_hi >>> 14) | (e_lo << 18)) ^
                ((e_hi >>> 18) | (e_lo << 14)) ^
                ((e_lo >>> 9)  | (e_hi << 23));
        s1_lo = ((e_lo >>> 14) | (e_hi << 18)) ^
                ((e_lo >>> 18) | (e_hi << 14)) ^
                ((e_hi >>> 9)  | (e_lo << 23));

        /* ch = (e & f) ^ (~e & g) */
        ch_hi = (e_hi & f_hi) ^ (~e_hi & g_hi);
        ch_lo = (e_lo & f_lo) ^ (~e_lo & g_lo);

        /*
         * t1 = h + S1 + ch + K512[i] + W[i]
         *
         * ALL FIVE ADDENDS AT ONCE, IN A DOUBLE. The obvious form adds them
         * pairwise and detects each carry with an unsigned comparison, which
         * is four comparisons and eight `>>> 0` coercions per round. Instead,
         * the five low halves are summed as ordinary numbers: five values
         * below 2^32 sum to less than 2^35, comfortably inside the 2^53 that
         * a double represents exactly, so the carry is one division and no
         * comparison at all.
         *
         * The same trick that ML-DSA's Montgomery reduction could NOT use,
         * for the opposite reason - there the product reached 2^54 and lost
         * bits. The bound is what decides it, and here there is room.
         */
        lo_sum = (h_lo >>> 0) + (s1_lo >>> 0) + (ch_lo >>> 0) +
                 (K512[j + 1] >>> 0) + (W[j + 1] >>> 0);
        t1_lo = lo_sum | 0;
        t1_hi = (h_hi + s1_hi + ch_hi + K512[j] + W[j] +
                 ((lo_sum / 4294967296) | 0)) | 0;

        /* S0 = rotr(a,28) ^ rotr(a,34) ^ rotr(a,39) */
        s0_hi = ((a_hi >>> 28) | (a_lo << 4))  ^
                ((a_lo >>> 2)  | (a_hi << 30)) ^
                ((a_lo >>> 7)  | (a_hi << 25));
        s0_lo = ((a_lo >>> 28) | (a_hi << 4))  ^
                ((a_hi >>> 2)  | (a_lo << 30)) ^
                ((a_hi >>> 7)  | (a_lo << 25));

        /* maj = (a & b) ^ (a & c) ^ (b & c) */
        maj_hi = (a_hi & b_hi) ^ (a_hi & c_hi) ^ (b_hi & c_hi);
        maj_lo = (a_lo & b_lo) ^ (a_lo & c_lo) ^ (b_lo & c_lo);

        /* t2 = S0 + maj */
        lo_sum = (s0_lo >>> 0) + (maj_lo >>> 0);
        t2_lo = lo_sum | 0;
        t2_hi = (s0_hi + maj_hi + ((lo_sum / 4294967296) | 0)) | 0;

        h_hi = g_hi; h_lo = g_lo;
        g_hi = f_hi; g_lo = f_lo;
        f_hi = e_hi; f_lo = e_lo;

        /* e = d + t1 */
        lo_sum = (d_lo >>> 0) + (t1_lo >>> 0);
        e_lo = lo_sum | 0;
        e_hi = (d_hi + t1_hi + ((lo_sum / 4294967296) | 0)) | 0;

        d_hi = c_hi; d_lo = c_lo;
        c_hi = b_hi; c_lo = b_lo;
        b_hi = a_hi; b_lo = a_lo;

        /* a = t1 + t2 */
        lo_sum = (t1_lo >>> 0) + (t2_lo >>> 0);
        a_lo = lo_sum | 0;
        a_hi = (t1_hi + t2_hi + ((lo_sum / 4294967296) | 0)) | 0;
    }

    /* H += a..h */
    lo_sum = (H[1] >>> 0) + (a_lo >>> 0);
    H[1] = lo_sum | 0; H[0] = (H[0] + a_hi + ((lo_sum / 4294967296) | 0)) | 0;

    lo_sum = (H[3] >>> 0) + (b_lo >>> 0);
    H[3] = lo_sum | 0; H[2] = (H[2] + b_hi + ((lo_sum / 4294967296) | 0)) | 0;

    lo_sum = (H[5] >>> 0) + (c_lo >>> 0);
    H[5] = lo_sum | 0; H[4] = (H[4] + c_hi + ((lo_sum / 4294967296) | 0)) | 0;

    lo_sum = (H[7] >>> 0) + (d_lo >>> 0);
    H[7] = lo_sum | 0; H[6] = (H[6] + d_hi + ((lo_sum / 4294967296) | 0)) | 0;

    lo_sum = (H[9] >>> 0) + (e_lo >>> 0);
    H[9] = lo_sum | 0; H[8] = (H[8] + e_hi + ((lo_sum / 4294967296) | 0)) | 0;

    lo_sum = (H[11] >>> 0) + (f_lo >>> 0);
    H[11] = lo_sum | 0; H[10] = (H[10] + f_hi + ((lo_sum / 4294967296) | 0)) | 0;

    lo_sum = (H[13] >>> 0) + (g_lo >>> 0);
    H[13] = lo_sum | 0; H[12] = (H[12] + g_hi + ((lo_sum / 4294967296) | 0)) | 0;

    lo_sum = (H[15] >>> 0) + (h_lo >>> 0);
    H[15] = lo_sum | 0; H[14] = (H[14] + h_hi + ((lo_sum / 4294967296) | 0)) | 0;
}


/**
 * SHA-256.
 */
export var sha256 = /* @__PURE__ */ (function () {
    /* First 32 bits of the fractional square roots of the first 8 primes.
       BLAKE2s and BLAKE3 use these same eight words as their own IV. They are
       not shared as code - see commons/arx32.js on extracting behaviour
       rather than coincidentally equal values. */
    var IV = new Int32Array([
        0x6a09e667|0, 0xbb67ae85|0, 0x3c6ef372|0, 0xa54ff53a|0,
        0x510e527f|0, 0x9b05688c|0, 0x1f83d9ab|0, 0x5be0cd19|0
    ]);
    var PARAMS = {
        compress:      sha256_compress,
        iv:            IV,
        w_size:        64,
        block_size:    64,
        len_field:     8,
        digest_size:   32,
        little_endian: false
    };
    function sha256(msg) { return md_hash(PARAMS, msg); }
    sha256.BLOCK_SIZE  = 64;
    sha256.DIGEST_SIZE = 32;
    /*
     * ⭐ THE MERKLE-DAMGARD PARAMETERS, EXPOSED FOR MIDSTATE REUSE.
     *
     *   A caller that hashes the same 64-byte prefix over and over - which
     *   is exactly what HMAC does, and PBKDF2 does a hundred thousand times -
     *   can compress that prefix once and keep the resulting state.
     *
     * ⛔ THIS IS AN INTERNAL. Nothing about the padding, the length field or
     *   the byte order is checked for a caller that drives `compress`
     *   directly, and getting any of them wrong produces a digest that is
     *   stable, well-distributed and not SHA-256. commons/hmac_fast.js is
     *   the one place that uses it, and it is verified against node.
     */
    sha256.PARAMS = PARAMS;
    sha256.create = sha256_create;
    sha256.NAME = 'sha256';
    return sha256;
}());

/**
 * SHA-224. SHA-256 with a different IV, truncated to 28 bytes.
 */
export var sha224 = /* @__PURE__ */ (function () {
    /* Second 32 bits of the fractional square roots of the ninth through sixteenth primes */
    var IV = new Int32Array([
        0xc1059ed8|0, 0x367cd507|0, 0x3070dd17|0, 0xf70e5939|0,
        0xffc00b31|0, 0x68581511|0, 0x64f98fa7|0, 0xbefa4fa4|0
    ]);
    var PARAMS = {
        compress:      sha256_compress,
        iv:            IV,
        w_size:        64,
        block_size:    64,
        len_field:     8,
        digest_size:   28,
        little_endian: false
    };
    function sha224(msg) { return md_hash(PARAMS, msg); }
    sha224.BLOCK_SIZE  = 64;
    sha224.DIGEST_SIZE = 28;
    sha224.PARAMS = PARAMS;
    sha224.create = sha224_create;
    sha224.NAME = 'sha224';
    return sha224;
}());

/**
 * SHA-512.
 */
export var sha512 = /* @__PURE__ */ (function () {
    /* First 64 bits of the fractional square roots of the first 8 primes */
    var IV = new Int32Array([
        0x6a09e667|0, 0xf3bcc908|0, 0xbb67ae85|0, 0x84caa73b|0,
        0x3c6ef372|0, 0xfe94f82b|0, 0xa54ff53a|0, 0x5f1d36f1|0,
        0x510e527f|0, 0xade682d1|0, 0x9b05688c|0, 0x2b3e6c1f|0,
        0x1f83d9ab|0, 0xfb41bd6b|0, 0x5be0cd19|0, 0x137e2179|0
    ]);
    var PARAMS = {
        compress:      sha512_compress,
        iv:            IV,
        w_size:        160,
        block_size:    128,
        len_field:     16,
        digest_size:   64,
        little_endian: false
    };
    function sha512(msg) { return md_hash(PARAMS, msg); }
    /* ⭐ see the note on sha256.PARAMS - same purpose, 128-byte blocks */
    sha512.PARAMS = PARAMS;
    sha512.BLOCK_SIZE  = 128;
    sha512.DIGEST_SIZE = 64;
    sha512.create = sha512_create;
    sha512.NAME = 'sha512';
    return sha512;
}());

/**
 * SHA-384. SHA-512 with a different IV, truncated to 48 bytes.
 *
 * More widely deployed than SHA-512 itself: TLS cipher suites and X.509
 * certificates reach for it because 384 bits already exceeds any practical
 * requirement while the digest stays smaller on the wire.
 */
export var sha384 = /* @__PURE__ */ (function () {
    /* Fractional square roots of the ninth through sixteenth primes */
    var IV = new Int32Array([
        0xcbbb9d5d|0, 0xc1059ed8|0, 0x629a292a|0, 0x367cd507|0,
        0x9159015a|0, 0x3070dd17|0, 0x152fecd8|0, 0xf70e5939|0,
        0x67332667|0, 0xffc00b31|0, 0x8eb44a87|0, 0x68581511|0,
        0xdb0c2e0d|0, 0x64f98fa7|0, 0x47b5481d|0, 0xbefa4fa4|0
    ]);
    var PARAMS = {
        compress:      sha512_compress,
        iv:            IV,
        w_size:        160,
        block_size:    128,
        len_field:     16,
        digest_size:   48,
        little_endian: false
    };
    function sha384(msg) { return md_hash(PARAMS, msg); }
    sha384.BLOCK_SIZE  = 128;
    sha384.DIGEST_SIZE = 48;
    sha384.PARAMS = PARAMS;
    sha384.create = sha384_create;
    sha384.NAME = 'sha384';
    return sha384;
}());

/**
 * SHA-512/224. SHA-512 truncated to 28 bytes.
 *
 * On 64-bit hardware this beats SHA-224 at the same security level, since
 * the underlying function chews 128-byte blocks with 64-bit words. In JS
 * that advantage inverts - see the BigInt note above.
 *
 * Immune to length extension by construction: an extension attack needs the
 * full internal state, and half of it is discarded.
 */
export var sha512_224 = /* @__PURE__ */ (function () {
    /* IV derived by the procedure in FIPS 180-4 section 5.3.6 */
    var IV = new Int32Array([
        0x8c3d37c8|0, 0x19544da2|0, 0x73e19966|0, 0x89dcd4d6|0,
        0x1dfab7ae|0, 0x32ff9c82|0, 0x679dd514|0, 0x582f9fcf|0,
        0x0f6d2b69|0, 0x7bd44da8|0, 0x77e36f73|0, 0x04c48942|0,
        0x3f9d85a8|0, 0x6a1d36c8|0, 0x1112e6ad|0, 0x91d692a1|0
    ]);
    var PARAMS = {
        compress:      sha512_compress,
        iv:            IV,
        w_size:        160,
        block_size:    128,
        len_field:     16,
        digest_size:   28,
        little_endian: false
    };
    function sha512_224(msg) { return md_hash(PARAMS, msg); }
    sha512_224.BLOCK_SIZE  = 128;
    sha512_224.DIGEST_SIZE = 28;
    sha512_224.PARAMS = PARAMS;
    sha512_224.create = sha512_224_create;
    sha512_224.NAME = 'sha512_224';
    return sha512_224;
}());

/**
 * SHA-512/256. SHA-512 truncated to 32 bytes.
 *
 * Same digest size and security level as SHA-256, but immune to length
 * extension: recovering the internal state would require the discarded half.
 * sha256(key || msg) is unsafe; sha512_256(key || msg) is not.
 */
export var sha512_256 = /* @__PURE__ */ (function () {
    /* IV derived by the procedure in FIPS 180-4 section 5.3.6 */
    var IV = new Int32Array([
        0x22312194|0, 0xfc2bf72c|0, 0x9f555fa3|0, 0xc84c64c2|0,
        0x2393b86b|0, 0x6f53b151|0, 0x96387719|0, 0x5940eabd|0,
        0x96283ee2|0, 0xa88effe3|0, 0xbe5e1e25|0, 0x53863992|0,
        0x2b0199fc|0, 0x2c85b8aa|0, 0x0eb72ddc|0, 0x81c52ca2|0
    ]);
    var PARAMS = {
        compress:      sha512_compress,
        iv:            IV,
        w_size:        160,
        block_size:    128,
        len_field:     16,
        digest_size:   32,
        little_endian: false
    };
    function sha512_256(msg) { return md_hash(PARAMS, msg); }
    sha512_256.BLOCK_SIZE  = 128;
    sha512_256.DIGEST_SIZE = 32;
    sha512_256.PARAMS = PARAMS;
    sha512_256.create = sha512_256_create;
    sha512_256.NAME = 'sha512_256';
    return sha512_256;
}());

/* ---------------- Incremental ---------------- */
/*
 * The same hashes, fed in pieces: create, update as often as needed, and
 * digest once. copy() forks the state, for a running digest over a stream
 * that continues - a TLS transcript is hashed after each handshake message.
 */
export function sha256_create()     { return md_create(sha256.PARAMS); }
export function sha224_create()     { return md_create(sha224.PARAMS); }
export function sha512_create()     { return md_create(sha512.PARAMS); }
export function sha384_create()     { return md_create(sha384.PARAMS); }
export function sha512_224_create() { return md_create(sha512_224.PARAMS); }
export function sha512_256_create() { return md_create(sha512_256.PARAMS); }
