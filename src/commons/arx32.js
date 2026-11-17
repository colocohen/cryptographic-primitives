/**
 * The 32-bit ARX quarter-round
 *
 * Extracted once BLAKE3 was written and its round turned out to be BLAKE2s's
 * round verbatim - same four ARX steps, same rotations, same column and
 * diagonal layout. That is not a coincidence of shape: BLAKE3 reuses the
 * BLAKE2s quarter-round by design, and both descend from ChaCha20.
 *
 * What differs between the two callers stays with them:
 *   BLAKE2s   picks message words through the SIGMA table, 10 rounds
 *   BLAKE3    takes them in order and permutes between rounds, 7 rounds
 *
 * ON THE CALL OVERHEAD
 * Both files previously inlined this, with a comment claiming a function call
 * per quarter-round would cost 80 calls per block. That was a guess. Measured
 * on 64 KB through BLAKE2s:
 *
 *     inline                    62.2 MB/s
 *     extracted, same module    65.5 MB/s
 *     extracted, this file      64.6 MB/s
 *
 * V8 inlines it across module boundaries, so the call is free. An earlier
 * measurement showed a 15% penalty; that was JIT warm-up ordering, and it
 * disappeared once the variants were run interleaved.
 *
 * A second attempt precomputed the (a, b, c, d) index quartets into a table,
 * on the reasoning that a lookup beats an if inside the round loop. It was
 * 18% SLOWER (52 MB/s against 63). The branch is perfectly predictable and
 * costs nothing; four array loads per quarter-round are real memory traffic.
 * The callers compute the indices inline for that reason.
 *
 * Two wrong guesses about inlining in a row, both caught only by measuring.
 */

/**
 * One quarter-round, in place on v.
 *
 *     a += b + x;  d = rotr(d ^ a, 16);  c += d;  b = rotr(b ^ c, 12)
 *     a += b + y;  d = rotr(d ^ a,  8);  c += d;  b = rotr(b ^ c,  7)
 *
 * @param {Int32Array} v  16-word working state
 * @param {number} a,b,c,d  indices into v
 * @param {number} x,y    the two message words for this step
 */
export function arx_g32(v, a, b, c, d, x, y) {
    var t;

    v[a] = (((v[a] + v[b]) | 0) + x) | 0;
    t = v[d] ^ v[a]; v[d] = ((t >>> 16) | (t << 16)) | 0;
    v[c] = (v[c] + v[d]) | 0;
    t = v[b] ^ v[c]; v[b] = ((t >>> 12) | (t << 20)) | 0;

    v[a] = (((v[a] + v[b]) | 0) + y) | 0;
    t = v[d] ^ v[a]; v[d] = ((t >>> 8)  | (t << 24)) | 0;
    v[c] = (v[c] + v[d]) | 0;
    t = v[b] ^ v[c]; v[b] = ((t >>> 7)  | (t << 25)) | 0;
}

/** One full round: four columns then four diagonals, message words picked
    through sigma[s .. s+16). */
export function arx_round32(v, m, sigma, s) {
    var a, b, c, d;
    for (var i = 0; i < 8; i++) {
        if (i < 4) { a = i;     b = 4 + i;             c = 8 + i;             d = 12 + i; }
        else       { a = i - 4; b = 4 + ((i - 3) & 3); c = 8 + ((i - 2) & 3); d = 12 + ((i - 1) & 3); }
        arx_g32(v, a, b, c, d, m[sigma[s + i * 2]], m[sigma[s + i * 2 + 1]]);
    }
}
