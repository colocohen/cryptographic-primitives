/**
 * Module lattices over R_q = Z_q[X]/(X^256 + 1): what ML-KEM and ML-DSA share
 * above their rings.
 *
 *   uniform(rho, a, b)    a uniform polynomial in the NTT domain from
 *                         SHAKE128(rho ‖ a ‖ b) - FIPS 203 SampleNTT,
 *                         FIPS 204 RejNTTPoly
 *   matrix(rho, k, l, t)  the matrix A: entry (i, j) from rho ‖ j ‖ i, both
 *                         standards alike; transposed (ML-KEM's encryption)
 *                         from rho ‖ i ‖ j
 *   row_dot(row, v)       a row of A times a vector, in the NTT domain
 *
 * THE LINE IS WHERE RUSTCRYPTO'S module-lattice DRAWS IT. The NTT and the
 * product in its domain stay with each ring, because they differ in kind:
 * q = 3329 is 1 mod 256 but not mod 512, so kyber_ring.js's transform stops
 * at seven layers and multiplies degree-one pairs; q = 8380417 is 1 mod 512,
 * so dilithium_ring.js's is complete and pointwise; and the reductions differ
 * (16-bit Montgomery, 32-bit). One code for both would branch inside the
 * hottest loops. What is the same idea with other constants is here.
 *
 * A RING gives: N, Q, poly_new, poly_mul (NTT domain), poly_add;
 * UNIFORM_BITS, the width of one candidate (12: two per 3 bytes; 23: one);
 * UNIFORM_BLOCKS, the SHAKE128 blocks squeezed first (speed only - the
 * stream grows if a rejection run needs more); and dot_finish, what a sum of
 * products needs before use (Kyber: its R^-1 removed, then reduced).
 *
 * ⚠ uniform's running time depends on its output - rejection sampling. That
 *   is safe because A is public, and only because: nothing secret goes here.
 */

import { shake128 } from '../sha3.js';
import { concat } from './bytes.js';
import { xof_stream } from './xof_stream.js';

export function module_lattice(R) {
    var PER = Math.floor(24 / R.UNIFORM_BITS), MASK = (1 << R.UNIFORM_BITS) - 1;

    /*
     * Three bytes, little-endian, are 24 bits: two 12-bit candidates or one
     * 23-bit one (the top bit dropped). A candidate at or above q is
     * DISCARDED, not reduced - reducing would skew A, and the security
     * argument needs it uniform.
     */
    function uniform(rho, a, b) {
        var p = R.poly_new(), n = 0;
        var st = xof_stream(shake128, concat([rho, new Uint8Array([a & 0xff, b & 0xff])]), 168 * R.UNIFORM_BLOCKS);
        while (n < R.N) {
            var t = st.read(3), v = t[0] | (t[1] << 8) | (t[2] << 16);
            for (var c = 0; c < PER && n < R.N; c++) {
                var d = v & MASK;
                if (d < R.Q) { p[n++] = d; }
                v >>>= R.UNIFORM_BITS;
            }
        }
        return p;
    }

    function matrix(rho, rows, cols, transposed) {
        var A = [];
        for (var i = 0; i < rows; i++) {
            var row = [];
            for (var j = 0; j < cols; j++) { row.push(transposed ? uniform(rho, i, j) : uniform(rho, j, i)); }
            A.push(row);
        }
        return A;
    }

    function row_dot(row, v) {
        var acc = R.poly_new(), tmp = R.poly_new();
        for (var j = 0; j < row.length; j++) {
            R.poly_mul(tmp, row[j], v[j]);
            R.poly_add(acc, acc, tmp);
        }
        R.dot_finish(acc);
        return acc;
    }

    return { uniform: uniform, matrix: matrix, row_dot: row_dot };
}
