/**
 * zk_elog.js - Pi^elog: a discrete log equal to an El-Gamal plaintext.
 *
 * CGGMP21 (eprint 2021/060, current revision) Figure 23, appendix A.1, for
 * the relation R_elog of section 3.2:
 *
 *     common input (G, g, L, M, X, Y, h); the prover knows (y, lambda) with
 *         L = g^lambda,  M = g^y X^lambda,  Y = h^y
 *
 * that is: (L, M) is an El-Gamal encryption of g^y under the key X, and y is
 * also the discrete log of Y to the base h. Written additively in the code,
 * as the GROUP interface is (commons/group.js): g^a is a*G, a product of two
 * elements is G.add.
 *
 *     1. alpha, m <- F_q;  A = g^alpha,  N = g^m X^alpha,  B = h^m
 *     2. e <- +-q
 *     3. z = alpha + e lambda mod q,  u = m + e y mod q
 *     check  g^z = A L^e,  g^u X^z = N M^e,  h^u = B Y^e
 *
 * Completeness and HVZK are perfect and soundness is 1/q (appendix A.1.1):
 * there is no range here and no Paillier modulus, so no C.1 parameters.
 *
 * ==================== WHERE THE PROTOCOL USES IT ====================
 *
 * Figure 8 (pre-signing), twice per party:
 *
 *   round 2 (a)   psi_i  = Pi^elog on (Gamma_i, g, B_i1, B_i2, Y_i); (gamma_i, b_i)
 *   round 3       psi'_i = Pi^elog on (Delta_i, Gamma, A_i1, A_i2, Y_i); (k_i, a_i)
 *
 * The figure lists the statement as R_elog's tuple (X, h, A, B, Y) of
 * section 3.2. In this file's names (Figure 23's) the first call is
 *
 *     Y = Gamma_i,  h = g,      L = B_i1,  M = B_i2,  X = Y_i;  y = gamma_i,  lambda = b_i
 *
 * and the second
 *
 *     Y = Delta_i,  h = Gamma,  L = A_i1,  M = A_i2,  X = Y_i;  y = k_i,      lambda = a_i
 *
 * ⛔ NO EXTERNAL ORACLE.
 */

import { mod, require_rng, random_below_biased } from './commons/primes.js';
import { fs_stream, fs_pm, require_sid, encode_proof, decode_proof } from './commons/zk_bytes.js';

var TAG = 'cryptographic-primitives/cggmp/elog/v1';
var INTS = ['z', 'u'];
var BLOBS = ['A', 'N', 'B'];

/* e uniform in +-q - the paper's set, half-width (q-1)/2 (zk_bytes.pm_half) */
function challenge(G, st, A, N, B, sid) {
    var read = fs_stream(TAG, sid, [
        G.encode(st.g), G.encode(st.h), G.encode(st.L), G.encode(st.M),
        G.encode(st.X), G.encode(st.Y), A, N, B
    ]);
    return fs_pm(read, G.ORDER);
}

function statement(G, st) {
    return { g: st.g || G.GENERATOR, h: st.h, L: st.L, M: st.M, X: st.X, Y: st.Y };
}

/**
 * @param {object} G     a prime-order group (commons/group.js)
 * @param {object} st    { L, M, X, Y, h, g? }  - g defaults to G.GENERATOR
 * @param {object} wit   { y, lambda }
 * @param {function} rng
 * @param {Uint8Array} sid
 * @return {{A, N, B, z, u}}
 */
export function prove_elog(G, st, wit, rng, sid) {
    require_sid('zk_elog', sid);
    rng = require_rng('prove_elog', rng);
    var q = G.ORDER, s = statement(G, st);
    var y = mod(wit.y, q), lambda = mod(wit.lambda, q);
    /* alpha, m <- F_q; both are nonces, so the scalar multiplications are the
       group's constant-time ones */
    var alpha = random_below_biased(q, rng), m = random_below_biased(q, rng);
    var A = G.encode(G.mul(alpha, s.g));
    var N = G.encode(G.add(G.mul(m, s.g), G.mul(alpha, s.X)));
    var B = G.encode(G.mul(m, s.h));
    var e = challenge(G, s, A, N, B, sid);
    return { A: A, N: N, B: B, z: mod(alpha + e * lambda, q), u: mod(m + e * y, q) };
}

/** @return {boolean} */
export function verify_elog(G, st, proof, sid) {
    require_sid('zk_elog', sid);
    if (!proof) { return false; }
    try {
        var q = G.ORDER, s = statement(G, st);
        if (typeof proof.z !== 'bigint' || typeof proof.u !== 'bigint') { return false; }
        /* z, u are residues mod q: a canonical encoding only, or the same
           proof would have a second set of bytes */
        if (proof.z < 0n || proof.z >= q || proof.u < 0n || proof.u >= q) { return false; }
        /* decode() is the prime-order contract - see commons/group.js */
        var A = G.decode(proof.A), N = G.decode(proof.N), B = G.decode(proof.B);
        if (!A || !N || !B) { return false; }
        var e = mod(challenge(G, s, proof.A, proof.N, proof.B, sid), q);
        /* g^z = A L^e */
        if (!G.equals(G.mul_vartime(proof.z, s.g), G.add(A, G.mul_vartime(e, s.L)))) { return false; }
        /* g^u X^z = N M^e */
        if (!G.equals(G.add(G.mul_vartime(proof.u, s.g), G.mul_vartime(proof.z, s.X)),
                      G.add(N, G.mul_vartime(e, s.M)))) { return false; }
        /* h^u = B Y^e */
        return G.equals(G.mul_vartime(proof.u, s.h), G.add(B, G.mul_vartime(e, s.Y)));
    } catch (err) {
        return false;
    }
}

/* ---------------- serialisation ---------------- */

export function encode_elog(proof) { return encode_proof(proof, INTS, BLOBS); }

/** @return {object|null} null if the encoding is malformed */
export function decode_elog(bytes) { return decode_proof(bytes, INTS, BLOBS); }
