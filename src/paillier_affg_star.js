/**
 * paillier_affg_star.js - Pi^aff-g*: the SETUP-LESS Paillier affine operation
 * with a group commitment, in range.
 *
 * CGGMP21 (eprint 2021/060, current revision) Figure 27, appendix A.5. The
 * same relation as Pi^aff-g (paillier_affg.js, Figure 25) - R_aff-g of
 * section 3.2 - but with NO ring-Pedersen parameters: soundness comes from
 * kappa repetitions with a one-bit challenge each, rather than from a large
 * challenge against a commitment the prover cannot open twice.
 *
 *     common input (G, g, N0, N1, C, D, Y, X) and kappa; the prover knows
 *     (x, y, rho, mu) with x in +-2^ell, y in +-2^ell',
 *         g^x = X,  (1+N1)^y mu^N1 = Y mod N1^2,  D = C^x (1+N0)^y rho^N0 mod N0^2
 *
 *     1. for j in [kappa]: alpha_j <- +-2^(ell+eps), beta_j <- +-2^(ell'+eps),
 *        r_j <- Z*_N0, s_j <- Z*_N1;
 *        A_j = C^alpha_j ((1+N0)^beta_j r_j^N0),  R_j = g^alpha_j,
 *        B_j = (1+N1)^beta_j s_j^N1
 *     2. e_j <- {0, 1}
 *     3. z_j = alpha_j + e_j x,  z'_j = beta_j + e_j y,
 *        w_j = r_j rho^e_j mod N0,  lambda_j = s_j mu^e_j mod N1
 *     check  C^z_j (1+N0)^z'_j w_j^N0 = A_j D^e_j mod N0^2,  g^z_j = R_j X^e_j,
 *            (1+N1)^z'_j lambda_j^N1 = B_j Y^e_j mod N1^2;
 *            z_j in +-2^(ell+eps) = I_eps,  z'_j in +-2^(ell'+eps) = J_eps
 *
 * Every "+-m" is the paper's set of m integers, half-width m/2
 * (zk_bytes.pm_half). Parameters (ell, eps, ell') default to (kappa,
 * 2 kappa, 5 kappa) from the group order and are checked against appendix
 * C.1 for both moduli.
 *
 * ⚠ THE REPETITION COUNT IS kappa = log q, the bit length of the group order
 *   (256 on secp256k1), as appendix C.1 defines kappa: soundness 2^-kappa,
 *   matching the 1/q of the large-challenge proofs. It is the verifier's
 *   (opts.kappa only to RAISE it); a proof with any other count is refused.
 *
 * ==================== WHERE THE PROTOCOL USES IT ====================
 *
 * Figure 9 (failed nonce or chi), round 1, for every j != i:
 *
 *     psi_ij = Pi^aff-g* on (I_eps, J_eps, D_ji, K_j, F_ji, Gamma_i);
 *                           (gamma_i, beta_ij, s_ij, r_ij)
 *
 * which in Figure 27's names (this file's) is
 *
 *     D = D_ji,  C = K_j,  Y = F_ji,  X = Gamma_i     N0 = N_j,  N1 = N_i
 *     x = gamma_i,  y = beta_ij,  rho = s_ij,  mu = r_ij
 *
 * and is checked in Figure 9's output step as Pi^aff-g* on
 * (I_eps, J_eps, D_lj, K_l, F_lj, Gamma_j). (I_eps, J_eps) are the ranges the
 * proof GUARANTEES - Figure 27's range check - not the witness ranges.
 *
 * ⛔ A SIGN TO WATCH IN FIGURE 8. There D_ji = (gamma_i (.) K_j) (+) enc_j(-beta_ij)
 *   while F_ji = enc_i(+beta_ij): the two ciphertexts carry OPPOSITE signs of
 *   beta. R_aff-g (and Figure 27) needs the SAME y in D and in Y. A caller
 *   following Figure 8 literally proves nothing true; it must use one sign in
 *   both - e.g. y = -beta_ij with F_ji = enc_i(-beta_ij) - and the same holds
 *   for Pi^aff-g in Figure 8 itself.
 *
 * ⛔ NO EXTERNAL ORACLE.
 */

import { mod, powmod_signed, powmod_signed_ct, unit_in, random_unit,
         require_rng } from './commons/primes.js';
import { fs_stream, fs_bits, require_sid, pm_in, pm_sample, pm_bits, require_pm, cggmp_params,
         encode_proof, decode_proof } from './commons/zk_bytes.js';
import { enc_raw } from './paillier.js';

var TAG = 'cryptographic-primitives/cggmp/affg-star/v1';
var INTS = ['A', 'B', 'z', 'zp', 'w', 'lam'];
var BLOBS = ['R'];
var FIELDS = INTS.concat(BLOBS);

function params(G, pkJ, pkI, opts) {
    var P = cggmp_params('paillier_affg_star', G.ORDER, opts, [pkJ.n, pkI.n]);
    P.q = G.ORDER;
    var k = (opts && opts.kappa) || P.kappa;
    if (k < P.kappa) { throw new Error('paillier_affg_star: kappa may be raised, not lowered below log q (' + P.kappa + ')'); }
    P.reps = k;
    return P;
}

function challenge(G, pkJ, pkI, st, A, B, R, P, sid) {
    var parts = [pkJ.n, pkI.n, G.encode(G.GENERATOR), st.C, st.D, st.Y, G.encode(st.X),
                 P.q, BigInt(P.ell), BigInt(P.ell2), BigInt(P.eps), BigInt(P.reps)];
    for (var j = 0; j < P.reps; j++) { parts.push(A[j], B[j], R[j]); }
    return fs_bits(fs_stream(TAG, sid, parts), P.reps);
}

/**
 * @param {object} G     a prime-order group (commons/group.js)
 * @param {object} pkJ   N0's key - the VERIFIER's; C and D live here
 * @param {object} pkI   N1's key - the PROVER's; Y lives here
 * @param {object} st    { C, D, Y, X }
 * @param {object} wit   { x, y, rho, mu }  rho for D (mod N0), mu for Y (mod N1)
 * @param {function} rng
 * @param {object} [opts]  ell, eps, ell2, kappa
 * @param {Uint8Array} sid
 * @return {{A: [], B: [], R: [], z: [], zp: [], w: [], lam: []}}
 */
export function prove_affg_star(G, pkJ, pkI, st, wit, rng, opts, sid) {
    require_sid('paillier_affg_star', sid);
    rng = require_rng('prove_affg_star', rng);
    var P = params(G, pkJ, pkI, opts), q = P.q;
    var N0 = pkJ.n, N02 = N0 * N0, N1 = pkI.n, N12 = N1 * N1;
    var L = 1n << BigInt(P.ell), LE = 1n << BigInt(P.ell + P.eps);
    var L2 = 1n << BigInt(P.ell2), L2E = 1n << BigInt(P.ell2 + P.eps);
    var x = require_pm('paillier_affg_star', 'x', wit.x, L);
    var y = require_pm('paillier_affg_star', 'y', wit.y, L2);

    var alpha = [], beta = [], r = [], sv = [], A = [], B = [], R = [];
    for (var j = 0; j < P.reps; j++) {
        alpha.push(pm_sample(LE, rng));
        beta.push(pm_sample(L2E, rng));
        r.push(random_unit(N0, rng));
        sv.push(random_unit(N1, rng));
        /* alpha_j and beta_j hide x and y: the constant-time ladder at the
           width of their own bound; r^N0 and s^N1 have public exponents */
        A.push(mod(powmod_signed_ct(st.C, alpha[j], N02, pm_bits(LE)) * enc_raw(N0, N02, beta[j], r[j]), N02));
        R.push(G.encode(G.base_mul(mod(alpha[j], q))));
        B.push(enc_raw(N1, N12, beta[j], sv[j]));
    }
    var e = challenge(G, pkJ, pkI, st, A, B, R, P, sid);
    var out = { A: A, B: B, R: R, z: [], zp: [], w: [], lam: [] };
    for (j = 0; j < P.reps; j++) {
        var ej = BigInt(e[j]);
        out.z.push(alpha[j] + ej * x);
        out.zp.push(beta[j] + ej * y);
        out.w.push(ej ? mod(r[j] * wit.rho, N0) : r[j]);
        out.lam.push(ej ? mod(sv[j] * wit.mu, N1) : sv[j]);
    }
    return out;
}

/** @return {boolean} */
export function verify_affg_star(G, pkJ, pkI, st, proof, opts, sid) {
    require_sid('paillier_affg_star', sid);
    if (!proof) { return false; }
    var P = params(G, pkJ, pkI, opts), q = P.q;
    try {
        var N0 = pkJ.n, N02 = N0 * N0, N1 = pkI.n, N12 = N1 * N1, k = P.reps, j, f;
        for (f = 0; f < FIELDS.length; f++) {
            if (!Array.isArray(proof[FIELDS[f]]) || proof[FIELDS[f]].length !== k) { return false; }
        }
        if (!unit_in(st.C, N02) || !unit_in(st.D, N02) || !unit_in(st.Y, N12)) { return false; }
        var X = st.X, LE = 1n << BigInt(P.ell + P.eps), L2E = 1n << BigInt(P.ell2 + P.eps);
        var e = challenge(G, pkJ, pkI, st, proof.A, proof.B, proof.R, P, sid);
        for (j = 0; j < k; j++) {
            var z = proof.z[j], zp = proof.zp[j];
            if (!pm_in(z, LE) || !pm_in(zp, L2E)) { return false; }   /* I_eps, J_eps */
            if (!unit_in(proof.A[j], N02) || !unit_in(proof.B[j], N12)) { return false; }
            if (!unit_in(proof.w[j], N0) || !unit_in(proof.lam[j], N1)) { return false; }
            var Rj = G.decode(proof.R[j]);
            if (!Rj) { return false; }
            var ej = e[j];
            /* C^z (1+N0)^z' w^N0 = A D^e mod N0^2 */
            var lhs = mod(powmod_signed(st.C, z, N02) * enc_raw(N0, N02, zp, proof.w[j]), N02);
            if (lhs !== (ej ? mod(proof.A[j] * st.D, N02) : proof.A[j])) { return false; }
            /* g^z = R X^e */
            if (!G.equals(G.mul_vartime(mod(z, q), G.GENERATOR), ej ? G.add(Rj, X) : Rj)) { return false; }
            /* (1+N1)^z' lambda^N1 = B Y^e mod N1^2 */
            if (enc_raw(N1, N12, zp, proof.lam[j]) !== (ej ? mod(proof.B[j] * st.Y, N12) : proof.B[j])) { return false; }
        }
        return true;
    } catch (err) {
        return false;
    }
}

/* ---------------- serialisation ---------------- */

export function encode_affg_star(proof) { return encode_proof(proof, INTS, BLOBS); }

/** @return {object|null} null if the encoding is malformed */
export function decode_affg_star(bytes) { return decode_proof(bytes, INTS, BLOBS, FIELDS); }
