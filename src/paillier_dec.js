/**
 * paillier_dec.js - Pi^dec: Paillier special decryption in the exponent,
 * SETUP-LESS.
 *
 * CGGMP21 (eprint 2021/060, current revision) Figure 28, appendix A.6, for
 * the relation R_dec of section 3.2.2:
 *
 *     common input (G, g, q, N0, I, J, K, X, D, S) and kappa; the prover
 *     knows (x, y, rho) with (y, x) in J x I, rho in Z*_N0 and
 *         (1+N0)^y rho^N0 = K^x D  mod N0^2,   (S, X) = (g^y, g^x)
 *
 *     1. for j in [kappa]: alpha_j <- I_eps, beta_j <- J_eps, r_j <- Z*_N0;
 *        A_j = K^(-alpha_j) (1+N0)^beta_j r_j^N0,  (B_j, C_j) = (g^beta_j, g^alpha_j)
 *     2. e_j <- {0, 1}
 *     3. z_j = alpha_j + e_j x,  w_j = beta_j + e_j y,  nu_j = r_j rho^e_j mod N0
 *     check  (1+N0)^w_j nu_j^N0 K^(-z_j) = A_j D^e_j mod N0^2,
 *            (g^z_j, g^w_j) = (C_j X^e_j, B_j S^e_j);   (z_j, w_j) in (I_eps, J_eps)
 *
 * ⚠ THREE ERRATA IN THE FIGURE, corrected here:
 *     - the relation reads "(1+N0)^z rho^N0 = K^x D"; the equality check
 *       (1+N0)^w nu^N0 K^-z = A D^e only closes for (1+N0)^y rho^N0 = K^x D,
 *       so "z" is a typo for y;
 *     - the check writes "A" for A_j;
 *     - and rho is written in "Z^2_N0", which can only mean Z*_N0.
 *
 * RANGES. I = +-2^I_bits and J = +-2^J_bits are the witness ranges, I_eps
 * and J_eps the same widened by eps - every "+-m" the paper's set of m
 * integers, half-width m/2 (zk_bytes.pm_half). By default I_bits = ell and
 * J_bits = ell', as in Figures 25 and 27; a caller whose y is wider passes
 * opts.I_bits / opts.J_bits, and the modulus must then hold J_eps without
 * wrapping (log N0 >= J_bits + eps, refused otherwise).
 *
 * ⚠ THE REPETITION COUNT IS kappa = log q (the group order's bit length, as
 *   appendix C.1 defines kappa): soundness 2^-kappa. The verifier's; opts.kappa
 *   may raise it, never lower it.
 *
 * ==================== WHERE THE PROTOCOL USES IT ====================
 *
 * Figure 9 (failed nonce or chi), round 1:
 *
 *     psi*_i = Pi^dec on (I_eps, J_eps, K_i, Gamma_i, D_i, g^delta_i, g);
 *                        (delta_i, gamma_i, rho_i)
 *
 * which in Figure 28's names (this file's) is
 *
 *     K = K_i,  X = Gamma_i,  D = D_i,  S = g^delta_i,  g = g;   N0 = N_i
 *     y = delta_i,  x = gamma_i,  rho = rho_i
 *
 * with rho_i "the randomizer of K_i^gamma_i D_i mod N_i^2", and is checked in
 * Figure 9's output step on (I_eps, J_eps, K_j, Gamma_j, D_j, g^delta_j, g).
 *
 * ⚠ delta_i HERE IS THE INTEGER PLAINTEXT of K_i^gamma_i D_i, not its value
 *   mod q: Figure 8 reduces delta_i mod q when it broadcasts it, but the
 *   relation is over (1+N0)^y, i.e. mod N0. It is a sum of n - 1 MtA
 *   outputs, each up to about 2^ell', so the caller sizes J_bits for it
 *   (roughly ell' + log2 n + 1); g^y is the same either way.
 *
 * ⛔ NO EXTERNAL ORACLE.
 */

import { mod, powmod_signed, powmod_signed_ct, unit_in, random_unit,
         require_rng } from './commons/primes.js';
import { fs_stream, fs_bits, require_sid, pm_in, pm_sample, pm_bits, require_pm, cggmp_params,
         encode_proof, decode_proof } from './commons/zk_bytes.js';
import { enc_raw } from './paillier.js';

var TAG = 'cryptographic-primitives/cggmp/dec/v1';
var INTS = ['A', 'z', 'w', 'nu'];
var BLOBS = ['B', 'C'];
var FIELDS = INTS.concat(BLOBS);

function params(G, pk, opts) {
    var P = cggmp_params('paillier_dec', G.ORDER, opts, [pk.n]);
    P.q = G.ORDER;
    P.I_bits = (opts && opts.I_bits) || P.ell;
    P.J_bits = (opts && opts.J_bits) || P.ell2;
    if (P.I_bits < P.ell) { throw new Error('paillier_dec: I_bits (' + P.I_bits + ') below ell (' + P.ell + ')'); }
    /* + 2: the extracted y = w1 - w0 reaches +-2^(J+eps), which must stay
       strictly inside +-N0/2 - see zk_bytes.cggmp_params */
    if (pk.n.toString(2).length < P.J_bits + P.eps + 2) {
        throw new Error('paillier_dec: log N0 (' + pk.n.toString(2).length + ' bits) < J_bits + eps + 2 (' +
                        (P.J_bits + P.eps + 2) + ') - J_eps would wrap the plaintext space');
    }
    var k = (opts && opts.kappa) || P.kappa;
    if (k < P.kappa) { throw new Error('paillier_dec: kappa may be raised, not lowered below log q (' + P.kappa + ')'); }
    P.reps = k;
    return P;
}

function statement(G, st) { return { g: st.g || G.GENERATOR, K: st.K, X: st.X, D: st.D, S: st.S }; }

function challenge(G, pk, s, A, B, C, P, sid) {
    var parts = [pk.n, G.encode(s.g), s.K, G.encode(s.X), s.D, G.encode(s.S),
                 P.q, BigInt(P.I_bits), BigInt(P.J_bits), BigInt(P.eps), BigInt(P.reps)];
    for (var j = 0; j < P.reps; j++) { parts.push(A[j], B[j], C[j]); }
    return fs_bits(fs_stream(TAG, sid, parts), P.reps);
}

/**
 * @param {object} G     a prime-order group (commons/group.js)
 * @param {object} pk    the PROVER's Paillier key (N0) - K and D live here
 * @param {object} st    { K, X, D, S, g? }
 * @param {object} wit   { x, y, rho }
 * @param {function} rng
 * @param {object} [opts]  ell, eps, ell2 (C.1), I_bits, J_bits, kappa
 * @param {Uint8Array} sid
 * @return {{A: [], B: [], C: [], z: [], w: [], nu: []}}
 */
export function prove_dec(G, pk, st, wit, rng, opts, sid) {
    require_sid('paillier_dec', sid);
    rng = require_rng('prove_dec', rng);
    var P = params(G, pk, opts), q = P.q, s = statement(G, st);
    var N0 = pk.n, N2 = N0 * N0;
    var I = 1n << BigInt(P.I_bits), J = 1n << BigInt(P.J_bits);
    var IE = 1n << BigInt(P.I_bits + P.eps), JE = 1n << BigInt(P.J_bits + P.eps);
    var x = require_pm('paillier_dec', 'x', wit.x, I);
    var y = require_pm('paillier_dec', 'y', wit.y, J);

    var alpha = [], beta = [], r = [], A = [], B = [], C = [];
    for (var j = 0; j < P.reps; j++) {
        alpha.push(pm_sample(IE, rng));
        beta.push(pm_sample(JE, rng));
        r.push(random_unit(N0, rng));
        /* alpha_j hides x: K^(-alpha_j) through the constant-time ladder at
           the width of I_eps; r^N0 has a public exponent */
        A.push(mod(powmod_signed_ct(s.K, -alpha[j], N2, pm_bits(IE)) * enc_raw(N0, N2, beta[j], r[j]), N2));
        B.push(G.encode(G.mul(mod(beta[j], q), s.g)));
        C.push(G.encode(G.mul(mod(alpha[j], q), s.g)));
    }
    var e = challenge(G, pk, s, A, B, C, P, sid);
    var out = { A: A, B: B, C: C, z: [], w: [], nu: [] };
    for (j = 0; j < P.reps; j++) {
        var ej = BigInt(e[j]);
        out.z.push(alpha[j] + ej * x);
        out.w.push(beta[j] + ej * y);
        out.nu.push(ej ? mod(r[j] * wit.rho, N0) : r[j]);
    }
    return out;
}

/** @return {boolean} */
export function verify_dec(G, pk, st, proof, opts, sid) {
    require_sid('paillier_dec', sid);
    if (!proof) { return false; }
    var P = params(G, pk, opts), q = P.q;
    try {
        var s = statement(G, st), N0 = pk.n, N2 = N0 * N0, k = P.reps, j, f;
        for (f = 0; f < FIELDS.length; f++) {
            if (!Array.isArray(proof[FIELDS[f]]) || proof[FIELDS[f]].length !== k) { return false; }
        }
        if (!unit_in(s.K, N2) || !unit_in(s.D, N2)) { return false; }
        var IE = 1n << BigInt(P.I_bits + P.eps), JE = 1n << BigInt(P.J_bits + P.eps);
        var e = challenge(G, pk, s, proof.A, proof.B, proof.C, P, sid);
        for (j = 0; j < k; j++) {
            var z = proof.z[j], w = proof.w[j];
            if (!pm_in(z, IE) || !pm_in(w, JE)) { return false; }   /* (I_eps, J_eps) */
            if (!unit_in(proof.A[j], N2) || !unit_in(proof.nu[j], N0)) { return false; }
            var Bj = G.decode(proof.B[j]), Cj = G.decode(proof.C[j]);
            if (!Bj || !Cj) { return false; }
            var ej = e[j];
            /* (1+N0)^w nu^N0 K^-z = A D^e mod N0^2 */
            var lhs = mod(enc_raw(N0, N2, w, proof.nu[j]) * powmod_signed(s.K, -z, N2), N2);
            if (lhs !== (ej ? mod(proof.A[j] * s.D, N2) : proof.A[j])) { return false; }
            /* g^z = C X^e,  g^w = B S^e */
            if (!G.equals(G.mul_vartime(mod(z, q), s.g), ej ? G.add(Cj, s.X) : Cj)) { return false; }
            if (!G.equals(G.mul_vartime(mod(w, q), s.g), ej ? G.add(Bj, s.S) : Bj)) { return false; }
        }
        return true;
    } catch (err) {
        return false;
    }
}

/* ---------------- serialisation ---------------- */

export function encode_dec(proof) { return encode_proof(proof, INTS, BLOBS); }

/** @return {object|null} null if the encoding is malformed */
export function decode_dec(bytes) { return decode_proof(bytes, INTS, BLOBS, FIELDS); }
