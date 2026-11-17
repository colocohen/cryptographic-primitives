/**
 * paillier_enc_elg.js - Pi^enc-elg: a Paillier plaintext in range, equal to
 * the value inside an El-Gamal commitment.
 *
 * CGGMP21 (eprint 2021/060, current revision) Figure 24, appendix A.2:
 *
 *     setup        the VERIFIER's ring-Pedersen parameters (Nhat, s, t)
 *     common input (G, q, g, N0, C, A, B, X)
 *     the prover knows (x, rho, b) with
 *         x in +-2^ell,  C = (1+N0)^x rho^N0 mod N0^2,
 *         B = g^b,  X = A^b g^x
 *
 *     1. alpha <- +-2^(ell+eps),  mu <- +-2^ell Nhat,  r <- Z*_N0,
 *        beta <- F_q,  gamma <- +-2^(ell+eps) Nhat
 *        S = s^x t^mu,  D = (1+N0)^alpha r^N0,  Y = A^beta g^alpha,
 *        Z = g^beta,    T = s^alpha t^gamma
 *     2. e <- +-q
 *     3. z1 = alpha + e x,  w = beta + e b mod q,  z2 = r rho^e mod N0,
 *        z3 = gamma + e mu
 *     check  (1+N0)^z1 z2^N0 = D C^e mod N0^2,  A^w g^z1 = Y X^e,
 *            g^w = Z B^e,  s^z1 t^z3 = T S^e mod Nhat;  z1 in +-2^(ell+eps)
 *
 * Every "+-m" is the paper's set of m integers, half-width m/2
 * (zk_bytes.pm_half); parameters are (ell, eps, ell') = (kappa, 2 kappa,
 * 5 kappa) from the group order by default and checked against appendix C.1
 * (zk_bytes.cggmp_params). The figure draws r from Z*_N - N is N0 there.
 *
 * ==================== WHERE THE PROTOCOL USES IT, AND THE (a, b) SWAP ====================
 *
 * Figure 8 (pre-signing) round 1, twice per party and per verifier j:
 *
 *     psi0_ji = Pi^enc-elg on (I_eps, K_i, Y_i, A_i1, A_i2); (k_i, rho_i, a_i)
 *     psi1_ji = Pi^enc-elg on (I_eps, G_i, Y_i, B_i1, B_i2); (gamma_i, nu_i, b_i)
 *
 * with (A_i1, A_i2) = (g^a_i, Y_i^a_i g^k_i). Figure 24 states the El-Gamal
 * triple as (A, B, X) = (g^a, g^b, g^(ab+x)) and its witness as (x, rho, a, b)
 * - but the proof only ever uses b: A is a BASE (A^beta, A^w) and B = g^b is
 * the commitment whose exponent the prover knows. So the prover needs b and
 * not a, and the Figure 8 call maps onto this file's names as
 *
 *     C = K_i,  A = Y_i,  B = A_i1,  X = A_i2;   x = k_i,  rho = rho_i,  b = a_i
 *
 * (and likewise for (G_i, Y_i, B_i1, B_i2; gamma_i, nu_i, b_i)). Y_i's own
 * discrete log is never needed - which is the point, since in Figure 8 it is
 * just "sample Y_i <- G". The witness here is therefore (x, rho, b).
 *
 * ⛔ NO EXTERNAL ORACLE.
 */

import { mod, powmod_signed, powmod_signed_ct, unit_in, random_unit, random_below_biased,
         require_rng, powmod_signed_blind } from './commons/primes.js';
import { fs_stream, fs_pm, require_sid, pm_in, pm_sample, pm_bits, require_pm, cggmp_params,
         encode_proof, decode_proof } from './commons/zk_bytes.js';
import { enc_raw } from './paillier.js';

var TAG = 'cryptographic-primitives/cggmp/enc-elg/v1';
var INTS = ['S', 'D', 'T', 'z1', 'w', 'z2', 'z3'];
var BLOBS = ['Y', 'Z'];

function params(G, pk, opts) {
    var P = cggmp_params('paillier_enc_elg', G.ORDER, opts, [pk.n]);
    P.q = G.ORDER;
    return P;
}

function statement(G, st) { return { g: st.g || G.GENERATOR, C: st.C, A: st.A, B: st.B, X: st.X }; }

function challenge(G, pk, aux, s, com, P, sid) {
    var read = fs_stream(TAG, sid, [
        pk.n, aux.N, aux.s, aux.t,
        G.encode(s.g), s.C, G.encode(s.A), G.encode(s.B), G.encode(s.X),
        com.S, com.D, com.Y, com.Z, com.T,
        P.q, BigInt(P.ell), BigInt(P.eps)
    ]);
    return fs_pm(read, P.q);
}

/**
 * @param {object} G     a prime-order group (commons/group.js)
 * @param {object} pk    the PROVER's Paillier public key (N0)
 * @param {object} aux   the VERIFIER's ring-Pedersen parameters {N, s, t}
 * @param {object} st    { C, A, B, X, g? }
 * @param {object} wit   { x, rho, b }
 * @param {function} rng
 * @param {object} [opts]  ell, eps, ell2 (checked against C.1)
 * @param {Uint8Array} sid
 * @return {{S, D, Y, Z, T, z1, w, z2, z3}}
 */
export function prove_enc_elg(G, pk, aux, st, wit, rng, opts, sid) {
    require_sid('paillier_enc_elg', sid);
    rng = require_rng('prove_enc_elg', rng);
    var P = params(G, pk, opts), s = statement(G, st), q = P.q;
    var N0 = pk.n, N2 = N0 * N0, Nh = aux.N;
    var L = 1n << BigInt(P.ell), LE = 1n << BigInt(P.ell + P.eps);
    var x = require_pm('paillier_enc_elg', 'x', wit.x, L);
    var b = mod(wit.b, q);

    /*
     * ⛔ x IS THE WITNESS; alpha, mu, gamma hide it and beta hides b. Every
     *   exponent mod Nhat goes through the constant-time ladder at
     *   zk_bytes.pm_bits of the bound it was drawn from; the group
     *   multiplications are the group's constant-time ones.
     */
    var alpha = pm_sample(LE, rng);
    var mu    = pm_sample(L * Nh, rng);
    var r     = random_unit(N0, rng);
    var beta  = random_below_biased(q, rng);
    var gamma = pm_sample(LE * Nh, rng);

    var com = {
        S: mod(powmod_signed_ct(aux.s, x, Nh, pm_bits(L)) * powmod_signed_ct(aux.t, mu, Nh, pm_bits(L * Nh)), Nh),
        D: enc_raw(N0, N2, alpha, r),
        Y: G.encode(G.add(G.mul(beta, s.A), G.mul(mod(alpha, q), s.g))),
        Z: G.encode(G.mul(beta, s.g)),
        T: mod(powmod_signed_ct(aux.s, alpha, Nh, pm_bits(LE)) * powmod_signed_ct(aux.t, gamma, Nh, pm_bits(LE * Nh)), Nh)
    };
    var e = challenge(G, pk, aux, s, com, P, sid);
    return {
        S: com.S, D: com.D, Y: com.Y, Z: com.Z, T: com.T,
        /* z1, z3 are INTEGERS - reducing them destroys the range property */
        z1: alpha + e * x,
        w:  mod(beta + e * b, q),
        /* e is public; rho opens C, so its inverse (e < 0) is blinded */
        z2: mod(r * powmod_signed_blind(wit.rho, e, N0, rng), N0),
        z3: gamma + e * mu
    };
}

/** @return {boolean} */
export function verify_enc_elg(G, pk, aux, st, proof, opts, sid) {
    require_sid('paillier_enc_elg', sid);
    if (!proof) { return false; }
    /* the verifier's parameters, refused if they violate C.1 */
    var P = params(G, pk, opts), q = P.q;
    try {
        var s = statement(G, st), N0 = pk.n, N2 = N0 * N0, Nh = aux.N;
        for (var i = 0; i < INTS.length; i++) { if (typeof proof[INTS[i]] !== 'bigint') { return false; } }
        if (!pm_in(proof.z1, 1n << BigInt(P.ell + P.eps))) { return false; }   /* z1 in +-2^(ell+eps) */
        if (proof.w < 0n || proof.w >= q) { return false; }
        /*
         * z3 is not hashed and the figure gives it no range - but it is an
         * EXPONENT here, and an unbounded one is a denial of service: a 64 KB
         * z3 cost 2.8 s against 4 ms. Honestly |z3| <= |gamma| + |e*mu| <
         * 2^(ell+eps) N^ + q 2^ell N^ (half-widths), so anything past twice
         * that is refused before any exponentiation.
         */
        var z3max = 2n * ((1n << BigInt(P.ell + P.eps)) * aux.N + q * (1n << BigInt(P.ell)) * aux.N);
        if (proof.z3 > z3max || proof.z3 < -z3max) { return false; }
        if (!unit_in(s.C, N2) || !unit_in(proof.D, N2) || !unit_in(proof.z2, N0)) { return false; }
        if (!unit_in(proof.S, Nh) || !unit_in(proof.T, Nh)) { return false; }
        var Y = G.decode(proof.Y), Z = G.decode(proof.Z);
        if (!Y || !Z) { return false; }

        var e = challenge(G, pk, aux, s, proof, P, sid), eq = mod(e, q);
        /* (1+N0)^z1 z2^N0 = D C^e mod N0^2 */
        if (enc_raw(N0, N2, proof.z1, proof.z2) !== mod(proof.D * powmod_signed(s.C, e, N2), N2)) { return false; }
        /* A^w g^z1 = Y X^e */
        if (!G.equals(G.add(G.mul_vartime(proof.w, s.A), G.mul_vartime(mod(proof.z1, q), s.g)),
                      G.add(Y, G.mul_vartime(eq, s.X)))) { return false; }
        /* g^w = Z B^e */
        if (!G.equals(G.mul_vartime(proof.w, s.g), G.add(Z, G.mul_vartime(eq, s.B)))) { return false; }
        /* s^z1 t^z3 = T S^e mod Nhat */
        return mod(powmod_signed(aux.s, proof.z1, Nh) * powmod_signed(aux.t, proof.z3, Nh), Nh) ===
               mod(proof.T * powmod_signed(proof.S, e, Nh), Nh);
    } catch (err) {
        return false;
    }
}

/* ---------------- serialisation ---------------- */

export function encode_enc_elg(proof) { return encode_proof(proof, INTS, BLOBS); }

/** @return {object|null} null if the encoding is malformed */
export function decode_enc_elg(bytes) { return decode_proof(bytes, INTS, BLOBS); }
