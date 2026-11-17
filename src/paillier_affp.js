/**
 * paillier_affp.js - Pi^aff-p: a Paillier affine operation, with a PAILLIER
 * commitment, in range.
 *
 * Pi^aff-g (paillier_affg.js) with the multiplier x committed as a Paillier
 * ciphertext under the prover's own key instead of a group element:
 *
 *     common input (N0, N1, C, D, X, Y); the prover knows (x, y, rho, rho_x,
 *     rho_y) with x in +-2^ell, y in +-2^ell2 and
 *         X = (1+N1)^x rho_x^N1,   Y = (1+N1)^y rho_y^N1      mod N1^2
 *         D = C^x (1+N0)^y rho^N0                             mod N0^2
 *
 * N0 is the VERIFIER's key (C and D live there), N1 the PROVER's. In MtA
 * terms: the prover multiplied the verifier's ciphertext by an x and added a
 * y, and x and y are the values it is committed to elsewhere - which is what
 * makes it usable when there is no curve, as in RSA key generation.
 *
 * CGGMP21 (eprint 2021/060), Figure 26 of the January 2021 revision
 * (appendix C.3; the current revision has only Pi^aff-g):
 *
 *     1. alpha <- +-2^(ell+eps), beta <- +-2^(ell2+eps),
 *        r <- Z*_N0, rx, ry <- Z*_N1,
 *        gamma <- +-2^(ell+eps) Nhat, m <- +-2^ell Nhat,
 *        delta <- +-2^(ell+eps) Nhat, mu <- +-2^ell Nhat;
 *        A = C^alpha (1+N0)^beta r^N0,
 *        Bx = (1+N1)^alpha rx^N1,  By = (1+N1)^beta ry^N1,
 *        E = s^alpha t^gamma, S = s^x t^m, F = s^beta t^delta, T = s^y t^mu
 *     2. e
 *     3. z1 = alpha + e x, z2 = beta + e y, z3 = gamma + e m, z4 = delta + e mu,
 *        w = r rho^e mod N0, wx = rx rho_x^e mod N1, wy = ry rho_y^e mod N1
 *     check  C^z1 (1+N0)^z2 w^N0 = A D^e,  (1+N1)^z1 wx^N1 = Bx X^e,
 *            (1+N1)^z2 wy^N1 = By Y^e,  s^z1 t^z3 = E S^e,  s^z2 t^z4 = F T^e,
 *            z1 in +-2^(ell+eps),  z2 in +-2^(ell2+eps)
 *
 * The sampling ranges are those of Pi^aff-g in the CURRENT revision (Figure
 * 25), which this file mirrors line for line; "+-m" is the paper's set of m
 * integers (zk_bytes.pm_half).
 *
 * ==================== THE PARAMETERS ARE THE CALLER'S ====================
 *
 * Pi^aff-g takes (ell, eps, ell2) from the curve order (appendix C.1). There
 * is no curve here, so the sizes are explicit and checked for what THIS
 * proof needs, not for what ECDSA needs:
 *
 *   - the challenge e in [0, 2^kappa), kappa default 128 and at least 128
 *     (as in Pi^zero and Pi^mul - non-negative, so no secret randomiser is
 *     ever inverted), below opts.factor_bits, the verified bound on the
 *     factors of the PROVER's N1 (zk_bytes.paillier_kappa);
 *   - eps >= 2 kappa: alpha must hide e*x, which reaches 2^(kappa+ell); at
 *     eps = 2 kappa the statistical distance is 2^-kappa, CGGMP's level;
 *   - |N1| >= max(ell, ell2) + eps + 2 and |N0| >= ell2 + eps + 2: the
 *     extracted x and y - differences of two responses - stay inside +-N/2
 *     of the modulus they are encrypted under (the same two bits as
 *     zk_bytes.cggmp_params, for the same reason).
 *
 * ⛔ WHAT THE PROOF DOES NOT SAY: that C's plaintext times x plus y fits in
 *   N0. That depends on C's plaintext range, which this proof never sees;
 *   the caller must choose ell, ell2 and N0 so that it does.
 *
 * ⛔ NO EXTERNAL ORACLE.
 */

import { mod, powmod_signed, powmod_signed_ct, powmod, unit_in, random_unit, in_range,
         require_rng } from './commons/primes.js';
import { fs_stream, fs_uint, require_sid, paillier_kappa, pm_in, pm_sample, pm_bits, require_pm,
         encode_proof, decode_proof } from './commons/zk_bytes.js';
import { enc_raw } from './paillier.js';

var TAG = 'cryptographic-primitives/paillier-affp/v1';
var INTS = ['A', 'Bx', 'By', 'E', 'S', 'F', 'T', 'z1', 'z2', 'z3', 'z4', 'w', 'wx', 'wy'];

function bits(n) { return n.toString(2).length; }

function params(pk0, pk1, opts) {
    var kappa = paillier_kappa('paillier_affp', opts, [pk1.n]);
    var ell = opts && opts.ell, ell2 = opts && opts.ell2;
    var eps = (opts && opts.eps) || 2 * kappa;
    function no(why) { throw new Error('paillier_affp: ' + why); }
    if (!Number.isInteger(ell) || ell < 1 || !Number.isInteger(ell2) || ell2 < 1) {
        no('ell and ell2 are required: there is no curve to take them from');
    }
    if (eps < 2 * kappa) { no('eps (' + eps + ') < 2 kappa (' + (2 * kappa) + ')'); }
    if (bits(pk1.n) < Math.max(ell, ell2) + eps + 2) {
        no("the prover's modulus (" + bits(pk1.n) + ' bits) < max(ell, ell2) + eps + 2 (' + (Math.max(ell, ell2) + eps + 2) + ')');
    }
    if (bits(pk0.n) < ell2 + eps + 2) {
        no("the verifier's modulus (" + bits(pk0.n) + ' bits) < ell2 + eps + 2 (' + (ell2 + eps + 2) + ')');
    }
    return { kappa: kappa, ell: ell, ell2: ell2, eps: eps };
}

function challenge(N0, N1, aux, st, com, P, sid) {
    var read = fs_stream(TAG, sid, [
        N0, N1, aux.N, aux.s, aux.t, st.C, st.D, st.X, st.Y,
        com.A, com.Bx, com.By, com.E, com.S, com.F, com.T,
        BigInt(P.kappa), BigInt(P.ell), BigInt(P.ell2), BigInt(P.eps)
    ]);
    return fs_uint(read, P.kappa);
}

/**
 * @param {object} pk0   the VERIFIER's Paillier key - C and D live here
 * @param {object} pk1   the PROVER's Paillier key - X and Y live here
 * @param {object} aux   the verifier's ring-Pedersen parameters {N, s, t}
 * @param {object} st    { C, D, X, Y }
 * @param {object} wit   { x, y, rho, rho_x, rho_y }
 * @param {function} rng
 * @param {object} opts  { ell, ell2, factor_bits } required; kappa, eps optional
 * @param {Uint8Array} sid
 */
export function prove_affp(pk0, pk1, aux, st, wit, rng, opts, sid) {
    require_sid('paillier_affp', sid);
    rng = require_rng('prove_affp', rng);
    var P = params(pk0, pk1, opts);
    var L  = 1n << BigInt(P.ell),  LE  = 1n << BigInt(P.ell + P.eps);
    var L2 = 1n << BigInt(P.ell2), L2E = 1n << BigInt(P.ell2 + P.eps);
    var x = require_pm('paillier_affp', 'x', wit.x, L);
    var y = require_pm('paillier_affp', 'y', wit.y, L2);
    var N0 = pk0.n, N02 = N0 * N0, N1 = pk1.n, N12 = N1 * N1, aN = aux.N;

    var alpha = pm_sample(LE, rng),  beta  = pm_sample(L2E, rng);
    var r  = random_unit(N0, rng), rx = random_unit(N1, rng), ry = random_unit(N1, rng);
    var gamma = pm_sample(LE * aN, rng), m  = pm_sample(L * aN, rng);
    var delta = pm_sample(LE * aN, rng), mu = pm_sample(L * aN, rng);

    /* every exponent below except the moduli is secret: the constant-time
       ladder at the width of the bound it was drawn from */
    function rp(a, ab, b, bb) {
        return mod(powmod_signed_ct(aux.s, a, aN, pm_bits(ab)) * powmod_signed_ct(aux.t, b, aN, pm_bits(bb)), aN);
    }
    var com = {
        A:  mod(powmod_signed_ct(st.C, alpha, N02, pm_bits(LE)) * enc_raw(N0, N02, beta, r), N02),
        Bx: enc_raw(N1, N12, alpha, rx),
        By: enc_raw(N1, N12, beta, ry),
        E:  rp(alpha, LE, gamma, LE * aN),
        S:  rp(x, L, m, L * aN),
        F:  rp(beta, L2E, delta, LE * aN),
        T:  rp(y, L2, mu, L * aN)
    };
    var e = challenge(N0, N1, aux, st, com, P, sid);
    return {
        A: com.A, Bx: com.Bx, By: com.By, E: com.E, S: com.S, F: com.F, T: com.T,
        /* INTEGERS - reducing them destroys the range property */
        z1: alpha + e * x, z2: beta + e * y, z3: gamma + e * m, z4: delta + e * mu,
        /* e >= 0 and public: variable-time powers, no inverse of a randomiser */
        w:  mod(r  * powmod(wit.rho,   e, N0), N0),
        wx: mod(rx * powmod(wit.rho_x, e, N1), N1),
        wy: mod(ry * powmod(wit.rho_y, e, N1), N1)
    };
}

/** @return {boolean} */
export function verify_affp(pk0, pk1, aux, st, proof, opts, sid) {
    require_sid('paillier_affp', sid);
    if (!proof) { return false; }
    var P = params(pk0, pk1, opts);
    try {
        var i;
        for (i = 0; i < INTS.length; i++) { if (typeof proof[INTS[i]] !== 'bigint') { return false; } }
        var N0 = pk0.n, N02 = N0 * N0, N1 = pk1.n, N12 = N1 * N1, aN = aux.N;
        if (!unit_in(st.C, N02) || !unit_in(st.D, N02) || !unit_in(st.X, N12) || !unit_in(st.Y, N12)) { return false; }
        if (!unit_in(proof.A, N02) || !unit_in(proof.Bx, N12) || !unit_in(proof.By, N12)) { return false; }
        var rpf = ['E', 'S', 'F', 'T'];
        for (i = 0; i < rpf.length; i++) { if (!unit_in(proof[rpf[i]], aN)) { return false; } }
        if (!unit_in(proof.w, N0) || !unit_in(proof.wx, N1) || !unit_in(proof.wy, N1)) { return false; }

        /* THE RANGE CHECKS, WHICH ARE THE PROOF */
        if (!pm_in(proof.z1, 1n << BigInt(P.ell + P.eps)) ||
            !pm_in(proof.z2, 1n << BigInt(P.ell2 + P.eps))) { return false; }
        /*
         * z3, z4: what an honest prover can produce (|gamma|, |delta| below
         * 2^(ell+eps-1) Nhat, |e m|, |e mu| below 2^(kappa+ell-1) Nhat, and
         * eps > kappa), and no more - so a verifier never exponentiates by an
         * arbitrary-size number, and the holder of the ring-Pedersen trapdoor
         * cannot shift them by multiples of ord(t) beyond that window.
         */
        var Z34 = (1n << BigInt(P.ell + P.eps)) * aN;
        if (!in_range(proof.z3, Z34) || !in_range(proof.z4, Z34)) { return false; }

        var e = challenge(N0, N1, aux, st, proof, P, sid);

        /* C^z1 (1+N0)^z2 w^N0 = A D^e  mod N0^2 */
        if (mod(powmod_signed(st.C, proof.z1, N02) * enc_raw(N0, N02, proof.z2, proof.w), N02) !==
            mod(proof.A * powmod(st.D, e, N02), N02)) { return false; }
        /* (1+N1)^z1 wx^N1 = Bx X^e  mod N1^2 */
        if (enc_raw(N1, N12, proof.z1, proof.wx) !== mod(proof.Bx * powmod(st.X, e, N12), N12)) { return false; }
        /* (1+N1)^z2 wy^N1 = By Y^e  mod N1^2 */
        if (enc_raw(N1, N12, proof.z2, proof.wy) !== mod(proof.By * powmod(st.Y, e, N12), N12)) { return false; }
        /* s^z1 t^z3 = E S^e,  s^z2 t^z4 = F T^e  mod Nhat */
        if (mod(powmod_signed(aux.s, proof.z1, aN) * powmod_signed(aux.t, proof.z3, aN), aN) !==
            mod(proof.E * powmod(proof.S, e, aN), aN)) { return false; }
        return mod(powmod_signed(aux.s, proof.z2, aN) * powmod_signed(aux.t, proof.z4, aN), aN) ===
               mod(proof.F * powmod(proof.T, e, aN), aN);
    } catch (err) {
        return false;
    }
}

/* ---------------- serialisation ---------------- */

export function encode_affp(proof) { return encode_proof(proof, INTS, []); }

/** @return {object|null} null if the encoding is malformed */
export function decode_affp(bytes) { return decode_proof(bytes, INTS, [], []); }
