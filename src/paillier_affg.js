/**
 * paillier_affg.js - Pi^aff-g: a Paillier affine operation, with a group
 * commitment, in range.
 *
 * THE BIG ONE, and the heart of MtA.
 *
 * mta.js does the arithmetic: Bob multiplies Alice's ciphertext by his b,
 * adds a mask, and hands it back. That is correct against an honest Bob and
 * wide open against a malicious one - he can multiply by something other than
 * b, or choose a mask large enough to wrap the modulus, and Alice cannot
 * tell. This proof is what closes it. Without it, mta.js is GG18's first
 * mistake.
 *
 * The statement, from section 3.4 of the LFDT specification:
 *
 *     I know (x, y, rho, rho_y) with
 *         x in +-2^ell,  y in +-2^ell2,
 *         D = (x (*) C) (+) enc_Nj(y; rho),
 *         Y = enc_Ni(y; rho_y),
 *         X = x * G
 *
 * where (*) is scalar multiplication of a ciphertext and (+) is ciphertext
 * addition. In MtA terms: Bob proves that D really is Alice's ciphertext
 * multiplied by the x he committed to on the curve, plus an encryption of a
 * y he also committed to - and that both are small enough not to wrap.
 *
 * TWO MODULI, AND THEY ARE NOT INTERCHANGEABLE. Nj is the party being proved
 * TO - the one whose ciphertext C is being operated on. Ni is the prover's
 * own, under which y is separately encrypted. Swapping them produces a proof
 * that verifies against nothing, and the argument order here follows the
 * specification exactly for that reason.
 *
 * ==================== THE RANGE CHECKS ARE THE PROOF ====================
 *
 * As everywhere else in this family: relations 10 through 14 hold for a
 * prover using an enormous x or y. Steps 15 and 16 - z1 in +-2^(ell+eps) and
 * z2 in +-2^(ell2+eps) - are what make the statement about SIZE, and size is
 * what stops the modulus wrapping and the share leaking.
 *
 * ==================== VERIFIED AGAINST THE SPECIFICATION ====================
 *
 * Built from section 3.4 rather than reconstructed, which is a different
 * thing from the two proofs in zk_cmp.js. That is a specification of one
 * implementation, not a standard: stronger than reading the paper,
 * weaker than a test vector, and there is no test vector to be had.
 *
 * ⭐ AND SINCE ALIGNED TO THE PAPER ITSELF: CGGMP21 (eprint 2021/060, current
 *   revision) Figure 25, appendix A.3 - every sampling range, the witness
 *   ranges, the challenge set +-q and both response ranges, read with the
 *   paper's "+-m" (a set of m integers, half-width m/2; zk_bytes.pm_half).
 *   The relation and the field names are the figure's.
 */

import { concat, be16 } from './commons/bytes.js';
import { mod, powmod_signed, powmod_signed_ct, powmod_signed_blind, unit_in, random_unit, require_rng } from './commons/primes.js';
import { fs_stream, fs_pm, require_sid, encode_fields, decode_fields,
         pm_in, pm_sample, pm_bits, require_pm, cggmp_params } from './commons/zk_bytes.js';
import { enc_raw } from './paillier.js';

/*
 * CGGMP's parameters - ell for x, ell' (ell2) for the additive mask y, eps
 * the slack - from the group order: zk_bytes.cggmp_params, (ell, eps, ell')
 * = (kappa, 2 kappa, 5 kappa) by default and checked against appendix C.1 in
 * prover and verifier, with log N for BOTH Paillier moduli.
 *
 * ⛔ THE OLD DEFAULT VIOLATED C.1: ell' = 512 at ell = 256, where C.1 needs
 *   ell' >= ell + eps + 2 ell = 1280. ell' must exceed the product the mask
 *   hides (gamma k, x k - about 2 ell bits) by eps; at 512 it did not.
 */

/*
 * enc_N(m; r) with g = n+1, so the exponent collapses to 1 + m*n.
 * ⭐ paillier.enc_raw, which is where the formula lives - six places computed
 *   it. A local enc() wrapper stayed behind here after that merge, adding a
 *   name and nothing else; the calls below go to enc_raw directly.
 */

/**
 * The Fiat-Shamir challenge, uniform in +-q.
 *
 * The specification draws it from +-q where q is the group order, because it
 * is used in elliptic point operations as well as modular ones - see the note
 * in section 3.9 about why the sign matters here and not in Pi^elog.
 *
 * `sid` first, so a proof cannot move between runs or between provers.
 */
function challenge(sid, Nj, Ni, aux, C, D, Y, eX, com, P) {
    /*
     * v3: e uniform in +-q EXACTLY - the paper's set, half-width (q-1)/2
     * (zk_bytes.fs_pm). v2 drew a sign and a magnitude below 2^|q|, about
     * four times as wide and not the figure's set. q and the parameter set
     * are hashed with every v2 input.
     */
    var read = fs_stream('cryptographic-primitives/paillier-affg/v3', sid, [
        Nj, Ni, aux.N, aux.s, aux.t,
        C, D, Y, eX,
        com.A, com.Bx, com.By, com.E, com.S, com.F, com.T,
        P.q, BigInt(P.ell), BigInt(P.ell2), BigInt(P.eps)
    ]);
    return fs_pm(read, P.q);
}

function params(G, pkJ, pkI, opts) {
    var P = cggmp_params('paillier_affg', G.ORDER, opts, [pkJ.n, pkI.n]);
    P.q = G.ORDER;
    return P;
}

/**
 * @param {object}     G     a prime-order group, see commons/group.js
 * @param {object}     pkJ   the VERIFIER's Paillier key - C and D live here
 * @param {object}     pkI   the PROVER's Paillier key - Y lives here
 * @param {object}     aux   the verifier's Ring-Pedersen parameters {N,s,t}
 * @param {bigint}     C     the ciphertext being operated on
 * @param {bigint}     D     the result, (x (*) C) (+) enc_Nj(y; rho)
 * @param {bigint}     Y     enc_Ni(y; rho_y)
 * @param {object}     X     x * G on the curve
 * @param {bigint}     x,y   the witnesses
 * @param {bigint}     rho   the randomness in D's added encryption
 * @param {bigint}     rhoY  the randomness in Y
 * @param {function}   [rng] omitted or null draws fresh ones from the platform
 * @param {object}     [opts]  ell, ell2, eps
 * @param {Uint8Array} [sid]
 */
export function prove_affg(G, pkJ, pkI, aux, C, D, Y, X,
                           x, y, rho, rhoY, rng, opts, sid) {
    require_sid('paillier_affg', sid);
    rng = require_rng('paillier_affg.prove_affg', rng);
    /*
     * The parameters, checked against C.1. The old guard "eps must exceed
     * the group order width" is part of it (eps >= ell + kappa): the
     * challenge is drawn from +-q, so z1 = alpha + e*x carries log2(q) + ell
     * bits, and with eps too small every honest proof fails its own range
     * check - which reads as a broken relation, not a parameter too small.
     */
    var P = params(G, pkJ, pkI, opts);
    var L  = 1n << BigInt(P.ell),  LE  = 1n << BigInt(P.ell + P.eps);
    var L2 = 1n << BigInt(P.ell2), L2E = 1n << BigInt(P.ell2 + P.eps);

    require_pm('paillier_affg', 'x', x, L);
    require_pm('paillier_affg', 'y', y, L2);

    var Nj = pkJ.n, Nj2 = Nj * Nj;
    var Ni = pkI.n, Ni2 = Ni * Ni;
    var aN = aux.N;

    /*
     * Figure 25 step 1, every "+-m" the paper's set of m integers
     * (zk_bytes.pm_half):
     *
     *     alpha <- +-2^(ell+eps)          beta <- +-2^(ell'+eps)
     *     r <- Z*_N0,  ry <- Z*_N1
     *     gamma <- +-2^(ell+eps) * Nhat   m  <- +-2^ell * Nhat
     *     delta <- +-2^(ell+eps) * Nhat   mu <- +-2^ell * Nhat
     *
     * ⚠ delta AND mu USED ell' WHERE THE FIGURE HAS ell: delta was drawn from
     *   +-2^(ell'+eps) * Nhat and mu from +-2^ell' * Nhat. Both were also
     *   twice the paper's width, as every bound here was.
     *
     * ⛔ x AND y ARE THE WITNESSES and alpha, beta, gamma, delta, m, mu are
     *   their blinders - every exponent in the commitments below is secret,
     *   so each goes through the constant-time ladder at zk_bytes.pm_bits of
     *   the bound it was drawn from or checked against. The ladder and the
     *   guard read the same number and cannot disagree. rho^e and rhoY^e
     *   below stay variable-time: e is the Fiat-Shamir challenge.
     */
    var alpha = pm_sample(LE, rng);
    var beta  = pm_sample(L2E, rng);
    var r     = random_unit(Nj, rng);
    var rY    = random_unit(Ni, rng);
    var gamma = pm_sample(LE * aN, rng);
    var m     = pm_sample(L * aN, rng);
    var delta = pm_sample(LE * aN, rng);
    var mu    = pm_sample(L * aN, rng);

    var com = {
        /* A = C^alpha ((1+N0)^beta r^N0) */
        A:  mod(powmod_signed_ct(C, alpha, Nj2, pm_bits(LE)) * enc_raw(Nj, Nj2, beta, r), Nj2),
        Bx: G.encode(G.mul(mod(alpha, G.ORDER), G.GENERATOR)),
        By: enc_raw(Ni, Ni2, beta, rY),
        E:  mod(powmod_signed_ct(aux.s, alpha, aN, pm_bits(LE)) * powmod_signed_ct(aux.t, gamma, aN, pm_bits(LE * aN)), aN),
        S:  mod(powmod_signed_ct(aux.s, x,     aN, pm_bits(L))  * powmod_signed_ct(aux.t, m,     aN, pm_bits(L * aN)),  aN),
        F:  mod(powmod_signed_ct(aux.s, beta,  aN, pm_bits(L2E)) * powmod_signed_ct(aux.t, delta, aN, pm_bits(LE * aN)), aN),
        T:  mod(powmod_signed_ct(aux.s, y,     aN, pm_bits(L2)) * powmod_signed_ct(aux.t, mu,    aN, pm_bits(L * aN)), aN)
    };

    var e = challenge(sid, Nj, Ni, aux, C, D, Y, G.encode(X), com, P);

    return {
        A: com.A, Bx: com.Bx, By: com.By,
        E: com.E, S: com.S, F: com.F, T: com.T,
        /* z1..z4 are INTEGERS - reducing them destroys the range property */
        z1: alpha + e * x,
        z2: beta  + e * y,
        z3: gamma + e * m,
        z4: delta + e * mu,
        /* rho, rhoY open D and Y: their inverse is blinded */
        w:  mod(r  * powmod_signed_blind(rho,  e, Nj, rng), Nj),
        wy: mod(rY * powmod_signed_blind(rhoY, e, Ni, rng), Ni)
    };
}

var AFFG_INTS = ['A', 'By', 'E', 'S', 'F', 'T', 'z1', 'z2', 'z3', 'z4', 'w', 'wy'];

/** @return {boolean} */
export function verify_affg(G, pkJ, pkI, aux, C, D, Y, X, proof, opts, sid) {
    require_sid('paillier_affg', sid);
    if (!proof || !proof.Bx) { return false; }
    /* the verifier's parameters, refused if they violate C.1 */
    var P = params(G, pkJ, pkI, opts);
    var i;

    try {
        for (i = 0; i < AFFG_INTS.length; i++) {
            if (typeof proof[AFFG_INTS[i]] !== 'bigint') { return false; }
        }

        var Nj = pkJ.n, Nj2 = Nj * Nj;
        var Ni = pkI.n, Ni2 = Ni * Ni;
        var aN = aux.N;

        /*
         * Steps 1-9: the public data and the commitment must be units in
         * their own moduli. A verifier that lets a non-unit through and
         * relies on the arithmetic to reject it is relying on an accident.
         */
        /* ⚠ unit_in - in range AND coprime. C, D, Y, w and wy were checked
           for gcd only, so a non-canonical encoding (v + N) passed and the
           same proof had a second set of bytes. */
        if (!unit_in(C, Nj2) || !unit_in(D, Nj2) || !unit_in(Y, Ni2)) { return false; }
        if (!unit_in(proof.A, Nj2) || !unit_in(proof.By, Ni2)) { return false; }
        var rp = ['E', 'S', 'F', 'T'];
        for (i = 0; i < rp.length; i++) { if (!unit_in(proof[rp[i]], aN)) { return false; } }
        if (!unit_in(proof.w, Nj) || !unit_in(proof.wy, Ni)) { return false; }

        /* decode() is the prime-order contract - see commons/group.js */
        var Bx = G.decode(proof.Bx);
        if (!Bx) { return false; }

        /*
         * Steps 15-16: THE RANGE CHECKS, WHICH ARE THE PROOF. Everything
         * below holds for a prover using an enormous x or y; these are what
         * make the statement about size, and size is what stops the Paillier
         * modulus wrapping and the share leaking.
         */
        /* z1 in +-2^(ell+eps), z2 in +-2^(ell'+eps) - the paper's sets */
        if (!pm_in(proof.z1, 1n << BigInt(P.ell + P.eps)) ||
            !pm_in(proof.z2, 1n << BigInt(P.ell2 + P.eps))) { return false; }

        var e = challenge(sid, Nj, Ni, aux, C, D, Y, G.encode(X), proof, P);

        /* 10: A (+) (e (*) D) == (z1 (*) C) (+) enc_Nj(z2; w) */
        var lhs1 = mod(proof.A * powmod_signed(D, e, Nj2), Nj2);
        var rhs1 = mod(powmod_signed(C, proof.z1, Nj2) * enc_raw(Nj, Nj2, proof.z2, proof.w), Nj2);
        if (lhs1 !== rhs1) { return false; }

        /* 11: z1 * G == Bx + e * X */
        if (!G.equals(G.mul(mod(proof.z1, G.ORDER), G.GENERATOR),
                      G.add(Bx, G.mul(mod(e, G.ORDER), X)))) { return false; }

        /* 12: By (+) (e (*) Y) == enc_Ni(z2; wy) */
        var lhs3 = mod(proof.By * powmod_signed(Y, e, Ni2), Ni2);
        if (lhs3 !== enc_raw(Ni, Ni2, proof.z2, proof.wy)) { return false; }

        /* 13: s^z1 t^z3 == E * S^e */
        if (mod(powmod_signed(aux.s, proof.z1, aN) *
                powmod_signed(aux.t, proof.z3, aN), aN) !==
            mod(proof.E * powmod_signed(proof.S, e, aN), aN)) { return false; }

        /* 14: s^z2 t^z4 == F * T^e */
        if (mod(powmod_signed(aux.s, proof.z2, aN) *
                powmod_signed(aux.t, proof.z4, aN), aN) !==
            mod(proof.F * powmod_signed(proof.T, e, aN), aN)) { return false; }

        return true;
    } catch (err) {
        return false;
    }
}

/* ---------------- serialisation ---------------- */

export function encode_affg(proof) {
    /* the twelve integers, then the one group element */
    return concat([encode_fields(proof, AFFG_INTS),
                   be16(proof.Bx.length), proof.Bx]);
}

/**
 * @return {object|null} A proof, or null if the encoding is malformed.
 */
export function decode_affg(bytes) {
    var r = decode_fields(bytes, AFFG_INTS);
    if (r === null) { return null; }
    var off = r.next;
    if (off + 2 > bytes.length) { return null; }
    var blen = (bytes[off] << 8) | bytes[off + 1];
    off += 2;
    if (off + blen > bytes.length) { return null; }
    r.fields.Bx = bytes.subarray(off, off + blen);
    return r.fields;
}
