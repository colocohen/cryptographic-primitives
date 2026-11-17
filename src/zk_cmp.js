/**
 * zk_cmp.js - CGGMP21 zero-knowledge proofs: Pi^sch and Pi^fac.
 *
 * Stateless mathematics, and they belong next to their three siblings already in this library:
 * ring_pedersen's prove_params (Pi^prm) and prove_modulus (Pi^mod), and
 * paillier_range (Pi^enc).
 *
 * ⚠ NEITHER PROOF IS COVERED BY A PUBLISHED TEST VECTOR. Both are
 *   RECONSTRUCTED FROM THE PAPER'S STRUCTURE rather than transcribed. FROST
 *   has RFC 9591 Appendix E, which is why frost_codec arrived with 73
 *   assertions against it; CGGMP21 has a paper and several
 *   implementations that publish code rather than values.
 *
 *   SINCE CHECKED against the LFDT-Lockness specification, sections 3.7
 *   (fac) and 3.8 (sch). Both relations match. The comparison found one real
 *   difference in Pi^fac - an extra sigma that verified because it cancelled
 *   on both sides and that the specification does not have - and two missing
 *   domain checks, all since fixed. That is a specification of one
 *   implementation, not a standard, so it is stronger than reading the paper
 *   and weaker than a test vector.
 *
 * ==================== A PROOF ABOUT A STEP IS NOT A CLAIM ABOUT THE RESULT ====================
 *
 * Worth stating once for the whole family, because it caught both sides of
 * this library from opposite directions.
 *
 * Pi^enc, Pi^aff-g and Pi^log* each say something true about one party's
 * step, in isolation. A caller who verifies every proof and finds them all
 * valid has learned that no party cheated on its own contribution - and NOT
 * that the computation came out right. A presigning built on these had every
 * proof pass while the result was wrong, because a step was missing
 * altogether and no proof is about a step that was never taken.
 *
 * The mirror image is Pi^fac carrying a redundant field for two years: every
 * property held, because internal consistency is exactly what a redundant
 * field does not break.
 *
 * So the protocol needs at least one check that speaks about the WHOLE
 * computation - in presigning that is Sum(Delta_i) == delta*G - and no number
 * of correct per-step proofs substitutes for it.
 *
 * ==================== THE RANGE CHECK IS THE PROOF ====================
 *
 * Worth reading before the code, because it is the thing that looks
 * removable and is not.
 *
 * Pi^fac's three algebraic relations hold for a prover who knows ANY
 * factorisation. What makes the statement "N0 has no small factors" is the
 * bound on z1 and z2, and nothing else: e*p cannot hide inside a mask sized
 * to 2^(ell+eps) * sqrt(N0) when p is small.
 *
 * An implementation with the equations and without the bound verifies every
 * honest proof, round-trips every encoding, and proves nothing. That is the
 * shape of half of CVE-2023-33241, where GG18 and GG20 accepted whatever
 * Paillier modulus a peer handed over - so a peer could hand over one it
 * could factor and read everyone else's contributions.
 *
 * The test that catches it goes the other way round: widen eps, and check
 * that a modulus WITH a small factor then PASSES.
 *
 * ==================== sid ====================
 *
 * Every challenge absorbs an opaque byte string first. Without it a proof is
 * valid in any run with the same parameters, so whoever watched one key
 * generation can replay its proofs into the next.
 *
 * The caller supplies the bytes and this file does not interpret them; a
 * protocol puts sid || prover || verifier there, which is protocol state and
 * has no business in a primitives library. Same parameter that
 * ring_pedersen and paillier_range now take, and it defaults to empty.
 */

import { concat, be16 } from './commons/bytes.js';
import { int_bytes, read_int, fs_stream, fs_below, fs_pm, require_sid,
         encode_fields, decode_fields, masks, pm_in, pm_sample, pm_bits, require_pm } from './commons/zk_bytes.js';
import { mod, powmod_signed, powmod_signed_ct, isqrt, gcd, unit_in,
         random_below_biased as random_below, require_rng } from './commons/primes.js';

/*
 * `sid` IS REQUIRED, and omitting it is not the same as passing nothing.
 *
 * An unbound proof verifies in every run with the same statement, so whoever
 * watched one key generation can replay its proofs into the next. A default
 * of "empty" makes that the behaviour a caller gets by forgetting - and this
 * is not a parameter anyone should reach by accident.
 *
 * Passing `new Uint8Array(0)` is still allowed. It is a decision that appears
 * in the caller's own source rather than in its absence.
 */

/* CGGMP21's masking parameters, from the paper. See paillier_range.js on why
   these are not tuning knobs: they are what the simulator argument needs. */
var ELL = 256;
var EPS = 512;
var DEFAULTS = { ell: ELL, eps: EPS };

/*
 * The Fiat-Shamir challenges, each from the set its figure names:
 *
 *     Pi^sch  (Figure 22)   e <- F_q       uniform below q  (zk_bytes.fs_below)
 *     Pi^fac  (Figure 26)   e <- +-2^ell   the paper's set, |e| <= 2^(ell-1)
 *                                          (zk_bytes.fs_pm)
 *
 * `sid` first, then the domain tag, then every public value. A challenge
 * computed over less than the full statement lets the prover fix the
 * remaining values after seeing it - the Fiat-Shamir break, which is total
 * and which looks like working code from every other angle.
 *
 * v3 of both tags: Pi^sch's e was uniform in [0, 2^|q|) - not F_q, and above
 * q a quarter of the time on a 2^k + small order - and Pi^fac's was
 * +-2^ell read as |e| <= 2^ell, twice the paper's set. Every v2 input is
 * still hashed.
 */
function sch_challenge(sid, G, X, A) {
    return fs_below(fs_stream('cryptographic-primitives/cggmp/sch/v3', sid, [G.encode(X), G.encode(A)]), G.ORDER);
}
function fac_challenge(sid, parts, ell) {
    return fs_pm(fs_stream('cryptographic-primitives/cggmp/fac/v3', sid, parts.concat([BigInt(ell)])), 1n << BigInt(ell));
}

function mulmod(a, b, m) { return mod(mod(a, m) * mod(b, m), m); }


/* ==================== Pi^sch: knowledge of a discrete log ==================== */

/**
 * Prove knowledge of x with X = x*G.
 *
 * THE ROGUE-KEY DEFENCE. In key generation the group key is the sum of every
 * party's contribution, so whoever publishes last can choose theirs as a
 * function of everyone else's and subtract the others out. Proving knowledge
 * of the discrete log of what you published makes that impossible: you
 * cannot prove knowledge of a value you built by subtraction.
 *
 * @param {object}     G     a prime-order group, see commons/group.js
 * @param {object}     X     the public point
 * @param {bigint}     x     the witness
 * @param {function}   [rng] omitted or null draws fresh ones from the platform
 * @param {Uint8Array} [sid] binds the proof to one run
 * @return {{A: Uint8Array, z: bigint}}
 */
export function prove_sch(G, X, x, rng, sid) {
    require_sid('zk_cmp', sid);
    rng = require_rng('zk_cmp.prove_sch', rng);
    var alpha = random_below(G.ORDER, rng);
    var A = G.base_mul(alpha);
    var e = sch_challenge(sid, G, X, A);
    return { A: G.encode(A), z: mod(alpha + e * x, G.ORDER) };
}

/** @return {boolean} */
export function verify_sch(G, X, proof, sid) {
    require_sid('zk_cmp', sid);
    if (!proof || !proof.A) { return false; }

    /*
     * decode() is the prime-order contract - on the curve, not the identity,
     * in the subgroup. A commitment of small order here would let the prover
     * satisfy the relation for a statement it does not know, which is exactly
     * why commons/group.js makes that check part of decoding rather than
     * something each caller remembers.
     */
    var A = G.decode(proof.A);
    if (!A) { return false; }
    if (typeof proof.z !== 'bigint' || proof.z < 0n || proof.z >= G.ORDER) { return false; }

    var e = sch_challenge(sid, G, X, A);

    /* z*G == A + e*X */
    return G.equals(G.base_mul(proof.z), G.add(A, G.mul_vartime(mod(e, G.ORDER), X)));
}

/* ==================== Pi^fac: N0 has no small factors ==================== */

/**
 * Prove that both factors of N0 are large, without revealing them.
 *
 * @param {bigint}     N0    the modulus being proved about
 * @param {bigint}     p,q   its factorisation - the witness
 * @param {object}     aux   another party's Ring-Pedersen parameters {N,s,t}
 * @param {function}   rng
 * @param {object}     [opts]  ell, eps
 * @param {Uint8Array} [sid]
 */
/**
 * ⚠ WHOSE ring-Pedersen PARAMETERS GO IN `aux`?
 *
 * In CGGMP21 this proof commits under the VERIFIER's parameters, and that is
 * what makes it zero-knowledge against that verifier: a prover who chose the
 * parameters could open the commitments to anything.
 *
 * ⛔ A ONE-SIDED SETUP HAS NO VERIFIER YET, so a server generating parameters
 *   for future clients commits under its OWN N-hat. That is a real
 *   difference from the CMP usage and it LOOKS LIKE A COPY-PASTE ERROR, so
 *   it is written down: the soundness still holds - the prover cannot forge
 *   a factorisation - but the zero-knowledge is against nobody in
 *   particular, and a client must not treat the server's own-parameter proof
 *   as if it had been made under the client's.
 *
 * `aux` is the ring-Pedersen triple { N, s, t } - NOT a seed, and not the
 * Paillier modulus.
 *
 * rng omitted or null draws fresh ones from the platform.
 */
export function prove_fac(N0, p, q, aux, rng, opts, sid) {
    require_sid('zk_cmp', sid);
    rng = require_rng('zk_cmp.prove_fac', rng);
    var mk = masks(opts, DEFAULTS), ell = mk.ell, eps = mk.eps;
    var N = aux.N, s = aux.s, t = aux.t;

    if (p * q !== N0) { throw new Error('zk_cmp: witness does not factor the statement'); }

    /*
     * ⚠ THE SAME BOUND THE VERIFIER APPLIES, CHECKED HERE TOO.
     *
     * verify_fac refuses any N0 below 2^(4*ell), because the statement -
     * "both factors exceed the bound" - is vacuous for a modulus too small
     * to have two such factors. With the default ell = 256 that means N0
     * must exceed 2^1024, so a 512- or 1024-bit modulus is refused.
     *
     * ⛔ AND IT USED TO BE REFUSED SILENTLY. prove_fac produced a proof
     *   happily and verify_fac returned false with nothing to say why,
     *   which reads as a broken proof rather than a modulus below the floor.
     *   A caller diagnosing it lands on the options - and shrinking ell
     *   until it passes WEAKENS THE PROOF, which is the opposite of a fix.
     */
    if (N0 <= (1n << BigInt(4 * ell))) {
        throw new Error('zk_cmp: prove_fac needs a modulus above 2^' +
                        (4 * ell) + ' for ell = ' + ell + ' - the statement ' +
                        'is vacuous below it. Use a larger modulus rather ' +
                        'than a smaller ell, which weakens the proof.');
    }

    /*
     * Figure 26, every "+-m" the paper's set of m integers (zk_bytes.pm_half):
     *
     *     p, q < +-sqrt(N0) 2^ell                      the witness
     *     alpha, beta <- +-2^(ell+eps) sqrt(N0)        mu, nu <- +-2^ell Nhat
     *     r <- +-2^(ell+eps) N0 Nhat                   x, y   <- +-2^(ell+eps) Nhat
     *
     * Each was twice the paper's width before (|v| < m rather than m/2).
     * sqrt(N0) is the integer square root - see primes.isqrt.
     */
    var root = isqrt(N0);
    var B_pq = (1n << BigInt(ell)) * root;         /* the witness's bound   */
    var B_ae = (1n << BigInt(ell + eps)) * root;   /* masks for the factors  */
    var B_l  = (1n << BigInt(ell)) * N;            /* masks for the openings */
    var B_le = (1n << BigInt(ell + eps)) * N;
    var B_r  = (1n << BigInt(ell + eps)) * N0 * N;

    require_pm('zk_cmp', 'p', p, B_pq);
    require_pm('zk_cmp', 'q', q, B_pq);

    var alpha = pm_sample(B_ae, rng);
    var beta  = pm_sample(B_ae, rng);
    var mu    = pm_sample(B_l,  rng);
    var nu    = pm_sample(B_l,  rng);
    var r     = pm_sample(B_r,  rng);
    var x     = pm_sample(B_le, rng);
    var y     = pm_sample(B_le, rng);

    /*
     * ⛔⛔ EVERY EXPONENT HERE IS SECRET, AND TWO OF THEM ARE THE PRIME
     *   FACTORS OF N0. powmod_signed leaks an exponent's Hamming weight
     *   through square-and-multiply AND its sign through a branch, so the
     *   variable-time version leaked p and q through timing - which is to
     *   say it leaked the factorisation this proof exists to attest WITHOUT
     *   revealing. Measured on the primitive: a factor of 2.07 on weight and
     *   1.23 on sign, both flattened to within noise by the _ct version.
     *
     * ⚠ THE WIDTHS ARE PASSED EXPLICITLY AND MUST BE. The blinders are drawn
     *   from B_l, B_le and B_r, which are deliberately much WIDER than N so
     *   the openings statistically hide the witness. powmod_ct walks exactly
     *   the width it is given, so letting it default to N's width truncates
     *   them and produces a proof that fails to verify with nothing pointing
     *   at the cause. The bounds are public, so declaring their widths leaks
     *   nothing. powmod_ct now throws rather than truncating.
     *
     * ⭐ verify_fac BELOW DELIBERATELY KEEPS THE VARIABLE-TIME VERSION. Its
     *   exponents are proof.z1, proof.w1 and the Fiat-Shamir challenge - all
     *   of them arrived on the wire.
     */
    /* every ladder width from the bound its exponent was drawn from or checked against */
    var w_pq = pm_bits(B_pq), w_ae = pm_bits(B_ae), w_l = pm_bits(B_l),
        w_le = pm_bits(B_le), w_r = pm_bits(B_r);

    var P  = mulmod(powmod_signed_ct(s, p, N, w_pq),     powmod_signed_ct(t, mu, N, w_l),  N);
    var Q  = mulmod(powmod_signed_ct(s, q, N, w_pq),     powmod_signed_ct(t, nu, N, w_l),  N);
    var A  = mulmod(powmod_signed_ct(s, alpha, N, w_ae), powmod_signed_ct(t, x,  N, w_le), N);
    var Bc = mulmod(powmod_signed_ct(s, beta, N, w_ae),  powmod_signed_ct(t, y,  N, w_le), N);
    var T  = mulmod(powmod_signed_ct(Q, alpha, N, w_ae), powmod_signed_ct(t, r,  N, w_r),  N);

    var e = fac_challenge(sid, [N0, N, s, t, P, Q, A, Bc, T], ell);

    /*
     * v = r - e*nu*p. The subtraction is what makes the third relation close:
     * Q already carries nu in its t-exponent, so raising it to
     * z1 = alpha + e*p drags e*nu*p in with it, and v has to cancel that.
     *
     * AN EARLIER VERSION CARRIED AN EXTRA sigma, committing to
     * R = s^N0 * t^sigma and adding e*sigma to v. It verified, because the
     * t^(e*sigma) appeared on both sides and cancelled - but it put a value
     * on the wire that does nothing, that no verifier can check, and that the
     * specification does not have. Removed after comparing against section
     * 3.7 of the LFDT specification.
     */
    return {
        P: P, Q: Q, A: A, B: Bc, T: T,
        z1: alpha + e * p,
        z2: beta  + e * q,
        w1: x     + e * mu,
        w2: y     + e * nu,
        v:  r     - e * nu * p
    };
}

var FAC_FIELDS = ['P', 'Q', 'A', 'B', 'T', 'z1', 'z2', 'w1', 'w2', 'v'];

/** @return {boolean} */
export function verify_fac(N0, proof, aux, opts, sid) {
    require_sid('zk_cmp', sid);
    var mk = masks(opts, DEFAULTS), ell = mk.ell, eps = mk.eps;
    var N = aux.N, s = aux.s, t = aux.t;
    var i;

    /*
     * Shape first. Every one of these came from a peer, and a verifier that
     * reduces a hostile input into range rather than rejecting it is a
     * verifier that accepts a proof of a different statement.
     */
    if (!proof) { return false; }
    for (i = 0; i < FAC_FIELDS.length; i++) {
        if (typeof proof[FAC_FIELDS[i]] !== 'bigint') { return false; }
    }
    /* the commitments must be UNITS mod N, not merely in range - the
       specification asks for Z*_Nj, and a non-unit satisfies the relations
       below in degenerate ways */
    var commitments = ['P', 'Q', 'A', 'B', 'T'];
    for (i = 0; i < commitments.length; i++) {
        if (!unit_in(proof[commitments[i]], N)) { return false; }
    }

    /* the statement is only meaningful for a modulus large enough to have
       two factors above the bound - specification section 3.7, step 6 */
    if (N0 <= (1n << BigInt(4 * ell))) { return false; }
    /*
     * ⛔ AND LARGE ENOUGH FOR THE RANGE BOUND TO MEAN ANYTHING. z1, z2 are
     *    bounded by 2^(ell+eps)·√N0; below N0 ≈ 2^(2(ell+eps)) that bound
     *    no longer separates a small factor from a large one, and a 1088-bit
     *    N with a 32-bit factor passed. This is the CVE-2023-33241 class.
     */
    if (!(opts && opts.allowSmall === true) &&
        N0.toString(2).length < 2 * (ell + eps)) { return false; }

    var e = fac_challenge(sid, [N0, N, s, t, proof.P, proof.Q, proof.A, proof.B,
                                proof.T], ell);

    /*
     * THE RANGE CHECK IS THE PROOF. The three relations below hold for a
     * prover who knows any factorisation; what makes the statement "no small
     * factors" is that z1 and z2 stay inside 2^(ell+eps)*sqrt(N0), which they
     * cannot if a factor is small enough for e*p to overflow the mask.
     * Dropping this and keeping the equations proves nothing - see the header.
     */
    /* z1, z2 in +-sqrt(N0) 2^(ell+eps) - the paper's set, half-width
       sqrt(N0) 2^(ell+eps-1) */
    var bound = (1n << BigInt(ell + eps)) * isqrt(N0);
    if (!pm_in(proof.z1, bound)) { return false; }
    if (!pm_in(proof.z2, bound)) { return false; }

    /* s^z1 * t^w1 == A * P^e */
    if (mulmod(powmod_signed(s, proof.z1, N), powmod_signed(t, proof.w1, N), N) !==
        mulmod(proof.A, powmod_signed(proof.P, e, N), N)) { return false; }

    /* s^z2 * t^w2 == B * Q^e */
    if (mulmod(powmod_signed(s, proof.z2, N), powmod_signed(t, proof.w2, N), N) !==
        mulmod(proof.B, powmod_signed(proof.Q, e, N), N)) { return false; }

    /*
     * Q^z1 * t^v == T * R^e, where R = s^N0 * t^sigma.
     *
     * The relation that ties the two factors together. The first two say "I
     * opened P and Q to something"; this says the two somethings multiply to
     * N0, because Q already carries q in its exponent and raising it to
     * z1 = alpha + e*p produces e*p*q = e*N0 in the s-exponent.
     */
    if (mulmod(powmod_signed(proof.Q, proof.z1, N), powmod_signed(t, proof.v, N), N) !==
        mulmod(proof.T, powmod_signed(s, N0 * e, N), N)) { return false; }

    return true;
}

/* ---------------- serialisation ---------------- */


export function encode_sch(proof) {
    return concat([be16(proof.A.length), proof.A, int_bytes(proof.z)]);
}

/**
 * @return {object|null} A proof, or null if the encoding is malformed.
 */
export function decode_sch(bytes) {
    if (!bytes || bytes.length < 2) { return null; }
    var alen = (bytes[0] << 8) | bytes[1];
    if (bytes.length < 2 + alen + 3) { return null; }
    var z = read_int(bytes, 2 + alen);
    if (!z || z.next !== bytes.length) { return null; }
    return { A: bytes.subarray(2, 2 + alen), z: z.value };
}

export function encode_fac(proof) {
    return encode_fields(proof, FAC_FIELDS);
}

export function decode_fac(bytes) {
    var r = decode_fields(bytes, FAC_FIELDS);
    return r === null ? null : r.fields;
}
