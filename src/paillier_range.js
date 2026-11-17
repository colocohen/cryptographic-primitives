/**
 * Range proof for a Paillier ciphertext  -  CGGMP21 section 5.1
 *
 * Prove that a Paillier ciphertext encrypts a value in a small range, without
 * revealing the value:
 *
 *     "C encrypts some x with |x| < 2^ell, and I know x and the randomness"
 *
 * ================= WHY THIS IS THE CRITICAL PIECE =================
 *
 * Paillier is additively homomorphic over Z_N, where N is around 2^2048. The
 * protocols built on it - threshold ECDSA above all - need the plaintexts to
 * be much smaller than that, around 2^256, because the arithmetic they perform
 * must not wrap.
 *
 * A malicious party who encrypts an enormous value makes the homomorphic sum
 * wrap modulo N, and the wrapped result is something they can predict and the
 * honest party cannot. That is not an abstract concern: THE 2021 TSSHOCK
 * ATTACKS RECOVERED COMPLETE PRIVATE KEYS FROM DEPLOYED THRESHOLD ECDSA
 * IMPLEMENTATIONS, and the flaw in several of them was a range proof that was
 * absent, or present but not actually checked.
 *
 * The proof is what forces every participant to stay inside the range the
 * protocol's security argument assumes.
 *
 * ===================== HOW IT WORKS =====================
 *
 * A Schnorr-style proof over two commitments at once. The prover commits to
 * the value twice - once as a Paillier ciphertext and once as a Ring-Pedersen
 * commitment - and proves the two agree AND that the value is small.
 *
 * CGGMP21 (eprint 2021/060, current revision) Figure 11, section 5.1.1, in
 * the paper's notation; "+-m" is the paper's set of m integers (half-width
 * m/2 - see zk_bytes.pm_half):
 *
 *     witness:   k in +-2^ell, K = (1+N0)^k rho^N0
 *     Prover:    alpha <- +-2^(ell+eps)        mu    <- +-2^ell * Nhat
 *                r     <- Z*_N0                gamma <- +-2^(ell+eps) * Nhat
 *                S = s^k t^mu,  A = (1+N0)^alpha r^N0,  C = s^alpha t^gamma
 *     Verifier:  e <- +-q                                  (q the group order)
 *     Prover:    z1 = alpha + e k,  z2 = r rho^e mod N0,  z3 = gamma + e mu
 *     Check:     z1 in +-2^(ell+eps)
 *                (1+N0)^z1 z2^N0 = A K^e  mod N0^2
 *                s^z1 t^z3      = C S^e  mod Nhat
 *
 * ⚠ THE FIELD NAMES ARE THIS FILE'S, NOT THE FIGURE'S, and kept for the
 *   encoding: S and A as in the figure, D is the figure's C, z1 its z1, z2 its
 *   z3 and w its z2.
 *
 * THE RANGE CHECK ON z1 IS THE PROOF. Everything else establishes that z1 is
 * genuinely gamma + e*x for the x inside C; the bound on |z1| then forces |x|
 * to be small, because gamma is drawn from a range only slightly wider and e
 * is not under the prover's control.
 *
 * THE SLACK IS REAL AND HAS TO BE ACCEPTED. The proof does not establish
 * k in +-2^ell. It establishes k in +-2^(ell+eps) (up to the challenge), because the prover's
 * mask alpha has to be wide enough to hide e*k statistically. A protocol
 * using this must set ell so that the LOOSER bound is still small enough for
 * its arithmetic - CGGMP21 uses (ell, eps) = (kappa, 2 kappa), so at
 * kappa = 256 the honest range is +-2^256 and what is proved is +-2^768.
 * An honest proof fails its own range check only when |alpha| falls outside
 * +-(2^(ell+eps) - q 2^ell), with probability at most q / 2^eps (section
 * 5.1.1); the prover does not retry, as the figure does not.
 *
 * WHOSE PARAMETERS ARE WHOSE, because getting this backwards silently breaks
 * everything: the PAILLIER modulus belongs to the PROVER, and the
 * RING-PEDERSEN parameters belong to the VERIFIER. The soundness rests on the
 * prover not knowing the order of the Ring-Pedersen group; the hiding rests on
 * the verifier not knowing the Paillier factorisation. Both parties must have
 * proved their own parameters well formed first - see ring_pedersen.js.
 */

import { unit_in, mod, powmod_signed, powmod_signed_ct, powmod_signed_blind, random_unit, require_rng } from './commons/primes.js';
import { enc_raw } from './paillier.js';
import { fs_stream, fs_pm, require_sid, encode_fields, decode_fields,
         pm_in, pm_sample, pm_bits, require_pm, cggmp_params } from './commons/zk_bytes.js';

/**
 * Default parameters, from CGGMP21 for a 2048-bit Paillier modulus.
 *
 * ELL IS THE HONEST RANGE and EPS IS THE SLACK. Both are security parameters:
 * a smaller eps makes the proof tighter and the zero-knowledge weaker, since
 * the masking value no longer hides e*x. Do not tune them without reading the
 * paper's Fact D.5.
 */
/*
 * ⭐ THE PARAMETERS COME FROM THE GROUP ORDER, which is now REQUIRED as
 *   opts.order. The challenge is drawn from +-q (Figure 11), so this proof
 *   cannot be built or checked without q; it used to take only ell and draw
 *   e from +-2^ell. Defaults are the paper's (ell, eps, ell') = (kappa,
 *   2 kappa, 5 kappa) with kappa = log q, and every set is checked against
 *   appendix C.1 (zk_bytes.cggmp_params) - which includes log N0 >= ell' +
 *   eps, so the prover's Paillier modulus must be large enough for the
 *   protocol this proof belongs to.
 *
 * ELL and EPS remain exported as the values for a 256-bit group order.
 */
export var ELL = 256;
export var EPS = 512;

function params(pk, opts) {
    var order = opts && opts.order;
    return cggmp_params('paillier_range', order, opts, [pk.n]);
}

/**
 * The Fiat-Shamir challenge, uniform in +-q.
 *
 * EVERY PUBLIC VALUE IS ABSORBED - both moduli, the Ring-Pedersen bases, the
 * ciphertext being proved about, the commitment, and all three of the
 * prover's first-round values. A challenge computed over less than that lets
 * the prover fix the remaining values after seeing it, which is the
 * Fiat-Shamir failure mode that has broken several deployed protocols.
 *
 * `sid` BINDS THE PROOF TO ONE RUN, and is absorbed before anything else; the
 * session identifier is the protocol's to construct, so it arrives as
 * `opts.sid`.
 *
 * v3: e from +-q (v2 drew it from +-2^ell), and q and the parameter set are
 * hashed too. Every v2 input is still here.
 */
function challenge(N0, aux, C, S, A, D, P, sid) {
    var read = fs_stream('cryptographic-primitives/paillier-range/enc/v3', sid,
                         [N0, aux.N, aux.s, aux.t, C, S, A, D,
                          P.q, BigInt(P.ell), BigInt(P.eps)]);
    return fs_pm(read, P.q);
}

/**
 * Prove that `C` encrypts `x` with x in +-2^ell (|x| <= 2^(ell-1)).
 *
 * @param {object} pk    the PROVER's Paillier public key
 * @param {object} aux   the VERIFIER's Ring-Pedersen parameters {N, s, t}
 * @param {bigint} C     the ciphertext
 * @param {bigint} x     the plaintext, in +-2^ell
 * @param {bigint} r     the randomness used to produce C
 * @param {object} opts  {order (REQUIRED), sid (REQUIRED), ell, eps, ell2}
 * @param {function} [rng]  omitted or null draws fresh ones from the platform
 * @return {{S, A, D, z1, z2, w}}
 */
export function prove(pk, aux, C, x, r, rng, opts) {
    var sid = require_sid('paillier_range', opts && opts.sid);
    rng = require_rng('paillier_range.prove', rng);
    var P = params(pk, opts);
    P.q = opts.order;
    var Nh = aux.N;
    var L  = 1n << BigInt(P.ell);              /* the paper's 2^ell */
    var LE = 1n << BigInt(P.ell + P.eps);      /* 2^(ell+eps) */

    require_pm('paillier_range', 'value', x, L);

    /*
     * ⛔ x IS THE WITNESS THIS PROOF EXISTS TO HIDE, and mu, alpha, gamma are
     *   the blinders that hide it. powmod_signed leaks an exponent's Hamming
     *   weight through square-and-multiply AND its sign through a branch, so
     *   every exponent here goes through the constant-time ladder - at the
     *   width zk_bytes.pm_bits derives from the SAME bound the value was
     *   drawn from or checked against, so the two cannot disagree.
     */
    var alpha = pm_sample(LE, rng);
    var mu    = pm_sample(L * Nh, rng);
    var rho   = random_unit(pk.n, rng);
    var gamma = pm_sample(LE * Nh, rng);

    var N2 = pk.n * pk.n;
    var S = mod(powmod_signed_ct(aux.s, x, Nh, pm_bits(L)) *
                powmod_signed_ct(aux.t, mu, Nh, pm_bits(L * Nh)), Nh);
    /* A is a fresh Paillier encryption of alpha; with g = n+1 the exponent
       collapses to 1 + alpha*n, exactly as in paillier.js */
    var A = enc_raw(pk.n, N2, alpha, rho);
    var D = mod(powmod_signed_ct(aux.s, alpha, Nh, pm_bits(LE)) *
                powmod_signed_ct(aux.t, gamma, Nh, pm_bits(LE * Nh)), Nh);

    var e = challenge(pk.n, aux, C, S, A, D, P, sid);

    return {
        S: S, A: A, D: D,
        /* z1 and z2 are INTEGERS, not residues - reducing them modulo
           anything destroys the range property the proof rests on */
        z1: alpha + e * x,
        z2: gamma + e * mu,
        /* e is public, so the exponentiation is variable-time; r opens C,
           so for e < 0 its inverse is blinded (primes.powmod_signed_blind) */
        w: mod(rho * powmod_signed_blind(r, e, pk.n, rng), pk.n)
    };
}

/**
 * @return {boolean}
 *
 * Returns false rather than throwing on every failure mode, because a
 * verifier fed a malformed proof by an adversary should reject it, not crash
 * the process it is running in.
 */
export function verify(pk, aux, C, proof, opts) {
    var sid = require_sid('paillier_range', opts && opts.sid);
    if (!proof) { return false; }
    /* the parameters are the verifier's and are checked here too: a set that
       violates C.1 is refused, not verified against */
    var P = params(pk, opts);
    P.q = opts.order;

    try {
        var N2 = pk.n * pk.n;

        /*
         * THE RANGE CHECK, WHICH IS THE ENTIRE POINT. Every other equation
         * here would pass for a prover using an enormous x; this is the one
         * that does not. Omitting it - or checking it after the algebra and
         * short-circuiting - is precisely the mistake the 2021 attacks
         * exploited.
         */
        /* z1 in +-2^(ell+eps), the paper's set: |z1| <= 2^(ell+eps-1) */
        if (!pm_in(proof.z1, 1n << BigInt(P.ell + P.eps))) { return false; }

        /*
         * Every element in its group, CANONICAL AND A UNIT — the CGGMP24
         * verifier's list: C (the statement) and A in Z*_{N0^2}; S, D in
         * Z*_{N̂}; w in Z*_{N0}. A was not checked at all, and C was taken on
         * trust from the caller.
         */
        if (typeof proof.z1 !== 'bigint' || typeof proof.z2 !== 'bigint') { return false; }
        if (!unit_in(C, N2) || !unit_in(proof.A, N2)) { return false; }
        if (!unit_in(proof.S, aux.N) || !unit_in(proof.D, aux.N)) { return false; }
        if (!unit_in(proof.w, pk.n)) { return false; }

        var e = challenge(pk.n, aux, C, proof.S, proof.A, proof.D, P, sid);

        /* (1+N0)^z1 * w^N0 == C^e * A  mod N0^2 */
        var lhs1 = enc_raw(pk.n, N2, proof.z1, proof.w);
        var rhs1 = mod(powmod_signed(C, e, N2) * proof.A, N2);
        if (lhs1 !== rhs1) { return false; }

        /* s^z1 * t^z2 == S^e * D  mod Nhat */
        var lhs2 = mod(powmod_signed(aux.s, proof.z1, aux.N) *
                       powmod_signed(aux.t, proof.z2, aux.N), aux.N);
        var rhs2 = mod(powmod_signed(proof.S, e, aux.N) * proof.D, aux.N);
        return lhs2 === rhs2;
    } catch (err) {
        return false;
    }
}

/* ---------------- serialisation ---------------- */

var RANGE_INTS = ['S', 'A', 'D', 'z1', 'z2', 'w'];

/**
 * Serialise: every integer sign-tagged and length-prefixed (encode_fields,
 * as affg and log do).
 *
 * ⛔ THIS USED TO PACK z1 AND z2 INTO A FIXED 256 BYTES. z2 is about 2816
 *   bits, so bigint_to_bytes kept the low 2048 and dropped the rest without
 *   a word - an encoding that could not be read back to the proof it came
 *   from. (pk and aux are kept in the signature for compatibility; the
 *   length prefixes make them unnecessary.)
 */
export function encode(proof, pk, aux) {
    return encode_fields(proof, RANGE_INTS);
}

/** @return {object|null} a proof, or null if the encoding is malformed */
export function decode(bytes) {
    var r = decode_fields(bytes, RANGE_INTS);
    if (r === null || r.next !== bytes.length) { return null; }
    return r.fields;
}
