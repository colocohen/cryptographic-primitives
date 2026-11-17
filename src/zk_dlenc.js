/**
 * zk_dlenc.js - Pi_dlenc, the ENCRYPTED DISCRETE LOG proof.
 *
 * eprint 2024/1950 section 5.5, Protocol 7.
 *
 * ==================== WHAT IT PROVES ====================
 *
 * That one secret x sits, consistently, in THREE places at once:
 *
 *     X = g^x                            a group element
 *     E = enc_N(x; rho^lambda)           a Paillier ciphertext
 *     P = u1^x u2^lambda v^mu  mod M     a ring-Pedersen commitment
 *
 * Any two of those could be proved separately and would say nothing useful:
 * the point is that the SAME x is behind all three. A protocol moving a
 * value between a group and a homomorphic ciphertext needs exactly this -
 * without it a party sends a ciphertext of one thing and a group element of
 * another, and nothing notices.
 *
 * ==================== ⚠ x AND lambda MAY BE NEGATIVE ====================
 *
 * The statement declares x in +/-2^n_x and lambda in +/-2^n_lambda, so both
 * are negative about half the time when a protocol above samples them that
 * way - Protocol 2 of the same paper does exactly that.
 *
 * ⛔ THE CALLER MUST BUILD THE COMMITMENTS WITH A SIGNED EXPONENTIATION.
 *   u1^x for negative x is the modular INVERSE. It is NOT u1^(x mod M),
 *   which is a different group element entirely - reducing an exponent
 *   modulo the MODULUS is meaningless, and only reduction modulo the ORDER
 *   would be sound, which the caller does not know.
 *
 *   commons/zk_bytes.js exports `signed_pow` for this. A P built the other
 *   way matches no proof, and the failure presents as a bug in the proof
 *   rather than in the commitment.
 *
 * ⚠ Paillier is the exception that makes this easy to get half-right:
 *   plaintexts live mod N, so enc_N(x) with x reduced mod N IS correct for
 *   negative x. The group is fine too, reduced mod the order. It is the
 *   ring-Pedersen commitment alone that breaks - so two of the three
 *   equations can look right while the third does not.
 *
 * ==================== THREE BASES, NOT TWO ====================
 *
 * ⚠ ring_pedersen.commit uses TWO bases, s^x t^r. This needs THREE, and they
 *   arrive as arguments rather than from a keygen result.
 *
 *   That is deliberate. SampleDF in the same paper outputs (M, v, u1, u2) -
 *   the three-base form is its natural output - while this library's
 *   keygen_rough returns the two-base { N, s, t }. Forcing one shape into
 *   the other would be adapting in the wrong direction, so the caller
 *   supplies whatever its parameter generator produced.
 *
 * ==================== ⭐ NO 2^ell0 HERE ====================
 *
 * Unlike Pi_df*, this does not rest on the order of a cheating subgroup. The
 * challenge is +/-2^ell and Claim 5.17 gives special soundness with a real
 * extractor. What it DOES depend on is N having no small factors, which is
 * what zk_cmp.prove_fac establishes - and that already exists here.
 *
 * ==================== ⚠ WHAT THE PAPER OMITS ====================
 *
 * Proposition 5.16 states (2^-(nu-2))-HVZK and says the proof "is similar to
 * Proposition 5.5 and is omitted from the text". The zero-knowledge argument
 * is NOT written out for this protocol. That is a gap in the source, and it
 * is recorded rather than assumed closed.
 *
 * ⛔ NO EXTERNAL ORACLE.
 */

import { require_rng, mod, in_range } from './commons/primes.js';
/*
 * `cpow` is zk_bytes.prover_pow: constant-time signed exponentiation for the
 * PROVER, whose exponents are secret masks, falling back to the variable-time
 * signed_pow only for a non-invertible (public) base. It was defined here and
 * again, identically, in the sibling proof.
 */
import { require_sid, signed_pow as spow, signed_mask as signed,
         paillier_enc_nth as enc, prover_pow as cpow, sizes_tag as sizes_tag_nu,
         fs_stream, fs_signed } from './commons/zk_bytes.js';

/** Statistical slack - the paper's nu. */
var NU = 96;

/**
 * @param {object} pub  { G, g, X, N, E, rho, M, u1, u2, v, P }
 * @param {object} sec  { x, lambda, mu }
 * @param {object} sizes { n_x, n_lambda, ell }
 */
export function prove_dlenc(pub, sec, sizes, rng, sid) {
    require_sid('zk_dlenc', sid);
    rng = require_rng('prove_dlenc', rng);

    var NUs = sizes.nu || NU, eps = sizes.ell + NUs;
    var N2 = pub.N * pub.N;
    var ord = pub.G.ORDER;

    /*
     * ⚠ EACH MASK MUST BE eps BITS LONGER THAN WHAT IT HIDES, because it has
     *   to cover e*value and e is ell bits.
     *
     *   A mask sized too small STILL VERIFIES for an honest prover: every
     *   equation holds and the only thing lost is the hiding, which no
     *   positive test can see. Same trap as the alpha bound in Pi_df*.
     */
    var alpha = signed(1n << BigInt(sizes.n_x + eps), rng);
    var lamp  = signed(1n << BigInt(sizes.n_lambda + eps), rng);
    var mup   = signed(pub.M * (1n << BigInt(NUs + eps)), rng);

    var A = pub.G.mul(((alpha % ord) + ord) % ord, pub.g);

    var wA = sizes.n_x + eps, wL = sizes.n_lambda + eps,
        wM = pub.M.toString(2).length + NUs + eps;
    var B = (cpow(pub.u1, alpha, pub.M, wA) *
             cpow(pub.u2, lamp, pub.M, wL) % pub.M) *
            cpow(pub.v, mup, pub.M, wM) % pub.M;

    var rmask = cpow(pub.rho, lamp, N2, wL);
    if (rmask === null) { throw new Error('zk_dlenc: rho is not invertible mod N^2'); }
    var D = enc(pub.N, alpha, rmask);
    if (D === null) { throw new Error('zk_dlenc: encryption failed'); }

    var e = challenge(pub, A, B, D, sid, sizes.ell, sizes);

    /*
     * z = mask + e*value, OVER THE INTEGERS. Not reduced - the verifier does
     * not know the orders involved, and a reduced z would not satisfy the
     * ring-Pedersen equation.
     */
    return {
        A: pub.G.encode(A), B: B, D: D,
        z1: alpha + e * sec.x,
        z2: lamp + e * sec.lambda,
        z3: mup + e * sec.mu
    };
}

/**
 * @return {boolean}
 *
 * ⭐ THREE EQUATIONS, EACH BINDING A DIFFERENT VARIABLE. Measured: a wrong
 *   z1 fails all three, a wrong z2 fails two, a wrong z3 fails one. A
 *   positive run alone would not distinguish three equations from one
 *   equation written three times.
 */
export function verify_dlenc(pub, proof, sizes, sid) {
    require_sid('zk_dlenc', sid);
    if (!proof || typeof proof.z1 !== 'bigint') { return false; }

    var NUs = sizes.nu || NU, eps = sizes.ell + NUs;
    var N2 = pub.N * pub.N;
    var ord = pub.G.ORDER;

    /*
     * ⚠ THE RANGE CHECK. Protocol 7 has it where Protocol 9 does not, and it
     *   is what stops a prover using a value far outside the claimed range -
     *   which is the whole content of a range-bounded statement.
     */
    var b1 = 1n << BigInt(sizes.n_x + eps);
    var b2 = 1n << BigInt(sizes.n_lambda + eps);
    if (!in_range(proof.z1, b1)) { return false; }
    if (!in_range(proof.z2, b2)) { return false; }
    /* ⚠ a SIZE CAP on z3 (not range-checked by Protocol 7): one bit above honest */
    if (typeof proof.z3 !== 'bigint') { return false; }
    var b3 = pub.M * (1n << BigInt(NUs + eps + 1));
    if (!in_range(proof.z3, b3)) { return false; }

    var A = pub.G.decode(proof.A);
    if (!A) { return false; }

    var e = challenge(pub, A, proof.B, proof.D, sid, sizes.ell, sizes);
    var en = ((e % ord) + ord) % ord;

    /* 1. g^z1 = A * X^e, in the group */
    var zn = ((proof.z1 % ord) + ord) % ord;
    if (!pub.G.equals(pub.G.mul_vartime(zn, pub.g),
                      pub.G.add(A, pub.G.mul_vartime(en, pub.X)))) { return false; }

    /* 2. u1^z1 u2^z2 v^z3 = B * P^e, mod M */
    var l1 = spow(pub.u1, proof.z1, pub.M);
    var l2 = spow(pub.u2, proof.z2, pub.M);
    var l3 = spow(pub.v, proof.z3, pub.M);
    var pe = spow(pub.P, e, pub.M);
    if (l1 === null || l2 === null || l3 === null || pe === null) { return false; }
    if ((l1 * l2 % pub.M) * l3 % pub.M !== (proof.B % pub.M) * pe % pub.M) {
        return false;
    }

    /* 3. enc_N(z1; rho^z2) = D * E^e, mod N^2 */
    var r = spow(pub.rho, proof.z2, N2);
    if (r === null) { return false; }
    var lhs = enc(pub.N, proof.z1, r);
    var ee = spow(pub.E, e, N2);
    if (lhs === null || ee === null) { return false; }
    return lhs === (proof.D % N2) * ee % N2;
}

/**
 * ⚠ DERIVED FROM A, B AND D, AFTER THEY ARE FIXED. If e could be known
 *   first, a prover could solve for commitments that pass without knowing x.
 */
export function challenge(pub, A, B, D, sid, ell, sizes) {
    var N2 = pub.N * pub.N, M = pub.M;
    /*
     * v3: zk_bytes.fs_stream, every value reduced into its modulus as v2's
     * mod_bytes did - EXCEPT the moduli themselves. v2 hashed
     * mod_bytes(N, N) and mod_bytes(M, M), which is N mod N = 0: a run of zero
     * bytes as wide as N, so the transcript bound the moduli' WIDTHS and not
     * their values. They go in whole now. The challenge is drawn
     * from +/-2^ell with a sign independent of the magnitude, and any ell -
     * v2 took one sha256 digest, capped ell at 256 without a word and, at 256,
     * read the sign from the magnitude's own lowest bit.
     */
    var read = fs_stream('cryptographic-primitives/dlenc/v3', sid, [
        pub.G.encode(pub.g), pub.G.encode(pub.X),
        pub.N, mod(pub.E, N2), mod(pub.rho, N2),
        M, mod(pub.u1, M), mod(pub.u2, M), mod(pub.v, M), mod(pub.P, M),
        sizes_tag(sizes),
        pub.G.encode(A), mod(B, M), mod(D, N2)
    ]);
    return fs_signed(read, ell);
}

/*
 * ⭐ EVERY PUBLIC INPUT GOES INTO THE CHALLENGE (v2), including the parameters
 *   the verifier itself chose and the declared ranges - see
 *   zk_bytes.sizes_tag. The encoder, the prover's exponentiation and the
 *   digest-to-challenge step were byte-for-byte copies of the ones in
 *   zk_sig.js and now live in commons/zk_bytes.js.
 */
function sizes_tag(sizes) { return sizes_tag_nu(sizes, NU); }
