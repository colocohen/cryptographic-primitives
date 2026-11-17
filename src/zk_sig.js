/**
 * zk_sig.js - Pi_sig, the WELL-FORMED SIGNATURE proof.
 *
 * eprint 2024/1950 section 5.3, Protocol 6.
 *
 * ==================== 🔴 READ THIS BEFORE USING IT ====================
 *
 * ⛔ THE EXTRACTABILITY OF THIS PROOF IS ARGUED IN THE GENERIC GROUP MODEL.
 *
 *   Section 5.3.2 is titled "Partial Straight-Line Extractability of Pi_sig
 *   in the GGM". Every other proof in this library - Pi_fac, Pi_mod,
 *   Pi_dlog, Pi_dlenc, and the CMP proofs - reduces to a standard
 *   assumption. This one does not, and it is the only one.
 *
 *   That is not a flaw in the protocol, which is an ordinary Sigma protocol,
 *   and the SOUNDNESS in Proposition 5.9 is standard with no 2^ell0 term.
 *   The GGM appears only in the straight-line extractability that the
 *   one-shot security proof of the whole scheme needs. The two claims are
 *   separate and are kept separate here.
 *
 *   But the GGM is a model in which proofs have been correct and
 *   implementations have been broken. So: not "this is proven", but "this is
 *   proven in the GGM, which is weaker than everything else here".
 *
 * ==================== WHAT IT PROVES ====================
 *
 * That a ciphertext was built FROM ANOTHER CIPHERTEXT:
 *
 *     S = enc_N(a; rho^lambda0) * E^b   mod N^2
 *
 * which is the shape a signature share takes - an encrypted `a`, scaled by
 * the counterparty's ciphertext E raised to `b`. The prover knows
 * (a, b, lambda0) and shows S is well-formed without revealing them.
 *
 * Pi_dlenc proves a ciphertext encrypts a discrete log; this proves a
 * ciphertext is a specific FUNCTION of another one, which is a different
 * statement and needs its own proof.
 *
 * ==================== ⚠ THREE GROUP GENERATORS ====================
 *
 * U-tilde = g^a h^b f^gamma is a Pedersen commitment to the PAIR (a, b) in
 * the group.
 *
 * ⛔ h AND f MUST BE INDEPENDENT OF g AND OF EACH OTHER. If anyone knows
 *   log_g(h), the commitment stops binding: they can open U-tilde to a
 *   different (a, b) and this proof will accept it.
 *
 * ⚠ THE PAPER DOES NOT SAY HOW THEY ARE GENERATED. That is a gap in the
 *   source and it is marked rather than filled by guessing - the same shape
 *   as the Prime_1 question in the tough-primes work, which took a
 *   measurement rather than an argument to settle.
 *
 *   `independent_generators` below derives them by hash-to-curve on distinct
 *   domain separators, which is the standard construction and gives nobody
 *   the discrete logs. ⛔ DERIVING THEM BY SCALAR MULTIPLICATION OF g WOULD
 *   SILENTLY DESTROY THE COMMITMENT - every equation would still verify.
 *
 * ⛔ NO EXTERNAL ORACLE, and see the GGM note above.
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
import { ascii } from './commons/bytes.js';

/** Statistical slack - the paper's nu. */
var NU = 96;

/*
 * ⭐ ON HS_0 : G -> F_q^2, WHICH APPENDIX C NEEDS.
 *
 * Nothing new is exported for it, because commons/h2c.js already has it:
 *
 *     hash_to_field(G.encode(P), 2, dst, q, 1, 48, expand)
 *
 * returns exactly two independent elements of F_q, and it is RFC 9380's
 * construction rather than one invented here - which matters, because a
 * hash-to-field written for one protocol is the kind of thing that gets
 * subtly reused with the wrong expansion length.
 *
 * ⚠ THE `challenge` FUNCTIONS IN THIS FILE AND IN zk_dlenc.js ARE NOT THAT.
 *   They are Fiat-Shamir transcripts - they bind a specific statement and
 *   are deliberately protocol-specific. Reaching for one of them where a
 *   general hash-to-field is meant would tie an unrelated protocol to this
 *   one's transcript layout.
 *
 * So: use hash_to_field with count = 2, and pass a domain separator the
 * caller owns.
 */

/**
 * Two generators independent of G.GENERATOR, for the (a, b) commitment.
 *
 * ⚠ NOBODY MAY KNOW THE DISCRETE LOGS BETWEEN THESE. Hash-to-curve on
 *   separate domain strings is what guarantees that: the result is a group
 *   element whose relation to g nobody chose. A caller that substitutes
 *   k*g for h has a commitment that opens to anything.
 */
export function independent_generators(G, label) {
    if (typeof G.hash !== 'function') {
        throw new TypeError('zk_sig: the group must provide hash-to-curve - ' +
                            'h and f cannot be derived any other way without ' +
                            'someone learning a discrete log');
    }
    var tag = label || new Uint8Array(0);
    return {
        h: G.hash(tag, ascii('cryptographic-primitives/sig/v1/h')),
        f: G.hash(tag, ascii('cryptographic-primitives/sig/v1/f'))
    };
}

/**
 * @param {object} pub
 *        { G, g, h, f, U, N, E, S, rho, M, s1, s2, t, P }
 * @param {object} sec  { a, b, lambda0, gamma, mu }
 * @param {object} sizes { n_a, n_b, n_lambda0, n_trho, ell }
 */
export function prove_sig(pub, sec, sizes, rng, sid) {
    require_sid('zk_sig', sid);
    rng = require_rng('prove_sig', rng);

    var NUs = sizes.nu || NU, eps = sizes.ell + NUs;
    var N2 = pub.N * pub.N;
    var q = pub.G.ORDER;

    /*
     * ⚠ EACH MASK IS eps BITS BEYOND WHAT IT HIDES, because it must cover
     *   e*value and e is ell bits. Undersized masks still verify - every
     *   equation holds and only the hiding is gone, which no positive test
     *   can see.
     *
     *   gamma' is the exception: it lives in F_q, so it is a full-range
     *   scalar rather than a widened mask.
     */
    var alpha = signed(1n << BigInt(sizes.n_a + eps), rng);
    var beta  = signed(1n << BigInt(sizes.n_b + eps), rng);
    var gammp = pub.G.random_scalar(rng);
    var mup   = signed(1n << BigInt(sizes.n_trho + eps), rng);
    var lamp  = signed(1n << BigInt(sizes.n_lambda0 + eps), rng);

    /* V-tilde = g^alpha h^beta f^gamma' */
    var an = ((alpha % q) + q) % q, bn = ((beta % q) + q) % q;
    var V = pub.G.add(pub.G.add(pub.G.mul(an, pub.g), pub.G.mul(bn, pub.h)),
                      pub.G.mul(gammp, pub.f));

    /* B-tilde = s1^alpha s2^beta t^mu' mod M */
    var wA = sizes.n_a + eps, wB = sizes.n_b + eps,
        wM = sizes.n_trho + eps, wL = sizes.n_lambda0 + eps;
    var B = (cpow(pub.s1, alpha, pub.M, wA) * cpow(pub.s2, beta, pub.M, wB) % pub.M) *
            cpow(pub.t, mup, pub.M, wM) % pub.M;

    /* D = enc_N(alpha; rho^lambda') * E^beta mod N^2 */
    var rmask = cpow(pub.rho, lamp, N2, wL);
    if (rmask === null) { throw new Error('zk_sig: rho is not invertible mod N^2'); }
    var d0 = enc(pub.N, alpha, rmask);
    var eb = cpow(pub.E, beta, N2, wB);
    if (d0 === null || eb === null) { throw new Error('zk_sig: E is not invertible'); }
    var D = (d0 * eb) % N2;

    var e = challenge(pub, V, B, D, sid, sizes.ell, sizes);
    var eq = ((e % q) + q) % q;

    return {
        V: pub.G.encode(V), B: B, D: D,
        z1: alpha + e * sec.a,
        z2: beta + e * sec.b,
        /* ⭐ w0 IS REDUCED mod q and the rest are not - gamma lives in the
           group's scalar field, everything else over the integers. */
        w0: (gammp + eq * (sec.gamma % q)) % q,
        w1: mup + e * sec.mu,
        w2: lamp + e * sec.lambda0
    };
}

/**
 * @return {boolean}
 *
 * ⭐ FIVE RESPONSES ACROSS THREE EQUATIONS, and the split is measurable:
 *   z1 and z2 appear in all three, w0 only in the group equation, w1 only in
 *   the ring-Pedersen one, w2 only in the Paillier one. Corrupting each in
 *   turn must break 3, 3, 1, 1, 1 - and an honest proof must break 0. If any
 *   of the last three reads 0 or 2, a step was misread.
 */
export function verify_sig(pub, proof, sizes, sid) {
    require_sid('zk_sig', sid);
    if (!proof || typeof proof.z1 !== 'bigint') { return false; }

    var NUs = sizes.nu || NU, eps = sizes.ell + NUs;
    var N2 = pub.N * pub.N;
    var q = pub.G.ORDER;

    /* the range check, which Protocol 6 has */
    var b1 = 1n << BigInt(sizes.n_a + eps);
    var b2 = 1n << BigInt(sizes.n_b + eps);
    if (!in_range(proof.z1, b1)) { return false; }
    if (!in_range(proof.z2, b2)) { return false; }
    /*
     * ⚠ SIZE CAPS on the responses Protocol 6 does not range-check: not for
     *   soundness, so that a prover cannot make the verifier exponentiate by
     *   megabit-long w1, w2 (a denial of service found in review). The caps
     *   are one bit above what an honest prover can produce.
     */
    if (typeof proof.w0 !== 'bigint' || typeof proof.w1 !== 'bigint' || typeof proof.w2 !== 'bigint') { return false; }
    var c1 = 1n << BigInt(sizes.n_trho + eps + 1), c2c = 1n << BigInt(sizes.n_lambda0 + eps + 1);
    if (!in_range(proof.w1, c1) || !in_range(proof.w2, c2c)) { return false; }
    if (proof.w0 < 0n || proof.w0 >= q) { return false; }

    var V = pub.G.decode(proof.V);
    if (!V) { return false; }

    var e = challenge(pub, V, proof.B, proof.D, sid, sizes.ell, sizes);
    var eq = ((e % q) + q) % q;

    /* 1. g^z1 h^z2 f^w0 = V * U^e, in the group */
    var zn1 = ((proof.z1 % q) + q) % q, zn2 = ((proof.z2 % q) + q) % q;
    var lhs1 = pub.G.add(pub.G.add(pub.G.mul_vartime(zn1, pub.g), pub.G.mul_vartime(zn2, pub.h)),
                         pub.G.mul_vartime(((proof.w0 % q) + q) % q, pub.f));
    if (!pub.G.equals(lhs1, pub.G.add(V, pub.G.mul_vartime(eq, pub.U)))) { return false; }

    /* 2. s1^z1 s2^z2 t^w1 = B * P^e, mod M */
    var a2 = spow(pub.s1, proof.z1, pub.M);
    var b2m = spow(pub.s2, proof.z2, pub.M);
    var c2 = spow(pub.t, proof.w1, pub.M);
    var p2 = spow(pub.P, e, pub.M);
    if (a2 === null || b2m === null || c2 === null || p2 === null) { return false; }
    if ((a2 * b2m % pub.M) * c2 % pub.M !== (proof.B % pub.M) * p2 % pub.M) {
        return false;
    }

    /* 3. enc_N(z1; rho^w2) * E^z2 = D * S^e, mod N^2 */
    var r3 = spow(pub.rho, proof.w2, N2);
    if (r3 === null) { return false; }
    var e3 = enc(pub.N, proof.z1, r3);
    var eb3 = spow(pub.E, proof.z2, N2);
    var s3 = spow(pub.S, e, N2);
    if (e3 === null || eb3 === null || s3 === null) { return false; }
    return (e3 * eb3) % N2 === (proof.D % N2) * s3 % N2;
}

/**
 * ⚠ DERIVED FROM V, B AND D, AFTER THEY ARE FIXED.
 */
export function challenge(pub, V, B, D, sid, ell, sizes) {
    var N2 = pub.N * pub.N, M = pub.M;
    /* v3: zk_bytes.fs_stream - v2's content, plus N and M themselves, which
       v2 hashed as mod_bytes(N, N), i.e. zeros; see zk_dlenc's challenge */
    var read = fs_stream('cryptographic-primitives/sig/v3/chal', sid, [
        pub.G.encode(pub.g), pub.G.encode(pub.h), pub.G.encode(pub.f), pub.G.encode(pub.U),
        pub.N, mod(pub.E, N2), mod(pub.S, N2), mod(pub.rho, N2),
        M, mod(pub.s1, M), mod(pub.s2, M), mod(pub.t, M), mod(pub.P, M),
        sizes_tag(sizes),
        pub.G.encode(V), mod(B, M), mod(D, N2)
    ]);
    return fs_signed(read, ell);
}

/*
 * ⭐ EVERY PUBLIC INPUT GOES INTO THE CHALLENGE (v2), including the parameters
 *   the verifier itself chose and the declared ranges - see
 *   zk_bytes.sizes_tag. The encoder, the prover's exponentiation and the
 *   digest-to-challenge step were byte-for-byte copies of the ones in
 *   zk_dlenc.js and now live in commons/zk_bytes.js.
 */
function sizes_tag(sizes) { return sizes_tag_nu(sizes, NU); }
