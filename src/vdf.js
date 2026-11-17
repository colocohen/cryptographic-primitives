/**
 * VDF  -  a computation that takes real time, and a proof that it did
 *
 * Wesolowski's verifiable delay function. Evaluating it requires T squarings
 * ONE AFTER ANOTHER - no amount of hardware makes it faster, because each
 * squaring needs the previous result. Verifying takes milliseconds.
 *
 *     evaluate(g, T, N)   ->  y and a proof, after T sequential squarings
 *     verify(g, y, pi, T) ->  immediate
 *
 * ==================== WHAT IT ADDS TO THE VRF HERE ====================
 *
 * A VRF stops the key holder from CHOOSING the output - there is exactly one
 * valid answer. But they learn it immediately, and in a protocol where they
 * decide whether to publish, that is enough to bias the result by staying
 * silent.
 *
 * A VDF stops EVERYONE, including the evaluator, from knowing the output
 * until the time has actually passed. Used together: commit-reveal supplies
 * an input nobody controls, and the VDF makes it impossible for the last
 * participant to compute the outcome and decide whether to reveal.
 *
 * That combination is what Chia's consensus is built on and what Ethereum's
 * randomness beacon was designed around.
 *
 * ========================= HOW IT WORKS =========================
 *
 *     y = g^(2^T)  mod N        T squarings, unavoidably sequential
 *
 * The proof is Wesolowski's, and it is elegant: hash g and y to a prime l,
 * write 2^T = q*l + r, and publish pi = g^q. The verifier checks
 *
 *     pi^l * g^r == y
 *
 * which holds only if the prover really performed the T squarings. The proof
 * is ONE group element and verification is two exponentiations with short
 * exponents, whatever T was.
 *
 * =============== THE MODULUS, AND WHY IT IS THE HARD PART ===============
 *
 * SECURITY REQUIRES THAT NOBODY KNOWS THE FACTORISATION OF N. Anyone who does
 * knows phi(N), can reduce 2^T modulo it, and computes the answer in one
 * exponentiation instead of T squarings - the delay evaporates.
 *
 * That leaves three options, and all three are awkward:
 *
 *   - AN RSA CEREMONY. Many parties jointly generate N so that no coalition
 *     knows p and q. Expensive, and the trust argument is the same one KZG's
 *     setup makes.
 *   - AN RSA CHALLENGE MODULUS. RSA-2048 from the old factoring challenge has
 *     never been factored and its factors were destroyed - or so RSA Security
 *     stated. It is the pragmatic choice and it rests on that statement.
 *   - A CLASS GROUP. No setup at all: the group is derived from a
 *     discriminant, and its order is genuinely unknown to everyone. This is
 *     what Chia uses: vdf_class.js, the same scheme over binary quadratic
 *     forms (and the README's section on choosing between the two).
 *
 * setup_unsafe() below generates a modulus and RETURNS ITS FACTORS, which
 * makes it useless for a real delay and correct for testing.
 *
 * ============================ ON SPEED ============================
 *
 * The delay is only as strong as the fastest implementation in existence. An
 * adversary with optimised hardware finishes sooner than an honest party on a
 * general-purpose machine, and in a protocol where being first matters, that
 * is an advantage.
 *
 * MEASURED HERE: 10,000 squarings on a 2048-bit modulus take 56-87 ms,
 * depending on the machine (tools/bench/vdf.mjs, beside the class groups),
 * against the 116 ms Chia reports for its reference implementation on a
 * 3.5 GHz i7. JavaScript is not the handicap one might expect, because the
 * work is a single long dependency chain of BigInt squarings and V8 hands
 * those to the same kind of code a C implementation would use.
 *
 * That is not a claim of parity with a tuned VDF ASIC, which exists and is
 * far faster than either. It means the gap is the usual hardware gap, not a
 * language gap.
 */

import { powmod, gcd, unknown_order_group_unsafe } from './commons/primes.js';
import { fs_stream, fs_qr, fs_prime } from './commons/zk_bytes.js';
import * as W from './commons/wesolowski.js';

/**
 * RSA-2048 from the RSA Factoring Challenge.
 *
 * Never factored, and RSA Security stated the factors were destroyed. Using
 * it means trusting that statement - which is a weaker assumption than a
 * ceremony you did not attend, and a stronger one than a class group.
 */
export var RSA_2048 =
    25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357n;

/*
 * THE PRIMALITY TEST USES ITS FIXED BASES ONLY - no extra random rounds.
 *
 * commons/primes.js takes an rng for those, and there is deliberately none
 * here: hash_to_prime must be DETERMINISTIC, because the verifier recomputes
 * the same prime from the same (g, y). A randomised test could accept a
 * candidate the verifier rejects, and the two would then derive different
 * primes from identical inputs.
 *
 * The fixed bases leave a composite roughly a 2^-80 chance of passing, and a
 * composite l does not forge anything here - it makes an honest proof fail to
 * verify, which is detectable rather than exploitable.
 */

/**
 * Generate a modulus AND ITS FACTORS.
 *
 * FOR TESTING ONLY, and the name says so. A delay function whose evaluator
 * knows the factorisation has no delay: phi(N) reduces 2^T to a short
 * exponent and the answer comes out in one step. Returning the factors makes
 * that impossible to overlook.
 */
export function setup_unsafe(bits, rng) {
    /* shared with accumulator.js and vector_commit.js - all three need a
       group of unknown order, and all three are broken by whoever knows the
       factorisation. See commons/primes.js. */
    return unknown_order_group_unsafe(bits, rng);
}

/**
 * Map an input to a group element.
 *
 * SQUARED, so the result lies in the subgroup of quadratic residues. That
 * matters: Z*_N has elements of order 2, and starting from one of them would
 * let the sequence collapse to something short.
 */
export function hash_to_group(input, N) {
    /*
     * v2: zk_bytes.fs_qr - primes.random_quadratic_residue reading the
     * Fiat-Shamir stream. v1 was a sha256 counter expansion of its own, and
     * an x below 2 became 2 rather than being drawn again; x must now also be
     * a unit, and N is bound alongside the input.
     */
    return fs_qr(fs_stream('cryptographic-primitives/vdf/g/v2', new Uint8Array(0), [N, input]), N);
}

/**
 * Hash (g, y) to a prime, for the Fiat-Shamir challenge.
 *
 * THE PRIME MUST NOT BE PREDICTABLE BEFORE y IS FIXED. If it were, a prover
 * could pick a convenient l and construct a y to match - which is exactly the
 * soundness gap analysed in the literature on this scheme. Deriving it from
 * both values closes that.
 *
 * The search walks upward from the hash rather than rehashing, which is
 * deterministic and costs a handful of primality tests.
 */
export function hash_to_prime(g, y, N, bits) {
    /* v2: zk_bytes.fs_prime over (N, g, y) - v1 hashed g and y at N's width
       but not N itself */
    var read = fs_stream('cryptographic-primitives/vdf/prime/v2', new Uint8Array(0),
                         [N, ((g % N) + N) % N, ((y % N) + N) % N]);
    return fs_prime(read, bits || 128);
}

/**
 * The delay itself: T sequential squarings.
 *
 * THIS LOOP IS THE WHOLE POINT AND CANNOT BE MADE PARALLEL. Every iteration
 * depends on the previous result, so more cores do not help - that is the
 * property the construction rests on, and any "optimisation" that removes it
 * removes the delay.
 */
export function eval_raw(g, T, N) {
    var y = ((g % N) + N) % N;
    for (var i = 0; i < T; i++) { y = (y * y) % N; }
    return y;
}

/**
 * Evaluate and prove.
 *
 * THE PROOF IS CHEAP: commons/wesolowski.js keeps a checkpoint every k
 * squarings and assembles π = g^⌊2^T/ℓ⌋ from them in about T/k + k·2^(k−1)
 * multiplications - about 1/k of the evaluation (10-20%), against a second
 * full pass for the plain long division. The memory is ⌈T/k⌉ elements; past
 * opts.max_checkpoints it falls back to the long division. π is the same
 * either way: it is one element, x^⌊2^T/ℓ⌋.
 *
 * T MUST EXCEED THE CHALLENGE PRIME'S BIT LENGTH TO MEAN ANYTHING. With T
 * below it (128 bits by default) the quotient ⌊2^T/ℓ⌋ is zero and the honest proof is g^0 = 1 -
 * which verifies, because r = 2^T mod ℓ is then 2^T itself and the equation
 * is g^(2^T) == y. Not a forgery: a delay function without a useful proof.
 * Real parameters are T in the millions.
 *
 * @param  {bigint} g  the starting element, from hash_to_group
 * @param  {number} T  the delay parameter, in squarings
 * @param  {bigint} N
 * @param  {object} [opts]  { prime_bits (default 128), k, max_checkpoints }
 * @return {{y: bigint, proof: bigint, l: bigint}}
 */
export function evaluate(g, T, N, opts) {
    var o = opts || {};
    var G = group(N);
    return W.evaluate(G, ((g % N) + N) % N, T, function (x, y) { return hash_to_prime(x, y, N, o.prime_bits); }, o);
}

/* Z*_N for commons/wesolowski.js */
function group(N) {
    return {
        one: 1n,
        mul: function (a, b) { return (a * b) % N; },
        square: function (a) { return (a * a) % N; },
        equals: function (a, b) { return a === b; }
    };
}

/**
 * Verify in milliseconds, whatever T was.
 *
 *     pi^l * g^r == y   where r = 2^T mod l
 *
 * The exponent r is computed by modular exponentiation of 2, not by forming
 * 2^T - the whole reason this scheme's verification is cheap.
 *
 * @return {boolean}
 */
export function verify(g, y, proof, T, N, opts) {
    try {
        var gg = ((g % N) + N) % N;
        var yy = ((y % N) + N) % N;
        var pp = ((proof % N) + N) % N;

        /* group membership: a proof outside Z*_N satisfies the equation in
           degenerate ways */
        if (gcd(gg, N) !== 1n || gcd(yy, N) !== 1n || gcd(pp, N) !== 1n) {
            return false;
        }

        if (!Number.isSafeInteger(T) || T < 0) { return false; }
        return W.verify(group(N), gg, yy, pp, T, hash_to_prime(gg, yy, N, (opts || {}).prime_bits));
    } catch (err) {
        return false;
    }
}

/**
 * The shortcut, for a party that knows the factorisation.
 *
 * EXPOSED DELIBERATELY, because it is what an adversary who knows p and q can
 * do, and having it in the open makes the requirement on N concrete rather
 * than abstract. It is also how the test suite checks that eval_raw is
 * correct without waiting for a real delay.
 */
export function eval_with_trapdoor(g, T, N, phi) {
    var e = powmod(2n, BigInt(T), phi);
    return powmod(((g % N) + N) % N, e, N);
}
