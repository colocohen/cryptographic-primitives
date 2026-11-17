/**
  * mta.js — multiplicative to additive.
  *
  * Four pure functions, no state, no parties, no rounds - what anyone
  * building threshold ECDSA needs.
  *
  * What is NOT here is the n-party composition — a loop over ordered
  * pairs of a party list, which is orchestration. It is reproduced at the
  * bottom of this file as a comment, because it is the thing this is FOR and
  * reading the primitive without it is confusing.
  *
  * THE PROBLEM THIS EXISTS FOR
  *
  * Threshold Schnorr is easy and threshold ECDSA is hard, and the whole
  * difference is one line. A Schnorr signature is
  *
  *     s = k + c·d
  *
  * which is addition and multiplication by a public constant. Split k and d
  * additively, have everyone compute their piece locally, add the pieces up,
  * and you are done — that is all frost.js does, and it needs no communication
  * beyond exchanging commitments.
  *
  * ECDSA is
  *
  *     s = k⁻¹·(hash + r·d)
  *
  * and now there are two operations nobody can do on shares alone. `k⁻¹` is an
  * inversion of a value that exists only in pieces, and `r·d` is a product of
  * TWO secrets that are each split. Addition of shares is free; multiplication
  * of shares is not, and no amount of rearranging removes it.
  *
  * MtA is the piece that buys the multiplication. It converts a MULTIPLICATIVE
  * sharing — Alice holds a, Bob holds b, and neither may learn the other's —
  * into an ADDITIVE one: Alice ends with α, Bob with β, and
  *
  *     α + β = a·b
  *
  * with neither learning anything about the other's input. Additive shares
  * compose freely, so once the product is additive the rest of the signature is
  * ordinary arithmetic again.
  *
  * HOW, IN THREE LINES
  *
  *   1. Alice encrypts a under her own Paillier key and sends the ciphertext.
  *   2. Bob multiplies it by b — homomorphically, so he never sees a — adds a
  *      fresh random β', and sends the result back. He keeps β = -β'.
  *   3. Alice decrypts and gets α = a·b + β'.
  *
  * Alice learns a·b + β', which is a·b hidden by Bob's randomness. Bob learns
  * nothing at all: he only ever handled ciphertexts under Alice's key.
  *
  * WHAT IS NOT HERE, AND IT IS THE HALF THAT MAKES IT SAFE
  *
  * Everything above is correct against an honest Bob. Against a malicious one
  * it is wide open: Bob can multiply by something other than b, or add a β'
  * so large it wraps the modulus, and Alice cannot tell. The zero-knowledge
  * proofs — Π^enc, Π^aff-g, Π^log* — are what close that, and they live in
  * cryptographic-primitives.
  *
  * So this file is the ARITHMETIC, testable now and secure against nobody. The
  * protocol layer that wraps it in proofs is what makes it CGGMP21. Reading
  * this without that caveat would be reading half of GG18.
  */

import { mod, random_below_biased as random_below, random_unit, require_rng } from './commons/primes.js';
import { encrypt_with_randomness, mul_plain, add_plain, decrypt_signed }
        from './paillier.js';

/*
  * PAILLIER IS IMPORTED, NOT INJECTED. Passing it in as a parameter would buy
  * nothing and cost a wrong argument at every call site.
  */

// =====================================================================
//  sizes
// =====================================================================

/**
  * How much bigger the Paillier modulus has to be than the curve order.
  *
  * THIS IS A CORRECTNESS CONSTRAINT BEFORE IT IS A SECURITY ONE. Paillier
  * arithmetic happens modulo N, and the value being carried is a·b + β'. Both
  * a and b are below q, so a·b approaches q², and β' has to be much larger
  * again to hide it. If the sum reaches N it wraps, Alice decrypts the wrong
  * number, and the signature simply fails — no error, no attribution, just an
  * invalid signature that appears at some rate depending on the inputs.
  *
  * CGGMP21 sizes the masking range at 2^(ell+eps) with ell ≈ log q, which puts
  * the requirement at roughly N > 2^(3·log q) with room to spare. For
  * secp256k1's 256-bit order that is comfortably inside a 2048-bit modulus, and
  * the check below is cheap enough to run rather than assume.
  */
export var MASK_SLACK = 2;   // β' is drawn from 2^(ell + eps); eps = ell·MASK_SLACK

/**
  * Is this Paillier modulus large enough for this curve?
  *
  * Called at setup rather than per operation, because the failure it prevents
  * is silent and rate-dependent — the worst kind to debug from a signature that
  * "sometimes doesn't verify".
  */
/**
 * ⛔ The floor for a Paillier modulus in threshold ECDSA: max(2048, 8·ℓ),
 * CGGMP's parameter set. Below it the MtA mask (5ℓ) and Π^fac's range bound
 * stop protecting anything. `opts.allowSmall` exists for tests only.
 */
export var MIN_MODULUS_BITS = 2048;

export function modulus_fits(N, order, opts) {
    var ell = order.toString(2).length;
    if (!(opts && opts.allowSmall === true)) {
        var floor = Math.max(MIN_MODULUS_BITS, 8 * ell);
        if (N.toString(2).length < floor - 1) { return false; }
    }

    // The carried value is a·b + β'. a·b reaches 2·ell bits, but β' is drawn at
    // ell·(1 + MASK_SLACK) — three times ell by default — so it dominates and
    // the sum is one bit above it at most. An earlier version added the two
    // widths and demanded ell·(2 + MASK_SLACK), which double-counts: it refused
    // a 1024-bit modulus for a 256-bit order, a combination that is fine and is
    // what everyone actually deploys. Caught by the test asserting the
    // combination should pass.
    var need = BigInt(ell) * BigInt(1 + MASK_SLACK) + 64n;
    return BigInt(N.toString(2).length) > need;
}

// =====================================================================
//  the exchange
// =====================================================================

/**
  * Alice's first move: encrypt her input under her OWN key.
  *
  * Her own key, deliberately. Bob will operate on this homomorphically and
  * send it back for her to decrypt, so the trapdoor has to be hers — if it were
  * Bob's he could simply decrypt a.
  *
  * The randomness is returned alongside because Π^enc needs it: Alice has to
  * prove the ciphertext encrypts something in range, and the proof is over the
  * plaintext AND the randomness that produced the ciphertext. A version of this
  * that discarded it would make the proof impossible to construct later, which
  * is the kind of API mistake that is only discovered two layers up.
  *
  * rng omitted or null draws fresh ones from the platform.
  */
export function alice_encrypt(pk, a, rng) {
    rng = require_rng('mta.alice_encrypt', rng);
    var r = random_unit(pk.n, rng);
    return {
        C: encrypt_with_randomness(pk, mod(a, pk.n), r),
        randomness: r
    };
}

/**
  * Bob's move: multiply by b, mask, and hand back.
  *
  *     D = (C ⊗ b) ⊕ Enc(β')
  *
  * `⊗` is scalar multiplication of a ciphertext and `⊕` is ciphertext addition;
  * Paillier gives both. Bob never decrypts anything and never sees a.
  *
  * β' IS DRAWN MUCH LARGER THAN a·b, and that is what makes this
  * zero-knowledge rather than merely obscure. Alice recovers a·b + β'. If β'
  * were the same size as a·b she could learn its high bits; the mask has to
  * dominate the value it hides. That is the same reasoning as `eps` in the
  * range proofs, and the same reason neither is a tuning parameter.
  *
  * Bob's output share is -β' rather than β': the two shares must SUM to the
  * product, and Alice's carries the +β' that Bob added.
  *
  * rng omitted or null draws fresh ones from the platform.
  */
export function bob_respond(pk, C, b, order, rng) {
    rng = require_rng('mta.bob_respond', rng);
    var ell = order.toString(2).length;
    var beta_prime = random_below(1n << BigInt(ell * (1 + MASK_SLACK)), rng);

    var product = mul_plain(pk, C, mod(b, pk.n));
    var masked  = add_plain(pk, product, mod(beta_prime, pk.n));

    return {
        D: masked,
        beta: mod(-beta_prime, order),
        beta_prime: beta_prime   // Π^aff-g proves the operation was this one
    };
}

/**
  * Alice's second move: decrypt, and reduce.
  *
  * `decrypt_signed` rather than `decrypt`: the plaintext here is an integer
  * that may be negative once interpreted, and Paillier's plaintext space wraps
  * at N. Reading a·b + β' as an unsigned residue when it should be signed gives
  * a value off by exactly N, and the resulting signature fails verification
  * with nothing to say why.
  */
export function alice_decrypt(sk, D, order) {
    return mod(decrypt_signed(sk, D), order);
}

/**
  * The whole exchange, for callers that hold both sides.
  *
  * Used by the tests and by any single-process composition; a real deployment
  * runs the three steps on two machines with proofs between them.
  *
  * rng omitted or null draws fresh ones from the platform.
  */
export function mta(keypair, a, b, order, rng) {
    rng = require_rng('mta.mta', rng);
    var first = alice_encrypt(keypair.pk, a, rng);
    var second = bob_respond(keypair.pk, first.C, b, order, rng);
    var alpha = alice_decrypt(keypair.sk, second.D, order);
    return { alpha: alpha, beta: second.beta };
}

// =====================================================================
//  composition — what the protocol actually does with it
// =====================================================================

// =====================================================================
//  helpers
// =====================================================================




/* ─────────────────────────────────────────────────────────────────────────
  * WHAT THE PROTOCOL DOES WITH THIS — kept as a comment because it is
  * orchestration and lives in the protocol, but the primitive is hard to read
  * without it.
  *
  * Given k = Σ kᵢ and γ = Σ γᵢ, each additively shared and neither existing
  * anywhere:
  *
  *     k·γ = (Σ kᵢ)(Σ γⱼ) = Σᵢ kᵢγᵢ  +  Σᵢ≠ⱼ kᵢγⱼ
  *
  * The diagonal terms are local. Every off-diagonal term is a product of two
  * secrets held by different parties, which is exactly one MtA exchange. Party
  * i runs one with each j and sets
  *
  *     δᵢ = kᵢγᵢ + Σⱼ≠ᵢ (αᵢⱼ + βᵢⱼ)
  *
  * and Σ δᵢ = k·γ, with each δᵢ looking like nothing on its own.
  *
  * Cost: n(n-1) exchanges, each an encryption, a homomorphic multiply and a
  * decryption. That is where threshold ECDSA's reputation for being expensive
  * comes from, and why presigning exists.
  *
  * Presigning runs this twice: once for k·γ, which turns the inversion of k
  * into a multiplication by a public constant (k⁻¹ = γ·δ⁻¹ once δ is opened),
  * and once for k·x, which is the other half of the signature.
  * ───────────────────────────────────────────────────────────────────────── */
