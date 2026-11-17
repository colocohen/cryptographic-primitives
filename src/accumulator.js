/**
 * RSA accumulator  -  a whole set as one number
 *
 * An accumulator represents a set of any size by a single group element, and
 * proves that something is or is not in it with a proof of the same fixed
 * size - 256 bytes for a 2048-bit modulus, whether the set holds ten elements
 * or ten million.
 *
 *     A = g^(p1 * p2 * ... * pn)  mod N
 *
 * where each element is mapped to a distinct prime. Membership of element i is
 * proved by exhibiting the accumulator built WITHOUT it:
 *
 *     witness = g^(product of all primes except pi)
 *     check:    witness^pi == A
 *
 * Only someone who knows the other primes can produce that witness, and the
 * check is one modular exponentiation.
 *
 * ================= HOW THIS DIFFERS FROM sparse_merkle.js =================
 *
 * Both answer "is this in the set" and "is this absent". They differ in three
 * ways that decide which to use:
 *
 *   PROOF SIZE. Sparse Merkle gives 5-11 hashes for a realistic set; this
 *   gives 256 bytes always. For small sets the tree wins, for enormous ones
 *   this does.
 *
 *   AGGREGATION. A hundred membership proofs here combine into ONE 256-byte
 *   proof, by multiplying the exponents. Merkle proofs do not combine at all.
 *
 *   UPDATES. Adding an element here is one exponentiation, and every existing
 *   witness is repaired by raising it to the new prime - no rebuild. In a
 *   Merkle tree every proof along the changed path is invalidated, so an
 *   append breaks proofs that other parties are holding.
 *
 * The cost is the setup: this needs a modulus nobody can factor.
 *
 * ==================== THE MODULUS ====================
 *
 * ANYONE WHO KNOWS THE FACTORISATION CAN FORGE. With phi(N) they compute the
 * inverse of any prime modulo phi(N) and produce a witness for an element
 * that was never added - so the accumulator proves nothing to anyone who
 * suspects the setup.
 *
 * The same three options as vdf.js: a multi-party ceremony, the RSA-2048
 * challenge modulus whose factors RSA Security said were destroyed, or a class
 * group with no setup at all. setup_unsafe() below returns the factors and is
 * for testing only.
 *
 * ==================== ELEMENTS MUST MAP TO PRIMES ====================
 *
 * And to DISTINCT primes, injectively. If two elements map to the same prime,
 * a membership proof for one is a proof for the other. The mapping here
 * hashes the element and searches upward for a prime, which is deterministic
 * and collision-resistant for the same reason the hash is.
 *
 * ==================== WHAT IT CANNOT DO ====================
 *
 * DELETION NEEDS THE FACTORISATION, or the full element list. Removing p from
 * the exponent means computing A^(1/p), which requires phi(N) - the trapdoor
 * nobody is supposed to have - or rebuilding from the remaining elements.
 * A construction that supports deletion by an untrusted party needs a
 * different scheme; this one is append-only in practice.
 */

import { powmod, powmod_signed, gcd, bezout, unknown_order_group_unsafe }
    from './commons/primes.js';
import { fs_stream, fs_prime } from './commons/zk_bytes.js';
import { mod_bytes } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';

/**
 * A modulus and generator, WITH the factors. Testing only - the shared
 * implementation and the reasoning are in commons/primes.js.
 */
export function setup_unsafe(bits, rng) {
    rng = require_rng('setup_unsafe', rng);
    return unknown_order_group_unsafe(bits, rng);
}

/**
 * Map an element to a prime, injectively and deterministically.
 *
 * DISTINCTNESS IS A SOUNDNESS REQUIREMENT, not a convenience: two elements
 * sharing a prime means a proof for one opens the other. The search walks
 * upward from the hash so that the same element always gives the same prime,
 * which every party must agree on.
 *
 * @param {Uint8Array} element
 * @param {number}     [bits=136]  wide enough that collisions are negligible
 */
export function element_to_prime(element, bits) {
    /* v2: zk_bytes.fs_prime over the Fiat-Shamir stream (v1 was
       primes.hash_to_prime's own sha256 expansion) */
    var read = fs_stream('cryptographic-primitives/accumulator/prime/v2', new Uint8Array(0), [element]);
    return fs_prime(read, bits || 136);
}

/* ---------------- building ---------------- */

/**
 * Accumulate a list of elements from the generator.
 *
 * @return {bigint} the accumulator value
 */
export function accumulate(g, elements, N) {
    var A = ((g % N) + N) % N;
    for (var i = 0; i < elements.length; i++) {
        A = powmod(A, element_to_prime(elements[i]), N);
    }
    return A;
}

/**
 * Add one element to an existing accumulator.
 *
 * ONE EXPONENTIATION, and every OTHER party's witness stays valid after they
 * raise it to the new prime - which they can do without help. That is the
 * property a Merkle tree cannot offer: there, an append invalidates every
 * proof along the changed path.
 */
export function add(A, element, N) {
    return powmod(((A % N) + N) % N, element_to_prime(element), N);
}

/**
 * Repair a witness after elements were added.
 *
 * The holder does this themselves from the public list of additions - no
 * interaction with whoever maintains the accumulator.
 */
export function update_witness(witness, added_elements, N) {
    /*
     * ⭐ THIS IS accumulate WITH THE ARGUMENTS RENAMED. Folding a set of
     *   elements into a witness and folding them into an accumulator are the
     *   same computation - base^(prod of hash_to_prime(e)) mod N - and the
     *   two names exist only to say which role the base is playing at the
     *   call site. Keeping two loops meant a fix to one could miss the
     *   other, and they must agree exactly or a witness stops verifying
     *   against its accumulator.
     */
    return accumulate(witness, added_elements, N);
}

/* ---------------- membership ---------------- */

/**
 * The witness for `element`: the accumulator built without it.
 *
 * REQUIRES THE FULL ELEMENT LIST. The accumulator value alone is not enough -
 * dividing it by the element's prime needs the trapdoor. In practice whoever
 * maintains the set holds the list and issues witnesses; holders then keep
 * theirs up to date with update_witness.
 *
 * @return {bigint}
 */
export function witness(g, elements, element, N) {
    var target = element_to_prime(element);
    var w = ((g % N) + N) % N;
    var found = false;
    for (var i = 0; i < elements.length; i++) {
        var p = element_to_prime(elements[i]);
        if (p === target) { found = true; continue; }
        w = powmod(w, p, N);
    }
    if (!found) { throw new Error('accumulator: element is not in the set'); }
    return w;
}

/**
 * Check a membership witness.
 *
 * @return {boolean}
 */
export function verify_membership(A, element, wit, N) {
    try {
        var w = ((wit % N) + N) % N;
        /* a witness outside the group satisfies the equation degenerately */
        if (gcd(w, N) !== 1n) { return false; }
        if (w === 1n) { return false; }
        return powmod(w, element_to_prime(element), N) === ((A % N) + N) % N;
    } catch (err) {
        return false;
    }
}

/**
 * Aggregate several membership witnesses into ONE.
 *
 * The combined witness is the accumulator built without ALL of them, and it
 * proves every one at once - still 256 bytes. This is the property that has
 * no Merkle equivalent: a hundred Merkle proofs are a hundred proofs.
 *
 * @return {{witness: bigint, elements: Array}}
 */
export function aggregate_witnesses(g, elements, subset, N) {
    var skip = {};
    for (var i = 0; i < subset.length; i++) {
        skip[element_to_prime(subset[i]).toString()] = true;
    }
    var w = ((g % N) + N) % N;
    for (var j = 0; j < elements.length; j++) {
        var p = element_to_prime(elements[j]);
        if (skip[p.toString()]) { continue; }
        w = powmod(w, p, N);
    }
    return { witness: w, elements: subset };
}

/** @return {boolean} */
export function verify_aggregate(A, subset, wit, N) {
    try {
        var w = ((wit % N) + N) % N;
        if (gcd(w, N) !== 1n || w === 1n) { return false; }
        var e = 1n;
        for (var i = 0; i < subset.length; i++) { e *= element_to_prime(subset[i]); }
        return powmod(w, e, N) === ((A % N) + N) % N;
    } catch (err) {
        return false;
    }
}

/* ---------------- non-membership ---------------- */

/**
 * Prove that an element is NOT in the set.
 *
 * THE PROOF IS A BEZOUT PAIR. Let x be the element's prime and s the product
 * of every prime in the set. If x is not among them then gcd(x, s) = 1, so
 * there exist a and b with
 *
 *     a*s + b*x = 1
 *
 * and the proof is (a, d) where d = g^(-b). The verifier checks
 *
 *     A^a * d^x == g
 *
 * which follows from the identity and holds only when x really is coprime to
 * s - that is, only when the element is genuinely absent. If x WERE in the
 * set, gcd would be x and no such pair exists.
 *
 * REQUIRES THE FULL SET, like witness(). And the exponent product grows with
 * the set, so this is the operation that scales worst: extended Euclid on a
 * number with as many bits as the set has elements times 136.
 *
 * @return {{a: bigint, d: bigint}}
 */
export function non_membership(g, elements, element, N) {
    var x = element_to_prime(element);
    var s = 1n;
    for (var i = 0; i < elements.length; i++) {
        var p = element_to_prime(elements[i]);
        if (p === x) { throw new Error('accumulator: element IS in the set'); }
        s *= p;
    }

    var bez = bezout(s, x);
    if (bez.g !== 1n) { throw new Error('accumulator: element is not coprime to the set'); }

    /*
     * d = g^b, inverted when b is negative: primes.powmod_signed, which this
     * file and vector_commit.js each wrote out as the same if/else around
     * mod_inverse. Variable time is right - g and the Bezout pair are public.
     */
    var d;
    try { d = powmod_signed(((g % N) + N) % N, bez.y, N); }
    catch (e) { throw new Error('accumulator: non-invertible'); }
    return { a: bez.x, d: d };
}

/**
 * Check a non-membership proof.
 *
 *     A^a * d^x == g
 *
 * @return {boolean}
 */
export function verify_non_membership(A, element, proof, g, N) {
    try {
        if (!proof) { return false; }
        var x = element_to_prime(element);
        var AA = ((A % N) + N) % N;
        var dd = ((proof.d % N) + N) % N;
        if (gcd(dd, N) !== 1n) { return false; }

        /* A^a for a signed a; a non-invertible A throws into the catch below,
           which is the `return false` this used to spell out */
        var lhs = (powmod_signed(AA, proof.a, N) * powmod(dd, x, N)) % N;
        return lhs === ((g % N) + N) % N;
    } catch (err) {
        return false;
    }
}


/** The accumulator as bytes, at the modulus's width. */
export function to_bytes(A, N) { return mod_bytes(A, N); }
