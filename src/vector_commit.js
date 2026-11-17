/**
 * Vector commitment over an RSA group
 *
 * Commit to a list with one number, then prove what sits at any position:
 *
 *     commit([v0, v1, ..., vn])  ->  one group element
 *     open(i)                     ->  a proof that position i holds vi
 *     verify(C, i, vi, proof)     ->  true or false
 *
 * The proof is 256 bytes for a 2048-bit modulus, whatever the vector's
 * length, and there is no trusted setup.
 *
 * ============ WHY THIS EXISTS WHEN kzg.js AND merkle.js DO TOO ============
 *
 * All three are vector commitments; they occupy different corners:
 *
 *     kzg.js      48 bytes, constant   -  but needs a trusted setup
 *     merkle.js   log(n) hashes        -  no setup, grows with the vector
 *     this file   256 bytes, constant  -  no setup
 *
 * Constant-size AND setup-free is the corner the other two leave empty. The
 * price is speed: every operation here is a modular exponentiation with an
 * exponent as long as the vector, so committing to a thousand elements is
 * slow where a Merkle tree is instant.
 *
 * USE kzg.js when a setup is acceptable and size matters. Use merkle.js when
 * neither is a constraint - it is faster than both by a wide margin. Use this
 * when a proof must be constant-size and nobody can be trusted to have
 * destroyed a secret.
 *
 * ======================== HOW IT WORKS ========================
 *
 * Each POSITION gets its own prime p_i, and the commitment is
 *
 *     C = g^(sum over i of v_i * (S / p_i))    where S is the product of all
 *
 * so that raising C to p_i leaves every other term still divisible by its own
 * prime, and only v_i's term survives modulo p_i. The proof for position i is
 * the commitment built with that term's contribution removed, and the
 * verifier reconstructs it.
 *
 * POSITION PRIMES, NOT VALUE PRIMES - which is the difference from
 * accumulator.js. There, elements map to primes and the structure is a SET
 * with no order. Here the primes are indexed by position, so the same value
 * at two positions gives two different contributions and the ordering is
 * part of what is committed to.
 *
 * ========================== CONSTRAINTS ==========================
 *
 * THE LENGTH IS FIXED AT COMMIT TIME. Position primes are derived from the
 * index and the length, so a vector cannot be extended without recomputing
 * everything - unlike accumulator.js, where adding an element is one
 * exponentiation. That is the trade for having positions at all.
 *
 * VALUES MUST BE SMALL RELATIVE TO THE POSITION PRIMES. A value at or above
 * p_i wraps modulo p_i and two different values become indistinguishable to
 * the verifier. The default 136-bit primes leave room for any 128-bit value;
 * commit() enforces the bound rather than letting it fail silently.
 *
 * AND THE MODULUS MUST BE UNFACTORABLE, as everywhere else in this family.
 * Anyone who knows phi(N) opens any position to any value.
 */

import { powmod, powmod_signed, gcd, unknown_order_group_unsafe } from './commons/primes.js';
import { fs_stream, fs_prime } from './commons/zk_bytes.js';
import { mod_bytes } from './commons/bytes.js';

/**
 * A modulus and generator, WITH the factors. Testing only - the shared
 * implementation and the reasoning are in commons/primes.js.
 */
export function setup_unsafe(bits, rng) {
    return unknown_order_group_unsafe(bits, rng);
}

/** How many bits of value each position can hold, with the default primes. */
export var VALUE_BITS = 128;

/**
 * The prime for position i in a vector of the given length.
 *
 * BOTH THE INDEX AND THE LENGTH GO IN. Without the length, a proof for
 * position 3 of a five-element vector would also verify against position 3 of
 * a ten-element one - the commitments differ, but an adversary choosing the
 * length gains a degree of freedom that costs nothing to remove.
 */
export function position_prime(index, length, bits) {
    /* v2: zk_bytes.fs_prime over the Fiat-Shamir stream (v1 was
       primes.hash_to_prime's own sha256 expansion) */
    var read = fs_stream('cryptographic-primitives/vector-commit/pos/v2', new Uint8Array(0),
                         [BigInt(index), BigInt(length)]);
    return fs_prime(read, bits || 136);
}

/** All the position primes, and their product. */
function primes_for(length) {
    var ps = [], S = 1n;
    for (var i = 0; i < length; i++) {
        var p = position_prime(i, length);
        ps.push(p);
        S *= p;
    }
    return { primes: ps, product: S };
}

/**
 * Commit to a vector of non-negative integers.
 *
 * @param  {bigint}         g
 * @param  {Array<bigint>}  values  each below 2^VALUE_BITS
 * @param  {bigint}         N
 * @return {bigint}
 */
export function commit(g, values, N) {
    var ctx = primes_for(values.length);
    var limit = 1n << BigInt(VALUE_BITS);

    var e = 0n;
    for (var i = 0; i < values.length; i++) {
        var v = values[i];
        if (v < 0n || v >= limit) {
            throw new Error('vector_commit: value at ' + i + ' is out of range');
        }
        /* v_i * (S / p_i) - the term that survives when C is raised to p_i */
        e += v * (ctx.product / ctx.primes[i]);
    }
    return powmod(((g % N) + N) % N, e, N);
}

/**
 * Prove that position `index` holds `values[index]`.
 *
 * The proof is the commitment with that position's contribution divided out -
 * which is possible without the trapdoor precisely because the exponent is
 * known here. A verifier could not compute it, which is what makes it a
 * proof.
 *
 * @return {bigint}
 */
export function open(g, values, index, N) {
    if (index < 0 || index >= values.length) {
        throw new Error('vector_commit: index out of range');
    }
    var ctx = primes_for(values.length);
    var pi = ctx.primes[index];

    /*
     * The witness carries every OTHER position's term, each divided by p_i as
     * well - so raising it to p_i reproduces those terms exactly, and the
     * verifier supplies the missing one from the claimed value.
     */
    var e = 0n;
    for (var i = 0; i < values.length; i++) {
        if (i === index) { continue; }
        e += values[i] * (ctx.product / (ctx.primes[i] * pi));
    }
    return powmod(((g % N) + N) % N, e, N);
}

/**
 * Check that `value` sits at `index` in the committed vector.
 *
 *     witness^(p_i) * g^(value * S / p_i)  ==  C
 *
 * @return {boolean}
 */
export function verify(C, index, value, witness, length, g, N) {
    try {
        if (index < 0 || index >= length) { return false; }
        if (value < 0n || value >= (1n << BigInt(VALUE_BITS))) { return false; }

        var w = ((witness % N) + N) % N;
        if (gcd(w, N) !== 1n) { return false; }

        var ctx = primes_for(length);
        var pi = ctx.primes[index];

        var lhs = (powmod(w, pi, N) *
                   powmod(((g % N) + N) % N, value * (ctx.product / pi), N)) % N;
        return lhs === ((C % N) + N) % N;
    } catch (err) {
        return false;
    }
}

/**
 * Update a commitment when one position changes.
 *
 * ONE EXPONENTIATION, without recomputing the whole vector - the property
 * that makes this worth using over a Merkle tree for frequently-updated data,
 * where every change rebuilds a path.
 *
 * Existing witnesses for OTHER positions need repairing with
 * update_witness(); only the changed position's own witness is invalidated
 * outright.
 */
export function update(C, index, old_value, new_value, length, g, N) {
    var ctx = primes_for(length);
    var factor = ctx.product / ctx.primes[index];
    var delta = new_value - old_value;

    return apply_delta(C, g, delta, factor, N);
}

/**
 * Multiply `base` by g^(delta*factor) mod N, where delta may be NEGATIVE.
 *
 * Both the commitment update and the witness repair do exactly this, and a
 * negative exponent is the part worth writing once: it is an inverse of the
 * positive power, and the inverse can fail to exist - which must be an error
 * rather than a wrong number, since the modulus here is an RSA modulus whose
 * factorisation nobody knows.
 */
function apply_delta(base, g, delta, factor, N) {
    /* the signed power is primes.powmod_signed - accumulator.js wrote the
       same branch-and-invert as well */
    var t;
    try { t = powmod_signed(((g % N) + N) % N, delta * factor, N); }
    catch (e) { throw new Error('vector_commit: non-invertible'); }
    return (((base % N) + N) % N * t) % N;
}

/**
 * Repair a witness for position `held` after position `changed` was updated.
 *
 * The holder does this from public information - the index that changed and
 * by how much - with no help from whoever maintains the commitment.
 */
export function update_witness(witness, held, changed, delta, length, g, N) {
    if (held === changed) {
        throw new Error('vector_commit: a witness for the changed position must be reissued');
    }
    var ctx = primes_for(length);
    var factor = ctx.product / (ctx.primes[changed] * ctx.primes[held]);

    return apply_delta(witness, g, delta, factor, N);
}

/** The commitment as bytes, at the modulus's width. */
export function to_bytes(C, N) { return mod_bytes(C, N); }
