/**
 * Shamir's Secret Sharing, and Lagrange interpolation at zero
 *
 * Split a secret into n pieces such that any t of them reconstruct it and any
 * t-1 reveal NOTHING - not "almost nothing", nothing at all. That last part
 * is the reason to use this rather than, say, splitting the bytes: with t-1
 * shares every possible secret remains exactly as likely as it was before,
 * which is information-theoretic security rather than computational.
 *
 * THE MECHANISM IS ONE LINE OF ALGEBRA. A polynomial of degree t-1 is
 * determined by exactly t points. Put the secret at f(0), choose the other
 * coefficients at random, and hand out f(1), f(2), ... f(n). Any t points fix
 * the polynomial and therefore f(0); any t-1 leave one degree of freedom, so
 * f(0) can still be anything.
 *
 * IT IS ITS OWN FILE BECAUSE THREE THINGS ALREADY NEEDED IT. bls12_381.js
 * had it for threshold signatures and again inside Feldman VSS; frost.js had
 * it for its trusted dealer. The two copies computed the same Horner
 * evaluation and the same Lagrange coefficient over different fields, and
 * were different enough as text that the duplication scanner did not flag
 * them - the same algorithm can be written two ways and look unrelated.
 *
 * THE FIELD IS A PARAMETER because the callers work over different ones: the
 * BLS scalar field, ristretto255's group order, or an ordinary prime for a
 * secret that has nothing to do with a curve. The only requirement is that
 * the modulus is PRIME, which every group order is - the interpolation
 * inverts differences of indices, and a composite modulus would leave some
 * of those non-invertible.
 *
 * WHAT THIS IS NOT: a distributed key generation. Everything here assumes a
 * DEALER who knows the secret and hands out pieces. Removing that trust needs
 * a protocol - several rounds, complaints, and a way to exclude a cheater -
 * and a protocol is not a function. bls12_381.js has the verifiable-dealing
 * half of it in vss_deal, which lets a recipient check their own share, and
 * that is as far as a library can go on its own.
 */

import { bytes_to_bigint, bigint_to_bytes } from './commons/bytes.js';
import { require_rng, mod as fmod, random_below_biased } from './commons/primes.js';
import { inv_prime, batch_invert } from './commons/modp.js';

/* fmod - reduce into [0, m) for a possibly negative input - is primes.mod;
   this file had its own copy of the one-liner under another name. */

/**
 * Modular inverse by Fermat's little theorem, valid because the modulus is
 * prime.
 *
 * NOT commons/primes.js's mod_inverse, deliberately. That one is the extended
 * Euclidean algorithm: faster, but its ITERATION COUNT DEPENDS ON THE
 * OPERANDS, so it leaks through timing. Fermat does a fixed number of
 * squarings for a given modulus whatever the input.
 *
 * It matters here because the values inverted are differences of share
 * indices, and which participants hold which index can be private - a
 * threshold signature that reveals the participating set defeats part of the
 * point.
 */
/* Fermat inversion in a prime field: commons/modp.inv_prime (was a copy). */
var inv = inv_prime;

/**
 * Evaluate a polynomial at x by Horner's method.
 *
 * `coeffs[0]` is the constant term, which is the secret.
 */
export function evaluate(coeffs, x, modulus) {
    var y = 0n;
    for (var i = coeffs.length - 1; i >= 0; i--) {
        y = fmod(y * x + coeffs[i], modulus);
    }
    return y;
}

/**
 * Build the polynomial: the secret as the constant term, then t-1 random
 * coefficients.
 *
 * THE RANDOM BYTES ARE WIDER THAN THE MODULUS ON PURPOSE. Reducing a value
 * drawn from exactly the modulus's width is biased towards the low end;
 * drawing 16 extra bytes makes the bias smaller than any adversary can
 * measure. Bias in the coefficients would leak information about the secret
 * across many sharings of it.
 *
 * @param {bigint}   secret
 * @param {number}   t        shares needed to reconstruct
 * @param {function} rng      (n) -> Uint8Array
 * @param {bigint}   modulus  prime
 */
export function polynomial(secret, t, rng, modulus) {
    rng = require_rng('polynomial', rng);
    var coeffs = [fmod(secret, modulus)];
    /*
     * ⭐ primes.random_below_biased: the modulus's byte width plus 16, one
     *   reduction. This loop was that function written out - the width came
     *   from the HEX length, (digits + 1) >> 1, which is the same byte count -
     *   and it draws identical coefficients from the same rng.
     */
    for (var i = 1; i < t; i++) { coeffs.push(random_below_biased(modulus, rng)); }
    return coeffs;
}

/**
 * Split a secret into n shares, t of which reconstruct it.
 *
 * INDICES START AT ONE, and must: index zero IS the secret, so a share at
 * position zero would hand it over outright.
 *
 * @return {Array<{index: bigint, value: bigint}>}
 */
export function split(secret, t, n, rng, modulus) {
    rng = require_rng('split', rng);
    if (t < 1 || t > n) { throw new Error('shamir: need 1 <= t <= n'); }
    var coeffs = polynomial(secret, t, rng, modulus);
    var out = [];
    for (var x = 1n; x <= BigInt(n); x++) {
        out.push({ index: x, value: evaluate(coeffs, x, modulus) });
    }
    return out;
}

/**
 * The Lagrange coefficient of share `i` at zero, given the participating set.
 *
 * IT DEPENDS ON THE WHOLE SET, which is the operational point people trip
 * over: a share's weight is not a property of the share. Which participants
 * are signing has to be known before any of them can produce their
 * contribution, and a different subset gives every share a different
 * coefficient.
 *
 * INDICES ARE COERCED, and that is not politeness.
 *
 * `split` returns them as bigint, and a bigint has no JSON representation -
 * `JSON.stringify` on a share THROWS. So every consumer that sends shares
 * over a network converts them to Number, and then every arithmetic
 * operation here fails with "Cannot mix BigInt and other types" from deep
 * inside the interpolation, far from the conversion that caused it.
 *
 * The contract is "a small positive integer", which is what an index is.
 * Accepting either spelling keeps that contract and costs one call.
 *
 * @param {bigint|number}         i        the index whose coefficient is wanted
 * @param {Array<bigint|number>}  indices  every participating index, including i
 */
/**
 * Refuse a repeated index - see lagrange_coeffs_at_zero for why it must be
 * refused rather than left to surface. Three interpolators opened with this
 * same loop; they share it now, and the message is unchanged.
 */
function refuse_duplicates(indices, modulus) {
    /*
     * ⚠ COMPARED MODULO THE FIELD when there is one. 1 and modulus + 1 are
     *   different integers and the same point: they passed the raw check, the
     *   batch product went to zero and every coefficient with it (and the
     *   one-at-a-time form returned a finite wrong value). An index that is 0
     *   mod the field is the secret's own position, never a share's.
     */
    var seen = {};
    for (var k = 0; k < indices.length; k++) {
        var v = BigInt(indices[k]);
        if (modulus !== undefined) {
            v = fmod(v, modulus);
            if (v === 0n) { throw new Error('shamir: index ' + String(indices[k]) + ' is 0 modulo the field'); }
        }
        var key = String(v);
        if (seen[key]) {
            throw new Error('shamir: duplicate index ' + String(indices[k]) +
                            ' - interpolation is degenerate');
        }
        seen[key] = true;
    }
}

/**
 * prod_{j != i} x_j and prod_{j != i} (x_j - x_i), mod `modulus`: the
 * numerator and denominator of i's coefficient at zero. lagrange_at_zero and
 * lagrange_coeffs_at_zero each wrote this loop; they differ only in how they
 * invert the denominator.
 */
function lagrange_parts(i, indices, modulus) {
    var num = 1n, den = 1n;
    for (var j = 0; j < indices.length; j++) {
        var jj = BigInt(indices[j]);
        if (jj === i) { continue; }
        num = fmod(num * jj, modulus);
        den = fmod(den * (jj - i), modulus);
    }
    return { num: num, den: den };
}

/**
 * All the Lagrange coefficients at zero for a set of indices, at once.
 *
 * ⭐ EVERY COEFFICIENT NEEDS ONE MODULAR INVERSION and callers always want
 *   the whole set - threshold_combine and threshold_public_key each build
 *   one coefficient per signer before doing a single MSM. Montgomery's trick
 *   turns those N inversions into 1 inversion plus 3(N-1) multiplications,
 *   and an inversion here costs roughly 100us against a few hundred
 *   nanoseconds for a multiplication.
 *
 * ⚠ A REPEATED INDEX DOES NOT PRODUCE A ZERO DENOMINATOR, which is the trap
 *   here. The inner loop skips every j equal to i, so both copies of a
 *   duplicate are skipped and the denominator comes out finite - the
 *   coefficients are simply wrong, for a degenerate interpolation that
 *   reconstructs the wrong secret without erroring. lagrange_at_zero has the
 *   same blind spot one coefficient at a time. So duplicates are rejected
 *   explicitly, up front, rather than hoped to surface as a zero.
 */
export function lagrange_coeffs_at_zero(indices, modulus) {
    var n = indices.length, k;
    refuse_duplicates(indices, modulus);
    var nums = new Array(n), dens = new Array(n);
    for (k = 0; k < n; k++) {
        var nd = lagrange_parts(BigInt(indices[k]), indices, modulus);
        nums[k] = nd.num; dens[k] = nd.den;
    }

    /* Montgomery's trick (modp.batch_invert): one Fermat inversion, constant
       time like inv_prime itself; no zero can reach it, duplicates and 0
       having been refused above */
    var inv_dens = batch_invert(dens, function (a, b) { return fmod(a * b, modulus); },
                                function (a) { return inv(a, modulus); }, 1n);
    var out = new Array(n);
    for (k = 0; k < n; k++) { out[k] = fmod(nums[k] * inv_dens[k], modulus); }
    return out;
}

/**
 * Lagrange coefficients at 0 OVER THE INTEGERS, scaled:
 *
 *     lambda_i = scale * prod_{j != i} (-x_j) / (x_i - x_j)
 *
 * For sharings over Z (threshold RSA, class groups) where there is no field
 * to invert in; `scale` (n! or a power of it) must clear every denominator.
 *
 * ⛔ EXACT DIVISION IS ASSERTED. A scale that does not clear a denominator
 *   would truncate silently and reconstruct a different number, so this
 *   throws instead. Duplicate indices are refused as above.
 *
 * @return {Object} index (as given, stringified) -> bigint coefficient
 */
export function lagrange_integer_at_zero(indices, scale) {
    var k, out = {};
    refuse_duplicates(indices);
    for (k = 0; k < indices.length; k++) {
        var xi = BigInt(indices[k]), num = 1n, den = 1n;
        for (var j = 0; j < indices.length; j++) {
            if (j === k) { continue; }
            var xj = BigInt(indices[j]);
            num *= -xj;
            den *= (xi - xj);
        }
        var t = scale * num;
        if (t % den !== 0n) {
            throw new Error('shamir: the scale does not clear the denominator at index ' + indices[k] +
                            ' - for indices in 1..n it must be a multiple of n!');
        }
        out[String(indices[k])] = t / den;
    }
    return out;
}

export function lagrange_at_zero(i, indices, modulus) {
    i = BigInt(i);
    /*
     * ⛔ THE SAME BLIND SPOT AS lagrange_coeffs_at_zero HAD: a repeated index
     *   is skipped like i itself, so the coefficient comes out finite and
     *   wrong. Refused here as there, and i must be one of the indices.
     */
    refuse_duplicates(indices, modulus);
    var has_i = false;
    for (var q = 0; q < indices.length; q++) {
        if (BigInt(indices[q]) === i) { has_i = true; }
    }
    if (!has_i) { throw new Error('shamir: index ' + i + ' is not among the indices'); }
    var nd = lagrange_parts(i, indices, modulus);
    return fmod(nd.num * inv(nd.den, modulus), modulus);
}

/**
 * Reconstruct the secret from t or more shares.
 *
 * NO CHECK IS POSSIBLE HERE. Given t shares this returns whatever polynomial
 * passes through them - if one is corrupt the result is a different value
 * with nothing to distinguish it from the right one. Detecting that needs
 * commitments alongside the shares, which is what Feldman VSS adds and why it
 * exists; plain Shamir is secret sharing, not verifiable secret sharing.
 *
 * @param {Array<{index: bigint, value: bigint}>} shares
 */
export function combine(shares, modulus) {
    if (shares.length === 0) { throw new Error('shamir: no shares'); }
    /* either spelling - see lagrange_at_zero */
    var indices = shares.map(function (s) { return BigInt(s.index); });

    for (var a = 0; a < indices.length; a++) {
        if (indices[a] === 0n) { throw new Error('shamir: index zero is the secret itself'); }
        for (var b = a + 1; b < indices.length; b++) {
            if (indices[a] === indices[b]) { throw new Error('shamir: duplicate index'); }
        }
    }

    /*
     * ⭐ ONE CALL FOR EVERY COEFFICIENT. This called lagrange_at_zero once per
     *   share - n separate Fermat inversions, each re-checking the whole set
     *   for duplicates - beside lagrange_coeffs_at_zero, which computes the
     *   same coefficients with one inversion. For distinct indices below the
     *   modulus, which is every sharing split() makes, the values are the same.
     */
    var ls = lagrange_coeffs_at_zero(indices, modulus);
    var acc = 0n;
    for (var k = 0; k < shares.length; k++) {
        acc = fmod(acc + ls[k] * shares[k].value, modulus);
    }
    return acc;
}

/**
 * Combine shares that live in a GROUP rather than a field - partial
 * signatures, public-key shares, any value of the form share*G.
 *
 * Same interpolation, with scalar multiplication and group addition in place
 * of multiplication and addition. It is the linearity of the underlying
 * scheme that makes this work at all, which is why BLS and Schnorr have
 * threshold variants this simple and ECDSA does not.
 *
 * @param {object}   G        group with ZERO, add and mul
 * @param {Array}    shares   [{index: bigint|number, point: <group element>}]
 *                             see lagrange_at_zero on why either is accepted
 */
export function combine_points(G, shares, modulus, bits) {
    var indices = shares.map(function (s) { return BigInt(s.index); });
    var acc = G.ZERO;
    if (shares.length === 0) { return acc; }
    /* every coefficient at once, as in combine */
    var ls = lagrange_coeffs_at_zero(indices, modulus);
    for (var k = 0; k < shares.length; k++) {
        acc = G.add(acc, G.mul(ls[k], shares[k].point, bits));
    }
    return acc;
}

/* ---------------- bytes, for callers with no field of their own ---------------- */

/**
 * The prime just below 2^256, for sharing a 32-byte secret that is not a
 * curve scalar - a backup key, a passphrase-derived key, a seed.
 *
 * 2^256 - 189 is the largest 256-bit prime. Any 32-byte value below it shares
 * and reconstructs exactly; the handful of values above it would wrap, so
 * split_bytes rejects them rather than silently returning a different secret.
 */
export var P256_PRIME = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43n;

/* big-endian conversion, shared through commons/bytes.js */
var bytes_to_int = bytes_to_bigint;
var int_to_bytes = bigint_to_bytes;

/**
 * Split an arbitrary 32-byte secret.
 *
 * @return {Array<{index: number, share: Uint8Array}>}
 */
export function split_bytes(secret, t, n, rng) {
    rng = require_rng('split_bytes', rng);
    if (secret.length !== 32) { throw new Error('shamir: secret must be 32 bytes'); }
    var s = bytes_to_int(secret);
    if (s >= P256_PRIME) {
        /* about one in 2^248 of random 32-byte values; refusing is better
           than reconstructing something else */
        throw new Error('shamir: secret is not below the field prime');
    }
    return split(s, t, n, rng, P256_PRIME).map(function (sh) {
        return { index: Number(sh.index), share: int_to_bytes(sh.value, 32) };
    });
}

/** @return {Uint8Array} 32 bytes */
export function combine_bytes(shares) {
    var s = shares.map(function (sh) {
        return { index: BigInt(sh.index), value: bytes_to_int(sh.share) };
    });
    return int_to_bytes(combine(s, P256_PRIME), 32);
}
