/**
 * KZG polynomial commitments  -  Kate, Zaverucha, Goldberg (2010)
 *
 * Commit to a polynomial with a SINGLE group element, then prove the value at
 * any point with another single element. Both are 48 bytes, whatever the
 * polynomial's degree.
 *
 *     commit(f)          ->  48 bytes, hides f
 *     open(f, z)         ->  48 bytes, proves f(z) = y
 *     verify(C, z, y, pi) ->  true or false
 *
 * CONSTANT SIZE IS THE WHOLE POINT, and it is what separates this from the
 * Merkle trees this library also has. A Merkle proof grows as log2(n): 320
 * bytes for a megabyte, 640 for a terabyte. A KZG proof is 48 bytes for a
 * polynomial of degree ten or ten million, and verification is one pairing
 * check rather than a chain of hashes.
 *
 * THE TRICK. The setup publishes powers of a secret s as group elements:
 * G, sG, s^2*G, ... and G2, s*G2. Nobody knows s. A commitment is f(s)*G,
 * computed WITHOUT knowing s by taking the linear combination of those
 * published powers with the polynomial's coefficients. To prove f(z) = y, the
 * prover exhibits the quotient q(X) = (f(X) - y) / (X - z), which is a
 * polynomial exactly when f(z) = y really does hold - and the pairing checks
 * that relation at the unknown s:
 *
 *     e(C - y*G, G2) == e(pi, s*G2 - z*G2)
 *
 * ============================ THE TRUSTED SETUP ============================
 *
 * THIS IS THE COST, AND IT IS NOT A DETAIL. Whoever generated the powers knew
 * s, and anyone who knows s can produce a valid opening for ANY value at ANY
 * point - they can prove f(z) equals whatever they like. The security of
 * every commitment ever made under those parameters depends on that number
 * having been destroyed.
 *
 * The mitigation is a multi-party ceremony: each participant contributes
 * randomness, and the result is safe if ANY ONE of them was honest. Ethereum's
 * KZG ceremony for EIP-4844 had over 140,000 participants, which is about as
 * strong as that argument gets.
 *
 * setup() BELOW GENERATES ITS OWN s AND RETURNS IT. That is correct for tests
 * and for a system where one party is legitimately trusted, and it is WRONG
 * for anything adversarial. To interoperate with Ethereum, load that
 * ceremony's parameters instead - see load_setup.
 *
 * BULLETPROOFS, IN THIS LIBRARY, NEEDS NO SETUP - every generator is hashed.
 * Its proofs are logarithmic rather than constant and its verification is
 * linear, so the trade is real in both directions.
 * ===========================================================================
 *
 * WHAT IT IS USED FOR: EIP-4844 blob commitments, Verkle trees, and the
 * polynomial commitment layer of PLONK and most modern SNARKs.
 */

import { mod, require_rng } from './commons/primes.js';
import { CURVE, POINT1, POINT2, BASE1, BASE2, PAIRING, FIELD12 } from './bls12_381.js';
import { bytes_to_bigint, bigint_to_bytes } from './commons/bytes.js';
import { inv_prime } from './commons/modp.js';
import { msm as pippenger, msm_group } from './commons/fixed_window.js';
import { evaluate as shamir_evaluate } from './shamir.js';

var R = CURVE.r;                    /* the scalar field order */


/* shared with bbs.js - see commons/modp.js */
function fr_inv(a) { return inv_prime(a, R); }

/* ---------------- the setup ---------------- */

/**
 * Generate parameters. THE RETURNED SECRET MUST BE DESTROYED.
 *
 * @param  {number}   max_degree  the largest polynomial this setup can commit
 *                                to; the parameters are that many points
 * @param  {function} [rng]     n => n random bytes; omitted or null draws
 *                                fresh ones from the platform
 * @return {{g1: Array, g2: Array, max_degree, secret}}
 *
 * `secret` is returned rather than discarded internally so that a caller
 * cannot pretend the ceremony problem does not exist: seeing it in the return
 * value is a reminder that someone held it.
 */
export function setup(max_degree, rng) {
    rng = require_rng('kzg.setup', rng);
    if (max_degree < 1) { throw new Error('kzg: max_degree must be at least 1'); }
    var s = mod(bytes_to_bigint(rng(48)), CURVE.r);
    if (s === 0n) { s = 1n; }

    /* [G, sG, s^2 G, ...] - the prover's basis */
    var g1 = [];
    var p = 1n;
    for (var i = 0; i <= max_degree; i++) {
        g1.push(POINT1.mul(p, BASE1, 255));
        p = mod(p * s, CURVE.r);
    }

    /* the verifier needs only G2 and s*G2 */
    var g2 = [BASE2, POINT2.mul_ct(s, BASE2, 255)];                   /* s is the trapdoor: constant time */

    return { g1: g1, g2: g2, max_degree: max_degree, secret: s };
}

/**
 * Build a setup from published parameters - Ethereum's ceremony output, for
 * instance.
 *
 * @param {Array<Uint8Array>} g1_bytes  compressed G1 points, s^i * G
 * @param {Array<Uint8Array>} g2_bytes  compressed G2 points, [G2, s*G2]
 */
export function load_setup(g1_bytes, g2_bytes, decompress_g1, decompress_g2) {
    var g1 = [], g2 = [];
    for (var i = 0; i < g1_bytes.length; i++) {
        var a = decompress_g1(g1_bytes[i]);
        if (a === null) { throw new Error('kzg: invalid G1 parameter'); }
        g1.push(POINT1.of(a.x, a.y));
    }
    for (var j = 0; j < g2_bytes.length; j++) {
        var b = decompress_g2(g2_bytes[j]);
        if (b === null) { throw new Error('kzg: invalid G2 parameter'); }
        g2.push(POINT2.of(b.x, b.y));
    }
    return { g1: g1, g2: g2, max_degree: g1.length - 1, secret: null };
}

/* ---------------- polynomials ---------------- */

/**
 * Evaluate at z by Horner's method. `coeffs[0]` is the constant term.
 *
 * The same polynomial evaluation shamir.js performs over its own field, so it
 * comes from there rather than being written twice - the modulus is the only
 * difference and it is already a parameter.
 */
export function evaluate(coeffs, z) {
    return shamir_evaluate(coeffs, mod(z, CURVE.r), R);
}

/**
 * Divide f(X) - y by (X - z), which is exact precisely when f(z) = y.
 *
 * SYNTHETIC DIVISION, and the remainder is discarded rather than checked
 * because the caller has already computed y as f(z) - if they pass a
 * different y the quotient is simply wrong and the pairing check fails, which
 * is the correct outcome and needs no separate error path.
 */
function quotient(coeffs, z) {
    var n = coeffs.length;
    var q = new Array(n - 1);
    var acc = 0n;
    for (var i = n - 1; i >= 1; i--) {
        acc = mod(coeffs[i] + acc * z, CURVE.r);
        q[i - 1] = acc;
    }
    return q;
}

/**
 * sum(coeffs[i] * g1[i]) - the commitment, and the only expensive step.
 *
 * NOT SHARED WITH THE OTHER ACCUMULATION LOOPS in this library, of which
 * there are several - bulletproofs.js, frost.js, bls12_381.js and
 * shamir.js:combine_points all add weighted points in a loop. They differ in
 * where the weights come from and in the group, and a common version would
 * take the group, the weights, the points and the ladder width as parameters,
 * which is longer than any of the loops it replaced.
 *
 * shamir.js:combine_points IS the shared form for the case where the weights
 * are Lagrange coefficients; this one's weights are polynomial coefficients
 * and there is nothing further to factor out.
 */
function msm_g1(setup_params, coeffs) {
    if (coeffs.length > setup_params.g1.length) {
        throw new Error('kzg: polynomial degree exceeds the setup');
    }
    var s = new Array(coeffs.length);
    for (var i = 0; i < coeffs.length; i++) { s[i] = mod(coeffs[i], CURVE.r); }

    /*
     * Pippenger, from commons/fixed_window.js - 4x at degree sixteen and 9x
     * at degree two hundred and fifty-six, which is where blob commitments
     * live.
     *
     * The scalars here are the POLYNOMIAL'S COEFFICIENTS, and whether they
     * are public depends on the caller: committing to data that will be
     * published is fine, committing to something meant to stay secret is not,
     * because Pippenger's bucket pattern reveals the scalars. The commitment
     * is not hiding anyway - see the note on commit() - so a caller relying
     * on secrecy here was already mistaken.
     */
    return pippenger(G1_GROUP, s, setup_params.g1.slice(0, coeffs.length), 255);
}

/* the group interface Pippenger expects */
var G1_GROUP = /* @__PURE__ */ msm_group(POINT1);

/* ---------------- commit and open ---------------- */

/**
 * Commit to a polynomial.
 *
 * IT IS BINDING BUT NOT HIDING. C = f(s)*G is a deterministic function of f,
 * so committing to the same polynomial twice gives the same value, and an
 * adversary who guesses f can confirm it. That is fine for the usual use -
 * committing to data the verifier will eventually see - and wrong if the
 * polynomial itself must stay secret. Adding a blinding term makes it hiding,
 * at the cost of one extra setup element, and this library does not do it
 * because EIP-4844 does not.
 *
 * @return {object} a G1 point
 */
export function commit(setup_params, coeffs) {
    return msm_g1(setup_params, coeffs);
}

/**
 * Prove that f(z) = y.
 *
 * A DEGREE-1 POLYNOMIAL GIVES THE SAME PROOF AT EVERY POINT, which looks like
 * a soundness failure and is not. For f(X) = a + bX the quotient
 * (f(X) - y)/(X - z) is the constant b whatever z is, so one proof opens
 * every point - and it is honest, because it genuinely establishes all of
 * them. The scheme's binding property is about the COMMITMENT, not about
 * proofs being distinguishable.
 *
 * @return {{y: bigint, proof: object}} the claimed value and a G1 point
 */
export function open(setup_params, coeffs, z) {
    var y = evaluate(coeffs, z);
    var q = quotient(coeffs, mod(z, CURVE.r));
    return { y: y, proof: msm_g1(setup_params, q) };
}

/**
 * Check an opening.
 *
 *     e(C - y*G, G2) == e(pi, s*G2 - z*G2)
 *
 * ONE PAIRING CHECK, whatever the degree - which is what "constant time
 * verification" means for this scheme and what a Merkle proof cannot offer.
 * The pairing itself is expensive, so a KZG check is slower in absolute terms
 * than verifying a short Merkle path; it wins when the data is large or when
 * many openings are batched.
 *
 * @return {boolean}
 */
export function verify(setup_params, commitment, z, y, proof) {
    /* C - y*G */
    var lhs = POINT1.add(commitment, POINT1.neg(POINT1.mul(mod(y, CURVE.r), BASE1, 255)));
    /* s*G2 - z*G2 */
    var rhs = POINT2.add(setup_params.g2[1], POINT2.neg(POINT2.mul(mod(z, CURVE.r), setup_params.g2[0])));

    /*
     * Rearranged as a PRODUCT so that one final exponentiation serves both
     * pairings - the same saving BLS verification makes, and close to a third
     * of the cost. The equation
     *
     *     e(C - y*G, G2) == e(pi, s*G2 - z*G2)
     *
     * becomes  e(C - y*G, G2) * e(-pi, s*G2 - z*G2) == 1.
     */
    /* the Miller loop takes AFFINE points, so both sides convert first */
    var acc = PAIRING.pair_product([
        [POINT1.to_affine(lhs), POINT2.to_affine(setup_params.g2[0])],
        [POINT1.to_affine(POINT1.neg(proof)), POINT2.to_affine(rhs)]
    ]);
    return FIELD12.eq(acc, FIELD12.ONE);
}

/* ---------------- encoding ---------------- */

/** A scalar as 32 big-endian bytes. */
export function scalar_bytes(x) { return bigint_to_bytes(mod(x, CURVE.r), 32); }

export function scalar_from_bytes(b) { return mod(bytes_to_bigint(b), CURVE.r); }

/**
 * Interpolate the polynomial through a set of points.
 *
 * Needed when the data is given as EVALUATIONS rather than coefficients,
 * which is how EIP-4844 blobs arrive - a blob is 4096 field elements that are
 * the values of a polynomial on a fixed domain, not its coefficients.
 *
 * This is the naive O(n^2) Lagrange form. For the 4096-point domain Ethereum
 * uses, an FFT over the roots of unity is the practical method and is a
 * different piece of machinery; this exists so that small cases work and the
 * relationship is visible.
 *
 * @param {Array<{x: bigint, y: bigint}>} points
 */
export function interpolate(points) {
    var n = points.length;
    var coeffs = new Array(n).fill(0n);

    for (var i = 0; i < n; i++) {
        /* the basis polynomial that is 1 at x_i and 0 at every other x_j */
        var basis = [1n];
        var denom = 1n;
        for (var j = 0; j < n; j++) {
            if (j === i) { continue; }
            /* multiply by (X - x_j) */
            var next = new Array(basis.length + 1).fill(0n);
            for (var k = 0; k < basis.length; k++) {
                next[k + 1] = mod(next[k + 1] + basis[k], CURVE.r);
                next[k] = mod(next[k] - basis[k] * points[j].x, CURVE.r);
            }
            basis = next;
            denom = mod(denom * (points[i].x - points[j].x), CURVE.r);
        }
        var scale = mod(points[i].y * fr_inv(denom), CURVE.r);
        for (var m = 0; m < basis.length; m++) {
            coeffs[m] = mod(coeffs[m] + basis[m] * scale, CURVE.r);
        }
    }
    return coeffs;
}
