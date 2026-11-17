/**
 * Point arithmetic on short Weierstrass curves: y^2 = x^3 + ax + b
 *
 * Covers secp256k1 (a = 0), the NIST P-curves (a = -3), and the Brainpool
 * family. Points are carried in homogeneous projective coordinates (X : Y : Z)
 * where the affine point is (X/Z, Y/Z), because inversion is the expensive
 * field operation and projective arithmetic needs none until the very end.
 *
 * COMPLETE FORMULAS, AND WHY
 * The textbook addition law has exceptional cases: adding a point to itself,
 * adding a point to its negation, and anything involving the point at
 * infinity all need different formulas. Every one of those is an `if` on
 * data, and in a scalar multiplication that data is derived from the private
 * key.
 *
 * The formulas below are Renes-Costello-Batina (2015). They are COMPLETE:
 * one straight-line sequence that is correct for every pair of inputs on the
 * curve, including the identity and including P + P. There is no branch to
 * remove because there was never a branch. That costs a handful of extra
 * multiplications and buys correctness and constant time together.
 *
 * The identity element is any point with Z = 0; the canonical one is
 * (0 : 1 : 0). It falls out of the formulas rather than being special-cased.
 *
 * ---------------------------------------------------------------------------
 * PERFORMANCE - WHAT WAS DONE, AND WHAT IS LEFT.
 *
 * The two optimisations predicted here were applied and measured against
 * @noble/curves, which is also pure JS and also BigInt-based. Median of seven
 * runs, per operation:
 *
 *                        before    after    noble
 *     ed25519 keygen      3.25      0.41     0.37
 *     ed25519 sign        4.82      0.41     0.58     (public key supplied)
 *     ed25519 verify      4.96      2.14     2.00
 *     secp256k1 sign      4.60      0.67     0.53
 *     secp256k1 verify    6.65      2.81     2.30
 *     p256 verify         8.06      3.34     3.65
 *
 * WHAT WORKED, and by how much:
 *
 *   1. A FIXED-BASE TABLE for the generator - commons/fixed_window.js. This
 *      was the large one: 9x on a single scalar multiplication, because the
 *      doublings vanish entirely rather than merely being batched. The
 *      prediction that it "applies only to key generation and signing" was
 *      right, and those are most of what a signing library does.
 *
 *   2. A FIXED WINDOW for arbitrary points. 1.7x at w = 5, close to the
 *      1.5-2x predicted.
 *
 *   3. NOT PREDICTED, AND WORTH AS MUCH AS EITHER: a VARIABLE-TIME INVERSE
 *      for points that are about to be published. F.inv uses Fermat for
 *      constant time and costs 0.19 ms; binary extended Euclid costs 0.06 ms,
 *      and every to_affine on a public key or a signature component can use
 *      it safely. That was a quarter of the cost of an Ed25519 signature,
 *      hiding in a function nobody thought of as expensive.
 *
 *   4. ALSO NOT PREDICTED: Shamir's trick for verification, and letting a
 *      caller supply a public key it already has rather than re-deriving it.
 *      The second is not an optimisation of the arithmetic at all - it is an
 *      API observation - and it halved signing.
 *
 * WHAT IS LEFT, in order of expected value:
 *
 *   - SPECIALISED MODULAR REDUCTION WAS TRIED AND LOST. It is the obvious
 *     next step and it makes things slower in JavaScript; the measurements
 *     and the reason are recorded in commons/modp.js so that nobody spends
 *     the afternoon again.
 *
 *   - THE GLV ENDOMORPHISM for secp256k1. Its efficiently computable
 *     endomorphism splits a 256-bit scalar into two 128-bit halves, halving
 *     the doublings. Worth about 1.4x on verification, and secp256k1 only.
 *
 * The earlier note that "this project has a record of performance guesses
 * being wrong in both directions" held up: the two predicted items delivered
 * roughly as expected, and the two largest remaining wins were things nobody
 * had written down.
 * ---------------------------------------------------------------------------
 */

import { cselect, ceq } from './modp.js';
import { window_mul } from './fixed_window.js';

/**
 * @param {object} F      the field, from modp.js
 * @param {bigint} a, b   the curve coefficients
 */
export function weierstrass(F, a, b) {
    var b3 = F.mul(b, 3n);

    var C = {
        F: F,
        a: a,
        b: b,

        /** The identity, (0 : 1 : 0). */
        ZERO: { X: 0n, Y: 1n, Z: 0n },

        of: function (x, y) { return { X: x, Y: y, Z: 1n }; },

        is_zero: function (P) { return ceq(P.Z, 0n); },

        neg: function (P) { return { X: P.X, Y: F.neg(P.Y), Z: P.Z }; },

        /**
         * Renes-Costello-Batina algorithm 1: complete addition for any a.
         *
         * Seventeen multiplications and no conditionals. The specialised
         * versions for a = 0 and a = -3 are shorter, but this one is correct
         * for every curve here and the difference is not where the time goes.
         */
        add: function (P, Q) {
            var X1 = P.X, Y1 = P.Y, Z1 = P.Z;
            var X2 = Q.X, Y2 = Q.Y, Z2 = Q.Z;
            var m = F.mul, ad = F.add, s = F.sub;

            var t0 = m(X1, X2);
            var t1 = m(Y1, Y2);
            var t2 = m(Z1, Z2);
            var t3 = ad(X1, Y1);
            var t4 = ad(X2, Y2);
            t3 = m(t3, t4);
            t4 = ad(t0, t1);
            t3 = s(t3, t4);
            t4 = ad(X1, Z1);
            var t5 = ad(X2, Z2);
            t4 = m(t4, t5);
            t5 = ad(t0, t2);
            t4 = s(t4, t5);
            t5 = ad(Y1, Z1);
            var X3 = ad(Y2, Z2);
            t5 = m(t5, X3);
            X3 = ad(t1, t2);
            t5 = s(t5, X3);
            var Z3 = m(a, t4);
            X3 = m(b3, t2);
            Z3 = ad(X3, Z3);
            X3 = s(t1, Z3);
            Z3 = ad(t1, Z3);
            var Y3 = m(X3, Z3);
            t1 = ad(t0, t0);
            t1 = ad(t1, t0);
            t2 = m(a, t2);
            t4 = m(b3, t4);
            t1 = ad(t1, t2);
            t2 = s(t0, t2);
            t2 = m(a, t2);
            t4 = ad(t4, t2);
            t0 = m(t1, t4);
            Y3 = ad(Y3, t0);
            t0 = m(t5, t4);
            X3 = m(t3, X3);
            X3 = s(X3, t0);
            t0 = m(t3, t1);
            Z3 = m(t5, Z3);
            Z3 = ad(Z3, t0);

            return { X: X3, Y: Y3, Z: Z3 };
        },

        /** Doubling is the same complete formula applied to one point. */
        dbl: function (P) { return C.add(P, P); },

        /** P when bit is 1, Q when 0 — every coordinate, by mask (fixed_window's scan). */
        cselect: function (bit, P, Q) {
            return { X: cselect(bit, P.X, Q.X), Y: cselect(bit, P.Y, Q.Y), Z: cselect(bit, P.Z, Q.Z) };
        },
        /** −P when bit is 1, P when 0: Y negated by mask. */
        cneg: function (bit, P) {
            return { X: P.X, Y: cselect(bit, F.neg(P.Y), P.Y), Z: P.Z };
        },

        /**
         * Constant-time scalar multiplication: a SIGNED FIXED WINDOW
         * (fixed_window.window_mul). It replaced the Montgomery ladder (11-11):
         * the same doublings, one addition per four bits instead of one per
         * bit, and still a fixed sequence of operations and table scans,
         * whatever the scalar. The loop runs over a FIXED number of bits -
         * using the scalar's actual bit length would leak its magnitude.
         *
         * @param {bigint} k     the scalar
         * @param {object} P     the point
         * @param {number} bits  fixed iteration count, normally the order's
         *                       bit length
         */
        mul: function (k, P, bits) { return window_mul(C, k, P, bits, 4); },

        /**
         * Scalar multiplication with the scalar blinded.
         *
         * k' = k + r*n multiplies to the same point, since n*P is the
         * identity, but the bits actually processed are randomised. That
         * defends against leaks the constant-time discipline does not cover -
         * including the one this library cannot fix, that V8's BigInt
         * operations are themselves sized to their operands.
         *
         * @param {bigint} n  the group order
         * @param {bigint} r  fresh randomness, from the caller
         */
        mul_blinded: function (k, P, n, r, bits) {
            return C.mul(k + r * n, P, bits);
        },

        /** Back to affine coordinates - one inversion, done once. */
        /* a point from a secret scalar: its Z is inverted BLINDED (modp inv_blinded) — constant time, a tenth of Fermat */
        to_affine: function (P) {
            if (P.Z === 0n) { return null; }
            var iz = F.inv_blinded ? F.inv_blinded(P.Z) : F.inv(P.Z);
            return { x: F.mul(P.X, iz), y: F.mul(P.Y, iz) };
        },
        /**
         * The same, for a point that is PUBLIC.
         *
         * Uses the variable-time inverse - see commons/modp.js. Correct
         * wherever the point is about to be encoded and sent, which is every
         * public key, every signature component, and every verifier-side
         * reconstruction. Never for a shared secret or an intermediate that
         * depends on one.
         */
        to_affine_public: function (P) {
            if (P.Z === 0n) { return null; }
            var iz = F.inv_vartime(P.Z);
            return { x: F.mul(P.X, iz), y: F.mul(P.Y, iz) };
        },


        /** Convert several points with one inversion - see F.inv_batch. */
        to_affine_batch: function (points) {
            var zs = points.map(function (P) { return P.Z === 0n ? 1n : P.Z; });
            var izs = F.inv_batch(zs);
            return points.map(function (P, i) {
                if (P.Z === 0n) { return null; }
                return { x: F.mul(P.X, izs[i]), y: F.mul(P.Y, izs[i]) };
            });
        },

        /**
         * Is the affine point on the curve?
         *
         * Checking this on every point that arrives from outside is not
         * optional. Feeding a point from a different, weaker curve into a
         * scalar multiplication leaks the scalar - the invalid-curve attack -
         * and the only defence is to reject the point up front.
         */
        is_on_curve: function (x, y) {
            var lhs = F.sqr(y);
            var rhs = F.add(F.add(F.mul(F.sqr(x), x), F.mul(a, x)), b);
            return lhs === rhs;
        },

        /** Recover y from x and one bit of sign - point decompression. */
        decompress: function (x, y_is_odd) {
            var rhs = F.add(F.add(F.mul(F.sqr(x), x), F.mul(a, x)), b);
            var y = F.sqrt(rhs);
            if (y === null) { return null; }
            var odd = (y & 1n) === 1n;
            return odd === !!y_is_odd ? y : F.neg(y);
        }
    };
    return C;
}
