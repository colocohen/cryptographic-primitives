/**
 * Point arithmetic on twisted Edwards curves: a*x^2 + y^2 = 1 + d*x^2*y^2
 *
 * Covers Ed25519 (a = -1) and Ed448 (a = 1). Points are carried in extended
 * coordinates (X : Y : Z : T) where the affine point is (X/Z, Y/Z) and
 * T = XY/Z. Keeping T around costs one field element and removes a
 * multiplication from every addition.
 *
 * WHY EDWARDS CURVES ARE PLEASANT
 * The Weierstrass addition law has exceptional cases that had to be worked
 * around with the Renes-Costello-Batina formulas, at a cost in
 * multiplications. On a twisted Edwards curve with a square and d non-square
 * - which is exactly the case for both curves here - the ORDINARY addition
 * formula is already complete. There is no special case for P + P, for
 * P + (-P), or for the identity, and no penalty was paid to get that.
 *
 * The identity is (0 : 1 : 1 : 0), the affine point (0, 1). Note that it is
 * an ordinary point with real coordinates, not a point at infinity - another
 * reason the formulas have nothing to branch on.
 *
 * This is also why Ed25519 signing is faster than ECDSA on a comparable
 * curve, quite apart from avoiding the modular inversion.
 */

import { cselect, batch_invert } from './modp.js';
import { window_mul } from './fixed_window.js';
import { bigint_to_bytes_le, bytes_to_bigint_le } from './bytes.js';

/**
 * @param {object} F  the field
 * @param {bigint} a  the twist coefficient: -1 for Ed25519, 1 for Ed448
 * @param {bigint} d
 */
export function edwards(F, a, d) {
    var d2 = F.mul(d, 2n);
    /*
     * ⭐ a·A FOR FREE when a is ±1 (Ed25519's −1, Ed448's 1): a negation or
     *    nothing, not a multiplication — one in every addition and doubling.
     */
    var A_IS = F.mod(a) === F.neg(1n) ? -1 : F.mod(a) === 1n ? 1 : 0;
    function mul_a(x) { return A_IS === -1 ? F.neg(x) : A_IS === 1 ? x : F.mul(a, x); }

    /**
     * What dbl and dbl_partial share: the terms of the doubling (Hisil et al.
     * dbl-2008-hwcd), which reads X, Y, Z and not T.
     */
    function dbl_terms(P) {
        var ad = F.add, s = F.sub, sq = F.sqr;
        /*
         * ⭐ THE SUM INSIDE THE SQUARING IS DENORMALIZED. sqr reduces, so
         *   (X+Y)^2 mod p is the same whether X+Y was reduced first - and
         *   doubling runs once per scalar bit, so this is the hottest
         *   addition in the library.
         *
         * ⚠ EVERYTHING ELSE STAYS NORMALIZED. G, Ff and H become
         *   coordinates of the result, and a denormalized coordinate
         *   grows on every doubling until the operands are large enough
         *   that the multiplications cost more than the reductions saved.
         */
        var A = sq(P.X);
        var B = sq(P.Y);
        var Cc = F.dbl(sq(P.Z));
        var D = mul_a(A);
        var E = s(s(sq(ad(P.X, P.Y)), A), B);
        var G = ad(D, B);
        return { E: E, G: G, Ff: s(G, Cc), H: s(D, B) };
    }

    var C = {
        F: F,
        a: a,
        d: d,

        /** The identity is the affine point (0, 1). */
        ZERO: { X: 0n, Y: 1n, Z: 1n, T: 0n },

        of: function (x, y) {
            return { X: x, Y: y, Z: 1n, T: F.mul(x, y) };
        },

        neg: function (P) {
            return { X: F.neg(P.X), Y: P.Y, Z: P.Z, T: F.neg(P.T) };
        },

        /**
         * Extended twisted Edwards addition, Hisil-Wong-Carter-Dawson 2008.
         *
         * Complete for every pair of points on these curves. Nine
         * multiplications, no conditionals, no exceptional inputs.
         */
        add: function (P, Q) {
            var m = F.mul, ad = F.add, s = F.sub;
            /*
             * ⭐ DENORMALIZED WHERE THE RESULT FEEDS A MULTIPLICATION.
             *
             *   `mul` reduces, so an operand slightly above p gives the same
             *   product - and skipping the conditional reduction is worth
             *   117 ns against 50 per operation, ten times per addition.
             *
             * ⚠ ONLY THE SUMS THAT GO STRAIGHT INTO A MULTIPLY use addN.
             *   E, Ff, G and H are also RETURNED as coordinates through
             *   further multiplications, so they stay normalized - a
             *   denormalized coordinate would grow on every point addition
             *   and the operands would get slower, not faster.
             */

            var A = m(P.X, Q.X);
            var B = m(P.Y, Q.Y);
            var Cc = m(m(P.T, d), Q.T);
            var D = m(P.Z, Q.Z);
            /* both sums are consumed by the multiply on the same line */
            var E = s(s(m(ad(P.X, P.Y), ad(Q.X, Q.Y)), A), B);
            var Ff = s(D, Cc);
            var G = ad(D, Cc);
            var H = s(B, mul_a(A));

            return {
                X: m(E, Ff),
                Y: m(G, H),
                T: m(E, H),
                Z: m(Ff, G)
            };
        },

        /*
         * ⭐ CACHED POINTS, for a table built once (fixed_window.fixed_base):
         *    affine (Z = 1) with T·d precomputed, so adding one costs two
         *    multiplications fewer than add (D = Z₁, no ·d) — and a cached
         *    point is three coordinates to scan, not four.
         */
        cache: function (points) {
            var zi = batch_invert(points.map(function (P) { return P.Z; }), F.mul, F.inv, 1n);
            return points.map(function (P, i) {
                var x = F.mul(P.X, zi[i]), y = F.mul(P.Y, zi[i]);
                return { X: x, Y: y, Td: F.mul(F.mul(x, y), d) };
            });
        },
        /** P + Q for Q cached: the same formula as add with Z₂ = 1 and T₂·d given. */
        add_cached: function (P, Q) {
            var m = F.mul, ad = F.add, s = F.sub;
            var A = m(P.X, Q.X);
            var B = m(P.Y, Q.Y);
            var Cc = m(P.T, Q.Td);
            var D = P.Z;
            var E = s(s(m(ad(P.X, P.Y), ad(Q.X, Q.Y)), A), B);
            var Ff = s(D, Cc);
            var G = ad(D, Cc);
            var H = s(B, mul_a(A));
            return { X: m(E, Ff), Y: m(G, H), T: m(E, H), Z: m(Ff, G) };
        },
        cselect_cached: function (bit, P, Q) {
            return { X: cselect(bit, P.X, Q.X), Y: cselect(bit, P.Y, Q.Y), Td: cselect(bit, P.Td, Q.Td) };
        },
        /** −Q for Q cached, variable time (verification's tables). */
        neg_cached: function (P) { return { X: F.neg(P.X), Y: P.Y, Td: F.neg(P.Td) }; },
        /** −Q for Q cached: x and x·y·d change sign. */
        cneg_cached: function (bit, P) {
            return { X: cselect(bit, F.neg(P.X), P.X), Y: P.Y, Td: cselect(bit, F.neg(P.Td), P.Td) };
        },

        /**
         * Doubling without T — for a doubling that another doubling follows
         * (fixed_window.wnaf_sum): doubling reads X, Y, Z only, so T is
         * needed only before an addition. One multiplication fewer.
         */
        dbl_partial: function (P) {
            var q = dbl_terms(P), m = F.mul;
            return { X: m(q.E, q.Ff), Y: m(q.G, q.H), T: null, Z: m(q.Ff, q.G) };
        },

        /**
         * Doubling, which does not need T of the input and so is cheaper than
         * a general addition - four squarings instead of nine multiplications.
         */
        dbl: function (P) {
            var q = dbl_terms(P), m = F.mul;
            return { X: m(q.E, q.Ff), Y: m(q.G, q.H), T: m(q.E, q.H), Z: m(q.Ff, q.G) };
        },

        /** P when bit is 1, Q when 0 — every coordinate, by mask (fixed_window's scan). */
        cselect: function (bit, P, Q) {
            return { X: cselect(bit, P.X, Q.X), Y: cselect(bit, P.Y, Q.Y), Z: cselect(bit, P.Z, Q.Z), T: cselect(bit, P.T, Q.T) };
        },
        /** −P when bit is 1, P when 0: X and T negated by mask. */
        cneg: function (bit, P) {
            return { X: cselect(bit, F.neg(P.X), P.X), Y: P.Y, Z: P.Z, T: cselect(bit, F.neg(P.T), P.T) };
        },

        /**
         * Constant-time scalar multiplication over a fixed number of bits, so
         * that the scalar's magnitude does not leak: a SIGNED FIXED WINDOW
         * (fixed_window.window_mul). It replaced the Montgomery ladder (11-11):
         * the same doublings, but one addition per four bits instead of one
         * per bit — 1.85 to 1.02 ms on ristretto255 — and still a fixed
         * sequence of operations and table scans, whatever the scalar.
         */
        mul: function (k, P, bits) { return window_mul(C, k, P, bits, 4); },

        /**
         * Unsafe scalar multiplication - variable time, for PUBLIC scalars
         * only.
         *
         * Verification multiplies by values an attacker already knows, so
         * uniformity buys nothing there and costs a factor of two. Signing
         * must never call this.
         */
        mul_unsafe: function (k, P) {
            var R = C.ZERO, base = P, n = k;
            while (n > 0n) {
                if (n & 1n) { R = C.add(R, base); }
                base = C.dbl(base);
                n >>= 1n;
            }
            return R;
        },

        /* a point from a secret scalar: its Z is inverted BLINDED (modp inv_blinded) — constant time, a tenth of Fermat */
        to_affine: function (P) {
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
            var iz = F.inv_vartime(P.Z);
            return { x: F.mul(P.X, iz), y: F.mul(P.Y, iz) };
        },


        eq: function (P, Q) {
            /* compare projectively rather than inverting twice */
            return F.mul(P.X, Q.Z) === F.mul(Q.X, P.Z) &&
                   F.mul(P.Y, Q.Z) === F.mul(Q.Y, P.Z);
        },

        is_on_curve: function (x, y) {
            var x2 = F.sqr(x), y2 = F.sqr(y);
            var lhs = F.add(F.mul(a, x2), y2);
            var rhs = F.add(1n, F.mul(F.mul(d, x2), y2));
            return lhs === rhs;
        }
    };
    return C;
}

/**
 * Membership in the prime-order subgroup of order L: [L]P == identity.
 *
 * ⭐ ONE CHECK FOR EVERY EDWARDS CURVE WITH A COFACTOR. ed25519, ed448 and
 *   babyjubjub each wrote it out - the first two identically, the third
 *   through the constant-time ladder at a fixed width. L is a public
 *   constant and P is a point that arrived from outside, so the variable-time
 *   multiply is the right one and roughly twice as fast.
 *
 * @return {function} (P) -> boolean
 */
export function subgroup_check(C, L) {
    return function (P) { return C.eq(C.mul_unsafe(L, P), C.ZERO); };
}

/**
 * The "y and a sign bit" encoding of an Edwards point, for curves whose field
 * needs Tonelli-Shanks to decompress.
 *
 *     32 bytes: y little-endian, and the top bit says which of x and -x
 *
 * ⭐ ONE DECODER FOR THE EMBEDDED CURVES. Baby Jubjub and Jubjub both encode
 *   this way, over fields that are 1 mod 2^28 or more (BN254's and
 *   BLS12-381's scalar fields), where none of sqrt_ratio's closed forms
 *   apply. They differ in exactly two places, and both are parameters:
 *
 *     sign    WHICH bit of x is stored. 'parity' is x's low bit - Ed25519's
 *             rule, and Jubjub's (repr_J). 'half' is "x > p/2" - circomlib's,
 *             and Baby Jubjub's. Both pick between x and -x; they disagree on
 *             about four in ten points, so choosing wrong round-trips
 *             perfectly with itself and with nothing else.
 *
 *     strict  refuse x = 0 with the sign bit set. x = 0 is its own negation,
 *             so that bit pattern names the same point as the one with the
 *             bit clear - a second encoding. ZIP 216 made Jubjub refuse it
 *             (it had been accepted, for (0, 1) and (0, -1)); Baby Jubjub's
 *             circomlib never checked, and this does not start to.
 *
 * ⚠ DECODE IS VARIABLE TIME, through the field's sqrt_vartime. A point being
 *   decoded arrived from outside and is public; never decode a secret here.
 *
 * ⚠ NOTHING ABOUT THE SUBGROUP. This answers "is it on the curve"; a caller
 *   that will multiply the point by a secret checks the subgroup itself.
 *
 * @param {object} C     an edwards() curve
 * @param {object} opts  { sign: 'parity' | 'half', strict: boolean }
 * @return {{ encode: function(P): Uint8Array, decode: function(Uint8Array): (object|null) }}
 */
export function y_sign_codec(C, opts) {
    var F = C.F, HALF = F.p >> 1n;
    var negative = opts.sign === 'half'
        ? function (x) { return x > HALF; }
        : function (x) { return (x & 1n) === 1n; };
    return {
        encode: function (P) {
            var A = C.to_affine(P);
            var out = bigint_to_bytes_le(A.y, 32);
            if (negative(A.x)) { out[31] |= 0x80; }
            return out;
        },
        decode: function (b) {
            if (!b || b.length !== 32) { return null; }
            var sign = (b[31] & 0x80) !== 0;
            var copy = new Uint8Array(b);
            copy[31] &= 0x7f;
            var y = bytes_to_bigint_le(copy);
            if (y >= F.p) { return null; }
            /* x^2 = (y^2 - 1) / (d*y^2 - a) */
            var y2 = F.sqr(y);
            var den = F.sub(F.mul(C.d, y2), C.a);
            if (den === 0n) { return null; }
            var x = F.sqrt_vartime(F.mul(F.sub(y2, 1n), F.inv(den)));
            if (x === null) { return null; }
            if (x === 0n && sign && opts.strict) { return null; }
            if (negative(x) !== sign) { x = F.neg(x); }
            return C.of(x, y);
        }
    };
}

/**
 * The p = 5 mod 8 candidate for sqrt(u/v): u*v^3 * (u*v^7)^((p-5)/8).
 *
 * It is a square root of u/v, or of -u/v, or off by sqrt(-1) - the caller
 * decides which by checking v*x^2 against u. sqrt_ratio below and
 * ristretto255's SQRT_RATIO_M1 both start here and then classify the result
 * differently: one returns null for a non-square, the other must return a
 * defined value there. The candidate itself was written out in both.
 */
export function sqrt_ratio_candidate(F, u, v) {
    var v3 = F.mul(F.sqr(v), v);
    var v7 = F.mul(F.sqr(v3), v);
    return F.mul(F.mul(u, v3), F.pow(F.mul(u, v7), (F.p - 5n) / 8n));
}

/**
 * Square root of u/v, for point decompression.
 *
 * Written as a ratio rather than as inv-then-sqrt because that is how
 * RFC 8032 specifies it and because it saves an inversion - the expensive
 * field operation - on the decoding path, which verification runs for every
 * signature.
 *
 * @param {number} mode  8 for p = 5 mod 8 (Ed25519), 4 for p = 3 mod 4 (Ed448)
 * @return {bigint|null} null when u/v is not a square
 */
export function sqrt_ratio(F, u, v, mode) {
    var p = F.p;
    var x;

    if (mode === 8) {
        /*
         * p = 5 mod 8. The candidate is (u/v)^((p+3)/8), and it may be off by
         * a factor of sqrt(-1) - which is why the check below is not optional
         * and why a naive "take a square root" gets Ed25519 decoding wrong
         * for half of all inputs.
         */
        x = sqrt_ratio_candidate(F, u, v);

        var check = F.mul(v, F.sqr(x));
        if (check === u) { return x; }
        if (check === F.neg(u)) {
            /*
             * ⭐ THE FIELD'S OWN CONSTANT, through its named method. This used
             *   to compute and cache sqrt(-1) here, independently of the copy
             *   in modp.js - two caches of the same value, and a divergence
             *   between them would give a square root that squares to the
             *   negative of its input.
             */
            var i = F.sqrt_of_neg_one();
            return F.mul(x, i);
        }
        return null;
    }

    /*
     * p = 3 mod 4: one exponentiation of u/v, which is exactly the field's
     * own sqrt for this shape of prime - the same (p+1)/4 power and the same
     * squaring check. It was written out here a second time.
     */
    return F.sqrt(F.mul(u, F.inv(v)));
}
