/**
 * Extension field arithmetic: Fp2, Fp6, Fp12
 *
 * Needed by pairing-friendly curves and by nothing else in this library.
 * BLS12-381 is the reason it exists.
 *
 * WHY A TOWER RATHER THAN ONE BIG FIELD
 * Fp12 could be defined directly as Fp[x]/(degree-12 polynomial), but
 * multiplying two such elements costs 144 base multiplications. Building it
 * as Fp2 -> Fp6 -> Fp12, each step a small extension of the last, brings that
 * down to about 54 through Karatsuba at every level. Pairings perform tens of
 * thousands of these, so the tower is not an optimisation - it is the
 * difference between practical and not.
 *
 * The tower for BLS12-381:
 *
 *     Fp2  = Fp[u]  / (u^2 + 1)          u is a square root of -1
 *     Fp6  = Fp2[v] / (v^3 - (u + 1))    v is a cube root of u+1
 *     Fp12 = Fp6[w] / (w^2 - v)          w is a square root of v
 *
 * Every element is an array of the level below: an Fp12 value is two Fp6
 * values, each of which is three Fp2 values, each of which is two BigInts.
 * Twelve BigInts in a nested shape that mirrors the algebra.
 *
 * THE NON-RESIDUE u+1 IS LOAD-BEARING. Reduction at each level replaces the
 * top coefficient by a multiple of it, so a fast multiplication by u+1 makes
 * every multiplication above it faster. It was chosen for BLS12-381 partly
 * for that reason.
 */

/**
 * Build Fp2 = Fp[u]/(u^2 + 1).
 *
 * @param {object} F  the base field, from modp.js
 */
/**
 * @param {object} F     the prime field
 * @param {Array}  [xi]  the non-residue [a, b] meaning a + b*u; defaults to
 *                       1 + u, which is bls12-381's
 *
 * THE NON-RESIDUE IS A PARAMETER, and it is not cosmetic. Fp6 is Fp2[v] with
 * v^3 = xi, so changing it changes the field itself. bls12-381 uses 1 + u and
 * bn254 uses 9 + u; a tower built with the wrong one produces arithmetic that
 * is internally consistent and describes a different field, which is why a
 * pairing built on it runs and is not bilinear.
 *
 * That cost five wrong attempts here, all of them looking for a sign or a
 * coefficient position, before the tower itself was checked.
 */
import { batch_invert } from './modp.js';

export function fp2_field(F, xi) {
    var XI_A = xi ? xi[0] : 1n;
    var XI_B = xi ? xi[1] : 1n;

    var Fp2 = {
        ZERO: [0n, 0n],
        ONE: [1n, 0n],

        of: function (a, b) { return [F.mod(a), F.mod(b === undefined ? 0n : b)]; },

        eq: function (a, b) { return a[0] === b[0] && a[1] === b[1]; },
        is_zero: function (a) { return a[0] === 0n && a[1] === 0n; },

        add: function (a, b) { return [F.add(a[0], b[0]), F.add(a[1], b[1])]; },
        sub: function (a, b) { return [F.sub(a[0], b[0]), F.sub(a[1], b[1])]; },
        neg: function (a) { return [F.neg(a[0]), F.neg(a[1])]; },
        dbl: function (a) { return [F.dbl(a[0]), F.dbl(a[1])]; },

        /**
         * Karatsuba: three base multiplications rather than four.
         *
         * (a0 + a1*u)(b0 + b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u,
         * and the cross terms come from one extra product of the sums.
         */
        mul: function (a, b) {
            var t0 = F.mul(a[0], b[0]);
            var t1 = F.mul(a[1], b[1]);
            var t2 = F.mul(F.add(a[0], a[1]), F.add(b[0], b[1]));
            return [F.sub(t0, t1), F.sub(t2, F.add(t0, t1))];
        },

        /** Squaring is cheaper still: two base multiplications. */
        sqr: function (a) {
            var s = F.add(a[0], a[1]);
            var d = F.sub(a[0], a[1]);
            return [F.mul(s, d), F.dbl(F.mul(a[0], a[1]))];
        },

        /** Multiply by a base-field scalar. */
        mul_scalar: function (a, k) { return [F.mul(a[0], k), F.mul(a[1], k)]; },

        /** The Frobenius conjugate: u -> -u. */
        conj: function (a) { return [a[0], F.neg(a[1])]; },

        /**
         * The inverse. The norm a0^2 + a1^2 lives in the BASE field, so this
         * needs only one base-field inversion.
         */
        inv: function (a) {
            var n = F.add(F.sqr(a[0]), F.sqr(a[1]));
            var ni = F.inv(n);
            return [F.mul(a[0], ni), F.neg(F.mul(a[1], ni))];
        },

        /**
         * The inverses of many values, for the price of one inversion.
         *
         * ⭐ MONTGOMERY'S TRICK. Running products go forward, one inversion of
         *   the total, then the individual inverses fall out walking back:
         *
         *       acc[i] = v[0]*...*v[i-1]
         *       t      = 1 / (v[0]*...*v[n-1])
         *       inv[i] = t * acc[i],  then t *= v[i]
         *
         *   n inversions become 1 inversion and 3n multiplications. An
         *   inversion here is Fermat - hundreds of squarings - against a
         *   multiplication that is one BigInt multiply and a modulo, so the
         *   trade is overwhelming for any n above one.
         *
         * ⛔ A ZERO ANYWHERE POISONS EVERY RESULT, not just its own. The
         *   running product becomes zero and all n outputs come back zero,
         *   where `inv` alone would have returned zero for the zero and
         *   correct values for the rest.
         *
         * ⚠ IT DOES NOT THROW, matching modp's inv_batch and modp's inv -
         *   which return zero rather than throwing because throwing on a
         *   secret value is itself a timing signal. The caller must not hand
         *   it a zero, which for projective Z-coordinates means not handing
         *   it the point at infinity.
         *
         * ⚠ AND IT IS AS VARIABLE-TIME AS `inv` IS. It inherits whatever the
         *   single inversion does; it adds no new leak and removes none.
         */
        inv_batch: function (values) {
            return batch_invert(values, Fp2.mul, Fp2.inv, Fp2.ONE);
        },


        /**
         * The same inverse, through the base field's variable-time routine.
         *
         * ⛔ NOT CONSTANT TIME. The name says so, and the choice belongs to
         *   the caller: the two return identical values and differ only in
         *   timing, so picking the wrong one gives correct answers and a
         *   side channel that no test will find.
         *
         * ⭐ THE PAIRING IS WHAT THIS IS FOR. Its inputs are public points -
         *   a signature and a public key - and the Miller loop does one Fp2
         *   inversion per iteration. Measured: 64 of them were 41 ms of a
         *   53 ms loop, and Fermat's inverse is 25x slower than Euclid's on
         *   this field.
         */
        inv_vartime: function (a) {
            var n = F.add(F.sqr(a[0]), F.sqr(a[1]));
            var ni = F.inv_vartime ? F.inv_vartime(n) : F.inv(n);
            return [F.mul(a[0], ni), F.neg(F.mul(a[1], ni))];
        },

        /** Multiplication by the non-residue, used by Fp6 reduction. */
        mul_nonres: XI_A === 1n && XI_B === 1n
            /* the 1 + u case, written out: (a0 - a1) + (a0 + a1)u */
            ? function (a) { return [F.sub(a[0], a[1]), F.add(a[0], a[1])]; }
            /* the general case: (a0 + a1 u)(xa + xb u) */
            : function (a) {
                return [
                    F.sub(F.mul(a[0], XI_A), F.mul(a[1], XI_B)),
                    F.add(F.mul(a[0], XI_B), F.mul(a[1], XI_A))
                ];
            },

        pow: function (a, e) {
            var r = Fp2.ONE, base = a, n = e;
            while (n > 0n) {
                if (n & 1n) { r = Fp2.mul(r, base); }
                base = Fp2.sqr(base);
                n >>= 1n;
            }
            return r;
        },

        /**
         * Square root in Fp2, for point decompression on G2.
         * Only defined for p = 3 mod 4, which BLS12-381 satisfies.
         */
        /**
         * A square root in Fp2.
         *
         * ⭐ THE COMPLEX METHOD when p = 3 mod 4: the work moves into Fp,
         *   where an exponentiation costs half what the same one costs in
         *   Fp2 - three base multiplications per Fp2 multiplication.
         *
         *       norm  = a0^2 + a1^2                  in Fp
         *       gamma = sqrt(norm)                   one Fp exponentiation
         *       delta = (a0 +/- gamma)/2
         *       x0    = sqrt(delta)                  second Fp exponentiation
         *       x1    = a1 / (2 x0)
         *
         *   2.80 ms to 1.93, and hash_to_g2 calls it twice.
         *
         * ⚠ delta HAS TWO CANDIDATES and only one is a square. Taking the
         *   first without checking gives null for half of all valid inputs -
         *   which looks like "this element has no square root" rather than
         *   like a bug.
         *
         * ⚠ THE GENERAL PATH BELOW IS STILL THERE for p = 1 mod 4, where the
         *   complex method does not apply. It is not dead code: fp2_field is
         *   built over whatever prime the caller supplies.
         */
        sqrt: function (a) {
            var p = F.p;

            if ((p & 3n) === 3n) {
                /* the base field's own sqrt: for p = 3 mod 4 it is this same
                   (p+1)/4 power with the same squaring check, which used to
                   be written out here as a local closure */
                var fsqrt = F.sqrt;
                var c0 = a[0], c1 = a[1];
                if (c1 === 0n) {
                    var s = fsqrt(c0);
                    if (s !== null) { return [s, 0n]; }
                    var s2 = fsqrt(F.neg(c0));
                    return s2 === null ? null : [0n, s2];
                }
                var half = F._half || (F._half = F.inv(2n));
                var norm = F.add(F.mul(c0, c0), F.mul(c1, c1));
                var gamma = fsqrt(norm);
                if (gamma === null) { return null; }
                var delta = F.mul(F.add(c0, gamma), half);
                var x0 = fsqrt(delta);
                if (x0 === null) {
                    delta = F.mul(F.sub(c0, gamma), half);
                    x0 = fsqrt(delta);
                    if (x0 === null) { return null; }
                }
                return [x0, F.mul(c1, F.inv(F.add(x0, x0)))];
            }

            var a1 = Fp2.pow(a, (p - 3n) / 4n);
            var alpha = Fp2.mul(Fp2.sqr(a1), a);
            var x0 = Fp2.mul(a1, a);
            if (Fp2.eq(alpha, [F.neg(1n), 0n])) {
                return [F.neg(x0[1]), x0[0]];
            }
            var b = Fp2.pow(Fp2.add(Fp2.ONE, alpha), (p - 1n) / 2n);
            var r = Fp2.mul(b, x0);
            return Fp2.eq(Fp2.sqr(r), a) ? r : null;
        },

        F: F
    };
    return Fp2;
}

/**
 * Build Fp6 = Fp2[v]/(v^3 - (u+1)).
 *
 * Elements are [c0, c1, c2] with c_i in Fp2, meaning c0 + c1*v + c2*v^2.
 */
export function fp6_field(Fp2) {
    var Fp6 = {
        ZERO: [Fp2.ZERO, Fp2.ZERO, Fp2.ZERO],
        ONE: [Fp2.ONE, Fp2.ZERO, Fp2.ZERO],

        eq: function (a, b) {
            return Fp2.eq(a[0], b[0]) && Fp2.eq(a[1], b[1]) && Fp2.eq(a[2], b[2]);
        },
        is_zero: function (a) {
            return Fp2.is_zero(a[0]) && Fp2.is_zero(a[1]) && Fp2.is_zero(a[2]);
        },

        add: function (a, b) { return [Fp2.add(a[0],b[0]), Fp2.add(a[1],b[1]), Fp2.add(a[2],b[2])]; },
        sub: function (a, b) { return [Fp2.sub(a[0],b[0]), Fp2.sub(a[1],b[1]), Fp2.sub(a[2],b[2])]; },
        neg: function (a) { return [Fp2.neg(a[0]), Fp2.neg(a[1]), Fp2.neg(a[2])]; },

        /**
         * Karatsuba over three coefficients: six Fp2 multiplications instead
         * of nine. The v^3 terms fold back in through the non-residue.
         */
        mul: function (a, b) {
            var t0 = Fp2.mul(a[0], b[0]);
            var t1 = Fp2.mul(a[1], b[1]);
            var t2 = Fp2.mul(a[2], b[2]);

            var c0 = Fp2.add(t0, Fp2.mul_nonres(Fp2.sub(
                Fp2.mul(Fp2.add(a[1], a[2]), Fp2.add(b[1], b[2])), Fp2.add(t1, t2))));
            var c1 = Fp2.add(Fp2.sub(
                Fp2.mul(Fp2.add(a[0], a[1]), Fp2.add(b[0], b[1])), Fp2.add(t0, t1)),
                Fp2.mul_nonres(t2));
            var c2 = Fp2.add(Fp2.sub(
                Fp2.mul(Fp2.add(a[0], a[2]), Fp2.add(b[0], b[2])), Fp2.add(t0, t2)), t1);

            return [c0, c1, c2];
        },

        /**
         * a^2, by substituting squarings for the multiplications that mul
         * would perform on equal operands.
         *
         * ⭐ THIS IS NOT A NEW FORMULA. It is Fp6.mul with b = a, and every
         *   Fp2.mul(x, x) in it replaced by Fp2.sqr(x). Fp2.sqr costs two
         *   base multiplications against mul's three, so six of them save
         *   six Fp muls out of eighteen - a third, with nothing transcribed
         *   from a paper and nothing new to get wrong.
         *
         * ⚠ Chung-Hasan SQR3 would save one more, and it IS a new formula.
         *   Not taken: the saving is small and the failure mode is a
         *   well-formed field element that matches nothing.
         *
         * The oracle is exact and cheap: sqr(a) must equal mul(a, a) for
         * every a, which is asserted over thousands of random values.
         */
        sqr: function (a) {
            var t0 = Fp2.sqr(a[0]);
            var t1 = Fp2.sqr(a[1]);
            var t2 = Fp2.sqr(a[2]);

            var c0 = Fp2.add(t0, Fp2.mul_nonres(Fp2.sub(
                Fp2.sqr(Fp2.add(a[1], a[2])), Fp2.add(t1, t2))));
            var c1 = Fp2.add(Fp2.sub(
                Fp2.sqr(Fp2.add(a[0], a[1])), Fp2.add(t0, t1)),
                Fp2.mul_nonres(t2));
            var c2 = Fp2.add(Fp2.sub(
                Fp2.sqr(Fp2.add(a[0], a[2])), Fp2.add(t0, t2)), t1);

            return [c0, c1, c2];
        },

        /** Multiply by v, which shifts the coefficients and folds v^3. */
        mul_v: function (a) {
            return [Fp2.mul_nonres(a[2]), a[0], a[1]];
        },

        inv: function (a) {
            var c0 = Fp2.sub(Fp2.sqr(a[0]), Fp2.mul_nonres(Fp2.mul(a[1], a[2])));
            var c1 = Fp2.sub(Fp2.mul_nonres(Fp2.sqr(a[2])), Fp2.mul(a[0], a[1]));
            var c2 = Fp2.sub(Fp2.sqr(a[1]), Fp2.mul(a[0], a[2]));

            var t = Fp2.add(Fp2.mul_nonres(Fp2.add(Fp2.mul(a[2], c1), Fp2.mul(a[1], c2))),
                            Fp2.mul(a[0], c0));
            var ti = Fp2.inv(t);
            return [Fp2.mul(c0, ti), Fp2.mul(c1, ti), Fp2.mul(c2, ti)];
        },

        Fp2: Fp2
    };
    return Fp6;
}

/**
 * Build Fp12 = Fp6[w]/(w^2 - v).
 *
 * Elements are [c0, c1] with c_i in Fp6, meaning c0 + c1*w. This is where
 * pairing values live.
 */
export function fp12_field(Fp6) {
    var Fp2 = Fp6.Fp2;

    var Fp12 = {
        ZERO: [Fp6.ZERO, Fp6.ZERO],
        ONE: [Fp6.ONE, Fp6.ZERO],

        eq: function (a, b) { return Fp6.eq(a[0], b[0]) && Fp6.eq(a[1], b[1]); },
        is_zero: function (a) { return Fp6.is_zero(a[0]) && Fp6.is_zero(a[1]); },

        add: function (a, b) { return [Fp6.add(a[0],b[0]), Fp6.add(a[1],b[1])]; },
        sub: function (a, b) { return [Fp6.sub(a[0],b[0]), Fp6.sub(a[1],b[1])]; },
        neg: function (a) { return [Fp6.neg(a[0]), Fp6.neg(a[1])]; },

        mul: function (a, b) {
            var t0 = Fp6.mul(a[0], b[0]);
            var t1 = Fp6.mul(a[1], b[1]);
            var c0 = Fp6.add(t0, Fp6.mul_v(t1));
            var c1 = Fp6.sub(Fp6.mul(Fp6.add(a[0], a[1]), Fp6.add(b[0], b[1])),
                             Fp6.add(t0, t1));
            return [c0, c1];
        },

        /**
         * a^2, the same substitution one level up.
         *
         * ⭐ Fp12.mul does three Fp6 multiplications; with b = a all three
         *   have equal operands, so all three become Fp6.sqr - which is
         *   itself a third cheaper. The saving compounds: an Fp12 squaring
         *   goes from 54 base multiplications to 36.
         *
         * ⭐ AND THIS IS WHERE IT MATTERS. final_exp measured 147 ms of a
         *   225 ms pairing, and it is almost entirely squarings - one
         *   exponentiation by a 1268-bit exponent.
         *
         * ⚠ THE CYCLOTOMIC SQUARING would be cheaper still, because the
         *   final exponentiation works in a subgroup where a shorter formula
         *   holds. It is a different formula with a precondition, and a
         *   caller who squared a non-cyclotomic element with it would get a
         *   wrong answer that still looks like an Fp12 element. Not taken.
         */
        sqr: function (a) {
            var t0 = Fp6.sqr(a[0]);
            var t1 = Fp6.sqr(a[1]);
            var c0 = Fp6.add(t0, Fp6.mul_v(t1));
            var c1 = Fp6.sub(Fp6.sqr(Fp6.add(a[0], a[1])), Fp6.add(t0, t1));
            return [c0, c1];
        },

        /** The conjugate w -> -w. In the cyclotomic subgroup this IS the
            inverse, which the final exponentiation exploits heavily. */
        conj: function (a) { return [a[0], Fp6.neg(a[1])]; },

        inv: function (a) {
            var t = Fp6.inv(Fp6.sub(Fp6.mul(a[0], a[0]), Fp6.mul_v(Fp6.mul(a[1], a[1]))));
            return [Fp6.mul(a[0], t), Fp6.neg(Fp6.mul(a[1], t))];
        },

        pow: function (a, e) {
            var r = Fp12.ONE, base = a, n = e < 0n ? -e : e;
            while (n > 0n) {
                if (n & 1n) { r = Fp12.mul(r, base); }
                base = Fp12.sqr(base);
                n >>= 1n;
            }
            return e < 0n ? Fp12.inv(r) : r;
        },

        Fp6: Fp6,
        Fp2: Fp2
    };
    return Fp12;
}
