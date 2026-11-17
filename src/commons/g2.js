import { cselect } from './modp.js';
import { ladder } from './ladder.js';

/* a constant-time select of an Fp2 element (two Fp coordinates) */
function cs2(bit, a, b) { return [cselect(bit, a[0], b[0]), cselect(bit, a[1], b[1])]; }

/**
 * G2 arithmetic over a quadratic extension.
 *
 * weierstrass.js is built on a prime field and does not generalise to an
 * extension without rewriting its comparisons, so pairing curves carry their
 * own small implementation of the group over Fp2. bls12-381 and bn254 need
 * exactly the same one - only the curve constant b differs - and a copy in
 * each file is how a fix reaches one and not the other.
 *
 * @param {object} Fp2  the quadratic extension
 * @param {Array}  B2   the curve constant of the twist
 */
export function g2_group(Fp2, B2) {
    var C2 = {
        ZERO: { x: Fp2.ZERO, y: Fp2.ONE, z: Fp2.ZERO },
        of: function (x, y) { return { x: x, y: y, z: Fp2.ONE }; },
        is_zero: function (P) { return Fp2.is_zero(P.z); },
        neg: function (P) { return { x: P.x, y: Fp2.neg(P.y), z: P.z }; },

        /* the same Renes-Costello-Batina shape as weierstrass.js, over Fp2 */
        add: function (P, Q) {
            var m = Fp2.mul, ad = Fp2.add, s = Fp2.sub;
            var b3 = Fp2.mul_scalar(B2, 3n);
            var t0 = m(P.x, Q.x), t1 = m(P.y, Q.y), t2 = m(P.z, Q.z);
            var t3 = ad(P.x, P.y), t4 = ad(Q.x, Q.y);
            t3 = m(t3, t4); t4 = ad(t0, t1); t3 = s(t3, t4);
            t4 = ad(P.x, P.z);
            var t5 = ad(Q.x, Q.z);
            t4 = m(t4, t5); t5 = ad(t0, t2); t4 = s(t4, t5);
            t5 = ad(P.y, P.z);
            var X3 = ad(Q.y, Q.z);
            t5 = m(t5, X3); X3 = ad(t1, t2); t5 = s(t5, X3);
            var Z3 = Fp2.ZERO;
            X3 = m(b3, t2); Z3 = X3;
            X3 = s(t1, Z3); Z3 = ad(t1, Z3);
            var Y3 = m(X3, Z3);
            t1 = ad(t0, t0); t1 = ad(t1, t0);
            t4 = m(b3, t4);
            t0 = m(t1, t4); Y3 = ad(Y3, t0);
            t0 = m(t5, t4); X3 = m(t3, X3); X3 = s(X3, t0);
            t0 = m(t3, t1); Z3 = m(t5, Z3); Z3 = ad(Z3, t0);
            return { x: X3, y: Y3, z: Z3 };
        },

        dbl: function (P) { return C2.add(P, P); },

        /*
         * ⛔ VARIABLE TIME — FOR PUBLIC SCALARS ONLY. Double-and-add: one
         *    addition per set bit, and as many rounds as the scalar is long,
         *    so the running time reads out the scalar. It is right for
         *    public inputs (the subgroup check's |x|, a verifier's weights,
         *    a signature's e) and wrong for a secret: a signing key, a KZG
         *    trapdoor. Those use mul_ct.
         */
        mul: function (k, P) {
            var R = C2.ZERO, base = P, n = k < 0n ? -k : k;
            while (n > 0n) {
                if (n & 1n) { R = C2.add(R, base); }
                base = C2.dbl(base);
                n >>= 1n;
            }
            return k < 0n ? C2.neg(R) : R;
        },

        /** Constant-time conditional swap: every coordinate touched, whatever the bit. */
        cswap: function (bit, P, Q) {
            return [{ x: cs2(bit, Q.x, P.x), y: cs2(bit, Q.y, P.y), z: cs2(bit, Q.z, P.z) },
                    { x: cs2(bit, P.x, Q.x), y: cs2(bit, P.y, Q.y), z: cs2(bit, P.z, Q.z) }];
        },

        /**
         * ⭐ SCALAR MULTIPLICATION FOR A SECRET: the Montgomery ladder
         *    (commons/ladder.js) — one addition and one doubling every round,
         *    over a FIXED number of rounds, the accumulators swapped rather
         *    than chosen between. The same as G1's (weierstrass.js mul). It
         *    was missing here, so BLS signing multiplied its key by
         *    double-and-add, whose time depends on the key's bits.
         *
         * The addition above is complete (Renes-Costello-Batina), so the
         * ladder's identity and doubling cases need no branch either.
         *
         * @param {number} bits  fixed round count — the order's bit length
         */
        mul_ct: function (k, P, bits) { return ladder(C2, k, P, bits); },

        to_affine: function (P) {
            if (Fp2.is_zero(P.z)) { return null; }
            var iz = Fp2.inv(P.z);
            return { x: Fp2.mul(P.x, iz), y: Fp2.mul(P.y, iz) };
        },

        eq: function (P, Q) {
            return Fp2.eq(Fp2.mul(P.x, Q.z), Fp2.mul(Q.x, P.z)) &&
                   Fp2.eq(Fp2.mul(P.y, Q.z), Fp2.mul(Q.y, P.z));
        },

        is_on_curve: function (x, y) {
            return Fp2.eq(Fp2.sqr(y), Fp2.add(Fp2.mul(Fp2.sqr(x), x), B2));
        }
};
    return C2;
}
