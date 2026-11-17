import { field } from './commons/modp.js';
import { weierstrass } from './commons/weierstrass.js';
import { fp2_field, fp6_field, fp12_field } from './commons/fp_ext.js';
import { g2_group } from './commons/g2.js';

export var CURVE = {
    name: 'bn254',
    p: 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n,
    r: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n,
    x: 0x44e992b44a6909f1n,
    G1: { b: 3n, Gx: 1n, Gy: 2n },
    G2: {
        Gx: [0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6edn,
             0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2n],
        Gy: [0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daan,
             0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975bn]
    }
};
var Fp   = /* @__PURE__ */ field(CURVE.p);
var Fp2  = /* @__PURE__ */ fp2_field(Fp, [9n, 1n]);
var Fp6  = /* @__PURE__ */ fp6_field(Fp2);
var Fp12 = /* @__PURE__ */ fp12_field(Fp6);
var C1 = /* @__PURE__ */ weierstrass(Fp, 0n, 3n);
var G1 = /* @__PURE__ */ C1.of(CURVE.G1.Gx, CURVE.G1.Gy);
var B2 = /* @__PURE__ */ Fp2.mul([3n, 0n], Fp2.inv([9n, 1n]));

export var FIELD = Fp;
export var FIELD2 = Fp2;
export var FIELD12 = Fp12;
export var POINT1 = C1;
export var BASE1 = G1;

/* G2 over Fp2 - shared with the other pairing curve, see commons/g2.js */
var C2 = /* @__PURE__ */ g2_group(Fp2, B2);

export var POINT2 = C2;
export var BASE2 = /* @__PURE__ */ C2.of(Fp2.of(CURVE.G2.Gx[0], CURVE.G2.Gx[1]),
                                          Fp2.of(CURVE.G2.Gy[0], CURVE.G2.Gy[1]));
/* ==================== the pairing ==================== */

/**
 * The optimal ate pairing, computed ENTIRELY IN Fp12.
 *
 * commons/pairing.js is faster - it keeps G2 on the twist in Fp2 and embeds
 * each line as three sparse coefficients - and it is written for bls12-381's
 * M-twist. bn254's twist is D-type, which changes not only which powers of w
 * the line coefficients occupy but what those coefficients are; several
 * attempts to parameterise it produced pairings that ran and were not
 * bilinear.
 *
 * So this untwists into Fp12 and runs the plain algorithm, which is what
 * py_ecc - the implementation Ethereum uses - also does. Roughly an order of
 * magnitude slower and obviously correct. The sparse version can replace it
 * later, with these tests as the oracle.
 *
 * THE TOWER WAS THE REAL BUG. fp2_field defaulted to the non-residue 1 + u,
 * which is bls12-381's; bn254 needs 9 + u. A tower built on the wrong one is
 * internally consistent and describes a DIFFERENT FIELD, so every pairing on
 * it is self-consistent and wrong - which is why five attempts at signs and
 * coefficient positions all failed identically, and why the fix was found
 * only by checking what v^3 actually equalled.
 */

var Z2 = Fp2.ZERO;

/* w^k in the tower: Fp12 = Fp6[w]/(w^2 - v), Fp6 = Fp2[v]/(v^3 - xi) */
function w_pow(k) {
    if (k === 2) { return [[Z2, Fp2.ONE, Z2], [Z2, Z2, Z2]]; }
    if (k === 3) { return [[Z2, Z2, Z2], [Z2, Fp2.ONE, Z2]]; }
    return [[Fp2.ONE, Z2, Z2], [Z2, Z2, Z2]];
}
function from_fp2(a) { return [[a, Z2, Z2], [Z2, Z2, Z2]]; }
function from_fp(a) { return from_fp2([a, 0n]); }

/** D-twist untwist: psi(x, y) = (x*w^2, y*w^3). */
function untwist(Q) {
    return { x: Fp12.mul(from_fp2(Q.x), w_pow(2)),
             y: Fp12.mul(from_fp2(Q.y), w_pow(3)) };
}
function lift_g1(P) { return { x: from_fp(P.x), y: from_fp(P.y) }; }

/*
 * Affine doubling and addition in Fp12, taking the SLOPE line12 has already
 * computed.
 *
 * ⭐ ONE INVERSION PER STEP, NOT TWO. line12 computes the slope to evaluate
 *   the line; dbl12 and add12 used to compute the very same slope again for
 *   the next point, which is the double inversion commons/pairing.js removed
 *   from its own loop. An Fp12 inversion is the most expensive thing here.
 *
 * ⚠ m IS OPTIONAL and null for a vertical line, where the old code divided by
 *   zero; recomputing in that case keeps the degenerate path exactly as it
 *   was rather than inventing a new answer for it.
 */
function dbl12(P, m) {
    var l = m != null ? m : Fp12.mul(Fp12.mul(Fp12.mul(P.x, P.x), from_fp(3n)),
                                     Fp12.inv(Fp12.add(P.y, P.y)));
    var x = Fp12.sub(Fp12.mul(l, l), Fp12.add(P.x, P.x));
    return { x: x, y: Fp12.sub(Fp12.mul(l, Fp12.sub(P.x, x)), P.y) };
}
function add12(A, B, m) {
    var l = m != null ? m : Fp12.mul(Fp12.sub(B.y, A.y), Fp12.inv(Fp12.sub(B.x, A.x)));
    var x = Fp12.sub(Fp12.sub(Fp12.mul(l, l), A.x), B.x);
    return { x: x, y: Fp12.sub(Fp12.mul(l, Fp12.sub(A.x, x)), A.y) };
}

/**
 * The line through A and B, evaluated at T, and its slope (null when the line
 * is vertical). `chord` is the slope only when it IS a chord: add12 must not
 * be handed the tangent of the R == Q case, where it used to divide by zero,
 * or that degenerate input would start giving a different answer.
 */
function line12(A, B, T) {
    var m;
    if (!Fp12.eq(A.x, B.x)) {
        m = Fp12.mul(Fp12.sub(B.y, A.y), Fp12.inv(Fp12.sub(B.x, A.x)));
        return { l: line_at(m, A, T), m: m, chord: m };
    } else if (Fp12.eq(A.y, B.y)) {
        m = Fp12.mul(Fp12.mul(Fp12.mul(A.x, A.x), from_fp(3n)),
                     Fp12.inv(Fp12.add(A.y, A.y)));
        return { l: line_at(m, A, T), m: m, chord: null };
    }
    return { l: Fp12.sub(T.x, A.x), m: null, chord: null };    /* vertical */
}
function line_at(m, A, T) {
    return Fp12.sub(Fp12.mul(m, Fp12.sub(T.x, A.x)), Fp12.sub(T.y, A.y));
}

var LOOP = /* @__PURE__ */ (6n * CURVE.x + 2n);
var FINAL_EXP = /* @__PURE__ */ ((CURVE.p ** 12n - 1n) / CURVE.r);

/**
 * @param {object} Q  a G2 point in AFFINE Fp2 coordinates
 * @param {object} P  a G1 point in AFFINE Fp coordinates
 */
export function pair(Q, P) {
    var Qt = untwist(Q), Pt = lift_g1(P);
    var R = Qt, f = Fp12.ONE, i;

    for (i = 63; i >= 0; i--) {
        var d = line12(R, R, Pt);
        f = Fp12.mul(Fp12.mul(f, f), d.l);
        R = dbl12(R, d.m);
        if (LOOP & (1n << BigInt(i))) {
            var a = line12(R, Qt, Pt);
            f = Fp12.mul(f, a.l);
            R = add12(R, Qt, a.chord);
        }
    }

    /*
     * The two extra line evaluations a BN loop needs and a BLS loop does not.
     * Without them the value is not in the target group, which shows up as
     * e(P,Q)^r != 1 rather than as anything obviously broken.
     */
    var Q1 = { x: Fp12.pow(Qt.x, CURVE.p), y: Fp12.pow(Qt.y, CURVE.p) };
    var Q2 = { x: Fp12.pow(Q1.x, CURVE.p),
               y: Fp12.neg(Fp12.pow(Q1.y, CURVE.p)) };
    var e1 = line12(R, Q1, Pt);
    f = Fp12.mul(f, e1.l);
    R = add12(R, Q1, e1.chord);
    f = Fp12.mul(f, line12(R, Q2, Pt).l);

    return Fp12.pow(f, FINAL_EXP);
}

/** e(A,B) * e(C,D) * ..., for verification equations that need a product. */
export function pair_product(pairs) {
    var acc = Fp12.ONE;
    for (var i = 0; i < pairs.length; i++) {
        acc = Fp12.mul(acc, pair(pairs[i][1], pairs[i][0]));
    }
    return acc;
}

export var PAIRING = { pair: pair, pair_product: pair_product };
