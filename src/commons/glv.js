/**
 * The GLV endomorphism  -  Gallant, Lambert, Vanstone (2001)
 *
 * A few curves admit an efficiently computable map that multiplies a point by
 * a fixed large scalar for the cost of ONE field multiplication. secp256k1 is
 * one of them: for a cube root of unity beta in the field,
 *
 *     (x, y)  ->  (beta*x, y)   equals   lambda * (x, y)
 *
 * where lambda is the matching cube root of unity modulo the group order.
 * Verifying that identity is one multiplication; computing lambda*P the
 * ordinary way is a full scalar multiplication.
 *
 * WHAT IT BUYS. Any scalar k can be written k = k1 + k2*lambda with BOTH
 * halves about half the width of k, so
 *
 *     k*P = k1*P + k2*(lambda*P) = k1*P + k2*endo(P)
 *
 * becomes a double multiplication with 128-bit scalars instead of a single
 * one with a 256-bit scalar. Interleaved, that halves the doublings, and the
 * endomorphism itself is nearly free. Roughly 1.4x on verification.
 *
 * THE SPLIT IS A LATTICE PROBLEM. Finding a short (k1, k2) means finding a
 * short vector in the lattice of pairs (a, b) with a + b*lambda = 0 mod n.
 * For secp256k1 the two basis vectors were computed once, by the extended
 * Euclidean algorithm on (n, lambda), and are the constants below - the same
 * ones every implementation uses, and they are checked at load against the
 * defining relation rather than trusted.
 *
 * NOT CONSTANT TIME AS USED HERE. The split involves rounded division and the
 * resulting scalars are short, so the number of doublings depends on them.
 * That is fine for VERIFICATION, where every scalar is public, and this file
 * is used nowhere else. Signing and key generation stay on the fixed-base
 * table, which is constant time and already faster.
 */

import { odd_multiples, wnaf_digits, wnaf_sum } from './fixed_window.js';

/* the cube roots, for secp256k1 */
export var SECP256K1_BETA =
    0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501een;
export var SECP256K1_LAMBDA =
    0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72n;

/*
 * The short lattice basis: (a1, b1) and (a2, b2) with
 * a1 + b1*lambda = 0 and a2 + b2*lambda = 0, both modulo n.
 */
export var SECP256K1_BASIS = {
    a1: 0x3086d221a7d46bcde86c90e49284eb15n,
    b1: -0xe4437ed6010e88286f547fa90abfe4c3n,
    a2: 0x114ca50f7a8e2f3f657c1108d9d44cfd8n,
    b2: 0x3086d221a7d46bcde86c90e49284eb15n
};

/** Round a/b to the nearest integer, for positive b. */
function round_div(a, b) {
    var neg = a < 0n;
    var x = neg ? -a : a;
    var q = (2n * x + b) / (2n * b);
    return neg ? -q : q;
}

/**
 * Split k into (k1, k2) with k = k1 + k2*lambda mod n and both about half
 * the width.
 *
 * @return {{k1: bigint, k1neg: boolean, k2: bigint, k2neg: boolean}}
 *         magnitudes plus signs, because a negative scalar is handled by
 *         negating the point rather than by reducing modulo n - which would
 *         make it full width again and defeat the whole exercise.
 */
export function split_scalar(k, n, basis) {
    var b = basis;
    var c1 = round_div(b.b2 * k, n);
    var c2 = round_div(-b.b1 * k, n);

    var k1 = k - c1 * b.a1 - c2 * b.a2;
    var k2 = -c1 * b.b1 - c2 * b.b2;

    var k1neg = k1 < 0n, k2neg = k2 < 0n;
    return {
        k1: k1neg ? -k1 : k1, k1neg: k1neg,
        k2: k2neg ? -k2 : k2, k2neg: k2neg
    };
}

/**
 * The endomorphism on a projective point: (X : Y : Z) → (βX : Y : Z). It acts
 * on the affine x alone, so no inversion is needed — the routines below used
 * to convert both points to affine first, two inversions a verification.
 */
function endo(F, beta, P) { return { X: F.mul(beta, P.X), Y: P.Y, Z: P.Z }; }

/**
 * ⭐ MSM TERMS, SPLIT (11-13): every full-width term k·P of a multi-scalar
 *    multiplication becomes two half-width ones, k1·(±P) + k2·(±endo(P)) -
 *    the same sum, with half the windows for those scalars. For msm
 *    (commons/fixed_window.js), which stays as it is: the split happens
 *    before the call, on this curve's side. A term already at most half
 *    width (a batch's 128-bit weight) is passed through.
 *
 *    The identity is the one every GLV verification rests on (GLV, CRYPTO
 *    2001; libsecp256k1 splits each term of its multi-multiplication the
 *    same way): k = k1 + k2·λ mod n and λ·P = endo(P), for every point of
 *    the curve's prime-order group. Variable time, as msm is: for public
 *    scalars only.
 *
 * @param scalars, points  the terms, scalars reduced mod n
 * @return {{ scalars, points }}  new arrays; the inputs are not changed
 */
export function glv_msm_terms(G, F, beta, n, basis, scalars, points) {
    var half = 1n << BigInt(Math.ceil(n.toString(2).length / 2) + 1);
    var s2 = [], p2 = [];
    for (var i = 0; i < scalars.length; i++) {
        var k = scalars[i], P = points[i];
        if (k < half) { s2.push(k); p2.push(P); continue; }
        var d = split_scalar(k, n, basis), Q = endo(F, beta, P);
        s2.push(d.k1); p2.push(d.k1neg ? G.neg(P) : P);
        s2.push(d.k2); p2.push(d.k2neg ? G.neg(Q) : Q);
    }
    return { scalars: s2, points: p2 };
}

function negated(d) { for (var i = 0; i < d.length; i++) { d[i] = -d[i]; } return d; }

/**
 * A FIXED POINT's GLV table, built on first use and kept: its odd multiples
 * at width w and their images under the endomorphism (the generator's, for
 * verification — commons/ecdsa.js).
 */
export function glv_base_table(G, F, beta, P, w) {
    var t = null;
    return function () {
        if (t === null) {
            var pre = odd_multiples(G, P, w);
            t = { w: w, pre: pre, pre2: pre.map(function (Q) { return endo(F, beta, Q); }) };
        }
        return t;
    };
}

/**
 * k·P as two half-width wNAF terms for fixed_window.wnaf_sum:
 * k = k1 + k2·λ, k2·λ·P = k2·endo(P); a negative half negates its digits.
 */
function glv_terms(G, F, beta, n, basis, k, P, table, w) {
    var s = split_scalar(k, n, basis), out = [], width, pre, pre2;
    if (table) { var T = table(); width = T.w; pre = T.pre; pre2 = T.pre2; }
    else {
        width = w;
        pre = odd_multiples(G, P, width);
        pre2 = pre.map(function (Q) { return endo(F, beta, Q); });
    }
    if (s.k1 !== 0n) {
        var d1 = wnaf_digits(s.k1, width);
        out.push({ digits: s.k1neg ? negated(d1) : d1, pre: pre, cached: false });
    }
    if (s.k2 !== 0n) {
        var d2 = wnaf_digits(s.k2, width);
        out.push({ digits: s.k2neg ? negated(d2) : d2, pre: pre2, cached: false });
    }
    return out;
}

/** k*P using the endomorphism, for a PUBLIC k: two 128-bit wNAF halves. */
export function glv_mul(G, F, beta, n, basis, k, P, w) {
    if (k === 0n) { return G.ZERO; }
    return wnaf_sum(G, glv_terms(G, F, beta, n, basis, k, P, null, w || 5));
}

/**
 * a*Gp + b*P, both scalars PUBLIC, with the endomorphism on both: four
 * 128-bit wNAF terms sharing one run of doublings. `table`: Gp's kept table
 * (glv_base_table) when Gp is the generator — no table to build for it, and
 * a wider window.
 *
 * ⭐ (11-11) wNAF instead of the fixed window w = 3 it had (four tables of
 *    eight, an addition in seven windows of eight), and the endomorphism on
 *    projective points instead of two inversions to affine.
 */
export function glv_double_mul(G, F, beta, n, basis, a, Gp, b, P, w, table) {
    var width = w || 5;
    var terms = a === 0n ? [] : glv_terms(G, F, beta, n, basis, a, Gp, table || null, width);
    if (b !== 0n) { terms = terms.concat(glv_terms(G, F, beta, n, basis, b, P, null, width)); }
    return wnaf_sum(G, terms);
}
