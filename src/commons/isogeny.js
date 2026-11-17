/**
 * Isogenies of supersingular Montgomery curves over GF(p^2), p = c * 2^e - 1
 *
 * The curve arithmetic of the isogeny signatures, as SQIsign's round-3
 * reference computes it: x-only Montgomery arithmetic (doubling, the
 * three-point and double-scalar ladders), chains of 4-isogenies, the
 * canonical Montgomery form of a curve, canonical bases of E[2^f] named by
 * one-byte hints, the (2^n, 2^n)-isogeny between products of elliptic curves
 * computed in theta coordinates (gluing, a chain of 2-isogenies between theta
 * structures, splitting), and discrete logarithms of Tate pairings through
 * cubical arithmetic.
 *
 * EVERY CURVE IS NAMED BY A CANONICAL MONTGOMERY COEFFICIENT, chosen among
 * the isomorphic ones as the largest under the encoding order, and the
 * canonical bases and the pairings' difference points depend on square roots
 * taken of projective values. So the formulas follow the reference step for
 * step, projective scalings included; a shortcut that changes a projective
 * representative changes a square root, a basis, and the curve a chain lands
 * on.
 *
 * GF(p^2) = GF(p)[i]/(i^2 + 1); elements are [re, im], points { x, z }
 * (projective x-coordinates), curves { A, C, A24, a24 } (A24 = (A + 2C : 4C),
 * a24 when it is normalised), theta points { x, y, z, t }.
 */

import { field } from './modp.js';
import { fp2_field } from './fp_ext.js';

/**
 * The tools for p = c * 2^e - 1.
 *
 * @param {bigint}   c   the cofactor
 * @param {number}   e   the power of 2 (the full 2-power torsion is E[2^e])
 * @param {Array}    E0  x(P) and x(Q) (affine, in GF(p^2)) of the 2^e-torsion
 *                       basis of E_0: y^2 = x^3 + x
 */
export function isogeny_tools(c, e, E0) {
    var COF = c, E2 = e, p = c * (1n << BigInt(e)) - 1n;
    var F = field(p), K = fp2_field(F), COF_BITS = c.toString(2).length;

    var E_SQRT = (p + 1n) >> 2n, E_34 = (p - 3n) >> 2n, E_QR = (p - 1n) >> 1n;
    var HALF = F.inv(2n);
    var ZERO = K.ZERO, ONE = K.ONE;
    var add = K.add, sub = K.sub, mul = K.mul, sqr = K.sqr, neg = K.neg;
    var is0 = K.is_zero, eq = K.eq;

    /* ---------------- GF(p) and GF(p^2) beyond the ring operations ---------------- */

    function fp_is_square(a) { return a === 0n || F.pow(a, E_QR) === 1n; }
    function fp2_is_square(a) { return fp_is_square(F.add(F.sqr(a[0]), F.sqr(a[1]))); }
    function fp2_is_one(a) { return a[0] === 1n && a[1] === 0n; }
    function fp2_half(a) { return [F.mul(a[0], HALF), F.mul(a[1], HALF)]; }
    function fp2_small(a, n) { return K.mul_scalar(a, BigInt(n)); }
    /* x * i when ctl, x * (-i) otherwise */
    function mul_by_i(x, ctl) { return ctl ? [F.neg(x[1]), x[0]] : [x[1], F.neg(x[0])]; }
    function inv(a) { return K.inv(a); }
    /* the reference's square root (it picks the root, so it is reproduced exactly) */
    function fp2_sqrt(a) {
        var x0 = F.pow(F.add(F.sqr(a[0]), F.sqr(a[1])), E_SQRT);
        if (a[1] === 0n) { x0 = a[0]; }
        x0 = F.add(x0, a[0]);
        var t0 = F.add(x0, x0), x1 = F.pow(t0, E_34);
        x0 = F.mul(x0, x1);
        x1 = F.mul(x1, a[1]);
        var t1 = F.sqr(F.add(x0, x0));
        return t0 === t1 ? [x0, x1] : [x1, F.neg(x0)];
    }
    /* the order of the encodings read as little-endian integers: im first */
    function fp2_less_than(a, b) { return a[1] < b[1] || (a[1] === b[1] && a[0] < b[0]); }
    function batched_inv(xs) { return K.inv_batch(xs); }

    /* ---------------- Montgomery curves, x-only ---------------- */

    function pt(x, z) { return { x: x, z: z }; }
    var INF = pt(ONE, ZERO);
    function curve(A) { return { A: A, C: ONE, A24: INF, a24: false }; }
    function copy_curve(E) { return { A: E.A, C: E.C, A24: E.A24, a24: E.a24 }; }
    function normalize_point(P) { return pt(mul(P.x, inv(P.z)), ONE); }
    function normalize_A24(E) {
        if (!E.a24) {
            var z = add(E.C, E.C);
            E.A24 = normalize_point(pt(add(E.A, z), add(z, z)));
            E.a24 = true;
        }
    }
    function normalize_curve_and_A24(E) {
        if (!fp2_is_one(E.C)) { E.A = mul(E.A, inv(E.C)); E.C = ONE; }
        if (!E.a24) {
            var a = [F.add(E.A[0], 2n), E.A[1]];
            E.A24 = pt(fp2_half(fp2_half(a)), ONE);
            E.a24 = true;
        }
    }
    function is_zero_pt(P) { return is0(P.z); }
    function has_zero_coordinate(P) { return is0(P.x) || is0(P.z); }
    function is_equal(P, Q) {
        var lz = is_zero_pt(P), rz = is_zero_pt(Q);
        return (lz && rz) || (!lz && !rz && eq(mul(P.x, Q.z), mul(P.z, Q.x)));
    }
    function is_two_torsion(P, E) {
        if (is_zero_pt(P)) { return false; }
        var t0 = sqr(add(P.x, P.z)), t1 = sqr(sub(P.x, P.z));
        var t2 = mul(sub(t0, t1), E.A);
        t1 = mul(add(t0, t1), E.C);
        return is0(P.x) || is0(add(add(t1, t1), t2));
    }
    function is_four_torsion(P, E) { return is_two_torsion(xDBL_A24(P, E.A24, E.a24), E); }
    function verify_A(A) {
        return !eq(A, [2n, 0n]) && !eq(A, [F.neg(2n), 0n]);
    }
    function xDBL_E0(P) {
        var t0 = sqr(add(P.x, P.z)), t1 = sqr(sub(P.x, P.z)), t2 = sub(t0, t1);
        t1 = add(t1, t1);
        return pt(mul(t0, t1), mul(add(t1, t2), t2));
    }
    /* doubling with (A : C) as given, AC = { x: A, z: C } */
    function xDBL(P, AC) {
        var t0 = sqr(add(P.x, P.z)), t1 = sqr(sub(P.x, P.z)), t2 = sub(t0, t1);
        var t3 = add(AC.z, AC.z);
        t1 = mul(t1, t3);
        t1 = add(t1, t1);
        var x = mul(t0, t1);
        t0 = add(mul(add(t3, AC.x), t2), t1);
        return pt(x, mul(t0, t2));
    }
    function xDBL_A24(P, A24, normalized) {
        var t0 = sqr(add(P.x, P.z)), t1 = sqr(sub(P.x, P.z)), t2 = sub(t0, t1);
        if (!normalized) { t1 = mul(t1, A24.z); }
        var x = mul(t0, t1);
        return pt(x, mul(add(mul(t2, A24.x), t1), t2));
    }
    function xADD(P, Q, PQ) {
        var t0 = add(P.x, P.z), t1 = sub(P.x, P.z), t2 = add(Q.x, Q.z), t3 = sub(Q.x, Q.z);
        t0 = mul(t0, t3);
        t1 = mul(t1, t2);
        t2 = sqr(add(t0, t1));
        t3 = sqr(sub(t0, t1));
        return pt(mul(PQ.z, t2), mul(PQ.x, t3));
    }
    /* [2P, P + Q] given P - Q; A24 must be normalised (only its x is read).
     * With special, the last factor PQ.z is left out (the gluing's PQ has z = 1). */
    function xDBLADD(P, Q, PQ, A24, special) {
        var t0 = add(P.x, P.z), t1 = sub(P.x, P.z), Rx = sqr(t0), t2 = sub(Q.x, Q.z), Sx = add(Q.x, Q.z);
        t0 = mul(t0, t2);
        var Rz = sqr(t1);
        t1 = mul(t1, Sx);
        t2 = sub(Rx, Rz);
        Rx = mul(Rx, Rz);
        Sx = mul(A24.x, t2);
        var Sz = sub(t0, t1);
        Rz = mul(add(Rz, Sx), t2);
        Sx = sqr(add(t0, t1));
        Sz = mul(sqr(Sz), PQ.x);
        if (!special) { Sx = mul(Sx, PQ.z); }
        return [pt(Rx, Rz), pt(Sx, Sz)];
    }
    function xMUL(P, k, kbits, E) {
        var A24;
        if (!E.a24) {
            var x = add(E.C, E.C);
            A24 = pt(add(x, E.A), add(x, x));
        } else { A24 = E.A24; }
        var R0 = INF, R1 = P, prev = 0, r, t;
        for (var i = kbits - 1; i >= 0; i--) {
            var bit = Number((k >> BigInt(i)) & 1n);
            if (bit ^ prev) { t = R0; R0 = R1; R1 = t; }
            prev = bit;
            r = xDBLADD(R0, R1, P, A24);
            R0 = r[0]; R1 = r[1];
        }
        return prev ? R1 : R0;
    }
    function ec_mul(P, k, kbits, E) {
        if (kbits > 50) { normalize_A24(E); }
        return xMUL(P, k, kbits, E);
    }
    function dbl(P, E) { return E.a24 ? xDBL_A24(P, E.A24, true) : xDBL(P, { x: E.A, z: E.C }); }
    function dbl_iter(P, n, E) {
        if (n > 50) { normalize_A24(E); }
        for (var i = 0; i < n; i++) { P = dbl(P, E); }
        return P;
    }
    /* P + [m]Q from P, Q, P - Q, bits of m from the lowest; E's A24 normalised */
    function ladder3pt(m, nbits, P, Q, PQ, E) {
        if (!fp2_is_one(E.A24.z) || has_zero_coordinate(PQ)) { return null; }
        var X0 = Q, X1 = P, X2 = PQ, r;
        for (var i = 0; i < nbits; i++) {
            if ((m >> BigInt(i)) & 1n) {
                r = xDBLADD(X0, X1, X2, E.A24);
                X0 = r[0]; X1 = r[1];
            } else {
                r = xDBLADD(X0, X2, X1, E.A24);
                X0 = r[0]; X2 = r[1];
            }
        }
        return X1;
    }
    /* [a]P + [b]Q, the verifier's variable-time double-scalar ladder */
    function biscalar_mul_verif(a, b, kbits, B, E) {
        if (has_zero_coordinate(B.P) || has_zero_coordinate(B.Q) || has_zero_coordinate(B.PmQ)) { return null; }
        var mask = (1n << BigInt(kbits)) - 1n, s0 = a & mask, s1 = b & mask, t;
        if (s0 === 0n && s1 === 0n) { return null; }
        var x0 = B.P, x1 = B.Q, xd = B.PmQ, xt;
        if (!is0(E.A)) { normalize_A24(E); }
        while (s0 !== 0n) {
            if (s1 < s0) { t = s0; s0 = s1; s1 = t; xt = x0; x0 = x1; x1 = xt; }
            if (s1 < (s0 << 2n)) {
                s1 -= s0;
                xt = x0;
                x0 = xADD(x1, x0, xd);
                xd = xt;
                if (has_zero_coordinate(x0)) { return null; }
            } else if ((s1 & 1n) === (s0 & 1n)) {
                s1 = (s1 - s0) >> 1n;
                x0 = xADD(x1, x0, xd);
                x1 = xDBL_A24(x1, E.A24, E.a24);
                if (has_zero_coordinate(x0) || has_zero_coordinate(x1)) { return null; }
            } else if (!(s1 & 1n)) {
                s1 >>= 1n;
                xd = xADD(x1, xd, x0);
                x1 = xDBL_A24(x1, E.A24, E.a24);
                if (has_zero_coordinate(xd) || has_zero_coordinate(x1)) { return null; }
            } else {
                s0 >>= 1n;
                xd = xADD(x0, xd, x1);
                x0 = xDBL_A24(x0, E.A24, E.a24);
                if (has_zero_coordinate(xd) || has_zero_coordinate(x0)) { return null; }
            }
        }
        while (!(s1 & 1n)) { s1 >>= 1n; x1 = xDBL_A24(x1, E.A24, E.a24); }
        if (s1 !== 1n) { x1 = ec_mul(x1, s1, kbits, E); }
        return has_zero_coordinate(x1) ? null : x1;
    }
    function bary(P, Q, PmQ) {
        var t0 = add(P.x, P.z), t1 = sub(P.x, P.z), t2 = add(Q.x, Q.z), t3 = sub(Q.x, Q.z);
        t0 = mul(t0, t3);
        t1 = mul(t1, t2);
        t2 = add(t1, t0);
        t3 = sub(t1, t0);
        t0 = sqr(mul(PmQ.z, t2));
        t1 = mul(t3, PmQ.x);
        t2 = mul(t3, PmQ.z);
        t3 = sqr(t1);
        var w = mul(t1, t2);
        return { u: add(t3, t0), v: sub(t3, t0), w: add(w, w) };
    }

    /* ---------------- 4-isogeny chains and the canonical Montgomery form ---------------- */

    function xisog_4(P) {
        var t1 = sqr(P.x), t2 = sqr(P.z);
        var B = pt(mul(add(t2, t1), sub(t2, t1)), sqr(t2));
        t2 = add(t2, t2);
        return { B: B, K: [add(t2, t2), sub(P.x, P.z), add(P.x, P.z)] };
    }
    function xeval_4(Q, K4) {
        var t0 = add(Q.x, Q.z), t1 = sub(Q.x, Q.z);
        var x = mul(t0, K4[1]), z = mul(t1, K4[2]);
        t0 = mul(mul(t0, t1), K4[0]);
        t1 = sqr(add(x, z));
        z = sqr(sub(x, z));
        return pt(mul(add(t0, t1), t1), mul(z, sub(t0, z)));
    }
    /* the image curve of the 2^len-isogeny with this kernel, in canonical form; false on failure */
    function isogeny_2chain(E, kernel, len) {
        normalize_A24(E);
        var A24 = E.A24, splits = [kernel], todo = [len], current = 0, i;
        for (var j = 0; j < (len >> 1) - 1; ++j) {
            while (todo[current] !== 2) {
                ++current;
                var s = splits[current - 1], nd = ((todo[current - 1] >> 2) << 1) + (todo[current - 1] & 1);
                todo[current] = todo[current - 1] - nd;
                while (nd--) { s = xDBL_A24(s, A24, false); }
                splits[current] = s;
            }
            if (j === 0) {
                if (!is_four_torsion(splits[current], E)) { return false; }
                if (is0(xDBL_A24(splits[current], A24, false).x)) { return false; }
            }
            var k4 = xisog_4(splits[current]);
            A24 = k4.B;
            for (i = 0; i < current; ++i) { splits[i] = xeval_4(splits[i], k4.K); todo[i] -= 2; }
            --current;
        }
        return !!theta_to_montgomery(E, splits[current]);
    }
    function montgomery_coefficient(th) {
        var xx = sqr(sqr(th.x)), zz = sqr(sqr(th.z)), x = add(xx, zz);
        return pt(add(x, x), sub(xx, zz));
    }
    /*
     * The Montgomery curve with this theta null point, as the largest of the
     * six coefficients (three curves and their negatives); E is overwritten,
     * and the returned matrix maps the theta x-coordinates to it (null if the
     * point is degenerate).
     */
    function theta_to_montgomery(E, th) {
        var ma = neg(th.x), mb = neg(th.z), ia = mul_by_i(th.x, 0), ib = mul_by_i(th.z, 0);
        var m1 = montgomery_coefficient(th);
        var m2 = montgomery_coefficient(pt(add(th.x, th.z), sub(th.x, th.z)));
        var m3 = montgomery_coefficient(pt(add(ia, th.z), add(th.x, ib)));
        var c = batched_inv([m1.z, m2.z, m3.z]);
        if (is0(c[0])) { return null; }
        c = [mul(m1.x, c[0]), mul(m2.x, c[1]), mul(m3.x, c[2])];
        c.push(neg(c[0]), neg(c[1]), neg(c[2]));
        var max = 0, A = c[0];
        for (var i = 1; i < 6; i++) { if (fp2_less_than(A, c[i])) { A = c[i]; max = i; } }
        E.A = A; E.C = ONE; E.A24 = INF; E.a24 = false;
        normalize_curve_and_A24(E);
        var s14 = max === 1 || max === 4, s25 = max === 2 || max === 5;
        return {
            a: s25 ? ia : s14 ? ma : th.z,
            b: s25 ? ib : s14 ? th.z : th.x,
            c: (max === 2 || max === 3 || max === 4) ? mb : th.z,
            d: (max === 0 || max === 1 || max === 5) ? ma : th.x
        };
    }
    function apply_isomorphism(P, M) {
        return pt(add(mul(P.x, M.a), mul(P.z, M.b)), add(mul(P.x, M.c), mul(P.z, M.d)));
    }

    /* ---------------- canonical bases of E[2^f] from the hints ---------------- */

    function difference_point(P, Q, E) {
        var t0 = mul(P.x, Q.x), t1 = mul(P.z, Q.z);
        var Bxx = mul(sqr(sub(t0, t1)), E.C), Bxz = add(t0, t1);
        t0 = mul(P.x, Q.z);
        t1 = mul(P.z, Q.x);
        var Bzz = add(t0, t1);
        Bxz = mul(Bxz, Bzz);
        Bzz = mul(sqr(sub(t0, t1)), E.C);
        Bxz = mul(Bxz, E.C);
        t0 = mul(mul(t0, t1), E.A);
        Bxz = add(Bxz, add(t0, t0));
        t0 = mul(mul(K.conj(E.C), E.C), K.conj(Bzz));
        Bxx = mul(Bxx, t0);
        Bxz = mul(Bxz, t0);
        Bzz = mul(Bzz, t0);
        t0 = fp2_sqrt(sub(sqr(Bxz), mul(Bxx, Bzz)));
        return [pt(add(Bxz, t0), Bzz), pt(sub(Bxz, t0), Bzz)];
    }
    /* is x^3 + A x^2 + x a square */
    function on_curve(x, E) {
        var t = mul(add(x, E.A), x);
        return fp2_is_square(mul([F.add(t[0], 1n), t[1]], x));
    }
    function clear_cofactor(P, E, f) {
        P = ec_mul(P, COF, COF_BITS, E);
        for (var i = 0; i < E2 - f; i++) { P = xDBL_A24(P, E.A24, E.a24); }
        return P;
    }
    /*
     * The two ways to a basis: when A is not a square, x = n A on the curve
     * (the first n from start); when it is, z = 1 + b i with b^2 + 1 and
     * b i A^2 - z^2 non-squares (the first b from start). Each gives a pair
     * (P, Q) and the hint that names it (0 when n or b is too large to fit).
     */
    function qr_pair(E, x) { return [pt(x, ONE), pt(neg(add(E.A, x)), ONE)]; }
    function nqr_pair(E, z) { var P = pt(neg(E.A), z); return [P, pt(neg(add(mul(E.A, z), P.x)), z)]; }
    function find_qr(E, start) {
        var n = start, x = n === 1 ? E.A : fp2_small(E.A, n);
        while (!on_curve(x, E)) { x = add(x, E.A); n++; }
        return [qr_pair(E, x), n < 128 ? n : 0];
    }
    function find_nqr(E, start) {
        var n = start, A2 = sqr(E.A);
        for (;;) {
            while (fp_is_square(F.mod(BigInt(n * n + 1)))) { n++; }
            var z = [1n, F.mod(BigInt(n))];
            n++;
            if (!fp2_is_square(sub(mul([0n, z[1]], A2), sqr(z)))) { return [nqr_pair(E, z), n <= 128 ? n - 1 : 0]; }
        }
    }
    function basis_E0(E, f) {
        var P = pt(E0_P, ONE), Q = pt(E0_Q, ONE);
        for (var i = 0; i < E2 - f; i++) { P = xDBL_E0(P); Q = xDBL_E0(Q); }
        return { P: P, Q: Q, PmQ: difference_point(P, Q, E)[1] };
    }
    /* the basis (P, P - Q, Q) of E[2^f] from the pair, and P + Q */
    function basis_from_pair(E, f, pq) {
        var P = clear_cofactor(pq[0], E, f), Q = clear_cofactor(pq[1], E, f), d = difference_point(P, Q, E);
        return { P: P, Q: d[1], PmQ: Q, PpQ: d[0] };
    }
    /* the basis of E[2^f] that hint names (E is normalised in place) */
    function basis_from_hint(E, f, hint) {
        normalize_curve_and_A24(E);
        if (is0(E.A)) { return basis_E0(E, f); }
        var hint_A = hint & 1, hint_P = hint >> 1, pq;
        if (!hint_A) { pq = hint_P ? qr_pair(E, fp2_small(E.A, hint_P)) : find_qr(E, 128)[0]; }
        else { pq = hint_P ? nqr_pair(E, [1n, BigInt(hint_P)]) : find_nqr(E, 128)[0]; }
        return basis_from_pair(E, f, pq);
    }
    /*
     * [basis, hint]: the canonical basis of E[2^f] and its hint. With e > 0, Q
     * is replaced by the other of P +- Q when that makes [2^(f-e)]P and
     * [2^(f-e)]Q differ by a square in the right way (the signer's choice).
     */
    function basis_to_hint(E, f, e) {
        normalize_curve_and_A24(E);
        if (is0(E.A)) { return [basis_E0(E, f), 0]; }
        var hint_A = fp2_is_square(E.A), r = hint_A ? find_nqr(E, 1) : find_qr(E, 1), B = basis_from_pair(E, f, r[0]);
        if (e > 0) {
            var Q = dbl_iter(B.Q, f - e, E), Q2 = dbl_iter(B.PpQ, f - e, E);
            var t0 = sub(mul(Q.x, Q2.z), mul(Q2.x, Q.z)), t1 = mul(Q.z, Q2.z);
            t0 = mul(t0, mul(t1, sqr(K.conj(t1))));
            if (eq(t0, fp2_sqrt(sqr(t0)))) { B.Q = pt(B.PpQ.x, B.Q.z); }
        }
        return [{ P: B.P, Q: B.Q, PmQ: B.PmQ }, (r[1] << 1) | (hint_A ? 1 : 0)];
    }
    var E0_P = E0[0], E0_Q = E0[1];

    /* ---------------- theta structures and the (2^n, 2^n)-isogeny chain ---------------- */

    function th(x, y, z, t) { return { x: x, y: y, z: z, t: t }; }
    function hadamard(P) {
        var t1 = add(P.x, P.y), t2 = sub(P.x, P.y), t3 = add(P.z, P.t), t4 = sub(P.z, P.t);
        return th(add(t1, t3), add(t2, t4), sub(t1, t3), sub(t2, t4));
    }
    function pw_sqr(P) { return th(sqr(P.x), sqr(P.y), sqr(P.z), sqr(P.t)); }
    function pw_mul(P, Q) { return th(mul(P.x, Q.x), mul(P.y, Q.y), mul(P.z, Q.z), mul(P.t, Q.t)); }
    function sq_theta(P) { return hadamard(pw_sqr(P)); }
    function th_invert(P) {
        var a = mul(P.x, P.y), d = mul(P.z, P.t);
        return th(mul(P.y, d), mul(P.x, d), mul(P.t, a), mul(P.z, a));
    }
    function dual_null_point(A) {
        var t = mul(A.dbl.x, A.dbl.t);
        return th(mul(t, A.dbl.y), mul(t, A.dbl.z), A.inv_dual.t, A.inv_dual.z);
    }
    function th_DBL(P, A) {
        if (!A.pre) { A.inv_sqr = th_invert(sq_theta(dual_null_point(A))); A.pre = true; }
        return pw_mul(hadamard(pw_mul(pw_sqr(sq_theta(P)), A.inv_sqr)), A.inv_dual);
    }
    function th_DBL_iter(P, A, n) { for (var i = 0; i < n; i++) { P = th_DBL(P, A); } return P; }

    function apply_change_coord(M, P, t_nonzero) {
        var r = [];
        for (var i = 0; i < 4; i++) {
            var v = add(add(mul(P.x, M[i][0]), mul(P.y, M[i][1])), mul(P.z, M[i][2]));
            if (t_nonzero) { v = add(v, mul(P.t, M[i][3])); }
            r.push(v);
        }
        return th(r[0], r[1], r[2], r[3]);
    }
    function couple_point_to_theta(M, T) {
        return apply_change_coord(M, th(mul(T.P1.x, T.P2.x), mul(T.P1.x, T.P2.z), mul(T.P2.x, T.P1.z), mul(T.P1.z, T.P2.z)), true);
    }
    function symmetric_element(T1, T2) {
        var r1 = add(T1.x, T1.z), s1 = sub(T1.x, T1.z), r2 = add(T2.x, T2.z), s2 = sub(T2.x, T2.z), pos = 255;
        if (is0(s1)) { pos = 0; }
        if (is0(r1)) { pos = 1; }
        if (is0(s2)) { pos = 2; }
        if (is0(r2)) { pos = 3; }
        s2 = mul(r1, s2);
        r1 = mul_by_i(s2, 1);
        r2 = mul(r2, s1);
        s1 = add(r1, r2);
        s2 = sub(r1, r2);
        if (is0(s1)) { pos = 4; }
        if (is0(s2)) { pos = 5; }
        var lo = (pos >> 1) === 0, tmp1 = lo ? T2.x : T1.x, tmp2 = lo ? T2.z : T1.z;
        s1 = sqr(tmp1);
        s2 = sqr(tmp2);
        var delta = sub(s1, s2);
        r1 = add(s1, s2);
        r2 = mul(tmp1, tmp2);
        r2 = add(r2, r2);
        var g1 = [neg(r1), r2, neg(r2)];
        var d = (pos & 1) ? delta : neg(delta), g2 = [ZERO, d, d], t;
        if (lo) { t = g1; g1 = g2; g2 = t; }
        var f1 = pos === 0 || pos === 3 || pos === 4, f2 = pos === 1 || pos === 2 || pos === 5;
        var g3 = [mul_by_i(r2, f1), mul_by_i(r1, f2), mul_by_i(r1, f1)];
        if ((pos >> 1) === 2) { t = g2; g2 = g3; g3 = t; }
        return { delta: delta, g1: g1, g2: g2, g3: g3 };
    }
    function gluing_basis(K1_4, K2_4) {
        var B1 = symmetric_element(K1_4.P1, K2_4.P1), B2 = symmetric_element(K1_4.P2, K2_4.P2);
        var d12 = mul(B1.delta, B2.delta), M = [[], [], [], []];
        function row0(i, j) { return sub(add(mul(B1.g1[i], B2.g1[j]), mul(B1.g2[i], B2.g2[j])), mul(B1.g3[i], B2.g3[j])); }
        M[0][0] = add(d12, row0(0, 0));
        M[0][1] = row0(0, 1);
        M[0][2] = row0(1, 0);
        M[0][3] = row0(1, 1);
        M[1][0] = add(mul(B2.g2[0], M[0][0]), mul(B2.g2[2], M[0][1]));
        M[1][1] = sub(mul(B2.g2[1], M[0][0]), mul(B2.g2[0], M[0][1]));
        M[1][2] = add(mul(B2.g2[0], M[0][2]), mul(B2.g2[2], M[0][3]));
        M[1][3] = sub(mul(B2.g2[1], M[0][2]), mul(B2.g2[0], M[0][3]));
        M[2][0] = add(mul(B1.g1[0], M[0][0]), mul(B1.g1[2], M[0][2]));
        M[2][1] = add(mul(B1.g1[0], M[0][1]), mul(B1.g1[2], M[0][3]));
        M[2][2] = sub(mul(B1.g1[1], M[0][0]), mul(B1.g1[0], M[0][2]));
        M[2][3] = sub(mul(B1.g1[1], M[0][1]), mul(B1.g1[0], M[0][3]));
        M[3][0] = add(mul(B1.g1[0], M[1][0]), mul(B1.g1[2], M[1][2]));
        M[3][1] = add(mul(B1.g1[0], M[1][1]), mul(B1.g1[2], M[1][3]));
        M[3][2] = sub(mul(B1.g1[1], M[1][0]), mul(B1.g1[0], M[1][2]));
        M[3][3] = sub(mul(B1.g1[1], M[1][1]), mul(B1.g1[0], M[1][3]));
        for (var i = 0; i < 4; i++) {
            M[0][i] = mul(M[0][i], d12);
            M[1][i] = mul(M[1][i], B1.delta);
            M[2][i] = mul(M[2][i], B2.delta);
        }
        return M;
    }
    function dbl_couple(T, E12) { return { P1: dbl(T.P1, E12[0]), P2: dbl(T.P2, E12[1]) }; }
    function gluing_compute(E12, K1_8, K2_8, verify) {
        var K1_4 = dbl_couple(K1_8, E12), K2_4 = dbl_couple(K2_8, E12);
        if (verify) {
            var K1_2 = dbl_couple(K1_4, E12), K2_2 = dbl_couple(K2_4, E12);
            if (!is_two_torsion(K1_2.P1, E12[0]) || !is_two_torsion(K1_2.P2, E12[1]) ||
                !is_two_torsion(K2_2.P1, E12[0]) || !is_two_torsion(K2_2.P2, E12[1]) ||
                is_equal(K1_2.P1, K2_2.P1) || is_equal(K1_2.P2, K2_2.P2)) { return null; }
        }
        var M = gluing_basis(K1_4, K2_4);
        var TT1 = sq_theta(couple_point_to_theta(M, K1_8)), TT2 = sq_theta(couple_point_to_theta(M, K2_8));
        if (!is0(TT1.t) || !is0(TT2.t)) { return null; }
        if (is0(TT1.x) || is0(TT2.x) || is0(TT1.y) || is0(TT2.z) || is0(TT1.z)) { return null; }
        var cy = mul(TT1.y, TT2.x), cz = mul(TT1.x, TT2.z);
        var idn = th(mul(TT1.y, TT2.z), cz, cy, ZERO);
        var k1x = mul(TT1.z, idn.z), k1z = mul(TT1.x, idn.x), k2x = mul(TT2.y, idn.y), k2y = mul(TT2.x, idn.x);
        return {
            M: M, inv_dual_theta_null: idn,
            codomain: hadamard(th(mul(TT1.x, TT2.x), cy, cz, ZERO)),
            inv_K1: th(k1x, k1x, k1z, k1z), inv_K2: th(k2x, k2y, k2x, k2y)
        };
    }
    function gluing_eval_bary(c1, c2, phi, aux_inv, dual_codomain) {
        var T1x = add(mul(c1.u, c2.u), mul(c1.v, c2.v));
        var T1 = th(T1x, mul(c1.u, c2.w), mul(c1.w, c2.u), mul(c1.w, c2.w));
        var T2 = th(sub(mul(add(c1.u, c1.v), add(c2.u, c2.v)), T1x), mul(c1.v, c2.w), mul(c1.w, c2.v), ZERO);
        T1 = pw_sqr(apply_change_coord(phi.M, T1, true));
        T2 = pw_sqr(apply_change_coord(phi.M, T2, false));
        var im = pw_mul(hadamard(th(sub(T1.x, T2.x), sub(T1.y, T2.y), sub(T1.z, T2.z), sub(T1.t, T2.t))), aux_inv);
        return dual_codomain ? im : hadamard(im);
    }
    function gluing_eval_special(P, phi) {
        var T = sq_theta(couple_point_to_theta(phi.M, P));
        if (!is0(T.t)) { return null; }
        var n = phi.inv_dual_theta_null;
        return hadamard(th(mul(T.x, n.x), mul(T.y, n.y), mul(T.z, n.z), ZERO));
    }
    /* the double-and-add ladder on (P, O): returns ([2^k]P, [2^k - 1]P) given P normalised */
    function gluing_double(T, diff, k, E) {
        var R1 = T.P1, R0 = T.P2, r;
        for (var i = k; i > 0; i--) { r = xDBLADD(R1, R0, diff, E.A24, true); R1 = r[0]; R0 = r[1]; }
        return { P1: R1, P2: R0 };
    }
    function gluing_start_chain(E12, P12, ker, todo, verify) {
        var current = 0, z = batched_inv([ker.T1.P1.z, ker.T1.P2.z, ker.T2.P1.z, ker.T2.P2.z]);
        var T11 = [{ P1: pt(mul(ker.T1.P1.x, z[0]), ONE), P2: INF }], T12 = [{ P1: pt(mul(ker.T1.P2.x, z[1]), ONE), P2: INF }];
        var T21 = [{ P1: pt(mul(ker.T2.P1.x, z[2]), ONE), P2: INF }], T22 = [{ P1: pt(mul(ker.T2.P2.x, z[3]), ONE), P2: INF }];
        while (todo[current] !== 1) {
            ++current;
            var t = todo[current - 1], nd = t >= 16 ? t >> 1 : t - 1;
            T11[current] = gluing_double(T11[current - 1], T11[0].P1, nd, E12[0]);
            T12[current] = gluing_double(T12[current - 1], T12[0].P1, nd, E12[1]);
            T21[current] = gluing_double(T21[current - 1], T21[0].P1, nd, E12[0]);
            T22[current] = gluing_double(T22[current - 1], T22[0].P1, nd, E12[1]);
            todo[current] = t - nd;
        }
        var K1_8 = { P1: T11[current].P1, P2: T12[current].P1 }, K2_8 = { P1: T21[current].P1, P2: T22[current].P1 };
        var phi = gluing_compute(E12, K1_8, K2_8, verify);
        if (!phi) { return null; }
        var pts = [], Q1 = [], Q2 = [], j;
        for (j = 0; j < P12.length; ++j) {
            if (!(pts[j] = gluing_eval_special(P12[j], phi))) { return null; }
        }
        Q1[0] = gluing_eval_bary(bary(K1_8.P1, T11[0].P1, T11[current].P2), bary(K1_8.P2, T12[0].P1, T12[current].P2), phi, phi.inv_K1, true);
        Q2[0] = gluing_eval_bary(bary(K2_8.P1, T21[0].P1, T21[current].P2), bary(K2_8.P2, T22[0].P1, T22[current].P2), phi, phi.inv_K2, true);
        --todo[0];
        var iK1 = th_invert(Q1[0]), iK2 = th_invert(Q2[0]);
        Q1[0] = hadamard(Q1[0]);
        Q2[0] = hadamard(Q2[0]);
        for (j = 1; j < current; ++j) {
            Q1[j] = gluing_eval_bary(bary(T11[j].P1, T11[0].P1, T11[j].P2), bary(T12[j].P1, T12[0].P1, T12[j].P2), phi, iK1, false);
            Q2[j] = gluing_eval_bary(bary(T21[j].P1, T21[0].P1, T21[j].P2), bary(T22[j].P1, T22[0].P1, T22[j].P2), phi, iK2, false);
            --todo[j];
        }
        return { phi: phi, Q1: Q1, Q2: Q2, pts: pts, current: current - 1 };
    }
    function theta_isogeny_compute(T1_8, T2_8, dual_domain, verify) {
        var TT1 = dual_domain ? sq_theta(hadamard(T1_8)) : sq_theta(T1_8);
        var TT2 = dual_domain ? sq_theta(hadamard(T2_8)) : sq_theta(T2_8);
        if (verify && (is0(TT2.x) || is0(TT2.y) || is0(TT2.z) || is0(TT2.t) || is0(TT1.x) || is0(TT1.y))) { return null; }
        var t1 = mul(TT1.y, TT2.t), t2 = mul(TT1.x, TT2.z);
        var A = {
            inv_dual: th(mul(t1, TT2.z), mul(t2, TT2.t), mul(t1, TT2.x), mul(t2, TT2.y)),
            dbl: th(TT2.x, TT1.x, TT1.y, TT2.y), inv_sqr: null, pre: false
        };
        if (verify && !eq(mul(TT1.z, A.inv_dual.z), mul(TT1.t, A.inv_dual.t))) { return null; }
        return A;
    }
    function theta_isogeny_eval(P, A, dual_domain) {
        return pw_mul(dual_domain ? sq_theta(hadamard(P)) : sq_theta(P), A.inv_dual);
    }
    function to_product(P) { return th(add(P.x, P.z), add(P.y, P.t), sub(P.y, P.t), sub(P.x, P.z)); }
    function tensor_to_couple(P) {
        if (!eq(mul(P.x, P.t), mul(P.y, P.z))) { return null; }
        return { P1: pt(P.x, P.z), P2: pt(P.x, P.y) };
    }
    function valid_theta_null(t) {
        return !is0(t.x) && !is0(t.z) && !eq(sqr(sqr(t.x)), sqr(sqr(t.z)));
    }
    function splitting(dnp, pts, mode) {
        dnp = to_product(dnp);
        if (is0(dnp.x) || is0(dnp.y) || is0(dnp.z) || is0(dnp.t)) { return null; }
        var c = tensor_to_couple(dnp), out = [], j, M;
        if (!c) { return null; }
        for (j = 0; j < pts.length; ++j) { if (!(out[j] = tensor_to_couple(to_product(pts[j])))) { return null; } }
        if (mode === -1 && !valid_theta_null(c.P2)) { return null; }
        var E3 = curve(ZERO), E4 = curve(ZERO);
        if (mode === 0 || mode === 1 || mode === -1) {
            if (!(M = theta_to_montgomery(E3, c.P1))) { return null; }
            for (j = 0; j < out.length; ++j) { out[j].P1 = apply_isomorphism(out[j].P1, M); }
        }
        if (mode === 0 || mode === 2) {
            if (!(M = theta_to_montgomery(E4, c.P2))) { return null; }
            for (j = 0; j < out.length; ++j) { out[j].P2 = apply_isomorphism(out[j].P2, M); }
        }
        return { E: [E3, E4], P: out };
    }
    /*
     * The (2^n, 2^n)-isogeny of E1 x E2 with kernel <(T1.P1, T1.P2), (T2.P1, T2.P2)>
     * (points of order 2^(n+2)), evaluated at the couple points P12. mode:
     * 0 both factors of the codomain, 1 the first, 2 the second, -1 the first
     * with the verifier's checks. Null when the chain fails or does not split.
     */
    function theta_chain(n, E12, ker, P12, mode) {
        normalize_A24(E12[0]);
        normalize_A24(E12[1]);
        var todo = [n];
        var g = gluing_start_chain(E12, P12, ker, todo, mode === -1);
        var current = g ? g.current : 0, Q1 = g ? g.Q1 : [], Q2 = g ? g.Q2 : [], pts = g ? g.pts : [], j;
        if (!g) { return null; }
        var step = { inv_dual: th_invert(g.phi.codomain), dbl: null, inv_sqr: th_invert(sq_theta(g.phi.codomain)), pre: true };
        for (var i = 1; current >= 0 && todo[current]; ++i) {
            var dual = i !== 1;
            while (todo[current] !== 1) {
                ++current;
                var nd = todo[current - 1] >> 1;
                Q1[current] = th_DBL_iter(Q1[current - 1], step, nd);
                Q2[current] = th_DBL_iter(Q2[current - 1], step, nd);
                todo[current] = todo[current - 1] - nd;
            }
            step = theta_isogeny_compute(Q1[current], Q2[current], dual, i === n - 1 ? false : mode === -1);
            if (!step) { return null; }
            for (j = 0; j < pts.length; ++j) { pts[j] = theta_isogeny_eval(pts[j], step, dual); }
            for (j = 0; j < current; ++j) {
                Q1[j] = theta_isogeny_eval(Q1[j], step, dual);
                Q2[j] = theta_isogeny_eval(Q2[j], step, dual);
                --todo[j];
            }
            --current;
        }
        return splitting(dual_null_point(step), pts, mode);
    }

    /* ---------------- the signer's curve arithmetic ---------------- */

    function sel(c, a, b) { return c ? b : a; }
    /* [k]P + [l]Q from P, Q, P - Q, the reference's constant-time double ladder (kbits > 1) */
    function xDBLMUL(P, k, Q, l, PQ, kbits, E) {
        if (has_zero_coordinate(P) || has_zero_coordinate(Q) || has_zero_coordinate(PQ)) { return null; }
        var M = (1n << BigInt(kbits)) - 1n, bk = Number(k & 1n), bl = Number(l & 1n);
        var s0 = bk ^ 1, s1 = bl ^ 1, mev = (s0 + s1) & 1, pre = 0, i, t;
        s0 = mev ? s0 : 0;
        s1 = mev ? s1 : 1;
        var kt = bk ? k : (k - 1n) & M, lt = bl ? l : (l - 1n) & M, r = [];
        for (i = 0; i < kbits; i++) {
            if (s0 ^ pre) { t = kt; kt = lt; lt = t; }
            var b1n = 0, b2n = 0;
            if (i !== kbits - 1) { b1n = Number(kt & 1n); kt >>= 1n; b2n = Number(lt & 1n); lt >>= 1n; }
            r[2 * i] = Number(kt & 1n) ^ b1n;
            r[2 * i + 1] = Number(lt & 1n) ^ b2n;
            pre = s0;
            if (r[2 * i + 1]) { t = s0; s0 = s1; s1 = t; }
        }
        var R0 = INF, R1 = sel(s0, P, Q), R2 = sel(s0, Q, P), D1a = R1, D1b = R2;
        R2 = xADD(R1, R2, PQ);
        if (has_zero_coordinate(R2)) { return null; }
        var D2a = R2, D2b = PQ, A0 = is0(E.A);
        for (i = kbits - 1; i >= 0; i--) {
            var h = r[2 * i] + r[2 * i + 1];
            var T0 = sel(h >> 1, sel(h & 1, R0, R1), R2);
            T0 = A0 ? xDBL_E0(T0) : xDBL_A24(T0, E.A24, true);
            var m = r[2 * i + 1], T1 = sel(m, R0, R1), T2 = sel(m, R1, R2);
            if (m) { t = D1a; D1a = D1b; D1b = t; }
            T1 = xADD(T1, T2, D1a);
            T2 = xADD(R0, R2, D2a);
            if (h & 1) { t = D2a; D2a = D2b; D2b = t; }
            R0 = T0; R1 = T1; R2 = T2;
        }
        return (bk & bl) ? R2 : sel(mev, R0, R1);
    }
    function biscalar_mul(a, b, kbits, B, E) {
        if (is0(B.PmQ.z)) { return null; }
        if (kbits === 1) {
            if (!is_two_torsion(B.P, E) || !is_two_torsion(B.Q, E) || !is_two_torsion(B.PmQ, E)) { return null; }
            return sel(a & 1n, sel(b & 1n, INF, B.Q), sel(b & 1n, B.P, B.PmQ));
        }
        var E1 = copy_curve(E), M = (1n << BigInt(kbits)) - 1n;
        if (!is0(E.A)) { normalize_A24(E1); }
        return xDBLMUL(B.P, a & M, B.Q, b & M, B.PmQ, kbits, E1);
    }
    function dbl_iter_basis(B, n, E) { return { P: dbl_iter(B.P, n, E), Q: dbl_iter(B.Q, n, E), PmQ: dbl_iter(B.PmQ, n, E) }; }

    /* the Tate pairing's discrete logarithms, through cubical arithmetic */
    function cubicalADD(P, Q, ix) {
        var t0 = mul(add(P.x, P.z), sub(Q.x, Q.z)), t1 = mul(sub(P.x, P.z), add(Q.x, Q.z));
        return pt(mul(ix, sqr(add(t0, t1))), sqr(sub(t0, t1)));
    }
    function cubicalDBLADD(P, Q, ix, A24) {
        var t0 = add(P.x, P.z), t1 = sub(P.x, P.z), s = add(Q.x, Q.z), t3 = sub(Q.x, Q.z);
        var t2 = sqr(s), QQz = sqr(t3);
        t0 = mul(t0, t3);
        t1 = mul(t1, s);
        var PpQ = pt(mul(ix, sqr(add(t0, t1))), sqr(sub(t0, t1)));
        t3 = sub(t2, QQz);
        return [PpQ, pt(mul(t2, QQz), mul(add(mul(t3, A24.x), QQz), t3))];
    }
    function translate(P, T) {
        if (is0(T.z)) { return P; }
        if (is0(T.x)) { return pt(P.z, P.x); }
        return pt(sub(mul(T.x, P.x), mul(T.z, P.z)), sub(mul(T.z, P.x), mul(T.x, P.z)));
    }
    function point_ratio(PnQ, nQ, P) { return pt(mul(nQ.x, P.x), PnQ.x); }
    function kappa(P, Q, E) {
        var xx = mul(P.x, Q.x), xz = mul(P.x, Q.z), zx = mul(P.z, Q.x), zz = mul(P.z, Q.z);
        var k01 = mul(mul(xx, zz), E.A);
        k01 = add(k01, k01);
        k01 = add(k01, mul(mul(add(xx, zz), add(xz, zx)), E.C));
        return [sqr(sub(xx, zz)), add(k01, k01), sqr(sub(xz, zx))];
    }
    function shared_difference(P1, P2, P1Q, P2Q, E) {
        var a = kappa(P1, P2, E), b = kappa(P1Q, P2Q, E);
        return pt(sub(mul(b[1], a[0]), mul(a[1], b[0])), mul(sub(mul(b[2], a[0]), mul(a[2], b[0])), E.C));
    }
    /* a with f * g^a = 1 for f, g of order dividing 2^e (g given inverted) */
    function dlog_2e(f, g_inv, e) {
        var pf = [f], pg = [g_inv];
        function rec(len, sl) {
            if (len === 0) { return 0n; }
            if (len === 1) {
                var one = fp2_is_one(pf[sl - 1]), ok = one || eq(pf[sl - 1], pg[sl - 1]);
                for (var i = 0; i < sl - 1; i++) {
                    if (!one) { pf[i] = mul(pf[i], pg[i]); }
                    pg[i] = sqr(pg[i]);
                }
                if (!ok) { throw new Error('sqisign: discrete logarithm failed'); }
                return one ? 0n : 1n;
            }
            var right = Math.floor(len * 0.5), left = len - right;
            pf[sl] = pf[sl - 1];
            pg[sl] = pg[sl - 1];
            for (var j = 0; j < left; j++) { pf[sl] = sqr(pf[sl]); pg[sl] = sqr(pg[sl]); }
            var d1 = rec(right, sl + 1), d2 = rec(left, sl);
            return (d2 << BigInt(right)) + d1;
        }
        return rec(e, 1);
    }
    /* [r1, r2, s1, s2] with R = [r1]P + [r2]Q and S = [s1]P + [s2]Q, for bases of E[2^e] */
    function pairing_dlog(PQ, RS, E, e) {
        normalize_A24(E);
        var A24 = E.A24, k = kappa(PQ.P, RS.P, E);
        var z = mul(k[0], k[2]);
        z = add(z, z);
        z = add(z, z);
        var PmR = pt(add(k[1], fp2_sqrt(sub(sqr(k[1]), z))), add(k[2], k[2]));
        var RmQ = shared_difference(RS.P, PQ.Q, PmR, PQ.PmQ, E), PmS = shared_difference(PQ.P, RS.Q, PmR, RS.PmQ, E);
        var SmQ = shared_difference(RS.Q, PQ.Q, PmS, PQ.PmQ, E);
        var t = batched_inv([E.C, PQ.P.x, PQ.Q.x, PQ.P.z, PQ.Q.z, RS.P.z, RS.Q.z, PQ.PmQ.z, PmR.z, PmS.z, RmQ.z, SmQ.z]);
        var ixP = mul(PQ.P.z, t[1]), ixQ = mul(PQ.Q.z, t[2]);
        function n(Pt, ti) { return pt(mul(Pt.x, t[ti]), ONE); }
        var P = n(PQ.P, 3), Q = n(PQ.Q, 4), R = n(RS.P, 5), S = n(RS.Q, 6), PmQ = n(PQ.PmQ, 7);
        PmR = n(PmR, 8); PmS = n(PmS, 9); RmQ = n(RmQ, 10); SmQ = n(SmQ, 11);
        var nP = P, nR = R, nS = S, nPQ = PmQ, PnR = PmR, PnS = PmS, nRQ = RmQ, nSQ = SmQ, r, i;
        for (i = 0; i < E2 - 1; i++) { r = cubicalDBLADD(nPQ, nP, ixQ, A24); nPQ = r[0]; nP = r[1]; }
        for (i = 0; i < e - 1; i++) {
            PnR = cubicalADD(PnR, nR, ixP);
            r = cubicalDBLADD(nRQ, nR, ixQ, A24); nRQ = r[0]; nR = r[1];
            PnS = cubicalADD(PnS, nS, ixP);
            r = cubicalDBLADD(nSQ, nS, ixQ, A24); nSQ = r[0]; nS = r[1];
        }
        nPQ = translate(nPQ, nP); PnR = translate(PnR, nR); nRQ = translate(nRQ, nR);
        PnS = translate(PnS, nS); nSQ = translate(nSQ, nS);
        nP = translate(nP, nP); nR = translate(nR, nR); nS = translate(nS, nS);
        var T = [point_ratio(nPQ, nP, Q), point_ratio(PnR, nR, P), point_ratio(nRQ, nR, Q), point_ratio(PnS, nS, P), point_ratio(nSQ, nS, Q)];
        var w1 = [T[0].x, T[1].x, T[2].z, T[3].x, T[4].z], w2 = [T[0].z, T[1].z, T[2].x, T[3].z, T[4].x];
        for (i = 0; i < 5; i++) { var tmp = w1[i]; w1[i] = mul(w2[i], K.conj(w1[i])); w2[i] = mul(tmp, K.conj(w2[i])); }
        w2 = batched_inv(w2);
        for (i = 0; i < 5; i++) {
            w1[i] = K.pow(mul(w1[i], w2[i]), COF);
            for (var j = 0; j < E2 - e; j++) { w1[i] = sqr(w1[i]); }
        }
        return [dlog_2e(w1[2], w1[0], e), dlog_2e(w1[1], w1[0], e), dlog_2e(w1[4], w1[0], e), dlog_2e(w1[3], w1[0], e)];
    }

    return {
        ZERO: ZERO, ONE: ONE, mul: mul, inv: inv, sqr: sqr, eq: eq, fp2_half: fp2_half,
        pt: pt, INF: INF, curve: curve, copy_curve: copy_curve, verify_A: verify_A, ec_mul: ec_mul,
        ladder3pt: ladder3pt, biscalar_mul: biscalar_mul, biscalar_mul_verif: biscalar_mul_verif, dbl_iter_basis: dbl_iter_basis,
        isogeny_2chain: isogeny_2chain, basis_from_hint: basis_from_hint, basis_to_hint: basis_to_hint,
        theta_chain: theta_chain, pairing_dlog: pairing_dlog
    };
}
