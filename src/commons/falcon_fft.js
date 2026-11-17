/**
 * Falcon's FFT over R[x]/(x^n + 1), operation for operation as the round-3
 * reference computes it
 *
 * Falcon's key generation and signing work on polynomials in FFT form, in
 * floating point. Their outputs are checked against the reference's test
 * vectors bit for bit, and that works only if every floating-point operation
 * here is the one the reference performs, in the same order, rounded the
 * same way.
 *
 * WHY JAVASCRIPT CAN DO THIS EXACTLY. The reference's floating point is IEEE
 * 754 binary64 with round-to-nearest-even and no fused multiply-add: its
 * "int" variant emulates exactly that in integers, and its "fpu" variant
 * relies on the hardware doing exactly that. JavaScript numbers are binary64,
 * every + - * / and Math.sqrt is correctly rounded, and nothing is ever fused
 * or kept in extended precision. So a + b here is fpr_add(a, b) there.
 *
 * WHAT MUST NOT CHANGE. The order of operations, including the ones that
 * look free to reorder: (a*b) - (c*d) and (a*b) + (c*d) as written,
 * x * 0.5 for a half, x + x for a double, 1/m then multiplications for a
 * division. Any rewrite that is "the same mathematically" changes the last
 * bit somewhere and the signatures stop matching.
 *
 * LAYOUT, as in the reference: a polynomial of degree n in FFT form is n
 * doubles, the real parts of the n/2 evaluations at the roots with positive
 * imaginary part first, then their imaginary parts. The other n/2 roots are
 * the conjugates and are not stored, since the polynomials are real.
 */

import { bit_reverse } from './bitpack.js';

/* ---------------- the table of roots ---------------- */

/*
 * GM[2j], GM[2j+1] for j = 1 .. 1023: the root used at butterfly j of the
 * FFT, e^(i*pi*(2*rev_k(j - 2^k) + 1) / 2^(k+1)) for 2^k <= j < 2^(k+1).
 *
 * The reference carries this as a table of 2048 constants. It is computed
 * here instead: each value is cos(pi*m/2048) for some m, correctly rounded
 * to a double, from a 256-bit fixed-point evaluation (pi by Machin's
 * formula, cos(pi/2048) by its Taylor series, the rest by the Chebyshev
 * recurrence). The test checks every entry against the reference's bit
 * patterns. The one entry whose real part is exactly zero, j = 1, is -0 in
 * the reference and is -0 here.
 */
var P = 256n;
function atan_inv(x, one) {
    /* atan(1/x) = sum (-1)^k / ((2k+1) x^(2k+1)) */
    var x2 = x * x, term = one / x, sum = term, k = 1n, sign = -1n;
    while (term !== 0n) {
        term = term / x2;
        sum += sign * (term / (2n * k + 1n));
        sign = -sign; k++;
    }
    return sum;
}

export var GM = /* @__PURE__ */ (function () {
    var G = 32n, one = 1n << (P + G);
    var pi = 16n * atan_inv(5n, one) - 4n * atan_inv(239n, one);
    var theta = pi / 2048n;
    /* cos(theta) = sum (-1)^k theta^(2k) / (2k)! */
    var t2 = (theta * theta) >> (P + G), term = one, c1 = one, k = 1n;
    while (term !== 0n) {
        term = -((term * t2) >> (P + G)) / ((2n * k - 1n) * (2n * k));
        c1 += term; k++;
    }
    var C = new Array(1025);
    C[0] = one; C[1] = c1;
    for (var m = 2; m <= 1024; m++) { C[m] = ((2n * c1 * C[m - 1]) >> (P + G)) - C[m - 2]; }
    /* round to the nearest double: Number() of a BigInt rounds correctly, and the scaling is exact */
    var scale = Math.pow(2, Number(P + G));
    var cosd = function (m) { return Number(C[m]) / scale; };
    function cos_pi(M) { return M <= 1024 ? cosd(M) : -cosd(2048 - M); }  /* cos(pi*M/2048), 0 <= M <= 2048 */

    var gm = new Float64Array(2048);
    for (var j = 1; j < 1024; j++) {
        var kk = 31 - Math.clz32(j), M = (2 * bit_reverse(j - (1 << kk), kk) + 1) << (10 - kk);
        gm[2 * j] = cos_pi(M);
        gm[2 * j + 1] = cos_pi(Math.abs(1024 - M));   /* sin(pi*M/2048), M < 2048 */
    }
    gm[2] = -0;
    return gm;
}());

/* 2/2^logn, the iFFT's final scaling (fpr_p2_tab) */
function p2(logn) { return Math.pow(2, 1 - logn); }

/* ---------------- transforms ---------------- */

export function fft(f, logn) {
    var n = 1 << logn, hn = n >> 1, t = hn;
    for (var u = 1, m = 2; u < logn; u++, m <<= 1) {
        var ht = t >> 1, hm = m >> 1;
        for (var i1 = 0, j1 = 0; i1 < hm; i1++, j1 += t) {
            var j2 = j1 + ht, s_re = GM[(m + i1) << 1], s_im = GM[((m + i1) << 1) + 1];
            for (var j = j1; j < j2; j++) {
                var x_re = f[j], x_im = f[j + hn], y_re = f[j + ht], y_im = f[j + ht + hn];
                var z_re = y_re * s_re - y_im * s_im, z_im = y_re * s_im + y_im * s_re;
                f[j] = x_re + z_re; f[j + hn] = x_im + z_im;
                f[j + ht] = x_re - z_re; f[j + ht + hn] = x_im - z_im;
            }
        }
        t = ht;
    }
}

export function ifft(f, logn) {
    var n = 1 << logn, hn = n >> 1, t = 1, m = n;
    for (var u = logn; u > 1; u--) {
        var hm = m >> 1, dt = t << 1;
        for (var i1 = 0, j1 = 0; j1 < hn; i1++, j1 += dt) {
            var j2 = j1 + t, s_re = GM[(hm + i1) << 1], s_im = -GM[((hm + i1) << 1) + 1];
            for (var j = j1; j < j2; j++) {
                var x_re = f[j], x_im = f[j + hn], y_re = f[j + t], y_im = f[j + t + hn];
                f[j] = x_re + y_re; f[j + hn] = x_im + y_im;
                x_re = x_re - y_re; x_im = x_im - y_im;
                f[j + t] = x_re * s_re - x_im * s_im; f[j + t + hn] = x_re * s_im + x_im * s_re;
            }
        }
        t = dt; m = hm;
    }
    if (logn > 0) {
        var ni = p2(logn);
        for (var k = 0; k < n; k++) { f[k] = f[k] * ni; }
    }
}

/* ---------------- arithmetic in FFT form ---------------- */

export function poly_add(a, b, logn) { for (var u = 0, n = 1 << logn; u < n; u++) { a[u] = a[u] + b[u]; } }
export function poly_sub(a, b, logn) { for (var u = 0, n = 1 << logn; u < n; u++) { a[u] = a[u] - b[u]; } }
export function poly_neg(a, logn) { for (var u = 0, n = 1 << logn; u < n; u++) { a[u] = -a[u]; } }
export function poly_adj(a, logn) { for (var n = 1 << logn, u = n >> 1; u < n; u++) { a[u] = -a[u]; } }
export function poly_mulconst(a, x, logn) { for (var u = 0, n = 1 << logn; u < n; u++) { a[u] = a[u] * x; } }

export function poly_mul(a, b, logn) {
    for (var hn = 1 << (logn - 1), u = 0; u < hn; u++) {
        var a_re = a[u], a_im = a[u + hn], b_re = b[u], b_im = b[u + hn];
        a[u] = a_re * b_re - a_im * b_im;
        a[u + hn] = a_re * b_im + a_im * b_re;
    }
}

/* a * adj(b) */
export function poly_muladj(a, b, logn) {
    for (var hn = 1 << (logn - 1), u = 0; u < hn; u++) {
        var a_re = a[u], a_im = a[u + hn], b_re = b[u], b_im = -b[u + hn];
        a[u] = a_re * b_re - a_im * b_im;
        a[u + hn] = a_re * b_im + a_im * b_re;
    }
}

/* a * adj(a), which is real */
export function poly_mulselfadj(a, logn) {
    for (var hn = 1 << (logn - 1), u = 0; u < hn; u++) {
        var a_re = a[u], a_im = a[u + hn];
        a[u] = a_re * a_re + a_im * a_im;
        a[u + hn] = 0;
    }
}

/* a * b where b is self-adjoint (real in FFT form: only its first half is read) */
export function poly_mul_autoadj(a, b, logn) {
    for (var hn = 1 << (logn - 1), u = 0; u < hn; u++) { a[u] = a[u] * b[u]; a[u + hn] = a[u + hn] * b[u]; }
}

export function poly_div_autoadj(a, b, logn) {
    for (var hn = 1 << (logn - 1), u = 0; u < hn; u++) {
        var ib = 1 / b[u];
        a[u] = a[u] * ib; a[u + hn] = a[u + hn] * ib;
    }
}

/* d = 1 / (a adj(a) + b adj(b)), real */
export function poly_invnorm2(d, a, b, logn) {
    for (var hn = 1 << (logn - 1), u = 0; u < hn; u++) {
        var a_re = a[u], a_im = a[u + hn], b_re = b[u], b_im = b[u + hn];
        d[u] = 1 / ((a_re * a_re + a_im * a_im) + (b_re * b_re + b_im * b_im));
    }
}

/* d = F adj(f) + G adj(g) */
export function poly_add_muladj(d, F, G, f, g, logn) {
    for (var hn = 1 << (logn - 1), u = 0; u < hn; u++) {
        var F_re = F[u], F_im = F[u + hn], G_re = G[u], G_im = G[u + hn];
        var f_re = f[u], f_im = -f[u + hn], g_re = g[u], g_im = -g[u + hn];
        var a_re = F_re * f_re - F_im * f_im, a_im = F_re * f_im + F_im * f_re;
        var b_re = G_re * g_re - G_im * g_im, b_im = G_re * g_im + G_im * g_re;
        d[u] = a_re + b_re; d[u + hn] = a_im + b_im;
    }
}

/*
 * The LDL decomposition of the 2x2 Gram matrix [[g00, g01], [adj g01, g11]]:
 * mu = g01 / g00, d11 = g11 - mu adj(g01), and l10 = adj(mu). In place:
 * g01 becomes l10 and g11 becomes d11.
 */
export function poly_ldl(g00, g01, g11, logn) {
    for (var hn = 1 << (logn - 1), u = 0; u < hn; u++) {
        var g00_re = g00[u], g00_im = g00[u + hn], g01_re = g01[u], g01_im = g01[u + hn];
        var m = 1 / (g00_re * g00_re + g00_im * g00_im);
        var b_re = g00_re * m, b_im = -g00_im * m;
        var mu_re = g01_re * b_re - g01_im * b_im, mu_im = g01_re * b_im + g01_im * b_re;
        var c_re = mu_re * g01_re - mu_im * -g01_im, c_im = mu_re * -g01_im + mu_im * g01_re;
        g11[u] = g11[u] - c_re; g11[u + hn] = g11[u + hn] - c_im;
        g01[u] = mu_re; g01[u + hn] = -mu_im;
    }
}

/*
 * f(x) = f0(x^2) + x f1(x^2): split a polynomial of degree n into two of
 * degree n/2 in FFT form, and merge them back.
 */
export function poly_split(f0, f1, f, logn) {
    var n = 1 << logn, hn = n >> 1, qn = hn >> 1;
    f0[0] = f[0]; f1[0] = f[hn];
    for (var u = 0; u < qn; u++) {
        var a_re = f[u << 1], a_im = f[(u << 1) + hn], b_re = f[(u << 1) + 1], b_im = f[(u << 1) + 1 + hn];
        f0[u] = (a_re + b_re) * 0.5; f0[u + qn] = (a_im + b_im) * 0.5;
        var t_re = a_re - b_re, t_im = a_im - b_im;
        var s_re = GM[(u + hn) << 1], s_im = -GM[((u + hn) << 1) + 1];
        f1[u] = (t_re * s_re - t_im * s_im) * 0.5;
        f1[u + qn] = (t_re * s_im + t_im * s_re) * 0.5;
    }
}

export function poly_merge(f, f0, f1, logn) {
    var n = 1 << logn, hn = n >> 1, qn = hn >> 1;
    f[0] = f0[0]; f[hn] = f1[0];
    for (var u = 0; u < qn; u++) {
        var a_re = f0[u], a_im = f0[u + qn], c_re = f1[u], c_im = f1[u + qn];
        var s_re = GM[(u + hn) << 1], s_im = GM[((u + hn) << 1) + 1];
        var b_re = c_re * s_re - c_im * s_im, b_im = c_re * s_im + c_im * s_re;
        f[u << 1] = a_re + b_re; f[(u << 1) + hn] = a_im + b_im;
        f[(u << 1) + 1] = a_re - b_re; f[(u << 1) + 1 + hn] = a_im - b_im;
    }
}

/* ---------------- rounding as the reference rounds ---------------- */

/* fpr_rint: to the nearest integer, ties to even, for |x| < 2^63 */
export function rint(x) {
    var r = Math.round(x);
    /* Math.round rounds ties up; ties go to even */
    if (r - x === 0.5 && (r % 2) !== 0) { r -= 1; }
    return r === 0 ? 0 : r;
}

/* fpr_floor and fpr_trunc, for values in int range */
export function floor(x) { var r = Math.floor(x); return r === 0 ? 0 : r; }
export function trunc(x) { var r = Math.trunc(x); return r === 0 ? 0 : r; }
