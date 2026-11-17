/**
 * Falcon key generation: the ring mod q, the Gaussian sampling of (f, g),
 * and the solution of the NTRU equation f G - g F = q
 *
 * Bit for bit the round-3 reference's keygen.c: the same (f, g) from the same
 * SHAKE256 stream, the same rejections, and the same (F, G). That last part
 * is what makes this file long. An NTRU equation has many solutions; Falcon
 * wants a SHORT one, found by Babai reduction with floating-point estimates,
 * and which short solution comes out depends on every estimate along the
 * way. Reproducing the reference's test vectors means reproducing its
 * estimates exactly.
 *
 * WHAT IS EXACT AND WHAT IS NOT. The reference works on big integers held as
 * 31-bit words, through residues modulo a list of primes and the CRT; all of
 * that computes exact integers, and here those integers are BigInts. Where
 * the reference APPROXIMATES - the top ten words of a number turned into a
 * double, a word at a time, low word first - this file does exactly the same
 * thing, from the same words (big_to_fp). Where it TRUNCATES - a value kept
 * in fewer words as it shrinks - this file wraps to the same width
 * (BigInt.asIntN). The floating point is commons/falcon_fft.js, operation
 * for operation.
 *
 * THE ALGORITHM (Pornin and Prest, "More Efficient Algorithms for the NTRU
 * Key Generation using the Field Norm", PKC 2019). Taking the field norm
 * N(f)(x^2) = f(x) f(-x) halves the degree; after log n steps f and g are
 * integers, their resultants with x^n + 1, and the equation is solved there
 * by an extended GCD. Each solution is then lifted back one degree at a time,
 * F(x) = F'(x^2) g(-x) and G(x) = G'(x^2) f(-x), and reduced against (f, g)
 * at that degree so that it stays short.
 */

import { shake256 } from '../sha3.js';
import { xof_stream } from './xof_stream.js';
import * as P from './falcon_fft.js';
import { bit_reverse } from './bitpack.js';

export var Q = 12289;

/* ---------------- Z_q[x]/(x^n + 1) ---------------- */

function pow_q(b, e) {
    var r = 1;
    b %= Q;
    while (e > 0) { if (e & 1) { r = (r * b) % Q; } b = (b * b) % Q; e >>= 1; }
    return r;
}

/*
 * NTT tables for each degree: zetas[k] = psi^brv(k) with psi a primitive
 * 2n-th root of unity mod q. 11 generates Z_q^* (the smallest that does),
 * and q - 1 = 2^12 * 3, so 11^(12288 / 2n) is one for every n up to 2048.
 */
var NTT_TABLES = [];
function ntt_table(logn) {
    if (NTT_TABLES[logn]) { return NTT_TABLES[logn]; }
    var n = 1 << logn, psi = pow_q(11, 12288 / (2 * n)), z = new Int32Array(n);
    for (var k = 0; k < n; k++) { z[k] = pow_q(psi, bit_reverse(k, logn)); }
    return (NTT_TABLES[logn] = z);
}

/* in place; coefficients in [0, q) */
export function ntt(a, logn) {
    var n = 1 << logn, z = ntt_table(logn), k = 0;
    for (var len = n >> 1; len > 0; len >>= 1) {
        for (var start = 0; start < n; start += 2 * len) {
            var zeta = z[++k];
            for (var j = start; j < start + len; j++) {
                var t = (zeta * a[j + len]) % Q, x = a[j];
                a[j + len] = x - t < 0 ? x - t + Q : x - t;
                a[j] = x + t >= Q ? x + t - Q : x + t;
            }
        }
    }
}

export function ntt_inverse(a, logn) {
    var n = 1 << logn, z = ntt_table(logn), k = n;
    for (var len = 1; len < n; len <<= 1) {
        for (var start = 0; start < n; start += 2 * len) {
            var zeta = Q - z[--k];
            for (var j = start; j < start + len; j++) {
                var x = a[j], y = a[j + len];
                a[j] = x + y >= Q ? x + y - Q : x + y;
                a[j + len] = (zeta * (x - y < 0 ? x - y + Q : x - y)) % Q;
            }
        }
    }
    var ninv = pow_q(n, Q - 2);
    for (var i = 0; i < n; i++) { a[i] = (a[i] * ninv) % Q; }
}

/* a small signed polynomial, reduced into [0, q) */
export function mod_q(a) {
    var r = new Int32Array(a.length);
    for (var i = 0; i < a.length; i++) { var v = a[i] % Q; r[i] = v < 0 ? v + Q : v; }
    return r;
}

/* a * b / c mod q, or null when c is not invertible (b may be null for a / c) */
export function mul_div_q(a, b, c, logn) {
    var n = 1 << logn, A = mod_q(a), C = mod_q(c);
    ntt(A, logn); ntt(C, logn);
    if (b) { var B = mod_q(b); ntt(B, logn); for (var i = 0; i < n; i++) { A[i] = (A[i] * B[i]) % Q; } }
    for (var j = 0; j < n; j++) {
        if (C[j] === 0) { return null; }
        A[j] = (A[j] * pow_q(C[j], Q - 2)) % Q;
    }
    ntt_inverse(A, logn);
    return A;
}

/* ---------------- sampling (f, g) ---------------- */

/*
 * The cumulative table of a discrete Gaussian of standard deviation
 * 1.17 * sqrt(q / 2048), scaled to 2^63, as [high 31 bits, low 32 bits].
 * For n < 1024 a coefficient is the sum of 1024/n such samples.
 */
var GAUSS = /* @__PURE__ */ [
    1283868770400643928n, 6416574995475331444n, 4078260278032692663n,
    2353523259288686585n, 1227179971273316331n, 575931623374121527n,
    242543240509105209n, 91437049221049666n, 30799446349977173n,
    9255276791179340n, 2478152334826140n, 590642893610164n,
    125206034929641n, 23590435911403n, 3948334035941n,
    586753615614n, 77391054539n, 9056793210n,
    940121950n, 86539696n, 7062824n,
    510971n, 32764n, 1862n,
    94n, 4n, 0n
].map(function (v) { return [Number(v >> 32n), Number(v & 0xffffffffn)]; });

/* 1 when the 63-bit value (hi, lo) is below table entry t, else 0 */
function below(hi, lo, t) {
    var dh = hi - t[0];
    return (dh < 0) | ((dh === 0) & (lo < t[1]));
}

function mkgauss(rng, logn) {
    var val = 0;
    for (var u = 0, iters = 1 << (10 - logn); u < iters; u++) {
        var b = rng.read(8), neg = b[7] >> 7;
        var hi = ((b[4] | (b[5] << 8) | (b[6] << 16) | ((b[7] & 0x7f) << 24)) >>> 0);
        var lo = ((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0);
        var f = below(hi, lo, GAUSS[0]), v = 0;
        b = rng.read(8);
        hi = ((b[4] | (b[5] << 8) | (b[6] << 16) | ((b[7] & 0x7f) << 24)) >>> 0);
        lo = ((b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0);
        for (var k = 1; k < GAUSS.length; k++) {
            var t = below(hi, lo, GAUSS[k]) ^ 1;
            v |= k & -(t & (f ^ 1));
            f |= t;
        }
        val += neg ? -v : v;
    }
    return val;
}

/* n coefficients in [-127, 127], with an odd sum (so the resultant is odd) */
function poly_small_mkgauss(rng, logn) {
    var n = 1 << logn, f = new Int8Array(n), mod2 = 0;
    for (var u = 0; u < n; u++) {
        var s;
        for (;;) {
            s = mkgauss(rng, logn);
            if (s < -127 || s > 127) { continue; }
            if (u === n - 1) { if ((mod2 ^ (s & 1)) === 0) { continue; } } else { mod2 ^= s & 1; }
            break;
        }
        f[u] = s;
    }
    return f;
}

/* ---------------- exact polynomial arithmetic ---------------- */

/*
 * Polynomials are plain arrays of Numbers while every product stays below
 * 2^53, and of BigInts beyond. The first levels of the tower (degree 1024
 * and 512, coefficients of a few bits) are most of the multiplications and
 * cost microseconds as doubles; BigInt there would be seconds.
 */
function maxabs(a) {
    var m = 0;
    for (var i = 0; i < a.length; i++) { var v = typeof a[i] === 'bigint' ? Number(a[i] < 0n ? -a[i] : a[i]) : Math.abs(a[i]); if (v > m) { m = v; } }
    return m;
}

/* a * b mod x^n + 1, n = a.length = b.length */
function mul_nc(a, b) {
    var n = a.length, r = new Array(n), i, j;
    if (maxabs(a) * maxabs(b) * n < 4503599627370496) {
        var a_ = a.map(Number), b_ = b.map(Number), acc = new Float64Array(n);
        for (i = 0; i < n; i++) {
            var ai = a_[i];
            if (ai === 0) { continue; }
            for (j = 0; j < n - i; j++) { acc[i + j] += ai * b_[j]; }
            for (j = n - i; j < n; j++) { acc[i + j - n] -= ai * b_[j]; }
        }
        for (i = 0; i < n; i++) { r[i] = acc[i] + 0; }
        return r;
    }
    var A = a.map(BigInt), B = b.map(BigInt), R = new Array(n).fill(0n);
    for (i = 0; i < n; i++) {
        var x = A[i];
        if (x === 0n) { continue; }
        for (j = 0; j < n - i; j++) { R[i + j] += x * B[j]; }
        for (j = n - i; j < n; j++) { R[i + j - n] -= x * B[j]; }
    }
    return R;
}

function add_p(a, b, sign) {
    var r = new Array(a.length), big = typeof a[0] === 'bigint' || typeof b[0] === 'bigint';
    for (var i = 0; i < a.length; i++) {
        r[i] = big ? BigInt(a[i]) + (sign < 0 ? -BigInt(b[i]) : BigInt(b[i])) : a[i] + sign * b[i];
    }
    return r;
}

/* even and odd halves: f(x) = fe(x^2) + x fo(x^2) */
function evens(f) { var r = []; for (var i = 0; i < f.length; i += 2) { r.push(f[i]); } return r; }
function odds(f) { var r = []; for (var i = 1; i < f.length; i += 2) { r.push(f[i]); } return r; }

/* x * a mod x^m + 1 */
function times_x(a) {
    var m = a.length, r = new Array(m);
    r[0] = typeof a[m - 1] === 'bigint' ? -a[m - 1] : -a[m - 1] + 0;
    for (var i = 1; i < m; i++) { r[i] = a[i - 1]; }
    return r;
}

/* the field norm: N(f)(y) = fe(y)^2 - y fo(y)^2, so that N(f)(x^2) = f(x) f(-x) */
function field_norm(f) {
    var e = evens(f), o = odds(f);
    return add_p(mul_nc(e, e), times_x(mul_nc(o, o)), -1);
}

/* F'(x^2) * g(-x), from F' of degree n/2 and g of degree n */
function lift(Fp, g) {
    var e = mul_nc(Fp, evens(g)), o = mul_nc(Fp, odds(g)), n = g.length, r = new Array(n);
    for (var i = 0; i < n / 2; i++) { r[2 * i] = e[i]; r[2 * i + 1] = typeof o[i] === 'bigint' ? -o[i] : -o[i] + 0; }
    return r;
}

function to_big(a) { return a.map(BigInt); }
function wrap(a, words) { var b = BigInt(31 * words); return a.map(function (v) { return BigInt.asIntN(Number(b), BigInt(v)); }); }

/*
 * poly_big_to_fp: a signed big integer as a double, the way the reference
 * builds it - its absolute value's 31-bit words, low word first, each
 * scaled by its power of 2^31 and added in turn. Every product is exact;
 * the additions round, and their order is what fixes the result.
 */
function big_to_fp(v) {
    if (typeof v !== 'bigint') { v = BigInt(v); }
    if (v === 0n) { return 0; }
    var neg = v < 0n, a = neg ? -v : v, x = 0, sc = 1;
    while (a > 0n) {
        var w = Number(a & 0x7fffffffn);
        x = x + (neg ? -w : w) * sc;
        sc *= 2147483648;
        a >>= 31n;
    }
    return x;
}

/* the top `rlen` of `len` words of each coefficient, as doubles */
function top_to_fp(a, len, rlen) {
    var sh = BigInt(31 * (len - rlen)), r = new Float64Array(a.length);
    for (var i = 0; i < a.length; i++) { r[i] = big_to_fp(BigInt(a[i]) >> sh); }
    return r;
}

/* ---------------- solving f G - g F = q ---------------- */

/* the reference's word budgets per depth, and the expected bit lengths of (f, g) */
var MAX_BL_SMALL = [1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209];
var MAX_BL_LARGE = [2, 2, 5, 7, 12, 21, 40, 78, 157, 308];
var BITLENGTH = [[4, 0], [11, 1], [24, 1], [50, 1], [102, 1], [202, 2], [401, 4], [794, 5], [1577, 8], [3138, 13], [6308, 25]];
var P0 = 2147473409;   /* the first of the reference's 31-bit primes: depth 0 works modulo it */

function modinv_big(a, m) {
    var r0 = m, r1 = ((a % m) + m) % m, t0 = 0n, t1 = 1n;
    while (r1 !== 0n) { var qq = r0 / r1; var r2 = r0 - qq * r1; r0 = r1; r1 = r2; var t2 = t0 - qq * t1; t0 = t1; t1 = t2; }
    return r0 === 1n ? ((t0 % m) + m) % m : null;
}

/*
 * The deepest level: x = Res(f), y = Res(g), both positive. zint_bezout
 * finds u, v with x u - y v = 1, 0 <= u <= y, 0 <= v <= x - the unique such
 * pair - and fails unless both are odd and coprime. Then (F, G) = (q v, q u),
 * stored in MAX_BL_SMALL[logn] words, and too large for them is a failure.
 */
function solve_deepest(x, y, logn) {
    if ((x & 1n) === 0n || (y & 1n) === 0n) { return null; }
    var u, v;
    if (y === 1n) { u = 1n; v = x - 1n; } else {
        u = modinv_big(x, y);
        if (u === null) { return null; }
        v = (x * u - 1n) / y;
    }
    var cap = 1n << BigInt(31 * MAX_BL_SMALL[logn]), Fq = v * 12289n, Gq = u * 12289n;
    if (Fq >= cap || Gq >= cap) { return null; }
    return { F: [Fq], G: [Gq] };
}

/* k * f mod x^n + 1 with k a polynomial of small Numbers */
function scaled_sub(F, k, f, scale, words) {
    var kf = mul_nc(k, f), s = BigInt(scale), b = 31 * words, r = new Array(F.length);
    for (var i = 0; i < F.length; i++) { r[i] = BigInt.asIntN(b, BigInt(F[i]) - (BigInt(kf[i]) << s)); }
    return r;
}

/*
 * One level up, with its reduction (solve_NTRU_intermediate). ft, gt are
 * the field norms at this depth; Fd, Gd the solution one level down.
 */
function solve_intermediate(logn_top, depth, ft, gt, Fd, Gd) {
    var logn = logn_top - depth, n = 1 << logn;
    var slen = MAX_BL_SMALL[depth], llen = MAX_BL_LARGE[depth];
    var F = lift(Fd, gt), G = lift(Gd, ft);

    var rlen = Math.min(slen, 10);
    var rt3 = top_to_fp(ft, slen, rlen), rt4 = top_to_fp(gt, slen, rlen), rt5 = new Float64Array(n);
    var scale_fg = 31 * (slen - rlen);
    var minbl_fg = BITLENGTH[depth][0] - 6 * BITLENGTH[depth][1];
    var maxbl_fg = BITLENGTH[depth][0] + 6 * BITLENGTH[depth][1];
    P.fft(rt3, logn); P.fft(rt4, logn);
    P.poly_invnorm2(rt5, rt3, rt4, logn);
    P.poly_adj(rt3, logn); P.poly_adj(rt4, logn);

    var FGlen = llen, maxbl_FG = 31 * llen, scale_k = maxbl_FG - minbl_fg;
    F = wrap(F, FGlen); G = wrap(G, FGlen);
    var k = new Array(n);
    for (;;) {
        rlen = Math.min(FGlen, 10);
        var scale_FG = 31 * (FGlen - rlen);
        var rt1 = top_to_fp(F, FGlen, rlen), rt2 = top_to_fp(G, FGlen, rlen);
        P.fft(rt1, logn); P.fft(rt2, logn);
        P.poly_mul(rt1, rt3, logn); P.poly_mul(rt2, rt4, logn);
        P.poly_add(rt2, rt1, logn);
        P.poly_mul_autoadj(rt2, rt5, logn);
        P.ifft(rt2, logn);

        /* 2^-dc by square and multiply, as the reference computes it (every step exact) */
        var dc = scale_k - scale_FG + scale_fg, pt = 0.5, pdc = 1;
        if (dc < 0) { dc = -dc; pt = 2; }
        while (dc !== 0) { if (dc & 1) { pdc = pdc * pt; } dc >>= 1; pt = pt * pt; }
        for (var u = 0; u < n; u++) {
            var xv = rt2[u] * pdc;
            if (!(-2147483647 < xv) || !(xv < 2147483647)) { return null; }
            k[u] = P.rint(xv);
        }
        F = scaled_sub(F, k, ft, scale_k, FGlen);
        G = scaled_sub(G, k, gt, scale_k, FGlen);

        var new_maxbl_FG = scale_k + maxbl_fg + 10;
        if (new_maxbl_FG < maxbl_FG) {
            maxbl_FG = new_maxbl_FG;
            if (FGlen * 31 >= maxbl_FG + 31) { FGlen--; F = wrap(F, FGlen); G = wrap(G, FGlen); }
        }
        if (scale_k <= 0) { break; }
        scale_k -= 25;
        if (scale_k < 0) { scale_k = 0; }
    }
    return { F: wrap(F, slen), G: wrap(G, slen) };
}

/*
 * Depth 1 (solve_NTRU_binary_depth1): the lifted (F, G) are small enough
 * that the whole reduction is done once, in floating point, on the full
 * values. The result is kept as the reference keeps it, in one 31-bit word.
 */
function solve_depth1(logn_top, ft, gt, Fd, Gd) {
    var logn = logn_top - 1, n = 1 << logn;
    var F = lift(Fd, gt), G = lift(Gd, ft);
    var rt1 = new Float64Array(n), rt2 = new Float64Array(n), rt3 = new Float64Array(n), rt4 = new Float64Array(n);
    for (var i = 0; i < n; i++) { rt1[i] = big_to_fp(F[i]); rt2[i] = big_to_fp(G[i]); rt3[i] = big_to_fp(ft[i]); rt4[i] = big_to_fp(gt[i]); }
    P.fft(rt1, logn); P.fft(rt2, logn); P.fft(rt3, logn); P.fft(rt4, logn);
    var rt5 = new Float64Array(n), rt6 = new Float64Array(n);
    P.poly_add_muladj(rt5, rt1, rt2, rt3, rt4, logn);
    P.poly_invnorm2(rt6, rt3, rt4, logn);
    P.poly_mul_autoadj(rt5, rt6, logn);
    P.ifft(rt5, logn);
    for (var u = 0; u < n; u++) {
        var z = rt5[u];
        /* fpr_ptwo63m1 is the double nearest 2^63 - 1, which is 2^63 */
        if (!(z < 9223372036854775807) || !(-9223372036854775807 < z)) { return null; }
        rt5[u] = P.rint(z);
    }
    P.fft(rt5, logn);
    P.poly_mul(rt3, rt5, logn); P.poly_mul(rt4, rt5, logn);
    P.poly_sub(rt1, rt3, logn); P.poly_sub(rt2, rt4, logn);
    P.ifft(rt1, logn); P.ifft(rt2, logn);
    var Fo = new Array(n), Go = new Array(n);
    for (var v = 0; v < n; v++) { Fo[v] = word31(P.rint(rt1[v])); Go[v] = word31(P.rint(rt2[v])); }
    return { F: Fo, G: Go };
}

/* (uint32_t) of an int64, then read back as a one-word signed value: the low 31 bits, sign-extended */
function word31(x) { return Number(BigInt.asIntN(31, BigInt(x))); }

/* the centred residue modulo P0, of a Number or a BigInt */
function center_p0(v) {
    var r = typeof v === 'bigint' ? Number(((v % BigInt(P0)) + BigInt(P0)) % BigInt(P0)) : ((v % P0) + P0) % P0;
    return r > (P0 - 1) / 2 ? r - P0 : r;
}

/* adj(f): f(1/x) mod x^n + 1 */
function adj(f) {
    var n = f.length, r = new Array(n);
    r[0] = f[0];
    for (var u = 1; u < n; u++) { r[n - u] = -f[u]; }
    return r;
}

/*
 * Depth 0 (solve_NTRU_binary_depth0): everything modulo the first prime,
 * which the values fit in, and one floating-point quotient.
 */
function solve_depth0(logn, f, g, Fd, Gd) {
    var n = 1 << logn;
    var F = lift(Fd, Array.from(g)).map(center_p0), G = lift(Gd, Array.from(f)).map(center_p0);
    var t2 = add_p(mul_nc(F, adj(Array.from(f))), mul_nc(G, adj(Array.from(g))), 1).map(center_p0);
    var t3 = add_p(mul_nc(Array.from(f), adj(Array.from(f))), mul_nc(Array.from(g), adj(Array.from(g))), 1).map(center_p0);
    var rt2 = Float64Array.from(t3), rt3 = Float64Array.from(t2);
    P.fft(rt2, logn); P.fft(rt3, logn);
    P.poly_div_autoadj(rt3, rt2, logn);
    P.ifft(rt3, logn);
    var k = new Array(n);
    for (var u = 0; u < n; u++) { k[u] = Number(BigInt.asIntN(32, BigInt(P.rint(rt3[u])))); }
    var kf = mul_nc(k, Array.from(f)), kg = mul_nc(k, Array.from(g)), Fo = new Array(n), Go = new Array(n);
    for (var v = 0; v < n; v++) { Fo[v] = word31(center_p0(BigInt(F[v]) - BigInt(kf[v]))); Go[v] = word31(center_p0(BigInt(G[v]) - BigInt(kg[v]))); }
    return { F: Fo, G: Go };
}

/* (F, G) with every coefficient in [-lim, lim] and f G - g F = q, or null */
function solve_ntru(logn, f, g, lim) {
    var norms = [Array.from(f)], gn = [Array.from(g)];
    for (var d = 1; d <= logn; d++) { norms.push(field_norm(norms[d - 1])); gn.push(field_norm(gn[d - 1])); }
    var r = solve_deepest(BigInt(norms[logn][0]), BigInt(gn[logn][0]), logn);
    if (r === null) { return null; }
    var stop = logn <= 2 ? 0 : 2;
    for (var depth = logn - 1; depth >= stop; depth--) {
        /* the previous level's values are read as signed in its word budget */
        var dl = MAX_BL_SMALL[depth + 1];
        r = solve_intermediate(logn, depth, wrap(norms[depth], MAX_BL_SMALL[depth]), wrap(gn[depth], MAX_BL_SMALL[depth]), wrap(r.F, dl), wrap(r.G, dl));
        if (r === null) { return null; }
    }
    if (logn > 2) {
        r = solve_depth1(logn, wrap(norms[1], MAX_BL_SMALL[1]), wrap(gn[1], MAX_BL_SMALL[1]), wrap(r.F, MAX_BL_SMALL[2]), wrap(r.G, MAX_BL_SMALL[2]));
        if (r === null) { return null; }
        r = solve_depth0(logn, f, g, r.F, r.G);
    } else {
        r = { F: r.F.map(function (v) { return word31(v); }), G: r.G.map(function (v) { return word31(v); }) };
    }
    var n = 1 << logn, F = new Int8Array(n), G = new Int8Array(n);
    for (var u = 0; u < n; u++) {
        if (r.F[u] < -lim || r.F[u] > lim || r.G[u] < -lim || r.G[u] > lim) { return null; }
        F[u] = r.F[u]; G[u] = r.G[u];
    }
    /* the check the reference makes last: f G - g F = q, here over the integers (the values are small) */
    var e = add_p(mul_nc(Array.from(f), Array.from(G)), mul_nc(Array.from(g), Array.from(F)), -1);
    if (e[0] !== 12289) { return null; }
    for (var w = 1; w < n; w++) { if (e[w] !== 0) { return null; } }
    return { F: F, G: G };
}

/* ---------------- key generation ---------------- */

var MAX_FG_BITS = [0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5];

/**
 * keygen.c's Zf(keygen) from a seed: SHAKE256(seed) drives the sampling.
 * Returns { f, g, F, G, h } - Int8Arrays, and h in [0, q).
 */
export function keygen(seed, logn) {
    var n = 1 << logn, rng = xof_stream(shake256, seed, 64 * n);
    for (;;) {
        var f = poly_small_mkgauss(rng, logn), g = poly_small_mkgauss(rng, logn);
        var lim = 1 << (MAX_FG_BITS[logn] - 1), ok = true, u;
        for (u = 0; u < n; u++) { if (f[u] >= lim || f[u] <= -lim || g[u] >= lim || g[u] <= -lim) { ok = false; break; } }
        if (!ok) { continue; }
        var norm = 0;
        for (u = 0; u < n; u++) { norm += f[u] * f[u] + g[u] * g[u]; }
        if (norm >= 16823) { continue; }

        /* the Gram-Schmidt norm of the other basis vector, q adj(f, g) / (f adj f + g adj g) */
        var rt1 = Float64Array.from(f), rt2 = Float64Array.from(g), rt3 = new Float64Array(n);
        P.fft(rt1, logn); P.fft(rt2, logn);
        P.poly_invnorm2(rt3, rt1, rt2, logn);
        P.poly_adj(rt1, logn); P.poly_adj(rt2, logn);
        P.poly_mulconst(rt1, 12289, logn); P.poly_mulconst(rt2, 12289, logn);
        P.poly_mul_autoadj(rt1, rt3, logn); P.poly_mul_autoadj(rt2, rt3, logn);
        P.ifft(rt1, logn); P.ifft(rt2, logn);
        var bnorm = 0;
        for (u = 0; u < n; u++) { bnorm = bnorm + rt1[u] * rt1[u]; bnorm = bnorm + rt2[u] * rt2[u]; }
        if (!(bnorm < 16822.4121)) { continue; }

        var h = mul_div_q(g, null, f, logn);
        if (h === null) { continue; }
        var FG = solve_ntru(logn, f, g, 127);
        if (FG === null) { continue; }
        return { f: f, g: g, F: FG.F, G: FG.G, h: h };
    }
}
