/**
 * Classic McEliece - the oldest public-key encryption still unbroken
 * (McEliece, 1978), as a KEM: the round-4 submission of 2022-10-23, the
 * version in the ISO process; byte-compatible with its KATs and its Sage
 * specification (classic.mceliece.org).
 *
 * WHY IT IS HERE. Its security assumption - decoding a random-looking binary
 * Goppa code - has survived 45 years of cryptanalysis, quantum algorithms
 * included, with no change of parameters beyond the expected. Germany's BSI
 * and the Netherlands' NLNCSA recommend it for long-term confidentiality.
 * The price is the public key: 261 KB at the smallest set, 1.36 MB at the
 * largest. Ciphertexts are tiny (96-208 bytes) and encapsulation is fast.
 *
 *     mceliece348864   mceliece460896   mceliece6688128   mceliece6960119   mceliece8192128
 *     and each with f: key generation in semi-systematic form, which
 *     succeeds far more often (the keys and ciphertexts are the same format)
 *
 * HOW IT WORKS. The secret is a Goppa code: a monic irreducible g(x) of
 * degree t over GF(2^m) and a support α_0..α_{n−1}, distinct field elements.
 * The public key is the code's parity-check matrix in systematic form (I | T),
 * only T stored. Encapsulation picks an error e of weight exactly t and sends
 * its syndrome C = H·e; only the holder of g and α can decode t errors.
 * K = SHAKE256(1 ‖ e ‖ C); a failed decoding gives SHAKE256(0 ‖ s ‖ C) -
 * implicit rejection, never an error.
 *
 * CONSTANT TIME, as far as JavaScript allows. GF(2^m) multiplication is
 * carry-less arithmetic, not log/exp tables indexed by secrets; the field
 * ordering and the control bits of the permutation network are computed
 * with a Batcher sorting network; Gaussian elimination, the Berlekamp-
 * Massey decoder and the root search use masks, not branches, on secrets.
 *
 * The secret key carries the support as the control bits of a Beneš
 * network (Bernstein, "Verified fast formulas for control bits for
 * permutation networks", 2020), as the specification encodes it.
 */
import { shake256 } from './sha3.js';
import { concat } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';

/* the specification's parameter sets: f(z) as an integer, F(y) as its lower terms [degree, coefficient] */
var F12 = 0x1009, F13 = 0x201b;
var SETS = {
    mceliece348864:  { m: 12, n: 3488, t: 64,  f: F12, F: [[3, 1], [1, 1], [0, 2]] },              /* y^64 + y^3 + y + z */
    mceliece460896:  { m: 13, n: 4608, t: 96,  f: F13, F: [[10, 1], [9, 1], [6, 1], [0, 1]] },
    mceliece6688128: { m: 13, n: 6688, t: 128, f: F13, F: [[7, 1], [2, 1], [1, 1], [0, 1]] },
    mceliece6960119: { m: 13, n: 6960, t: 119, f: F13, F: [[8, 1], [0, 1]] },
    mceliece8192128: { m: 13, n: 8192, t: 128, f: F13, F: [[7, 1], [2, 1], [1, 1], [0, 1]] }
};
var L_BYTES = 32, SIGMA1 = 16, SIGMA2 = 32, MU = 32, NU = 64;

/* ---------------- constant-time helpers ---------------- */
function nonzero(x) { return ((x | -x) >>> 31) & 1; }                     /* 1 if x != 0 (x < 2^31) */
function lt_u32(x, y) { return ((x ^ ((x ^ y) | (((x - y) | 0) ^ y))) >>> 31) & 1; }   /* x < y, unsigned */

/*
 * Batcher's odd-even merge sort (the network djbsort uses), on a
 * power-of-two length: the same compares and swaps whatever the data.
 * `cmp_swap(i, j)` puts the smaller at i.
 */
function sorting_network(n, cmp_swap) {
    for (var p = 1; p < n; p <<= 1) {
        for (var k = p; k >= 1; k >>= 1) {
            for (var j = k % p; j + k < n; j += 2 * k) {
                for (var i = 0; i < Math.min(k, n - j - k); i++) {
                    if (Math.floor((i + j) / (2 * p)) === Math.floor((i + j + k) / (2 * p))) { cmp_swap(i + j, i + j + k); }
                }
            }
        }
    }
}
/* sort u32 values below 2^31 */
function sort_u31(a) {
    sorting_network(a.length, function (i, j) {
        var x = a[i], y = a[j], m = ((y - x) >> 31);        /* -1 if y < x */
        a[i] = (x & ~m) | (y & m); a[j] = (y & ~m) | (x & m);
    });
}

/* ---------------- the Beneš network's control bits (controlbits.py) ---------------- */
/* composeinv(c, π): out[π[i]] = c[i], by sorting (π[i], c[i]) - not a secret-indexed store */
function composeinv(c, pi) {
    var n = pi.length, w = new Uint32Array(n);
    for (var i = 0; i < n; i++) { w[i] = (pi[i] << 14) | c[i]; }
    sort_u31(w);
    var out = new Uint32Array(n);
    for (var j = 0; j < n; j++) { out[j] = w[j] & 0x3fff; }
    return out;
}
function control_bits(pi) {
    var n = pi.length, m = Math.log2(n) | 0, x, j;
    if (m === 1) { return [pi[0]]; }
    var p = new Uint32Array(n), q = new Uint32Array(n), id = new Uint32Array(n);
    for (x = 0; x < n; x++) { p[x] = pi[x ^ 1]; q[x] = pi[x] ^ 1; id[x] = x; }
    var piinv = composeinv(id, pi);
    var np = composeinv(p, q), nq = composeinv(q, p); p = np; q = nq;
    var c = new Uint32Array(n);
    for (x = 0; x < n; x++) { var a = p[x], lo = -lt_u32(x, a); c[x] = (x & lo) | (a & ~lo); }
    np = composeinv(p, q); nq = composeinv(q, p); p = np; q = nq;
    for (var i = 1; i < m - 1; i++) {
        var cp = composeinv(c, q);
        np = composeinv(p, q); nq = composeinv(q, p); p = np; q = nq;
        for (x = 0; x < n; x++) { var u = c[x], v = cp[x], s = -lt_u32(v, u); c[x] = (v & s) | (u & ~s); }
    }
    var f = new Uint32Array(n >> 1), F = new Uint32Array(n);
    for (j = 0; j < n / 2; j++) { f[j] = c[2 * j] & 1; }
    for (x = 0; x < n; x++) { F[x] = x ^ f[x >> 1]; }
    var Fpi = composeinv(F, piinv);
    var l = new Uint32Array(n >> 1), Lp = new Uint32Array(n);
    for (var k = 0; k < n / 2; k++) { l[k] = Fpi[2 * k] & 1; }
    for (var y = 0; y < n; y++) { Lp[y] = y ^ l[y >> 1]; }
    var M = composeinv(Fpi, Lp);
    var sub0 = new Uint32Array(n >> 1), sub1 = new Uint32Array(n >> 1);
    for (j = 0; j < n / 2; j++) { sub0[j] = M[2 * j] >> 1; sub1[j] = M[2 * j + 1] >> 1; }
    var z0 = control_bits(sub0), z1 = control_bits(sub1), z = [];
    for (j = 0; j < z0.length; j++) { z.push(z0[j], z1[j]); }
    return Array.from(f).concat(z, Array.from(l));
}
/* the permutation the control bits describe: every swap computed, kept by its bit */
function permutation_of(bits, m) {
    var n = 1 << m, pi = new Uint32Array(n);
    for (var i = 0; i < n; i++) { pi[i] = i; }
    for (var layer = 0; layer < 2 * m - 1; layer++) {
        var gap = 1 << Math.min(layer, 2 * m - 2 - layer);
        for (var j = 0; j < n / 2; j++) {
            var b = bits[layer * (n >> 1) + j], pos = (j % gap) + 2 * gap * Math.floor(j / gap);
            var x = pi[pos], y = pi[pos + gap], d = (x ^ y) & -b;
            pi[pos] = x ^ d; pi[pos + gap] = y ^ d;
        }
    }
    return pi;
}

function build(name, semi) {
    var P = SETS[name], m = P.m, n = P.n, t = P.t, q = 1 << m, MT = m * t, k = n - MT, Q1 = q - 1;
    var label = name + (semi ? 'f' : '');
    var NB = n >> 3, CB = (MT + 7) >> 3, KB = (k + 7) >> 3, NW = (n + 31) >> 5;
    var PK_BYTES = MT * KB, CB_BYTES = ((2 * m - 1) << (m - 1)) >> 3;
    var SK_BYTES = L_BYTES + 8 + 2 * t + CB_BYTES + NB;

    /* ---------------- GF(2^m) ---------------- */
    function gmul(a, b) {
        var r = 0;
        for (var i = 0; i < m; i++) { r ^= a & -((b >> i) & 1); a = (a << 1) ^ (P.f & -((a >> (m - 1)) & 1)); }
        return r & Q1;
    }
    function ginv(a) {                         /* a^(2^m − 2), a fixed chain: m − 1 squarings, m − 2 products */
        var r = gmul(a, a), sq = r;
        for (var i = 2; i < m; i++) { sq = gmul(sq, sq); r = gmul(r, sq); }
        return r;
    }
    function brev(x) { var r = 0; for (var i = 0; i < m; i++) { r |= ((x >> i) & 1) << (m - 1 - i); } return r; }
    function poly_eval(g, x) {                 /* g monic of degree t, coefficients g[0..t−1]; Horner */
        var r = 1;
        for (var i = t - 1; i >= 0; i--) { r = gmul(r, x) ^ g[i]; }
        return r;
    }

    /* ---------------- Irreducible: the minimal polynomial of β in GF(q^t) ---------------- */
    function fqt_mul(a, b) {                   /* in GF(q)[y]/F(y) */
        var prod = new Uint16Array(2 * t - 1), i, j;
        for (i = 0; i < t; i++) { for (j = 0; j < t; j++) { prod[i + j] ^= gmul(a[i], b[j]); } }
        for (i = 2 * t - 2; i >= t; i--) {
            var c = prod[i];
            for (j = 0; j < P.F.length; j++) { prod[i - t + P.F[j][0]] ^= gmul(c, P.F[j][1]); }
        }
        return prod.slice(0, t);
    }
    function irreducible(d) {                  /* d: t 16-bit little-endian words; null if β's powers are dependent */
        var beta = new Uint16Array(t);
        for (var j = 0; j < t; j++) { beta[j] = (d[2 * j] | (d[2 * j + 1] << 8)) & Q1; }
        var pw = [], cur = new Uint16Array(t);
        cur[0] = 1;
        for (var i = 0; i <= t; i++) { pw.push(cur); cur = fqt_mul(cur, beta); }
        /* solve Σ_i g_i·β^i = β^t: A[r][i] = coefficient r of β^i, Gauss-Jordan with masks */
        var A = [];
        for (var r = 0; r < t; r++) { var row = new Uint16Array(t + 1); for (var c = 0; c < t; c++) { row[c] = pw[c][r]; } row[t] = pw[t][r]; A.push(row); }
        var ok = 1;
        for (var col = 0; col < t; col++) {
            for (var r2 = col + 1; r2 < t; r2++) {
                var mk = -(nonzero(A[col][col]) ^ 1) & Q1;
                for (var c2 = col; c2 <= t; c2++) { A[col][c2] ^= A[r2][c2] & mk; }
            }
            ok &= nonzero(A[col][col]);
            var inv = ginv(A[col][col]);
            for (var c3 = col; c3 <= t; c3++) { A[col][c3] = gmul(A[col][c3], inv); }
            for (var r3 = 0; r3 < t; r3++) {
                if (r3 === col) { continue; }
                var fct = A[r3][col];
                for (var c4 = col; c4 <= t; c4++) { A[r3][c4] ^= gmul(A[col][c4], fct); }
            }
        }
        if (!ok) { return null; }
        var g = new Uint16Array(t);
        for (var i2 = 0; i2 < t; i2++) { g[i2] = A[i2][t]; }
        return g;
    }

    /* ---------------- FieldOrdering ---------------- */
    function field_ordering(b) {               /* q 32-bit little-endian values; null on a repeated one */
        var hi = new Uint32Array(q), ix = new Uint32Array(q);
        for (var j = 0; j < q; j++) { hi[j] = (b[4 * j] | (b[4 * j + 1] << 8) | (b[4 * j + 2] << 16) | (b[4 * j + 3] << 24)) >>> 0; ix[j] = j; }
        sorting_network(q, function (i, j) {
            var a = hi[i], c = hi[j], eq = nonzero(a ^ c) ^ 1;
            var sw = -(lt_u32(c, a) | (eq & lt_u32(ix[j], ix[i])));
            var x = (a ^ c) & sw; hi[i] = a ^ x; hi[j] = c ^ x;
            var y = (ix[i] ^ ix[j]) & sw; ix[i] ^= y; ix[j] ^= y;
        });
        var dup = 0;
        for (var r = 1; r < q; r++) { dup |= nonzero(hi[r] ^ hi[r - 1]) ^ 1; }
        return dup ? null : ix;                /* π: the sorted indices; α_i = bitreverse(π_i) */
    }

    /* ---------------- MatGen: (I | T), systematic or semi-systematic ---------------- */
    function bit(row, c) { return (row[c >> 5] >>> (c & 31)) & 1; }
    function eliminate(H, row) {               /* pivot `row` at column `row`, below and above; 1 on success */
        var w0 = row >> 5;
        for (var r = row + 1; r < MT; r++) {
            var mk = -(bit(H[row], row) ^ 1);
            for (var w = w0; w < NW; w++) { H[row][w] ^= H[r][w] & mk; }
        }
        var ok = bit(H[row], row);
        for (var r2 = 0; r2 < MT; r2++) {
            if (r2 === row) { continue; }
            var m2 = -bit(H[r2], row);
            for (var w2 = w0; w2 < NW; w2++) { H[r2][w2] ^= H[row][w2] & m2; }
        }
        return ok;
    }
    function matgen(g, pi) {
        var alpha = new Uint16Array(n), j, i, b;
        for (j = 0; j < n; j++) { alpha[j] = brev(pi[j]); }
        /* Ĥ: row i·m + b is bit b of α_j^i / g(α_j) */
        var H = [];
        for (i = 0; i < MT; i++) { H.push(new Uint32Array(NW)); }
        for (j = 0; j < n; j++) {
            var v = ginv(poly_eval(g, alpha[j]));
            for (i = 0; i < t; i++) {
                for (b = 0; b < m; b++) { H[i * m + b][j >> 5] |= ((v >> b) & 1) << (j & 31); }
                v = gmul(v, alpha[j]);
            }
        }
        var ok = 1, first = semi ? MT - MU : MT, cmask = null;
        for (var row = 0; row < first; row++) { ok &= eliminate(H, row); }
        if (!ok) { return null; }
        if (semi) {
            /*
             * The pivots of the last μ rows inside the ν-column window: the
             * RREF of that μ × ν block (rows as two 32-bit halves), its pivot
             * columns found with a branchless count of trailing zeros - the
             * reference's mov_columns.
             */
            var lo = new Uint32Array(MU), hi = new Uint32Array(MU), piv = new Uint32Array(MU);
            for (var r = 0; r < MU; r++) {
                for (var c = 0; c < NU; c++) { var bt = bit(H[first + r], first + c); if (c < 32) { lo[r] |= bt << c; } else { hi[r] |= bt << (c - 32); } }
            }
            for (var r1 = 0; r1 < MU; r1++) {
                var tl = lo[r1], th = hi[r1];
                for (var r2 = r1 + 1; r2 < MU; r2++) { tl |= lo[r2]; th |= hi[r2]; }
                ok &= nonzero(tl) | nonzero(th);
                /* ctz over 64 bits: the first set bit, no branch */
                var pos = 0, seen = 0;
                for (var bi = 0; bi < NU; bi++) {
                    var bv = bi < 32 ? (tl >>> bi) & 1 : (th >>> (bi - 32)) & 1, take = bv & (seen ^ 1);
                    pos |= bi & -take; seen |= bv;
                }
                piv[r1] = pos;
                for (var r3 = r1 + 1; r3 < MU; r3++) {
                    var have = pos < 32 ? (lo[r1] >>> pos) & 1 : (hi[r1] >>> (pos - 32)) & 1, mk = -(have ^ 1);
                    lo[r1] ^= lo[r3] & mk; hi[r1] ^= hi[r3] & mk;
                }
                for (var r4 = r1 + 1; r4 < MU; r4++) {
                    var on = pos < 32 ? (lo[r4] >>> pos) & 1 : (hi[r4] >>> (pos - 32)) & 1, mk2 = -on;
                    lo[r4] ^= lo[r1] & mk2; hi[r4] ^= hi[r1] & mk2;
                }
            }
            if (!ok) { return null; }
            /* swap column first+s with column first+piv[s], in H and in π, through masks over the window */
            cmask = new Uint8Array(8);
            for (var s = 0; s < MU; s++) {
                var at = first + s;
                for (var cw = 0; cw < NU; cw++) {
                    var to = first + cw, sel = -(nonzero(cw ^ piv[s]) ^ 1);
                    cmask[cw >> 3] |= (1 << (cw & 7)) & sel;
                    for (var rr = 0; rr < MT; rr++) {
                        var d = (bit(H[rr], at) ^ bit(H[rr], to)) & sel;
                        H[rr][at >> 5] ^= d << (at & 31); H[rr][to >> 5] ^= d << (to & 31);
                    }
                    var dp = (pi[at] ^ pi[to]) & sel;
                    pi[at] ^= dp; pi[to] ^= dp;
                }
            }
            for (var row2 = first; row2 < MT; row2++) { ok &= eliminate(H, row2); }
            if (!ok) { return null; }
        }
        /* T: columns MT..n−1, each row packed little-endian */
        var pk = new Uint8Array(PK_BYTES);
        for (var r4 = 0; r4 < MT; r4++) {
            for (var c3 = 0; c3 < k; c3++) { pk[r4 * KB + (c3 >> 3)] |= bit(H[r4], MT + c3) << (c3 & 7); }
        }
        return { pk: pk, pi: pi, c: cmask || new Uint8Array([255, 255, 255, 255, 0, 0, 0, 0]) };
    }

    /* ---------------- SeededKeyGen ---------------- */
    var G_BYTES = (n + SIGMA2 * q + SIGMA1 * t) / 8 + L_BYTES;
    function seeded_keygen(delta) {
        for (var tries = 0; tries < 1000; tries++) {
            var E = shake256(concat([new Uint8Array([64]), delta]), G_BYTES);
            var s = E.subarray(0, NB), next = E.slice(G_BYTES - L_BYTES);
            var pi = field_ordering(E.subarray(NB, NB + SIGMA2 * q / 8));
            var g = pi && irreducible(E.subarray(NB + SIGMA2 * q / 8, NB + SIGMA2 * q / 8 + SIGMA1 * t / 8));
            var res = g && matgen(g, pi);
            if (res) {
                var gb = new Uint8Array(2 * t);
                for (var i = 0; i < t; i++) { gb[2 * i] = g[i] & 0xff; gb[2 * i + 1] = g[i] >> 8; }
                var cb = control_bits(res.pi), cbytes = new Uint8Array(CB_BYTES);
                for (var j = 0; j < cb.length; j++) { cbytes[j >> 3] |= cb[j] << (j & 7); }
                var sk = concat([delta, res.c, gb, cbytes, s]);
                E.fill(0); g.fill(0);
                return { pk: res.pk, sk: sk };
            }
            E.fill(0);
            delta = next;
        }
        throw new Error(label + ': key generation did not succeed');
    }

    /* ---------------- Encode / FixedWeight ---------------- */
    var TAU = t;
    while (TAU * n < t * q) { TAU *= 2; }
    function fixed_weight(rng) {
        for (;;) {
            var b = rng(SIGMA1 * TAU / 8), a = [], e = new Uint8Array(NB);
            for (var j = 0; j < TAU && a.length < t; j++) { var d = (b[2 * j] | (b[2 * j + 1] << 8)) & Q1; if (d < n) { a.push(d); } }
            if (a.length < t) { continue; }
            var rep = 0;
            for (var i = 1; i < t; i++) { for (var i2 = 0; i2 < i; i2++) { rep |= nonzero(a[i] ^ a[i2]) ^ 1; } }
            if (rep) { continue; }
            for (var p = 0; p < t; p++) { for (var w = 0; w < NB; w++) { var eq = nonzero(w ^ (a[p] >> 3)) ^ 1; e[w] |= (1 << (a[p] & 7)) & -eq; } }
            b.fill(0);
            return e;
        }
    }
    function encode(pk, e) {                   /* C = e[0..MT) + T·e[MT..n) */
        var C = new Uint8Array(CB);
        for (var r = 0; r < MT; r++) {
            var acc = 0, base = r * KB;
            for (var c = 0; c < k; c++) { acc ^= ((pk[base + (c >> 3)] >> (c & 7)) & 1) & ((e[(MT + c) >> 3] >> ((MT + c) & 7)) & 1); }
            acc ^= (e[r >> 3] >> (r & 7)) & 1;
            C[r >> 3] |= acc << (r & 7);
        }
        return C;
    }

    /* ---------------- Decode: syndrome, Berlekamp-Massey, roots, check ---------------- */
    function syndrome(g, alpha, v) {           /* S_j = Σ v_i α_i^j / g(α_i)^2, j < 2t; every i visited */
        var S = new Uint16Array(2 * t);
        for (var i = 0; i < n; i++) {
            var gi = poly_eval(g, alpha[i]), w = ginv(gmul(gi, gi)), vi = -((v[i >> 3] >> (i & 7)) & 1) & Q1;
            w &= vi;
            for (var j = 0; j < 2 * t; j++) { S[j] ^= w; w = gmul(w, alpha[i]); }
        }
        return S;
    }
    function berlekamp_massey(S) {             /* the connection polynomial, degree <= t, with masks */
        var C = new Uint16Array(t + 1), B = new Uint16Array(t + 1), T = new Uint16Array(t + 1);
        C[0] = 1; B[1] = 1;
        var L = 0, bb = 1;
        for (var N = 0; N < 2 * t; N++) {
            var d = 0;
            for (var i = 0; i <= Math.min(N, t); i++) { d ^= gmul(C[i], S[N - i]); }
            var mne = -nonzero(d), mle = -(((N - 2 * L) >>> 31) ^ 1) & mne;   /* d != 0 and 2L <= N */
            var f = gmul(ginv(bb), d);
            for (var j = 0; j <= t; j++) { T[j] = C[j]; }
            for (var j2 = 0; j2 <= t; j2++) { C[j2] ^= gmul(f, B[j2]) & mne; }
            L = (L & ~mle) | ((N + 1 - L) & mle);
            for (var j3 = 0; j3 <= t; j3++) { B[j3] = (B[j3] & ~mle) | (T[j3] & mle); }
            bb = (bb & ~mle) | (d & mle);
            for (var j4 = t; j4 >= 1; j4--) { B[j4] = B[j4 - 1]; }
            B[0] = 0;
        }
        return C;
    }
    function decode(g, alpha, C) {             /* { e, ok }: ok when a weight-t error has syndrome C */
        var v = new Uint8Array(NB);
        v.set(C.subarray(0, CB));
        if (MT & 7) { v[CB - 1] &= (1 << (MT & 7)) - 1; }
        var S = syndrome(g, alpha, v), sig = berlekamp_massey(S);
        var e = new Uint8Array(NB), wt = 0;
        for (var i = 0; i < n; i++) {
            /* the reversed locator, x^t·σ(1/x), vanishes at the error positions */
            var r = 0;
            for (var j = 0; j <= t; j++) { r = gmul(r, alpha[i]) ^ sig[j]; }
            var z = nonzero(r) ^ 1;
            e[i >> 3] |= z << (i & 7); wt += z;
        }
        var S2 = syndrome(g, alpha, e), diff = nonzero(wt ^ t);
        for (var s = 0; s < 2 * t; s++) { diff |= nonzero(S[s] ^ S2[s]); }
        return { e: e, ok: diff ^ 1 };
    }

    /* ---------------- the KEM ---------------- */
    function H(b, e, C) { return shake256(concat([new Uint8Array([b]), e, C]), 32); }

    function decaps(sk, C) {
        if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES) { throw new Error(label + ': a secret key is ' + SK_BYTES + ' bytes'); }
        if (!(C instanceof Uint8Array) || C.length !== CB) { throw new Error(label + ': a ciphertext is ' + CB + ' bytes'); }
        var o = L_BYTES + 8, g = new Uint16Array(t);
        for (var i = 0; i < t; i++) { g[i] = (sk[o + 2 * i] | (sk[o + 2 * i + 1] << 8)) & Q1; }
        o += 2 * t;
        var cb = sk.subarray(o, o + CB_BYTES), s = sk.subarray(o + CB_BYTES), nbits = (2 * m - 1) << (m - 1), bits = new Uint8Array(nbits);
        for (var j = 0; j < nbits; j++) { bits[j] = (cb[j >> 3] >> (j & 7)) & 1; }
        var pi = permutation_of(bits, m), alpha = new Uint16Array(n);
        for (var a = 0; a < n; a++) { alpha[a] = brev(pi[a]); }
        var d = decode(g, alpha, C);
        /* e on success, s otherwise; b = ok - with no branch on ok */
        var mk = -d.ok & 0xff, chosen = new Uint8Array(NB);
        for (var w = 0; w < NB; w++) { chosen[w] = (d.e[w] & mk) | (s[w] & ~mk); }
        var K = H(d.ok, chosen, C);
        g.fill(0); bits.fill(0); pi.fill(0); alpha.fill(0); d.e.fill(0); chosen.fill(0);
        return K;
    }

    return {
        NAME: label, PK_BYTES: PK_BYTES, SK_BYTES: SK_BYTES, CT_BYTES: CB, SS_BYTES: 32,
        /** δ, 32 bytes, is all the randomness key generation uses (SeededKeyGen) */
        keygen_derand: function (delta) {
            if (!(delta instanceof Uint8Array) || delta.length !== L_BYTES) { throw new Error(label + ': the key seed is 32 bytes'); }
            return seeded_keygen(new Uint8Array(delta));
        },
        keygen: function (rng) { rng = require_rng(label + '.keygen', rng); var d = rng(L_BYTES); try { return seeded_keygen(d); } finally { d.fill(0); } },
        /** rng is called once per FixedWeight attempt, for 2τ bytes - as the KATs draw it */
        encaps: function (pk, rng) {
            if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { throw new Error(label + ': a public key is ' + PK_BYTES + ' bytes'); }
            rng = require_rng(label + '.encaps', rng);
            var e = fixed_weight(rng), C = encode(pk, e), K = H(1, e, C);
            e.fill(0);
            return { ct: C, ss: K };
        },
        /** Never fails: a ciphertext that does not decode gives SHAKE256(0 ‖ s ‖ C). */
        decaps: decaps
    };
}

export var mceliece348864 = /* @__PURE__ */ build('mceliece348864', false);
export var mceliece348864f = /* @__PURE__ */ build('mceliece348864', true);
export var mceliece460896 = /* @__PURE__ */ build('mceliece460896', false);
export var mceliece460896f = /* @__PURE__ */ build('mceliece460896', true);
export var mceliece6688128 = /* @__PURE__ */ build('mceliece6688128', false);
export var mceliece6688128f = /* @__PURE__ */ build('mceliece6688128', true);
export var mceliece6960119 = /* @__PURE__ */ build('mceliece6960119', false);
export var mceliece6960119f = /* @__PURE__ */ build('mceliece6960119', true);
export var mceliece8192128 = /* @__PURE__ */ build('mceliece8192128', false);
export var mceliece8192128f = /* @__PURE__ */ build('mceliece8192128', true);
