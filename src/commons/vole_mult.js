/**
 * The bilinear tables of FAEST's CRT-based VOLE multiplication
 *
 * FAEST round 3 commits to the masks u * Delta in GF(2)[x]/p(x) without
 * a full field multiplication per mask: Delta is held as its residues modulo
 * the tau GGM-tree moduli M_i (Delta', lambda - w bits), the residue products
 * modulo the M_i come free from the trees, and the rest of the product is
 * reached through further CRT places (powers of x, x+1, infinity and of other
 * irreducibles), each computed by a bilinear algorithm down to single bit
 * multiplications f_e(u) * g_e(Delta'). All linear glue is flattened into
 * fixed matrices, so that
 *
 *   u * Delta mod p = W_tree * res(u, Delta') + W_gate * (F u  .*  G Delta')
 *
 * with Delta = W_crt * Delta' and res the concatenated residue products.
 *
 * This is the round-3 table generator (vole_mult_tables.py of the reference
 * package) carried over decision for decision: the same tree moduli (the
 * smallest irreducibles of the tree degrees), the same exact knapsack over
 * places with the same tie-breaking, the same Karatsuba / Montgomery / F_4
 * tower building blocks, and the same pruning, so the tables come out
 * identical to the ones the reference compiles in. They are built once per
 * parameter set, on first use.
 *
 * Polynomials and bit vectors are BigInts, bit i = coefficient of x^i.
 */

var ONE = BigInt(1), ZERO = BigInt(0);

function pdeg(a) { return a === ZERO ? -1 : a.toString(2).length - 1; }
function pmul(a, b) { var r = ZERO; while (b) { if (b & ONE) { r ^= a; } b >>= ONE; a <<= ONE; } return r; }
function pmod(a, m) { var d = pdeg(m), da; while (a && (da = pdeg(a)) >= d) { a ^= m << BigInt(da - d); } return a; }
function pmulmod(a, b, m) { return pmod(pmul(a, b), m); }
function pgcd(a, b) { while (b) { var t = pmod(a, b); a = b; b = t; } return a; }
function pdivmod(a, b) {
    var q = ZERO, db = pdeg(b), da;
    while (a && (da = pdeg(a)) >= db) { q |= ONE << BigInt(da - db); a ^= b << BigInt(da - db); }
    return [q, a];
}
function pinvmod(a, m) {
    var r0 = m, r1 = pmod(a, m), s0 = ZERO, s1 = ONE;
    while (r1) {
        var qr = pdivmod(r0, r1), t = s0 ^ pmul(qr[0], s1);
        r0 = r1; r1 = qr[1]; s0 = s1; s1 = t;
    }
    if (r0 !== ONE) { throw new Error('vole_mult: not coprime'); }
    return pmod(s0, m);
}
function bits(x) {
    var s = x.toString(2), out = [];
    for (var i = s.length - 1, j = 0; i >= 0; i--, j++) { if (s.charCodeAt(i) === 49) { out.push(j); } }
    return x === ZERO ? [] : out;
}
function parity(x) { var s = x.toString(2), p = 0; for (var i = 0; i < s.length; i++) { p ^= s.charCodeAt(i) & 1; } return p; }
function combine(mask, rows) { var out = ZERO, b = bits(mask); for (var i = 0; i < b.length; i++) { out ^= rows[b[i]]; } return out; }
function B(n) { return BigInt(n); }
function bit(n) { return ONE << BigInt(n); }

function crt_lift_cols(moduli) {
    var Mt = ONE, cols = [], i;
    for (i = 0; i < moduli.length; i++) { Mt = pmul(Mt, moduli[i]); }
    for (i = 0; i < moduli.length; i++) {
        var Q = pdivmod(Mt, moduli[i])[0], E = pmulmod(Q, pinvmod(Q, moduli[i]), Mt);
        for (var b = 0; b < pdeg(moduli[i]); b++) { cols.push(pmulmod(E, bit(b), Mt)); }
    }
    return { cols: cols, Mtree: Mt };
}

function x_pow_2k(f, k) { var r = pmod(B(2), f); for (var i = 0; i < k; i++) { r = pmulmod(r, r, f); } return r; }
function prime_factors(n) { var fs = [], d = 2; while (d * d <= n) { if (n % d === 0) { fs.push(d); while (n % d === 0) { n /= d; } } d++; } if (n > 1) { fs.push(n); } return fs; }
function is_irreducible(f) {
    var n = pdeg(f);
    if (n <= 0) { return false; }
    if (n === 1) { return true; }
    if (!(f & ONE)) { return false; }
    if (x_pow_2k(f, n) !== pmod(B(2), f)) { return false; }
    var pf = prime_factors(n);
    for (var i = 0; i < pf.length; i++) {
        if (pgcd(f, pmod(x_pow_2k(f, n / pf[i]) ^ B(2), f)) !== ONE) { return false; }
    }
    return true;
}
var IRR = {};
function irreducibles(d) {
    if (IRR[d]) { return IRR[d]; }
    var out = [];
    for (var f = 1 << d; f < 1 << (d + 1); f++) { if (is_irreducible(B(f))) { out.push(B(f)); } }
    return (IRR[d] = out);
}

function reduction_rows(q, ncols) {
    var d = pdeg(q), rows = [], cur = ONE, i;
    for (i = 0; i < d; i++) { rows.push(ZERO); }
    for (var j = 0; j < ncols; j++) {
        var bs = bits(cur);
        for (i = 0; i < bs.length; i++) { rows[bs[i]] |= bit(j); }
        cur = pmod(cur << ONE, q);
    }
    return rows;
}
function pascal_rows(e) {
    var rows = [];
    for (var i = 0; i < e; i++) { var r = ZERO; for (var j = 0; j < e; j++) { if ((i & j) === i) { r |= bit(j); } } rows.push(r); }
    return rows;
}
function left_inverse(rows, ncols) {
    var m = rows.length, wr = [], wt = [], used = [], piv_of = [], c, i;
    for (i = 0; i < m; i++) { wr.push(rows[i]); wt.push(bit(i)); used.push(false); }
    for (c = 0; c < ncols; c++) {
        var piv = -1, cb = bit(c);
        for (i = 0; i < m; i++) { if (!used[i] && (wr[i] & cb)) { piv = i; break; } }
        if (piv < 0) { throw new Error('vole_mult: evaluation map not full rank'); }
        used[piv] = true; piv_of.push(piv);
        var pr = wr[piv], pt = wt[piv];
        for (i = 0; i < m; i++) { if (i !== piv && (wr[i] & cb)) { wr[i] ^= pr; wt[i] ^= pt; } }
    }
    return piv_of.map(function (p) { return wt[p]; });
}

/* ---- F_4 = F_2[w]/(w^2+w+1), codes u + 2v for u + v w ---- */
var F4M = [[0, 0, 0, 0], [0, 1, 2, 3], [0, 2, 3, 1], [0, 3, 1, 2]], F4INV = [0, 1, 3, 2];
function f4_pow(t, j) { var r = 1; for (var i = 0; i < j; i++) { r = F4M[r][t]; } return r; }
function f4_pmul(A, Bv) {
    var out = new Array(A.length + Bv.length - 1).fill(0);
    for (var i = 0; i < A.length; i++) { if (A[i]) { for (var j = 0; j < Bv.length; j++) { out[i + j] ^= F4M[A[i]][Bv[j]]; } } }
    return out;
}
function f4_pmod(A, Q) {
    var dq = Q.length - 1, w = A.slice();
    for (var i = w.length - 1; i >= dq; i--) { var c = w[i]; if (c) { for (var j = 0; j <= dq; j++) { w[i - dq + j] ^= F4M[c][Q[j]]; } } }
    while (w.length < dq) { w.push(0); }
    return w.slice(0, dq);
}
function f4_peval(P, t) { var r = 0; for (var i = P.length - 1; i >= 0; i--) { r = F4M[r][t] ^ P[i]; } return r; }
/* itertools.product(range(4), repeat=m), first coordinate slowest */
function product4(m) {
    var out = [];
    for (var v = 0; v < Math.pow(4, m); v++) { var t = []; for (var j = m - 1; j >= 0; j--) { t.push((v >> (2 * j)) & 3); } out.push(t); }
    return out;
}
function f4_irreducibles(m) {
    var quads = null, out = [];
    if (m === 4) { quads = product4(2).map(function (t) { return t.concat([1]); }).filter(function (P) { return [0, 1, 2, 3].every(function (u) { return f4_peval(P, u) !== 0; }); }); }
    product4(m).forEach(function (t) {
        var P = t.concat([1]);
        if ([0, 1, 2, 3].some(function (u) { return f4_peval(P, u) === 0; })) { return; }
        if (m === 4 && quads.some(function (Q2) { return f4_pmod(P, Q2).every(function (x) { return x === 0; }); })) { return; }
        out.push(P);
    });
    return out;
}
function f4_xpow_cols(Q, count) {
    var dq = Q.length - 1, cur = [1].concat(new Array(dq - 1).fill(0)), cols = [];
    for (var i = 0; i < count; i++) { cols.push(cur.slice()); cur = f4_pmod([0].concat(cur), Q); }
    return cols;
}
function f4_matinv(M) {
    var n = M.length, A = M.map(function (row, i) { return row.concat(new Array(n).fill(0).map(function (_, j) { return j === i ? 1 : 0; })); });
    for (var c = 0; c < n; c++) {
        var piv = c; while (!A[piv][c]) { piv++; }
        var t = A[c]; A[c] = A[piv]; A[piv] = t;
        var inv = F4INV[A[c][c]];
        A[c] = A[c].map(function (v) { return F4M[inv][v]; });
        for (var i = 0; i < n; i++) {
            if (i !== c && A[i][c]) { var f = A[i][c]; A[i] = A[i].map(function (v, j) { return v ^ F4M[f][A[c][j]]; }); }
        }
    }
    return A.map(function (row) { return row.slice(n); });
}
function f4_full_product(m) {
    var gates4 = [], ev = [], R4 = [], t, j, npts = m === 2 ? 2 : 4, row;
    for (t = 0; t < npts; t++) {
        R4.push([[gates4.length, 1]]);
        row = []; for (j = 0; j < m; j++) { row.push(f4_pow(t, j)); } gates4.push(row);
        row = []; for (j = 0; j < 2 * m - 1; j++) { row.push(f4_pow(t, j)); } ev.push(row);
    }
    R4.push([[gates4.length, 1]]);
    gates4.push(new Array(m - 1).fill(0).concat([1]));
    row = new Array(2 * m - 1).fill(0); row[2 * m - 2] = 1; ev.push(row);
    if (m === 4) {
        var Q2 = f4_irreducibles(2)[0], beta = Q2[0], alpha = Q2[1], cin = f4_xpow_cols(Q2, m);
        var r0 = cin.map(function (c) { return c[0]; }), r1 = cin.map(function (c) { return c[1]; }), ga = gates4.length;
        gates4.push(r0, r1, r0.map(function (a, i) { return a ^ r1[i]; }));
        var cout = f4_xpow_cols(Q2, 2 * m - 1);
        ev.push(cout.map(function (c) { return c[0]; }), cout.map(function (c) { return c[1]; }));
        R4.push([[ga, 1], [ga + 1, beta]]);
        R4.push([[ga, 1], [ga + 1, 1 ^ alpha], [ga + 2, 1]]);
    }
    var Inv = f4_matinv(ev), ng = gates4.length, W4 = [];
    for (var k = 0; k < 2 * m - 1; k++) {
        row = new Array(ng).fill(0);
        for (j = 0; j < R4.length; j++) {
            var c = Inv[k][j];
            if (c) { for (var q = 0; q < R4[j].length; q++) { row[R4[j][q][0]] ^= F4M[c][R4[j][q][1]]; } }
        }
        W4.push(row);
    }
    return { gates4: gates4, W4: W4 };
}
function t_to_bits(t) { var r = ZERO; for (var j = 0; j < t.length; j++) { r |= B(t[j]) << B(2 * j); } return r; }

function Alg(na, nb, gates, W) { return { na: na, nb: nb, gates: gates, W: W }; }
function precompose(alg, Ar, Br, na, nb) {
    return Alg(na, nb, alg.gates.map(function (g) { return [combine(g[0], Ar), combine(g[1], Br)]; }), alg.W.slice());
}

function tower_place_alg(q, na, nb) {
    var d = pdeg(q), m = d / 2, Q = f4_irreducibles(m)[0], fp = f4_full_product(m), gates4 = fp.gates4, W4 = fp.W4;
    var RQ = f4_xpow_cols(Q, 2 * m - 1), ng4 = gates4.length, W4m = [], k, j, g;
    for (k = 0; k < m; k++) {
        var row = new Array(ng4).fill(0);
        for (j = 0; j < 2 * m - 1; j++) { var c = RQ[j][k]; if (c) { for (g = 0; g < ng4; g++) { row[g] ^= F4M[c][W4[j][g]]; } } }
        W4m.push(row);
    }
    var one = [1].concat(new Array(m - 1).fill(0));
    function tmul(a, b) { return f4_pmod(f4_pmul(a, b), Q); }
    var rho = null, cands = product4(m);
    for (var ci = 0; ci < cands.length && !rho; ci++) {
        var acc = new Array(m).fill(0);
        for (var i = pdeg(q); i >= 0; i--) {
            acc = tmul(acc, cands[ci]);
            if ((q >> B(i)) & ONE) { acc = acc.map(function (x, t) { return x ^ one[t]; }); }
        }
        if (acc.every(function (x) { return x === 0; })) { rho = cands[ci]; }
    }
    if (!rho) { throw new Error('vole_mult: no root in the tower field'); }
    var cols = [], p = one, r;
    for (i = 0; i < d; i++) { cols.push(t_to_bits(p)); p = tmul(p, rho); }
    var Mrows = [];
    for (r = 0; r < d; r++) { var mr = ZERO; for (i = 0; i < d; i++) { if ((cols[i] >> B(r)) & ONE) { mr |= bit(i); } } Mrows.push(mr); }
    var Minv = left_inverse(Mrows, d), ra_ = reduction_rows(q, na), rb_ = reduction_rows(q, nb), trow_a = [], trow_b = [];
    for (r = 0; r < d; r++) { trow_a.push(combine(Mrows[r], ra_)); trow_b.push(combine(Mrows[r], rb_)); }
    function form(L, trow) {
        var p_ = ZERO, r_ = ZERO;
        for (var jj = 0; jj < L.length; jj++) {
            var cc = L[jj];
            if (cc) {
                var pj = trow[2 * jj], rj = trow[2 * jj + 1];
                if (cc & 1) { p_ ^= pj; r_ ^= rj; }
                if (cc & 2) { p_ ^= rj; r_ ^= pj ^ rj; }
            }
        }
        return [p_, r_];
    }
    var gates = [], comp = [];
    gates4.forEach(function (L) {
        var a = form(L, trow_a), b = form(L, trow_b), base = gates.length;
        gates.push([a[0], b[0]], [a[1], b[1]], [a[0] ^ a[1], b[0] ^ b[1]]);
        comp.push([bit(base) | bit(base + 1), bit(base) | bit(base + 2)]);
    });
    var towout = new Array(d).fill(ZERO);
    for (k = 0; k < m; k++) {
        var o0 = ZERO, o1 = ZERO;
        for (g = 0; g < ng4; g++) {
            var cg = W4m[k][g];
            if (cg) {
                if (cg & 1) { o0 ^= comp[g][0]; o1 ^= comp[g][1]; }
                if (cg & 2) { o0 ^= comp[g][1]; o1 ^= comp[g][0] ^ comp[g][1]; }
            }
        }
        towout[2 * k] = o0; towout[2 * k + 1] = o1;
    }
    var W = [];
    for (r = 0; r < d; r++) { W.push(combine(Minv[r], towout)); }
    return [Alg(na, nb, gates, W), reduction_rows(q, na + nb - 1)];
}

var TOWER = { 6: 15, 8: 24 };
var MONT5_GATES = [31, 29, 23, 27, 13, 22, 24, 3, 17, 16, 8, 2, 1];
var MONT5_W = [[12], [7, 11, 12], [2, 5, 7, 8, 9, 12], [0, 1, 3, 6, 8, 9], [0, 4, 5, 6, 7, 9, 10, 11, 12],
    [0, 2, 3, 7, 8, 12], [1, 4, 6, 8, 9, 12], [6, 9, 10], [9]];

/* ---- cost search (memoised; the inventory never depends on the parameter set below the top level) ---- */
var FULL_COST = {}, SHORT_COST = {};
function full_cost(n) {
    if (FULL_COST[n]) { return FULL_COST[n]; }
    var best;
    if (n === 1) { best = [1, ['base']]; } else {
        best = n === 5 ? [13, ['mont5']] : null;
        for (var s = 2; s < n; s++) {
            var m = Math.ceil(n / s), c = full_cost(s)[0] * full_cost(m)[0];
            if (!best || c < best[0]) { best = [c, ['split', s, m]]; }
        }
        var pools = {};
        for (var d = 2; d < n; d++) { pools[d] = irreducibles(d); }
        var res = crt_search(2 * n - 1, n - 1, n - 1, pools);
        if (res && (!best || res[0] < best[0])) { best = [res[0], ['crt', res[1]]]; }
    }
    return (FULL_COST[n] = best);
}
function short_cost(n) {
    if (SHORT_COST[n]) { return SHORT_COST[n]; }
    var best;
    if (n === 1) { best = [1, ['base']]; } else {
        best = [full_cost(n)[0], ['full']];
        for (var m = Math.ceil(n / 2); m < n; m++) {
            var c = full_cost(m)[0] + 2 * short_cost(n - m)[0];
            if (c < best[0]) { best = [c, ['shortsplit', m]]; }
        }
    }
    return (SHORT_COST[n] = best);
}
function place_gate_cost(kind, poly, e) {
    if (kind !== 'irr') { return short_cost(e)[0]; }
    var d = pdeg(poly);
    if (e === 1 && TOWER[d]) { return Math.min(TOWER[d], full_cost(d)[0]); }
    return full_cost(d * e)[0];
}
/* exact multiple-choice knapsack: at most one multiplicity per place, total degree >= target, least gates */
function crt_search(target, maxe_lin, cap_irr, pools) {
    var groups = [], e, opts;
    [['inf', null], ['lin', B(2)], ['lin', B(3)]].forEach(function (kp) {
        var o = [];
        for (var ee = 1; ee <= maxe_lin; ee++) { o.push([ee, short_cost(ee)[0], [[kp[0], kp[1], ee]]]); }
        if (o.length) { groups.push(o); }
    });
    Object.keys(pools).map(Number).sort(function (a, b) { return a - b; }).forEach(function (d) {
        var pool = pools[d];
        if (!pool.length) { return; }
        opts = [];
        if (d === 2) {
            for (e = 1; d * e <= cap_irr; e++) { opts.push([d * e, place_gate_cost('irr', pool[0], e), [['irr', pool[0], e]]]); }
        } else {
            var per = place_gate_cost('irr', pool[0], 1), maxt = Math.min(pool.length, Math.floor(target / d) + 1);
            for (var t = 1; t <= maxt; t++) { opts.push([t * d, t * per, pool.slice(0, t).map(function (q) { return ['irr', q, 1]; })]); }
        }
        if (opts.length) { groups.push(opts); }
    });
    var dp = new Map([[0, [0, []]]]);
    groups.forEach(function (o) {
        var ndp = new Map(dp);
        dp.forEach(function (v, deg0) {
            for (var i = 0; i < o.length; i++) {
                var nd = Math.min(deg0 + o[i][0], target), nc = v[0] + o[i][1], cur = ndp.get(nd);
                if (cur === undefined || nc < cur[0]) { ndp.set(nd, [nc, v[1].concat(o[i][2])]); }
            }
        });
        dp = ndp;
    });
    return dp.get(target) || null;
}

/* ---- bilinear algorithms ---- */
var FULL_ALG = {}, SHORT_ALG = {};
function full_alg(n) {
    if (FULL_ALG[n]) { return FULL_ALG[n]; }
    var plan = full_cost(n)[1], alg, gates, W, q;
    if (plan[0] === 'base') { alg = Alg(1, 1, [[ONE, ONE]], [ONE]); }
    else if (plan[0] === 'mont5') {
        alg = Alg(5, 5, MONT5_GATES.map(function (m) { return [B(m), B(m)]; }),
            MONT5_W.map(function (row) { return row.reduce(function (acc, g) { return acc | bit(g); }, ZERO); }));
    } else if (plan[0] === 'split') {
        var s = plan[1], m = plan[2], OA = full_alg(s), IA = full_alg(m), ngi = IA.gates.length;
        gates = [];
        OA.gates.forEach(function (og) {
            var Ar = [], Br = [];
            for (var i = 0; i < m; i++) {
                var fa = ZERO, fb = ZERO;
                bits(og[0]).forEach(function (t) { if (t * m + i < n) { fa |= bit(t * m + i); } });
                bits(og[1]).forEach(function (t) { if (t * m + i < n) { fb |= bit(t * m + i); } });
                Ar.push(fa); Br.push(fb);
            }
            IA.gates.forEach(function (ig) { gates.push([combine(ig[0], Ar), combine(ig[1], Br)]); });
        });
        W = [];
        for (q = 0; q < 2 * n - 1; q++) {
            var row = ZERO;
            for (var r = 0; r < 2 * s - 1; r++) {
                var i2 = q - r * m;
                if (i2 >= 0 && i2 <= 2 * m - 2) { bits(OA.W[r]).forEach(function (o) { row ^= IA.W[i2] << B(o * ngi); }); }
            }
            W.push(row);
        }
        alg = Alg(n, n, gates, W);
    } else {
        gates = []; var resm = [], evrows = [];
        plan[1].forEach(function (pk) {
            var pa = place_alg(pk, n, n), off = B(gates.length);
            gates = gates.concat(pa[0].gates);
            pa[0].W.forEach(function (w) { resm.push(w << off); });
            evrows = evrows.concat(pa[1]);
        });
        var X = left_inverse(evrows, 2 * n - 1);
        W = [];
        for (q = 0; q < 2 * n - 1; q++) { W.push(combine(X[q], resm)); }
        alg = Alg(n, n, gates, W);
    }
    return (FULL_ALG[n] = alg);
}
function short_alg(n) {
    if (SHORT_ALG[n]) { return SHORT_ALG[n]; }
    var plan = short_cost(n)[1], alg, i;
    if (plan[0] === 'base') { alg = Alg(1, 1, [[ONE, ONE]], [ONE]); }
    else if (plan[0] === 'full') { var A = full_alg(n); alg = Alg(n, n, A.gates.slice(), A.W.slice(0, n)); }
    else {
        var m = plan[1], lo = [], lo2 = [], hi2 = [];
        for (i = 0; i < m; i++) { lo.push(bit(i)); }
        for (i = 0; i < n - m; i++) { lo2.push(bit(i)); hi2.push(bit(m + i)); }
        var G1 = precompose(full_alg(m), lo, lo, n, n), S = short_alg(n - m);
        var G2 = precompose(S, lo2, hi2, n, n), G3 = precompose(S, hi2, lo2, n, n);
        var o2 = B(G1.gates.length), o3 = o2 + B(G2.gates.length), W = [];
        for (var j = 0; j < n; j++) {
            var row = ZERO;
            if (j <= 2 * m - 2) { row ^= G1.W[j]; }
            if (j >= m) { row ^= (G2.W[j - m] << o2) ^ (G3.W[j - m] << o3); }
            W.push(row);
        }
        alg = Alg(n, n, G1.gates.concat(G2.gates, G3.gates), W);
    }
    return (SHORT_ALG[n] = alg);
}
function place_alg(pk, na, nb) {
    var kind = pk[0], poly = pk[1], e = pk[2], N2 = na + nb - 1, i;
    if (kind === 'inf') {
        var ra = [], rb = [], ev = [];
        for (i = 0; i < e; i++) { ra.push(bit(na - 1 - i)); rb.push(bit(nb - 1 - i)); ev.push(bit(N2 - 1 - i)); }
        return [precompose(short_alg(e), ra, rb, na, nb), ev];
    }
    if (kind === 'lin') {
        var q = ONE;
        for (i = 0; i < e; i++) { q = pmul(q, poly); }
        var Ra = reduction_rows(q, na), Rb = reduction_rows(q, nb), Rev = reduction_rows(q, N2), ina = Ra, inb = Rb, evl = Rev;
        if (poly !== B(2)) {
            var P = pascal_rows(e);
            ina = P.map(function (p) { return combine(p, Ra); });
            inb = P.map(function (p) { return combine(p, Rb); });
            evl = P.map(function (p) { return combine(p, Rev); });
        }
        return [precompose(short_alg(e), ina, inb, na, nb), evl];
    }
    var dp = pdeg(poly);
    if (e === 1 && TOWER[dp] && TOWER[dp] < full_cost(dp)[0]) { return tower_place_alg(poly, na, nb); }
    var qq = ONE;
    for (i = 0; i < e; i++) { qq = pmul(qq, poly); }
    var d = pdeg(qq), alg = precompose(full_alg(d), reduction_rows(qq, na), reduction_rows(qq, nb), na, nb);
    var Rout = reduction_rows(qq, 2 * d - 1), W = [];
    for (i = 0; i < d; i++) { W.push(combine(Rout[i], alg.W)); }
    return [Alg(na, nb, alg.gates, W), reduction_rows(qq, N2)];
}

var MODULI = { 128: (ONE << B(128)) | B(0x87), 192: (ONE << B(192)) | B(0x87), 256: (ONE << B(256)) | B(0x425) };
var TABLES = {};

/**
 * The tables for (lambda, tau, w_grind): { F, G, W_tree, W_gate, W_crt }
 * as arrays of BigInt rows (F[e] over the lambda bits of u, G[e] over the
 * lambda - w bits of Delta', W_tree[k] and W_gate[k] over the residue and
 * gate bits, W_crt[k] over Delta'), plus the tree moduli (in tree order)
 * and M_tree, their product.
 */
export function vole_mult_tables(lambda, tau, wgrind) {
    var key = lambda + '/' + tau + '/' + wgrind;
    if (TABLES[key]) { return TABLES[key]; }
    var nb = lambda - wgrind, d1 = Math.floor(nb / tau) + 1, tau1 = nb % tau, spec = [], i, r;
    if (tau1) { spec.push([d1, tau1]); }
    spec.push([d1 - 1, tau - tau1]);
    var moduli = [];
    spec.forEach(function (s) { moduli = moduli.concat(irreducibles(s[0]).slice(0, s[1])); });
    var pools = {};
    for (var dd = 2; dd <= 10; dd++) { pools[dd] = irreducibles(dd).filter(function (q) { return moduli.indexOf(q) < 0; }); }
    var p = MODULI[lambda], D = lambda - 1, picks = crt_search(D, 10, 10, pools)[1];
    /* build */
    var na = lambda, N2 = na + nb - 1, evrows = [], gates = [], resm = [];
    moduli.forEach(function (M) { evrows = evrows.concat(reduction_rows(M, N2)); });
    picks.forEach(function (pk) {
        var pa = place_alg(pk, na, nb), off = B(gates.length);
        gates = gates.concat(pa[0].gates);
        pa[0].W.forEach(function (w) { resm.push(w << off); });
        evrows = evrows.concat(pa[1]);
    });
    var X = left_inverse(evrows, N2), Red = reduction_rows(p, N2), Wt = [], Wg = [];
    for (r = 0; r < lambda; r++) {
        var sel = bits(combine(Red[r], X)), wt = ZERO, wg = ZERO;
        for (i = 0; i < sel.length; i++) { if (sel[i] < nb) { wt |= bit(sel[i]); } else { wg ^= resm[sel[i] - nb]; } }
        Wt.push(wt); Wg.push(wg);
    }
    var lift = crt_lift_cols(moduli), F = gates.map(function (g) { return g[0]; });
    var G = gates.map(function (g) { var v = ZERO; for (var j = 0; j < nb; j++) { if (parity(g[1] & lift.cols[j])) { v |= bit(j); } } return v; });
    /* prune: zero gates, exact duplicates (first kept), unreferenced gates */
    var ng = F.length, canon = new Map(), Wg1 = [], used = ZERO;
    for (i = 0; i < ng; i++) { if (F[i] && G[i]) { var k = F[i] + ',' + G[i]; if (!canon.has(k)) { canon.set(k, i); } } }
    Wg.forEach(function (row) {
        var nr = ZERO;
        bits(row).forEach(function (g) { if (F[g] && G[g]) { nr ^= bit(canon.get(F[g] + ',' + G[g])); } });
        Wg1.push(nr); used |= nr;
    });
    var newidx = {}, F2 = [], G2 = [];
    for (i = 0; i < ng; i++) { if ((used >> B(i)) & ONE) { newidx[i] = F2.length; F2.push(F[i]); G2.push(G[i]); } }
    var Wg2 = Wg1.map(function (row) { var nr = ZERO; bits(row).forEach(function (g) { nr |= bit(newidx[g]); }); return nr; });
    var Wcrt = [];
    for (r = 0; r < lambda; r++) { var v = ZERO; for (var j = 0; j < nb; j++) { if ((lift.cols[j] >> B(r)) & ONE) { v |= bit(j); } } Wcrt.push(v); }
    return (TABLES[key] = { F: F2, G: G2, W_tree: Wt, W_gate: Wg2, W_crt: Wcrt, moduli: moduli, M_tree: lift.Mtree });
}
