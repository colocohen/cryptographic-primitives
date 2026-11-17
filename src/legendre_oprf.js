/**
 * The 2Hash Legendre OPRF (Beullens, Dodgson, Faller, Hesse; Eurocrypt 2025,
 * ePrint 2024/450, section 5)
 *
 * A post-quantum OPRF secure against MALICIOUS clients and servers, from
 * Legendre symbols over p = 2^255 - 19, oblivious transfer and a VOLE-based
 * zero-knowledge proof:
 *
 *     F_K(x) = H2(x, (K + l_i / p)_(i < l_com), (H1(x) + K + l'_j / p)_(j < l_eval))
 *
 * with public random offsets l, l' and H1 slow (2^16 iterations of BLAKE2b,
 * so that guessing x offline costs as much again). The first l_com symbols
 * depend on the key only - they commit to it; the last l_eval carry the input.
 *
 * THE PROTOCOL (Fig. 6), the server holding K, the client h = H1(x):
 *   1. the server picks a in (F_p*)^l_eval, v = a^2 * shift(a^2), u = (K + l') * v,
 *      and commits (VOLE-in-the-head style, but interactive: QuickSilver)
 *      to w = (K, a, s, r_u, r_v, a_last^-1), with s_i^2 (K + l_i) = E(e_i)
 *      for its key symbols e
 *   2. VOLE+ (Fig. 13) gives the client o = u + h v = (h + K + l') * v and a
 *      hash of u and v under the client's gamma - masked by r_u, r_v
 *   3. the server proves, on the committed w, that its u, v hash to those
 *      values, that e are the symbols of K, and that a_last != 0
 *   4. the client reads e' = (o_j / p): v_j is a nonzero square
 * Both VOLEs come from subset VOLE (SoftSpokenOT / FAEST): (N-1)-of-N OT by
 * a GGM tree, N = 2^t, over random 1-of-2 OTs the client receives.
 *
 * MESSAGES. Random OTs first (inputs here, as for pool.js: ot_kem.js and
 * ot_extend.js make them), then
 *     server -> client   S1  trees, witness corrections, VOLE+ corrections, e
 *     client -> server   C1  three challenge seeds
 *     server -> client   S2  consistency checks
 *     client -> server   C2  lambda, Delta' (the masked input)
 *     server -> client   S3  u', v' and the proof
 * and the client checks everything before it outputs.
 *
 * PARAMETERS (section 5.2): l_eval = 128, l_com = 493, statistical security
 * 64, t (log N) a speed/size trade-off: VOLE+ takes ceil((255 + 128) / t)
 * subset VOLEs, the proof ceil(64 / t). The paper's implementation uses t = 8;
 * in JavaScript t = 4 is several times faster for twice the traffic, and is
 * the default.
 */

import { field } from './commons/modp.js';
import { jacobi, require_rng } from './commons/primes.js';
import { blake2b } from './blake2.js';
import { shake256 } from './sha3.js';
import { concat, ascii, be32, xor_into } from './commons/bytes.js';
import { domain_xof } from './commons/domain_xof.js';
import { ggm } from './commons/ggm.js';
import { check_sender_ots, check_receiver_ots } from './commons/random_ot.js';

var P = (1n << 255n) - 19n, Fp = /* @__PURE__ */ field(P), FB = 32, NONRES = 2n;
var DST = /* @__PURE__ */ ascii('cryptographic-primitives/2hash-legendre/v1');
var L_EVAL = 128, L_COM = 493, STAT = 64, SEED = 16;

var H = /* @__PURE__ */ domain_xof(shake256, DST);
function fe_dec(b, off, n) { return Fp.vec_from_bytes(b, off, n, 'legendre_oprf'); }
function dot(a, b) { var s = 0n; for (var i = 0; i < a.length; i++) { s += a[i] * b[i]; } return s % P; }
function legendre(x) { return x === 0n ? 0 : jacobi(x, P); }
/* E(e): 1 -> 1, -1 -> a fixed non-residue (2), 0 -> 0 */
function E(e) { return e === 1 ? 1n : e === -1 ? NONRES : 0n; }

/* the public offsets l (l_com) and l' (l_eval) */
var OFFSETS = /* @__PURE__ */ (function () {
    var v = Fp.vec_from_wide(H(0, [ascii('offsets')], Fp.WIDE * (L_COM + L_EVAL)), L_COM + L_EVAL);
    return { l: v.slice(0, L_COM), le: v.slice(L_COM) };
}());

/* the key's symbols e, and s with (K + l_i) s_i^2 = E(e_i) */
function key_symbols(K) {
    var e = [], s = [];
    for (var i = 0; i < L_COM; i++) {
        var x = Fp.add(K, OFFSETS.l[i]), ei = legendre(x);
        e.push(ei);
        s.push(ei === 0 ? 0n : Fp.sqrt(Fp.mul(E(ei), Fp.inv(x))));
    }
    return { e: e, s: s };
}
function enc_symbols(e) { return Uint8Array.from(e, function (x) { return x + 1; }); }
function dec_symbols(b) {
    var e = [];
    for (var i = 0; i < b.length; i++) { if (b[i] > 2) { throw new Error('legendre_oprf: a symbol is -1, 0 or 1'); } e.push(b[i] - 1); }
    return e;
}

function H1(x, iters) {
    var h = blake2b(concat([DST, x]), 64);
    for (var i = 0; i < iters; i++) { h = blake2b(concat([be32(i), h]), 64); }
    return Fp.from_wide(h);
}
function H2(x, sym) { return blake2b(concat([DST, enc_symbols(sym), x]), 32); }

/* ---------------- subset VOLE from a GGM tree ---------------- */

var TREE_OF = /* @__PURE__ */ ggm(function (seed) { var c = H(1, [seed], 2 * SEED); return [c.subarray(0, SEED), c.subarray(SEED)]; });
function pad(key, len) { return H(2, [key], len); }
function leaf_vector(sid, inst, j, seed, len) { return Fp.vec_from_wide(H(3, [sid, be32(inst), be32(j), seed], Fp.WIDE * len), len); }

/*
 * Sender: a tree from a random root, its level sums sent under the random
 * OT pads, and (u, v) = (-sum_j j R_j, sum_j R_j) - so that the receiver's
 * o = sum_(j != Delta) (Delta - j) R_j = u + Delta v.
 */
function svole_send(t, root, pairs, sid, inst, len) {
    var tr = TREE_OF.level_sums(root, t, SEED), level = tr.levels[t], ct = new Uint8Array(2 * t * SEED), l, b, j;
    for (l = 1; l <= t; l++) {
        for (b = 0; b < 2; b++) { ct.set(xor_into(tr.sums[l - 1][b], pad(pairs[l - 1][b], SEED)), (2 * (l - 1) + b) * SEED); }
    }
    var u = new Array(len).fill(0n), v = new Array(len).fill(0n);
    for (j = 0; j < level.length; j++) {
        var R = leaf_vector(sid, inst, j, level[j], len), J = BigInt(j);
        for (var q = 0; q < len; q++) { v[q] += R[q]; u[q] -= J * R[q]; }
    }
    for (j = 0; j < len; j++) { u[j] = Fp.mod(u[j]); v[j] = Fp.mod(v[j]); }
    return { u: u, v: v, ct: ct };
}
/* Receiver: Delta from its OT choices (the sibling side at each level), every leaf but Delta's, o */
function svole_receive(t, recv, ct, sid, inst, len) {
    var delta = 0, l, j;
    for (l = 1; l <= t; l++) { delta = (delta << 1) | (1 - recv[l - 1].choice); }
    /* the OT at level l gives the level sum on its choice side - the side off Delta's path */
    var known = TREE_OF.from_sums(t, delta, function (lv, side) {
        return xor_into(ct.slice((2 * (lv - 1) + side) * SEED, (2 * (lv - 1) + side + 1) * SEED), pad(recv[lv - 1].key, SEED));
    });
    var o = new Array(len).fill(0n), D = BigInt(delta);
    for (j = 0; j < known.length; j++) {
        if (j === delta) { continue; }
        var R = leaf_vector(sid, inst, j, known[j], len), m = D - BigInt(j);
        for (var q = 0; q < len; q++) { o[q] += m * R[q]; }
    }
    for (j = 0; j < len; j++) { o[j] = Fp.mod(o[j]); }
    return { o: o, delta: D };
}

/* ---------------- the protocol ---------------- */

export function legendre_oprf(opts) {
    var t = (opts && opts.t) || 4, iters = opts && opts.h1_iterations !== undefined ? opts.h1_iterations : 1 << 16;
    if (!(t >= 1 && t <= 10)) { throw new Error('legendre_oprf: t is 1 to 10'); }
    var KV = Math.ceil((255 + 2 * STAT) / t), KZ = Math.ceil(STAT / t), LV = L_EVAL + 1;
    /* the witness: K, a (l_eval), s (l_com), r_u, r_v, a_last^-1, four masks, the check mask */
    var W_A = 1, W_S = W_A + L_EVAL, W_RU = W_S + L_COM, W_RV = W_RU + 1, W_AI = W_RV + 1, W_M = W_AI + 1, W_CHK = W_M + 4, LZ = W_CHK + 1;
    var NOTS = (KV + KZ) * t, TREE = 2 * t * SEED;
    var S1_BYTES = 16 + (KV + KZ) * TREE + KZ * LZ * FB + (KV - 1) * LV * FB + L_COM;
    var C1_BYTES = 48, S2_BYTES = (KZ + 1) * FB + (KV + 1) * FB, C2_BYTES = 16 + FB, S3_BYTES = 2 * LV * FB + 5 * FB;

    function seeds(seed, n) { return Fp.vec_from_wide(H(4, [seed], Fp.WIDE * n), n); }
    /* the ZK constraint, as a degree-5 polynomial in the prover's VOLE indeterminate (coefficients low first) or as a value at Delta */
    function pmul(a, b) { var o = new Array(a.length + b.length - 1).fill(0n); for (var i = 0; i < a.length; i++) { for (var j = 0; j < b.length; j++) { o[i + j] += a[i] * b[j]; } } return o.map(function (x) { return x % P; }); }
    function padd(acc, a, shift) { for (var i = 0; i < a.length; i++) { acc[i + shift] = (acc[i + shift] + a[i]) % P; } }
    function pscale(a, c) { return a.map(function (x) { return x * c % P; }); }

    /** A server key: K, with its key symbols precomputed. */
    function server_key(K) {
        if (typeof K !== 'bigint' || K < 0n || K >= P) { throw new Error('legendre_oprf: K is a field element'); }
        var ks = key_symbols(K);
        return { K: K, e: ks.e, s: ks.s };
    }
    function keygen(rng) { rng = require_rng('legendre_oprf.keygen', rng); return server_key(Fp.from_wide(rng(Fp.WIDE))); }
    function eval_symbols(K, h, e) {
        var ks = e ? e.slice() : OFFSETS.l.map(function (l) { return legendre(Fp.add(K, l)); });
        for (var j = 0; j < L_EVAL; j++) { ks.push(legendre(Fp.add(Fp.add(h, K), OFFSETS.le[j]))); }
        return ks;
    }
    /** The PRF, with the key: F_K(x). */
    function evaluate(key, x) { return H2(x, eval_symbols(key.K, H1(x, iters), key.e)); }

    /* ---- server ---- */
    function server_start(key, pairs, rng) {
        rng = require_rng('legendre_oprf.server_start', rng);
        check_sender_ots(pairs, NOTS, 'legendre_oprf');
        var sid = rng(16), a = [], i;
        for (i = 0; i < L_EVAL; i++) { var x; do { x = Fp.from_wide(rng(Fp.WIDE)); } while (x === 0n); a.push(x); }
        var a2 = a.map(function (y) { return y * y % P; }), v = a2.map(function (y, q) { return q ? y * a2[q - 1] % P : y; });
        var u = v.map(function (y, q) { return Fp.mul(Fp.add(key.K, OFFSETS.le[q]), y); });
        var ru = Fp.from_wide(rng(Fp.WIDE)), rv = Fp.from_wide(rng(Fp.WIDE));
        var w = [key.K].concat(a, key.s, [ru, rv, Fp.inv(a[L_EVAL - 1])]);
        for (i = 0; i < 5; i++) { w.push(Fp.from_wide(rng(Fp.WIDE))); }
        /* subset VOLEs: KZ for the proof, KV for VOLE+ */
        var trees = [], zs = [], vs = [];
        for (i = 0; i < KZ + KV; i++) {
            var sv = svole_send(t, rng(SEED), pairs.slice(i * t, (i + 1) * t), sid, i, i < KZ ? LZ : LV);
            trees.push(sv.ct);
            (i < KZ ? zs : vs).push(sv);
        }
        /* the witness, committed in every proof VOLE: corrections w - v_i */
        var corr = [];
        for (i = 0; i < KZ; i++) { corr.push(Fp.vec_to_bytes(w.map(function (y, q) { return Fp.sub(y, zs[i].v[q]); }))); }
        /* VOLE+: every v_i made v_1 */
        var vcorr = [];
        for (i = 1; i < KV; i++) { vcorr.push(Fp.vec_to_bytes(vs[0].v.map(function (y, q) { return Fp.sub(y, vs[i].v[q]); }))); }
        var msg = concat([sid].concat(trees, corr, vcorr, [enc_symbols(key.e)]));
        return { state: { key: key, sid: sid, a: a, u: u, v: v, ru: ru, rv: rv, w: w, zs: zs, vs: vs }, msg: msg };
    }
    function server_respond(st, c1) {
        if (!(c1 instanceof Uint8Array) || c1.length !== C1_BYTES) { throw new Error('legendre_oprf: C1 is ' + C1_BYTES + ' bytes'); }
        st.gz = seeds(c1.subarray(0, 16), LZ - 1);
        st.gv = seeds(c1.subarray(16, 32), L_EVAL);
        st.lin = c1.subarray(32, 48);
        var gz = st.gz, gv1 = st.gv.concat([1n]), out = [], i;
        /* the proof's consistency check */
        out.push((st.w[W_CHK] + dot(gz, st.w.slice(0, LZ - 1))) % P);
        for (i = 0; i < KZ; i++) { out.push((st.zs[i].u[W_CHK] + dot(gz, st.zs[i].u.slice(0, LZ - 1))) % P); }
        /* VOLE+ */
        for (i = 0; i < KV; i++) { out.push(dot(gv1, st.vs[i].u)); }
        out.push(dot(gv1, st.vs[0].v));
        return Fp.vec_to_bytes(out);
    }
    function server_finish(st, c2) {
        if (!(c2 instanceof Uint8Array) || c2.length !== C2_BYTES) { throw new Error('legendre_oprf: C2 is ' + C2_BYTES + ' bytes'); }
        var lam = seeds(c2.subarray(0, 16), KV), dp = fe_dec(c2, 16, 1)[0], i, q;
        var uu = st.u.concat([st.ru]), vv = st.v.concat([st.rv]), u2 = new Array(LV), v2 = new Array(LV);
        for (q = 0; q < LV; q++) {
            var s = 0n;
            for (i = 0; i < KV; i++) { s += lam[i] * st.vs[i].u[q]; }
            u2[q] = Fp.mod(uu[q] - s + dp * st.vs[0].v[q]);
            v2[q] = Fp.sub(vv[q], st.vs[0].v[q]);
        }
        return concat([Fp.vec_to_bytes(u2), Fp.vec_to_bytes(v2), Fp.vec_to_bytes(prove(st))]);
    }
    /* QuickSilver: the prover's polynomials, w_j X + c_j with c_j = sum_i 2^(t i) u_i[j] */
    function prove(st) {
        var c = new Array(LZ).fill(0n), i, j;
        for (i = 0; i < KZ; i++) { var m = 1n << BigInt(t * i); for (j = 0; j < LZ; j++) { c[j] += m * st.zs[i].u[j]; } }
        var Pw = c.map(function (cj, q) { return [cj % P, st.w[q]]; });
        var acc = new Array(6).fill(0n);
        constraint(Pw, st.gv, st.lin, function (poly, deg) { padd(acc, poly, 5 - deg); }, true);
        /* the masks hide coefficients 0..4 */
        for (i = 0; i < 4; i++) { padd(acc, Pw[W_M + i], i); }
        return acc.slice(0, 5);
    }
    /*
     * The batched constraint over values X: polynomials (prover) or field
     * elements at Delta (verifier). emit(value, degree); the targets (cu, cv,
     * E(e), 1) enter at degree 5 on the verifier's side.
     */
    function constraint(X, gv, lin, emit, prover) {
        var mul = prover ? pmul : function (a, b) { return a * b % P; };
        var add = prover ? function (a, b) { var o = a.slice(); padd(o, b, 0); return o; } : function (a, b) { return (a + b) % P; };
        var scl = prover ? pscale : function (a, k) { return a * k % P; };
        var cst = prover ? function (k) { return [0n, k]; } : null;
        var r = seeds(lin, 2 + L_COM), i;
        function plus_const(x, k) { return prover ? add(x, cst(k)) : null; }
        /* v_i = a_i^2 a_(i-1)^2 and (K + l'_i) v_i, hashed with gamma */
        var a2 = [], hv = null, hu = null;
        for (i = 0; i < L_EVAL; i++) { a2.push(mul(X[W_A + i], X[W_A + i])); }
        for (i = 0; i < L_EVAL; i++) {
            var vi = i ? mul(a2[i], a2[i - 1]) : a2[0];
            if (!i && prover) { vi = [0n, 0n].concat(vi); }       /* degree 4 like the rest */
            var term = scl(vi, gv[i]);
            hv = hv === null ? term : add(hv, term);
            var kl = prover ? plus_const(X[0], OFFSETS.le[i]) : null;
            hu = hu === null ? (prover ? mul(term, kl) : null) : (prover ? add(hu, mul(term, kl)) : null);
        }
        if (prover) {
            emit(add(hu, [0n, 0n, 0n, 0n].concat(X[W_RU])), 5);
            emit(scl(add(hv, [0n, 0n, 0n].concat(X[W_RV])), r[0]), 4);
            for (i = 0; i < L_COM; i++) { emit(scl(mul(plus_const(X[0], OFFSETS.l[i]), mul(X[W_S + i], X[W_S + i])), r[2 + i]), 3); }
            emit(scl(mul(X[W_A + L_EVAL - 1], X[W_AI]), r[1]), 2);
        }
        return { a2: a2, r: r };
    }

    /* ---- client ---- */
    function client_start(x, recv, s1, rng) {
        rng = require_rng('legendre_oprf.client_start', rng);
        check_receiver_ots(recv, NOTS, 'legendre_oprf');
        if (!(s1 instanceof Uint8Array) || s1.length !== S1_BYTES) { throw new Error('legendre_oprf: S1 is ' + S1_BYTES + ' bytes'); }
        var sid = s1.subarray(0, 16), off = 16, i, j, zo = [], vo = [];
        for (i = 0; i < KZ + KV; i++) {
            var r = svole_receive(t, recv.slice(i * t, (i + 1) * t), s1.subarray(off, off + TREE), sid, i, i < KZ ? LZ : LV);
            off += TREE;
            (i < KZ ? zo : vo).push(r);
        }
        for (i = 0; i < KZ; i++) {
            var cw = fe_dec(s1, off, LZ); off += LZ * FB;
            for (j = 0; j < LZ; j++) { zo[i].o[j] = Fp.add(zo[i].o[j], Fp.mul(zo[i].delta, cw[j])); }
        }
        for (i = 1; i < KV; i++) {
            var cv = fe_dec(s1, off, LV); off += LV * FB;
            for (j = 0; j < LV; j++) { vo[i].o[j] = Fp.add(vo[i].o[j], Fp.mul(vo[i].delta, cv[j])); }
        }
        var e = dec_symbols(s1.subarray(off, off + L_COM));
        var c1 = rng(48);
        return {
            state: { x: x, h: H1(x, iters), zo: zo, vo: vo, e: e, gz: seeds(c1.subarray(0, 16), LZ - 1), gv: seeds(c1.subarray(16, 32), L_EVAL), lin: c1.slice(32, 48) },
            msg: c1
        };
    }
    function client_continue(st, s2, rng) {
        rng = require_rng('legendre_oprf.client_continue', rng);
        if (!(s2 instanceof Uint8Array) || s2.length !== S2_BYTES) { throw new Error('legendre_oprf: S2 is ' + S2_BYTES + ' bytes'); }
        var v = fe_dec(s2, 0, KZ + 1 + KV + 1), i, gz = st.gz, gv1 = st.gv.concat([1n]);
        var zcv = v[0];
        for (i = 0; i < KZ; i++) {
            var oi = st.zo[i].o;
            if ((oi[W_CHK] + dot(gz, oi.slice(0, LZ - 1))) % P !== (v[1 + i] + st.zo[i].delta * zcv) % P) { throw new Error('legendre_oprf: the server\'s commitment is inconsistent'); }
        }
        var cv1 = v[KZ + 1 + KV];
        for (i = 0; i < KV; i++) {
            if (dot(gv1, st.vo[i].o) !== (v[KZ + 1 + i] + st.vo[i].delta * cv1) % P) { throw new Error('legendre_oprf: the server\'s VOLE is inconsistent'); }
        }
        st.cv1 = cv1;
        var ls = rng(16), lam = seeds(ls, KV), D = 0n;
        for (i = 0; i < KV; i++) { D += lam[i] * st.vo[i].delta; }
        st.lam = lam;
        return concat([ls, Fp.vec_to_bytes([Fp.sub(st.h, Fp.mod(D))])]);
    }
    function client_finish(st, s3) {
        if (!(s3 instanceof Uint8Array) || s3.length !== S3_BYTES) { throw new Error('legendre_oprf: S3 is ' + S3_BYTES + ' bytes'); }
        var u2 = fe_dec(s3, 0, LV), v2 = fe_dec(s3, LV * FB, LV), pf = fe_dec(s3, 2 * LV * FB, 5), i, q;
        /* VOLE+: o = sum_i lambda_i o_i + u' + h v' */
        var o = new Array(LV);
        for (q = 0; q < LV; q++) {
            var s = 0n;
            for (i = 0; i < KV; i++) { s += st.lam[i] * st.vo[i].o[q]; }
            o[q] = Fp.mod(s + u2[q] + st.h * v2[q]);
        }
        var gv1 = st.gv.concat([1n]), cv = (st.cv1 + dot(gv1, v2)) % P, cu = Fp.sub(dot(gv1, o), Fp.mul(st.h, cv));
        /* the proof, at Delta = sum_i 2^(t i) Delta_i */
        var Dz = 0n, Kz = new Array(LZ).fill(0n);
        for (i = 0; i < KZ; i++) { var m = 1n << BigInt(t * i); Dz += m * st.zo[i].delta; for (q = 0; q < LZ; q++) { Kz[q] += m * st.zo[i].o[q]; } }
        Dz %= P;
        Kz = Kz.map(function (y) { return y % P; });
        var dp = [1n]; for (i = 1; i <= 5; i++) { dp.push(dp[i - 1] * Dz % P); }
        var c = constraint(Kz, st.gv, st.lin, null, false), r = c.r, val = 0n, hv = 0n, hu = 0n;
        for (i = 0; i < L_EVAL; i++) {
            var vi = i ? c.a2[i] * c.a2[i - 1] % P : c.a2[0] * dp[2] % P;
            var term = vi * st.gv[i] % P;
            hv += term;
            hu += term * ((Kz[0] + OFFSETS.le[i] * Dz) % P);
        }
        val += (hu + Kz[W_RU] * dp[4]) % P - cu * dp[5];
        val += r[0] * ((hv + Kz[W_RV] * dp[3]) % P - cv * dp[4]) % P * Dz;
        for (i = 0; i < L_COM; i++) {
            var f = (Kz[0] + OFFSETS.l[i] * Dz) % P * Kz[W_S + i] % P * Kz[W_S + i] % P - E(st.e[i]) * dp[3];
            val += r[2 + i] * f % P * dp[2];
        }
        val += r[1] * ((Kz[W_A + L_EVAL - 1] * Kz[W_AI] - dp[2]) % P) % P * dp[3];
        for (i = 0; i < 4; i++) { val += Kz[W_M + i] * dp[i]; }
        var claim = 0n; for (i = 0; i < 5; i++) { claim += pf[i] * dp[i]; }
        if (Fp.mod(val) !== Fp.mod(claim)) { throw new Error('legendre_oprf: the server\'s proof does not verify'); }
        /* the output */
        var sym = st.e.slice(), zeros = 0;
        for (q = 0; q < L_EVAL; q++) { if (o[q] === 0n) { zeros++; } sym.push(legendre(o[q])); }
        if (zeros > 1) { throw new Error('legendre_oprf: two evaluations are zero'); }
        for (i = 0; i < L_COM; i++) {
            if (st.e[i] === 0) {
                /* K = -l_i is the only key with this symbol: check the whole sequence against it */
                var want = eval_symbols(Fp.neg(OFFSETS.l[i]), st.h);
                for (q = 0; q < want.length; q++) { if (want[q] !== sym[q]) { throw new Error('legendre_oprf: the server\'s symbols are inconsistent'); } }
            }
        }
        return H2(st.x, sym);
    }

    return {
        T: t, OTS: NOTS, KV: KV, KZ: KZ, P: P,
        /** the public offsets l (l_com) and l' (l_eval), copies */
        offsets: function () { return { l: OFFSETS.l.slice(), le: OFFSETS.le.slice() }; },
        BYTES: { S1: S1_BYTES, C1: C1_BYTES, S2: S2_BYTES, C2: C2_BYTES, S3: S3_BYTES },
        keygen: keygen, server_key: server_key, evaluate: evaluate,
        server_start: server_start, server_respond: server_respond, server_finish: server_finish,
        client_start: client_start, client_continue: client_continue, client_finish: client_finish
    };
}
