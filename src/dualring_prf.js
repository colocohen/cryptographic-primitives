/**
 * DualRing-PRF  -  post-quantum ring and linkable ring signatures from the
 * Legendre and power-residue PRFs (Zhang, Steinfeld, Liu, Esgin, Liu, Ruj;
 * ePrint 2024/985)
 *
 * A RING SIGNATURE over keys pk = L_K(I) - the PRF L_K(a) = (K + a / p)
 * (Legendre, t = 2) or the t-th power residue symbol of K + a (t = 254),
 * evaluated on L public points I - in the DualRing pattern: the signer picks
 * a challenge c_j for every other member, and its own c_pi closes the ring
 * (XOR of all c_j = H1(commitment)). Each challenge names B points of I; the
 * signer proves, in MPC-in-the-head (LegRoast's sacrificing check, tau
 * parallel runs of N parties), that its o_b = (K + I_b) r_b, with the
 * symbols of the r_b committed beforehand as T_b = L_0(r_b) - sum_(j != pi)
 * pk_j[I_j,b]. The verifier checks T_b = L_0(o_b) - sum_j pk_j[I_j,b] over
 * the WHOLE ring, so it never learns which I_b the proof used: those enter
 * the MPC only masked, and a cut-and-choose over M masked copies (one left
 * unopened, its offsets committed in a Merkle tree under a secret
 * permutation of the ring) shows the masking was honest.
 *
 * LINKABLE (section 3.2): the signature carries tag = L_K(I'), I' expanded
 * from the event ID, and the same proof covers o'_b = (K + I'_b) r'_b at B
 * further points; one key and one event give one tag.
 *
 * PARAMETER SETS (Table 2), p = 2^127 - 1:
 *   L_FAST / L_MEDIUM / L_SLOW      Legendre, L = 2^15: N = 16/64/256, B = 10/10/11,
 *                                   tau = 74/58/46, M = 2^7/2^8/2^9
 *   PR_FAST / PR_MEDIUM / PR_SLOW   t = 254, L = 2^12: N = 16/64/256, B = 5/6/7,
 *                                   tau = 59/43/34, M = 2^7/2^8/2^9
 * Public keys are 4 KB; signatures grow with the ring (34-97 KB for 2^4 to
 * 2^10 members), signing and verifying with tau M ring-sized trees.
 *
 * ENCODING (this library's; the paper publishes no vectors): SHAKE256 for
 * every hash, PRG and expansion, with one domain byte each; the masks are B
 * field elements per copy (one per checked point); the Merkle leaf position
 * of the signer's offsets travels with its path; I and the field's t-th
 * root of unity are derived from fixed labels.
 */

import { field } from './commons/modp.js';
import { shake256 } from './sha3.js';
import { concat, ascii, be32, rd_be32u } from './commons/bytes.js';
import { domain_xof } from './commons/domain_xof.js';
import { ggm } from './commons/ggm.js';
import { require_rng, jacobi } from './commons/primes.js';

var P = (1n << 127n) - 1n, Fp = /* @__PURE__ */ field(P), FB = 16, SEED = 16, DIG = 32;
var DST = /* @__PURE__ */ ascii('cryptographic-primitives/dualring-prf/v1');
var SETS = {
    L_FAST: [2, 15, 16, 10, 74, 7], L_MEDIUM: [2, 15, 64, 10, 58, 8], L_SLOW: [2, 15, 256, 11, 46, 9],
    PR_FAST: [254, 12, 16, 5, 59, 7], PR_MEDIUM: [254, 12, 64, 6, 43, 8], PR_SLOW: [254, 12, 256, 7, 34, 9]
};
var D = { I: 0, SEEDT: 1, SHARE: 2, MPC: 3, CSD: 4, CMASK: 5, CDELTA: 6, MERKLE: 7, ACC: 8, H1: 9, H2: 10, H3: 11, H4: 12, IDX: 13, PERM: 14, ID: 15, KEY: 16, CH: 17 };

var H = /* @__PURE__ */ domain_xof(shake256, DST);
function expand_f(dom, parts, n) { return Fp.vec_from_wide(H(dom, parts, Fp.WIDE * n), n); }
function rd_fe(b, off) { return Fp.vec_from_bytes(b, off, 1, 'dualring_prf')[0]; }
function log2(n) { return 31 - Math.clz32(n); }
function sum(list) { var s = 0n; for (var i = 0; i < list.length; i++) { s += list[i]; } return s % P; }

/* ---- the PRF: symbols in Z_t ---- */
var SYM = /* @__PURE__ */ (function () {
    var out = {};
    [2, 254].forEach(function (t) {
        var ex = (P - 1n) / BigInt(t), table = new Map(), w;
        for (var g = 3n; ; g++) {
            w = Fp.pow(g, ex);
            if (Fp.pow(w, BigInt(t / 2)) !== 1n && (t === 2 || Fp.pow(w, 2n) !== 1n)) { break; }
        }
        for (var i = 0, x = 1n; i < t; i++, x = Fp.mul(x, w)) { table.set(x, i); }
        out[t] = { ex: ex, table: table };
    });
    return out;
}());
function symbol(t, a) {
    if (a === 0n) { return 0; }
    if (t === 2) { return jacobi(a, P) === 1 ? 0 : 1; }
    var s = SYM[t], i = s.table.get(Fp.pow(a, s.ex));
    if (i === undefined) { throw new Error('dualring_prf: no symbol'); }
    return i;
}

/* ---- seed trees: n leaves from a root, all but one opened by log n siblings ---- */
var TREE = /* @__PURE__ */ ggm(function (seed) { var c = H(D.SEEDT, [seed], 2 * SEED); return [c.subarray(0, SEED), c.subarray(SEED)]; });

/* ---- Merkle accumulator over ell leaves (padded to a power of two) ---- */
function merkle_levels(leaves, salt) {
    var n = 1; while (n < leaves.length) { n *= 2; }
    var lv = leaves.slice(); while (lv.length < n) { lv.push(new Uint8Array(DIG)); }
    var levels = [lv];
    while (lv.length > 1) { var nx = []; for (var i = 0; i < lv.length; i += 2) { nx.push(H(D.MERKLE, [salt, lv[i], lv[i + 1]], DIG)); } levels.push(nx); lv = nx; }
    return levels;
}
function merkle_path(levels, pos) { var out = []; for (var l = 0; l < levels.length - 1; l++) { out.push(levels[l][pos ^ 1]); pos >>= 1; } return out; }
function merkle_root_from(leaf, pos, path, salt) {
    var x = leaf;
    for (var l = 0; l < path.length; l++) { x = (pos & 1) ? H(D.MERKLE, [salt, path[l], x], DIG) : H(D.MERKLE, [salt, x, path[l]], DIG); pos >>= 1; }
    return x;
}
function permutation(seed, n) {
    var p = []; for (var i = 0; i < n; i++) { p.push(i); }
    /* Fisher-Yates on 64-bit draws: a draw mod (i + 1) is uniform to within 2^-48 */
    var b = H(D.PERM, [seed], 8 * n);
    for (i = n - 1; i > 0; i--) {
        var m = i + 1, r = ((rd_be32u(b, 8 * i) % m) * (0x100000000 % m) + rd_be32u(b, 8 * i + 4) % m) % m, t = p[i];
        p[i] = p[r]; p[r] = t;
    }
    return p;
}

export function dualring_prf(name) {
    var S = SETS[name];
    if (!S) { throw new Error('dualring_prf: unknown parameter set ' + name); }
    var t = S[0], LB = S[1], L = 1 << LB, N = S[2], B = S[3], TAU = S[4], MB = S[5], M = 1 << MB, NB = log2(N);
    var PK_BYTES = t === 2 ? L / 8 : L, SK_BYTES = FB;
    var I = expand_f(D.I, [ascii('I'), be32(L)], L);

    function enc_pk(sy) { var o = new Uint8Array(PK_BYTES); for (var i = 0; i < L; i++) { if (t === 2) { o[i >> 3] |= sy[i] << (i & 7); } else { o[i] = sy[i]; } } return o; }
    function pk_sym(pk, i) { return t === 2 ? (pk[i >> 3] >> (i & 7)) & 1 : pk[i]; }
    function prf(K, pts) { return pts.map(function (a) { return symbol(t, Fp.add(K, a)); }); }
    /* indices into I: TAU x B per challenge seed */
    function indices(dom, seed, n) {
        var b = H(dom, [seed], 2 * n), o = new Array(n);
        for (var i = 0; i < n; i++) { o[i] = (b[2 * i] | (b[2 * i + 1] << 8)) & (L - 1); }
        return o;
    }
    function draws(h, n, bits) { var b = H(D.IDX, [h], 2 * n), o = []; for (var i = 0; i < n; i++) { o.push((b[2 * i] | (b[2 * i + 1] << 8)) & ((1 << bits) - 1)); } return o; }

    function keygen(rng) {
        rng = require_rng('dualring_prf.keygen', rng);
        var K; do { K = Fp.from_wide(rng(Fp.WIDE)); } while (K === 0n);
        return { pk: enc_pk(prf(K, I)), sk: Fp.to_bytes(K) };
    }
    function check_ring(ring) {
        if (!Array.isArray(ring) || ring.length < 2) { throw new Error('dualring_prf: a ring is an array of at least two public keys'); }
        ring.forEach(function (pk) {
            if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { throw new Error('dualring_prf: a public key is ' + PK_BYTES + ' bytes'); }
            if (t === 254) { for (var i = 0; i < L; i++) { if (pk[i] >= t) { throw new Error('dualring_prf: a symbol out of range'); } } }
        });
    }
    function ring_bytes(ring) { return concat([be32(ring.length)].concat(ring)); }

    /* the shares one party's seed gives: K, r (B), [r' (B)], a, b, c */
    function nshare(linkable) { return 4 + (linkable ? 2 : 1) * B; }
    function shares(sd, linkable) {
        var v = expand_f(D.MPC, [sd], nshare(linkable));
        return { K: v[0], r: v.slice(1, 1 + B), r2: linkable ? v.slice(1 + B, 1 + 2 * B) : null, a: v[v.length - 3], b: v[v.length - 2], c: v[v.length - 1] };
    }
    function mask_share(sd) { return expand_f(D.SHARE, [sd], B); }

    /* lambda and epsilon from h3 */
    function coins(h3, linkable) {
        var per = 1 + (linkable ? 2 : 1) * B, v = expand_f(D.H3, [h3, ascii('coins')], TAU * per), out = [];
        for (var e = 0; e < TAU; e++) { var w = v.slice(e * per, (e + 1) * per); out.push({ eps: w[0], lam: w.slice(1, 1 + B), lam2: linkable ? w.slice(1 + B) : null }); }
        return out;
    }

    /*
     * The per-party computation of the sacrificing check (Algorithm 5 lines
     * 4-16, Algorithm 6 lines 9-20): alpha_i, beta_i and z'_i of party i.
     */
    function party(sh, Ishare, ch, o2pts, alpha, beta, extra) {
        var a = (sh.a + ch.eps * sh.K) % P, b = sh.b, beta_i = sh.b;
        for (var q = 0; q < B; q++) { beta_i += ch.lam[q] * sh.r[q]; }
        var zp = 0n;
        for (q = 0; q < B; q++) { zp -= ch.lam[q] * sh.r[q] % P * Ishare[q]; }
        if (sh.r2) { for (q = 0; q < B; q++) { beta_i += ch.lam2[q] * sh.r2[q]; zp -= ch.lam2[q] * sh.r2[q] % P * o2pts[q]; } }
        zp = Fp.mod(zp + extra);
        var res = { alpha: a, beta: Fp.mod(beta_i), zp: zp };
        if (alpha !== null) { res.gamma = Fp.mod(alpha * b + beta * sh.a - sh.c + ch.eps * zp); }
        return res;
    }

    function sign_any(sk, ring, msg, rng, event) {
        rng = require_rng('dualring_prf.sign', rng);
        check_ring(ring);
        if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES) { throw new Error('dualring_prf: a secret key is ' + SK_BYTES + ' bytes'); }
        var K = rd_fe(sk, 0), pk = enc_pk(prf(K, I)), n = ring.length, pi = -1, e, k, j, q;
        for (j = 0; j < n; j++) { var d = 0; for (q = 0; q < PK_BYTES; q++) { d |= ring[j][q] ^ pk[q]; } if (!d) { pi = j; break; } }
        if (pi < 0) { throw new Error('dualring_prf: the signer\'s public key is not in the ring'); }
        var linkable = event !== undefined, I2 = null, tag = null;
        if (linkable) { I2 = expand_f(D.ID, [event], L); tag = enc_pk(prf(K, I2)); }
        var salt = rng(DIG), cs = new Array(n), idx = new Array(n);
        for (j = 0; j < n; j++) { if (j !== pi) { cs[j] = rng(SEED); idx[j] = indices(D.CH, cs[j], TAU * B); } }
        var R = [], s1 = [salt, msg, ring_bytes(ring)].concat(linkable ? [event, tag] : []);
        /* Phase 1 */
        for (e = 0; e < TAU; e++) {
            var mroot = rng(SEED), mseeds = TREE.leaves(mroot, M), mpcroot = rng(SEED), proot = rng(SEED);
            var sds = TREE.leaves(mpcroot, N), sh = sds.map(function (sd) { return shares(sd, linkable); });
            var Cmpc = sds.map(function (sd, ii) { return H(D.CSD, [salt, be32(e), be32(ii), sd], DIG); });
            var masks = [], Cmask = [];
            for (k = 0; k < M; k++) {
                var ss = TREE.leaves(mseeds[k], N), ms = ss.map(mask_share);
                masks.push({ seeds: ss, shares: ms });
                Cmask.push(ms.map(function (m, ii) { return H(D.CMASK, [salt, be32(e), be32(k), be32(ii), Fp.vec_to_bytes(m)], DIG); }));
            }
            var Ksum = sum(sh.map(function (x) { return x.K; })), dK = Fp.sub(K, Ksum);
            sh[0].K = Fp.add(sh[0].K, dK);
            var as = sum(sh.map(function (x) { return x.a; })), bs = sum(sh.map(function (x) { return x.b; })), dc = Fp.sub(Fp.mul(as, bs), sum(sh.map(function (x) { return x.c; })));
            sh[0].c = Fp.add(sh[0].c, dc);
            var r = [], r2 = [], Te = [], T2 = [];
            for (q = 0; q < B; q++) {
                r.push(sum(sh.map(function (x) { return x.r[q]; })));
                var s = symbol(t, r[q]);
                for (j = 0; j < n; j++) { if (j !== pi) { s -= pk_sym(ring[j], idx[j][e * B + q]); } }
                Te.push(((s % t) + t) % t);
                if (linkable) { r2.push(sum(sh.map(function (x) { return x.r2[q]; }))); T2.push(symbol(t, r2[q])); }
            }
            R.push({ mroot: mroot, mseeds: mseeds, mpcroot: mpcroot, proot: proot, sds: sds, sh: sh, Cmpc: Cmpc, masks: masks, Cmask: Cmask, dK: dK, dc: dc, r: r, r2: r2 });
            s1.push(concat([].concat(Cmask.reduce(function (acc, row) { return acc.concat(row); }, []), Cmpc)), Uint8Array.from(Te), Uint8Array.from(T2), Fp.to_bytes(dK), Fp.to_bytes(dc));
        }
        var h1 = H(D.H1, s1, DIG), cpi = h1.slice(0, SEED);
        for (j = 0; j < n; j++) { if (j !== pi) { for (q = 0; q < SEED; q++) { cpi[q] ^= cs[j][q]; } } }
        cs[pi] = cpi; idx[pi] = indices(D.CH, cpi, TAU * B);
        /* the linkable points come from what the challenges XOR to: h1's first half */
        var idx2 = linkable ? indices(D.ID, h1.subarray(0, SEED), TAU * B) : null;
        /* Phase 2: offsets, permuted and accumulated */
        var accs = [];
        for (e = 0; e < TAU; e++) {
            var Re = R[e], pseeds = TREE.leaves(Re.proot, M), acc_k = [];
            Re.pseeds = pseeds; Re.levels = []; Re.perm = []; Re.dI = [];
            for (k = 0; k < M; k++) {
                var mk = []; for (q = 0; q < B; q++) { mk.push(sum(Re.masks[k].shares.map(function (x) { return x[q]; }))); }
                var dIk = new Array(n), perm = permutation(pseeds[k], n);
                for (j = 0; j < n; j++) {
                    var di = []; for (q = 0; q < B; q++) { di.push(Fp.sub(I[idx[j][e * B + q]], mk[q])); }
                    dIk[j] = di;
                }
                var leafs = []; for (var pos = 0; pos < n; pos++) { leafs.push(H(D.CDELTA, [salt, be32(e), be32(k), Fp.vec_to_bytes(dIk[perm[pos]])], DIG)); }
                var lv = merkle_levels(leafs, salt);
                Re.levels.push(lv); Re.perm.push(perm); Re.dI.push(dIk[pi]);
                acc_k.push(lv[lv.length - 1][0]);
            }
            accs.push(H(D.ACC, [salt, be32(e)].concat(acc_k), DIG));
        }
        var h2 = H(D.H2, [h1].concat(accs), DIG), kbar = draws(concat([h2, ascii('k')]), TAU, MB);
        /* Phase 4: the responses */
        var os = [];
        for (e = 0; e < TAU; e++) {
            var oe = [];
            for (q = 0; q < B; q++) { oe.push(Fp.mul(Fp.add(K, I[idx[pi][e * B + q]]), R[e].r[q])); }
            if (linkable) { for (q = 0; q < B; q++) { oe.push(Fp.mul(Fp.add(K, I2[idx2[e * B + q]]), R[e].r2[q])); } }
            os.push(oe);
        }
        var h3 = H(D.H3, [h2].concat(os.map(function (o) { return Fp.vec_to_bytes(o); })), DIG), ch = coins(h3, linkable);
        /* Phase 6: the sacrificing check */
        var s4 = [h3], views = [];
        for (e = 0; e < TAU; e++) {
            var Re2 = R[e], c = ch[e], kb = kbar[e], o = os[e];
            var Ipi = []; for (q = 0; q < B; q++) { Ipi.push(I[idx[pi][e * B + q]]); }
            var o2pts = linkable ? Array.from({ length: B }, function (_, qq) { return I2[idx2[e * B + qq]]; }) : null;
            var parts = Re2.sh.map(function (x, ii) {
                var Ish = Re2.masks[kb].shares[ii].slice();
                if (ii === 0) { for (var qq = 0; qq < B; qq++) { Ish[qq] = Fp.add(Ish[qq], Re2.dI[kb][qq]); } }
                return { pre: party(x, Ish, c, o2pts, null, null, 0n), Ish: Ish };
            });
            /* z with the true points, and the correction dz */
            var z = 0n, zp_sum = 0n;
            Re2.sh.forEach(function (x) { for (var qq = 0; qq < B; qq++) { z -= c.lam[qq] * x.r[qq] % P * Ipi[qq]; } if (x.r2) { for (qq = 0; qq < B; qq++) { z -= c.lam2[qq] * x.r2[qq] % P * o2pts[qq]; } } });
            parts.forEach(function (pp) { zp_sum += pp.pre.zp; });
            var dz = Fp.mod(z - zp_sum), lo = 0n;
            for (q = 0; q < B; q++) { lo += c.lam[q] * o[q]; }
            if (linkable) { for (q = 0; q < B; q++) { lo += c.lam2[q] * o[B + q]; } }
            var alpha = sum(parts.map(function (pp) { return pp.pre.alpha; })), beta = sum(parts.map(function (pp) { return pp.pre.beta; }));
            var vw = Re2.sh.map(function (x, ii) { return party(x, parts[ii].Ish, c, o2pts, alpha, beta, ii === 0 ? dz + lo : 0n); });
            views.push({ dz: dz, alpha: alpha, beta: beta });
            s4.push(Fp.vec_to_bytes([alpha, beta]), Fp.vec_to_bytes([].concat.apply([], vw.map(function (v) { return [v.alpha, v.beta, v.gamma]; }))));
        }
        var h4 = H(D.H4, s4, DIG), ibar = draws(concat([h4, ascii('i')]), TAU, NB);
        /* Phase 8: the signature */
        var out = [salt, h2, h4].concat(cs);
        for (e = 0; e < TAU; e++) {
            var Rf = R[e], kf = kbar[e], ib = ibar[e], posf = Rf.perm[kf].indexOf(pi);
            out.push(concat(TREE.open(Rf.proot, M, kf)), concat(TREE.open(Rf.mroot, M, kf)), concat(TREE.open(Rf.mseeds[kf], N, ib)),
                     be32(posf), concat(merkle_path(Rf.levels[kf], posf)), concat(TREE.open(Rf.mpcroot, N, ib)),
                     Fp.vec_to_bytes([Rf.dK, Rf.dc, views[e].dz, views[e].alpha, views[e].beta].concat(os[e], Rf.dI[kf])),
                     Rf.Cmpc[ib], Rf.Cmask[kf][ib]);
        }
        if (linkable) { out.push(tag); }
        return concat(out);
    }

    function per_e_bytes(n, linkable) {
        var depth = 0; while ((1 << depth) < n) { depth++; }
        return 2 * MB * SEED + 2 * NB * SEED + 4 + depth * DIG + FB * (5 + (linkable ? 3 : 2) * B) + 2 * DIG;
    }
    function sig_bytes(n, linkable) { return DIG * 3 + n * SEED + TAU * per_e_bytes(n, linkable) + (linkable ? PK_BYTES : 0); }

    function verify_any(ring, msg, sig, event) {
        try { check_ring(ring); } catch (err) { return false; }
        var n = ring.length, linkable = event !== undefined;
        if (!(sig instanceof Uint8Array) || sig.length !== sig_bytes(n, linkable)) { return false; }
        try { return verify_inner(ring, msg, sig, event, n, linkable); } catch (err) { return false; }
    }
    function verify_inner(ring, msg, sig, event, n, linkable) {
        var off = 0, e, i, k, j, q, depth = 0;
        while ((1 << depth) < n) { depth++; }
        function take(len) { var s = sig.subarray(off, off + len); off += len; return s; }
        var salt = take(DIG), h2 = take(DIG), h4 = take(DIG), cs = [], idx = [];
        for (j = 0; j < n; j++) { cs.push(take(SEED)); idx.push(indices(D.CH, cs[j], TAU * B)); }
        var per = [];
        for (e = 0; e < TAU; e++) {
            var pr = { perms: [], mseeds: [], mshares: [], mpc: [], auth: [] };
            for (q = 0; q < MB; q++) { pr.perms.push(take(SEED)); }
            for (q = 0; q < MB; q++) { pr.mseeds.push(take(SEED)); }
            for (q = 0; q < NB; q++) { pr.mshares.push(take(SEED)); }
            pr.pos = rd_be32u(take(4), 0);
            if (pr.pos >= n) { return false; }
            for (q = 0; q < depth; q++) { pr.auth.push(take(DIG)); }
            for (q = 0; q < NB; q++) { pr.mpc.push(take(SEED)); }
            var nf = 5 + (linkable ? 3 : 2) * B, fv = [];
            for (q = 0; q < nf; q++) { fv.push(rd_fe(take(FB), 0)); }
            pr.dK = fv[0]; pr.dc = fv[1]; pr.dz = fv[2]; pr.alpha = fv[3]; pr.beta = fv[4];
            pr.o = fv.slice(5, 5 + (linkable ? 2 : 1) * B); pr.dI = fv.slice(5 + (linkable ? 2 : 1) * B);
            pr.Cmpc = take(DIG); pr.Cmask = take(DIG);
            per.push(pr);
        }
        var tag = null, I2 = null, idx2 = null, h1x = new Uint8Array(SEED);
        cs.forEach(function (c) { for (q = 0; q < SEED; q++) { h1x[q] ^= c[q]; } });
        if (linkable) {
            tag = take(PK_BYTES);
            if (t === 254) { for (q = 0; q < L; q++) { if (tag[q] >= t) { return false; } } }
            I2 = expand_f(D.ID, [event], L);
            idx2 = indices(D.ID, h1x, TAU * B);
        }
        var kbar = draws(concat([h2, ascii('k')]), TAU, MB), ibar = draws(concat([h4, ascii('i')]), TAU, NB);
        var h3 = H(D.H3, [h2].concat(per.map(function (x) { return Fp.vec_to_bytes(x.o); })), DIG), ch = coins(h3, linkable);
        var s1 = [salt, msg, ring_bytes(ring)].concat(linkable ? [event, tag] : []), s4 = [h3], accs = [];
        for (e = 0; e < TAU; e++) {
            var p2 = per[e], kb = kbar[e], ib = ibar[e], c = ch[e];
            var Cmpc = new Array(N), Cmask = [];
            for (k = 0; k < M; k++) { Cmask.push(new Array(N)); }
            Cmpc[ib] = p2.Cmpc; Cmask[kb][ib] = p2.Cmask;
            /* the opened masks: every share, their sum, the offsets of every member, the tree */
            var mseeds = TREE.rebuild(p2.mseeds, M, kb), pseeds = TREE.rebuild(p2.perms, M, kb), acc_k = new Array(M);
            for (k = 0; k < M; k++) {
                if (k === kb) { continue; }
                var ms = TREE.leaves(mseeds[k], N).map(mask_share);
                for (i = 0; i < N; i++) { Cmask[k][i] = H(D.CMASK, [salt, be32(e), be32(k), be32(i), Fp.vec_to_bytes(ms[i])], DIG); }
                var mk = []; for (q = 0; q < B; q++) { mk.push(sum(ms.map(function (x) { return x[q]; }))); }
                var perm = permutation(pseeds[k], n), leafs = [];
                for (var pos = 0; pos < n; pos++) {
                    var di = [];
                    for (q = 0; q < B; q++) { di.push(Fp.sub(I[idx[perm[pos]][e * B + q]], mk[q])); }
                    leafs.push(H(D.CDELTA, [salt, be32(e), be32(k), Fp.vec_to_bytes(di)], DIG));
                }
                var lv = merkle_levels(leafs, salt);
                acc_k[k] = lv[lv.length - 1][0];
            }
            acc_k[kb] = merkle_root_from(H(D.CDELTA, [salt, be32(e), be32(kb), Fp.vec_to_bytes(p2.dI)], DIG), p2.pos, p2.auth, salt);
            accs.push(H(D.ACC, [salt, be32(e)].concat(acc_k), DIG));
            /* T, over the whole ring; T' against the tag */
            var Te = [], T2 = [];
            for (q = 0; q < B; q++) {
                var sy = symbol(t, p2.o[q]);
                for (j = 0; j < n; j++) { sy -= pk_sym(ring[j], idx[j][e * B + q]); }
                Te.push(((sy % t) + t) % t);
                if (linkable) { T2.push(((symbol(t, p2.o[B + q]) - pk_sym(tag, idx2[e * B + q])) % t + t) % t); }
            }
            /* the opened parties' views, and the hidden one's from the totals */
            var sds = TREE.rebuild(p2.mpc, N, ib), mss = TREE.rebuild(p2.mshares, N, ib);
            var o2pts = linkable ? Array.from({ length: B }, function (_, qq) { return I2[idx2[e * B + qq]]; }) : null;
            var lo = 0n; for (q = 0; q < B; q++) { lo += c.lam[q] * p2.o[q]; }
            if (linkable) { for (q = 0; q < B; q++) { lo += c.lam2[q] * p2.o[B + q]; } }
            var views = new Array(N), sa = 0n, sb = 0n, sg = 0n;
            for (i = 0; i < N; i++) {
                if (i === ib) { continue; }
                Cmpc[i] = H(D.CSD, [salt, be32(e), be32(i), sds[i]], DIG);
                var sh = shares(sds[i], linkable), Ish = mask_share(mss[i]);
                Cmask[kb][i] = H(D.CMASK, [salt, be32(e), be32(kb), be32(i), Fp.vec_to_bytes(Ish)], DIG);
                if (i === 0) { sh.K = Fp.add(sh.K, p2.dK); sh.c = Fp.add(sh.c, p2.dc); for (q = 0; q < B; q++) { Ish[q] = Fp.add(Ish[q], p2.dI[q]); } }
                var v = party(sh, Ish, c, o2pts, p2.alpha, p2.beta, i === 0 ? p2.dz + lo : 0n);
                views[i] = v; sa += v.alpha; sb += v.beta; sg += v.gamma;
            }
            views[ib] = { alpha: Fp.mod(p2.alpha - sa), beta: Fp.mod(p2.beta - sb), gamma: Fp.mod(p2.alpha * p2.beta - sg) };
            s1.push(concat([].concat(Cmask.reduce(function (acc, row) { return acc.concat(row); }, []), Cmpc)), Uint8Array.from(Te), Uint8Array.from(T2), Fp.to_bytes(p2.dK), Fp.to_bytes(p2.dc));
            s4.push(Fp.vec_to_bytes([p2.alpha, p2.beta]), Fp.vec_to_bytes([].concat.apply([], views.map(function (w) { return [w.alpha, w.beta, w.gamma]; }))));
        }
        var h1 = H(D.H1, s1, DIG), ok = 1;
        for (q = 0; q < SEED; q++) { ok &= h1[q] === h1x[q] ? 1 : 0; }
        var h2b = H(D.H2, [h1].concat(accs), DIG), h4b = H(D.H4, s4, DIG);
        for (q = 0; q < DIG; q++) { ok &= (h2b[q] === h2[q] ? 1 : 0) & (h4b[q] === h4[q] ? 1 : 0); }
        return ok === 1;
    }

    return {
        NAME: 'DualRing-PRF-' + name, PK_BYTES: PK_BYTES, SK_BYTES: SK_BYTES, L: L, T: t,
        sig_bytes: function (n) { return sig_bytes(n, false); },
        linkable_sig_bytes: function (n) { return sig_bytes(n, true); },
        keygen: keygen,
        sign: function (sk, ring, msg, rng) { return sign_any(sk, ring, msg, rng); },
        verify: function (ring, msg, sig) { return verify_any(ring, msg, sig); },
        sign_linkable: function (sk, ring, msg, event, rng) { return sign_any(sk, ring, msg, rng, event); },
        verify_linkable: function (ring, msg, event, sig) { return verify_any(ring, msg, sig, event); },
        tag: function (sig) { return sig.slice(sig.length - PK_BYTES); }
    };
}
