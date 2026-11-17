/**
 * VOLE-in-the-head  -  the proof system of FAEST v3, for any statement
 *
 * A non-interactive zero-knowledge proof of knowledge of a bit string w (the
 * witness, ell bits) satisfying polynomial constraints of degree up to D over
 * GF(2^lambda), from symmetric primitives only:
 *
 *   1. COMMIT. tau GGM trees in one tree (the BAVC) give each of the ell
 *      columns a VOLE correlation q = v + u * Delta, u a random bit known to
 *      the prover, Delta known to nobody yet. The prover sends the corrections
 *      that make every tree's u the same (c), and the CRT-committed masks
 *      u * Delta of the ZK check (c_mult, commons/vole_mult.js).
 *   2. CHECK THE VOLE: a universal hash of u and of v, chall1 from the
 *      commitment.
 *   3. COMMIT TO THE WITNESS: d = w xor u, so each witness bit has a tag.
 *   4. PROVE: every constraint, evaluated on tagged values, is a polynomial
 *      in Delta whose top coefficient vanishes for a true witness; a random
 *      linear combination of them (chall2) is sent as its D lower
 *      coefficients, masked.
 *   5. OPEN: Delta is chall3 (grinding w zero bits), and all leaves but one
 *      per tree are revealed; the verifier rebuilds q and checks the
 *      combination at Delta.
 *
 * The STATEMENT is a function constraints(Rg, emit, chall2) over an abstract
 * ring: Rg.bit(i) is witness bit i, Rg.cbit / Rg.cfield constants, Rg.add /
 * mul / scale / shift arithmetic, and emit(c, d) a constraint c of degree d
 * that must vanish. The same function runs on the prover's polynomials and on
 * the verifier's values at Delta. chall2 comes after the witness commitment,
 * so a statement may derive its own random combinations from it; Rg.raw
 * gives bulk access for statements too large for value-by-value arithmetic.
 * Every witness bit is checked to be a bit first.
 *
 * TWO STAGES. The VOLE commitment (commit) can be made, and published, before
 * the witness is known; its random u then serves as a committed random string
 * (the first `free` witness bits take u as they are, with no correction).
 * The blind signatures build on that (pomfrit.js); FAEST runs both stages at
 * once (faest.js).
 *
 * PARAMETERS: lambda, tau, the grinding w, T_open (the tree opening bound),
 * ell, D, and the leaf commitment: em (FAEST's Even-Mansour sets) commits
 * leaves by a PRG, otherwise by a universal hash over GF(2^(3 lambda)).
 *
 * This is the code of faest.js, moved here; FAEST's KATs pin it.
 */

import { shake128, shake256 } from '../sha3.js';
import { aes_expand_key, aes_encrypt_block } from '../aes.js';
import { binary_field } from './binfield.js';
import { vole_mult_tables } from './vole_mult.js';
import { concat, le32, be8 } from './bytes.js';
import { bit_le as bit, bits_le as bits_at } from './bitpack.js';

var TWEAK = 0x80000000, ONE = BigInt(1), ZERO = BigInt(0);

function set_bit(b, i, v) { if (v) { b[i >> 3] |= 1 << (i & 7); } }
function parity32(v) { v ^= v >>> 16; v ^= v >>> 8; v ^= v >>> 4; return (0x6996 >>> (v & 0xf)) & 1; }

/* BigInt rows -> flat Uint32Array of nw words per row */
function word_rows(rows, nbits) {
    var nw = Math.ceil(nbits / 32), out = new Uint32Array(rows.length * nw), m = BigInt(0xffffffff), s = BigInt(32);
    for (var r = 0; r < rows.length; r++) { for (var v = rows[r], j = 0; j < nw; j++, v >>= s) { out[r * nw + j] = Number(v & m); } }
    return { w: out, nw: nw, n: rows.length };
}
/* out bit r = <row r, x> for a bit vector x given as bytes */
function matvec(T, x, xbits) {
    var xw = new Uint32Array(T.nw), out = new Uint8Array((T.n + 7) >> 3), i;
    for (i = 0; i < xbits; i++) { if (bit(x, i)) { xw[i >> 5] |= 1 << (i & 31); } }
    for (var r = 0; r < T.n; r++) {
        var acc = 0;
        for (var j = 0, o = r * T.nw; j < T.nw; j++) { acc ^= T.w[o + j] & xw[j]; }
        set_bit(out, r, parity32(acc));
    }
    return out;
}

/**
 * @param {object} o  { lambda, tau, w, T_open, ell, D, em }
 */
export function voleith(o) {
    var lambda = o.lambda, tau = o.tau, w = o.w, T_OPEN = o.T_open, ell = o.ell, D_ZK = o.D, em = !!o.em;
    var N_MASK = D_ZK - 1 + 4;                 /* the ZK mask's D - 1 elements and the VOLE hash's 4 */
    if (ell % 8) { throw new Error('voleith: ell must be a multiple of 8 (pad the witness)'); }
    /* the CRT gates read the first lambda columns of u (gate_rows), corrected only over the witness */
    if (ell < lambda) { throw new Error('voleith: ell must be at least lambda (pad the witness)'); }
    var lb = lambda / 8, F = binary_field(lambda), W = F.W, H = lambda === 128 ? shake128 : shake256;
    var nd = lambda - w, k = Math.floor(nd / tau) + 1, tau1 = nd % tau, L = tau1 * (1 << k) + (tau - tau1) * (1 << (k - 1));
    var depth = function (i) { return i < tau1 ? k : k - 1; }, D0 = depth(0);
    var ell_bytes = ell / 8, ell_hat = ell + N_MASK * D0, EHB = (ell_hat + 7) >> 3;
    var T = vole_mult_tables(lambda, tau, w), n_mult = T.F.length, nmb = (n_mult + 7) >> 3;
    var TF = word_rows(T.F, lambda), TG = word_rows(T.G, nd), TWT = word_rows(T.W_tree, nd), TWG = word_rows(T.W_gate, n_mult), TWC = word_rows(T.W_crt, nd);
    var MTREE = T.M_tree, moduli = T.moduli.map(Number);
    var COM = em ? 2 * lb : 3 * lb, DECOM = tau * COM + T_OPEN * lb;
    var F3 = em ? null : binary_field(3 * lambda);
    var HLEN = Math.ceil(N_MASK / 8), hmask = N_MASK % 8 ? (1 << (N_MASK % 8)) - 1 : 0xff;

    function hsh(parts, dom, len) { return H(concat(parts.concat([be8(dom)])), len); }

    /* PRG: AES-lambda in CTR mode, tweak added to the IV's top 32-bit word, counter in its bottom word */
    function prg(key, iv, tweak, len) {
        var ks = aes_expand_key(key), nr = key.length / 4 + 6, ctr = new Uint8Array(iv), out = new Uint8Array(Math.ceil(len / 16) * 16);
        var t = (ctr[12] | (ctr[13] << 8) | (ctr[14] << 16) | (ctr[15] << 24)) + tweak;
        ctr.set(le32(t >>> 0), 12);
        for (var q = 0; q < out.length; q += 16) {
            aes_encrypt_block(ks, nr, ctr, 0, out, q);
            for (var j = 0; j < 4 && ++ctr[j] === 256; j++) { ctr[j] = 0; }
        }
        return out.length === len ? out : out.subarray(0, len);
    }

    /* ---- the BAVC: one GGM tree over all L leaves ---- */
    function pos(i, j) {
        var half = 1 << (k - 1);
        return j < half ? L - 1 + tau * j + i : L - 1 + tau * half + tau1 * (j & (half - 1)) + i;
    }
    /* the leaf commitment: (seed, com); com = uhash * x0 + x1 over GF(2^(3 lambda)), or a plain 2-lambda PRG output for EM */
    function uhash(iv) { return em ? null : F3.from_bytes(hsh([iv], 0, 3 * lb), 0, 1); }
    function leaf_commit(key, iv, i, uh) {
        if (em) { return { sd: key.slice(), com: prg(key, iv, i + L - 1, 2 * lb) }; }
        var buf = prg(key, iv, i + L - 1, 4 * lb);
        var x0 = F3.from_bytes(concat([buf.subarray(0, lb), new Uint8Array(2 * lb)]), 0, 1), r = new Uint32Array(F3.W);
        F3.mul(r, 0, uh, 0, x0, 0);
        F3.add(r, 0, r, 0, F3.from_bytes(buf, lb, 1), 0);
        return { sd: buf.slice(0, lb), com: F3.to_bytes(r, 0, 1) };
    }
    function bavc_commit(root, iv) {
        var nodes = new Uint8Array((2 * L - 1) * lb), i, j, offset = 0, sd = new Uint8Array(L * lb), com = new Uint8Array(L * COM), hs = [], uh = uhash(iv);
        nodes.set(root);
        for (var a = 0; a < L - 1; a++) { nodes.set(prg(nodes.subarray(a * lb, (a + 1) * lb), iv, a, 2 * lb), (2 * a + 1) * lb); }
        for (i = 0; i < tau; i++) {
            var start = offset;
            for (j = 0; j < 1 << depth(i); j++, offset++) {
                var al = pos(i, j), lc = leaf_commit(nodes.subarray(al * lb, (al + 1) * lb), iv, i, uh);
                sd.set(lc.sd, offset * lb); com.set(lc.com, offset * COM);
            }
            hs.push(hsh([com.subarray(start * COM, offset * COM)], 1, 2 * lb));
        }
        return { nodes: nodes, sd: sd, com: com, h: hsh(hs, 1, 2 * lb) };
    }
    function hidden_set(idelta) {
        var s = new Uint8Array(2 * L - 1);
        for (var i = 0; i < tau; i++) { s[pos(i, idelta[i])] = 1; }
        return s;
    }
    function bavc_open(vc, idelta) {
        var s = new Uint8Array(2 * L - 1), nh = 0, i;
        for (i = 0; i < tau; i++) {
            var a = pos(i, idelta[i]);
            s[a] = 1; nh++;
            while (a > 0 && !s[(a - 1) >> 1]) { a = (a - 1) >> 1; s[a] = 1; nh++; }
        }
        if (nh - 2 * tau + 1 > T_OPEN) { return null; }
        var out = new Uint8Array(DECOM), q = 0, base = 0;
        for (i = 0; i < tau; i++) { out.set(vc.com.subarray((base + idelta[i]) * COM, (base + idelta[i] + 1) * COM), q); q += COM; base += 1 << depth(i); }
        for (i = L - 2; i >= 0; i--) {
            s[i] = s[2 * i + 1] | s[2 * i + 2];
            if (s[2 * i + 1] ^ s[2 * i + 2]) { var al = 2 * i + 1 + s[2 * i + 1]; out.set(vc.nodes.subarray(al * lb, (al + 1) * lb), q); q += lb; }
        }
        return out;
    }
    function bavc_reconstruct(decom, idelta, iv) {
        var s = hidden_set(idelta), keys = new Uint8Array((2 * L - 1) * lb), p = tau * COM, end = p + T_OPEN * lb, i, j;
        for (i = L - 2; i >= 0; i--) {
            s[i] = s[2 * i + 1] | s[2 * i + 2];
            if (s[2 * i + 1] ^ s[2 * i + 2]) {
                if (p === end) { return null; }
                var al = 2 * i + 1 + s[2 * i + 1];
                keys.set(decom.subarray(p, p + lb), al * lb); p += lb;
            }
        }
        for (; p < end; p++) { if (decom[p]) { return null; } }
        for (i = 0; i < L - 1; i++) { if (!s[i]) { keys.set(prg(keys.subarray(i * lb, (i + 1) * lb), iv, i, 2 * lb), (2 * i + 1) * lb); } }
        var seeds = [], hs = [], uh = uhash(iv);
        for (i = 0; i < tau; i++) {
            var coms = [], ts = [];
            for (j = 0; j < 1 << depth(i); j++) {
                var al2 = pos(i, j);
                if (s[al2]) { coms.push(decom.subarray(i * COM, (i + 1) * COM)); ts.push(null); }
                else { var lc = leaf_commit(keys.subarray(al2 * lb, (al2 + 1) * lb), iv, i, uh); coms.push(lc.com); ts.push(lc.sd); }
            }
            seeds.push(ts);
            hs.push(hsh(coms, 1, 2 * lb));
        }
        return { seeds: seeds, h: hsh(hs, 1, 2 * lb) };
    }

    /*
     * Seeds into VOLE rows: per tree, the leaf streams r_j (ell_hat bits);
     * row d of the tree is the sum of the r_j with bit d of j set, read off a
     * binary reduction; u is the sum of all of them. Seed slot 0 may be
     * absent (the verifier's hidden leaf, relabelled to 0).
     */
    function convert(seeds, iv, i, rows, ro) {
        var d = depth(i), n = 1 << d, cur = [], j, b;
        for (j = 0; j < n; j++) { cur.push(seeds[j] ? prg(seeds[j], iv, (i ^ TWEAK) >>> 0, EHB) : new Uint8Array(EHB)); }
        for (b = 0; b < d; b++) {
            var next = [], row = rows.subarray((ro + b) * EHB, (ro + b + 1) * EHB);
            for (j = 0; j < cur.length / 2; j++) {
                var x = cur[2 * j], y = cur[2 * j + 1], z = new Uint8Array(EHB);
                for (var q = 0; q < EHB; q++) { row[q] ^= y[q]; z[q] = x[q] ^ y[q]; }
                next.push(z);
            }
            cur = next;
        }
        return cur[0];
    }
    /* per mask m: the tree residue products from the VOLE rows, reduced modulo each tree's modulus */
    function residues(rows, m) {
        var out = new Uint8Array((nd + 7) >> 3), col = ell + m * D0, ro = 0, bi = 0;
        for (var t = 0; t < tau; t++) {
            var d = depth(t), acc = 0;
            for (var e = 0; e < d; e++) { for (var b = 0; b < d; b++) { if (bit(rows.subarray((ro + b) * EHB), col + e)) { acc ^= 1 << (b + e); } } }
            for (var hb = 2 * d - 2; hb >= d; hb--) { if ((acc >> hb) & 1) { acc ^= moduli[t] << (hb - d); } }
            for (b = 0; b < d; b++) { set_bit(out, bi + b, (acc >> b) & 1); }
            ro += d; bi += d;
        }
        return out;
    }
    /* L_e: the sum of the rows selected by G[e], first lambda bits */
    function gate_rows(rows, e) {
        var out = new Uint8Array(lb);
        for (var r = 0; r < nd; r++) {
            if ((TG.w[e * TG.nw + (r >> 5)] >>> (r & 31)) & 1) { for (var q = 0; q < lb; q++) { out[q] ^= rows[r * EHB + q]; } }
        }
        return out;
    }
    function h5(iv, e, Le) {
        var out = hsh([iv, le32(e), Le], 5, HLEN);
        out[HLEN - 1] &= hmask;
        return out;
    }
    /* the first ell columns as field elements: W_crt applied to each column of the rows */
    function columns(rows) {
        var out = new Uint32Array(ell * W), cb = new Uint8Array((nd + 7) >> 3);
        for (var l = 0; l < ell; l++) {
            cb.fill(0);
            for (var r = 0; r < nd; r++) { if (bit(rows.subarray(r * EHB), l)) { set_bit(cb, r, 1); } }
            F.from_bytes(matvec(TWC, cb, nd), 0, 1, out, l * W);
        }
        return out;
    }
    function mask_tags(res, gates) {
        var a = matvec(TWT, res, nd), b = matvec(TWG, gates, n_mult);
        for (var q = 0; q < lb; q++) { a[q] ^= b[q]; }
        return a.subarray(0, lb);
    }

    /**
     * The VOLE commitment: rows, u (ell bits), the tags V of the first ell
     * columns, the masks u_bar / v_bar, and what is sent - the tree hash
     * vc.h, the corrections c and c_mult.
     */
    function commit(root, iv) {
        var vc = bavc_commit(root, iv), rows = new Uint8Array(nd * EHB), ui = [], ro = 0, base = 0, i, j, m, e, q, b;
        for (i = 0; i < tau; i++) {
            var sds = [];
            for (j = 0; j < 1 << depth(i); j++, base++) { sds.push(vc.sd.subarray(base * lb, (base + 1) * lb)); }
            ui.push(convert(sds, iv, i, rows, ro));
            ro += depth(i);
        }
        var u = ui[0].slice(0, ell_bytes), c = new Uint8Array((tau - 1) * ell_bytes);
        for (i = 1; i < tau; i++) { for (q = 0; q < ell_bytes; q++) { c[(i - 1) * ell_bytes + q] = ui[0][q] ^ ui[i][q]; } }
        var uhi = prg(root, iv, TWEAK - 1, Math.ceil(N_MASK * w / 8)), u_bar = new Uint8Array(N_MASK * lb), c_mult = new Uint8Array(N_MASK * nmb), res = [];
        for (m = 0; m < N_MASK; m++) {
            var ulow = new Uint8Array((nd + 7) >> 3), col = ell + m * D0, bi = 0;
            for (var t = 0; t < tau; t++) { for (b = 0; b < depth(t); b++) { set_bit(ulow, bi + b, bit(ui[t], col + b)); } bi += depth(t); }
            var first = matvec(TWC, ulow, nd), hi = BigInt(bits_at(uhi, m * w, w)), prod = ZERO, mt = MTREE;
            for (b = 0; b < w; b++) { if ((hi >> BigInt(b)) & ONE) { prod ^= mt << BigInt(b); } }
            for (q = 0; q < lb; q++) { u_bar[m * lb + q] = first[q] ^ Number((prod >> BigInt(8 * q)) & BigInt(0xff)); }
            c_mult.set(matvec(TF, u_bar.subarray(m * lb, (m + 1) * lb), lambda), m * nmb);
            res.push(residues(rows, m));
        }
        var gin = [], v_bar = new Uint8Array(N_MASK * lb);
        for (m = 0; m < N_MASK; m++) { gin.push(new Uint8Array(nmb)); }
        for (e = 0; e < n_mult; e++) {
            var Le = gate_rows(rows, e), L1 = Le.slice();
            for (q = 0; q < lb; q++) { L1[q] ^= ui[0][q]; }
            var v0 = h5(iv, e, Le), v1 = h5(iv, e, L1);
            for (m = 0; m < N_MASK; m++) {
                if (bit(v0, m) ^ bit(v1, m)) { c_mult[m * nmb + (e >> 3)] ^= 1 << (e & 7); }
                set_bit(gin[m], e, bit(v0, m));
            }
        }
        for (m = 0; m < N_MASK; m++) { v_bar.set(mask_tags(res[m], gin[m]), m * lb); }
        return { vc: vc, c: c, c_mult: c_mult, u: u, V: columns(rows), u_bar: u_bar, v_bar: v_bar };
    }

    function decode(chall3) {
        var out = [], lo = 0;
        for (var i = 0; i < tau; i++) { out.push(bits_at(chall3, lo, depth(i))); lo += depth(i); }
        return out;
    }
    function reconstruct(iv, chall3, decom, c, c_mult) {
        var idelta = decode(chall3), rec = bavc_reconstruct(decom, idelta, iv);
        if (!rec) { return null; }
        var rows = new Uint8Array(nd * EHB), ro = 0, i, j, m, e, q;
        for (i = 0; i < tau; i++) {
            var n = 1 << depth(i), sd = new Array(n).fill(null);
            for (j = 0; j < n; j++) { if (j !== idelta[i]) { sd[j ^ idelta[i]] = rec.seeds[i][j]; } }
            convert(sd, iv, i, rows, ro);
            if (i > 0) {
                for (var d = 0; d < depth(i); d++) {
                    if ((idelta[i] >> d) & 1) { for (q = 0; q < ell_bytes; q++) { rows[(ro + d) * EHB + q] ^= c[(i - 1) * ell_bytes + q]; } }
                }
            }
            ro += depth(i);
        }
        var q_bar = new Uint8Array(N_MASK * lb), gin = [];
        for (m = 0; m < N_MASK; m++) { gin.push(new Uint8Array(nmb)); }
        for (e = 0; e < n_mult; e++) {
            var g = 0;
            for (var r = 0; r < nd; r++) { if ((TG.w[e * TG.nw + (r >> 5)] >>> (r & 31)) & 1) { g ^= bit(chall3, r); } }
            var he = h5(iv, e, gate_rows(rows, e));
            for (m = 0; m < N_MASK; m++) { set_bit(gin[m], e, bit(he, m) ^ (g & bit(c_mult, m * 8 * nmb + e))); }
        }
        for (m = 0; m < N_MASK; m++) { q_bar.set(mask_tags(residues(rows, m), gin[m]), m * lb); }
        var delta = F.from_bytes(matvec(TWC, chall3, nd), 0, 1);
        return { h: rec.h, Q: columns(rows), q_bar: q_bar, delta: delta };
    }

    /* the universal hash of the VOLE: 4 lambda-bit outputs over ell + D - 1 + 4 elements */
    function vole_hash(sd, X) {
        var lp = ell + D_ZK - 1, s = F.from_bytes(sd, 4 * lb, 4), s5 = F.from_bytes(concat([sd.subarray(8 * lb, 8 * lb + 8), new Uint8Array(lb - 8)]), 0, 1);
        var ys = new Uint32Array(5 * W), sx = new Uint32Array(5 * W), out = new Uint32Array(4 * W), j, i;
        sx.set(s); sx.set(s5, 4 * W);
        for (j = 0; j < 5; j++) { F.copy(ys, j * W, X, 0); }
        for (i = 1; i < lp; i++) { for (j = 0; j < 5; j++) { F.mul(ys, j * W, ys, j * W, sx, j * W); F.add(ys, j * W, ys, j * W, X, i * W); } }
        var hd = F.from_bytes(sd, 0, 4);
        for (i = 0; i < 4; i++) {
            F.mul(out, i * W, hd, i * W, ys, 0); F.add(out, i * W, out, i * W, ys, (i + 1) * W); F.add(out, i * W, out, i * W, X, (lp + i) * W);
        }
        return out;
    }

    /* prover values are polynomials in the VOLE indeterminate, as (d+1) coefficient elements; verifier values their value at Delta */
    function prover_ring(wbits, tags) {
        function mk(d) { return { d: d, c: new Uint32Array((d + 1) * W) }; }
        return {
            /*
             * For statements that compute their constraints in bulk: the
             * prover's tags and bits, and value(d, c) to wrap d + 1
             * coefficients (lowest first) as a ring value.
             */
            raw: { prover: true, F: F, W: W, tags: tags, wbits: wbits, value: function (d, c) { return { d: d, c: c }; } },
            bit: function (i) { var v = mk(1); F.copy(v.c, 0, tags, i * W); v.c[W] = bit(wbits, i); return v; },
            cbit: function (b) { var v = mk(1); v.c[W] = b; return v; },
            cfield: function (x, d) { var v = mk(d); F.copy(v.c, d * W, x, 0); return v; },
            add: function (a, b) {
                var v = mk(Math.max(a.d, b.d)), i;
                for (i = 0; i < a.c.length; i++) { v.c[i] = a.c[i]; }
                for (i = 0; i < b.c.length; i++) { v.c[i] ^= b.c[i]; }
                return v;
            },
            mul: function (a, b) {
                var v = mk(a.d + b.d), t = new Uint32Array(W);
                for (var i = 0; i <= a.d; i++) { for (var j = 0; j <= b.d; j++) { F.mul(t, 0, a.c, i * W, b.c, j * W); F.add(v.c, (i + j) * W, v.c, (i + j) * W, t, 0); } }
                return v;
            },
            scale: function (a, x) { var v = mk(a.d); for (var i = 0; i <= a.d; i++) { F.mul(v.c, i * W, a.c, i * W, x, 0); } return v; },
            shift: function (a, n) { var v = mk(a.d + n); v.c.set(a.c, n * W); return v; }
        };
    }
    function verifier_ring(keys, dpow) {
        function mk() { return { d: 0, c: new Uint32Array(W) }; }
        return {
            /* the verifier's keys, the powers of Delta, and value(d, c) to wrap a value at Delta */
            raw: { prover: false, F: F, W: W, keys: keys, dpow: dpow, value: function (d, c) { return { d: 0, c: c }; } },
            bit: function (i) { var v = mk(); F.copy(v.c, 0, keys, i * W); return v; },
            cbit: function (b) { var v = mk(); if (b) { F.copy(v.c, 0, dpow, W); } return v; },
            cfield: function (x, d) { var v = mk(); F.mul(v.c, 0, x, 0, dpow, d * W); return v; },
            add: function (a, b) { var v = mk(); F.add(v.c, 0, a.c, 0, b.c, 0); return v; },
            mul: function (a, b) { var v = mk(); F.mul(v.c, 0, a.c, 0, b.c, 0); return v; },
            scale: function (a, x) { var v = mk(); F.mul(v.c, 0, a.c, 0, x, 0); return v; },
            shift: function (a, n) { var v = mk(); F.mul(v.c, 0, a.c, 0, dpow, n * W); return v; }
        };
    }

    function challenges(chall2) {
        return { s: F.from_bytes(chall2, 2 * lb, 1), t: F.from_bytes(concat([chall2.subarray(3 * lb, 3 * lb + 8), new Uint8Array(lb - 8)]), 0, 1),
                 r0: F.from_bytes(chall2, 0, 1), r1: F.from_bytes(chall2, lb, 1) };
    }

    function zk_prover(chall2, wbits, tags, u_bar, v_bar, constraints) {
        var Rg = prover_ring(wbits, tags), ch = challenges(chall2);
        var h0 = new Uint32Array(D_ZK * W), h1 = new Uint32Array(D_ZK * W);
        function emit(v, d) {
            var p = Rg.shift(v, D_ZK - d);
            for (var i = 0; i < D_ZK; i++) {
                F.mul(h0, i * W, h0, i * W, ch.s, 0); F.add(h0, i * W, h0, i * W, p.c, i * W);
                F.mul(h1, i * W, h1, i * W, ch.t, 0); F.add(h1, i * W, h1, i * W, p.c, i * W);
            }
        }
        for (var l = 0; l < ell; l++) { var x = Rg.bit(l); emit(Rg.mul(x, Rg.add(x, Rg.cbit(1))), 2); }
        constraints(Rg, emit, chall2);
        var ub = F.from_bytes(u_bar, 0, N_MASK), vb = F.from_bytes(v_bar, 0, N_MASK), x1 = new Uint32Array(D_ZK * W), j;
        F.copy(x1, 0, vb, 0);
        for (j = 1; j < D_ZK - 1; j++) { F.add(x1, j * W, ub, (j - 1) * W, vb, j * W); }
        F.copy(x1, (D_ZK - 1) * W, ub, (D_ZK - 2) * W);
        var out = new Uint32Array(D_ZK * W), tmp = new Uint32Array(W);
        for (j = 0; j < D_ZK; j++) {
            F.mul(out, j * W, ch.r0, 0, h0, j * W); F.mul(tmp, 0, ch.r1, 0, h1, j * W);
            F.add(out, j * W, out, j * W, tmp, 0); F.add(out, j * W, out, j * W, x1, j * W);
        }
        return F.to_bytes(out, 0, D_ZK);
    }
    function zk_verifier(chall2, keys, dpow, q_bar, a1toi, constraints) {
        var Rg = verifier_ring(keys, dpow), ch = challenges(chall2);
        var h0 = new Uint32Array(W), h1 = new Uint32Array(W);
        function emit(v, d) {
            var p = Rg.shift(v, D_ZK - d);
            F.mul(h0, 0, h0, 0, ch.s, 0); F.add(h0, 0, h0, 0, p.c, 0);
            F.mul(h1, 0, h1, 0, ch.t, 0); F.add(h1, 0, h1, 0, p.c, 0);
        }
        for (var l = 0; l < ell; l++) { var x = Rg.bit(l); emit(Rg.mul(x, Rg.add(x, Rg.cbit(1))), 2); }
        constraints(Rg, emit, chall2);
        var qb = F.from_bytes(q_bar, 0, N_MASK), qs = new Uint32Array(W), tmp = new Uint32Array(W), j;
        for (j = 0; j < D_ZK - 1; j++) { F.mul(tmp, 0, qb, j * W, dpow, j * W); F.add(qs, 0, qs, 0, tmp, 0); }
        var acc = new Uint32Array(W);
        F.mul(acc, 0, ch.r0, 0, h0, 0); F.mul(tmp, 0, ch.r1, 0, h1, 0); F.add(acc, 0, acc, 0, tmp, 0); F.add(acc, 0, acc, 0, qs, 0);
        var a = F.from_bytes(a1toi, 0, D_ZK - 1);
        for (j = 1; j < D_ZK; j++) { F.mul(tmp, 0, a, (j - 1) * W, dpow, j * W); F.add(acc, 0, acc, 0, tmp, 0); }
        return F.to_bytes(acc, 0, 1);
    }

    /* ---------------- the Fiat-Shamir pipeline ---------------- */

    /*
     * The proof, in FAEST's layout: c, c_mult, u_tilde, d (the witness bits
     * from `free` on), a_1..a_{D-1}, decom, chall3, iv_pre, ctr.
     */
    function d_bytes(free) { return ell_bytes - (free >> 3); }
    function proof_bytes(free) {
        return (tau - 1) * ell_bytes + N_MASK * nmb + 4 * lb + d_bytes(free) + (D_ZK - 1) * lb + DECOM + lb + 16 + 4;
    }

    /**
     * The second stage: given the commitment V (commit(root, iv)) and the
     * statement digest mu, prove that wit satisfies the constraints. The
     * first `free` bits of wit (a multiple of 8) are V.u's own bits and are
     * not corrected; the rest are committed through d.
     */
    function prove(V, mu, iv_pre, wit, free, constraints) {
        var fb = (free || 0) >> 3, i;
        var chall1 = hsh([mu, V.vc.h, V.c, V.c_mult, iv_pre], 9, 8 * lb + 8);
        var uh = new Uint32Array((ell + N_MASK) * W);
        for (i = 0; i < ell; i++) { uh[i * W] = bit(V.u, i); }
        uh.set(F.from_bytes(V.u_bar, 0, N_MASK), ell * W);
        var vrow = new Uint32Array((ell + N_MASK) * W);
        vrow.set(V.V); vrow.set(F.from_bytes(V.v_bar, 0, N_MASK), ell * W);
        var u_tilde = F.to_bytes(vole_hash(chall1, uh), 0, 4), v_tilde = F.to_bytes(vole_hash(chall1, vrow), 0, 4);
        var d = new Uint8Array(ell_bytes - fb);
        for (i = 0; i < d.length; i++) { d[i] = wit[fb + i] ^ V.u[fb + i]; }
        var chall2 = hsh([chall1, u_tilde, v_tilde, d], 10, 3 * lb + 8);
        var a = zk_prover(chall2, wit, V.V, V.u_bar, V.v_bar, constraints), pre = concat([chall2, a]);
        for (var ctr = 0; ctr < 0x100000000; ctr++) {
            var chall3 = hsh([pre, le32(ctr)], 11, lb);
            var ok = true;
            for (i = nd; i < lambda; i++) { if (bit(chall3, i)) { ok = false; break; } }
            if (!ok) { continue; }
            var decom = bavc_open(V.vc, decode(chall3));
            if (decom) { return concat([V.c, V.c_mult, u_tilde, d, a.subarray(lb), decom, chall3, iv_pre, le32(ctr)]); }
        }
        throw new Error('voleith: no counter gives a valid challenge');
    }

    /** The parts of a proof, by name - or null when its length is wrong. */
    function parse(proof, free) {
        if (!(proof instanceof Uint8Array) || proof.length !== proof_bytes(free || 0)) { return null; }
        var q = 0;
        function take(n) { var s = proof.subarray(q, q + n); q += n; return s; }
        return { c: take((tau - 1) * ell_bytes), c_mult: take(N_MASK * nmb), u_tilde: take(4 * lb), d: take(d_bytes(free || 0)),
                 a1toi: take((D_ZK - 1) * lb), decom: take(DECOM), chall3: take(lb), iv_pre: take(16), ctr: take(4) };
    }

    /**
     * Verify. iv_of(iv_pre) gives the IV the prover committed under (the
     * caller binds it); mu the statement digest. With `free` > 0 the first
     * free bits are tagged by the VOLE alone, and `on_q` (if given) receives
     * the reconstructed commitment's hash, so a caller can bind it.
     */
    function verify(proof, mu, iv_of, free, constraints) {
        var p = parse(proof, free), i;
        if (!p) { return false; }
        for (i = nd; i < lambda; i++) { if (bit(p.chall3, i)) { return false; } }
        var V = reconstruct(iv_of(p.iv_pre), p.chall3, p.decom, p.c, p.c_mult);
        if (!V) { return false; }
        var chall1 = hsh([typeof mu === 'function' ? mu(V.h, p) : mu, V.h, p.c, p.c_mult, p.iv_pre], 9, 8 * lb + 8);
        var qrow = new Uint32Array((ell + N_MASK) * W);
        qrow.set(V.Q); qrow.set(F.from_bytes(V.q_bar, 0, N_MASK), ell * W);
        var qt = vole_hash(chall1, qrow), ut = F.from_bytes(p.u_tilde, 0, 4), tmp = new Uint32Array(W);
        for (i = 0; i < 4; i++) { F.mul(tmp, 0, ut, i * W, V.delta, 0); F.add(qt, i * W, qt, i * W, tmp, 0); }
        var chall2 = hsh([chall1, p.u_tilde, F.to_bytes(qt, 0, 4), p.d], 10, 3 * lb + 8);
        var dpow = new Uint32Array((D_ZK + 1) * W);
        dpow[0] = 1;
        for (i = 1; i <= D_ZK; i++) { F.mul(dpow, i * W, dpow, (i - 1) * W, V.delta, 0); }
        var keys = new Uint32Array(ell * W), fbits = free || 0;
        for (i = 0; i < ell; i++) {
            F.copy(keys, i * W, V.Q, i * W);
            if (i >= fbits && bit(p.d, i - fbits)) { F.add(keys, i * W, keys, i * W, V.delta, 0); }
        }
        var a0 = zk_verifier(chall2, keys, dpow, V.q_bar, p.a1toi, constraints);
        var want = hsh([chall2, a0, p.a1toi, p.ctr], 11, lb), diff = 0;
        for (i = 0; i < lb; i++) { diff |= want[i] ^ p.chall3[i]; }
        return diff === 0;
    }

    return {
        lambda: lambda, lb: lb, ell: ell, ell_bytes: ell_bytes, D: D_ZK, F: F, W: W,
        hsh: hsh, prg: prg,
        commit: commit,
        prove: prove,
        verify: verify,
        parse: parse,
        proof_bytes: proof_bytes
    };
}

/* ---------------- OR over public values: a committed one-hot index ---------------- */

/*
 * A statement "v = values[i] for some i < n", i secret: the prover commits
 * to i as dim one-hot vectors of m entries (m^dim >= n), the last entry of
 * each implied by the others - dim (m - 1) witness bits - and to v. The
 * selector of i is the product of one entry from each vector (degree dim),
 * so v = sum_i sel_i values[i] is one constraint of degree dim per bit of v,
 * and the vectors are well formed when sum_k b_k = 1 (built in) and
 * (sum_k e_k b_k - e_k) b_k = 0 for every k, e_k the field element k + 1
 * (the 1-hot-vector check of Chiang et al., ePrint 2025/113, section 4.1.3).
 *
 * one_hot_shape(n, max_dim) -> {n, dim, m, bits}   the fewest witness bits
 * one_hot_witness(shape, i) -> Uint8Array of shape.bits 0/1 values
 * one_hot_select(Rg, emit, F, shape, off, values, voff, nbits)
 *     values: n byte strings; constrains witness bits voff.. (nbits, little-endian
 *     within bytes) to equal values[i], the index committed at witness bit off
 */
export function one_hot_shape(n, max_dim) {
    if (!(n >= 2)) { throw new Error('voleith: a selection needs at least two values'); }
    var best = null;
    for (var dim = 1; dim <= max_dim; dim++) {
        var m = Math.ceil(Math.pow(n, 1 / dim) - 1e-9);
        while (Math.pow(m, dim) < n) { m++; }
        while (m > 2 && Math.pow(m - 1, dim) >= n) { m--; }
        var bits = dim * (m - 1);
        if (!best || bits < best.bits) { best = { n: n, dim: dim, m: m, bits: bits }; }
    }
    return best;
}

function digits(shape, i) { var d = []; for (var j = 0; j < shape.dim; j++) { d.push(i % shape.m); i = Math.floor(i / shape.m); } return d; }

export function one_hot_witness(shape, i) {
    if (!(i >= 0 && i < shape.n)) { throw new Error('voleith: index out of range'); }
    var out = new Uint8Array(shape.bits), d = digits(shape, i);
    for (var j = 0; j < shape.dim; j++) { if (d[j] < shape.m - 1) { out[j * (shape.m - 1) + d[j]] = 1; } }
    return out;
}

export function one_hot_select(Rg, emit, F, shape, off, values, voff, nbits) {
    var dim = shape.dim, m = shape.m, j, k, i, p;
    function field_int(x) { var b = new Uint8Array(F.BYTES); b[0] = x & 0xff; b[1] = x >> 8; return F.from_bytes(b, 0, 1); }
    var one = field_int(1), rows = [];
    for (j = 0; j < dim; j++) {
        var row = [], last = Rg.cbit(1);
        for (k = 0; k < m - 1; k++) { var x = Rg.bit(off + j * (m - 1) + k); row.push(x); last = Rg.add(last, x); }
        row.push(last);
        rows.push(row);
        /* well formed: at most one entry set (their sum is 1 by construction) */
        var E = [], sigma = null;
        for (k = 0; k < m; k++) { E.push(field_int(k + 1)); var t = Rg.scale(row[k], E[k]); sigma = sigma ? Rg.add(sigma, t) : t; }
        for (k = 0; k < m; k++) { emit(Rg.mul(Rg.add(sigma, Rg.cfield(E[k], 1)), row[k]), 2); }
    }
    /* the selectors; exactly one of the first n is set */
    var sel = [], total = null;
    for (i = 0; i < shape.n; i++) {
        var d = digits(shape, i), s = rows[0][d[0]];
        for (j = 1; j < dim; j++) { s = Rg.mul(s, rows[j][d[j]]); }
        sel.push(s);
        total = total ? Rg.add(total, s) : s;
    }
    emit(Rg.add(total, Rg.cfield(one, dim)), dim);
    /* v = sum_i sel_i values[i] */
    var acc = [];
    for (p = 0; p < nbits; p++) { var vb = Rg.bit(voff + p); acc.push(dim > 1 ? Rg.shift(vb, dim - 1) : vb); }
    for (i = 0; i < shape.n; i++) {
        var val = values[i];
        for (p = 0; p < nbits; p++) { if ((val[p >> 3] >> (p & 7)) & 1) { acc[p] = Rg.add(acc[p], sel[i]); } }
    }
    for (p = 0; p < nbits; p++) { emit(acc[p], dim); }
}
