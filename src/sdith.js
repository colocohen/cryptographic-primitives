/**
 * SDitH  -  the round-3 submission to NIST's additional signatures (the
 * VOLE-in-the-head variant, August 2026)
 *
 * A proof of knowledge of a regular syndrome-decoding solution: a vector x of
 * weight w over GF(2) with one 1 in each of w blocks of n/w positions, such
 * that H x = y for a random binary H (the public key is the seed of H and y).
 * The prover commits to the solution, encoded per block as the controls of a
 * tree of multiplexers, with VOLE correlations from tau GGM trees of 2^kappa
 * leaves (all in one tree), proves in GF(2^lambda) that every multiplexer
 * tree picks one column of H whose sum is y, and opens all leaves but one per
 * repetition, chosen by Fiat-Shamir with w bits of grinding.
 *
 * THE PARAMETER SETS: level 1, 3 or 5 (lambda = 128, 192, 256), "short"
 * (kappa = 11) or "fast" (kappa = 7), and the grinding done with SHAKE or,
 * in the _cipherpow sets, with the block cipher (whose fast sets at levels 1
 * and 3 take their own tau, Topen and w). The block cipher is AES-128 at
 * level 1 and Rijndael-256 above (keyed with the seed padded with zeros at
 * level 3, and truncated to 192 bits where a seed is produced); the hash is
 * SHAKE128 at level 1 and SHAKE256 above.
 *
 * KEYS: pk = seed_H || y; sk = seed_H || y || the encoded solution. keygen
 * takes seed_H then the secret seed (lambda/8 bytes each); sign takes the
 * salt then the GGM root seed.
 */

import { shake128, shake256 } from './sha3.js';
import { aes_expand_key, aes_encrypt_block } from './aes.js';
import { rijndael_key, rijndael_encrypt } from './commons/rijndael.js';
import { binary_field } from './commons/binfield.js';
import { concat, le32, be8, secure_random } from './commons/bytes.js';
import { bit_le as bit, bits_le as bits_at } from './commons/bitpack.js';
import { lazy_scheme } from './commons/lazy_scheme.js';

/* [lambda, kappa, tau, Topen, w (grinding), rsd w, rsd n, mux arities, cipher grinding] */
var SETS = {
    cat1_short: [128, 11, 11, 109, 9, 56, 10360, [4, 4, 4, 3], false],
    cat3_short: [192, 11, 17, 169, 7, 73, 18396, [4, 4, 4, 4], false],
    cat5_short: [256, 11, 23, 228, 5, 104, 19864, [4, 4, 4, 3], false],
    cat1_fast: [128, 7, 18, 107, 4, 56, 10360, [4, 4, 4, 3], false],
    cat3_fast: [192, 7, 27, 161, 5, 73, 18396, [4, 4, 4, 4], false],
    cat5_fast: [256, 7, 36, 216, 6, 104, 19864, [4, 4, 4, 3], false],
    cat1_short_cipherpow: [128, 11, 11, 109, 9, 56, 10360, [4, 4, 4, 3], true],
    cat3_short_cipherpow: [192, 11, 17, 169, 7, 73, 18396, [4, 4, 4, 4], true],
    cat5_short_cipherpow: [256, 11, 23, 228, 5, 104, 19864, [4, 4, 4, 3], true],
    cat1_fast_cipherpow: [128, 7, 17, 101, 11, 56, 10360, [4, 4, 4, 3], true],
    cat3_fast_cipherpow: [192, 7, 26, 155, 12, 73, 18396, [4, 4, 4, 4], true],
    cat5_fast_cipherpow: [256, 7, 36, 216, 6, 104, 19864, [4, 4, 4, 3], true]
};
var H_BAVC = 1, H_AUX = 2, H_LINES = 3, H_PIOP = 4, POW_H0 = 5, POW_H1 = 6;

function xor_into(dst, doff, src, soff, n) { for (var i = 0; i < n; i++) { dst[doff + i] ^= src[soff + i]; } }

function build(name) {
    var P = SETS[name], lambda = P[0], kappa = P[1], tau = P[2], TOPEN = P[3], pow_w = P[4];
    var rsd_w = P[5], rsd_n = P[6], AR = P[7], cipher_pow = P[8];
    var lb = lambda / 8, F = binary_field(lambda), W = F.W, H = lambda === 128 ? shake128 : shake256;
    var npw = rsd_n / rsd_w, codim = (Math.ceil(rsd_w * Math.log2(npw) + 6.64385618977) + 7) & ~7;
    var codim_bytes = codim / 8, limbs = Math.ceil(codim / lambda), depth = AR.length, D = Math.max(depth, 2);
    var mux_in = 0, a;
    for (a = 0; a < depth; a++) { mux_in += AR[a] - 1; }
    var n_in = mux_in * rsd_w, n_cchk = lambda + 16, n_cz = lambda * (D - 1);
    var in_pad = (n_in + 7) & ~7, L = (n_in + n_cchk + n_cz + 7) & ~7, Lbyte = L / 8, Lslice = (Lbyte + 31) & ~31;
    var off_in = n_cchk, off_cz = n_cchk + in_pad, ncols = L - n_cchk, kt = kappa * tau, nleaves = 1 << kappa, TL = tau << kappa;
    var ENC_BYTES = (n_in + 7) >> 3, PK = lb + codim_bytes, SK = PK + ENC_BYTES;
    var SIG = lb + TOPEN * lb + tau * 2 * lb + (tau - 1) * Lbyte + n_cchk / 8 + ENC_BYTES + (D - 1) * lb + 2 * lb + 4;
    /* the block cipher: 16-byte AES blocks at level 1, 32-byte Rijndael-256 blocks above */
    var B = lambda === 128 ? 16 : 32, KP = new Uint8Array(32);
    var key = lambda === 128 ? aes_expand_key : function (k) {
        if (k.length === 32) { return rijndael_key(k, 8); }
        KP.fill(0); KP.set(k); return rijndael_key(KP, 8);
    };
    var enc = lambda === 128 ? function (ks, s, so, o, oo) { aes_encrypt_block(ks, 10, s, so, o, oo); } : rijndael_encrypt;
    var CB = new Uint8Array(B), OB = new Uint8Array(2 * B);
    /* CTR from base (incremented in its low 64 bits, little-endian), n blocks into out */
    function ctr(ks, base, n, out, oo) {
        CB.set(base);
        for (var i = 0; i < n; i++) {
            enc(ks, CB, 0, out, oo + i * B);
            for (var j = 0; j < 8 && ++CB[j] === 256; j++) { CB[j] = 0; }
        }
    }
    function xof(parts, len) { return H(concat(parts), len); }

    /* the salt with its low 24 bits cleared for the tweak, and a 1- or 2-bit prefix on top */
    function masked(salt, ggm) {
        var s = new Uint8Array(B);
        s.set(salt); s[0] = s[1] = s[2] = 0;
        if (cipher_pow) { s[lb - 1] = (s[lb - 1] & 0x3f) | (ggm ? 0x40 : 0); }
        else { s[lb - 1] = ggm ? s[lb - 1] | 0x80 : s[lb - 1] & 0x7f; }
        return s;
    }
    function tweaked(s, t) { var b = new Uint8Array(s); b[0] |= t & 0xff; b[1] |= (t >>> 8) & 0xff; b[2] |= (t >>> 16) & 0xff; return b; }
    /* two lambda-bit outputs keyed by ks, tweaks t and t+1: the GGM children, or a leaf commitment */
    function two(ks, s, t, out, oo) {
        ctr(ks, tweaked(s, t), 2, OB, 0);
        out.set(OB.subarray(0, lb), oo); out.set(OB.subarray(B, B + lb), oo + lb);
    }

    /* ---- the GGM tree over tau * 2^kappa leaves (heap order, leaf l of repetition i at TL + l*tau + i) ---- */
    function expand_tree(seeds, have, gs) {
        for (var k = 1; k < TL; k++) {
            if (!have || have[k]) {
                two(key(seeds.subarray(k * lb, (k + 1) * lb)), gs, 2 * k, seeds, 2 * k * lb);
                if (have) { have[2 * k] = have[2 * k + 1] = 1; }
            }
        }
    }
    function hidden_leaves(delta0) {
        var h = [];
        for (var i = 0; i < tau; i++) { h.push(bits_at(delta0, i * kappa, kappa) * tau + i + TL); }
        return h.sort(function (x, y) { return x - y; });
    }
    /* the nodes whose seeds open every leaf but the hidden ones, in decreasing order */
    function siblings(hidden) {
        var q = hidden.slice().reverse(), s = 0, out = [];
        while (q.length - s >= 2) {
            var f = q[s];
            if ((f ^ q[s + 1]) === 1) { s += 2; } else { out.push(f ^ 1); s += 1; }
            q.push(f >>> 1);
        }
        for (var n = q[s]; n !== 1; n >>>= 1) { out.push(n ^ 1); }
        return out;
    }

    /*
     * The leaves into VOLE correlations: per repetition, u = sum of the leaf
     * streams and row j of v the sum of those whose Gray-coded position has
     * bit j set (accumulated as the positions are walked in Gray order). The
     * verifier passes the hidden leaves' commitments and its corrections s;
     * a hidden leaf contributes s instead of its stream.
     */
    function leaves(seeds, salt, gs, vs, hidden, hcom, s) {
        var u = s || new Uint8Array(tau * Lslice), v = new Uint8Array(tau * kappa * Lslice), r = new Uint8Array(Lslice);
        var cm = [], hp = 0, i, l, node;
        for (i = 0; i < tau; i++) { cm.push(new Uint8Array(nleaves * 2 * lb)); }
        var vsi = [];
        for (i = 0; i < tau; i++) { vsi.push(tweaked(vs, i << 16)); }
        for (l = 0; l < nleaves; l++) {
            var loc = l + 1 < nleaves ? 31 - Math.clz32((l + 1) & -(l + 1)) : kappa - 1;
            for (i = 0; i < tau; i++) {
                node = TL + l * tau + i;
                var vo = (i * kappa + loc) * Lslice, uo = i * Lslice;
                if (hidden && hp < tau && node === hidden[hp]) {
                    cm[i].set(hcom.subarray(hp * 2 * lb, (hp + 1) * 2 * lb), l * 2 * lb);
                    xor_into(v, vo, u, uo, Lslice);
                    hp++;
                    continue;
                }
                var ks = key(seeds.subarray(node * lb, (node + 1) * lb));
                two(ks, gs, 2 * node, cm[i], l * 2 * lb);
                ctr(ks, vsi[i], Lslice / B, r, 0);
                xor_into(u, uo, r, 0, Lslice);
                xor_into(v, vo, u, uo, Lslice);
            }
        }
        var subs = [];
        for (i = 0; i < tau; i++) { subs.push(xof([be8(H_BAVC), cm[i]], 2 * lb)); }
        return { u: u, v: v, hash: xof([be8(H_BAVC), salt].concat(subs), 2 * lb) };
    }
    /* lambda rows of L bits (rows past kappa*tau are zero) into L field elements */
    function transpose(v) {
        var out = new Uint32Array(L * W);
        for (var rr = 0; rr < kt; rr++) {
            var ro = rr * Lslice, wo = rr >> 5, m = 1 << (rr & 31);
            for (var l = 0; l < L; l++) { if ((v[ro + (l >> 3)] >> (l & 7)) & 1) { out[l * W + wo] |= m; } }
        }
        return out;
    }
    /* the consistency-check matrix and M * x[n_cchk..] + x[..n_cchk], for elements */
    function cchk_matrix(hash_aux) { return xof([hash_aux], n_cchk * ncols / 8); }
    function cchk_elems(M, X) {
        var out = new Uint32Array(n_cchk * W).fill(0), i, j, k;
        for (i = 0; i < n_cchk; i++) {
            for (k = 0; k < W; k++) { out[i * W + k] = X[i * W + k]; }
            for (j = 0; j < ncols; j++) {
                if (bit(M, i * ncols + j)) { for (k = 0; k < W; k++) { out[i * W + k] ^= X[(n_cchk + j) * W + k]; } }
            }
        }
        return out;
    }

    /* ---- the RSD instance ---- */
    function matrix_rows(seed_h) {
        var ks = key(seed_h), bpr = Math.ceil(codim / (8 * B)), row = new Uint8Array(bpr * B), base = new Uint8Array(B);
        var keep = codim & (8 * B - 1);
        return function (r) {
            base.fill(0); var c = r * bpr;
            for (var j = 0; j < 6; j++) { base[j] = c & 0xff; c = Math.floor(c / 256); }
            ctr(ks, base, bpr, row, 0);
            if (keep) {
                for (var q = keep; q < 8 * B; q++) { row[(bpr - 1) * B + (q >> 3)] &= ~(1 << (q & 7)); }
            }
            return row;
        };
    }
    /* chall_a . H (n elements) and chall_a . y */
    function times_chall(seed_h, y, chall) {
        var out = new Uint32Array(rsd_n * W), limb = new Uint32Array(W), t, r, j;
        for (t = 0; t < codim; t++) { F.mul_xpow(out, t * W, chall, Math.floor(t / lambda) * W, t % lambda); }
        var rows = matrix_rows(seed_h), buf = new Uint8Array(limbs * lb), ay = new Uint32Array(W);
        /* dst[o] += sum_j limb_j(src) chall_j */
        function dot(src, dst, o) {
            for (j = 0; j < limbs; j++) {
                F.from_bytes(src, j * lb, 1, limb, 0);
                if (!F.is_zero(limb, 0)) { F.mul(limb, 0, limb, 0, chall, j * W); F.add(dst, o, dst, o, limb, 0); }
            }
        }
        for (r = 0; r < rsd_n - codim; r++) { buf.set(rows(r).subarray(0, limbs * lb)); dot(buf, out, (codim + r) * W); }
        buf.fill(0); buf.set(y.subarray(0, codim_bytes));
        dot(buf, ay, 0);
        return { aH: out, ay: ay };
    }
    /* seed: seed_H || the secret seed, SEED_BYTES; omitted or null draws fresh ones from the platform */
    function keygen(seed) {
        if (seed == null) { seed = secure_random(2 * lb); }
        if (!(seed instanceof Uint8Array) || seed.length !== 2 * lb) { throw new Error('sdith: keygen takes ' + 2 * lb + ' bytes (seed_H, then the secret seed)'); }
        var seed_h = seed.slice(0, lb), ks = key(seed.subarray(lb)), stream = new Uint8Array(4 * B), sp = stream.length, blk = 0;
        var base = new Uint8Array(B), max = 0xffffffff - (0xffffffff % npw), sol = [], i, j;
        function next() {
            if (sp === stream.length) {
                base.fill(0); base[0] = blk & 0xff; base[1] = (blk >>> 8) & 0xff; base[2] = (blk >>> 16) & 0xff; base[3] = blk >>> 24;
                ctr(ks, base, 4, stream, 0); blk += 4; sp = 0;
            }
            var v = (stream[sp] | (stream[sp + 1] << 8) | (stream[sp + 2] << 16) | (stream[sp + 3] << 24)) >>> 0;
            sp += 4;
            return v;
        }
        for (i = 0; i < rsd_w; i++) { var p; do { p = next(); } while (p >= max); sol.push(p % npw); }
        var y = new Uint8Array(codim_bytes), rows = matrix_rows(seed_h);
        for (i = 0; i < rsd_w; i++) {
            var idx = i * npw + sol[i];
            if (idx < codim) { y[idx >> 3] ^= 1 << (idx & 7); } else { xor_into(y, 0, rows(idx - codim), 0, codim_bytes); }
        }
        var enc_sol = new Uint8Array(ENC_BYTES), pos = 0;
        for (i = 0; i < rsd_w; i++) {
            for (var si = sol[i], d = 0; d < depth; d++) {
                var sij = si % AR[d];
                si = (si - sij) / AR[d];
                if (sij) { j = pos + sij - 1; enc_sol[j >> 3] |= 1 << (j & 7); }
                pos += AR[d] - 1;
            }
        }
        var pk = concat([seed_h, y]);
        return { pk: pk, sk: concat([pk, enc_sol]) };
    }

    /* ---- the multiplexer circuit, on polynomials (prover) and on evaluations (verifier) ---- */
    var X32 = new Uint32Array(W);
    X32[1] = 1;
    function pmul(a, da, b, db) {
        var r = new Uint32Array((da + db + 1) * W), t = new Uint32Array(W);
        for (var i = 0; i <= da; i++) {
            for (var j = 0; j <= db; j++) { F.mul(t, 0, a, i * W, b, j * W); F.add(r, (i + j) * W, r, (i + j) * W, t, 0); }
        }
        return r;
    }
    function padd(r, a) { for (var k = 0; k < a.length; k++) { r[k] ^= a[k]; } }
    /* sum_i x^(s i) c_i, for n degree-1 controls (prover: two coefficients each) or values */
    function echelon(c, co, n, s, deg) {
        var r = new Uint32Array((deg + 1) * W), t = new Uint32Array(W);
        for (var i = 0; i < n; i++) {
            for (var q = 0; q <= deg; q++) { F.mul_xpow(t, 0, c, co + (i * (deg + 1) + q) * W, s * i); F.add(r, q * W, r, q * W, t, 0); }
        }
        return r;
    }
    /* coeff * ((sum x^i c_i)(sum x^(k i) c_i) + sum x^((k+1) i) c_i), over the k controls of a level */
    function unitary(c, co, k, coeff, deg) {
        var r = pmul(echelon(c, co, k, 1, deg), deg, echelon(c, co, k - 1, k, deg), deg);
        padd(r, echelon(c, co, k - 1, k + 1, deg));
        return pmul(r, 2 * deg, coeff, 0);
    }
    /*
     * One tree: npw challenge values in, one value out; each level picks one of
     * `arity` inputs per mux with arity-1 one-hot controls (none set: input 0).
     * deg is 1 for the prover's degree-1 controls, 0 for the verifier's values.
     */
    function mux_tree(c, co, a, ao, chall_c, cco, deg) {
        var res = new Uint32Array((deg ? D + 1 : 1) * W), uc = null, nin = npw, cur = a, curo = ao, d, j, i, q;
        var ONE = new Uint32Array(W);
        ONE[0] = 1;
        for (d = 0; d < depth; d++) {
            var ar = AR[d];
            if (ar > 2) {
                if (!uc) { uc = chall_c.slice(cco, cco + W); } else { F.mul(uc, 0, uc, 0, X32, 0); }
                padd(res, unitary(c, co, ar - 1, uc, deg));
            }
            var nout = Math.ceil(nin / ar), din = deg * d, dout = deg * (d + 1), out = new Uint32Array(nout * (dout + 1) * W);
            for (j = 0; j < nout; j++) {
                var arity = j + 1 < nout ? ar : nin - j * ar;
                /* ctrl0 = (1 + sum c_i, c_0, ...), constant terms; ctrl1 likewise for the x terms */
                var c0 = new Uint32Array(arity * W), c1 = new Uint32Array(arity * W);
                c0[0] = 1;
                for (i = 1; i < arity; i++) {
                    F.copy(c0, i * W, c, co + (i - 1) * (deg + 1) * W);
                    F.add(c0, 0, c0, 0, c0, i * W);
                    if (deg) { F.copy(c1, i * W, c, co + ((i - 1) * 2 + 1) * W); F.add(c1, 0, c1, 0, c1, i * W); }
                }
                var t = new Uint32Array(W), oo = j * (dout + 1) * W;
                for (i = 0; i < arity; i++) {
                    var io = curo + (j * ar + i) * (din + 1) * W;
                    for (q = 0; q <= din; q++) {
                        F.mul(t, 0, c0, i * W, cur, io + q * W); F.add(out, oo + q * W, out, oo + q * W, t, 0);
                        if (deg) { F.mul(t, 0, c1, i * W, cur, io + q * W); F.add(out, oo + (q + 1) * W, out, oo + (q + 1) * W, t, 0); }
                    }
                }
            }
            if (d === depth - 1) { padd(res.subarray(0, (dout + 1) * W), out.subarray(0, (dout + 1) * W)); }
            co += (ar - 1) * (deg + 1) * W;
            nin = nout; cur = out; curo = 0;
        }
        return res;
    }

    /* ---- grinding: delta0 (kappa*tau bits) from h_piop and a 32-bit counter ---- */
    function pow_init(h_piop) {
        var DB = (kt + 7) >> 3;
        if (!cipher_pow) {
            var NB = (kt + pow_w + 7) >> 3;
            return function (c) {
                var o = xof([h_piop, le32(c)], NB);
                return bits_at(o, kt, pow_w) === 0 ? o.slice(0, DB) : null;
            };
        }
        var x = xof([be8(POW_H0), h_piop], 4 * B), p0 = x.slice(0, B), p1 = x.slice(B, 2 * B);
        var k0 = x.slice(2 * B, 3 * B), k1 = x.slice(3 * B, 4 * B), c0 = new Uint8Array(B), c1 = new Uint8Array(B), mask = (1 << (pow_w - 1)) - 1;
        p0[B - 1] |= 0x80; p1[B - 1] |= 0x80; k0[0] &= 0xfe; k1[0] |= 1;
        var ks0 = key(k0), ks1 = key(k1);
        return function (c) {
            var cb = le32(c);
            p0.set(cb); p1.set(cb);
            enc(ks0, p0, 0, c0, 0); enc(ks1, p1, 0, c1, 0);
            if ((((c0[0] ^ c1[0]) | ((c0[1] ^ c1[1]) << 8) | ((c0[2] ^ c1[2]) << 16)) & mask) !== 0) { return null; }
            return xof([be8(POW_H1), h_piop, cb, c0, c1], DB);
        };
    }
    function delta1_of(delta0) {
        var d1 = new Uint32Array(W);
        for (var i = 0; i < tau; i++) {
            var p = bits_at(delta0, i * kappa, kappa), g = p ^ (p >> 1);
            for (var j = 0; j < kappa; j++) { if ((g >> j) & 1) { var b = i * kappa + j; d1[b >> 5] |= 1 << (b & 31); } }
        }
        return d1;
    }
    function bits_zero(b, n) { for (var i = 0; i < n; i++) { if (bit(b, i)) { return false; } } return true; }

    /* rnd: salt || root seed, RND_BYTES; omitted or null draws fresh ones from the platform */
    function sign(sk, msg, rnd) {
        if (!(sk instanceof Uint8Array) || sk.length !== SK) { throw new Error('sdith: secret key must be ' + SK + ' bytes'); }
        if (rnd == null) { rnd = secure_random(2 * lb); }
        if (!(rnd instanceof Uint8Array) || rnd.length !== 2 * lb) { throw new Error('sdith: sign takes ' + 2 * lb + ' bytes of randomness (salt, root seed)'); }
        var seed_h = sk.subarray(0, lb), y = sk.subarray(lb, PK), enc_sol = sk.subarray(PK), salt = rnd.slice(0, lb), i, j, k;
        var gs = masked(salt, true), vs = masked(salt, false), seeds = new Uint8Array(2 * TL * lb);
        seeds.set(rnd.subarray(lb), lb);
        expand_tree(seeds, null, gs);
        var V = leaves(seeds, salt, gs, vs, null, null, null), u = V.u, Vv = transpose(V.v);
        var corr = new Uint8Array((tau - 1) * Lbyte);
        for (i = 1; i < tau; i++) { for (j = 0; j < Lbyte; j++) { corr[(i - 1) * Lbyte + j] = u[i * Lslice + j] ^ u[j]; } }
        var hash_aux = xof([be8(H_AUX), V.hash, corr], 2 * lb), M = cchk_matrix(hash_aux);
        var cchk_u = new Uint8Array(n_cchk / 8);
        for (i = 0; i < n_cchk; i++) {
            var bb = bit(u, i);
            for (j = 0; j < ncols; j++) { bb ^= bit(M, i * ncols + j) & bit(u, n_cchk + j); }
            cchk_u[i >> 3] |= bb << (i & 7);
        }
        var cchk_v = F.to_bytes(cchk_elems(M, Vv), 0, n_cchk);
        /* the masks of the check-zero polynomial: D-1 degree-1 pairs into one of degree D-1, mirrored */
        var f = new Uint32Array(2 * (D - 1) * W), t = new Uint32Array(W);
        for (i = 0; i < D - 1; i++) {
            for (j = 0; j < lambda; j++) { F.mul_xpow(t, 0, Vv, (off_cz + i * lambda + j) * W, j); F.add(f, 2 * i * W, f, 2 * i * W, t, 0); }
            F.from_bytes(u.slice((off_cz + i * lambda) >> 3, ((off_cz + i * lambda) >> 3) + lb), 0, 1, f, (2 * i + 1) * W);
        }
        var g = new Uint32Array(D * W), rvp = new Uint32Array(D * W);
        F.copy(g, 0, f, 0);
        for (i = 1; i < D - 1; i++) { F.add(g, i * W, f, 2 * i * W, f, (2 * i - 1) * W); }
        F.copy(g, (D - 1) * W, f, (2 * D - 3) * W);
        for (i = 0; i < D; i++) { F.copy(rvp, i * W, g, (D - 1 - i) * W); }
        /* the committed inputs: published as bit ^ u, with x term v */
        var in_pub = new Uint8Array(ENC_BYTES), inputs = new Uint32Array(n_in * 2 * W);
        for (i = 0; i < n_in; i++) {
            var sb = bit(enc_sol, i);
            in_pub[i >> 3] |= (sb ^ bit(u, off_in + i)) << (i & 7);
            inputs[2 * i * W] = sb;
            F.copy(inputs, (2 * i + 1) * W, Vv, (off_in + i) * W);
        }
        var hash_lines = xof([be8(H_LINES), hash_aux, cchk_u, cchk_v, in_pub], 2 * lb);
        var ch = xof([hash_lines], lb * (limbs + rsd_w)), chall_a = F.from_bytes(ch, 0, limbs), chall_u = F.from_bytes(ch, lb * limbs, rsd_w);
        var A = times_chall(seed_h, y, chall_a), res = new Uint32Array((D + 1) * W);
        F.copy(res, 0, A.ay, 0);
        for (i = 0; i < rsd_w; i++) { padd(res, mux_tree(inputs, i * mux_in * 2 * W, A.aH, i * npw * W, chall_u, i * W, 1)); }
        var cz = new Uint32Array(D * W);
        for (i = 0; i < D; i++) { F.add(cz, i * W, rvp, i * W, res, (i + 1) * W); }
        var cz_bytes = F.to_bytes(cz, 0, D), h_piop = xof([be8(H_PIOP), seed_h, y, hash_lines, cz_bytes, msg], 2 * lb);

        var pw = pow_init(h_piop), c = 0, delta0, hidden, sib;
        for (;; c++) {
            if (c >= 0x100000000) { throw new Error('sdith: no counter gives a valid challenge'); }
            if (!(delta0 = pw(c)) || bits_zero(delta0, kt)) { continue; }
            hidden = hidden_leaves(delta0);
            if ((sib = siblings(hidden)).length <= TOPEN) { break; }
        }
        var sig = new Uint8Array(SIG), o = 0;
        sig.set(salt, o); o += lb;
        for (k = 0; k < sib.length; k++) { sig.set(seeds.subarray(sib[k] * lb, (sib[k] + 1) * lb), o + k * lb); }
        o += TOPEN * lb;
        for (k = 0; k < tau; k++, o += 2 * lb) { two(key(seeds.subarray(hidden[k] * lb, (hidden[k] + 1) * lb)), gs, 2 * hidden[k], sig, o); }
        sig.set(corr, o); o += corr.length;
        sig.set(cchk_u, o); o += cchk_u.length;
        sig.set(in_pub, o); o += ENC_BYTES;
        sig.set(cz_bytes.subarray(lb), o); o += (D - 1) * lb;
        sig.set(h_piop, o); o += 2 * lb;
        sig.set(le32(c), o);
        return sig;
    }

    function verify(pk, msg, sig) {
        if (!(pk instanceof Uint8Array) || pk.length !== PK || !(sig instanceof Uint8Array) || sig.length !== SIG) { return false; }
        var o = 0, salt = sig.slice(0, lb), i, j, k;
        var path = sig.subarray(o += lb, o += TOPEN * lb), hcom = sig.subarray(o, o += tau * 2 * lb);
        var corr = sig.subarray(o, o += (tau - 1) * Lbyte), cchk_u = sig.subarray(o, o += n_cchk / 8);
        var in_pub = sig.subarray(o, o += ENC_BYTES), cz_pub = F.from_bytes(sig, o, D - 1);
        o += (D - 1) * lb;
        var h_piop = sig.subarray(o, o += 2 * lb), c = (sig[o] | (sig[o + 1] << 8) | (sig[o + 2] << 16) | (sig[o + 3] << 24)) >>> 0;
        var seed_h = pk.subarray(0, lb), y = pk.subarray(lb);
        for (i = n_in; i < 8 * ENC_BYTES; i++) { if (bit(in_pub, i)) { return false; } }
        var delta0 = pow_init(h_piop)(c);
        if (!delta0 || bits_zero(delta0, kt)) { return false; }
        var hidden = hidden_leaves(delta0), sib = siblings(hidden);
        if (sib.length > TOPEN) { return false; }
        for (i = sib.length * lb; i < TOPEN * lb; i++) { if (path[i]) { return false; } }
        var d1 = delta1_of(delta0), d2 = new Uint32Array(W);
        F.inv(d2, 0, d1, 0);
        /* the tree from the sibling path, then the leaves */
        var gs = masked(salt, true), vs = masked(salt, false), seeds = new Uint8Array(2 * TL * lb), have = new Uint8Array(2 * TL);
        for (k = 0; k < sib.length; k++) { seeds.set(path.subarray(k * lb, (k + 1) * lb), sib[k] * lb); have[sib[k]] = 1; }
        expand_tree(seeds, have, gs);
        var s = new Uint8Array(tau * Lslice);
        for (i = 1; i < tau; i++) { s.set(corr.subarray((i - 1) * Lbyte, i * Lbyte), i * Lslice); }
        var V = leaves(seeds, salt, gs, vs, hidden, hcom, s), q = V.v;
        var d1b = F.to_bytes(d1, 0, 1);
        for (i = 0; i < tau; i++) {
            var di = bits_at(d1b, i * kappa, kappa);
            for (j = 0; j < kappa; j++) { if ((di >> j) & 1) { xor_into(q, (i * kappa + j) * Lslice, s, i * Lslice, Lslice); } }
        }
        var Q = transpose(q), hash_aux = xof([be8(H_AUX), V.hash, corr], 2 * lb), M = cchk_matrix(hash_aux);
        var chk = cchk_elems(M, Q);
        for (i = 0; i < n_cchk; i++) { if (bit(cchk_u, i)) { F.add(chk, i * W, chk, i * W, d1, 0); } }
        var hash_lines = xof([be8(H_LINES), hash_aux, cchk_u, F.to_bytes(chk, 0, n_cchk), in_pub], 2 * lb);
        /* the check-zero mask at delta: Horner in delta1, then times delta2^(D-1) */
        var qz = new Uint32Array((D - 1) * W), t = new Uint32Array(W), acc = new Uint32Array(W);
        for (i = 0; i < D - 1; i++) {
            for (j = 0; j < lambda; j++) { F.mul_xpow(t, 0, Q, (off_cz + i * lambda + j) * W, j); F.add(qz, i * W, qz, i * W, t, 0); }
        }
        F.copy(acc, 0, qz, (D - 2) * W);
        for (i = D - 3; i >= 0; i--) { F.mul(acc, 0, acc, 0, d1, 0); F.add(acc, 0, acc, 0, qz, i * W); }
        F.pow(t, 0, d2, 0, D - 1); F.mul(acc, 0, acc, 0, t, 0);
        var inputs = new Uint32Array(n_in * W);
        for (i = 0; i < n_in; i++) { F.mul(inputs, i * W, Q, (off_in + i) * W, d2, 0); inputs[i * W] ^= bit(in_pub, i); }
        var ch = xof([hash_lines], lb * (limbs + rsd_w)), chall_a = F.from_bytes(ch, 0, limbs), chall_u = F.from_bytes(ch, lb * limbs, rsd_w);
        var A = times_chall(seed_h, y, chall_a), res = A.ay.slice();
        for (i = 0; i < rsd_w; i++) { padd(res, mux_tree(inputs, i * mux_in * W, A.aH, i * npw * W, chall_u, i * W, 0)); }
        /* alpha_1 from the published alpha_2..alpha_D */
        var part = cz_pub.slice((D - 2) * W, (D - 1) * W);
        for (i = D - 3; i >= 0; i--) { F.mul(part, 0, part, 0, d2, 0); F.add(part, 0, part, 0, cz_pub, i * W); }
        F.mul(part, 0, part, 0, d2, 0); F.add(part, 0, part, 0, acc, 0);
        F.mul(t, 0, res, 0, d1, 0); F.add(part, 0, part, 0, t, 0);
        var want = xof([be8(H_PIOP), seed_h, y, hash_lines, F.to_bytes(part, 0, 1), F.to_bytes(cz_pub, 0, D - 1), msg], 2 * lb), diff = 0;
        for (i = 0; i < 2 * lb; i++) { diff |= want[i] ^ h_piop[i]; }
        return diff === 0;
    }

    return {
        NAME: 'SDiTH-' + name.toUpperCase().replace(/_/g, '-'),
        PK_BYTES: PK, SK_BYTES: SK, SIG_BYTES: SIG, SEED_BYTES: 2 * lb, RND_BYTES: 2 * lb,
        keygen: keygen, sign: sign, verify: verify
    };
}

function lazy(name) {
    return lazy_scheme(function () { return build(name); },
        ['NAME', 'PK_BYTES', 'SK_BYTES', 'SIG_BYTES', 'SEED_BYTES', 'RND_BYTES'],
        ['keygen', 'sign', 'verify']);
}

export var sdith_cat1_short = /* @__PURE__ */ lazy('cat1_short');
export var sdith_cat3_short = /* @__PURE__ */ lazy('cat3_short');
export var sdith_cat5_short = /* @__PURE__ */ lazy('cat5_short');
export var sdith_cat1_fast = /* @__PURE__ */ lazy('cat1_fast');
export var sdith_cat3_fast = /* @__PURE__ */ lazy('cat3_fast');
export var sdith_cat5_fast = /* @__PURE__ */ lazy('cat5_fast');
export var sdith_cat1_short_cipherpow = /* @__PURE__ */ lazy('cat1_short_cipherpow');
export var sdith_cat3_short_cipherpow = /* @__PURE__ */ lazy('cat3_short_cipherpow');
export var sdith_cat5_short_cipherpow = /* @__PURE__ */ lazy('cat5_short_cipherpow');
export var sdith_cat1_fast_cipherpow = /* @__PURE__ */ lazy('cat1_fast_cipherpow');
export var sdith_cat3_fast_cipherpow = /* @__PURE__ */ lazy('cat3_fast_cipherpow');
export var sdith_cat5_fast_cipherpow = /* @__PURE__ */ lazy('cat5_fast_cipherpow');
