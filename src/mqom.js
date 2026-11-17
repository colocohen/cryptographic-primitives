/**
 * MQOM  -  the round-3 submission to NIST's additional signatures (v3,
 * August 2026)
 *
 * A signature that proves knowledge of a solution x of a random multivariate
 * quadratic system y_i = x^T A_i x + b_i x over a small field, by the
 * MPC-in-the-head / VOLE-in-the-head paradigm: the prover commits to x
 * through tau GGM trees of N leaves, turns the leaves into a degree-1
 * polynomial (a "line") whose evaluation at a hidden point is x, proves the
 * quadratic relation on the line, and reveals all leaves but one per tree
 * (chosen by Fiat-Shamir, with w bits of grinding). Security rests only on the
 * hardness of random MQ and on the symmetric primitives.
 *
 * ROUND 3: the correlated-tree seed expansion and the domain separation
 * were redone in v3 (SALT_SEL / DOM_ values throughout); this follows v3 and
 * its KATs, not v2.
 *
 * THE PARAMETER SETS: security level 1, 3 or 5 (lambda = 16, 24, 32 bytes);
 * base field GF(2) ("shorter") or GF(16) ("short", "fast"); and the tree
 * layout: correlated trees (_ct: tau trees, each with a sum constraint that
 * shortens the opening) or one big tree (_ot: all tau*N leaves in one tree,
 * opened with a fixed number Topen of nodes). The extension field is
 * GF(256) for "fast" and GF(2^16) = GF(256)[y]/(y^2 + y + 32) otherwise; the
 * block cipher is AES-128 at level 1 and Rijndael-256 at levels 3 and 5
 * (truncated to 192 bits at level 3); the hash is SHAKE128 at level 1 and
 * SHAKE256 above.
 *
 * KEYS: pk = mseed_eq (2 lambda) || y; sk = pk || x. keygen takes the
 * randomness for x and then mseed_eq; sign takes mseed || salt (lambda
 * bytes each). Either omitted or null draws fresh bytes from the platform.
 */

import { shake128, shake256 } from './sha3.js';
import { aes_expand_key, aes_encrypt_block } from './aes.js';
import { rijndael_key, rijndael_encrypt } from './commons/rijndael.js';
import { gmul, POLY_AES } from './commons/gf256.js';
import { concat, le_bytes, secure_random } from './commons/bytes.js';
import { lazy_scheme } from './commons/lazy_scheme.js';

var LAMBDA = { 1: 16, 3: 24, 5: 32 };
var N_VARS = { gf2: { 1: 160, 3: 240, 5: 320 }, gf16: { 1: 64, 3: 96, 5: 128 } };
/* [extension field bits, N, tau, w, Topen] */
var TRADE = {
    '1-shorter-ct': [16, 4096, 10, 18], '1-shorter-ot': [16, 8192, 10, 8, 110],
    '1-short-ct': [16, 2048, 12, 8], '1-short-ot': [16, 2048, 12, 8, 120],
    '1-fast-ct': [8, 256, 17, 9], '1-fast-ot': [8, 256, 17, 9, 119],
    '3-shorter-ct': [16, 4096, 16, 16], '3-shorter-ot': [16, 4096, 17, 5, 170],
    '3-short-ct': [16, 2048, 18, 12], '3-short-ot': [16, 2048, 19, 2, 175],
    '3-fast-ct': [8, 256, 26, 10], '3-fast-ot': [8, 256, 26, 10, 186],
    '5-shorter-ct': [16, 4096, 22, 14], '5-shorter-ot': [16, 4096, 22, 14, 241],
    '5-short-ct': [16, 2048, 25, 6], '5-short-ot': [16, 2048, 25, 6, 238],
    '5-fast-ct': [8, 256, 35, 11], '5-fast-ot': [8, 256, 36, 4, 235]
};

/* XOF domains and salt-tweak selectors (v3, domains.py) */
var DOM_EQ = 0, DOM_COM2 = 1, DOM_PRESIG = 2, DOM_MSG = 3, DOM_SIG = 4, DOM_CHAL = 5, DOM_ISTAR = 6, DOM_COM1 = 7, DOM_GAMMA = 8;
var SEL_LEFT = 0, SEL_RIGHT = 1, SEL_GGM = 2, SEL_EXPAND = 3;

/* GF(16) = GF(2)[X]/(X^4 + X + 1) embedded in GF(256) (the AES field) */
var LIFT16 = [0, 1, 224, 225, 93, 92, 189, 188, 176, 177, 80, 81, 237, 236, 13, 12];

/*
 * The extension field as log/exp tables. LOG[0] is 2(2^k - 1) and EXP is zero
 * from there on, so EXP[LOG[a] + LOG[b]] is the product for every a, b,
 * zeros included, with no branch.
 */
var FIELDS = {};
function mul16(a, b) {
    var a0 = a & 0xff, a1 = a >>> 8, b0 = b & 0xff, b1 = b >>> 8;
    var lead = gmul(a1, b1, POLY_AES), cnst = gmul(a0, b0, POLY_AES);
    return (cnst ^ gmul(32, lead, POLY_AES)) | ((cnst ^ gmul(a0 ^ a1, b0 ^ b1, POLY_AES)) << 8);
}
function field(bits) {
    if (FIELDS[bits]) { return FIELDS[bits]; }
    var ord = (1 << bits) - 1, mul = bits === 8 ? function (a, b) { return gmul(a, b, POLY_AES); } : mul16;
    var EXP = new Uint16Array(4 * ord + 1), LOG = new Uint32Array(ord + 1), g, i, x;
    for (g = 2; g <= ord; g++) {
        for (i = 0, x = 1; i < ord; i++) {
            if (i > 0 && x === 1) { break; }
            EXP[i] = x; LOG[x] = i; x = mul(x, g);
        }
        if (i === ord) { break; }
    }
    for (i = ord; i < 2 * ord; i++) { EXP[i] = EXP[i - ord]; }
    LOG[0] = 2 * ord;
    return (FIELDS[bits] = { EXP: EXP, LOG: LOG });
}

/* lambda-byte block cipher: AES-128, Rijndael-256 truncated to 192, Rijndael-256 */
function cipher(lam) {
    if (lam === 16) {
        return {
            key: function (k) { return aes_expand_key(k); },
            enc: function (ks, src, off, out, out_off) { aes_encrypt_block(ks, 10, src, off, out, out_off); }
        };
    }
    if (lam === 32) {
        return {
            key: function (k) { return rijndael_key(k, 8); },
            enc: rijndael_encrypt
        };
    }
    var kp = new Uint8Array(32), bp = new Uint8Array(32), bo = new Uint8Array(32);
    return {
        key: function (k) { kp.set(k); return rijndael_key(kp, 8); },
        enc: function (ks, src, off, out, out_off) {
            bp.set(src.subarray(off, off + 24)); rijndael_encrypt(ks, bp, 0, bo, 0);
            out.set(bo.subarray(0, 24), out_off);
        }
    };
}

function build(sec, base, trade, variant) {
    var lam = LAMBDA[sec], gf2 = base === 'gf2', n = N_VARS[base][sec], T = TRADE[sec + '-' + trade + '-' + variant];
    var kbits = T[0], N = T[1], tau = T[2], w = T[3], Topen = T[4], ot = variant === 'ot';
    var log2q = gf2 ? 1 : 4, mu = kbits / log2q, mh = n / mu, eta = 8 * lam / kbits, Kb = kbits / 8;
    var logN = Math.round(Math.log2(N)), nsep = ot ? 3 : 2, h = ot ? logN + Math.ceil(Math.log2(tau)) : logN;
    var XB = n * log2q / 8, UB = eta * Kb, E = XB + UB, EP = (E + 3) & ~3, NBLK = Math.ceil(E / lam), HALF = lam / 2;
    var PK = 2 * lam + mh * Kb, SK = PK + XB, TN = tau * N;
    var OPEN = ot ? Topen * lam + tau * (2 * lam + XB + UB) : tau * (logN * lam + lam + XB + UB);
    var SIG = 3 * lam + 4 + OPEN, PER = n * (n + 1) / 2 + n, TRI = n * (n + 1) / 2;
    var H = lam === 16 ? shake128 : shake256, C = cipher(lam), F = field(kbits), EXP = F.EXP, LOG = F.LOG;
    var LK = new Uint32Array(logN);
    for (var k = 0; k < logN; k++) { LK[k] = LOG[1 << k]; }

    function xof(parts, len) { return H(concat(parts), len); }
    function getx(b, o, j) { return gf2 ? (b[o + (j >> 3)] >> (j & 7)) & 1 : LIFT16[(b[o + (j >> 1)] >> ((j & 1) << 2)) & 15]; }
    function getk(b, o, j) { return Kb === 1 ? b[o + j] : b[o + 2 * j] | (b[o + 2 * j + 1] << 8); }
    function putk(b, o, j, v) { if (Kb === 1) { b[o + j] = v; } else { b[o + 2 * j] = v & 0xff; b[o + 2 * j + 1] = v >>> 8; } }
    function logs(v) { var l = new Uint32Array(v.length); for (var i = 0; i < v.length; i++) { l[i] = LOG[v[i]]; } return l; }

    function tweak(salt, sel, v) {
        var t = new Uint8Array(salt);
        t.set(le_bytes(sel + 4 * v, nsep), lam - nsep);
        return C.key(t);
    }
    /* out = Enc_ks(seed) ^ (L ^ R || L), the seed's linear orthomorphism */
    function derive(ks, src, so, out, oo) {
        C.enc(ks, src, so, out, oo);
        for (var i = 0; i < HALF; i++) {
            out[oo + i] ^= src[so + i] ^ src[so + HALF + i];
            out[oo + HALF + i] ^= src[so + i];
        }
    }

    /* The MQ system: per equation, the lower-triangular A_i row by row, then b_i, as logs */
    function equations(mseed_eq) {
        var LA = new Uint32Array(mh * PER), nb = Math.ceil(PER * Kb / lam), st = new Uint8Array(nb * lam), ctr = new Uint8Array(lam);
        for (var i = 0; i < mh; i++) {
            var ks = C.key(xof([new Uint8Array([DOM_EQ]), mseed_eq, le_bytes(i, 2)], lam));
            for (var b = 0; b < nb; b++) { ctr.set(le_bytes(b, 4)); C.enc(ks, ctr, 0, st, b * lam); }
            for (var t = 0; t < PER; t++) { LA[i * PER + t] = LOG[getk(st, 0, t)]; }
        }
        return LA;
    }
    /* out = A_i v, with lv the logs of v */
    function a_times(LA, i, lv, out) {
        for (var j = 0, p = i * PER; j < n; j++) {
            var acc = 0;
            for (var k = 0; k <= j; k++) { acc ^= EXP[LA[p++] + lv[k]]; }
            out[j] = acc;
        }
    }
    function dot(u, lv) { var acc = 0; for (var j = 0; j < n; j++) { acc ^= EXP[LOG[u[j]] + lv[j]]; } return acc; }
    function b_dot(LA, i, lv) { var acc = 0, p = i * PER + TRI; for (var j = 0; j < n; j++) { acc ^= EXP[LA[p + j] + lv[j]]; } return acc; }
    function gamma(com1e) {
        var g = xof([new Uint8Array([DOM_GAMMA]), com1e], eta * mh * Kb), L = new Uint32Array(eta * mh);
        for (var t = 0; t < eta * mh; t++) { L[t] = LOG[getk(g, 0, t)]; }
        return L;
    }
    /* out[r] ^= sum_c Gamma[r][c] z[c] */
    function gamma_add(LG, z, out) {
        var lz = logs(z);
        for (var r = 0; r < eta; r++) {
            var acc = out[r];
            for (var c = 0; c < mh; c++) { acc ^= EXP[LG[r * mh + c] + lz[c]]; }
            out[r] = acc;
        }
    }

    /*
     * The leaves of one repetition, as a line. Each leaf seed is committed
     * (2 lambda bytes) and expanded to its share of x and u, packed; S is the
     * xor of the shares and acc[k] the xor of those whose index has bit k set
     * in its Gray code omega_i, so sum_i omega_i share_i = sum_k 2^k acc[k].
     * The hidden leaf (skip) is left out.
     */
    function line(salt, e, buf, pos, skip) {
        var ksl = tweak(salt, SEL_LEFT, e), ksr = tweak(salt, SEL_RIGHT, e), kse = [], b, q;
        for (b = 0; b < NBLK; b++) { kse.push(tweak(salt, SEL_EXPAND, e + 64 * b)); }
        var com = new Uint8Array(N * 2 * lam), W4 = EP >> 2, S = new Int32Array(W4), acc = new Int32Array(logN * W4);
        var ex = new Uint8Array(Math.max(NBLK * lam, EP)), ex32 = new Int32Array(ex.buffer, 0, W4), s_ = new Uint8Array(lam);
        for (var i = 0; i < N; i++) {
            if (i === skip) { continue; }
            var o = pos(i);
            derive(ksl, buf, o, com, 2 * lam * i);
            derive(ksr, buf, o, com, 2 * lam * i + lam);
            if (ot) {
                for (q = 0; q < HALF; q++) { s_[q] = buf[o + q] ^ buf[o + HALF + q]; s_[HALF + q] = buf[o + q]; }
                b = 0;
            } else {
                ex.set(buf.subarray(o, o + lam));
                C.enc(kse[0], buf, o, s_, 0);
                b = 1;
            }
            for (; b < NBLK; b++) {
                C.enc(kse[b], buf, o, ex, b * lam);
                for (q = 0; q < lam; q++) { ex[b * lam + q] ^= s_[q]; }
            }
            ex.fill(0, E, EP);
            for (q = 0; q < W4; q++) { S[q] ^= ex32[q]; }
            for (var g = i ^ (i >> 1), k = 0; g; g >>= 1, k++) {
                if (g & 1) { for (q = 0; q < W4; q++) { acc[k * W4 + q] ^= ex32[q]; } }
            }
        }
        return { com: com, S: new Uint8Array(S.buffer), acc: new Uint8Array(acc.buffer) };
    }
    /* sum_k 2^k acc[k], element j of the x part or of the u part */
    function omega_x(acc, j) {
        var v = 0;
        for (var k = 0; k < logN; k++) { v ^= EXP[LK[k] + LOG[getx(acc, k * EP, j)]]; }
        return v;
    }
    function omega_u(acc, j) {
        var v = 0;
        for (var k = 0; k < logN; k++) { v ^= EXP[LK[k] + LOG[getk(acc, k * EP + XB, j)]]; }
        return v;
    }
    function com1_of(e, salt, com, dx) {
        return xof([new Uint8Array([DOM_COM1, e]), salt, com, dx], 2 * lam);
    }

    /* ---- the GGM trees ---- */
    function ct_expand(salt, mseed, e, delta) {
        var t = new Uint8Array(2 * N * lam), ks = tweak(salt, SEL_GGM, e), j, kk, q;
        derive(ks, mseed, 0, t, 2 * lam);
        for (q = 0; q < lam; q++) { t[3 * lam + q] = t[2 * lam + q] ^ delta[q]; }
        for (j = 1; j < logN; j++) {
            ks = tweak(salt, SEL_GGM, e + 64 * j);
            for (kk = 1 << j; kk < 2 << j; kk++) { children(ks, t, kk); }
        }
        return t;
    }
    function children(ks, t, kk) {
        derive(ks, t, kk * lam, t, 2 * kk * lam);
        for (var q = 0; q < lam; q++) { t[(2 * kk + 1) * lam + q] = t[2 * kk * lam + q] ^ t[kk * lam + q]; }
    }
    function ct_partial(salt, path, po, e, hidden) {
        var t = new Uint8Array(2 * N * lam), have = new Uint8Array(2 * N), node = N + hidden, j, kk, ks;
        for (j = 0; j < logN; j++, node >>= 1) {
            t.set(path.subarray(po + j * lam, po + (j + 1) * lam), (node ^ 1) * lam); have[node ^ 1] = 1;
        }
        for (j = 1; j < logN; j++) {
            ks = null;
            for (kk = 1 << j; kk < 2 << j; kk++) {
                if (have[kk]) { ks = ks || tweak(salt, SEL_GGM, e + 64 * j); children(ks, t, kk); have[2 * kk] = have[2 * kk + 1] = 1; }
            }
        }
        return t;
    }
    var DEEP = 2 * TN - (2 ** h);
    function leaf_pos(i) { return i < DEEP ? (2 ** h) + i : TN + (i - DEEP); }
    function leaf_depth(i) { return i < DEEP ? h : h - 1; }
    function ot_expand(salt, mseed) {
        var t = new Uint8Array(2 * TN * lam);
        t.set(mseed, lam);
        for (var kk = 1; kk < TN; kk++) { children(tweak(salt, SEL_GGM, kk), t, kk); }
        return t;
    }
    function hidden_leaves(istar) { var l = []; for (var e = 0; e < tau; e++) { l.push(istar[e] * tau + e); } return l; }
    function sensitive(leaves) {
        var s = leaves.slice().sort(function (a, b) { return a - b; }), out = [], path = new Array(h + 1).fill(0);
        for (var e = 0; e < tau; e++) {
            var node = leaf_pos(s[e]), depth = leaf_depth(s[e]), mp = depth;
            while (mp >= 0 && path[mp] !== node) { path[mp] = node; node = Math.floor(node / 2); mp--; }
            for (var j = mp + 1; j <= depth; j++) { out.push(path[j]); }
        }
        return out;
    }
    function valid_opening(istar) { return sensitive(hidden_leaves(istar)).length - 2 * tau + 1 <= Topen; }
    function path_nodes(hidden) {
        var hp = 0, size = hidden.length - 2 * tau + 1, stack = [1], out = [];
        while (stack.length) {
            var kk = stack.pop();
            if (hp >= hidden.length || kk !== hidden[hp]) {
                if (size < Topen && kk < TN) { size++; } else { out.push(kk); continue; }
            } else { hp++; }
            if (kk < TN) { stack.push(2 * kk + 1, 2 * kk); }
        }
        return out;
    }
    function ot_partial(salt, path, istar) {
        var nodes = path_nodes(sensitive(hidden_leaves(istar))), t = new Uint8Array(2 * TN * lam), have = new Uint8Array(2 * TN);
        for (var p = 0; p < Topen; p++) { t.set(path.subarray(p * lam, (p + 1) * lam), nodes[p] * lam); have[nodes[p]] = 1; }
        for (var kk = 1; kk < TN; kk++) {
            if (have[kk]) { children(tweak(salt, SEL_GGM, kk), t, kk); have[2 * kk] = have[2 * kk + 1] = 1; }
        }
        return t;
    }

    /* ---- Fiat-Shamir with grinding: the low w-1 bits of Enc_k0(g0||nonce) ^ Enc_k1(g1||nonce) must be 0 ---- */
    function challenge(sig_id) {
        var g = lam - 4, ex = xof([new Uint8Array([DOM_CHAL]), sig_id], 4 * lam - 8);
        var k0 = ex.slice(2 * g, 2 * g + lam), k1 = ex.slice(2 * g + lam, 2 * g + 2 * lam);
        k0[lam - 1] = (k0[lam - 1] & 0x3f) ^ 0x80; k1[lam - 1] = (k1[lam - 1] & 0x3f) ^ 0xc0;
        var ks0 = C.key(k0), ks1 = C.key(k1), p0 = new Uint8Array(lam), p1 = new Uint8Array(lam);
        p0.set(ex.subarray(0, g)); p1.set(ex.subarray(g, 2 * g));
        var c0 = new Uint8Array(lam), c1 = new Uint8Array(lam), mask = (1 << (w - 1)) - 1;
        return function (nonce) {
            var nb = le_bytes(nonce, 4);
            p0.set(nb, g); p1.set(nb, g);
            C.enc(ks0, p0, 0, c0, 0); C.enc(ks1, p1, 0, c1, 0);
            if ((((c0[0] ^ c1[0]) | ((c0[1] ^ c1[1]) << 8) | ((c0[2] ^ c1[2]) << 16)) & mask) !== 0) { return null; }
            var u = xof([new Uint8Array([DOM_ISTAR]), sig_id, nb, c0, c1], 2 * tau), istar = [];
            for (var e = 0; e < tau; e++) { istar.push((u[2 * e] | (u[2 * e + 1] << 8)) & (N - 1)); }
            return ot && !valid_opening(istar) ? null : istar;
        };
    }

    function sig_id_of(pk, com1, alpha0, alpha1, msg) {
        var al = new Uint8Array(2 * tau * UB);
        for (var e = 0; e < tau; e++) {
            for (var r = 0; r < eta; r++) { putk(al, 2 * e * UB, r, alpha0[e][r]); putk(al, (2 * e + 1) * UB, r, alpha1[e][r]); }
        }
        var com2 = xof([new Uint8Array([DOM_COM2]), al], 2 * lam);
        var mh_ = xof([new Uint8Array([DOM_MSG]), msg], 2 * lam);
        var pre = xof([new Uint8Array([DOM_PRESIG]), pk].concat(com1, [com2]), 2 * lam);
        return xof([new Uint8Array([DOM_SIG]), pre, mh_], 2 * lam);
    }

    function keygen(seed) {
        if (seed == null) { seed = secure_random(XB + 2 * lam); }
        if (!(seed instanceof Uint8Array) || seed.length !== XB + 2 * lam) {
            throw new Error('mqom: keygen takes ' + (XB + 2 * lam) + ' bytes (x, then mseed_eq)');
        }
        var xb = seed.slice(0, XB), mseed_eq = seed.slice(XB), LA = equations(mseed_eq);
        var xl = new Uint16Array(n), t = new Uint16Array(n), j;
        for (j = 0; j < n; j++) { xl[j] = getx(xb, 0, j); }
        var lx = logs(xl), pk = new Uint8Array(PK);
        pk.set(mseed_eq);
        for (var i = 0; i < mh; i++) { a_times(LA, i, lx, t); putk(pk, 2 * lam, i, dot(t, lx) ^ b_dot(LA, i, lx)); }
        var sk = new Uint8Array(SK);
        sk.set(pk); sk.set(xb, PK);
        return { pk: pk, sk: sk };
    }

    function sign(sk, msg, rnd) {
        if (!(sk instanceof Uint8Array) || sk.length !== SK) { throw new Error('mqom: secret key must be ' + SK + ' bytes'); }
        if (rnd == null) { rnd = secure_random(2 * lam); }
        if (!(rnd instanceof Uint8Array) || rnd.length !== 2 * lam) { throw new Error('mqom: sign takes ' + 2 * lam + ' bytes of randomness (mseed, salt)'); }
        var pk = sk.subarray(0, PK), xb = sk.subarray(PK), mseed = rnd.subarray(0, lam), salt = rnd.slice(lam);
        var trees = [], coms = [], dxs = [], com1 = [], x0 = [], u0 = [], u1 = [], e, j, q;
        var big = ot ? ot_expand(salt, mseed) : null;
        for (e = 0; e < tau; e++) {
            var t = big || ct_expand(salt, mseed, e, xb), ee = e;
            var L = line(salt, e, t, ot ? function (i) { return leaf_pos(tau * i + ee) * lam; } : function (i) { return (N + i) * lam; }, -1);
            var dx = new Uint8Array(XB), xv = new Uint16Array(n), uv = new Uint16Array(eta), u1v = new Uint16Array(eta);
            for (q = 0; q < XB; q++) { dx[q] = xb[q] ^ L.S[q]; }
            for (j = 0; j < n; j++) { xv[j] = omega_x(L.acc, j); }
            for (j = 0; j < eta; j++) { uv[j] = omega_u(L.acc, j); u1v[j] = getk(L.S, XB, j); }
            var dser = ot ? dx : dx.subarray(lam);
            trees.push(t); coms.push(L.com); dxs.push(dser); x0.push(xv); u0.push(uv); u1.push(u1v);
            com1.push(com1_of(e, salt, L.com, dser));
        }
        /* the PIOP: alpha = u + Gamma z, with P_z(X) = P_t(X)^T P_x(X) - y X^2 */
        var LA = equations(pk.subarray(0, 2 * lam)), xl = new Uint16Array(n);
        for (j = 0; j < n; j++) { xl[j] = getx(xb, 0, j); }
        var lx = logs(xl), t1 = [], t0 = new Uint16Array(n), z0 = new Uint16Array(mh), z1 = new Uint16Array(mh), i;
        for (i = 0; i < mh; i++) {
            var v = new Uint16Array(n);
            a_times(LA, i, lx, v);
            for (j = 0, q = i * PER + TRI; j < n; j++) { v[j] ^= EXP[LA[q + j]]; }
            t1.push(v);
        }
        var alpha0 = [], alpha1 = [];
        for (e = 0; e < tau; e++) {
            var lx0 = logs(x0[e]);
            for (i = 0; i < mh; i++) {
                a_times(LA, i, lx0, t0);
                z0[i] = dot(t0, lx0);
                z1[i] = dot(t0, lx) ^ dot(t1[i], lx0);
            }
            var LG = gamma(com1[e]), a0 = u0[e].slice(), a1 = u1[e].slice();
            gamma_add(LG, z0, a0); gamma_add(LG, z1, a1);
            alpha0.push(a0); alpha1.push(a1);
        }
        var sig_id = sig_id_of(pk, com1, alpha0, alpha1, msg), ch = challenge(sig_id), istar = null, nonce;
        for (nonce = 0; nonce < 2 ** 32 && !(istar = ch(nonce)); nonce++) { /* grind */ }
        if (!istar) { throw new Error('mqom: no nonce gives a valid challenge'); }

        var sig = new Uint8Array(SIG), o = 0;
        sig.set(sig_id, o); o += 2 * lam;
        sig.set(salt, o); o += lam;
        sig.set(le_bytes(nonce, 4), o); o += 4;
        if (ot) {
            var nodes = path_nodes(sensitive(hidden_leaves(istar)));
            for (q = 0; q < Topen; q++, o += lam) { sig.set(big.subarray(nodes[q] * lam, (nodes[q] + 1) * lam), o); }
            for (e = 0; e < tau; e++, o += 2 * lam) { sig.set(coms[e].subarray(istar[e] * 2 * lam, (istar[e] + 1) * 2 * lam), o); }
            for (e = 0; e < tau; e++, o += XB) { sig.set(dxs[e], o); }
            for (e = 0; e < tau; e++, o += UB) { for (j = 0; j < eta; j++) { putk(sig, o, j, alpha1[e][j]); } }
        } else {
            for (e = 0; e < tau; e++) {
                for (var node = N + istar[e], d = 0; d < logN; d++, node >>= 1, o += lam) {
                    sig.set(trees[e].subarray((node ^ 1) * lam, ((node ^ 1) + 1) * lam), o);
                }
                sig.set(coms[e].subarray(istar[e] * 2 * lam, (istar[e] + 1) * 2 * lam), o); o += 2 * lam;
                sig.set(dxs[e], o); o += XB - lam;
                for (j = 0; j < eta; j++) { putk(sig, o, j, alpha1[e][j]); }
                o += UB;
            }
        }
        return sig;
    }

    function verify(pk, msg, sig) {
        if (!(pk instanceof Uint8Array) || pk.length !== PK || !(sig instanceof Uint8Array) || sig.length !== SIG) { return false; }
        var sig_id = sig.subarray(0, 2 * lam), salt = sig.slice(2 * lam, 3 * lam), nonce = 0, e, j, q, i;
        for (q = 3; q >= 0; q--) { nonce = nonce * 256 + sig[3 * lam + q]; }
        var istar = challenge(sig_id)(nonce);
        if (!istar) { return false; }
        var op = sig.subarray(3 * lam + 4), big = ot ? ot_partial(salt, op, istar) : null;
        var LA = equations(pk.subarray(0, 2 * lam)), com1 = [], alpha0 = [], alpha1 = [];
        var vt = new Uint16Array(n), vz = new Uint16Array(mh);
        for (e = 0; e < tau; e++) {
            var t, dx, oc, oa, ee = e;
            if (ot) {
                t = big; oc = Topen * lam + e * 2 * lam;
                dx = op.subarray(Topen * lam + tau * 2 * lam + e * XB, Topen * lam + tau * 2 * lam + (e + 1) * XB);
                oa = Topen * lam + tau * (2 * lam + XB) + e * UB;
            } else {
                var base = e * (logN * lam + lam + XB + UB);
                t = ct_partial(salt, op, base, e, istar[e]); oc = base + logN * lam;
                dx = new Uint8Array(XB); dx.set(op.subarray(oc + 2 * lam, oc + lam + XB), lam);
                oa = oc + lam + XB;
            }
            var L = line(salt, e, t, ot ? function (i) { return leaf_pos(tau * i + ee) * lam; } : function (i) { return (N + i) * lam; }, istar[e]);
            L.com.set(op.subarray(oc, oc + 2 * lam), istar[e] * 2 * lam);
            com1.push(com1_of(e, salt, L.com, ot ? dx : dx.subarray(lam)));

            var r = istar[e] ^ (istar[e] >> 1), lr = LOG[r], r2 = LOG[EXP[2 * lr]];
            var sx = new Uint8Array(XB), xe = new Uint16Array(n), ue = new Uint16Array(eta), a1 = new Uint16Array(eta);
            for (q = 0; q < XB; q++) { sx[q] = dx[q] ^ L.S[q]; }
            for (j = 0; j < n; j++) { xe[j] = EXP[lr + LOG[getx(sx, 0, j)]] ^ omega_x(L.acc, j); }
            for (j = 0; j < eta; j++) { ue[j] = EXP[lr + LOG[getk(L.S, XB, j)]] ^ omega_u(L.acc, j); a1[j] = getk(op, oa, j); }
            var lv = logs(xe);
            for (i = 0; i < mh; i++) {
                a_times(LA, i, lv, vt);
                for (j = 0, q = i * PER + TRI; j < n; j++) { vt[j] ^= EXP[LA[q + j] + lr]; }
                vz[i] = dot(vt, lv) ^ EXP[LOG[getk(pk, 2 * lam, i)] + r2];
            }
            gamma_add(gamma(com1[e]), vz, ue);
            for (j = 0; j < eta; j++) { ue[j] ^= EXP[LOG[a1[j]] + lr]; }
            alpha0.push(ue); alpha1.push(a1);
        }
        var want = sig_id_of(pk, com1, alpha0, alpha1, msg), diff = 0;
        for (q = 0; q < 2 * lam; q++) { diff |= want[q] ^ sig_id[q]; }
        return diff === 0;
    }

    return {
        NAME: 'MQOM3-L' + sec + '-' + base + '-' + trade + '-' + variant,
        PK_BYTES: PK, SK_BYTES: SK, SIG_BYTES: SIG, SEED_BYTES: XB + 2 * lam, RND_BYTES: 2 * lam,
        keygen: keygen, sign: sign, verify: verify
    };
}

/* name -> the scheme, built on first use (the GF(2^16) tables cost a few ms) */
function lazy(sec, base, trade, variant) {
    return lazy_scheme(function () { return build(sec, base, trade, variant); },
        ['NAME', 'PK_BYTES', 'SK_BYTES', 'SIG_BYTES', 'SEED_BYTES', 'RND_BYTES'],
        ['keygen', 'sign', 'verify']);
}

export var mqom3_cat1_gf2_shorter_ct = /* @__PURE__ */ lazy(1, 'gf2', 'shorter', 'ct');
export var mqom3_cat1_gf2_shorter_ot = /* @__PURE__ */ lazy(1, 'gf2', 'shorter', 'ot');
export var mqom3_cat1_gf16_short_ct = /* @__PURE__ */ lazy(1, 'gf16', 'short', 'ct');
export var mqom3_cat1_gf16_short_ot = /* @__PURE__ */ lazy(1, 'gf16', 'short', 'ot');
export var mqom3_cat1_gf16_fast_ct = /* @__PURE__ */ lazy(1, 'gf16', 'fast', 'ct');
export var mqom3_cat1_gf16_fast_ot = /* @__PURE__ */ lazy(1, 'gf16', 'fast', 'ot');
export var mqom3_cat3_gf2_shorter_ct = /* @__PURE__ */ lazy(3, 'gf2', 'shorter', 'ct');
export var mqom3_cat3_gf2_shorter_ot = /* @__PURE__ */ lazy(3, 'gf2', 'shorter', 'ot');
export var mqom3_cat3_gf16_short_ct = /* @__PURE__ */ lazy(3, 'gf16', 'short', 'ct');
export var mqom3_cat3_gf16_short_ot = /* @__PURE__ */ lazy(3, 'gf16', 'short', 'ot');
export var mqom3_cat3_gf16_fast_ct = /* @__PURE__ */ lazy(3, 'gf16', 'fast', 'ct');
export var mqom3_cat3_gf16_fast_ot = /* @__PURE__ */ lazy(3, 'gf16', 'fast', 'ot');
export var mqom3_cat5_gf2_shorter_ct = /* @__PURE__ */ lazy(5, 'gf2', 'shorter', 'ct');
export var mqom3_cat5_gf2_shorter_ot = /* @__PURE__ */ lazy(5, 'gf2', 'shorter', 'ot');
export var mqom3_cat5_gf16_short_ct = /* @__PURE__ */ lazy(5, 'gf16', 'short', 'ct');
export var mqom3_cat5_gf16_short_ot = /* @__PURE__ */ lazy(5, 'gf16', 'short', 'ot');
export var mqom3_cat5_gf16_fast_ct = /* @__PURE__ */ lazy(5, 'gf16', 'fast', 'ct');
export var mqom3_cat5_gf16_fast_ot = /* @__PURE__ */ lazy(5, 'gf16', 'fast', 'ot');
