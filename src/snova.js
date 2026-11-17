/**
 * SNOVA  -  the round-3 submission to NIST's additional signatures
 * (September 2026)
 *
 * UOV over a matrix ring. The variables are l x l matrices over GF(16), the
 * secret oil space is spanned by elements of the commutative subring F_q[S]
 * (polynomials in a fixed symmetric matrix S), and each public polynomial is
 * "emulsified" into many equations by public matrices A, B, Q1, Q2. The
 * result is UOV's structure with far smaller keys: 376 bytes to 2.7 KB of
 * public key, 272 to 896 bytes of signature. Round 3 makes signatures rectangular - an
 * (n l) x r matrix rather than (n l) x l - which is what the B, K and S
 * variants trade between.
 *
 * THE PARAMETER SETS: SNOVA_{I,III,V}_{B,K,S}, each with its public key
 * expanded by SHAKE128 blocks (the default) or by AES-128 in counter mode
 * (_AES). v, o, l, r and m1 (the number of distinct public polynomials;
 * equation mi uses polynomial (mi + alpha) mod m1) are the submission's.
 *
 * The computation follows the submission's SageMath implementation, which
 * generates its KATs: dense matrices over GF(16), product by product.
 *
 * KEYS. pk = pk_seed (16) || P22. sk = the 48-byte seed (pk_seed || sk_seed)
 * || SHAKE256(pk, 48), the hash the signature binds to.
 */

import { shake128, shake256 } from './sha3.js';
import { aes_ctr } from './aes.js';
import { concat, secure_random } from './commons/bytes.js';
import { equal } from './commons/ct.js';
import { GF16 } from './commons/gf2k.js';

var F = GF16, mul = F.mul;

var SETS = {
    I_B: [27, 4, 4, 6, 5], I_K: [29, 3, 4, 8, 5], I_S: [27, 5, 4, 4, 5],
    III_B: [38, 5, 4, 6, 7], III_K: [38, 4, 4, 8, 7], III_S: [38, 6, 4, 5, 7],
    V_B: [40, 5, 5, 6, 6], V_K: [40, 4, 5, 8, 6], V_S: [40, 6, 5, 5, 6]
};

/* ---------------- dense matrices over GF(16), row-major ---------------- */

function mat(r, c) { return { r: r, c: c, d: new Uint8Array(r * c) }; }

function mm(A, B) {
    var C = mat(A.r, B.c), n = B.c;
    for (var i = 0; i < A.r; i++) {
        for (var k = 0; k < A.c; k++) {
            var a = A.d[i * A.c + k];
            if (a === 0) { continue; }
            for (var j = 0; j < n; j++) { C.d[i * n + j] ^= mul(a, B.d[k * n + j]); }
        }
    }
    return C;
}
function add(A, B) { var C = mat(A.r, A.c); for (var i = 0; i < C.d.length; i++) { C.d[i] = A.d[i] ^ B.d[i]; } return C; }
function tr(A) { var C = mat(A.c, A.r); for (var i = 0; i < A.r; i++) { for (var j = 0; j < A.c; j++) { C.d[j * A.r + i] = A.d[i * A.c + j]; } } return C; }
function scale(A, s) { var C = mat(A.r, A.c); for (var i = 0; i < C.d.length; i++) { C.d[i] = mul(s, A.d[i]); } return C; }
function eye(n) { var I = mat(n, n); for (var i = 0; i < n; i++) { I.d[i * n + i] = 1; } return I; }

/* M applied to each l-row block of X (block_diag(M, ..., M) X), M l x l */
function blocks(M, X) {
    var l = M.r, C = mat(X.r, X.c), n = X.c;
    for (var b = 0; b < X.r / l; b++) {
        for (var i = 0; i < l; i++) {
            for (var k = 0; k < l; k++) {
                var a = M.d[i * l + k];
                if (a === 0) { continue; }
                for (var j = 0; j < n; j++) { C.d[(b * l + i) * n + j] ^= mul(a, X.d[(b * l + k) * n + j]); }
            }
        }
    }
    return C;
}
/* X block_diag(M, ..., M), over l-column blocks */
function blocks_right(X, M) { return tr(blocks(tr(M), tr(X))); }

function det_zero(A) {
    var n = A.r, B = A.d.slice();
    for (var c = 0; c < n; c++) {
        var p = -1;
        for (var i = c; i < n; i++) { if (B[i * n + c] !== 0) { p = i; break; } }
        if (p < 0) { return true; }
        if (p !== c) { for (var j = 0; j < n; j++) { var t = B[c * n + j]; B[c * n + j] = B[p * n + j]; B[p * n + j] = t; } }
        var pi = F.inv(B[c * n + c]);
        for (var r = c + 1; r < n; r++) {
            var e = mul(B[r * n + c], pi);
            if (e === 0) { continue; }
            for (var k = c; k < n; k++) { B[r * n + k] ^= mul(e, B[c * n + k]); }
        }
    }
    return false;
}

/* bytes to GF(16) elements, low nibble first, and back */
function nibbles(b, count) { var r = new Uint8Array(count); for (var i = 0; i < count; i++) { r[i] = (b[i >> 1] >> ((i & 1) << 2)) & 15; } return r; }
function pack(e) { var r = new Uint8Array((e.length + 1) >> 1); for (var i = 0; i < e.length; i++) { r[i >> 1] |= e[i] << ((i & 1) << 2); } return r; }

function build(name, use_aes) {
    var P = SETS[name], v = P[0], o = P[1], l = P[2], r = P[3], m1 = P[4];
    var n = v + o, n_alpha = l * r + 2 * r, vl = v * l, ol = o * l, nl = n * l, olr = o * l * r;

    /* S: S[i][j] = |8 - (i + j)|, with S[4][4] = 9 for l = 5 */
    var S = mat(l, l);
    for (var i = 0; i < l; i++) { for (var j = 0; j < l; j++) { S.d[i * l + j] = Math.abs(8 - (i + j)); } }
    if (l === 5) { S.d[24] = 9; }
    var SP = [eye(l)];
    for (var e = 1; e <= l; e++) { SP.push(mm(SP[e - 1], S)); }
    function in_FqS(c) { var M = mat(l, l); for (var a = 0; a < l; a++) { M = add(M, scale(SP[a], c[a])); } return M; }

    var PUB_GF = m1 * (v * v + 2 * v * o) * l * l, P22_GF = m1 * ol * ol;
    var PK_BYTES = 16 + (P22_GF >> 1), SK_BYTES = 96, SIG_BYTES = (nl * r >> 1) + 16;

    /* the public key's random part: SHAKE128(seed || block index, 168) blocks, or AES-128-CTR */
    function xof(seed) {
        var len = (PUB_GF + 1) >> 1;
        if (use_aes) { return aes_ctr(seed, new Uint8Array(16), new Uint8Array(len)); }
        var out = new Uint8Array(Math.ceil(len / 168) * 168), blk = new Uint8Array(24);
        blk.set(seed);
        for (var b = 0; b * 168 < len; b++) {
            for (var t = 0; t < 8; t++) { blk[16 + t] = Math.floor(b / Math.pow(2, 8 * t)) & 0xff; }
            out.set(shake128(blk, 168), b * 168);
        }
        return out.subarray(0, len);
    }

    /* a block matrix (rb x cb blocks of l x l) filled block by block, row-major inside */
    function fill(data, at, rb, cb) {
        var M = mat(rb * l, cb * l);
        for (var bi = 0; bi < rb; bi++) {
            for (var bj = 0; bj < cb; bj++) {
                for (var i1 = 0; i1 < l; i1++) { for (var j1 = 0; j1 < l; j1++) { M.d[(bi * l + i1) * M.c + bj * l + j1] = data[at.i++]; } }
            }
        }
        return M;
    }
    function flatten(M, rb, cb, out) {
        for (var bi = 0; bi < rb; bi++) {
            for (var bj = 0; bj < cb; bj++) {
                for (var i1 = 0; i1 < l; i1++) { for (var j1 = 0; j1 < l; j1++) { out.push(M.d[(bi * l + i1) * M.c + bj * l + j1]); } }
            }
        }
    }

    function expand_public(pk_seed) {
        var data = nibbles(xof(pk_seed), PUB_GF), at = { i: 0 }, P11 = [], P12 = [], P21 = [], mi;
        for (mi = 0; mi < m1; mi++) { P11.push(fill(data, at, v, v)); }
        for (mi = 0; mi < m1; mi++) { P12.push(fill(data, at, v, o)); }
        for (mi = 0; mi < m1; mi++) { P21.push(fill(data, at, o, v)); }
        return { P11: P11, P12: P12, P21: P21 };
    }

    /* the secret T12: v x o blocks, each an element of F_q[S] */
    function expand_t12(sk_seed) {
        var c = nibbles(shake256(sk_seed, o * v * l), o * v * l), T = mat(vl, ol);
        for (var ni = 0; ni < v; ni++) {
            for (var nj = 0; nj < o; nj++) {
                var B = in_FqS(c.subarray(l * (ni * o + nj)));
                for (var i1 = 0; i1 < l; i1++) { for (var j1 = 0; j1 < l; j1++) { T.d[(ni * l + i1) * ol + nj * l + j1] = B.d[i1 * l + j1]; } }
            }
        }
        return T;
    }

    /* the emulsifier A, B, Q1, Q2: fixed, from SHAKE256("SNOVA_ABQ"); computed once */
    var ABQ = null;
    function abq() {
        if (ABQ) { return ABQ; }
        var N = o * n_alpha, total = N * (r * (r + l) + 2 * l);
        var d = nibbles(shake256(new TextEncoder().encode('SNOVA_ABQ'), total), total);
        function make(off, r1, r2) {
            var M = mat(r1, r2);
            for (var i = 0; i < r1 * r2; i++) { M.d[i] = d[off + i]; }
            if (r1 === l && r2 === l) {
                var f1 = 1;
                while (det_zero(M) && f1 < 16) { M = add(M, scale(S, f1)); f1++; }
                if (f1 === 16) { throw new Error('snova: f1 == q'); }
            }
            return M;
        }
        var A = [], B = [], Q1 = [], Q2 = [];
        for (var k = 0; k < N; k++) {
            A.push(make(k * r * r, r, r));
            B.push(make(N * r * r + k * l * r, r, l));
            Q1.push(in_FqS(d.subarray(N * r * (r + l) + k * l)));
            Q2.push(in_FqS(d.subarray(N * r * (r + l) + N * l + k * l)));
        }
        return (ABQ = { A: A, B: B, Q1: Q1, Q2: Q2, q1: function (k) { return d.subarray(N * r * (r + l) + k * l); }, q2: function (k) { return d.subarray(N * r * (r + l) + N * l + k * l); } });
    }

    /* the message's target: o r x l matrices, flattened as (mi, l index, r index) */
    function target(msg, bind, salt) {
        var res = nibbles(shake256(concat([bind, shake256(msg, 64), salt]), (olr + 1) >> 1), olr), t = new Uint8Array(olr);
        for (var mi = 0; mi < o; mi++) { for (var i1 = 0; i1 < l; i1++) { for (var j1 = 0; j1 < r; j1++) { t[mi * l * r + i1 * r + j1] = res[mi * l * r + j1 * l + i1]; } } }
        return t;
    }

    /*
     * The emulsified quadratic part: for each equation mi, the r x l matrix
     * sum over alpha of A (sum over a, b of q1_a X^T S^a P S^b X q2_b) B,
     * flattened like the target. X is (blocks * l) x r, Ps the m1 maps.
     */
    function emulsify(X, Ps) {
        var E = abq(), SX = [], a, b, mi;
        for (a = 0; a < l; a++) { SX.push(blocks(SP[a], X)); }
        var pv = [];
        for (mi = 0; mi < m1; mi++) {
            var row = [];
            for (b = 0; b < l; b++) { row.push(mm(Ps[mi], SX[b])); }
            var pm = [];
            for (a = 0; a < l; a++) { var ta = tr(SX[a]), pa = []; for (b = 0; b < l; b++) { pa.push(mm(ta, row[b])); } pm.push(pa); }
            pv.push(pm);
        }
        var out = new Uint8Array(olr);
        for (mi = 0; mi < o; mi++) {
            var acc = mat(r, l);
            for (var al = 0; al < n_alpha; al++) {
                var k = mi * n_alpha + al, mp = (mi + al) % m1, q1 = E.q1(k), q2 = E.q2(k), pqq = mat(r, r);
                for (a = 0; a < l; a++) { for (b = 0; b < l; b++) { pqq = add(pqq, scale(pv[mp][a][b], mul(q1[a], q2[b]))); } }
                acc = add(acc, mm(mm(E.A[k], pqq), E.B[k]));
            }
            for (var j1 = 0; j1 < l; j1++) { for (var i1 = 0; i1 < r; i1++) { out[mi * l * r + j1 * r + i1] = acc.d[i1 * l + j1]; } }
        }
        return out;
    }

    function keypair(seed) {
        var pk_seed = seed.subarray(0, 16), T = expand_t12(seed.subarray(16, 48)), X = expand_public(pk_seed), Tt = tr(T), flat = [];
        for (var mi = 0; mi < m1; mi++) {
            var P22 = add(mm(Tt, add(mm(X.P11[mi], T), X.P12[mi])), mm(X.P21[mi], T));
            flatten(P22, o, o, flat);
        }
        var pk = concat([pk_seed, pack(Uint8Array.from(flat))]);
        return { pk: pk, sk: concat([seed, shake256(pk, 48)]) };
    }

    function sign(sk, msg, salt) {
        var seed = sk.subarray(0, 48), pk_seed = seed.subarray(0, 16), sk_seed = seed.subarray(16, 48);
        var T = expand_t12(sk_seed), X = expand_public(pk_seed), Tt = tr(T), E = abq(), mi;
        var F12 = [], F21 = [];
        for (mi = 0; mi < m1; mi++) { F12.push(add(mm(X.P11[mi], T), X.P12[mi])); F21.push(add(mm(Tt, X.P11[mi]), X.P21[mi])); }
        var t = target(msg, sk.subarray(48), salt), hmsg = shake256(msg, 64);
        for (var num = 1; num < 255; num++) {
            var vg = nibbles(shake256(concat([sk_seed, hmsg, salt, new Uint8Array([num])]), (vl * r + 1) >> 1), vl * r);
            var V = mat(vl, r);
            V.d.set(vg);
            var fvv = emulsify(V, X.P11), rhs = new Uint8Array(olr), Vt = tr(V);
            for (var z = 0; z < olr; z++) { rhs[z] = t[z] ^ fvv[z]; }

            /* the oil variables' coefficients */
            var G = mat(olr, olr);
            for (mi = 0; mi < o; mi++) {
                for (var al = 0; al < n_alpha; al++) {
                    var k = mi * n_alpha + al, mp = (mi + al) % m1, A = E.A[k], B = E.B[k];
                    var H1 = mm(blocks(E.Q1[k], mm(F21[mp], blocks(E.Q2[k], V))), B);            /* ol x l */
                    var H2 = blocks_right(mm(A, mm(blocks_right(Vt, E.Q1[k]), F12[mp])), E.Q2[k]);  /* r x ol */
                    for (var i0 = 0; i0 < o; i0++) {
                        for (var i1 = 0; i1 < l; i1++) {
                            for (var i2 = 0; i2 < r; i2++) {
                                var row = mi * l * r + i1 * r + i2;
                                for (var j1 = 0; j1 < l; j1++) {
                                    var h1 = H1.d[(i0 * l + j1) * l + i1], h2 = H2.d[i2 * ol + i0 * l + j1];
                                    for (var j2 = 0; j2 < r; j2++) {
                                        G.d[row * olr + i0 * l * r + j1 * r + j2] ^= mul(h1, A.d[i2 * r + j2]) ^ mul(h2, B.d[j2 * l + i1]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            /* solve G x = rhs: columns of G as packed vectors for the field's solver */
            var cols = new Uint8Array(olr * F.len(olr));
            for (var c = 0; c < olr; c++) { for (var rr = 0; rr < olr; rr++) { F.set(cols.subarray(c * F.len(olr)), rr, G.d[rr * olr + c]); } }
            var xs = F.solve(cols, pack(rhs), olr);
            if (xs === null) { continue; }
            var sol = mat(ol, r);
            sol.d.set(nibbles(xs, olr));
            var Vs = add(V, mm(T, sol));
            return concat([pack(concat([Vs.d, sol.d])), salt]);
        }
        throw new Error('snova: signing failed');
    }

    function verify(pk, msg, sig) {
        var salt = sig.subarray(SIG_BYTES - 16), Sg = mat(nl, r);
        Sg.d.set(nibbles(sig, nl * r));
        var X = expand_public(pk.subarray(0, 16)), p22 = nibbles(pk.subarray(16), P22_GF), at = { i: 0 }, Ps = [];
        for (var mi = 0; mi < m1; mi++) {
            var P22 = fill(p22, at, o, o), M = mat(nl, nl);
            for (var i = 0; i < nl; i++) {
                for (var j = 0; j < nl; j++) {
                    M.d[i * nl + j] = i < vl ? (j < vl ? X.P11[mi].d[i * vl + j] : X.P12[mi].d[i * ol + j - vl])
                                             : (j < vl ? X.P21[mi].d[(i - vl) * vl + j] : P22.d[(i - vl) * ol + j - vl]);
                }
            }
            Ps.push(M);
        }
        return equal(emulsify(Sg, Ps), target(msg, shake256(pk, 48), salt)) === 1;
    }

    return {
        NAME: 'SNOVA_' + name + (use_aes ? '_AES' : ''),
        PK_BYTES: PK_BYTES,
        SK_BYTES: SK_BYTES,
        SIG_BYTES: SIG_BYTES,

        /**
         * @param {Uint8Array} [seed]  48 bytes: pk_seed (16) || sk_seed (32);
         *                             omitted or null draws fresh ones from
         *                             the platform
         */
        keygen: function (seed) {
            if (seed == null) { seed = secure_random(48); }
            if (!(seed instanceof Uint8Array) || seed.length !== 48) { throw new Error('snova: the seed is 48 bytes'); }
            return keypair(seed);
        },

        /** @param {Uint8Array} [salt]  16 random bytes; omitted or null draws fresh ones from the platform */
        sign: function (sk, msg, salt) {
            if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES) { throw new Error('snova: the private key is ' + SK_BYTES + ' bytes'); }
            if (salt == null) { salt = secure_random(16); }
            if (!(salt instanceof Uint8Array) || salt.length !== 16) { throw new Error('snova: the salt is 16 bytes'); }
            return sign(sk, msg, salt);
        },

        verify: function (pk, msg, sig) {
            if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { return false; }
            if (!(sig instanceof Uint8Array) || sig.length !== SIG_BYTES) { return false; }
            return verify(pk, msg, sig);
        }
    };
}

export var snova_i_b = /* @__PURE__ */ build('I_B', false);
export var snova_i_b_aes = /* @__PURE__ */ build('I_B', true);
export var snova_i_k = /* @__PURE__ */ build('I_K', false);
export var snova_i_k_aes = /* @__PURE__ */ build('I_K', true);
export var snova_i_s = /* @__PURE__ */ build('I_S', false);
export var snova_i_s_aes = /* @__PURE__ */ build('I_S', true);
export var snova_iii_b = /* @__PURE__ */ build('III_B', false);
export var snova_iii_b_aes = /* @__PURE__ */ build('III_B', true);
export var snova_iii_k = /* @__PURE__ */ build('III_K', false);
export var snova_iii_k_aes = /* @__PURE__ */ build('III_K', true);
export var snova_iii_s = /* @__PURE__ */ build('III_S', false);
export var snova_iii_s_aes = /* @__PURE__ */ build('III_S', true);
export var snova_v_b = /* @__PURE__ */ build('V_B', false);
export var snova_v_b_aes = /* @__PURE__ */ build('V_B', true);
export var snova_v_k = /* @__PURE__ */ build('V_K', false);
export var snova_v_k_aes = /* @__PURE__ */ build('V_K', true);
export var snova_v_s = /* @__PURE__ */ build('V_S', false);
export var snova_v_s_aes = /* @__PURE__ */ build('V_S', true);
