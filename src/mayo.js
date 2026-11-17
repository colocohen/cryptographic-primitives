/**
 * MAYO  -  the round-3 submission to NIST's additional signatures (August
 * 2026)
 *
 * UOV with a small oil space, made to work by "whipping". A UOV public key
 * needs an oil space as large as the number of equations m, and that is what
 * makes UOV keys large. MAYO takes o much smaller than m - a key a hundred
 * times smaller - and recovers solvability by signing with k vectors at once:
 * the k copies of the public map are combined with the matrices E_ij,
 * multiplication by powers of z in GF(16)[z]/(f(z)), into one system of m
 * equations in k*o oil unknowns.
 *
 * ROUND 3 changed three things, all here: new MAYO1 and MAYO2 parameters
 * (MAYO2 against the wedge attack), a whipping schedule chosen so that the
 * matrix of powers is MDS, and LINEAR TERMS in the verification equation,
 * P*(s) + L(s) = t, with L derived from the hash of the message and salt so
 * that collision searches no longer give forgeries.
 *
 * KEYS: the compact forms. csk is the seed; cpk is pk_seed and P3. Signing
 * expands the seed; verification expands pk_seed into P1 and P2 by AES-128.
 */

import { shake256 } from './sha3.js';
import { aes_ctr, aes_block_fn } from './aes.js';
import { concat, secure_random } from './commons/bytes.js';
import { equal } from './commons/ct.js';
import { GF16 } from './commons/gf2k.js';
import { ov_map } from './commons/ov_map.js';

var F = GF16;

/*
 * The whipping schedules: Z[i][j] is the power of z that E_ij multiplies by.
 * Symmetric, its upper triangle a permutation of 0 .. k(k+1)/2 - 1, and MDS.
 */
var Z = {
    5: [[11, 13, 3, 4, 6], [13, 0, 14, 10, 2], [3, 14, 8, 1, 5], [4, 10, 1, 12, 9], [6, 2, 5, 9, 7]],
    10: [[10, 25, 7, 44, 40, 24, 12, 32, 5, 27], [25, 6, 45, 50, 19, 0, 11, 14, 37, 52], [7, 45, 51, 16, 42, 30, 53, 8, 21, 4],
        [44, 50, 16, 15, 39, 26, 48, 54, 23, 34], [40, 19, 42, 39, 22, 33, 1, 35, 41, 18], [24, 0, 30, 26, 33, 13, 46, 17, 2, 47],
        [12, 11, 53, 48, 1, 46, 36, 20, 49, 43], [32, 14, 8, 54, 35, 17, 20, 38, 29, 9], [5, 37, 21, 23, 41, 2, 49, 29, 3, 31],
        [27, 52, 4, 34, 18, 47, 43, 9, 31, 28]],
    11: [[35, 13, 39, 32, 4, 7, 40, 14, 43, 62, 64], [13, 55, 42, 11, 63, 19, 58, 49, 36, 12, 20], [39, 42, 6, 15, 57, 47, 16, 34, 44, 46, 50],
        [32, 11, 15, 18, 5, 21, 28, 10, 51, 24, 31], [4, 63, 57, 5, 38, 0, 56, 29, 54, 60, 23], [7, 19, 47, 21, 0, 22, 27, 61, 3, 48, 8],
        [40, 58, 16, 28, 56, 27, 37, 45, 30, 1, 17], [14, 49, 34, 10, 29, 61, 45, 26, 52, 59, 41], [43, 36, 44, 51, 54, 3, 30, 52, 25, 9, 2],
        [62, 12, 46, 24, 60, 48, 1, 59, 9, 53, 65], [64, 20, 50, 31, 23, 8, 17, 41, 2, 65, 33]],
    12: [[62, 30, 52, 53, 24, 0, 25, 12, 71, 20, 57, 32], [30, 7, 37, 55, 43, 70, 31, 47, 35, 9, 69, 15], [52, 37, 64, 26, 76, 45, 54, 10, 40, 34, 11, 19],
        [53, 55, 26, 61, 16, 60, 5, 18, 42, 17, 8, 75], [24, 43, 76, 16, 41, 27, 6, 2, 4, 51, 68, 38], [0, 70, 45, 60, 27, 63, 22, 49, 23, 1, 21, 48],
        [25, 31, 54, 5, 6, 22, 14, 29, 44, 65, 77, 72], [12, 47, 10, 18, 2, 49, 29, 58, 67, 59, 39, 56], [71, 35, 40, 42, 4, 23, 44, 67, 33, 73, 36, 74],
        [20, 9, 34, 17, 51, 1, 65, 59, 73, 28, 46, 3], [57, 69, 11, 8, 68, 21, 77, 39, 36, 46, 50, 13], [32, 15, 19, 75, 38, 48, 72, 56, 74, 3, 13, 66]]
};

/*
 * (n, m, o, k), the seed/salt length, the message digest length, and f(z) =
 * z^m + c3 z^3 + c2 z^2 + c1 z + c0 as [c0, c1, c2, c3] (GF(16) elements as
 * integers, x = 2).
 */
var SETS = {
    mayo1: { n: 88, m: 80, o: 8, k: 10, salt: 24, digest: 32, f: [2, 0, 4, 2] },
    mayo2: { n: 86, m: 64, o: 13, k: 5, salt: 24, digest: 32, f: [8, 0, 2, 8] },
    mayo3: { n: 118, m: 108, o: 10, k: 11, salt: 32, digest: 48, f: [8, 0, 1, 7] },
    mayo5: { n: 154, m: 142, o: 12, k: 12, salt: 40, digest: 64, f: [4, 0, 8, 1] }
};

function tri(k) { return k * (k + 1) / 2; }

function build(name) {
    var S = SETS[name], n = S.n, m = S.m, o = S.o, k = S.k, v = n - o, Zk = Z[k], f = S.f;
    var OB = m / 2, VB = F.len(v), KO = k * o;
    var O_BYTES = F.len(v * o), R_BYTES = F.len(KO), P1_BYTES = OB * tri(v), P2_BYTES = OB * v * o, P3_BYTES = OB * tri(o);
    var SIG_BYTES = F.len(k * n) + S.salt, PK_BYTES = 16 + P3_BYTES, SK_BYTES = S.salt;
    var Q = ov_map(F, v, o, OB);

    function unpack(b, len) { var r = new Uint8Array(len); for (var i = 0; i < len; i++) { r[i] = F.get(b, i); } return r; }

    /* (pk_seed, O unpacked row-major, P1, P2) from the secret seed */
    function expand(seed_sk) {
        var s = shake256(seed_sk, 16 + O_BYTES), seed_pk = s.slice(0, 16), Ou = unpack(s.subarray(16), v * o);
        var p = expand_p(seed_pk);
        return { seed_pk: seed_pk, Ou: Ou, P1: p.P1, P2: p.P2 };
    }
    function expand_p(seed_pk) {
        var p = aes_ctr(seed_pk, new Uint8Array(16), new Uint8Array(P1_BYTES + P2_BYTES));
        return { P1: p.subarray(0, P1_BYTES), P2: p.subarray(P1_BYTES) };
    }

    /*
     * t and Lambda from SHAKE256(M_digest || salt). Lambda (m x n, the linear
     * terms) is AES-128 keyed by the hash, in a counter mode whose block
     * index is XORed - not added - into the last bytes of the hashed IV.
     * Column c of Lambda is a packed m-vector, so Lambda is a vector of n
     * batches as it stands.
     */
    function target(h_msg, salt) {
        var hb = shake256(concat([h_msg, salt]), OB + 32), enc = aes_block_fn(hb.slice(OB, OB + 16)), iv = hb.subarray(OB + 16, OB + 32);
        var L = new Uint8Array(m * n / 2), blk = new Uint8Array(16);
        for (var c = 0, off = 0; off < L.length; c++, off += 16) {
            blk.set(iv);
            blk[12] ^= c >>> 24; blk[13] ^= (c >>> 16) & 0xff; blk[14] ^= (c >>> 8) & 0xff; blk[15] ^= c & 0xff;
            var out = new Uint8Array(16);
            enc(blk, 0, out, 0);
            L.set(out.subarray(0, Math.min(16, L.length - off)), off);
        }
        return { t: unpack(hb, m), Lambda: L };
    }

    /* u <- u * z^e in GF(16)[z]/(f), u an unpacked m-vector, in place */
    function times_z(u, e) {
        for (var s = 0; s < e; s++) {
            var top = u[m - 1];
            for (var i = m - 1; i > 0; i--) { u[i] = u[i - 1]; }
            u[0] = 0;
            for (var j = 0; j < 4; j++) { u[j] ^= F.mul(top, f[j]); }
        }
        return u;
    }
    /* acc += E_e b for a packed batch b */
    function add_e(acc, b, e) {
        var u = times_z(unpack(b, m), e);
        for (var i = 0; i < m; i++) { acc[i] ^= u[i]; }
    }

    /*
     * SampleSolution: x = r + x' with A x' = y - A r, x' zero off the pivot
     * columns of A's echelon form - the solution the specification's
     * back-substitution produces - or null when A has rank below m.
     * Gauss-Jordan over the augmented matrix, with the row additions masked.
     */
    function sample_solution(A, y, r) {
        var w = KO + 1, B = new Uint8Array(m * w), i, j, c;
        for (i = 0; i < m; i++) {
            var acc = y[i];
            for (j = 0; j < KO; j++) { B[i * w + j] = A[i * KO + j]; acc ^= F.mul(A[i * KO + j], r[j]); }
            B[i * w + KO] = acc;
        }
        var piv = new Int32Array(m).fill(-1), row = 0;
        for (c = 0; c < KO && row < m; c++) {
            for (i = row + 1; i < m; i++) {
                var take = (B[row * w + c] === 0 ? 1 : 0) & (B[i * w + c] !== 0 ? 1 : 0);
                for (j = c; j < w; j++) { B[row * w + j] ^= B[i * w + j] & -take; }
            }
            var p = B[row * w + c];
            if (p === 0) { continue; }
            var pi = F.inv(p);
            for (j = c; j < w; j++) { B[row * w + j] = F.mul(pi, B[row * w + j]); }
            for (i = 0; i < m; i++) {
                if (i === row) { continue; }
                var e = B[i * w + c];
                for (j = c; j < w; j++) { B[i * w + j] ^= F.mul(e, B[row * w + j]); }
            }
            piv[row++] = c;
        }
        if (row < m) { return null; }
        var x = new Uint8Array(r);
        for (i = 0; i < m; i++) { x[piv[i]] ^= B[i * w + KO]; }
        return x;
    }

    /*
     * The preimage sampler: s with P*(s) + Lambda(s) = t, Lambda the linear
     * terms (null for none - the bare trapdoor). vseed(ctr) gives attempt
     * ctr's vinegar and randomness, k*VB + R_BYTES bytes.
     */
    function sample(E, t, Lam, vseed) {
        var L = Q.l_p3(E.P1, E.P2, E.Ou, false).L;
        for (var ctr = 0; ctr < 256; ctr++) {
            var V = vseed(ctr);
            var vs = [], Ms = [], Ws = [], i, j, a, b;
            for (i = 0; i < k; i++) {
                var vi = V.subarray(i * VB, (i + 1) * VB);
                vs.push(vi);
                Ms.push(Q.x_mat(L, 0, vi, v, o));          /* M_i: column a = sum_b v_i[b] L(b, a) */
                Ws.push(Q.x_ut(E.P1, 0, vi, v));           /* v_i^T P1 */
            }
            if (Lam) {
                /* M_0 += Lambda_v O + Lambda_o */
                for (a = 0; a < o; a++) {
                    for (b = 0; b < v; b++) { F.madd(Ms[0], a * OB, Lam, b * OB, E.Ou[b * o + a], OB); }
                    F.madd(Ms[0], a * OB, Lam, (v + a) * OB, 1, OB);
                }
            }
            var r = unpack(V.subarray(k * VB), KO);
            var y = new Uint8Array(t), A = new Uint8Array(m * KO);
            for (i = 0; i < k; i++) {
                if (Lam) { add_e(y, Q.dot(new Uint8Array(OB), Lam, vs[i], v), Zk[i][0]); }
                for (j = i; j < k; j++) {
                    var u = Q.dot(new Uint8Array(OB), Ws[i], vs[j], v);
                    if (i !== j) { Q.dot(u, Ws[j], vs[i], v); }
                    add_e(y, u, Zk[i][j]);
                    for (a = 0; a < o; a++) {
                        var cj = times_z(unpack(Ms[j].subarray(a * OB), m), Zk[i][j]);
                        for (b = 0; b < m; b++) { A[b * KO + i * o + a] ^= cj[b]; }
                        if (i !== j) {
                            var ci = times_z(unpack(Ms[i].subarray(a * OB), m), Zk[i][j]);
                            for (b = 0; b < m; b++) { A[b * KO + j * o + a] ^= ci[b]; }
                        }
                    }
                }
            }
            var x = sample_solution(A, y, r);
            if (x === null) { continue; }
            /* s_i = (v_i + O x_i, x_i) */
            var sig = new Uint8Array(F.len(k * n));
            for (i = 0; i < k; i++) {
                for (b = 0; b < v; b++) {
                    var e = F.get(vs[i], b);
                    for (a = 0; a < o; a++) { e ^= F.mul(E.Ou[b * o + a], x[i * o + a]); }
                    F.set(sig, i * n + b, e);
                }
                for (a = 0; a < o; a++) { F.set(sig, i * n + v + a, x[i * o + a]); }
            }
            return sig;
        }
        throw new Error('mayo: no solvable system in 256 attempts');
    }

    function sign_with(seed_sk, E, msg, R) {
        var h_msg = shake256(msg, S.digest), salt = shake256(concat([h_msg, R, seed_sk]), S.salt);
        var T = target(h_msg, salt);
        var s = sample(E, T.t, T.Lambda, function (ctr) {
            return shake256(concat([h_msg, salt, seed_sk, new Uint8Array([ctr])]), k * VB + R_BYTES);
        });
        return concat([s, salt]);
    }

    /* P*(s) + Lambda(s), unpacked, for s the k*n packed GF(16) elements; Lambda null for none */
    function evaluate(pk, s, Lam) {
        var p = expand_p(pk.subarray(0, 16)), P3 = pk.subarray(16);
        var ss = [], ws = [], i, j;
        for (i = 0; i < k; i++) {
            var si = new Uint8Array(F.len(n));
            for (var c = 0; c < n; c++) { F.set(si, c, F.get(s, i * n + c)); }
            ss.push(si);
            ws.push(Q.s_p(p.P1, p.P2, P3, si));
        }
        var y = new Uint8Array(m);
        for (i = 0; i < k; i++) {
            if (Lam) { add_e(y, Q.dot(new Uint8Array(OB), Lam, ss[i], n), Zk[i][0]); }
            for (j = i; j < k; j++) {
                var u = Q.dot(new Uint8Array(OB), ws[i], ss[j], n);
                if (i !== j) { Q.dot(u, ws[j], ss[i], n); }
                add_e(y, u, Zk[i][j]);
            }
        }
        return y;
    }

    function check_target(t) {
        if (!(t instanceof Uint8Array) || t.length !== m) { throw new Error('mayo: a target is ' + m + ' GF(16) elements'); }
        for (var i = 0; i < m; i++) { if (t[i] > 15) { throw new Error('mayo: a target element is a nibble, 0..15'); } }
    }

    return {
        NAME: 'MAYO_' + name.slice(4),
        PK_BYTES: PK_BYTES,
        SK_BYTES: SK_BYTES,
        SIG_BYTES: SIG_BYTES,

        /**
         * @param {Uint8Array} [seed]  the secret seed, SK_BYTES long; the compact
         *                             secret key is the seed itself. Omitted or
         *                             null draws fresh ones from the platform
         */
        keygen: function (seed) {
            if (seed == null) { seed = secure_random(SK_BYTES); }
            if (!(seed instanceof Uint8Array) || seed.length !== SK_BYTES) { throw new Error('mayo: the seed is ' + SK_BYTES + ' bytes'); }
            var E = expand(seed);
            return { pk: concat([E.seed_pk, Q.l_p3(E.P1, E.P2, E.Ou, true).P3]), sk: seed.slice() };
        },

        /**
         * @param {Uint8Array} [rnd]  S.salt random bytes (R): the salt is
         *                            SHAKE256(M_digest || R || seed), so all
         *                            zeros gives deterministic signatures;
         *                            omitted or null draws fresh ones from
         *                            the platform
         */
        sign: function (sk, msg, rnd) {
            if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES) { throw new Error('mayo: the private key is ' + SK_BYTES + ' bytes'); }
            if (rnd == null) { rnd = secure_random(S.salt); }
            if (!(rnd instanceof Uint8Array) || rnd.length !== S.salt) { throw new Error('mayo: rnd is ' + S.salt + ' bytes'); }
            return sign_with(sk, expand(sk), msg, rnd);
        },

        verify: function (pk, msg, sig) {
            if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { return false; }
            if (!(sig instanceof Uint8Array) || sig.length !== SIG_BYTES) { return false; }
            var salt = sig.subarray(SIG_BYTES - S.salt), T = target(shake256(msg, S.digest), salt);
            var y = evaluate(pk, sig.subarray(0, SIG_BYTES - S.salt), T.Lambda);
            return equal(y, T.t) === 1;
        },

        /**
         * ⚠ HAZMAT - THE BARE TRAPDOOR, without the hash, the salt or the
         * linear terms: P*(s) = t for a target t chosen by the caller. A
         * signature scheme built on it must make the targets unpredictable
         * itself (pomfrit.js: the blind signatures, whose targets are a
         * random-oracle output plus a committed random string). Signing
         * arbitrary chosen targets with it is NOT MAYO.
         *
         * t: m GF(16) elements, unpacked (0..15). s: the k*n elements, packed.
         */
        trapdoor: {
            M: m, N: n, K: k, S_BYTES: F.len(k * n),
            /*
             * The public map as data, for a proof system that evaluates it on
             * committed values: P1, P2, P3 (batches of m packed coefficients,
             * commons/ov_map.js's layout), v, o, the whipping schedule Z
             * (E_ij multiplies by z^Z[i][j]) and f(z)'s low coefficients.
             */
            public_map: function (pk) {
                if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { throw new Error('mayo: the public key is ' + PK_BYTES + ' bytes'); }
                var p = expand_p(pk.subarray(0, 16));
                return { P1: p.P1, P2: p.P2, P3: pk.subarray(16), v: v, o: o, n: n, m: m, k: k, OB: OB, Z: Zk, f: f, ut: Q.ut };
            },
            /** P*(s) for a public key, unpacked */
            evaluate: function (pk, s) {
                if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { throw new Error('mayo: the public key is ' + PK_BYTES + ' bytes'); }
                if (!(s instanceof Uint8Array) || s.length !== F.len(k * n)) { throw new Error('mayo: s is ' + F.len(k * n) + ' bytes'); }
                return evaluate(pk, s, null);
            },
            /*
             * a preimage of t; rnd (S.salt bytes) randomizes it, all zeros
             * gives one fixed preimage per t, and omitted or null draws fresh
             * ones from the platform
             */
            sample: function (sk, t, rnd) {
                if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES) { throw new Error('mayo: the private key is ' + SK_BYTES + ' bytes'); }
                if (rnd == null) { rnd = secure_random(S.salt); }
                if (!(rnd instanceof Uint8Array) || rnd.length !== S.salt) { throw new Error('mayo: rnd is ' + S.salt + ' bytes'); }
                check_target(t);
                var E = expand(sk), tb = concat([new Uint8Array([0x54]), t]);
                return sample(E, t, null, function (ctr) {
                    return shake256(concat([tb, rnd, sk, new Uint8Array([ctr])]), k * VB + R_BYTES);
                });
            }
        }
    };
}

export var mayo1 = /* @__PURE__ */ build('mayo1');
export var mayo2 = /* @__PURE__ */ build('mayo2');
export var mayo3 = /* @__PURE__ */ build('mayo3');
export var mayo5 = /* @__PURE__ */ build('mayo5');
