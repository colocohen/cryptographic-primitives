/**
 * QR-UOV  -  the round-3 submission to NIST's additional signatures (v3.0,
 * September 2026)
 *
 * UOV over an extension field, read back down to the base field. The public
 * key's matrices are taken over F_{q^L} = F_q[x]/(x^L - fc x^fe - fc0)
 * (blocks of quotient-ring elements, hence the name), and each equation is
 * one fixed coefficient of the extension-field value. The public key shrinks
 * by a factor L, since an L x L block over F_q is now one element. q is a
 * small Mersenne prime (7, 31 or 127): field elements are 3 to 7 bits.
 *
 * ROUND 3: signing refuses systems whose rank is below m - delta (and
 * otherwise draws salts until the system is consistent, so rank-deficient
 * systems are SOLVED, with the free variables from a seed), and a signature
 * is replaced by its negation when that is lexicographically smaller -
 * verification insists on the smaller one, closing the trivial s -> -s
 * forgery against strong unforgeability.
 *
 * THE PARAMETER SETS: (security, q, L) in {1, 3, 5} x {(127, 3), (127, 10),
 * (31, 3), (31, 10), (7, 10)} - the first two are the round-3 proposal, the
 * others its appendix - each with the public matrices expanded by AES-128
 * (_aes, the reference's default) or by SHAKE128 (_shake).
 *
 * KEYS: sk = seed_sk (32 bytes); pk = seed_pk || P3, seed_pk derived from
 * seed_sk. sign takes three 32-byte seeds, for the vinegar values, the salt
 * stream and the free oil values, in that order.
 */

import { shake128, shake256 } from './sha3.js';
import { aes_ctr } from './aes.js';
import { concat, secure_random } from './commons/bytes.js';

/* [security, q, L, v, m, fc, fc0, fe, tau_n1, tau_n2, tau_v, tau_m] */
var SETS = {
    '1q127L3': [1, 127, 3, 156, 54, 1, 1, 1, 4267, 2916, 192, 82],
    '1q127L10': [1, 127, 10, 540, 60, 2, 1, 3, 15135, 3357, 594, 89],
    '1q31L3': [1, 31, 3, 165, 60, 1, 1, 1, 4959, 3571, 226, 104],
    '1q31L10': [1, 31, 10, 600, 70, 5, 1, 3, 19242, 4518, 704, 116],
    '1q7L10': [1, 7, 10, 740, 100, 2, 1, 1, 32629, 8947, 1024, 201],
    '3q127L3': [3, 127, 3, 228, 78, 1, 1, 1, 9020, 6123, 283, 120],
    '3q127L10': [3, 127, 10, 820, 90, 2, 1, 3, 34603, 7600, 902, 134],
    '3q31L3': [3, 31, 3, 246, 87, 1, 1, 1, 10878, 7655, 338, 154],
    '3q31L10': [3, 31, 10, 890, 100, 5, 1, 3, 41974, 9507, 1046, 169],
    '3q7L10': [3, 7, 10, 1100, 140, 2, 1, 1, 71432, 18461, 1526, 289],
    '5q127L3': [5, 127, 3, 306, 105, 1, 1, 1, 16144, 11018, 380, 162],
    '5q127L10': [5, 127, 10, 1040, 110, 2, 1, 3, 55473, 11760, 1148, 168],
    '5q31L3': [5, 31, 3, 324, 114, 1, 1, 1, 18738, 13145, 447, 203],
    '5q31L10': [5, 31, 10, 1120, 120, 5, 1, 3, 66236, 14326, 1324, 210],
    '5q7L10': [5, 7, 10, 1490, 190, 2, 1, 1, 130305, 33694, 2065, 391]
};
var DELTA = { 127: 2, 31: 3, 7: 4 };

function be16(x) { return new Uint8Array([x >> 8, x & 0xff]); }

function build(name, prg_aes) {
    var P = SETS[name], sec = P[0], q = P[1], L = P[2], v = P[3], m = P[4], fc = P[5], fc0 = P[6], fe = P[7];
    var tau_n1 = P[8], tau_n2 = P[9], tau_v = P[10], tau_m = P[11];
    var n = v + m, V = v / L, M = m / L, N = n / L, LOG = q === 127 ? 7 : q === 31 ? 5 : 3;
    var n1 = L * V * (V + 1) / 2, n2 = L * V * M, P3_EQ = L * M * (M + 1) / 2;
    var SALT = sec === 1 ? 16 : sec === 3 ? 24 : 32, delta = DELTA[q];
    var bytes_for = function (k) { return (LOG * k + 7) >> 3; };
    var CHUNK = 8, P3_BYTES = 0;
    for (var e0 = 0; e0 < m; e0 += CHUNK) { P3_BYTES += bytes_for(Math.min(CHUNK, m - e0) * P3_EQ); }
    var PK_BYTES = 16 + P3_BYTES, SIG_BYTES = SALT + bytes_for(n);
    var perm = function (t) { return t <= fe - 1 ? fe - 1 - t : L + fe - 1 - t; }, perm0 = perm(0);

    function inv(a) { var r = 1, b = a, e = q - 2; while (e > 0) { if (e & 1) { r = (r * b) % q; } b = (b * b) % q; e >>= 1; } return r; }

    /* each byte masked to log q bits; the value q is rejected and replaced from the bytes past `len` */
    function reject(buf, len) {
        var d = new Uint8Array(buf), i;
        for (i = 0; i < d.length; i++) { d[i] &= q; }
        var aux = len;
        while (aux < d.length && d[aux] === q) { aux++; }
        for (i = 0; i < len; i++) {
            if (d[i] === q) {
                if (aux < d.length) { d[i] = d[aux++]; while (aux < d.length && d[aux] === q) { aux++; } } else { d[i] = 0; }
            }
        }
        return d.subarray(0, len);
    }

    /* the public matrices of equation eq: pi1 at index 2 eq, pi2 at 2 eq + 1 */
    function prg(seed, index, len) {
        if (prg_aes) {
            var iv = new Uint8Array(16); iv[6] = index >> 8; iv[7] = index & 0xff;
            return aes_ctr(seed, iv, new Uint8Array(len));
        }
        return shake128(concat([seed, be16(index)]), len);
    }

    /* z = sum over i < len of a_i b_i in F_{q^L}, a and b runs of L-coefficient elements */
    var acc = new Float64Array(2 * L - 1);
    function dot(z, zo, a, ao, b, bo, len) {
        acc.fill(0);
        for (var i = 0; i < len; i++) {
            var ai = ao + i * L, bi = bo + i * L;
            for (var j = 0; j < L; j++) {
                var x = a[ai + j];
                if (x === 0) { continue; }
                for (var k = 0; k < L; k++) { acc[j + k] += x * b[bi + k]; }
            }
        }
        for (var t = 2 * L - 2; t >= L; t--) {
            var c = acc[t] % q;
            acc[t - L] += fc0 * c;
            acc[t - L + fe] += fc * c;
        }
        for (var u = 0; u < L; u++) { z[zo + u] = acc[u] % q; }
    }

    /* symmetric V x V from its packed upper triangle */
    function symm(packed, d) {
        var S = new Uint8Array(d * d * L), off = 0;
        for (var i = 0; i < d; i++) {
            for (var j = i; j < d; j++) {
                S.set(packed.subarray(off, off + L), (i * d + j) * L);
                S.set(packed.subarray(off, off + L), (j * d + i) * L);
                off += L;
            }
        }
        return S;
    }
    function pi1_of(seed, eq) { return symm(reject(prg(seed, 2 * eq, tau_n1), n1), V); }
    function pi2_of(seed, eq) { return reject(prg(seed, 2 * eq + 1, tau_n2), n2); }   /* V x M */
    /* the transpose of a V x M matrix of elements */
    function transpose_vm(a) {
        var t = new Uint8Array(M * V * L);
        for (var i = 0; i < V; i++) { for (var j = 0; j < M; j++) { t.set(a.subarray((i * M + j) * L, (i * M + j + 1) * L), (j * V + i) * L); } }
        return t;
    }
    /* dst = A x for a rows x cols matrix A of elements */
    function mat_vec(A, x, rows, cols) {
        var out = new Uint8Array(rows * L);
        for (var i = 0; i < rows; i++) { dot(out, i * L, A, i * cols * L, x, 0, cols); }
        return out;
    }

    function seed_pk_of(seed_sk) { return shake256(concat([seed_sk, be16(1)]), 16); }
    function sd_of(seed_sk) { return reject(shake256(concat([seed_sk, be16(0)]), tau_n2), n2); }

    /* elements in LOG bits each, least significant first; P3 in chunks of 8 equations, each byte-aligned */
    function store(vals) {
        var out = new Uint8Array(bytes_for(vals.length)), o = 0, a = 0, bits = 0;
        for (var i = 0; i < vals.length; i++) {
            a |= vals[i] << bits; bits += LOG;
            while (bits >= 8) { out[o++] = a & 0xff; a >>>= 8; bits -= 8; }
        }
        if (bits > 0) { out[o] = a; }
        return out;
    }
    function load(src, count) {
        var used = (LOG * count) & 7, len = bytes_for(count);
        if (src.length < len || (used && (src[len - 1] & ~((1 << used) - 1) & 0xff))) { return null; }
        var out = new Uint8Array(count), i = 0, a = 0, bits = 0, p = 0;
        for (; i < count; i++) {
            while (bits < LOG) { a |= src[p++] << bits; bits += 8; }
            out[i] = a & q; a >>>= LOG; bits -= LOG;
            if (out[i] === q) { return null; }
        }
        return out;
    }

    function hash_t(mu, salt) { return reject(shake256(concat([mu, salt]), tau_m), m); }

    function keygen(seed_sk) {
        var seed_pk = seed_pk_of(seed_sk), sd = sd_of(seed_sk), sdt = transpose_vm(sd);
        var chunks = [], chunk = [], tmp = new Uint8Array(L);
        var sp1 = new Uint8Array(M * V * L), sp2 = new Uint8Array(M * M * L);
        for (var eq = 0; eq < m; eq++) {
            var pi1 = pi1_of(seed_pk, eq), pi2t = transpose_vm(pi2_of(seed_pk, eq)), i, j, k;
            for (i = 0; i < M; i++) { for (j = 0; j < V; j++) { dot(sp1, (i * V + j) * L, sdt, i * V * L, pi1, j * V * L, V); } }
            for (i = 0; i < M; i++) { for (j = 0; j < M; j++) { dot(sp2, (i * M + j) * L, sdt, i * V * L, pi2t, j * V * L, V); } }
            /* P3 = Upper(-sd^T pi1 sd + sd^T pi2 + (sd^T pi2)^T) */
            for (i = 0; i < M; i++) {
                for (j = i; j < M; j++) {
                    dot(tmp, 0, sp1, i * V * L, sdt, j * V * L, V);
                    for (k = 0; k < L; k++) { chunk.push((2 * q - tmp[k] + sp2[(i * M + j) * L + k] + sp2[(j * M + i) * L + k]) % q); }
                }
            }
            if ((eq + 1) % CHUNK === 0 || eq === m - 1) { chunks.push(store(chunk)); chunk = []; }
        }
        return concat([seed_pk].concat(chunks));
    }

    function sign(seed_sk, msg, seed_y, seed_r, seed_sol) {
        var seed_pk = seed_pk_of(seed_sk), sd = sd_of(seed_sk), sdt = transpose_vm(sd);
        var y = reject(shake256(seed_y, tau_v), v);
        /* the linear system in the oil variables, and its constant part u */
        var A = new Uint8Array(m * m), u = new Uint8Array(m), yy = new Uint8Array(L), i, k;
        for (var eq = 0; eq < m; eq++) {
            var pi1y = mat_vec(pi1_of(seed_pk, eq), y, V, V), pi2t = transpose_vm(pi2_of(seed_pk, eq));
            dot(yy, 0, y, 0, pi1y, 0, V);
            var a1 = mat_vec(sdt, pi1y, M, V), a2 = mat_vec(pi2t, y, M, V);
            for (i = 0; i < M; i++) {
                for (k = 0; k < L; k++) {
                    var f = (2 * ((a2[i * L + k] - a1[i * L + k] + q) % q)) % q;
                    A[eq * m + i * L + perm(k)] = f;
                }
            }
            u[eq] = yy[perm0];
        }
        var mu = shake256(concat([seed_pk, msg]), 64);
        var free = reject(shake256(seed_sol, tau_m), m);
        var E = echelon(A);
        if (E.rank < m - delta) { return null; }
        /* salts from one SHAKE256 stream over seed_r, until the system is consistent */
        for (var c = 0; ; c++) {
            var salt = shake256(seed_r, (c + 1) * SALT).subarray(c * SALT), t = hash_t(mu, salt);
            var rhs = new Uint8Array(m);
            for (i = 0; i < m; i++) { rhs[i] = (t[i] - u[i] + q) % q; }
            var oil = solve(E, rhs, free);
            if (oil === null) { continue; }
            /* s = (y - sd oil, oil), then the smaller of s and -s */
            var sdo = mat_vec(sd, oil, V, M), s = new Uint8Array(n);
            for (i = 0; i < v; i++) { s[i] = (y[i] - sdo[i] + q) % q; }
            s.set(oil, v);
            if (!canonical(s)) { for (i = 0; i < n; i++) { if (s[i] !== 0) { s[i] = q - s[i]; } } }
            return concat([salt, store(s)]);
        }
    }

    function canonical(s) {
        for (var i = 0; i < s.length; i++) { if (s[i] !== 0) { return s[i] <= (q - 1) >> 1; } }
        return true;
    }

    /*
     * Gaussian elimination of the m x m system: the pivot columns (each the
     * first column, from the left, with a non-zero entry among the rows not
     * yet used) and the reduced rows. The solution then puts the free
     * values on the other columns, highest column first, and back-
     * substitutes - the reference's linsys_sample_solution, which does the
     * same with an LU factorisation.
     */
    function echelon(A0) {
        var R = [], i, j, c;
        for (i = 0; i < m; i++) { R.push(Array.from(A0.subarray(i * m, (i + 1) * m))); }
        var ids = R.map(function (_, k) { return k; }), piv = [], row = 0, ops = [];
        for (c = 0; c < m && row < m; c++) {
            var p = -1;
            for (i = row; i < m; i++) { if (R[i][c] !== 0) { p = i; break; } }
            if (p < 0) { continue; }
            var t = R[p]; R[p] = R[row]; R[row] = t;
            var ti = ids[p]; ids[p] = ids[row]; ids[row] = ti;
            var pv = inv(R[row][c]);
            for (j = c; j < m; j++) { R[row][j] = (R[row][j] * pv) % q; }
            for (i = row + 1; i < m; i++) {
                var f = R[i][c];
                if (f === 0) { continue; }
                for (j = c; j < m; j++) { R[i][j] = (R[i][j] + (q - f) * R[row][j]) % q; }
            }
            piv.push(c);
            row++;
        }
        return { rank: row, rows: R, piv: piv, A: A0 };
    }

    /* the solution with the given free values, or null when rhs is outside the column space */
    function solve(E, rhs, free) {
        /* redo the row operations on rhs (Gauss-Jordan on an augmented copy is simpler and the same) */
        var w = m + 1, B = [], i, j, c, r;
        for (i = 0; i < m; i++) { var rowv = Array.from(E.A.subarray(i * m, (i + 1) * m)); rowv.push(rhs[i]); B.push(rowv); }
        var row = 0, piv = [];
        for (c = 0; c < m && row < m; c++) {
            var p = -1;
            for (i = row; i < m; i++) { if (B[i][c] !== 0) { p = i; break; } }
            if (p < 0) { continue; }
            var t = B[p]; B[p] = B[row]; B[row] = t;
            var pv = inv(B[row][c]);
            for (j = c; j < w; j++) { B[row][j] = (B[row][j] * pv) % q; }
            for (i = row + 1; i < m; i++) {
                var f = B[i][c];
                if (f === 0) { continue; }
                for (j = c; j < w; j++) { B[i][j] = (B[i][j] + (q - f) * B[row][j]) % q; }
            }
            piv.push(c); row++;
        }
        for (i = row; i < m; i++) { if (B[i][m] !== 0) { return null; } }
        var x = new Uint8Array(m), isp = new Int32Array(m).fill(-1), fp = 0;
        for (r = 0; r < row; r++) { isp[piv[r]] = r; }
        for (c = m - 1; c >= 0; c--) {
            if (isp[c] < 0) { x[c] = free[fp++]; continue; }
            r = isp[c];
            var s = B[r][m];
            for (j = c + 1; j < m; j++) { s = (s + (q - B[r][j]) * x[j]) % q; }
            x[c] = s;
        }
        return x;
    }

    function verify(pk, msg, sig) {
        var seed_pk = pk.subarray(0, 16), salt = sig.subarray(0, SALT), s = load(sig.subarray(SALT), n);
        if (s === null || !canonical(s)) { return false; }
        var mu = shake256(concat([seed_pk, msg]), 64), t = hash_t(mu, salt);
        var vin = s.subarray(0, v), oil = s.subarray(v), ok = true, off = 16;
        var e1 = new Uint8Array(L), e2 = new Uint8Array(L), e3 = new Uint8Array(L);
        for (var eq0 = 0; eq0 < m; eq0 += CHUNK) {
            var ce = Math.min(CHUNK, m - eq0), p3 = load(pk.subarray(off), ce * P3_EQ);
            off += bytes_for(ce * P3_EQ);
            if (p3 === null) { return false; }
            for (var k = 0; k < ce; k++) {
                var eq = eq0 + k;
                dot(e1, 0, vin, 0, mat_vec(pi1_of(seed_pk, eq), vin, V, V), 0, V);
                dot(e2, 0, vin, 0, mat_vec(pi2_of(seed_pk, eq), oil, V, M), 0, V);
                dot(e3, 0, oil, 0, mat_vec(symm(p3.subarray(k * P3_EQ), M), oil, M, M), 0, M);
                ok = ok && ((e1[perm0] + 2 * e2[perm0] + e3[perm0]) % q === t[eq]);
            }
        }
        return ok;
    }

    return {
        NAME: 'qruov' + sec + 'q' + q + 'l' + L + 'v' + v + 'm' + m + (prg_aes ? 'aes' : 'shake'),
        PK_BYTES: PK_BYTES,
        SK_BYTES: 32,
        SIG_BYTES: SIG_BYTES,

        /**
         * @param {Uint8Array} [seed]  seed_sk, 32 bytes; it is the private key.
         *                             Omitted or null draws fresh ones from the
         *                             platform
         */
        keygen: function (seed) {
            if (seed == null) { seed = secure_random(32); }
            if (!(seed instanceof Uint8Array) || seed.length !== 32) { throw new Error('qruov: the seed is 32 bytes'); }
            return { pk: keygen(seed), sk: seed.slice() };
        },

        /**
         * @param {Uint8Array} [rnd]  96 bytes: seed_y, seed_r, seed_sol;
         *                            omitted or null draws fresh ones from
         *                            the platform
         * @return {Uint8Array} the signature; with a caller's rnd, throws in
         *         the rare case (rank below m - delta) where the reference
         *         fails and a fresh rnd is needed - with drawn ones, draws
         *         again instead
         */
        sign: function (sk, msg, rnd) {
            if (!(sk instanceof Uint8Array) || sk.length !== 32) { throw new Error('qruov: the private key is 32 bytes'); }
            var drawn = rnd == null;
            if (drawn) { rnd = secure_random(96); }
            if (!(rnd instanceof Uint8Array) || rnd.length !== 96) { throw new Error('qruov: rnd is 96 bytes'); }
            var s = sign(sk, msg, rnd.subarray(0, 32), rnd.subarray(32, 64), rnd.subarray(64));
            while (s === null && drawn) {
                rnd = secure_random(96);
                s = sign(sk, msg, rnd.subarray(0, 32), rnd.subarray(32, 64), rnd.subarray(64));
            }
            if (s === null) { throw new Error('qruov: the system has rank below m - delta; sign again with fresh randomness'); }
            return s;
        },

        verify: function (pk, msg, sig) {
            if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { return false; }
            if (!(sig instanceof Uint8Array) || sig.length !== SIG_BYTES) { return false; }
            return verify(pk, msg, sig);
        }
    };
}

export var qruov1q127l3_aes = /* @__PURE__ */ build('1q127L3', true);
export var qruov1q127l3_shake = /* @__PURE__ */ build('1q127L3', false);
export var qruov1q127l10_aes = /* @__PURE__ */ build('1q127L10', true);
export var qruov1q127l10_shake = /* @__PURE__ */ build('1q127L10', false);
export var qruov1q31l3_aes = /* @__PURE__ */ build('1q31L3', true);
export var qruov1q31l3_shake = /* @__PURE__ */ build('1q31L3', false);
export var qruov1q31l10_aes = /* @__PURE__ */ build('1q31L10', true);
export var qruov1q31l10_shake = /* @__PURE__ */ build('1q31L10', false);
export var qruov1q7l10_aes = /* @__PURE__ */ build('1q7L10', true);
export var qruov1q7l10_shake = /* @__PURE__ */ build('1q7L10', false);
export var qruov3q127l3_aes = /* @__PURE__ */ build('3q127L3', true);
export var qruov3q127l3_shake = /* @__PURE__ */ build('3q127L3', false);
export var qruov3q127l10_aes = /* @__PURE__ */ build('3q127L10', true);
export var qruov3q127l10_shake = /* @__PURE__ */ build('3q127L10', false);
export var qruov3q31l3_aes = /* @__PURE__ */ build('3q31L3', true);
export var qruov3q31l3_shake = /* @__PURE__ */ build('3q31L3', false);
export var qruov3q31l10_aes = /* @__PURE__ */ build('3q31L10', true);
export var qruov3q31l10_shake = /* @__PURE__ */ build('3q31L10', false);
export var qruov3q7l10_aes = /* @__PURE__ */ build('3q7L10', true);
export var qruov3q7l10_shake = /* @__PURE__ */ build('3q7L10', false);
export var qruov5q127l3_aes = /* @__PURE__ */ build('5q127L3', true);
export var qruov5q127l3_shake = /* @__PURE__ */ build('5q127L3', false);
export var qruov5q127l10_aes = /* @__PURE__ */ build('5q127L10', true);
export var qruov5q127l10_shake = /* @__PURE__ */ build('5q127L10', false);
export var qruov5q31l3_aes = /* @__PURE__ */ build('5q31L3', true);
export var qruov5q31l3_shake = /* @__PURE__ */ build('5q31L3', false);
export var qruov5q31l10_aes = /* @__PURE__ */ build('5q31L10', true);
export var qruov5q31l10_shake = /* @__PURE__ */ build('5q31L10', false);
export var qruov5q7l10_aes = /* @__PURE__ */ build('5q7L10', true);
export var qruov5q7l10_shake = /* @__PURE__ */ build('5q7L10', false);
