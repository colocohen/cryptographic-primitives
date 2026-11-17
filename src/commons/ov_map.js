/**
 * Oil-and-vinegar quadratic maps on batched coefficients, shared by UOV and
 * MAYO
 *
 * Both schemes hold m quadratic forms in n = v + o variables as one
 * upper-triangular block matrix P = [[P1, P2], [0, P3]] whose every entry is
 * a BATCH: the m forms' coefficients at that position, packed as a vector
 * over GF(q) (commons/gf2k.js). P1 is v x v upper triangular, P2 is v x o,
 * P3 is o x o upper triangular, each stored row by row, entry by entry. A
 * vector of batches - one per variable - is the same packed layout.
 *
 * Everything the two schemes do with P reduces to the few products here,
 * each a sequence of dst += a * batch.
 *
 * O, the secret oil matrix (v x o), is passed unpacked: Ou[k * o + j] is
 * O(k, j). UOV and MAYO store it in different orders; each decodes its own.
 */

export function ov_map(F, v, o, OB) {
    var n = v + o;

    /* the byte offset of entry (i, j), i <= j < d, of a row-major upper-triangular d x d */
    function ut(i, j, d) { return (i * d - (i * (i - 1) >> 1) + (j - i)) * OB; }

    /*
     * x^T T for an upper-triangular d x d T at offset `off`: d batches, the
     * c-th being sum over b <= c of x_b T(b, c). x is a packed vector.
     */
    function x_ut(T, off, x, d) {
        var w = new Uint8Array(d * OB);
        for (var b = 0; b < d; b++) {
            var xb = F.get(x, b);
            if (xb === 0) { continue; }
            for (var c = b; c < d; c++) { F.madd(w, c * OB, T, off + ut(b, c, d), xb, OB); }
        }
        return w;
    }

    /* x^T M for a full rows x cols M of batches: cols batches */
    function x_mat(M, off, x, rows, cols) {
        var w = new Uint8Array(cols * OB);
        for (var b = 0; b < rows; b++) {
            var xb = F.get(x, b);
            if (xb === 0) { continue; }
            for (var c = 0; c < cols; c++) { F.madd(w, c * OB, M, off + (b * cols + c) * OB, xb, OB); }
        }
        return w;
    }

    /* acc += sum over c < d of x_c w_c: the pairing of a vector of batches with a vector */
    function dot(acc, w, x, d) {
        for (var c = 0; c < d; c++) { F.madd(acc, 0, w, c * OB, F.get(x, c), OB); }
        return acc;
    }

    /* s^T P for the full map, s a packed vector of n elements: n batches */
    function s_p(P1, P2, P3, s) {
        var sv = new Uint8Array(F.len(v)), so = new Uint8Array(F.len(o));
        for (var i = 0; i < v; i++) { F.set(sv, i, F.get(s, i)); }
        for (var j = 0; j < o; j++) { F.set(so, j, F.get(s, v + j)); }
        var w = new Uint8Array(n * OB);
        w.set(x_ut(P1, 0, sv, v), 0);
        var a = x_mat(P2, 0, sv, v, o), c = x_ut(P3, 0, so, o);
        for (var k = 0; k < o * OB; k++) { w[v * OB + k] = a[k] ^ c[k]; }
        return w;
    }

    /*
     * L = P2 + (P1 + P1^T) O, the secret key's linear part (UOV's F2), and
     * P3 = Upper(O^T (P1 O + P2)) when asked: the public key's last block. In
     * characteristic 2 the signs of the specifications' -O^T P1 O - O^T P2
     * do not matter, and P1's diagonal enters P1 + P1^T twice and cancels.
     */
    function l_p3(P1, P2, Ou, want_p3) {
        var S = P2.slice(), i, j, k;
        /* S += P1 O, with P1 upper triangular */
        for (i = 0; i < v; i++) {
            for (k = i; k < v; k++) {
                var p = ut(i, k, v);
                for (j = 0; j < o; j++) { F.madd(S, (i * o + j) * OB, P1, p, Ou[k * o + j], OB); }
            }
        }
        var P3 = null;
        if (want_p3) {
            /* M = O^T S, then P3(r, c) = M(r, c) + M(c, r) above the diagonal */
            var M = new Uint8Array(o * o * OB);
            for (i = 0; i < o; i++) {
                for (k = 0; k < v; k++) {
                    var a = Ou[k * o + i];
                    if (a === 0) { continue; }
                    for (j = 0; j < o; j++) { F.madd(M, (i * o + j) * OB, S, (k * o + j) * OB, a, OB); }
                }
            }
            P3 = new Uint8Array(OB * o * (o + 1) / 2);
            for (var r = 0; r < o; r++) {
                for (var c = r; c < o; c++) {
                    var d = ut(r, c, o);
                    P3.set(M.subarray((r * o + c) * OB, (r * o + c + 1) * OB), d);
                    if (c !== r) { F.madd(P3, d, M, (c * o + r) * OB, 1, OB); }
                }
            }
        }
        /* S += P1^T O */
        for (i = 0; i < v; i++) {
            for (k = 0; k <= i; k++) {
                var q = ut(k, i, v);
                for (j = 0; j < o; j++) { F.madd(S, (i * o + j) * OB, P1, q, Ou[k * o + j], OB); }
            }
        }
        return { L: S, P3: P3 };
    }

    return { ut: ut, x_ut: x_ut, x_mat: x_mat, dot: dot, s_p: s_p, l_p3: l_p3 };
}
