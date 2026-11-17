/**
 * GF(16) and GF(256) with packed vectors, for the multivariate signatures
 *
 * UOV, MAYO and SNOVA compute with vectors over a small binary field: m
 * equations evaluated at once, a batch per coefficient. They store a vector
 * packed, one element per byte over GF(256) and two per byte over GF(16),
 * the element with the even index in the LOW nibble. Everything here works
 * on that packed form directly.
 *
 * THE ONE FAST OPERATION is dst += a * src for a scalar a, and it is a table
 * lookup per byte: ROW[a] maps a packed byte to its product with a - both
 * nibbles at once over GF(16). Every matrix product in those schemes is a
 * sequence of these.
 *
 * The fields are the ones the schemes specify: GF(16) = GF(2)[x]/(x^4+x+1)
 * and GF(256) = GF(2)[x]/(x^8+x^4+x^3+x+1), the AES field.
 */

function make(bits, poly) {
    var q = 1 << bits, M = new Uint8Array(q * q);
    function slow(a, b) {
        var r = 0;
        for (var i = 0; i < bits; i++) {
            if (b & 1) { r ^= a; }
            b >>= 1;
            var hi = a & (q >> 1);
            a = (a << 1) & (q - 1);
            if (hi) { a ^= poly; }
        }
        return r;
    }
    for (var a = 0; a < q; a++) { for (var b = 0; b < q; b++) { M[a * q + b] = slow(a, b); } }
    var INV = new Uint8Array(q);
    for (var x = 1; x < q; x++) { for (var y = 1; y < q; y++) { if (M[x * q + y] === 1) { INV[x] = y; break; } } }

    /* ROW[a][byte]: the packed byte times a */
    var ROW = [];
    for (var s = 0; s < q; s++) {
        var r = new Uint8Array(256);
        for (var v = 0; v < 256; v++) {
            r[v] = bits === 8 ? M[s * q + v] : M[s * q + (v & 15)] | (M[s * q + (v >> 4)] << 4);
        }
        ROW.push(r);
    }

    var F = {
        q: q,
        bits: bits,
        mul: function (a, b) { return M[a * q + b]; },
        inv: function (a) { return INV[a]; },
        ROW: ROW,
        /** bytes for n packed elements */
        len: bits === 8 ? function (n) { return n; } : function (n) { return (n + 1) >> 1; },
        get: bits === 8 ? function (v, i) { return v[i]; } : function (v, i) { return (v[i >> 1] >> ((i & 1) << 2)) & 15; },
        set: bits === 8 ? function (v, i, x) { v[i] = x; } : function (v, i, x) {
            var sh = (i & 1) << 2;
            v[i >> 1] = (v[i >> 1] & ~(15 << sh)) | (x << sh);
        },
        /** dst[doff..doff+n) += a * src[soff..soff+n), n in bytes */
        madd: function (dst, doff, src, soff, a, n) {
            if (a === 0) { return; }
            var row = ROW[a];
            for (var k = 0; k < n; k++) { dst[doff + k] ^= row[src[soff + k]]; }
        },

        /**
         * The unique x with sum_j x_j * col_j = rhs, for n columns of n
         * elements each (column j packed at cols[j * len(n)]); null when the
         * columns are dependent. Gauss-Jordan without early exits on the
         * values, so that its time does not depend on them; only the
         * singular/non-singular outcome is visible.
         */
        solve: function (cols, rhs, n) {
            var w = n + 1, A = new Uint8Array(n * w), i, j, k;
            var nb = F.len(n);
            for (j = 0; j < n; j++) { for (i = 0; i < n; i++) { A[i * w + j] = F.get(cols.subarray(j * nb), i); } }
            for (i = 0; i < n; i++) { A[i * w + n] = F.get(rhs, i); }
            var ok = 1;
            for (k = 0; k < n; k++) {
                /* bring a non-zero pivot to row k: add every lower row whose entry is wanted */
                for (i = k + 1; i < n; i++) {
                    var need = (A[k * w + k] === 0) ? 1 : 0;
                    var take = need & (A[i * w + k] !== 0 ? 1 : 0);
                    for (j = k; j < w; j++) { A[k * w + j] ^= A[i * w + j] & -take; }
                }
                var p = A[k * w + k];
                ok &= p !== 0 ? 1 : 0;
                var pi = INV[p];
                for (j = k; j < w; j++) { A[k * w + j] = M[pi * q + A[k * w + j]]; }
                for (i = 0; i < n; i++) {
                    if (i === k) { continue; }
                    var c = A[i * w + k];
                    for (j = k; j < w; j++) { A[i * w + j] ^= M[c * q + A[k * w + j]]; }
                }
            }
            if (!ok) { return null; }
            var x = new Uint8Array(nb);
            for (i = 0; i < n; i++) { F.set(x, i, A[i * w + n]); }
            return x;
        }
    };
    return F;
}

export var GF16 = /* @__PURE__ */ make(4, 0x3);
export var GF256 = /* @__PURE__ */ make(8, 0x1b);
