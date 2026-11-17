/**
 * The negacyclic NTT over Z_q[X]/(X^n + 1), any prime q = 1 mod 2n, BigInt.
 *
 * negacyclic(n, q, who) precomputes one ring: forward takes coefficients to
 * the values at the roots of X^n + 1 (odd powers of psi, in bit-reversed
 * order), inverse takes them back, the 1/n included. bfv.js uses it for its
 * ciphertext ring and its batching slots, leap.js for R_257.
 */

import { mod, powmod } from './primes.js';

/**
 * Negacyclic NTT.
 *
 * Polynomial multiplication is n^2 coefficient products done directly and
 * n log n done here, which at n = 4096 is the difference between usable and
 * not. NEGACYCLIC because the ring reduces modulo X^n + 1 rather than
 * X^n - 1: folding the wrap-around with a sign is what that quotient means,
 * and it is handled by twisting with psi, a 2n-th root of unity, rather than
 * the n-th root an ordinary NTT would use.
 */
function ntt(a, q, psiTable, n) {
    /*
     * THE PSI TWIST IS IN THE TABLE, not applied separately. Applying it in
     * both places - which is what a first reading of the literature invites,
     * because some presentations pre-scale and others fold it into the
     * butterflies - squares it, and every product comes out wrong. Caught by
     * checking 1 * x = x against schoolbook, which is the cheapest possible
     * oracle and the one worth writing first.
     */
    var out = a.slice();
    var t = n, m = 1;
    while (m < n) {
        t >>= 1;
        for (var k = 0; k < m; k++) {
            var j1 = 2 * k * t, j2 = j1 + t;
            var S = psiTable[m + k];
            for (var j = j1; j < j2; j++) {
                var U = out[j], V = mod(out[j + t] * S, q);
                out[j] = mod(U + V, q);
                out[j + t] = mod(U - V, q);
            }
        }
        m <<= 1;
    }
    return out;
}

/** Build the bit-reversed powers of psi that the loop above indexes. */
function psi_powers(psi, q, n) {
    var tbl = new Array(n), p = 1n, i;
    var lin = new Array(n);
    for (i = 0; i < n; i++) { lin[i] = p; p = mod(p * psi, q); }
    var bits = Math.log2(n);
    for (i = 0; i < n; i++) {
        var r = 0;
        for (var b = 0; b < bits; b++) { r = (r << 1) | ((i >> b) & 1); }
        tbl[i] = lin[r];
    }
    return { linear: lin, reversed: tbl };
}

/**
 * A primitive 2n-th root of unity mod m, or null.
 *
 * Needed twice - once for the ciphertext ring and once for the plaintext
 * batching - and the two differ only in which modulus they search. Two copies
 * of a search this easy to get subtly wrong (the second condition is what
 * makes it PRIMITIVE, and dropping it yields a root of the wrong order that
 * still passes the first) is how one gets fixed and the other does not.
 */
function root_of_unity(m, twoN) {
    for (var c = 2n; c < 100000n; c++) {
        var cand = powm(c, (m - 1n) / twoN, m);
        if (powm(cand, twoN, m) === 1n && powm(cand, twoN / 2n, m) !== 1n) {
            return cand;
        }
    }
    return null;
}

/* square-and-multiply is primes.powmod; this was a copy that also reduced a
   negative base first, which is the one thing kept */
function powm(b, e, m) { return powmod(mod(b, m), e, m); }

function ntt_inv(a, q, tbl, n) {
    var out = a.slice();
    var t = 1, m = n;
    while (m > 1) {
        var j1 = 0, h = m >> 1;
        for (var k = 0; k < h; k++) {
            var j2 = j1 + t;
            var S = tbl[h + k];
            for (var j = j1; j < j2; j++) {
                var U = out[j], V = out[j + t];
                out[j] = mod(U + V, q);
                out[j + t] = mod(mod(U - V, q) * S, q);
            }
            j1 += 2 * t;
        }
        t <<= 1; m >>= 1;
    }
    return out;
}

/**
 * One ring's transform, precomputed: {n, q, psi, fwd, inv, nInv, forward, inverse}.
 * THROWS when q is not 1 mod 2n (who names the caller).
 */
export function negacyclic(n, q, who) {
    var twoN = BigInt(2 * n);
    if ((q - 1n) % twoN !== 0n) { throw new Error(who + ': the modulus must be 1 mod 2n for the NTT to exist'); }
    var psi = root_of_unity(q, twoN);
    if (psi === null) { throw new Error(who + ': no 2n-th root of unity'); }
    var fwd = psi_powers(psi, q, n), inv = psi_powers(powm(psi, q - 2n, q), q, n), nInv = powm(BigInt(n), q - 2n, q);
    return {
        n: n, q: q, psi: psi, fwd: fwd, inv: inv, nInv: nInv,
        /** Coefficients (bigint, length n) to values. */
        forward: function (a) { return ntt(a, q, fwd.reversed, n); },
        /** Values to coefficients. */
        inverse: function (A) {
            var r = ntt_inv(A, q, inv.reversed, n);
            for (var i = 0; i < n; i++) { r[i] = mod(r[i] * nInv, q); }
            return r;
        }
    };
}
