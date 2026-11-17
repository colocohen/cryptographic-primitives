/**
 * commons/wesolowski.js - Wesolowski's proof of exponentiation, over any
 * group of unknown order: y = x^(2^T), and π = x^⌊2^T / ℓ⌋ for a prime ℓ
 * hashed from (x, y). A verifier checks
 *
 *     π^ℓ · x^r == y,   r = 2^T mod ℓ
 *
 * in two short exponentiations, whatever T was. The group decides the rest -
 * vdf.js runs it in Z*_N (an RSA modulus), vdf_class.js in a class group -
 * and the scheme, ℓ's derivation included, is the caller's.
 *
 * THE PROOF, CHEAPLY (Wesolowski, "Efficient verifiable delay functions",
 * §4.1). Write ⌊2^T/ℓ⌋ in base 2^k, digits b_i = ⌊2^(T−ki)/ℓ⌋ mod 2^k. With
 * the evaluation's checkpoints C_i = x^(2^(ki)) kept,
 *
 *     π = Π C_i^(b_i) = Π_v (Π_{b_i = v} C_i)^v
 *
 * one multiplication per checkpoint, then k·2^(k−1) for the powers v: about
 * T/k + k·2^(k−1) group operations against T for the evaluation - about 1/k
 * of it at the default k ≈ log2(T)/2 (16% at T = 20,000, 10% at a million).
 * The price is ⌈T/k⌉ elements in memory; past
 * max_checkpoints the proof is the long division instead (π = π²·x^bit, bit
 * by bit: T more squarings, nothing kept). Either way the same π: it is
 * x^⌊2^T/ℓ⌋, one element.
 *
 * @typedef {object} Group
 *   one, mul(a, b), square(a), equals(a, b)
 */

/**
 * y = x^(2^T) and its proof.
 *
 * @param {Group} G
 * @param x
 * @param {number} T         squarings, a non-negative safe integer
 * @param {function} prime   (x, y) → ℓ, the scheme's challenge
 * @param {object} [opts]    { k: the checkpoint spacing (default ≈ log2(T)/2),
 *                             max_checkpoints: (default 2^20) }
 * @return {{ y, proof, l: bigint }}
 */
export function evaluate(G, x, T, prime, opts) {
    var o = opts || {};
    if (!Number.isSafeInteger(T) || T < 0) { throw new RangeError('wesolowski: T is a non-negative safe integer'); }
    var k = o.k != null ? o.k : Math.max(1, Math.round(Math.log2(Math.max(T, 2)) / 2));
    if (!Number.isInteger(k) || k < 1 || k > 24) { throw new RangeError('wesolowski: k is an integer in [1, 24]'); }
    var max = o.max_checkpoints != null ? o.max_checkpoints : 1 << 20;
    var keep = Math.ceil(T / k) <= max;

    /* the delay: T squarings, one after another - the only part that cannot be parallel */
    var checkpoints = keep ? [x] : null, y = x;
    for (var i = 1; i <= T; i++) {
        y = G.square(y);
        if (keep && i % k === 0) { checkpoints.push(y); }
    }
    var l = prime(x, y);
    return { y: y, proof: keep ? from_checkpoints(G, checkpoints, k, T, l) : long_division(G, x, T, l), l: l };
}

/* π = Π_v (Π_{b_i = v} C_i)^v, the digits b_i of ⌊2^T/ℓ⌋ in base 2^k from the top */
function from_checkpoints(G, C, k, T, l) {
    var n = Math.ceil(T / k), K = BigInt(k), buckets = new Array(1 << k).fill(null);
    /* r = 2^(T − k(i+1)) mod ℓ for the full digits, walking down from the top one */
    var top = n - 1, e_top = T - k * top;         /* the top digit has e_top <= k bits */
    var r = 1n;
    for (var i = top; i >= 0; i--) {
        var b;
        if (i === top) { b = Number((1n << BigInt(e_top)) / l); r = (1n << BigInt(e_top)) % l; }
        else { var rr = r << K; b = Number(rr / l); r = rr % l; }
        if (b !== 0) { buckets[b] = buckets[b] === null ? C[i] : G.mul(buckets[b], C[i]); }
    }
    /* Π_v y_v^v = Π_j (Π_{v: bit j set} y_v)^(2^j), by Horner from the top bit */
    var acc = G.one;
    for (var j = k - 1; j >= 0; j--) {
        acc = G.square(acc);
        var z = null;
        for (var v = 1; v < buckets.length; v++) {
            if (buckets[v] !== null && (v >> j) & 1) { z = z === null ? buckets[v] : G.mul(z, buckets[v]); }
        }
        if (z !== null) { acc = G.mul(acc, z); }
    }
    return acc;
}

/* π = x^⌊2^T/ℓ⌋ by long division, bit by bit: no 2^T, nothing kept */
function long_division(G, x, T, l) {
    var pi = G.one, r = 1n;
    for (var i = 0; i < T; i++) {
        var rr = r << 1n;
        pi = G.square(pi);
        if (rr >= l) { r = rr - l; pi = G.mul(pi, x); } else { r = rr; }
    }
    return pi;
}

/**
 * π^ℓ · x^r == y, r = 2^T mod ℓ. The caller derives ℓ from (x, y) as the
 * prover did, and checks that x, y and π are elements of the group.
 */
export function verify(G, x, y, proof, T, l) {
    return G.equals(pow_pair(G, proof, l, x, modpow2(T, l)), y);
}

/* a^e · b^f in one chain of squarings (Shamir's trick): max(|e|, |f|) squarings, not their sum */
function pow_pair(G, a, e, b, f) {
    var ab = G.mul(a, b), acc = G.one, n = Math.max(e.toString(2).length, f.toString(2).length);
    for (var i = BigInt(n - 1); i >= 0n; i--) {
        acc = G.square(acc);
        var u = (e >> i) & 1n, v = (f >> i) & 1n;
        if (u && v) { acc = G.mul(acc, ab); } else if (u) { acc = G.mul(acc, a); } else if (v) { acc = G.mul(acc, b); }
    }
    return acc;
}

function modpow2(T, m) {
    var r = 1n, b = 2n % m, e = BigInt(T);
    while (e > 0n) { if (e & 1n) { r = r * b % m; } b = b * b % m; e >>= 1n; }
    return r;
}
