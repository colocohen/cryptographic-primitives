/**
 * Fixed-window and fixed-base scalar multiplication
 *
 * Two techniques that replace the Montgomery ladder where they apply, both
 * preserving constant time, both measured rather than assumed.
 *
 * THE LADDER'S COST. commons/ladder.js performs one addition AND one doubling
 * for every bit of the scalar, regardless of that bit's value, which is what
 * makes it constant time. For a 256-bit scalar that is 256 of each. Its
 * advantage is that it needs no storage and no precomputation; its cost is
 * that it does the maximum amount of work every time.
 *
 * 1. FIXED WINDOW. Process w bits at a time against a table of the first
 *    2^w multiples of P. A 4-bit window turns 256 doublings and 256 additions
 *    into 256 doublings and 64 additions. Building the table costs 2^w - 2
 *    additions, so it pays for itself immediately at w = 4.
 *
 * 2. FIXED BASE. When the point is the GENERATOR - which it is for key
 *    generation, for signing, and for the first half of every verification -
 *    the table can be built once at load and reused forever. Then the
 *    doublings disappear too: with a table of multiples of 2^(w*i) * G, the
 *    whole multiplication is one table lookup and one addition per window.
 *    That is 64 additions and NO doublings for a 256-bit scalar.
 *
 * CONSTANT TIME IS PRESERVED BY SCANNING, NOT INDEXING. Reading table[k]
 * where k comes from secret scalar bits is exactly the cache-timing leak this
 * library warns about in aes.js. Every lookup below walks the WHOLE table and
 * selects with arithmetic masks, so the memory access pattern is identical
 * whatever the scalar is. That costs 2^w field operations per window and is
 * the reason w stays small.
 *
 * ⭐ SIGNED DIGITS HALVE THE SCAN (11-11). The scalar is recoded into digits
 *    in [−2^(w−1)+1, 2^(w−1)] (signed_digits, below), so a table holds only
 *    0..2^(w−1) multiples: the scan reads half the entries, and the sign is
 *    applied after it by a constant-time conditional negation — negating a
 *    point is negating one or two coordinates. Every window still performs
 *    one scan, one negation and one addition, whatever its digit.
 *
 *    Measured with the point-level select and, on Edwards curves, the cached
 *    tables (medians of seven rounds, ristretto255): k·G 531 → 230 µs; k·P
 *    1.85 ms (the ladder) → 1.02 ms.
 */

import { finish_task } from './task.js';

/**
 * Select table[index] in constant time by scanning every entry.
 *
 * The mask is 0n when i != index and all-ones otherwise, built from a
 * comparison that produces a BigInt rather than a branch. Every entry is read
 * and combined, so the access pattern does not depend on `index`.
 */
function ct_select(G, table, index) {
    var acc = table[0];
    for (var i = 1; i < table.length; i++) {
        /* (i === index) as 0n or 1n: (x - 1) >>> 31 is 1 exactly when x is 0
           (x is a small non-negative integer here), with no comparison. */
        var eq = BigInt(((i ^ index) - 1) >>> 31);
        acc = G.cselect ? G.cselect(eq, table[i], acc) : field_select(eq, table[i], acc);
    }
    return acc;
}

/**
 * The signed digit's point: |d|·P from the table by a scan, then negated
 * when d < 0 — by G.cneg when the curve has one, otherwise by selecting
 * between it and G.neg of it. Branch-free in the digit.
 */
function ct_signed(G, table, d) {
    var s = d >> 31;                          /* −1 when d < 0, else 0 */
    var P = ct_select(G, table, (d ^ s) - s);  /* |d| */
    var neg = BigInt(s & 1);
    if (G.cneg) { return G.cneg(neg, P); }
    var N = G.neg(P);
    return G.cselect ? G.cselect(neg, N, P) : field_select(neg, N, P);
}

/**
 * k (taken mod 2^bits) as ceil(bits/w) + 1 signed digits, least significant
 * first: k = Σ d_i·2^(w·i), d_i ∈ [−2^(w−1)+1, 2^(w−1)].
 *
 * A digit above 2^(w−1) becomes d − 2^w and carries one into the next; the
 * carry is computed by arithmetic, not compared. The extra top digit takes
 * the last carry, so every scalar has the same number of digits.
 */
function signed_digits(k, bits, w) {
    var n = Math.ceil(bits / w) + 1, out = new Int32Array(n);
    var half = 1 << (w - 1), full = 1 << w, mask = BigInt(full - 1);
    var x = k & ((1n << BigInt(bits)) - 1n), carry = 0;
    for (var i = 0; i < n; i++) {
        var d = Number((x >> BigInt(i * w)) & mask) + carry;
        carry = ((half - d) >>> 31) & 1;      /* 1 exactly when d > half */
        out[i] = d - carry * full;
    }
    return out;
}

/**
 * Select between two points by arithmetic on their coordinates — no branch
 * on `eq`. The old fallback was `eq === 1n ? a : b`, so every base_mul (keys
 * and nonces included) branched on the secret window. Points here are
 * objects whose own fields are bigint coordinates; anything else falls back
 * to the branch rather than producing a malformed point.
 */
function field_select(eq, a, b) {
    var keys = Object.keys(a);
    var out = Object.create(Object.getPrototypeOf(a));
    for (var k = 0; k < keys.length; k++) {
        var x = a[keys[k]], y = b[keys[k]];
        if (typeof x !== 'bigint' || typeof y !== 'bigint') { return eq === 1n ? a : b; }
        out[keys[k]] = y + eq * (x - y);
    }
    return out;
}

/**
 * Build the table [O, P, 2P, ..., (2^w - 1)P].
 */
/**
 * @param {number} n  table size; callers with a window width pass 1 << w
 *
 * EXPORTED because glv.js had a byte-identical copy. Two implementations of
 * the same table is how one gets a fix and the other does not, and this one
 * is the odd-index add / even-index double pattern that is easy to write
 * subtly wrong.
 */
export function window_table(G, P, n) {
    var t = new Array(n);
    t[0] = G.ZERO;
    t[1] = P;
    for (var i = 2; i < n; i++) {
        t[i] = (i & 1) ? G.add(t[i - 1], P) : G.dbl(t[i >> 1]);
    }
    return t;
}

/**
 * Fixed-window scalar multiplication for an ARBITRARY point.
 *
 * @param {object} G     group with ZERO, add, dbl and cselect
 * @param {bigint} k     the scalar
 * @param {object} P     the point
 * @param {number} bits  a fixed iteration count, so the scalar's magnitude
 *                       does not show in the running time
 * @param {number} [w=4] window width
 */
export function window_mul(G, k, P, bits, w) {
    var width = w || 4;
    /* 0..2^(w−1) multiples: the digits are signed (signed_digits) */
    var table = window_table(G, P, (1 << (width - 1)) + 1);
    var digits = signed_digits(k, bits, width);

    /* the top digit starts the accumulator — w doublings of the identity would be wasted */
    var acc = ct_signed(G, table, digits[digits.length - 1]);
    for (var i = digits.length - 2; i >= 0; i--) {
        for (var d = 0; d < width; d++) { acc = G.dbl(acc); }
        acc = G.add(acc, ct_signed(G, table, digits[i]));
    }
    return acc;
}

/**
 * Precompute a fixed-base table for a generator.
 *
 * Layout: comb[i][j] = j * 2^(w*i) * G for j = 0..2^(w−1) (the digits are
 * signed), so a scalar's i-th window can be added directly with no doublings
 * at all.
 *
 * MEMORY. For a 256-bit curve at w = 4 that is 65 windows of 9 points, or
 * 585 points. Each is three or four field elements, so on the order of a
 * hundred kilobytes of BigInts - built once, at first use, not at import, so
 * that a caller who never touches this curve never pays for it.
 *
 * @return {function} (k) -> k*G
 */
export function fixed_base(G, P, bits, w) {
    var width = w || 4;
    var windows = Math.ceil(bits / width) + 1;     /* signed_digits' count */
    var size = (1 << (width - 1)) + 1;
    var comb = null;

    /*
     * ⭐ A CURVE WITH CACHED POINTS (edwards.js: affine, T·d precomputed) has
     *    its table stored that way: a cheaper addition and a narrower scan.
     *    The table is scanned and negated through the cached forms.
     */
    var cached = typeof G.cache === 'function';
    var CG = cached ? { cselect: G.cselect_cached, cneg: G.cneg_cached } : G;

    function build() {
        comb = new Array(windows);
        var base = P;
        for (var i = 0; i < windows; i++) {
            /* each row IS a window table of this window's base - it used to
               be the same odd-add / even-double loop written out a second
               time, inside the file that exports window_table */
            comb[i] = window_table(G, base, size);
            /* advance the base by 2^width for the next window */
            for (var d = 0; d < width; d++) { base = G.dbl(base); }
        }
        if (cached) {
            var flat = G.cache([].concat.apply([], comb));
            for (var r = 0; r < windows; r++) { comb[r] = flat.slice(r * size, (r + 1) * size); }
        }
    }

    return function (k) {
        if (comb === null) { build(); }
        var digits = signed_digits(k, bits, width);
        var acc = G.ZERO;
        for (var i = 0; i < windows; i++) {
            var e = ct_signed(CG, comb[i], digits[i]);
            acc = cached ? G.add_cached(acc, e) : G.add(acc, e);
        }
        return acc;
    };
}

/* ================= VARIABLE TIME — PUBLIC SCALARS ONLY ================= */

/*
 * Signature verification multiplies by values an attacker already knows: the
 * challenge, the public key, the signature's own components. Constant time
 * buys nothing there and costs a factor of two. Everything below follows the
 * scalar — the number of additions and which table entries are touched — so
 * ⛔ NEVER CALL IT WITH A SECRET.
 *
 * ONE ENGINE (11-11). wnaf_mul, double_mul, double_mul_base and the GLV
 * routines (commons/glv.js) are all `wnaf_sum` over a list of terms, each a
 * scalar's wNAF digits and its point's odd multiples:
 *
 *   ⭐ wNAF, not fixed windows. A fixed window adds in almost every window —
 *      about 120 additions for a two-scalar 256-bit verification at w = 4 —
 *      where wNAF's density is 1/(w+1): about 43 at w = 5.
 *   ⭐ A BASE TABLE BUILT ONCE (base_table): the generator's odd multiples at
 *      a wide window (w = 8: ~28 additions for 256 bits), kept — the
 *      generator is the same in every verification, its table need not be
 *      rebuilt — and in a curve's cached form where it has one (Edwards:
 *      affine, T·d precomputed, two multiplications fewer per addition).
 *   ⭐ DOUBLINGS WITHOUT T on Edwards curves (dbl_partial) where no addition
 *      follows: a run of doublings needs only X, Y, Z.
 *
 * Measured (medians of seven rounds): Ed25519 verify 1.48 → 1.17 ms, BIP-340
 * 1.43 → 1.17, ECDSA on secp256k1 1.77 → 1.16, sr25519 1.54 → 1.23.
 */

/**
 * The wNAF of k ≥ 0: digits odd in [−(2^(w−1)−1), 2^(w−1)−1] or zero, at
 * least w−1 zeros after each non-zero one, least significant first —
 * libsecp256k1's secp256k1_ecmult_wnaf, on the scalar's bits as numbers (one
 * conversion, not a BigInt operation per bit).
 */
export function wnaf_digits(k, w) {
    var s = k.toString(2), bits = s.length, len = bits + 1;
    var out = new Int16Array(len);
    function bit(i) { return i < bits ? s.charCodeAt(bits - 1 - i) - 48 : 0; }
    var i = 0, carry = 0;
    while (i < len) {
        if (bit(i) === carry) { i++; continue; }
        var now = w < len - i ? w : len - i, word = 0;
        for (var j = 0; j < now; j++) { word |= bit(i + j) << j; }
        word += carry;
        carry = (word >> (w - 1)) & 1;
        word -= carry << w;
        out[i] = word;
        i += now;
    }
    return out;
}

/** [P, 3P, 5P, …, (2^(w−1) − 1)P]: what a wNAF digit indexes, by (|d| − 1)/2. */
export function odd_multiples(G, P, w) {
    var n = 1 << (w - 2), pre = new Array(n);
    pre[0] = P;
    if (n > 1) {
        var P2 = G.dbl(P);
        for (var i = 1; i < n; i++) { pre[i] = G.add(pre[i - 1], P2); }
    }
    return pre;
}

/**
 * A fixed point's table, built on first use and kept: { w, pre, cached }.
 * In the curve's cached form where it has one.
 */
export function base_table(G, P, w) {
    var t = null;
    return function () {
        if (t === null) {
            var pre = odd_multiples(G, P, w), cached = typeof G.cache === 'function';
            t = { w: w, pre: cached ? G.cache(pre) : pre, cached: cached };
        }
        return t;
    };
}

/**
 * Σ k_i·P_i, every k_i public: terms [{ digits, pre, cached }], one shared
 * run of doublings, an addition wherever a digit is non-zero.
 */
export function wnaf_sum(G, terms) {
    var top = 0, t, q;
    for (q = 0; q < terms.length; q++) { if (terms[q].digits.length > top) { top = terms[q].digits.length; } }
    var partial = typeof G.dbl_partial === 'function';
    var acc = G.ZERO, started = false;
    for (var j = top - 1; j >= 0; j--) {
        var any = false;
        for (q = 0; q < terms.length && !any; q++) { t = terms[q]; if (j < t.digits.length && t.digits[j] !== 0) { any = true; } }
        if (started) {
            /* T is needed only before an addition, and at the end */
            acc = (any || j === 0 || !partial) ? G.dbl(acc) : G.dbl_partial(acc);
        }
        if (!any) { continue; }
        for (q = 0; q < terms.length; q++) {
            t = terms[q];
            var d = j < t.digits.length ? t.digits[j] : 0;
            if (d === 0) { continue; }
            var e = t.pre[((d < 0 ? -d : d) - 1) >> 1];
            if (t.cached) { acc = G.add_cached(acc, d > 0 ? e : G.neg_cached(e)); }
            else { acc = G.add(acc, d > 0 ? e : G.neg(e)); }
            started = true;
        }
    }
    return acc;
}

/** k·P for a PUBLIC k: wNAF. */
export function wnaf_mul(G, k, P, w) {
    var width = w || 5;
    if (k === 0n) { return G.ZERO; }
    return wnaf_sum(G, [{ digits: wnaf_digits(k, width), pre: odd_multiples(G, P, width), cached: false }]);
}

/**
 * Shamir's trick: a·P + b·Q in one pass, both scalars PUBLIC — the shape of
 * every signature verification. The doublings are shared; each scalar adds
 * where its wNAF digit is non-zero.
 */
export function double_mul(G, a, P, b, Q, w) {
    var width = w || 5, terms = [];
    if (a !== 0n) { terms.push({ digits: wnaf_digits(a, width), pre: odd_multiples(G, P, width), cached: false }); }
    if (b !== 0n) { terms.push({ digits: wnaf_digits(b, width), pre: odd_multiples(G, Q, width), cached: false }); }
    return wnaf_sum(G, terms);
}

/**
 * a·B + b·Q for B a fixed point with a kept table (base_table): what
 * verification does with the generator. The table's own width; Q's is w.
 */
export function double_mul_base(G, a, table, b, Q, w) {
    var width = w || 5, T = table(), terms = [];
    if (a !== 0n) { terms.push({ digits: wnaf_digits(a, T.w), pre: T.pre, cached: T.cached }); }
    if (b !== 0n) { terms.push({ digits: wnaf_digits(b, width), pre: odd_multiples(G, Q, width), cached: false }); }
    return wnaf_sum(G, terms);
}

/**
 * Multi-scalar multiplication by Pippenger's algorithm.
 *
 *     P = a1*G1 + a2*G2 + ... + an*Gn
 *
 * The naive loop costs n scalar multiplications. Pippenger costs roughly
 * n / log2(n) point additions, which for a thousand terms is a factor of ten
 * and for a million is a factor of forty.
 *
 * THE IDEA IS TO SORT INSTEAD OF MULTIPLY. Split every scalar into c-bit
 * windows. For one window position, each point falls into one of 2^c buckets
 * according to its window value, and the answer for that position is
 *
 *     1*bucket[1] + 2*bucket[2] + ... + (2^c - 1)*bucket[2^c - 1]
 *
 * which looks like it needs multiplications and does not: running the buckets
 * from the top down and keeping a running sum computes it with two additions
 * per bucket. So a window position costs n additions to fill the buckets plus
 * 2^(c+1) to drain them, and the windows are combined with doublings.
 *
 * THE WINDOW WIDTH IS A TRADE and the formula below is the usual heuristic:
 * too small and there are too many window positions, too large and draining
 * 2^c buckets dominates. It matters enough that a fixed c would give up most
 * of the benefit at one end or the other.
 *
 * NOT CONSTANT TIME, AND THAT IS INHERENT. The bucket a point lands in IS its
 * scalar's window value, so the memory access pattern reveals the scalars.
 * There is no fix that keeps the speedup - the speedup IS the data-dependent
 * grouping. Every use must therefore be on PUBLIC scalars: verifying a batch
 * of signatures, checking a commitment against published data, recomputing a
 * proof's left-hand side. Never on a secret.
 *
 * @param {object} G        group with ZERO, add, dbl and neg
 * @param {Array}  scalars  bigints, already reduced
 * @param {Array}  points   group elements, same length
 * @param {number} [bits]   scalar width; derived from the largest if omitted
 */
/**
 * Wrap a curve object as the interface msm expects.
 *
 * Four files needed the same four-line adapter, which is a sign the interface
 * is slightly wrong rather than that the callers are repetitive: msm wants
 * `dbl` and `neg` as plain functions, and the curve objects in this library
 * expose them as methods that some also take extra arguments for. This
 * normalises that in one place.
 */
export function msm_group(C) {
    return {
        ZERO: C.ZERO,
        add: function (P, Q) { return C.add(P, Q); },
        dbl: function (P) { return C.dbl(P); },
        neg: function (P) { return C.neg(P); }
    };
}

/**
 * The bucket parameters both msm paths derive identically.
 *
 * ⭐ SHARED because jscpd found twenty-two duplicated lines between msm and
 *   the old msm_cb (now msm_task). Two copies of a parameter derivation is the worst kind to
 *   duplicate: a divergence produces a DIFFERENT BUT VALID-LOOKING result,
 *   so the two functions would disagree and neither would fail.
 */
function msm_params(scalars, points, bits) {
    /* `points` is unused: only the scalars decide the window width and the
       bucket count. It stays for symmetry with msm_window and msm_direct,
       which take the same three - a helper whose signature differs from its
       siblings is the kind of asymmetry a caller gets wrong once */
    var n = scalars.length;
    var width = bits;
    if (!width) {
        width = 1;
        for (var b = 0; b < n; b++) {
            var l = scalars[b].toString(2).length;
            if (l > width) { width = l; }
        }
    }
    /* the standard heuristic: c is about log2(n) with a small correction */
    var c = Math.floor(Math.log2(n)) - 2;
    if (c < 3) { c = 3; }
    if (c > 16) { c = 16; }
    return {
        c: c,
        num_buckets: (1 << c) - 1,
        mask: BigInt((1 << c) - 1),
        windows: Math.ceil(width / c)
    };
}

/** One window pass, folded into the running accumulator. */
/*
 * ⚠ ct DROPS THE ZERO-DIGIT SKIP. The skip below is what makes Pippenger
 *   fast and what makes it leak: a scalar whose digit is zero costs nothing
 *   in that window, so the running time counts the non-zero digits of the
 *   scalars. Over a secret scalar vector that is a direct read-out.
 *
 * ⭐ BUCKET 0 IS NEVER READ - the aggregation below runs from num_buckets
 *   down to 1 - so writing into it is harmless, and the unconditional add
 *   gives every scalar exactly one bucket add per window whatever its
 *   value. That keeps Pippenger's shape instead of falling back to one
 *   ladder per term, which measured about 10x worse.
 *
 * ⛔ THIS IS NOT FULL CONSTANT TIME and cannot be within BigInt: idx indexes
 *   the bucket array, and an addition into the identity costs less than one
 *   between two full points, because BigInt operations scale with operand
 *   magnitude. What it removes is the large, directly measurable leak - the
 *   9.7x on a_R in bulletproofs - not the residue.
 */
function msm_window(G, scalars, points, wi, p, result, ct) {
    for (var d = 0; d < p.c; d++) { result = G.dbl(result); }

    var buckets = new Array(p.num_buckets + 1);
    for (var i = 0; i <= p.num_buckets; i++) { buckets[i] = G.ZERO; }

    for (var k = 0; k < scalars.length; k++) {
        var idx = Number((scalars[k] >> BigInt(wi * p.c)) & p.mask);
        if (ct) { buckets[idx] = G.add(buckets[idx], points[k]); continue; }
        /*
         * ⚠ THIS BRANCH IS FINE, AND ONLY HERE. msm is Pippenger for
         *   VERIFICATION - its scalars are challenges and its points are
         *   published commitments, so skipping a zero window leaks nothing
         *   that was not already on the wire.
         *
         * ⛔ fixed_base ABOVE HAS NO SUCH BRANCH, deliberately: its scalar is
         *   a secret key or a nonce, and it reads every window through
         *   ct_select. A reviewer grepping for `if (idx` will find this line
         *   first; it is not the one that matters.
         */
        if (idx !== 0) { buckets[idx] = G.add(buckets[idx], points[k]); }
    }

    var running = G.ZERO, sum = G.ZERO;
    for (var j = p.num_buckets; j >= 1; j--) {
        running = G.add(running, buckets[j]);
        sum = G.add(sum, running);
    }
    return G.add(result, sum);
}

/** The small-input path, where buckets cost more than they save. */
function msm_direct(G, scalars, points) {
    var acc = G.ZERO;
    for (var q = 0; q < scalars.length; q++) {
        if (scalars[q] === 0n) { continue; }
        /* wnaf_mul takes (G, k, P, w) - there is no bits parameter, and
           passing one silently becomes a window width of 255 */
        acc = G.add(acc, wnaf_mul(G, scalars[q], points[q], 5));
    }
    return acc;
}

export function msm(G, scalars, points, bits) {
    return finish_task(msm_task(G, scalars, points, bits, false));
}

/**
 * Multi-scalar multiplication for SECRET scalars.
 *
 * ⛔ msm() ABOVE SKIPS ZERO DIGITS and so runs in time proportional to the
 *   number of non-zero digits across the scalar vector. Use this one
 *   wherever the scalars are a witness, a blinder or anything else the
 *   proof exists to hide; use msm() for verification, where the scalars
 *   arrived on the wire.
 *
 * ⚠ IT DOES NOT FALL BACK TO msm_direct for small inputs - that path calls
 *   wnaf_mul, which is variable-time by construction, and skips zero
 *   scalars outright.
 */
export function msm_ct(G, scalars, points, bits) {
    return finish_task(msm_task(G, scalars, points, bits, true));
}

/**
 * msm (ct false) or msm_ct (ct true) as a task (commons/task.js): a step is
 * one WINDOW pass, so a callback form can run a proof's msms in slices.
 *
 * ==================== WHY ====================
 *
 * ⛔ msm IS THE BLOCKING OPERATION IN EVERY PROOF SYSTEM HERE. Measured:
 *   bulletproofs.prove_range at 32 bits is about 446 point multiplications
 *   and takes ~1 second, of which essentially all is msm. kzg and
 *   bls12_381.batch_verify have the same shape. A second of blocking freezes
 *   a browser tab, and on a server stalls every other request.
 *
 * ==================== WHERE IT CUTS ====================
 *
 * The bucket algorithm runs one pass per WINDOW - about ceil(bits/c) of
 * them, each independent of the next except through the accumulator. That
 * makes the window boundary the natural step: no partial state escapes, and
 * the result after each window is exactly what one run straight through
 * holds - msm and msm_ct are this task, finished.
 *
 * ⚠ A WINDOW IS NOT UNIFORM. Its cost is proportional to the number of
 *   scalars, so with a large input one step can still be long. This trades
 *   one long block for several shorter ones; it does not promise any
 *   particular step length.
 *
 * ⚠ msm_direct (below 8 terms) calls wnaf_mul and skips zero scalars -
 *   variable-time by construction - so the ct form never takes it.
 */
export function msm_task(G, scalars, points, bits, ct) {
    var n = scalars.length;
    if (n !== points.length) { throw new Error(ct ? 'msm_ct: length mismatch' : 'msm: length mismatch'); }
    var result = G.ZERO, wi = -1, p = null, done = n === 0;
    if (!done && !(n < 8 && !ct)) {
        p = msm_params(scalars, points, bits);
        wi = p.windows - 1;
    }
    return {
        step: function () {
            if (done) { return true; }
            if (!p) {
                result = msm_direct(G, scalars, points);
                done = true;
                return true;
            }
            result = msm_window(G, scalars, points, wi, p, result, ct);
            done = --wi < 0;
            return done;
        },
        result: function () { return result; }
    };
}
