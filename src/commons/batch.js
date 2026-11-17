import { msm } from './fixed_window.js';
import { require_rng } from './primes.js';

/**
 * commons/batch.js - what every batch signature check shares: the random
 * weights, and the walk from "the batch failed" to "these items".
 *
 * A batch check is one equation, Σ z_i·(item i's equation) == 0, over
 * random weights z_i drawn AFTER the items are fixed. Every valid item
 * makes its term vanish, so a valid batch always passes; an invalid one
 * survives only if its z_i hits one value mod the group order - 2^-128 with
 * 128-bit weights. The equation itself is the scheme's (commons/eddsa.js,
 * secp256k1.js BIP-340); these two are not.
 */

/*
 * A weight in [1, 2^128): 16 bytes, drawn once more on zero - the one value
 * that would drop its item from the check. Zero twice is a broken rng, not
 * luck, and with it the weights are no secret: refused.
 *
 * rng omitted or null draws fresh ones from the platform.
 */
export function batch_weight(rng, who) {
    rng = require_rng('batch.batch_weight', rng);
    var z = le(rng(16));
    if (z === 0n) { z = le(rng(16)); }
    if (z === 0n) { throw new Error(who + ': the rng returned zeros'); }
    return z;
}

function le(b) {
    var x = 0n;
    for (var i = b.length - 1; i >= 0; i--) { x = (x << 8n) | BigInt(b[i]); }
    return x;
}

/**
 * Every item valid? Below `min` items one by one (`one`): an msm's buckets
 * cost more than they save there, and the answer is the same.
 *
 * @param holds  (items) → boolean, the batch equation over all of them
 * @param one    (item)  → boolean, the scheme's own verify
 */
export function batch_all(items, holds, one, min) {
    if (items.length >= min) { return holds(items); }
    for (var i = 0; i < items.length; i++) { if (!one(items[i])) { return false; } }
    return true;
}

/**
 * The indices of the items that are NOT valid, ascending. A failing batch is
 * halved and each half checked again; below `min` items each one goes
 * through `one` - the scheme's own verify - so the indices are exactly the
 * ones it rejects. One bad item among n costs about 2·log2(n) batches.
 */
export function batch_find(items, holds, one, min) {
    var bad = [];
    (function find(idx) {
        if (idx.length < min) {
            for (var i = 0; i < idx.length; i++) { if (!one(items[idx[i]])) { bad.push(idx[i]); } }
            return;
        }
        if (holds(idx.map(function (i) { return items[i]; }))) { return; }
        var mid = idx.length >> 1;
        find(idx.slice(0, mid));
        find(idx.slice(mid));
    })(items.map(function (_, i) { return i; }));
    return bad;
}

/*
 * ⭐ THE SCHNORR BATCH EQUATION ON A PRIME-ORDER GROUP (the common GROUP
 *    interface, commons/group.js), for schemes whose verify checks
 *    s·B == R + c·P - schnorr.js, frost_pure's signatures, sr25519:
 *
 *        Σ z_i·R_i + Σ (z_i·c_i)·P_i − (Σ z_i·s_i)·B == O
 *
 *    over entries { R, P, s, c, key } each already past its scheme's own
 *    checks. On a group of prime order each item's equation holds or it
 *    does not - no small-order part to kill, as EdDSA must - so a valid
 *    batch always passes, and an invalid one with probability 2^-128.
 *    key: bytes naming P, or null; entries with one key share its msm term.
 *    rng omitted or null draws fresh ones from the platform.
 */
export function group_batch_holds(G, entries, rng, who) {
    rng = require_rng('batch.group_batch_holds', rng);
    var scalars = [], points = [], by_key = new Map(), sB = 0n, n = G.ORDER;
    for (var i = 0; i < entries.length; i++) {
        var e = entries[i], z = batch_weight(rng, who);
        sB = (sB + z * e.s) % n;
        scalars.push(z);
        points.push(e.R);
        var zc = (z * e.c) % n;
        var key = e.key ? String.fromCharCode.apply(null, e.key) : null;
        var at = key === null ? undefined : by_key.get(key);
        if (at === undefined) {
            if (key !== null) { by_key.set(key, scalars.length); }
            scalars.push(zc);
            points.push(e.P);
        } else {
            scalars[at] = (scalars[at] + zc) % n;
        }
    }
    scalars.push((n - sB) % n);
    points.push(G.GENERATOR);
    /* every scalar is public - a weight drawn here or a value from a signature - so the variable-time msm is right */
    return G.equals(msm(msm_of(G), scalars, points), G.IDENTITY);
}

/* msm's view of a GROUP: ZERO, add, dbl, neg - built once per group */
var MSM_VIEWS = new WeakMap();
function msm_of(G) {
    var v = MSM_VIEWS.get(G);
    if (!v) {
        v = { ZERO: G.IDENTITY, add: G.add, neg: G.neg, dbl: function (P) { return G.add(P, P); } };
        MSM_VIEWS.set(G, v);
    }
    return v;
}

/** The common argument check: an array of items, and { rng } (the CSPRNG by default). */
export function batch_items(items, who) {
    if (!Array.isArray(items)) { throw new TypeError(who + ': items is an array of { msg, sig, pk }'); }
}
