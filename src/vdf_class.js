/**
 * VDF over a class group  -  Wesolowski's, with no setup and no one to trust
 *
 * The same delay function as vdf.js - y = x^(2^T), T squarings one after
 * another, and a proof checked in milliseconds - in the class group of an
 * imaginary quadratic field (class_group.js) instead of Z*_N. vdf.js's group
 * has an order its maker knew (RSA-2048's factors were "destroyed"); this
 * one's order is known to no one, from the moment its discriminant is
 * derived from a public seed.
 *
 *     D = discriminant(seed, bits)          any public seed, any size (×8)
 *     x = group(D).generator()              or group(D).hash_to_group(input)
 *     { y, proof } = evaluate(x, T, D)      T squarings, then the proof
 *     verify(x, y, proof, T, D)             two short exponentiations
 *
 * ======================== CHIA, BYTE FOR BYTE ========================
 *
 * With the defaults - the compressed encoding, a 264-bit challenge prime
 * from HashPrime(enc(x) ‖ enc(y), 264, {263}) - this is chiavdf's
 * one-segment Wesolowski proof (proof_common.h GetB, verifier.h
 * VerifyWesolowskiProof): the same D from the same seed, the same y, the
 * same π, the same 100-byte elements for |D| <= 1024 bits. A proof made by
 * chiavdf verifies here, and one made here verifies there (the tests run
 * both). That is what lets a native prover and this verifier - or a later
 * port of this one - agree on every byte.
 *
 * ======================== CHOOSING THE PARAMETERS ========================
 *
 * They are the caller's; nothing here is fixed. What decides them:
 *
 *   - THE THREAT IS COMPUTING THE CLASS NUMBER h(D): with it, x^(2^T) is
 *     x^(2^T mod h), one short exponentiation, and the delay is gone. The
 *     best algorithm is subexponential, L|D|[1/2, 1] heuristically; the
 *     usual estimates put 1024 bits around 90-bit work, 1348 bits at
 *     112-bit, 1827 bits at 128-bit (Hamdy-Möller; Biasse, Jacobson, Silvester).
 *   - ONE GROUP FOR A LONG TIME is the harder case: an attacker has all that
 *     time, and a group whose order happens to be weak (smooth - found by
 *     Sutherland's generic algorithm) stays weak, with no known way to tell
 *     in advance. Dobson, Galbraith and Smith (ePrint 2020/196) put the
 *     fixed-group size for 128-bit security at about 3840 bits, 6784 if the
 *     chance of a weak group must itself be 2^-128.
 *   - A FRESH GROUP PER CHALLENGE (Chia: a discriminant per challenge, 1024
 *     bits) leaves an attacker the challenge's lifetime, not years, and a
 *     weak group only that long. A long-running chain gets the same by
 *     changing D on a schedule, from a seed nobody knows before the change
 *     (one derived from the chain itself at that point).
 *   - SPEED is the delay's other half: the delay is only as long as the
 *     fastest evaluator in existence makes it. Measured in
 *     tools/bench/vdf.mjs.
 */

import * as CG from './class_group.js';
import * as W from './commons/wesolowski.js';
import { concat } from './commons/bytes.js';

/** Chia's challenge-prime width. */
export var PRIME_BITS = 264;

function group_of(D) {
    var G = CG.group(D);
    if (!G.wesolowski) {
        G.wesolowski = { one: G.identity(), mul: G.mul, square: G.square, equals: G.equals };
    }
    return G;
}

/* an element as a form - a form of this group, or its encoding - or null */
function element(G, v, compressed) {
    if (v instanceof Uint8Array) { return G.decode(v, { compressed: compressed }); }
    if (v && typeof v.a === 'bigint' && typeof v.b === 'bigint' && typeof v.c === 'bigint' &&
        G.is_reduced(v) && v.b * v.b - 4n * v.a * v.c === G.D) { return v; }
    return null;
}

/**
 * ℓ = HashPrime(enc(x) ‖ enc(y), bits, {bits − 1}): the challenge prime, from
 * both elements' encodings - so it is fixed only once y is (chiavdf GetB).
 */
export function challenge(x, y, D, opts) {
    var o = opts || {}, G = group_of(D), bits = o.prime_bits || PRIME_BITS;
    var enc = { compressed: o.compressed !== false };
    return CG.hash_prime(concat([G.encode(x, enc), G.encode(y, enc)]), bits, [bits - 1]);
}

/**
 * y = x^(2^T) and its proof.
 *
 * @param x          a form of the group of D, or its encoding
 * @param {number} T squarings
 * @param {bigint} D
 * @param {object} [opts]
 *   prime_bits      the challenge prime's width (default 264, Chia's)
 *   compressed      the encoding the challenge hashes, and of `bytes` (default true)
 *   k, max_checkpoints   the prover's memory and time (commons/wesolowski.js)
 * @return {{ y, proof, l, bytes: { y, proof } }}
 */
export function evaluate(x, T, D, opts) {
    var o = opts || {}, G = group_of(D), comp = o.compressed !== false;
    var xf = element(G, x, comp);
    if (!xf) { throw new TypeError('vdf_class: x is not an element of this group'); }
    var r = W.evaluate(G.wesolowski, xf, T, function (a, b) { return challenge(a, b, D, o); }, o);
    var enc = { compressed: comp };
    return { y: r.y, proof: r.proof, l: r.l, bytes: { y: G.encode(r.y, enc), proof: G.encode(r.proof, enc) } };
}

/**
 * Whether y = x^(2^T), by the proof. x, y and proof are forms of the group of
 * D or their encodings - and an encoding that is not the one encoding of a
 * reduced form of THIS discriminant is rejected before anything else
 * (class_group decode). Never throws on bad input: false.
 */
export function verify(x, y, proof, T, D, opts) {
    try {
        var o = opts || {}, G = group_of(D), comp = o.compressed !== false;
        var xf = element(G, x, comp), yf = element(G, y, comp), pf = element(G, proof, comp);
        if (!xf || !yf || !pf) { return false; }
        if (!Number.isSafeInteger(T) || T < 0) { return false; }
        return W.verify(G.wesolowski, xf, yf, pf, T, challenge(xf, yf, D, o));
    } catch (e) {
        return false;
    }
}
