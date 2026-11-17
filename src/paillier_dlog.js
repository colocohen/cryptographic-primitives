/**
 * paillier_dlog.js - Pi^enc-exp: a Paillier ciphertext and an exponent in a
 * group of HIDDEN order hold the same integer.
 *
 *     common input (N0, C, M, g, Y); the prover knows (x, rho) with
 *         C = (1+N0)^x rho^N0   mod N0^2
 *         Y = g^x               mod M          x an INTEGER, |x| < 2^xbits
 *
 * M is a modulus nobody can factor - in threshold RSA, the RSA modulus being
 * shared, and g a base in Z*_M. The statement ties a value committed under
 * Paillier (where the protocol computed it) to the exponent the RSA group
 * uses (where signing needs it).
 *
 *     per repetition k:
 *     1. r <- [0, 2^(xbits+eps)),  sigma <- Z*_N0;   A = Enc(r; sigma),  B = g^r
 *     2. c in {0, 1}
 *     3. z = r + c x  (over the integers),  tau = sigma rho^c mod N0
 *     check  Enc(z; tau) = A C^c,  g^z = B Y^c,  |z| < 2^(xbits+eps) + 2^xbits
 *
 * ⭐ ONE-BIT CHALLENGES, AND THAT IS THE POINT. From the two answers of one
 *   repetition the extractor gets x' = z1 - z0 EXACTLY, as an integer, with
 *   g^x' = Y and Enc(x') = C. A wider challenge would leave Y = g^x' times an
 *   element of order dividing c - c', and in Z*_M - order hidden, small odd
 *   orders possible - nothing rules such an element out without an extra
 *   assumption. Damgard-Dupont make the same choice for the same reason
 *   (PKC 2005, section 4.6: "secure no matter how the RSA modulus is
 *   chosen"). `reps` repetitions in parallel, Fiat-Shamir: soundness 2^-reps.
 *
 * ⛔ THE INTEGER x' EQUALS THE PAILLIER PLAINTEXT ONLY IF IT CANNOT WRAP:
 *   |x'| < 2^(xbits+eps+1) must stay below N0/2. Checked from the key.
 *
 * Statistical zero knowledge: z = r + c x with r uniform over 2^(xbits+eps)
 * values is within 2^-eps of r alone, per repetition - `eps` must exceed
 * log2(reps) by the statistical margin (default 80 + 7).
 */

import { mod, powmod, powmod_signed, powmod_signed_ct, unit_in, random_unit,
         require_rng } from './commons/primes.js';
import { fs_stream, fs_bits, require_sid, encode_proof, decode_proof } from './commons/zk_bytes.js';
import { enc_raw, enc_raw_sk } from './paillier.js';
import { bytes_to_bigint } from './commons/bytes.js';

var TAG = 'cryptographic-primitives/paillier-dlog/v1';
var INTS = ['A', 'B', 'z', 'tau'];

function params(opts, N0) {
    var o = opts || {};
    var xbits = o.xbits, eps = o.eps == null ? 87 : o.eps, reps = o.reps == null ? 128 : o.reps;
    if (!Number.isInteger(xbits) || xbits < 1) { throw new TypeError('paillier_dlog: opts.xbits (a public bound on |x|) is required'); }
    if (!Number.isInteger(eps) || eps < 64) { throw new RangeError('paillier_dlog: eps must be at least 64'); }
    if (!Number.isInteger(reps) || reps < 64 || reps > 1024) { throw new RangeError('paillier_dlog: reps must be in [64, 1024]'); }
    /* the extracted x' must not wrap mod N0 */
    if (xbits + eps + 2 >= N0.toString(2).length - 1) {
        throw new RangeError('paillier_dlog: N0 is too small for xbits + eps — the extracted value could wrap');
    }
    return { xbits: xbits, eps: eps, reps: reps };
}

function challenge(N0, C, M, g, Y, P, A, B, sid) {
    var parts = [N0, C, M, g, Y, BigInt(P.xbits), BigInt(P.eps), BigInt(P.reps)];
    for (var k = 0; k < A.length; k++) { parts.push(A[k], B[k]); }
    return fs_bits(fs_stream(TAG, sid, parts), P.reps);
}

function mask(bits, rng) {
    var bytes = (bits + 7) >> 3;
    return bytes_to_bigint(rng(bytes)) >> BigInt(bytes * 8 - bits);
}

/**
 * @param {object} pk     the PROVER's Paillier key {n} (C is under it)
 * @param {bigint} C      Enc(x; rho)
 * @param {bigint} x      the integer, |x| < 2^opts.xbits
 * @param {bigint} rho    C's randomiser
 * @param {bigint} g      the base in Z*_M
 * @param {bigint} Y      g^x mod M
 * @param {bigint} M      a modulus of hidden order
 * @param {function} rng
 * @param {object} opts   { xbits (required), eps (87), reps (128), sk (the prover's
 *                        Paillier secret key, to encrypt by CRT — optional) }
 * @param {Uint8Array} sid
 * @return {{A: bigint[], B: bigint[], z: bigint[], tau: bigint[]}}
 */
export function prove_dlog(pk, C, x, rho, g, Y, M, rng, opts, sid) {
    require_sid('paillier_dlog', sid);
    rng = require_rng('prove_dlog', rng);
    var N0 = pk.n, N2 = N0 * N0;
    var P = params(opts, N0);
    var bound = 1n << BigInt(P.xbits);
    if (typeof x !== 'bigint' || x <= -bound || x >= bound) { throw new RangeError('paillier_dlog: |x| is not below 2^xbits'); }
    var sk = opts && opts.sk && opts.sk.n === N0 ? opts.sk : null;
    var enc = function (m, r) { return sk ? enc_raw_sk(sk, m, r) : enc_raw(N0, N2, m, r); };
    if (enc(x, rho) !== mod(C, N2)) { throw new Error('paillier_dlog: C is not Enc(x; rho) — the statement is false'); }
    /* x is secret (an RSA key share): constant time, at the public bound's width (review 11-07) */
    if (powmod_signed_ct(g, x, M, P.xbits + 1) !== mod(Y, M)) { throw new Error('paillier_dlog: Y is not g^x — the statement is false'); }

    var rbits = P.xbits + P.eps, A = [], B = [], r = [], sigma = [];
    for (var k = 0; k < P.reps; k++) {
        r.push(mask(rbits, rng));
        sigma.push(random_unit(N0, rng));
        A.push(enc(r[k], sigma[k]));
        /* r is secret: constant time, at its public width */
        B.push(powmod_signed_ct(g, r[k], M, rbits));
    }
    var c = challenge(N0, C, M, g, Y, P, A, B, sid);
    var z = [], tau = [];
    for (var j = 0; j < P.reps; j++) {
        z.push(r[j] + (c[j] ? x : 0n));
        tau.push(c[j] ? mod(sigma[j] * rho, N0) : sigma[j]);
        r[j] = 0n; sigma[j] = 0n;
    }
    return { A: A, B: B, z: z, tau: tau };
}

/** @return {boolean} */
export function verify_dlog(pk, C, g, Y, M, proof, opts, sid) {
    require_sid('paillier_dlog', sid);
    if (!proof) { return false; }
    try {
        var N0 = pk.n, N2 = N0 * N0;
        var P = params(opts, N0);
        var A = proof.A, B = proof.B, z = proof.z, tau = proof.tau;
        if (!Array.isArray(A) || !Array.isArray(B) || !Array.isArray(z) || !Array.isArray(tau)) { return false; }
        if (A.length !== P.reps || B.length !== P.reps || z.length !== P.reps || tau.length !== P.reps) { return false; }
        if (!unit_in(C, N2) || !unit_in(g, M) || !unit_in(Y, M)) { return false; }
        var zmax = (1n << BigInt(P.xbits + P.eps)) + (1n << BigInt(P.xbits));
        for (var i = 0; i < P.reps; i++) {
            if (!unit_in(A[i], N2) || !unit_in(B[i], M) || !unit_in(tau[i], N0)) { return false; }
            if (typeof z[i] !== 'bigint' || z[i] <= -zmax || z[i] >= zmax) { return false; }
        }
        var c = challenge(N0, C, M, g, Y, P, A, B, sid);
        for (var k = 0; k < P.reps; k++) {
            var lhs1 = enc_raw(N0, N2, z[k], tau[k]);
            var rhs1 = c[k] ? mod(A[k] * C, N2) : A[k];
            if (lhs1 !== rhs1) { return false; }
            var lhs2 = powmod_signed(g, z[k], M);
            var rhs2 = c[k] ? mod(B[k] * Y, M) : B[k];
            if (lhs2 !== rhs2) { return false; }
        }
        return true;
    } catch (err) {
        return false;
    }
}

/* ---------------- serialisation ---------------- */

export function encode_dlog(proof) { return encode_proof(proof, INTS, []); }

/** @return {object|null} null if the encoding is malformed */
export function decode_dlog(bytes) { return decode_proof(bytes, INTS, [], INTS); }
