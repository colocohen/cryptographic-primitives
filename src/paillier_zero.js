/**
 * paillier_zero.js - Pi^zero: a Paillier ciphertext encrypts ZERO.
 *
 *     common input (N, C); the prover knows rho with  C = rho^N mod N^2
 *
 * An encryption of 0 is exactly an N-th residue mod N^2, so this is a proof
 * of knowledge of an N-th root - Damgard-Jurik's (PKC 2001), the pi_ZERO of
 * Hazay, Mikkelsen, Rabin, Toft, Nicolosi (eprint 2011/494, section 3.2
 * item 2, and the general form pi_EXP-RERAND of section 3.3 item 3, which is
 * where its proof is written out):
 *
 *     1. Prover: r <- Z*_N,  a = r^N mod N^2
 *     2. Verifier: e <- [0, 2^kappa)
 *     3. Prover: z = r * rho^e mod N
 *     check  z^N = a * C^e  mod N^2
 *
 * WHAT IT IS FOR. A party whose values are all Paillier ciphertexts under its
 * OWN key (CGGMP21's "Paillier as a commitment", Remark 2.1) proves a LINEAR
 * relation among them by combining them homomorphically into one ciphertext
 * that must encrypt 0, and proving that. E.g. p_i = x + m*k:
 *
 *     C = Enc(p_i) * Enc(x)^-1 * Enc(k)^-m     encrypts p_i - x - m*k
 *
 * ⛔ THE RELATION THIS GIVES IS MOD N, NOT OVER THE INTEGERS. "C encrypts 0"
 *   is "the combination is 0 mod N". To read it as an integer equation every
 *   value in it needs a range proof (Pi^enc) small enough that the
 *   combination cannot reach N - 2011/494 section 4.1 is the warning.
 *
 * ⛔ PROVING IS NOT REVEALING. The prover knows the combined randomiser and
 *   could simply publish it; that opens THIS combination, and combined with
 *   another opening later it opens the parts. The proof shows the root
 *   exists without giving it.
 *
 * Perfect honest-verifier zero knowledge (z is a uniform unit, a follows).
 * Special soundness: from (a, e, z), (a, e', z) with e != e', alpha(e - e') +
 * beta N = 1 by Euclid, and ((z/z')^alpha C^beta)^N = C - which needs e - e'
 * to be a unit mod N - below N's smallest prime factor, which the caller
 * must vouch for as opts.factor_bits (zk_bytes.paillier_kappa: without it a
 * prover with N = 65537 q forges this proof in about 10^5 hashes).
 *
 * The challenge is non-negative (as in DJ01 and 2011/494), so no inverse of
 * the secret rho is ever taken.
 *
 * ⛔ NO EXTERNAL ORACLE.
 */

import { mod, powmod, unit_in, random_unit, require_rng } from './commons/primes.js';
import { fs_stream, fs_uint, require_sid, paillier_kappa,
         encode_proof, decode_proof } from './commons/zk_bytes.js';

var TAG = 'cryptographic-primitives/paillier-zero/v1';
var INTS = ['a', 'z'];

function challenge(N, C, a, kappa, sid) {
    return fs_uint(fs_stream(TAG, sid, [N, C, a, BigInt(kappa)]), kappa);
}

/**
 * @param {object} pk     the PROVER's Paillier key {n}
 * @param {bigint} C      the ciphertext, rho^N mod N^2
 * @param {bigint} rho    its randomiser, in Z*_N
 * @param {function} rng
 * @param {object} opts   { factor_bits (REQUIRED, see zk_bytes.paillier_kappa), kappa (default 128) }
 * @param {Uint8Array} sid
 * @return {{a: bigint, z: bigint}}
 */
export function prove_zero(pk, C, rho, rng, opts, sid) {
    require_sid('paillier_zero', sid);
    rng = require_rng('prove_zero', rng);
    var N = pk.n, N2 = N * N;
    var kappa = paillier_kappa('paillier_zero', opts, [N]);
    if (!unit_in(rho, N)) { throw new Error('paillier_zero: rho must be a unit mod N'); }
    if (powmod(rho, N, N2) !== mod(C, N2)) { throw new Error('paillier_zero: C is not rho^N - the statement is false'); }
    var r = random_unit(N, rng);
    var a = powmod(r, N, N2);
    var e = challenge(N, C, a, kappa, sid);
    /* e is public: a variable-time power of rho is fine; e >= 0, so no inverse */
    return { a: a, z: mod(r * powmod(rho, e, N), N) };
}

/** @return {boolean} */
export function verify_zero(pk, C, proof, opts, sid) {
    require_sid('paillier_zero', sid);
    if (!proof) { return false; }
    var N = pk.n, N2 = N * N;
    var kappa = paillier_kappa('paillier_zero', opts, [N]);
    try {
        if (!unit_in(C, N2) || !unit_in(proof.a, N2) || !unit_in(proof.z, N)) { return false; }
        var e = challenge(N, C, proof.a, kappa, sid);
        return powmod(proof.z, N, N2) === mod(proof.a * powmod(C, e, N2), N2);
    } catch (err) {
        return false;
    }
}

/* ---------------- serialisation ---------------- */

export function encode_zero(proof) { return encode_proof(proof, INTS, []); }

/** @return {object|null} null if the encoding is malformed */
export function decode_zero(bytes) { return decode_proof(bytes, INTS, [], []); }
