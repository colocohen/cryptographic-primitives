/**
 * paillier_mul.js - Pi^mul: a Paillier ciphertext is a PRODUCT of two.
 *
 *     common input (N, X, Y, C); the prover knows (x, rho, rho_x) with
 *         X = (1+N)^x rho_x^N   and   C = Y^x rho^N    mod N^2
 *
 * so C encrypts x*y where y is Y's plaintext (which the prover need not
 * know). CGGMP21 (eprint 2021/060), Figure 28 of the January 2021 revision
 * (appendix C.5; the current revision dropped it with the three-round
 * presign), after Damgard-Jurik:
 *
 *     1. Prover: alpha <- Z_N, r, s <- Z*_N;
 *        A = Y^alpha r^N,  B = (1+N)^alpha s^N            mod N^2
 *     2. Verifier: e
 *     3. Prover: z = alpha + e x,  u = r rho^e,  v = s rho_x^e   mod N
 *     check  Y^z u^N = A C^e   and   (1+N)^z v^N = B X^e    mod N^2
 *
 * ⛔ THE FIGURE AS PRINTED LEAKS x. It takes z = alpha + e*x OVER THE
 *   INTEGERS with alpha uniform in Z_N - but x is a full element of Z_N and
 *   e is up to 2^kappa, so alpha cannot hide e*x: alpha = z - e*x in [0, N)
 *   pins x to an interval of width N/e, about kappa bits of x per proof.
 *   (Its second check also reads "c^N" for "v^N".)
 *
 *   HERE z IS REDUCED MOD N, and the multiple of N it drops is folded into u:
 *   with alpha + e*x = z + k*N,
 *
 *       Y^(alpha + e x) = Y^z (Y^k)^N,   so   u = Y^k r rho^e mod N
 *
 *   (reducing u mod N is sound because (a + bN)^N = a^N mod N^2), and
 *   (1+N)^(kN) = 1 mod N^2 leaves the second check unchanged. z is then a
 *   uniform element of Z_N (up to random_below_biased's 2^-128) and u, v
 *   uniform units: statistical honest-verifier zero knowledge at 2^-128,
 *   which the printed figure does not have at all.
 *
 * ⚠ k DEPENDS ON x (k = floor((alpha + e x) / N)), so Y^k goes through the
 *   constant-time ladder at the width of its public bound, 2^kappa.
 *
 * ⛔ THE PRODUCT IS MOD N. Like every Paillier relation, "C encrypts x*y" is
 *   x*y mod N; reading it over the integers needs range proofs on x and y
 *   that keep |x*y| below N/2.
 *
 * The challenge is e in [0, 2^kappa), non-negative as in DJ01 rather than the
 * figure's +-q: there is no group here to take q from, and with e >= 0 no
 * inverse of a secret randomiser is ever needed. Special soundness:
 * x = (z - z')/(e - e') mod N, which needs e - e' to be a unit mod N - below
 * N's smallest prime factor, vouched for as opts.factor_bits
 * (zk_bytes.paillier_kappa).
 *
 * ⛔ NO EXTERNAL ORACLE.
 */

import { mod, powmod, powmod_ct, unit_in, random_unit, random_below_biased,
         require_rng } from './commons/primes.js';
import { fs_stream, fs_uint, require_sid, paillier_kappa,
         encode_proof, decode_proof } from './commons/zk_bytes.js';
import { enc_raw } from './paillier.js';

var TAG = 'cryptographic-primitives/paillier-mul/v1';
var INTS = ['A', 'B', 'z', 'u', 'v'];

function challenge(N, st, A, B, kappa, sid) {
    return fs_uint(fs_stream(TAG, sid, [N, st.X, st.Y, st.C, A, B, BigInt(kappa)]), kappa);
}

/**
 * @param {object} pk    the PROVER's Paillier key {n}; X, Y, C all live under it
 * @param {object} st    { X, Y, C }
 * @param {object} wit   { x, rho, rho_x }  x in [0, N); rho for C, rho_x for X
 * @param {function} rng
 * @param {object} opts  { factor_bits (REQUIRED, see zk_bytes.paillier_kappa), kappa (default 128) }
 * @param {Uint8Array} sid
 * @return {{A, B, z, u, v}}
 */
export function prove_mul(pk, st, wit, rng, opts, sid) {
    require_sid('paillier_mul', sid);
    rng = require_rng('prove_mul', rng);
    var N = pk.n, N2 = N * N;
    var kappa = paillier_kappa('paillier_mul', opts, [N]);
    var x = mod(wit.x, N);
    if (!unit_in(wit.rho, N) || !unit_in(wit.rho_x, N)) { throw new Error('paillier_mul: randomisers must be units mod N'); }
    if (enc_raw(N, N2, x, wit.rho_x) !== mod(st.X, N2) ||
        mod(powmod_ct(mod(st.Y, N2), x, N2, N.toString(2).length) * powmod(wit.rho, N, N2), N2) !== mod(st.C, N2)) {
        throw new Error('paillier_mul: the witness does not open the statement');
    }

    var alpha = random_below_biased(N, rng);
    var r = random_unit(N, rng), s = random_unit(N, rng);
    var nbits = N.toString(2).length;
    /* alpha hides x: the constant-time ladder at the width of N */
    var A = mod(powmod_ct(mod(st.Y, N2), alpha, N2, nbits) * powmod(r, N, N2), N2);
    var B = enc_raw(N, N2, alpha, s);

    var e = challenge(N, st, A, B, kappa, sid);

    var full = alpha + e * x;              /* in [0, 2^kappa N) */
    var z = mod(full, N);
    var k = (full - z) / N;                /* in [0, 2^kappa) - secret-dependent */
    var Yk = powmod_ct(mod(st.Y, N), k, N, kappa + 1);
    return {
        A: A, B: B, z: z,
        u: mod(Yk * r % N * powmod(wit.rho, e, N), N),
        v: mod(s * powmod(wit.rho_x, e, N), N)
    };
}

/** @return {boolean} */
export function verify_mul(pk, st, proof, opts, sid) {
    require_sid('paillier_mul', sid);
    if (!proof) { return false; }
    var N = pk.n, N2 = N * N;
    var kappa = paillier_kappa('paillier_mul', opts, [N]);
    try {
        for (var i = 0; i < INTS.length; i++) { if (typeof proof[INTS[i]] !== 'bigint') { return false; } }
        if (!unit_in(st.X, N2) || !unit_in(st.Y, N2) || !unit_in(st.C, N2)) { return false; }
        if (!unit_in(proof.A, N2) || !unit_in(proof.B, N2)) { return false; }
        if (proof.z < 0n || proof.z >= N) { return false; }      /* canonical: one encoding per proof */
        if (!unit_in(proof.u, N) || !unit_in(proof.v, N)) { return false; }
        var e = challenge(N, st, proof.A, proof.B, kappa, sid);
        /* Y^z u^N = A C^e mod N^2 */
        if (mod(powmod(st.Y, proof.z, N2) * powmod(proof.u, N, N2), N2) !==
            mod(proof.A * powmod(st.C, e, N2), N2)) { return false; }
        /* (1+N)^z v^N = B X^e mod N^2 */
        return enc_raw(N, N2, proof.z, proof.v) === mod(proof.B * powmod(st.X, e, N2), N2);
    } catch (err) {
        return false;
    }
}

/* ---------------- serialisation ---------------- */

export function encode_mul(proof) { return encode_proof(proof, INTS, []); }

/** @return {object|null} null if the encoding is malformed */
export function decode_mul(bytes) { return decode_proof(bytes, INTS, [], []); }
