/**
 * zk_fac_sp.js - "N has no small factors", proved in a SAFE-PRIME group.
 *
 * eprint 2024/1950 section 5.1, Protocol 4 (the small factors proof Pi_fac),
 * with Lemma 5.6's special soundness.
 *
 * ==================== WHAT IT PROVES ====================
 *
 * That N = p*q with |p|, |q| <= 2^(n/2+ell+nu): no factor is small. A
 * Paillier modulus with a small factor makes the range proofs built on it
 * unsound (a small factor k lets a prover hide k-th roots), so a party that
 * receives N must check this before relying on any proof over N.
 *
 * ==================== ⛔ WHY NOT zk_cmp.prove_fac ====================
 *
 * CGGMP21's version commits under RING-PEDERSEN parameters (N^, s, t), and
 * its soundness needs the PROVER not to know their trapdoor. That holds in
 * CGGMP, where the VERIFIER supplies them. It does not hold when the prover
 * proves under its own parameters - with the factorisation of N^ it can
 * open commitments to anything and "prove" a modulus with a small factor.
 *
 * This version commits in QR_d for a public SAFE prime d, with g and h
 * derived from (d, aux) by hashing, so nobody knows log_g(h) and the
 * commitments bind everyone (Lemma 5.6: a cheating proof yields either the
 * factorisation bound or a discrete log of h to the base g mod d).
 *
 * ==================== THE PRIME d ====================
 *
 * The paper suggests the hard-coded strong prime 2^3459 + 1169115, sized for
 * n = 3072, ell = 128, nu = 64: d must exceed 2^(n + 2 ell + 2 nu + 3). A
 * larger nu needs a larger d, so the default here is the 4096-bit MODP prime
 * of RFC 3526 (group 16) - a published safe prime, re-verified by this
 * library's tests (d prime AND (d-1)/2 prime). The bound is CHECKED on every
 * call: a d too small for (n, ell, nu) is refused, not used.
 *
 * ⛔ NO EXTERNAL ORACLE.
 */
import { powmod_signed, powmod_signed_ct, is_probable_prime, mod, in_range, random_below_biased, require_rng } from './commons/primes.js';
import { require_sid, signed_mask, fs_stream, fs_signed, fs_qr } from './commons/zk_bytes.js';

/** RFC 3526 section 5, the 4096-bit MODP group prime: a safe prime. */
export var RFC3526_4096 = /* @__PURE__ */ BigInt('0x' +
    'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74' +
    '020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437' +
    '4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed' +
    'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05' +
    '98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb' +
    '9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b' +
    'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718' +
    '3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33' +
    'a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7' +
    'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864' +
    'd87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2' +
    '08e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d7' +
    '88719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8' +
    'dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2' +
    '233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9' +
    '93b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff');

/** The paper's own suggestion (section 8.1), for n = 3072, ell = 128, nu = 64. */
export var PAPER_D = /* @__PURE__ */ (1n << 3459n) + 1169115n;

var TAG = 'cryptographic-primitives/fac-sp/v2';   /* v2: the transcripts moved to zk_bytes.fs_stream */

function bits(x) { return (x < 0n ? -x : x).toString(2).length; }

/** True when d is a safe prime: d and (d-1)/2 both prime. For tests and for a caller-supplied d. */
export function is_safe_prime(d, rng) {
    return is_probable_prime(d, 40, rng) && is_probable_prime((d - 1n) >> 1n, 40, rng);
}

/**
 * g, h in QR_d, derived from (d, aux) so that nobody knows log_g(h): a hash
 * to [2, d-2], squared. Squaring lands in QR_d, which has prime order (d-1)/2.
 */
export function generators(d, aux) {
    /*
     * v2: a square from the Fiat-Shamir stream over (d, label) -
     * zk_bytes.fs_qr, the same "random square mod N" the provers use with a
     * real rng. v1 hashed shake256 with a one-byte counter and its own
     * reduction; it is the same idea, written once instead of twice.
     *
     * d - 1 is never a square for a safe prime (d = 3 mod 4), so the check
     * below matters only for a caller-supplied d that is not one.
     */
    function one(label) {
        var read = fs_stream(TAG + '/gen', aux, [d, label]);
        for (var ctr = 0; ctr < 256; ctr++) {
            var y = fs_qr(read, d);
            if (y !== d - 1n) { return y; }
        }
        throw new Error('zk_fac_sp: no generator found');
    }
    return { g: one('g'), h: one('h') };
}

function check_params(N, d, ell, nu) {
    var n = bits(N);
    var need = BigInt(n + 2 * ell + 2 * nu + 3);
    if (d <= (1n << need)) {
        throw new Error('zk_fac_sp: d must exceed 2^' + need + ' for an ' + n + '-bit N with ell = ' +
                        ell + ', nu = ' + nu + ' (Protocol 4) - pass a larger safe prime');
    }
    return n;
}

function challenge(N, d, gh, P, Q, A, B, C, aux, ell) {
    /*
     * e in +/-2^ell: zk_bytes.fs_stream over the same values, then fs_signed.
     * v1 was one sha512 digest read at a width that took the sign from bit
     * ell - the eighth Fiat-Shamir expander in the library, now gone.
     */
    var read = fs_stream(TAG + '/chal', aux, [N, d, gh.g, gh.h, P, Q, A, B, C]);
    return fs_signed(read, ell);
}

/**
 * @param {bigint} N, p, q   N = p*q
 * @param {object} o         { ell = 128, nu = 64, d = RFC3526_4096 }
 * @param {Uint8Array} aux   the session context (sid, party, ...)
 * @param {function} [rng]  omitted or null draws fresh ones from the platform
 */
export function prove_fac_sp(N, p, q, o, rng, aux) {
    require_sid('zk_fac_sp', aux);
    rng = require_rng('zk_fac_sp.prove_fac_sp', rng);
    if (p * q !== N) { throw new Error('zk_fac_sp: p*q != N'); }
    o = o || {};
    var ell = o.ell || 128, nu = o.nu || 64, d = o.d || RFC3526_4096;
    var n = check_params(N, d, ell, nu);
    var dp = (d - 1n) >> 1n, dbits = bits(d);
    var gh = generators(d, aux), g = gh.g, h = gh.h;
    var zbound = 1n << BigInt(Math.ceil(n / 2) + ell + nu);
    /* p, q < N: the ladder runs over N's width, which is public, never p's own */
    var pw = n;
    /* uniform below (d-1)/2: primes.random_below_biased. This was |signed_mask|,
       the same distribution through a sign byte that was then thrown away */
    function rnd_dp() { return random_below_biased(dp, rng); }

    for (var attempt = 0; attempt < 64; attempt++) {
        var r = rnd_dp(), s = rnd_dp();
        var P = powmod_signed_ct(g, p, d, pw) * powmod_signed_ct(h, r, d, dbits) % d;
        var Q = powmod_signed_ct(g, q, d, pw) * powmod_signed_ct(h, s, d, dbits) % d;
        var alpha = signed_mask(zbound, rng), beta = signed_mask(zbound, rng);
        var rho = rnd_dp(), sig = rnd_dp(), mu = rnd_dp();
        var zw = bits(zbound) + 1;
        var A = powmod_signed_ct(g, alpha, d, zw) * powmod_signed_ct(h, rho, d, dbits) % d;
        var B = powmod_signed_ct(g, beta, d, zw) * powmod_signed_ct(h, sig, d, dbits) % d;
        var C = powmod_signed_ct(Q, alpha, d, zw) * powmod_signed_ct(h, mu, d, dbits) % d;
        var e = challenge(N, d, gh, P, Q, A, B, C, aux, ell);
        var z1 = alpha + e * p, z2 = beta + e * q;
        /*
         * ⚠ THE VERIFIER REJECTS z OUTSIDE +/-2^(n/2+ell+nu). With alpha in that
         *   range and |e*p| <= 2^(n/2+ell) an honest z leaves it with
         *   probability about 2^-nu; then start again with fresh randomness
         *   rather than send a proof that cannot verify.
         */
        if (!in_range(z1, zbound) || !in_range(z2, zbound)) { continue; }
        return {
            P: P, Q: Q, A: A, B: B, C: C,
            z1: z1, z2: z2,
            l1: mod(rho + e * r, dp), l2: mod(sig + e * s, dp),
            w: mod(mu - e * s * p, dp)
        };
    }
    throw new Error('zk_fac_sp: could not produce an in-range response');
}

function in_qr(x, d, dp) { return x > 0n && x < d && powmod_signed(x, dp, d) === 1n; }

/** @return {boolean} */
export function verify_fac_sp(N, proof, o, aux) {
    require_sid('zk_fac_sp', aux);
    o = o || {};
    var ell = o.ell || 128, nu = o.nu || 64, d = o.d || RFC3526_4096;
    var n;
    try { n = check_params(N, d, ell, nu); } catch (e) { return false; }
    if (!proof) { return false; }
    var f = ['P', 'Q', 'A', 'B', 'C', 'z1', 'z2', 'l1', 'l2', 'w'];
    for (var i = 0; i < f.length; i++) { if (typeof proof[f[i]] !== 'bigint') { return false; } }
    var dp = (d - 1n) >> 1n;
    /* the mod-(d-1)/2 responses must be reduced: bounds the verifier's work too */
    if (proof.l1 < 0n || proof.l1 >= dp || proof.l2 < 0n || proof.l2 >= dp || proof.w < 0n || proof.w >= dp) { return false; }
    /* every commitment in QR_d, where exponents live mod the prime (d-1)/2 */
    var cs = [proof.P, proof.Q, proof.A, proof.B, proof.C];
    for (i = 0; i < cs.length; i++) { if (!in_qr(cs[i], d, dp)) { return false; } }
    var zbound = 1n << BigInt(Math.ceil(n / 2) + ell + nu);
    if (!in_range(proof.z1, zbound) || !in_range(proof.z2, zbound)) { return false; }
    var gh = generators(d, aux), g = gh.g, h = gh.h;
    var e = challenge(N, d, gh, proof.P, proof.Q, proof.A, proof.B, proof.C, aux, ell);
    var pw = function (b, x) { return powmod_signed(b, x, d); };
    if (pw(g, proof.z1) * pw(h, proof.l1) % d !== proof.A * pw(proof.P, e) % d) { return false; }
    if (pw(g, proof.z2) * pw(h, proof.l2) % d !== proof.B * pw(proof.Q, e) % d) { return false; }
    if (pw(proof.Q, proof.z1) * pw(h, proof.w) % d !== proof.C * pw(g, N * e) % d) { return false; }
    return true;
}
