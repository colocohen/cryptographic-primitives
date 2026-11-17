/**
 * Blind signatures  -  signing something you cannot see
 *
 * The signer produces a valid signature over a message they never learn, and
 * afterwards cannot connect the finished signature to the session that
 * produced it.
 *
 *     blind(msg)        ->  a blinded value the signer sees
 *     sign_blinded(...)  ->  a signature over that value
 *     unblind(...)       ->  a signature over the REAL message
 *
 * The last step is what makes it useful: the result verifies against the
 * signer's ordinary public key, with the ordinary verifier, and looks like
 * any other signature.
 *
 * ==================== WHAT IT IS FOR ====================
 *
 * ANONYMOUS TOKENS. A service signs a token to say "this user is entitled to
 * one request", and later accepts the token without being able to tell which
 * user it issued it to. That is Privacy Pass in its original form, and the
 * anti-abuse tokens browsers use.
 *
 * eCASH. A bank signs a note without seeing its serial number. When the note
 * is spent the bank verifies its own signature and cannot link the spend to
 * the withdrawal. Chaum's construction from 1982, and the reason this
 * primitive was invented.
 *
 * VOTING. An authority signs a ballot to certify the voter was eligible,
 * without seeing the vote.
 *
 * ================ HOW IT DIFFERS FROM WHAT IS ALREADY HERE ================
 *
 * OPRF also computes on a blinded input, and the difference matters: an OPRF
 * returns a PSEUDORANDOM VALUE that only the two parties can recompute. A
 * blind signature returns a SIGNATURE that anyone can verify against a
 * published key. Different problems.
 *
 * =========================== THE HAZARD ===========================
 *
 * THE SIGNER IS SIGNING SOMETHING THEY CANNOT INSPECT. That is the point and
 * it is also the danger: nothing stops a client from blinding a message that
 * says something the signer would never agree to. A protocol using blind
 * signatures must constrain what can be signed by some other means - a
 * separate key per token type, a cut-and-choose step, or a structure the
 * client must prove their message has.
 *
 * The classic failure is a bank that uses one key for all denominations: a
 * client blinds a note claiming a larger value than they paid for, and the
 * bank signs it without seeing.
 */

/*
 * ⭐ base_mul GOES THROUGH secp256k1's COMB TABLE, which nothing here was
 *   using: multiplying G through POINT.mul ran the generic variable-base
 *   routine at 2.30 ms against 320 us.
 *
 * ⚠ IT IS CONSTANT TIME, through ct_select. Every scalar multiplied by G in
 *   this file is secret - the commitment nonce, the blinding factors, the
 *   private key - so an indexed table would be faster and would leak them.
 *
 * ⚠ AND IT RETURNS AN AFFINE POINT where POINT.mul returns the internal
 *   representation. Handing the affine form to POINT.add reads its
 *   coordinates as projective and gives a point on nothing, so call sites
 *   that feed point arithmetic lift it back with POINT.of.
 */
import { base_mul, CURVE, POINT, G, lift_x_even, bip340_challenge } from './secp256k1.js';
import { powmod_ct, powmod, mod_inverse, gcd, require_rng, mod } from './commons/primes.js';
import { concat, bytes_to_bigint, bigint_to_bytes } from './commons/bytes.js';

var N = CURVE.n;


/* ============================ RSA ============================
 *
 * Chaum's original scheme, and still the one most deployed - Privacy Pass's
 * first version, and every eCash system descended from DigiCash.
 *
 * It works because RSA is multiplicatively homomorphic:
 *
 *     blind:    m' = m * r^e  (mod n)
 *     sign:     s' = (m')^d = m^d * r  (mod n)
 *     unblind:  s  = s' / r  = m^d     (mod n)
 *
 * The signer sees m * r^e for a uniform r, which is uniform and carries no
 * information about m.
 */

/**
 * Blind a message for RSA signing.
 *
 * THE MESSAGE MUST ALREADY BE PADDED. This takes an integer, not a hash: RSA
 * without padding is malleable and forgeable, and the padding has to be
 * applied before blinding because the signer cannot check it afterwards.
 * PSS is the right choice; the caller supplies the encoded value.
 *
 * @return {{blinded: bigint, r: bigint}} keep r - it is needed to unblind
 */
export function rsa_blind(pk, padded_msg, rng) {
    rng = require_rng('rsa_blind', rng);
    var width = ((pk.n.toString(2).length + 7) >> 3) + 16;
    var r;
    for (var i = 0; i < 200; i++) {
        r = bytes_to_bigint(rng(width)) % pk.n;
        if (r > 1n && gcd(r, pk.n) === 1n) { break; }
        r = 0n;
    }
    if (r === 0n) { throw new Error('blind: could not draw a blinding factor'); }

    var blinded = (padded_msg % pk.n) * powmod(r, pk.e, pk.n) % pk.n;
    return { blinded: blinded, r: r };
}

/**
 * Sign a blinded value.
 *
 * THIS IS A RAW RSA OPERATION ON ATTACKER-SUPPLIED INPUT, which is exactly
 * what one normally refuses to do. It is safe here only because the
 * surrounding protocol constrains what the client can usefully obtain - see
 * the hazard note at the top. A signer that will sign anything has given
 * away its key for all practical purposes.
 */
export function rsa_sign_blinded(sk, blinded) {
    /*
     * ⛔ sk.d IS THE SIGNING KEY, and powmod's time tracks its Hamming
     *   weight - measured at a factor of 2 between a sparse and a dense
     *   exponent. The message is blinded, which stops chosen-input attacks;
     *   d is the same in every call, so timing accumulates.
     */
    return powmod_ct(blinded % sk.n, sk.d, sk.n);
}

/** Divide out the blinding factor. */
export function rsa_unblind(pk, blinded_sig, r) {
    var rinv = mod_inverse(r, pk.n);
    if (rinv === null) { throw new Error('blind: blinding factor is not invertible'); }
    return (blinded_sig % pk.n) * rinv % pk.n;
}

/* ============================ SCHNORR ============================
 *
 * Blind Schnorr over secp256k1, producing a signature indistinguishable from
 * an ordinary BIP 340 one.
 *
 * IT NEEDS TWO ROUNDS, unlike RSA. The signer must commit to a nonce BEFORE
 * seeing the blinded challenge, because the blinding happens on the challenge
 * rather than on the message:
 *
 *     signer:  R = k*G                          (round 1)
 *     client:  R' = R + a*G + b*P               blinds the nonce point
 *              c' = H(R'.x, P.x, msg)           the real challenge
 *              c  = c' + b                      the blinded challenge
 *     signer:  s = k + c*d                      (round 2)
 *     client:  s' = s + a                       and (R', s') verifies
 *
 * ============ THE ROS ATTACK, AND WHY IT MATTERS HERE ============
 *
 * BLIND SCHNORR IS NOT SAFE UNDER CONCURRENT SIGNING. An adversary who opens
 * many sessions at once can solve the ROS problem - Random inhomogeneities in
 * an Overdetermined Solvable system - and forge one extra signature. Benhamouda
 * et al. showed in 2020 that this is practical for a few hundred concurrent
 * sessions, which broke several deployed designs.
 *
 * THE ONLY SAFE USE IS SEQUENTIAL: one open session at a time per signer key.
 * If concurrency is needed, the answer is a different scheme - Clause Blind
 * Schnorr, which this file does not implement - and not a larger group.
 *
 * This is not a caveat that can be engineered away by careful use of the API,
 * so it is stated here rather than hidden in a parameter.
 */

/** Round 1: the signer commits to a nonce. Keep k secret and use it once. */
export function schnorr_blind_commit(rng) {
    rng = require_rng('schnorr_blind_commit', rng);
    var k = mod(bytes_to_bigint(rng(48)), N);
    if (k === 0n) { k = 1n; }
    var Rb = base_mul(k);
    return { k: k, R: POINT.of(Rb.x, Rb.y) };
}

/**
 * The client blinds the challenge.
 *
 * @param  {object}     R_point  the signer's commitment
 * @param  {Uint8Array} pubkey   the signer's x-only key, 32 bytes
 * @param  {Uint8Array} msg      32 bytes
 * @return {{c: bigint, a: bigint, b: bigint, R_prime: object}}
 */
export function schnorr_blind(R_point, pubkey, msg, rng) {
    rng = require_rng('schnorr_blind', rng);
    var P = lift_x_even(pubkey);
    if (P === null) { throw new Error('blind: invalid public key'); }

    var a = mod(bytes_to_bigint(rng(48)), N);
    var b = mod(bytes_to_bigint(rng(48)), N);
    if (a === 0n) { a = 1n; }
    if (b === 0n) { b = 1n; }

    /* R' = R + a*G + b*P */
    var Rp = (function () { var Ab = base_mul(a); return POINT.add(POINT.add(R_point, POINT.of(Ab.x, Ab.y)), POINT.mul(b, P, 256)); }());
    var Ra = POINT.to_affine(Rp);

    /*
     * IF R' HAS ODD y, EVERY TERM ON THAT SIDE FLIPS.
     *
     * A finished BIP 340 signature carries only R'.x, and the verifier checks
     * against the EVEN-y lift - which is -R' when the real point is odd. So
     * the whole relation s'*G = R' + c'*P is being checked against -R', and
     * both the blinding scalars and the signer's response have to follow.
     *
     * WORKING IT OUT RATHER THAN GUESSING, because two guesses were wrong.
     * The verifier checks s'*G == lift_even(R') + c'*P, and with R' odd that
     * is -R'. Writing R' = (k+a)*G + b*P:
     *
     *     s'*G == -(k+a)*G - b*P + c'*P
     *     s'   == -(k+a) + (c' - b)*d
     *
     * The signer will return s = k + c*d for whatever c we send. Matching the
     * two gives s' = -s - a, and that only holds when
     *
     *     c = b - c'      rather than      c = c' + b
     *
     * So the odd branch changes the CHALLENGE FORMULA, not just a sign on the
     * scalars. Flipping a, or a and b, leaves the even branch passing and the
     * odd branch failing every single time - which is what both earlier
     * attempts produced.
     */
    var neg = (Ra.y & 1n) !== 0n;

    /* the BIP 340 challenge, from secp256k1.js - the value the verifier
       will recompute, so it must not have a copy of its own here */
    var c_prime = bip340_challenge(bigint_to_bytes(Ra.x, 32), pubkey, msg);

    return {
        c: neg ? mod(b - c_prime, N) : mod(c_prime + b, N),
        a: a, b: b, R_prime: Rp, neg: neg
    };
}

/**
 * Round 2: the signer answers the blinded challenge.
 *
 * THE SIGNER LEARNS NOTHING. c is c' + b for a uniform b, so it is uniform
 * and independent of the message.
 */
export function schnorr_sign_blinded(k, secret, c) {
    var d0 = bytes_to_bigint(secret);
    if (d0 === 0n || d0 >= N) { throw new Error('blind: invalid secret key'); }
    var P = base_mul(d0);
    /* BIP 340 keys have even y */
    var d = (P.y & 1n) === 0n ? d0 : N - d0;
    return mod(k + c * d, N);
}

/**
 * Remove the blinding, producing an ordinary BIP 340 signature.
 *
 * @return {Uint8Array} 64 bytes
 */
export function schnorr_unblind(s_blinded, blinding) {
    var Ra = POINT.to_affine(blinding.R_prime);
    /* s' = -s - a when R' is odd, s + a when it is even - see schnorr_blind */
    var s = blinding.neg ? mod(-s_blinded - blinding.a, N)
                         : mod(s_blinded + blinding.a, N);
    return concat([bigint_to_bytes(Ra.x, 32), bigint_to_bytes(s, 32)]);
}

