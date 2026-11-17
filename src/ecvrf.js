/**
 * ECVRF  -  Verifiable Random Function, RFC 9381
 *
 * A VRF is a keyed hash whose output ANYONE CAN VERIFY was computed correctly,
 * without holding the key.
 *
 *     beta = VRF(sk, alpha)         the output - looks random to everyone
 *     pi                            a proof that beta belongs to alpha
 *     verify(pk, alpha, pi) -> beta anyone can check it
 *
 * THREE PROPERTIES, AND ALL THREE ARE NEEDED:
 *
 *   UNIQUENESS      for a given key and input there is exactly ONE output
 *                   that verifies. The holder cannot shop for a result they
 *                   like by trying variations.
 *   PSEUDORANDOMNESS to anyone without the key, beta is indistinguishable
 *                   from random - even after seeing many other outputs.
 *   VERIFIABILITY   the proof is checkable against the public key alone.
 *
 * WHAT IT IS FOR. Choosing a validator, running a lottery, assigning a shard,
 * ordering a queue - anywhere a value must be unpredictable in advance and
 * undeniable afterwards. Algorand selects its committee this way and Cardano
 * its slot leaders.
 *
 * WHY NOT JUST COMMIT-REVEAL. Because the last participant to reveal sees
 * every other value, computes the outcome, and can simply refuse to reveal if
 * they dislike it. Biasing costs one abstention. A VRF removes the choice:
 * there is one output and the key holder cannot change it.
 *
 * WHY NOT JUST A SIGNATURE. Most signature schemes are MALLEABLE in the sense
 * that matters here - a signer can produce many valid signatures over the same
 * message by varying the nonce, and then pick whichever hashes to a
 * convenient value. ECDSA and Ed25519 both allow that. A VRF's output is fixed
 * by the key and input alone.
 *
 * COMPARED TO THE BLS VRF THIS LIBRARY ALREADY HAS. BLS signatures are unique,
 * so hashing one gives a VRF for free - and that is what drand does. The
 * differences:
 *
 *     BLS      needs a pairing-friendly curve, verification is slow, but a
 *              THRESHOLD version is nearly free, so no single party holds the
 *              key at all
 *     ECVRF    ordinary curve, fast verification, standardised - but the key
 *              is held by one party
 *
 * Use BLS when no single party should be able to compute the value; use ECVRF
 * when one party legitimately holds the key and just must not be able to
 * choose the result.
 *
 * =========================== THE CIPHERSUITE HERE ===========================
 *
 * ECVRF-EDWARDS25519-SHA512-ELL2, suite byte 0x04. Edwards25519 with SHA-512,
 * hashing to the curve by Elligator2 per RFC 9380. This is the suite Cardano
 * and most Ed25519-based systems use, and the one with test vectors in
 * RFC 9381 appendix B.4.
 *
 * THE COFACTOR APPEARS IN TWO PLACES and both matter. The output hashes
 * cofactor*Gamma rather than Gamma, which clears any small-order component so
 * that two keys differing by a small-order point cannot produce the same
 * beta. And validate_key rejects public keys of small order outright.
 */

import { mod } from './commons/primes.js';
import { wnaf_mul } from './commons/fixed_window.js';
import { CURVE, POINT, base_mul, encode_point, decode_point, ed25519_h2c, expand_seed,
         get_public_key as ed_public_key } from './ed25519.js';
import { sha512 } from './sha2.js';
import { concat, ascii, bytes_to_bigint_le, bigint_to_bytes_le } from './commons/bytes.js';

var L = CURVE.L;                    /* the group order */
var COFACTOR = 8n;

/*
 * THE LADDER WIDTH IS 255, NOT 253.
 *
 * L is a 253-bit number, so 253 is the right width for any scalar reduced
 * modulo it - which is what the rest of this library multiplies by. Ed25519's
 * CLAMPED secret scalar is not reduced: clamping SETS bit 254, so the value
 * is always 255 bits and always larger than L.
 *
 * Passing 253 here silently drops the top two bits and produces a point that
 * is on the curve, encodes fine, and is wrong. That cost an afternoon.
 */
var SCALAR_BITS = 255;
var SUITE = /* @__PURE__ */ new Uint8Array([0x04]);
var C_LEN = 16;                     /* the challenge is truncated to 16 bytes */

/* the hash-to-curve DST, fixed by the suite */
var H2C_DST = /* @__PURE__ */ ascii(
    'ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\u0004');


/* the 25519 family is little-endian throughout - see commons/bytes.js */
var bytes_to_int_le = bytes_to_bigint_le;
var int_to_bytes_le = bigint_to_bytes_le;

/**
 * The secret scalar and the nonce prefix, from a 32-byte seed.
 *
 * IDENTICAL TO Ed25519's derivation, which RFC 9381 specifies deliberately so
 * that an existing Ed25519 key can serve as a VRF key. The CLAMPING - low
 * three bits cleared, top two fixed - forces the scalar into the prime-order
 * subgroup; skipping it breaks both uniqueness and the security proof.
 */
/* ed25519.js's own expansion - this file used to repeat the hash, the split
   and the clamp, which are RFC 8032's and must stay identical to it */
var expand = expand_seed;

/** @return {Uint8Array} the 32-byte public key - the same as Ed25519's */
export var get_public_key = ed_public_key;

/**
 * Hash the input to a curve point.
 *
 * The salt is the PUBLIC KEY, which is what stops one party's outputs from
 * being reusable under another party's key: the same alpha maps to a
 * different H for every signer.
 */
function encode_to_curve(pk, alpha) {
    return ed25519_h2c.encode_to_curve(concat([pk, alpha]), H2C_DST);
}

/**
 * The nonce, derived from the key and the input - never from randomness.
 *
 * This is RFC 8032's construction and it is here for the same reason it is
 * there: a repeated or predictable nonce reveals the secret scalar outright,
 * exactly as in ECDSA. Deriving it deterministically makes that failure
 * impossible rather than merely unlikely, and it is also what makes the VRF
 * output reproducible - a randomised nonce would give a different proof each
 * time for the same input, which is harmless but wasteful.
 */
function nonce(prefix, h_string) {
    return mod(bytes_to_int_le(sha512(concat([prefix, h_string]))), L);
}

/**
 * The challenge, over all five points.
 *
 * TRUNCATED TO 16 BYTES, which is the suite's choice and is deliberate: 128
 * bits is enough for the soundness of the proof, and a shorter challenge
 * makes the proof 16 bytes smaller. The domain separator bytes 0x02 and 0x00
 * bracket the points so that this hash cannot collide with the output hash,
 * which uses 0x03.
 */
function challenge(P1, P2, P3, P4, P5) {
    var parts = [SUITE, new Uint8Array([0x02])];
    var pts = [P1, P2, P3, P4, P5];
    for (var i = 0; i < pts.length; i++) { parts.push(encode_point(pts[i])); }
    parts.push(new Uint8Array([0x00]));
    var h = sha512(concat(parts));
    return bytes_to_int_le(h.subarray(0, C_LEN));
}

/**
 * Produce a proof.
 *
 * @param  {Uint8Array} seed   32 bytes, the same form as an Ed25519 seed
 * @param  {Uint8Array} alpha  the input
 * @return {Uint8Array} 80 bytes: Gamma(32) || c(16) || s(32)
 */
export function prove(seed, alpha) {
    if (seed.length !== 32) { throw new Error('ecvrf: seed must be 32 bytes'); }
    var e = expand(seed);
    var Y = get_public_key(seed);

    var H = encode_to_curve(Y, alpha);
    var h_string = encode_point(H);

    var Gamma = POINT.mul(e.scalar, H, SCALAR_BITS);
    var k = nonce(e.prefix, h_string);

    var c = challenge(decode_point(Y), H, Gamma,
                      base_mul(k), POINT.mul(k, H, SCALAR_BITS));
    var s = mod(k + c * e.scalar, L);

    return concat([encode_point(Gamma), int_to_bytes_le(c, C_LEN), int_to_bytes_le(s, 32)]);
}

/**
 * The VRF output for a proof.
 *
 * ONLY CALL THIS ON A PROOF YOU PRODUCED OR HAVE VERIFIED. It does not check
 * the proof - it just hashes Gamma - so running it on an unverified proof
 * yields a value with no guarantees behind it at all. The RFC states this
 * explicitly and it is the easiest way to misuse the API.
 *
 * @return {Uint8Array|null} 64 bytes
 */
export function proof_to_hash(pi) {
    var d = decode_proof(pi);
    if (d === null) { return null; }
    /* cofactor*Gamma clears any small-order component - see the note above */
    var cG = POINT.mul(COFACTOR, d.Gamma, 4);
    return sha512(concat([SUITE, new Uint8Array([0x03]), encode_point(cG),
                          new Uint8Array([0x00])]));
}

/** @return {{Gamma, c, s}|null} */
export function decode_proof(pi) {
    if (pi.length !== 80) { return null; }
    var Gamma = decode_point(pi.subarray(0, 32));
    if (Gamma === null) { return null; }
    var c = bytes_to_int_le(pi.subarray(32, 32 + C_LEN));
    var s = bytes_to_int_le(pi.subarray(48));
    /* a non-canonical s is a malleability hole, as in Ed25519 */
    if (s >= L) { return null; }
    return { Gamma: Gamma, c: c, s: s };
}

/**
 * Reject public keys of small order.
 *
 * Without this a malicious key holder can pick a key whose small-order
 * component makes two different inputs collide, breaking uniqueness. RFC 9381
 * section 7.1.1 is entirely about this, and the check is one scalar
 * multiplication.
 *
 * @return {boolean}
 */
export function validate_key(pk) {
    var Y = decode_point(pk);
    if (Y === null) { return false; }
    var cY = POINT.mul(COFACTOR, Y, 4);
    return !POINT.eq(cY, POINT.ZERO);
}

/**
 * Verify a proof and return the output.
 *
 * @return {Uint8Array|null} beta on success, null on failure
 */
export function verify(pk, alpha, pi, skip_key_validation) {
    var Y = decode_point(pk);
    if (Y === null) { return null; }
    if (!skip_key_validation && !validate_key(pk)) { return null; }

    var d = decode_proof(pi);
    if (d === null) { return null; }

    var H = encode_to_curve(pk, alpha);

    /* U = s*B - c*Y   and   V = s*H - c*Gamma */
    /*
     * Verification: s, c, Y, H and Gamma are all public, so the generator
     * goes through ed25519's comb table and the rest through wNAF - these
     * were four constant-time ladders.
     */
    var U = POINT.add(base_mul(d.s), POINT.neg(wnaf_mul(POINT, d.c, Y, 5)));
    var V = POINT.add(wnaf_mul(POINT, d.s, H, 5), POINT.neg(wnaf_mul(POINT, d.c, d.Gamma, 5)));

    if (challenge(Y, H, d.Gamma, U, V) !== d.c) { return null; }
    return proof_to_hash(pi);
}
