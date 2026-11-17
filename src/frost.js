/*
 * ==================== WHY THE BINDING FACTOR IS NOT OPTIONAL ====================
 *
 * FROST's nonce commitments are combined with a binding factor
 * rho = H(commitments, message), so the group nonce R depends on the message.
 * That looks like defensive hashing and is in fact the defence against a
 * concrete forgery.
 *
 * DFNS disclosed on 24 November 2025 that a threshold ECDSA protocol
 * combining PRESIGNATURES with RAW SIGNING - signing a hash the signers never
 * saw a preimage for - permits forgery: an attacker who learns the public R
 * of a presignature crafts a hash h' whose signature transforms into a valid
 * signature on a different message m, one nobody approved. They state it
 * "cannot be fixed at the protocol level" and that the only robust answer is
 * to forbid the combination at the API. The attack was first described by
 * Groth and Shoup, eprint 2021/1330.
 *
 * FROST IS NOT EXPOSED, and the reason is structural rather than lucky:
 *
 *     CGGMP    a presignature IS R, fixed before the message exists
 *     FROST    a presignature is nonces and commitments; R is only
 *              determined once the message enters the binding factor
 *
 * So there is no R for an attacker to see in advance, and nothing to craft a
 * hash against. Anyone reading this file and wondering whether rho could be
 * dropped for a round trip: that is what it is for.
 */

/**
 * FROST  -  RFC 9591, two-round threshold Schnorr signatures
 *
 * t-of-n signing on ORDINARY curves, producing a signature that is
 * indistinguishable from a single-signer one.
 *
 * WHY IT MATTERS ALONGSIDE THE BLS THRESHOLD SCHEME IN bls12_381.js.
 *
 *   BLS threshold   no communication between signers at all, but requires a
 *                   pairing-friendly curve, verification is slow, and no
 *                   existing wallet or chain recognises the signature.
 *
 *   FROST           two rounds of communication, but runs on secp256k1,
 *                   Ed25519, P-256 or ristretto255, and THE OUTPUT IS AN
 *                   ORDINARY SCHNORR SIGNATURE. A verifier cannot tell a
 *                   group produced it. Bitcoin Taproot accepts it like any
 *                   other signature.
 *
 * That last property is the point. Threshold custody becomes invisible from
 * the outside: no special script, no larger transaction, no disclosure of the
 * policy or the number of signers.
 *
 * THE TWO ROUNDS AND WHY THERE ARE TWO. A naive threshold Schnorr has each
 * signer contribute a nonce commitment, then sign. That is broken: an
 * attacker who can see others' commitments before choosing their own can run
 * Wagner's generalised birthday attack across many concurrent sessions and
 * forge. FROST's answer is the BINDING FACTOR - each signer commits to TWO
 * nonces, and the second is weighted by a hash of the whole commitment list,
 * the message and the group key. A signer cannot influence that weight
 * without changing their own commitment, which they already published.
 *
 * NONCE REUSE IS FATAL AND IS THE MOST LIKELY WAY TO GET THIS WRONG. A
 * (hiding, binding) pair from round one MUST be used in exactly one signing
 * session and then destroyed. Reusing it across two sessions leaks the
 * signer's key share to anyone who sees both signatures - the same arithmetic
 * that breaks ECDSA under a repeated k. The API below returns nonces as an
 * opaque object the caller has to pass back exactly once; it cannot enforce
 * more than that.
 *
 * THE COORDINATOR IS UNTRUSTED. It gathers commitments, distributes the
 * message, and sums the shares - and it can do none of that maliciously
 * without producing an invalid signature. It CAN refuse to produce one, so it
 * is trusted for liveness and nothing else. `verify_share` lets it identify
 * which participant sent a bad share, which is what makes an abort
 * attributable.
 */

/*
 * ⭐ THIS FILE IS ristretto255 FROST, AND IT IS NOW A THIN WRAPPER.
 *
 * The arithmetic lives in two files that take the suite as an argument:
 * frost_codec.js (the five hashes, binding factors, the challenge, scalar
 * encoding) and frost_pure.js (nonce generation, the signature share, share
 * verification). They run on six ciphersuites; this file binds them to
 * ristretto255 and keeps the API every existing caller uses.
 *
 * ⚠ AN EARLIER HEADER HERE SAID "THE CURVE IS A PARAMETER NOW". It was not -
 *   the file imported ristretto255 and nothing else - and it still is not: a
 *   caller wanting FROST on another curve uses frost_pure and frost_codec
 *   with that curve's GROUP. What changed is that this file stopped carrying
 *   private copies of those two: binding factors, challenge, nonce, share and
 *   share verification were all written out again here for one curve. They
 *   were checked byte for byte against the shared versions before going.
 *
 * ⚠ THE CHECKS GOT STRICTER, NEVER LOOSER. The codec refuses a commitment
 *   list with a duplicate or zero identifier, and any Element that is not
 *   exactly 32 bytes - including the group public key passed to sign and
 *   verify_share. The copies here hashed whatever they were given.
 *
 * ⛔ THE LAGRANGE COEFFICIENT STAYS CONSTANT TIME. frost_pure computes it
 *   through codec.derive_interpolating_value, which goes to shamir.js's
 *   Fermat inverse - the same one this file used directly. The verify note at
 *   the bottom says why: a timing signal on it reveals who signed.
 */
import * as r255 from './ristretto255.js';
import { msm } from './commons/fixed_window.js';

/*
 * ⚠ pippenger NEEDS `dbl`, which ristretto's public surface does not expose -
 *   it has `add` only, because doubling a ristretto point is just adding it to
 *   itself and a separate name would suggest otherwise.
 */
var GROUP_ADAPTER = {
    ZERO: r255.IDENTITY,
    add: r255.add,
    dbl: function (P) { return r255.add(P, P); },
    neg: r255.neg
};

import * as shamir from './shamir.js';
import * as codec from './frost_codec.js';
import * as pure from './frost_pure.js';
import { require_rng } from './commons/primes.js';

var ORDER = r255.ORDER;
var SUITE = 'ristretto255';
var GROUP = r255.GROUP;

var enc = r255.encode;

/* ---------------- key generation ---------------- */

/**
 * Trusted-dealer key generation, RFC 9591 appendix C.
 *
 * Shamir sharing of a secret over the scalar field, with the group public key
 * being the secret's public key. WHOEVER RUNS THIS SEES THE WHOLE SECRET -
 * a real deployment should use a distributed key generation instead, which is
 * a protocol rather than a function and is out of scope here. The same
 * caveat, and the same reasoning, as bls12_381.js's split_secret.
 *
 * @return {{group_public_key, shares: [{id, share, public}], secret}}
 */
export function keygen_dealer(t, n, rng, secret) {
    rng = require_rng('keygen_dealer', rng);
    if (t < 2 || t > n) { throw new Error('frost: need 2 <= t <= n'); }

    var s0 = secret === undefined ? r255.scalar_from_uniform_bytes(rng(64))
                                  : r255.scalar_from_canonical_bytes(secret);
    /* the secret is a SCALAR (RFC 9591 C: 32 bytes, canonical), not uniform
       bytes to reduce */
    if (s0 === null) { throw new Error('frost: secret must be a canonical 32-byte scalar'); }
    /* the polynomial and its evaluation live in shamir.js - the same
       code serves bls12_381.js, over a different field */
    var raw = shamir.split(s0, t, n, rng, ORDER);
    var shares = raw.map(function (sh) {
        return { id: sh.index, share: sh.value, public: enc(r255.base_mul(sh.value)) };
    });
    var coeffs = [s0];

    return {
        group_public_key: enc(r255.base_mul(coeffs[0])),
        shares: shares,
        secret: coeffs[0]
    };
}

/* ---------------- round one ---------------- */

/*
 * The nonce is frost_pure's nonce_generate: H3(random32 || the share), with
 * the randomness drawn inside it. Mixing the share in means that a failure of
 * the random source alone does not produce a predictable nonce - it would
 * also have to leak the share, which it cannot. Both inputs matter:
 * randomness alone is a single point of failure, and the share alone would
 * repeat.
 */

/**
 * Round one: produce two nonces and their commitments.
 *
 * THE NONCES MUST NOT LEAVE THE SIGNER AND MUST NOT BE REUSED. The
 * commitments go to the coordinator; the nonces are held for round two and
 * then destroyed.
 *
 * @return {{nonces: {hiding, binding}, commitment: {id, hiding, binding}}}
 */
export function commit(id, share, rng) {
    rng = require_rng('commit', rng);
    /* hiding first, then binding - each draws 32 bytes, in this order */
    var hiding = pure.nonce_generate(SUITE, share, rng);
    var binding = pure.nonce_generate(SUITE, share, rng);
    return {
        nonces: { hiding: hiding, binding: binding },
        commitment: {
            id: id,
            hiding: enc(r255.base_mul(hiding)),
            binding: enc(r255.base_mul(binding))
        }
    };
}

/* ---------------- binding factors and the group commitment ---------------- */

/*
 * The codec's commitment list: {identifier, hiding, binding}. This file's
 * callers spell the identifier `id`, which is the only difference. The codec
 * sorts by identifier itself and refuses duplicates and zero, so the sort
 * that used to live here went with the encoding it fed.
 */
function codec_list(list) {
    return list.map(function (c) {
        return { identifier: BigInt(c.id), hiding: c.hiding, binding: c.binding };
    });
}

/* RFC 9591 section 4.4, from frost_codec.js: one factor per identifier,
   keyed by its decimal string */
function binding_factors(group_public_key, list, msg) {
    return codec.compute_binding_factors(SUITE, group_public_key, msg, list);
}

/*
 * ⚠ THE ONE PIECE KEPT LOCAL, deliberately. frost_pure.group_commitment takes
 *   decoded points and walks them with one constant-time ladder per signer;
 *   this one DECODES (the validation boundary) and sums all 2n points in a
 *   single Pippenger pass, which is safe because every input is a published
 *   commitment. Same R; different boundary and cost.
 */
function group_commitment(list, factors) {
    /*
     * ⭐ ONE MULTI-SCALAR MULTIPLICATION, not one scalar multiply per signer.
     *
     *   The sum is
     *
     *       sum_i ( H_i + rho_i * B_i )
     *
     *   which is a single MSM over 2n points with scalars [1,...,1,rho...].
     *   Written as a loop of r255.mul it ran an independent 253-bit ladder
     *   per participant; pippenger shares the doubling chain across all of
     *   them.
     *
     * ⚠ THE DECODES STILL DOMINATE. Each is a 252-bit exponentiation inside
     *   ristretto's inverse square root, and there are two per participant -
     *   batching those needs a batch inverse-sqrt, which is not the same
     *   trick as batch inversion and is not done here.
     *
     * ⛔ AND AN INVALID ENCODING MUST STILL THROW. r255.decode returns null
     *   for a point off the curve or a non-canonical encoding, and feeding
     *   that to the MSM would produce a group commitment from garbage rather
     *   than a rejection.
     */
    var pts = [], scs = [];
    for (var i = 0; i < list.length; i++) {
        var h = r255.decode(list[i].hiding);
        var b = r255.decode(list[i].binding);
        if (!h || !b) { throw new Error('frost: invalid commitment'); }
        pts.push(h); scs.push(1n);
        pts.push(b); scs.push(factors[list[i].id.toString()]);
    }
    return msm(GROUP_ADAPTER, scs, pts, 253);
}

/* RFC 9591 section 4.6, from frost_codec.js */
function challenge(R, group_public_key, msg) {
    return codec.compute_challenge(SUITE, enc(R), group_public_key, msg);
}

/* everything both sign and verify_share derive from the public inputs */
function session(commitment_list, group_public_key, msg) {
    var list = codec_list(commitment_list);
    var factors = binding_factors(group_public_key, list, msg);
    var R = group_commitment(commitment_list, factors);
    return {
        factors: factors,
        participants: list.map(function (c) { return c.identifier; }),
        R: R,
        challenge: challenge(R, group_public_key, msg)
    };
}

/* ---------------- round two ---------------- */

/**
 * Round two: one signer's share of the signature.
 *
 * @param {object} nonces  from commit(), used EXACTLY ONCE
 * @param {Array}  commitment_list  every participating signer's round-one output
 * @return {bigint} the signature share
 */
export function sign(id, share, group_public_key, nonces, msg, commitment_list) {
    var sv = session(commitment_list, group_public_key, msg);
    /* z_i = hiding + binding*rho_i + lambda_i*share*c - frost_pure.sign_share */
    return pure.sign_share(GROUP, SUITE, {
        factors: sv.factors,
        identifier: BigInt(id),
        participants: sv.participants,
        hiding: nonces.hiding,
        binding: nonces.binding,
        secret: share,
        challenge: sv.challenge
    });
}

/**
 * Verify one participant's share before aggregating.
 *
 * THIS IS WHAT MAKES AN ABORT ATTRIBUTABLE. Without it a single bad share
 * produces an invalid signature with no indication of who sent it, and the
 * coordinator can only retry blindly. With it, the faulty participant is
 * named.
 *
 * @return {boolean}
 */
export function verify_share(id, participant_public, commitment, share_value,
                             commitment_list, group_public_key, msg) {
    var sv = session(commitment_list, group_public_key, msg);

    /* the decoding boundary: an invalid encoding is a failed check, not a throw */
    var h = r255.decode(commitment.hiding);
    var b = r255.decode(commitment.binding);
    var PK = r255.decode(participant_public);
    if (!h || !b || !PK) { return false; }

    /* z_i*G == (hiding_i + rho_i*binding_i) + (c*lambda_i)*PK_i - frost_pure */
    return pure.verify_share(GROUP, SUITE, {
        factors: sv.factors,
        identifier: BigInt(id),
        participants: sv.participants,
        hiding_pt: h,
        binding_pt: b,
        PK_i: PK,
        z: share_value,
        challenge: sv.challenge
    });
}

/**
 * Aggregate the shares into one signature.
 *
 * The coordinator learns nothing and cannot forge: a wrong sum produces a
 * signature that fails verification. It SHOULD verify before publishing,
 * which is what the caller should do with `verify`.
 *
 * @return {Uint8Array} 64 bytes, R || z
 */
export function aggregate(commitment_list, msg, group_public_key, shares) {
    var R = session(commitment_list, group_public_key, msg).R;

    var z = 0n;
    for (var i = 0; i < shares.length; i++) { z = codec.mod(z + shares[i], ORDER); }

    return codec.serialize_signature(SUITE, enc(R), z);
}

/**
 * Verify a FROST signature.
 *
 * IT IS AN ORDINARY SCHNORR VERIFICATION over the group - nothing about it
 * refers to thresholds or participants. That is the whole selling point.
 *
 * @return {boolean}
 */
export function verify(msg, sig, group_public_key) {
    if (sig.length !== 64) { return false; }
    var R = r255.decode(sig.subarray(0, 32));
    var PK = r255.decode(group_public_key);
    if (!R || !PK) { return false; }

    /* DeserializeScalar, with the range check RFC 9591 requires - it was a
       little-endian loop here and a `z >= ORDER` test */
    var z;
    try { z = codec.deserialize_scalar(SUITE, sig.subarray(32)); } catch (e) { return false; }

    var c = challenge(R, group_public_key, msg);
    /* z*G == R + c*PK */
    /*
     * ⭐ VARIABLE-TIME IS CORRECT HERE. This is verification: z and R come
     *   from the signature, c is the hash of published values, and PK is the
     *   group public key. Nothing on this line is secret from anyone who can
     *   observe the timing, because all of it is already public.
     *
     * ⛔ THE SIGNING PATHS ABOVE MUST NOT DO THIS. Their scalars include the
     *   share and the Lagrange coefficient, and a timing signal on the
     *   latter reveals which participants signed - which is part of what
     *   threshold signing is for.
     */
    return r255.equals(r255.base_mul(z), r255.add(R, r255.mul_vartime(c, PK)));
}
