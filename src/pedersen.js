/**
 * Pedersen commitments
 *
 * A commitment lets you fix a value now and reveal it later, such that you
 * cannot change your mind (BINDING) and nobody learns it early (HIDING).
 * Pedersen's construction is
 *
 *     C = v*G + r*H
 *
 * where v is the value, r is a random blinding factor, and G and H are two
 * generators with NO KNOWN relationship.
 *
 * IT IS PERFECTLY HIDING AND COMPUTATIONALLY BINDING, and the asymmetry
 * matters. Because r is uniform, C is uniform over the whole group whatever v
 * is - so a commitment reveals NOTHING about the value even to an adversary
 * with unlimited computing power, now or in fifty years. Binding is the
 * weaker half: opening one commitment to two values requires solving a
 * discrete log, which is hard today and would not be against a quantum
 * computer.
 *
 * That trade is the right way round for most uses. A commitment published
 * today is often still sensitive in thirty years; a commitment that could be
 * cheated open in thirty years usually is not, because the protocol resolved
 * long ago. Hash commitments have the opposite profile - perfectly binding,
 * only computationally hiding - which is why they are the wrong tool for
 * anything where the value stays secret.
 *
 * EVERYTHING RESTS ON H. If anyone knows h such that H = h*G, they can open
 * any commitment to any value: C = v*G + r*H = (v + r*h)*G, and any (v', r')
 * with v' + r'h equal to that opens it. So H is DERIVED BY HASHING TO THE
 * CURVE, which produces a point whose discrete log nobody knows - including
 * whoever wrote this. That is the whole reason hash-to-curve exists.
 *
 * THE HOMOMORPHISM is what makes it more than a commitment:
 *
 *     C(v1, r1) + C(v2, r2) = C(v1 + v2, r1 + r2)
 *
 * Sums of commitments commit to sums of values. That is what lets a
 * confidential transaction prove inputs equal outputs without revealing any
 * amount, and it is what makes Pedersen the input to range proofs.
 *
 * TWO GROUPS ARE SUPPORTED: ristretto255 and secp256k1. The first has no
 * cofactor and canonical encodings, which is what a new design should use;
 * the second is there because Bitcoin and Ethereum tooling speaks it.
 */

import * as r255 from './ristretto255.js';
import * as secp from './secp256k1.js';
import { concat, ascii, be32 } from './commons/bytes.js';
import { require_rng, mod } from './commons/primes.js';

/* ---------------- the two groups ---------------- */

/*
 * ⭐ THE CURVES' OWN GROUP OBJECTS, plus the second generator H.
 *
 *   This file used to build two adapters by hand - one around ristretto255's
 *   exports, one around secp256k1's POINT with its own SEC 1 encode, affine
 *   equality, comb-table base_mul and wNAF - re-creating, field by field,
 *   what commons/group.js already provides for both curves. Every protocol
 *   file but this one took a GROUP; now this one does too.
 *
 * ⚠ ONE IDENTITY BEHAVIOUR FOR THE LIBRARY: GROUP.encode THROWS on the
 *   identity and GROUP.decode refuses it. The secp256k1 adapter used to
 *   encode it as 33 zero bytes and the ristretto one as ristretto's
 *   canonical zero encoding. No Pedersen operation needs the identity on
 *   the wire: a commitment is the identity only for v = r = 0 mod q, which a
 *   uniform blinding factor makes negligible, and verify_balance compares
 *   points without encoding them. A caller who commits with a zero blinding
 *   factor to zero has published the value, and an error says so.
 *
 * H is derived from a domain-separated hash of the generator's encoding,
 * so it is reproducible and its discrete log is unknown. The bytes hashed
 * and the suites are unchanged, so both H are the same points as before.
 */
function with_h(G, dst) {
    return { G: G, H: G.hash(G.encode(G.GENERATOR), ascii(dst)) };
}

var RISTRETTO = /* @__PURE__ */ with_h(r255.GROUP, 'cryptographic-primitives/pedersen/ristretto255/H');
var SECP = /* @__PURE__ */ with_h(secp.GROUP, 'cryptographic-primitives/pedersen/secp256k1/H');

export var GROUPS = { ristretto255: RISTRETTO, secp256k1: SECP };

function group_of(name) {
    var g = GROUPS[name || 'ristretto255'];
    if (!g) { throw new Error('pedersen: unknown group ' + name); }
    return g;
}

/* ---------------- commitments ---------------- */

/**
 * A fresh blinding factor.
 *
 * MUST be uniform over the scalar field and MUST NOT be reused across
 * commitments to different values - two commitments sharing a blinding factor
 * let an observer compute the difference of the values from the difference of
 * the commitments.
 *
 * @param {function} rng  (n) -> Uint8Array
 */
var EMPTY_DOMAIN = /* @__PURE__ */ new Uint8Array(0);

export function random_blinding(rng, group) {
    rng = require_rng('random_blinding', rng);
    return group_of(group).G.random_scalar(rng);
}

/**
 * @param  {bigint}   value     the committed value
 * @param  {bigint}   blinding  from random_blinding
 * @return {object}   the commitment point
 */
export function commit(value, blinding, group) {
    var g = group_of(group), G = g.G;
    /* GROUP.base_mul and GROUP.mul reduce their scalars themselves */
    return G.add(G.base_mul(value), G.mul(blinding, g.H));
}

/** The commitment as bytes, for transmission and comparison. */
export function commit_bytes(value, blinding, group) {
    return group_of(group).G.encode(commit(value, blinding, group));
}

/**
 * Check that a commitment opens to a value.
 *
 * @return {boolean}
 */
export function verify(commitment, value, blinding, group) {
    return group_of(group).G.equals(commitment, commit(value, blinding, group));
}

/* ---------------- the homomorphism ---------------- */

/**
 * Add commitments. The result commits to the sum of the values under the sum
 * of the blindings - which the caller must track to open it.
 */
export function add(c1, c2, group) { return group_of(group).G.add(c1, c2); }

export function sub(c1, c2, group) { var G = group_of(group).G; return G.add(c1, G.neg(c2)); }

/** Multiply a commitment by a scalar: C(v, r) * k = C(v*k, r*k). */
export function scale(c, k, group) {
    return group_of(group).G.mul(k, c);
}

/**
 * Sum a list of commitments and the matching blindings.
 *
 * @return {{commitment: object, blinding: bigint}}
 */
export function sum(commitments, blindings, group) {
    var G = group_of(group).G;
    var acc = G.IDENTITY;
    var r = 0n;
    for (var i = 0; i < commitments.length; i++) {
        acc = G.add(acc, commitments[i]);
        if (blindings) { r = (r + blindings[i]) % G.ORDER; }
    }
    return { commitment: acc, blinding: r };
}

/**
 * Verify that a set of commitments balances: sum(inputs) == sum(outputs).
 *
 * THIS IS THE CONFIDENTIAL TRANSACTION CHECK, and it works without knowing a
 * single value. If the difference of the two sums is a commitment to zero
 * then the values balance - and a commitment to zero is just `excess * H`,
 * which is what the caller proves knowledge of.
 *
 * WHAT IT DOES NOT PROVE is that every value is non-negative. Without a range
 * proof alongside it, a participant can commit to a negative amount and
 * "balance" the equation while creating value from nothing. That is not a
 * hypothetical: it is the single most important thing range proofs exist for.
 *
 * @param  {bigint} excess  the difference of the blinding sums
 * @return {boolean}
 */
export function verify_balance(inputs, outputs, excess, group) {
    var g = group_of(group), G = g.G;
    var lhs = sum(inputs, null, group).commitment;
    var rhs = sum(outputs, null, group).commitment;
    var diff = G.add(lhs, G.neg(rhs));
    /* ⭐ e is the claimed excess - an input to verification, so public */
    return G.equals(diff, G.mul_vartime(excess, g.H));
}

/* ---------------- proving equality without revealing ---------------- */

/**
 * Prove that two commitments hide the SAME value, without revealing it.
 *
 * If C1 = v*G + r1*H and C2 = v*G + r2*H then C1 - C2 = (r1-r2)*H, so proving
 * knowledge of the discrete log of the difference in base H proves the values
 * are equal. This is a Schnorr proof of that knowledge.
 *
 * The challenge is derived by hashing the transcript - Fiat-Shamir - so the
 * proof is non-interactive. THE HASH MUST COVER EVERYTHING the verifier will
 * use: both commitments and the prover's nonce point. Omitting any of them
 * lets a prover choose the challenge and forge.
 *
 * @return {{R: Uint8Array, s: Uint8Array}}
 */
export function prove_equal(c1, c2, r1, r2, rng, group, domain) {
    rng = require_rng('prove_equal', rng);
    var g = group_of(group), G = g.G;
    var dom = domain || EMPTY_DOMAIN;
    var delta = mod(r1 - r2, G.ORDER);

    var k = G.random_scalar(rng);
    var R = G.mul(k, g.H);

    var e = challenge(g, c1, c2, R, dom);
    var s = (k + e * delta) % G.ORDER;

    return { R: G.encode(R), s: G.scalar_bytes(s) };
}

/** @return {boolean} */
export function verify_equal(c1, c2, proof, group, domain) {
    var g = group_of(group), G = g.G;
    var dom = domain || EMPTY_DOMAIN;
    var R = G.decode(proof.R);
    if (!R) { return false; }
    /*
     * ⛔ CANONICAL ONLY, NOW. This reduced whatever bytes it was given -
     *   s + q, or any length, decoded to the same s - the hole dleq.js and
     *   oprf.js both had closed. GROUP.scalar_from_bytes refuses it.
     */
    var s = G.scalar_from_bytes(proof.s);
    if (s === null) { return false; }

    var e = challenge(g, c1, c2, R, dom);
    /* s*H must equal R + e*(C1 - C2) */
    /*
     * ⭐ VARIABLE-TIME IS CORRECT HERE. s and e come from the proof and the
     *   transcript - both published before this function is called.
     *
     * ⛔ prove_equal ABOVE KEEPS THE LADDER: its scalars are the blinding
     *   factors, which the commitment exists to hide.
     */
    var lhs = G.mul_vartime(s, g.H);
    var rhs = G.add(R, G.mul_vartime(e, G.add(c1, G.neg(c2))));
    return G.equals(lhs, rhs);
}

function challenge(g, c1, c2, R, dom) {
    return g.G.hash_to_scalar(concat([
        /*
         * ⚠ THE LIBRARY NAMES THE SCHEME; THE CALLER NAMES THE CONTEXT.
         *
         * The constant identifies the proof system and the group. Both sides
         * must agree on it or nothing verifies, so it is correctly the
         * library's - unlike `domain`, which separates one USE of the proof
         * from another and only the caller can know.
         *
         * dleq, ring, elgamal and the three paillier proofs all took a
         * domain and this did not, which was an inconsistency rather than a
         * decision.
         *
         * ⚠ IT DEFAULTS TO EMPTY so existing callers are unchanged - and an
         *   empty domain separates nothing. A system running several
         *   protocols over one group should pass one, and the length prefix
         *   below is what stops two different domains colliding by
         *   concatenation.
         */
        ascii('cryptographic-primitives/pedersen/equal/' + g.G.name),
        be32(dom.length), dom,
        g.G.encode(c1), g.G.encode(c2), g.G.encode(R)
    ]));
}

/*
 * The response scalar is GROUP.scalar_bytes - whichever byte order the curve
 * uses. This file used to choose the order by comparing the group's NAME to
 * 'ristretto255', a third way of answering a question the GROUP answers.
 */

/** The two generators, exposed so a caller can check them or reuse them. */
export function generators(group) {
    var g = group_of(group);
    return { G: g.G.encode(g.G.GENERATOR), H: g.G.encode(g.H) };
}
