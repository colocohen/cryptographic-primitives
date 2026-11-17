/**
 * MuSig2  -  BIP 327, n-of-n Schnorr signatures on secp256k1
 *
 * Several signers combine their keys into ONE aggregate public key, and
 * together produce ONE ordinary Schnorr signature. A verifier sees a normal
 * BIP 340 signature against a normal x-only public key and has no way to tell
 * that more than one person was involved.
 *
 * HOW IT DIFFERS FROM FROST, which this library also has:
 *
 *     FROST     t-of-n. The key is SPLIT: a dealer or a DKG produces shares,
 *               and any t of them can sign. Three of five directors.
 *     MuSig2    n-of-n. The keys are COMBINED: every signer already has their
 *               own key, brings it, and ALL of them must sign. Two partners
 *               who both have to approve.
 *
 * The practical difference is the setup. FROST needs a ceremony before anyone
 * can sign; MuSig2 needs nothing - two existing wallets can aggregate their
 * public keys and start. The cost is that there is no threshold: losing one
 * signer loses the funds.
 *
 * ==================== WHY THE KEYS CANNOT SIMPLY BE ADDED ====================
 *
 * The obvious construction - aggregate key = P1 + P2 - is broken by the
 * ROGUE KEY ATTACK. The second signer waits to see P1, then registers
 * P2 = X - P1 for an X whose secret they know. The aggregate is X, and they
 * can sign alone.
 *
 * MuSig2 stops this by weighting each key with a coefficient derived from the
 * hash of ALL the keys:
 *
 *     Q = a1*P1 + a2*P2 + ... where ai = H(L, Pi) and L = H(P1||P2||...)
 *
 * A signer choosing Pi last cannot control ai, because ai depends on Pi
 * itself. This is why key aggregation looks more complicated than it should:
 * every part of it is load-bearing.
 *
 * THE SECOND-KEY COEFFICIENT IS 1, deliberately. BIP 327 gives the first key
 * that differs from the first key in the list a coefficient of exactly 1,
 * which makes the aggregate of a single key equal to that key and saves one
 * multiplication. It looks like a special case and it is a specified one.
 *
 * ========================= TWO ROUNDS, AND WHY TWO =========================
 *
 * Each signer publishes TWO nonce points rather than one. With a single
 * nonce, an attacker running many concurrent sessions can use Wagner's
 * generalised birthday attack to forge - the same attack FROST defends
 * against, and the reason MuSig1 needed three rounds with a commitment phase.
 *
 * MuSig2's answer is that the effective nonce is R1 + b*R2 where b is a hash
 * of the aggregate nonce, the aggregate key and the message. A signer cannot
 * choose b without changing what they already published, so the attack has
 * nothing to grind against.
 *
 * ========================= TWEAKS, AND AN ADAPTOR =========================
 *
 * apply_tweak is BIP-327's (plain for a BIP-32 child, x-only for a Taproot
 * output key), and every vector of the BIP passes, tweaked ones included.
 * An adaptor point T, passed to sign / partial_verify / partial_sig_agg,
 * moves the challenge to R + T: the result is adaptor.js's Schnorr
 * pre-signature, which adaptor.js checks, completes and opens.
 *
 * REUSING A SECRET NONCE LEAKS THE SECRET KEY. Not "weakens" - leaks, from
 * two signatures, by the same arithmetic that breaks ECDSA under a repeated
 * k. The API below returns nonces as a value the caller must pass back
 * exactly once and then destroy; it cannot enforce more than that.
 */

import { CURVE, POINT, G, GROUP, encode_point, decode_point, tagged_hash, bip340_challenge }
    from './secp256k1.js';
import { concat, bytes_to_bigint, bigint_to_bytes } from './commons/bytes.js';
import { equal_bool } from './commons/ct.js';
import { require_rng, mod } from './commons/primes.js';

var N = CURVE.n;
var P = CURVE.p;


/* the BIP 340 tagged hash, from secp256k1.js - musig2 reuses BIP 340's own
   challenge tag, so the two must not have separate implementations */
var tagged = tagged_hash;

/** 32 bytes, big-endian - the x-coordinate only. */
function xbytes(pt) {
    var A = POINT.to_affine(pt);
    return bigint_to_bytes(A.x, 32);
}

/** 33 bytes, compressed SEC 1. */
function cbytes(pt) {
    var A = POINT.to_affine(pt);
    return encode_point(A.x, A.y, true);
}

function has_even_y(pt) {
    var A = POINT.to_affine(pt);
    return (A.y & 1n) === 0n;
}

/* ---------------- key aggregation ---------------- */

/** L = H(P1 || P2 || ...), the commitment to the whole key list. */
function key_list_hash(pubkeys) {
    return tagged('KeyAgg list', pubkeys);
}

/**
 * The first key in the list that differs from the first key.
 *
 * Its coefficient is 1 rather than a hash - see the note at the top. Returns
 * null when every key is identical, in which case no key gets the shortcut.
 */
function second_key(pubkeys) {
    for (var i = 1; i < pubkeys.length; i++) {
        var same = pubkeys[i].length === pubkeys[0].length;
        if (same) {
            for (var j = 0; j < pubkeys[i].length; j++) {
                if (pubkeys[i][j] !== pubkeys[0][j]) { same = false; break; }
            }
        }
        if (!same) { return pubkeys[i]; }
    }
    return null;
}

/*
 * Byte comparison, from commons/ct.js.
 *
 * Every use here is on PUBLIC data - a key list, a nonce's key binding - so
 * an early-exit compare would be correct. Using the constant-time one costs
 * nothing measurable and removes the need to re-check that judgement if a
 * future caller passes something secret.
 */
function same_bytes(a, b) {
    if (a === null || b === null) { return false; }
    return equal_bool(a, b);
}

/** ai = H(L, Pi), or 1 for the second key. */
function key_agg_coeff(pk, L, second) {
    if (same_bytes(pk, second)) { return 1n; }
    return mod(bytes_to_bigint(tagged('KeyAgg coefficient', [L, pk])), N);
}

/**
 * Aggregate a list of 33-byte compressed public keys.
 *
 * THE ORDER MATTERS. The coefficients depend on the list as given, so two
 * signers who disagree about the order compute different aggregate keys and
 * the signature simply fails. BIP 327 provides a sort for callers who want
 * order-independence; this returns what it is given.
 *
 * @return {{Q, L, pubkeys, gacc, tacc}} the aggregate context
 */
export function key_agg(pubkeys) {
    if (pubkeys.length === 0) { throw new Error('musig2: no public keys'); }
    var L = key_list_hash(pubkeys);
    var second = second_key(pubkeys);

    var Q = POINT.ZERO;
    for (var i = 0; i < pubkeys.length; i++) {
        var d = decode_point(pubkeys[i]);
        if (d === null) { throw new Error('musig2: invalid public key at ' + i); }
        var a = key_agg_coeff(pubkeys[i], L, second);
        Q = POINT.add(Q, POINT.mul(a, POINT.of(d.x, d.y), 256));
    }
    if (POINT.is_zero(Q) === 1n) { throw new Error('musig2: aggregate key is the identity'); }

    return { Q: Q, L: L, pubkeys: pubkeys, gacc: 1n, tacc: 0n };
}

/** The x-only aggregate key, which is what a BIP 340 verifier uses. */
export function get_xonly_pubkey(ctx) { return xbytes(ctx.Q); }

/** The aggregate key as 33 bytes, compressed - for a plain tweak's caller, and for verifiers that take one. */
export function get_plain_pubkey(ctx) { return cbytes(ctx.Q); }

/* ---------------- tweaking ---------------- */

/**
 * BIP-327 ApplyTweak: a new context whose key is the aggregate moved by t.
 *
 *     plain     Q' = Q + t*G                 (BIP-32 style: the child key)
 *     x-only    Q' = g*Q + t*G, g = -1 when Q has odd y
 *                                            (BIP-341: the Taproot output key)
 *
 * gacc and tacc carry the accumulated sign and shift, so each signer's
 * partial signature and the aggregation stay exactly BIP-327's. Any number
 * of tweaks, in any order; the context is a value, not mutated.
 */
export function apply_tweak(ctx, tweak, is_xonly) {
    if (!(tweak instanceof Uint8Array) || tweak.length !== 32) { throw new Error('musig2: a tweak is 32 bytes'); }
    var t = bytes_to_bigint(tweak);
    if (t >= N) { throw new Error('musig2: the tweak must be less than n'); }
    var g = is_xonly && !has_even_y(ctx.Q) ? N - 1n : 1n;
    var Q = POINT.add(POINT.mul(g, ctx.Q, 256), POINT.mul(t, G, 256));
    if (POINT.is_zero(Q) === 1n) { throw new Error('musig2: the tweaked key is the identity'); }
    return { Q: Q, L: ctx.L, pubkeys: ctx.pubkeys, gacc: mod(g * ctx.gacc, N), tacc: mod(t + g * ctx.tacc, N) };
}

/* ---------------- nonces ---------------- */

/**
 * Generate a signer's nonce pair.
 *
 * THE SECRET KEY IS MIXED INTO THE RANDOMNESS, not relied upon alone. If the
 * random source fails, the nonce is still unpredictable to anyone without the
 * key; if the key were the only input, the nonce would repeat. Both inputs
 * matter and BIP 327 requires both.
 *
 * @return {{secnonce: {k1, k2, pk}, pubnonce: Uint8Array}} 66 bytes public
 */
export function nonce_gen(rng, secret, pubkey, aggpk, msg, extra) {
    rng = require_rng('nonce_gen', rng);
    var rand = rng(32);
    if (secret) {
        var h = tagged('MuSig/aux', [rand]);
        var x = new Uint8Array(32);
        for (var i = 0; i < 32; i++) { x[i] = secret[i] ^ h[i]; }
        rand = x;
    }

    var apk = aggpk || new Uint8Array(0);
    var m_prefixed;
    if (msg === undefined || msg === null) {
        m_prefixed = new Uint8Array([0]);
    } else {
        m_prefixed = concat([new Uint8Array([1]),
                             bigint_to_bytes(BigInt(msg.length), 8), msg]);
    }
    var ex = extra || new Uint8Array(0);

    var ks = [];
    for (var j = 0; j < 2; j++) {
        var seed = concat([rand,
                           new Uint8Array([pubkey.length]), pubkey,
                           new Uint8Array([apk.length]), apk,
                           m_prefixed,
                           bigint_to_bytes(BigInt(ex.length), 4), ex,
                           new Uint8Array([j])]);
        ks.push(mod(bytes_to_bigint(tagged('MuSig/nonce', [seed])), N));
    }
    if (ks[0] === 0n || ks[1] === 0n) { throw new Error('musig2: degenerate nonce'); }

    return {
        secnonce: { k1: ks[0], k2: ks[1], pk: pubkey },
        pubnonce: concat([cbytes(POINT.mul(ks[0], G, 256)),
                          cbytes(POINT.mul(ks[1], G, 256))])
    };
}

/**
 * Sum every signer's nonce pair componentwise.
 *
 * Anyone can do this - the aggregator is untrusted, and a wrong aggregate
 * simply produces a signature that does not verify.
 */
export function nonce_agg(pubnonces) {
    var R1 = POINT.ZERO, R2 = POINT.ZERO;
    for (var i = 0; i < pubnonces.length; i++) {
        var a = decode_point(pubnonces[i].subarray(0, 33));
        var b = decode_point(pubnonces[i].subarray(33, 66));
        if (a === null || b === null) { throw new Error('musig2: invalid pubnonce at ' + i); }
        R1 = POINT.add(R1, POINT.of(a.x, a.y));
        R2 = POINT.add(R2, POINT.of(b.x, b.y));
    }
    /*
     * An aggregate that lands on infinity is encoded as 33 zero bytes rather
     * than treated as an error, because a malicious signer could otherwise
     * force the session to abort by choosing their nonce to cancel the rest.
     */
    return concat([point_or_zero(R1), point_or_zero(R2)]);
}

function point_or_zero(pt) {
    return POINT.is_zero(pt) === 1n ? new Uint8Array(33) : cbytes(pt);
}

function decode_or_zero(b) {
    var all_zero = true;
    for (var i = 0; i < b.length; i++) { if (b[i] !== 0) { all_zero = false; break; } }
    if (all_zero) { return POINT.ZERO; }
    var d = decode_point(b);
    return d === null ? null : POINT.of(d.x, d.y);
}

/* ---------------- the session ---------------- */

/**
 * Everything both signing and verification need, derived from the public
 * inputs alone.
 *
 * @return {{Q, b, R, e, gacc, tacc}}
 */
/*
 * ⭐ THE SESSION'S VALUES ONCE: b, R and e are the same for every partial a
 *    signer checks (all public), so the last ones are kept and reused while
 *    the same context, nonce, message and T come back.
 */
var last_values = null;
export function session_values(ctx, aggnonce, msg, T) {
    var l = last_values;
    if (l !== null && l.ctx === ctx && l.aggnonce === aggnonce && l.msg === msg && l.T === T) { return l.sv; }
    var sv = compute_values(ctx, aggnonce, msg, T);
    last_values = { ctx: ctx, aggnonce: aggnonce, msg: msg, T: T, sv: sv };
    return sv;
}
function compute_values(ctx, aggnonce, msg, T) {
    var R1 = decode_or_zero(aggnonce.subarray(0, 33));
    var R2 = decode_or_zero(aggnonce.subarray(33, 66));
    if (R1 === null || R2 === null) { throw new Error('musig2: invalid aggnonce'); }

    var b = mod(bytes_to_bigint(
        tagged('MuSig/noncecoef', [aggnonce, xbytes(ctx.Q), msg])), N);

    var R = POINT.add(R1, POINT.mul(b, R2, 256));
    /*
     * If the effective nonce is the point at infinity the session uses G
     * instead. That cannot help an attacker - they would have to know the
     * discrete log of G, which is 1 - and it avoids an abort that a malicious
     * signer could otherwise trigger at will.
     */
    if (POINT.is_zero(R) === 1n) { R = G; }

    /*
     * ⭐ AN ADAPTOR POINT T (adaptor.js): the challenge is over R + T, and its
     *    parity decides the nonce's sign, exactly as for one signer or FROST.
     *    R itself stays the pre-signature's R. T must be fixed before the
     *    nonces are exchanged - in the session id, say - since
     *    a T chosen after seeing R would choose the challenge's nonce point.
     */
    var Rc = R;
    if (T instanceof Uint8Array) {
        T = GROUP.decode(T);
        if (T === null || POINT.is_zero(T) === 1n) { throw new Error('musig2: T is not a point of the group, or is the identity'); }
    }
    if (T != null) {
        Rc = POINT.add(R, T);
        if (POINT.is_zero(Rc) === 1n) { throw new Error('musig2: R + T is the identity'); }
    }

    /* BIP 340's own challenge, so the aggregate verifies as a plain Schnorr
       signature - computed by secp256k1.js rather than restated here */
    var e = bip340_challenge(xbytes(Rc), xbytes(ctx.Q), msg);

    return { Q: ctx.Q, b: b, R: R, Rc: Rc, e: e, gacc: ctx.gacc, tacc: ctx.tacc };
}

/**
 * One signer's partial signature.
 *
 * THE TWO NEGATIONS ARE THE FIDDLY PART. BIP 340 keys are x-only, so both the
 * aggregate key and the final nonce may need their y flipped - and flipping a
 * point means negating the secret behind it. `g` handles the aggregate key
 * and the nonce branch handles R. Getting either wrong produces a partial
 * signature that aggregates into something that does not verify, with no
 * indication of which signer was at fault.
 *
 * @return {bigint} the partial signature
 */
export function sign(secnonce, secret, ctx, aggnonce, msg, T) {
    var sv = session_values(ctx, aggnonce, msg, T);

    var k1 = secnonce.k1, k2 = secnonce.k2;
    if (k1 === 0n || k2 === 0n || k1 >= N || k2 >= N) {
        throw new Error('musig2: invalid secnonce');
    }
    /* the nonce must match the final R's parity */
    if (!has_even_y(sv.Rc)) { k1 = N - k1; k2 = N - k2; }

    var d0 = bytes_to_bigint(secret);
    if (d0 === 0n || d0 >= N) { throw new Error('musig2: invalid secret key'); }
    var Pt = POINT.mul(d0, G, 256);
    var pk = cbytes(Pt);
    if (!same_bytes(pk, secnonce.pk)) {
        throw new Error('musig2: secnonce does not belong to this key');
    }

    var second = second_key(ctx.pubkeys);
    var a = key_agg_coeff(pk, ctx.L, second);

    /* and the secret must match the aggregate key's parity */
    var g = has_even_y(sv.Q) ? 1n : N - 1n;
    var d = mod(g * sv.gacc * d0, N);

    return mod(k1 + sv.b * k2 + sv.e * a * d, N);
}

/**
 * Check one partial signature before aggregating.
 *
 * THIS IS WHAT MAKES A FAILED SESSION ATTRIBUTABLE. Without it, one bad
 * partial produces an invalid signature and no information about who sent it,
 * and the coordinator can only retry blindly.
 *
 * @return {boolean}
 */
export function partial_verify(psig, pubnonce, pubkey, ctx, aggnonce, msg, T) {
    if (psig >= N) { return false; }
    var sv = session_values(ctx, aggnonce, msg, T);

    var r1 = decode_point(pubnonce.subarray(0, 33));
    var r2 = decode_point(pubnonce.subarray(33, 66));
    var pd = decode_point(pubkey);
    if (r1 === null || r2 === null || pd === null) { return false; }

    var Re = POINT.add(POINT.of(r1.x, r1.y),
                       POINT.mul(sv.b, POINT.of(r2.x, r2.y), 256));
    /* the signer's effective nonce follows R's parity, like the secret does */
    if (!has_even_y(sv.Rc)) { Re = POINT.neg(Re); }

    var second = second_key(ctx.pubkeys);
    var a = key_agg_coeff(pubkey, ctx.L, second);
    var g = has_even_y(sv.Q) ? 1n : N - 1n;
    var ga = mod(g * sv.gacc, N);

    /*
     * GROUP.equals, the projective comparison commons/group.js defines for
     * Weierstrass curves. This went to affine on both sides - two inversions
     * - and compared coordinates, with the null-for-identity case handled by
     * hand: the same test written a third way. Every value here is public,
     * so the left side goes through the comb table and the right through wNAF.
     */
    var lhs = GROUP.base_mul(psig);
    var rhs = POINT.add(Re, GROUP.mul_vartime(mod(sv.e * a * ga, N), POINT.of(pd.x, pd.y)));
    return GROUP.equals(lhs, rhs);
}

/**
 * Combine the partial signatures into a BIP 340 signature.
 *
 * @return {Uint8Array} 64 bytes, verifiable by schnorr_verify
 */
export function partial_sig_agg(psigs, ctx, aggnonce, msg, T) {
    var sv = session_values(ctx, aggnonce, msg, T);
    var s = 0n;
    for (var i = 0; i < psigs.length; i++) {
        if (psigs[i] >= N) { throw new Error('musig2: partial signature ' + i + ' out of range'); }
        s = mod(s + psigs[i], N);
    }
    var g = has_even_y(sv.Q) ? 1n : N - 1n;
    s = mod(s + sv.e * g * sv.tacc, N);
    /* ⭐ with T: adaptor.js's Schnorr pre-signature { R, T, s } - schnorr_verify / complete / extract read it */
    if (T != null) { return { R: cbytes(sv.R), T: T instanceof Uint8Array ? T : cbytes(T), s: s }; }
    return concat([xbytes(sv.R), bigint_to_bytes(s, 32)]);
}
