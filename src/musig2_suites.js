/**
 * MuSig2 on the other Schnorr suites — Ed25519, Ed448, ristretto255, sr25519.
 *
 *     Nick, Ruffing, Seurin, "MuSig2: Simple Two-Round Schnorr
 *     Multi-Signatures", CRYPTO 2021 (ePrint 2020/1261), with BIP-327's
 *     structure (KeySort, KeyAgg, NonceGen, NonceAgg, Sign,
 *     PartialSigVerify, PartialSigAgg, plain tweaks).
 *
 * musig2.js is BIP-327 — Bitcoin's MuSig2, x-only keys and tagged hashes.
 * This is the same protocol where the signature is another suite's: the
 * challenge is the suite's own (frost_codec compute_challenge), so the
 * aggregate verifies under the ordinary verifier —
 *
 *     ed25519     RFC 8032 Ed25519           ed448       RFC 8032 Ed448
 *     ristretto255 RFC 9591's Schnorr         sr25519     schnorrkel (sr25519.js)
 *
 * ⭐ THE SAME FUNCTION NAMES AND ARGUMENTS AS musig2.js, bound to a suite by
 *    `musig2_on(curve)`, so a caller switches suite, not code.
 *
 * ⭐ NO STANDARD FIXES THE HASHES HERE (BIP-327's are Bitcoin's). Each is the
 *    suite's own domain-separated hash-to-scalar (frost_codec
 *    hash_to_scalar_labelled) under a label of this file's:
 *
 *        "musig2 keyagg list"   L = H(P_1 ‖ … ‖ P_n)          over the sorted keys
 *        "musig2 keyagg coef"   a_i = H(L ‖ P_i)
 *        "musig2 nonce"         k_j = H(rand' ‖ P ‖ Q ‖ msg ‖ extra ‖ j)
 *        "musig2 noncecoef"     b = H(R_1 ‖ R_2 ‖ Q ‖ msg)
 *
 *    The verifier never sees them — it checks an ordinary signature — so
 *    they only have to agree among the signers, who all run this file.
 *
 * ⭐ NO PARITY ANYWHERE. These keys are whole points, not x-only, so nothing
 *    is negated: tweaks are plain (Q + t·G), the nonce is R₁ + b·R₂, and an
 *    adaptor point moves the challenge to R + T (adaptor.js schnorr_nonce).
 *
 * ⭐ sr25519: the message is sr25519.signing_message(context, message), as
 *    for FROST on that suite.
 *
 * ⛔ A NONCE IS USED ONCE. nonce_gen's secnonce signs one partial signature;
 *    two from one nonce give the key away.
 */

import { GROUP as ED25519, POINT as ED25519_POINT, expand_seed as ed25519_expand } from './ed25519.js';
import { GROUP as ED448, POINT as ED448_POINT, expand_seed as ed448_expand } from './ed448.js';
import { GROUP as RISTRETTO } from './ristretto255.js';
import { secret_scalar as sr25519_scalar } from './sr25519.js';
import { suite, serialize_scalar, deserialize_scalar, serialize_signature, compute_challenge, hash_to_scalar_labelled } from './frost_codec.js';
import { schnorr_nonce } from './adaptor.js';
import { concat, lp32 } from './commons/bytes.js';
import { double_mul } from './commons/fixed_window.js';
import { mod } from './commons/primes.js';

var GROUPS = { ed25519: ED25519, ed448: ED448, ristretto255: RISTRETTO, sr25519: RISTRETTO };
/* the curve under each group (ristretto255's elements are Ed25519 points), for the interleaved walk */
var CURVES = { ed25519: ED25519_POINT, ed448: ED448_POINT, ristretto255: ED25519_POINT, sr25519: ED25519_POINT };


/** KeySort: the encoded keys in byte order. */
function key_sort(keys) {
    return keys.slice().sort(function (a, b) {
        for (var i = 0; i < Math.min(a.length, b.length); i++) { if (a[i] !== b[i]) { return a[i] - b[i]; } }
        return a.length - b.length;
    });
}

/**
 * The suite's MuSig2: { key_agg, apply_tweak, get_plain_pubkey, nonce_gen,
 * nonce_agg, session_values, sign, partial_verify, partial_sig_agg,
 * key_sort, secret_from, curve, GROUP }.
 */
export function musig2_on(curve) {
    var G = GROUPS[curve];
    if (!G) { throw new Error('musig2: no MuSig2 here for "' + curve + '" — ed25519, ed448, ristretto255, sr25519 (and BIP-327 on taproot, musig2.js)'); }
    var cs = suite(curve), N = G.ORDER, Ne = cs.Ne, C = CURVES[curve];
    var H = function (label, parts) { return hash_to_scalar_labelled(curve, 'musig2 ' + label, concat(parts)); };
    var dec = function (b, what) {
        var P = b instanceof Uint8Array && b.length === Ne ? G.decode(b) : null;
        if (P == null) { throw new Error('musig2: ' + what + ' is not a point of the group'); }
        return P;
    };

    function coeff(L, pk) { return H('keyagg coef', [L, pk]); }
    /* a key's coefficient, once per context — partial_verify asks for every signer's */
    function coeff_of(ctx, pk) {
        var key = pk.join(',');
        if (!ctx.coef) { ctx.coef = new Map(); }
        if (!ctx.coef.has(key)) { ctx.coef.set(key, coeff(ctx.L, pk)); }
        return ctx.coef.get(key);
    }
    /*
     * ⭐ THE SESSION'S VALUES ONCE: b, R and e are the same for every partial
     *    a signer checks (all public), so the last ones are kept and reused
     *    while the same context, nonce, message and T come back.
     */
    var last = null;

    /** KeyAgg over keys in the order given (KeySort them first). */
    function key_agg(pubkeys) {
        if (!Array.isArray(pubkeys) || pubkeys.length < 1) { throw new Error('musig2: key_agg needs keys'); }
        var L = serialize_scalar(curve, H('keyagg list', pubkeys.map(function (p) { dec(p, 'a key'); return p; }))), Q = G.IDENTITY;   // the list's hash, as bytes
        for (var i = 0; i < pubkeys.length; i++) {
            var P = dec(pubkeys[i], 'a key');
            if (G.equals(P, G.IDENTITY)) { throw new Error('musig2: a key is the identity'); }
            Q = G.add(Q, G.mul_vartime(coeff(L, pubkeys[i]), P));
        }
        if (G.equals(Q, G.IDENTITY)) { throw new Error('musig2: the aggregate key is the identity'); }
        return { Q: Q, L: L, tacc: 0n, pubkeys: pubkeys.slice() };
    }
    function get_plain_pubkey(ctx) { return G.encode(ctx.Q); }

    /** A plain tweak: Q + t·G. These keys have no x-only form. */
    function apply_tweak(ctx, tweak, is_xonly) {
        if (is_xonly) { throw new Error('musig2: an x-only tweak is BIP-340\'s — "' + curve + '" keys are whole points'); }
        var t = tweak instanceof Uint8Array ? deserialize_scalar(curve, tweak) : BigInt(tweak);
        if (t < 0n || t >= N) { throw new Error('musig2: tweak out of range'); }
        var Q = G.add(ctx.Q, G.base_mul(t));
        if (G.equals(Q, G.IDENTITY)) { throw new Error('musig2: the tweaked key is the identity'); }
        return { Q: Q, L: ctx.L, tacc: mod(ctx.tacc + t, N), pubkeys: ctx.pubkeys };
    }

    /**
     * Two nonces, hedged: fresh randomness XORed with a hash of the secret,
     * then hashed with the key, the aggregate, the message and `extra`.
     * secret: the scalar's encoding (secret_from), or null.
     */
    function nonce_gen(rng, secret, pubkey, aggpk, msg, extra) {
        if (typeof rng !== 'function') { throw new TypeError('musig2: nonce_gen needs an rng'); }
        var rand = rng(32);
        if (secret) {
            /* BIP-327's rand' = sk ⊕ H(aux, rand), at the suite's scalar width */
            var hs = serialize_scalar(curve, H('aux', [rand]));
            if (!(secret instanceof Uint8Array) || secret.length !== hs.length) { throw new TypeError('musig2: secret is the scalar\'s ' + hs.length + '-byte encoding'); }
            var x = new Uint8Array(hs.length);
            for (var i = 0; i < hs.length; i++) { x[i] = secret[i] ^ hs[i]; }
            rand = x;
        }
        var m = msg == null ? new Uint8Array([0]) : concat([new Uint8Array([1]), lp32(msg)]);
        var ks = [0, 1].map(function (j) {
            return H('nonce', [rand, lp32(pubkey), lp32(aggpk || new Uint8Array(0)), m, lp32(extra || new Uint8Array(0)), new Uint8Array([j])]);
        });
        if (ks[0] === 0n || ks[1] === 0n) { throw new Error('musig2: degenerate nonce'); }
        return { secnonce: { k1: ks[0], k2: ks[1], pk: pubkey },
                 pubnonce: concat([G.encode(G.base_mul(ks[0])), G.encode(G.base_mul(ks[1]))]) };
    }

    /** Sum the nonce pairs componentwise — the identity encodes on these groups. */
    function nonce_agg(pubnonces) {
        var R1 = G.IDENTITY, R2 = G.IDENTITY;
        for (var i = 0; i < pubnonces.length; i++) {
            var p = pubnonces[i];
            if (!(p instanceof Uint8Array) || p.length !== 2 * Ne) { throw new Error('musig2: pubnonce ' + i + ' is not two points'); }
            R1 = G.add(R1, dec(p.subarray(0, Ne), 'pubnonce ' + i));
            R2 = G.add(R2, dec(p.subarray(Ne), 'pubnonce ' + i));
        }
        return concat([G.encode(R1), G.encode(R2)]);
    }

    function session_values(ctx, aggnonce, msg, T) {
        if (last !== null && last.ctx === ctx && last.aggnonce === aggnonce && last.msg === msg && last.T === T) { return last.sv; }
        var sv = compute_values(ctx, aggnonce, msg, T);
        last = { ctx: ctx, aggnonce: aggnonce, msg: msg, T: T, sv: sv };
        return sv;
    }
    function compute_values(ctx, aggnonce, msg, T) {
        var R1 = dec(aggnonce.subarray(0, Ne), 'aggnonce'), R2 = dec(aggnonce.subarray(Ne, 2 * Ne), 'aggnonce');
        var b = H('noncecoef', [aggnonce, G.encode(ctx.Q), msg]);
        var R = G.add(R1, G.mul_vartime(b, R2));
        if (G.equals(R, G.IDENTITY)) { R = G.base_mul(1n); }        // as BIP-327: a nonce of infinity becomes G
        var Tp = null, Rc = R;
        if (T != null) {
            Tp = T instanceof Uint8Array ? G.decode(T) : T;
            if (Tp == null || G.equals(Tp, G.IDENTITY)) { throw new Error('musig2: T is not a point of the group, or is the identity'); }
            Rc = schnorr_nonce(G, curve, R, Tp).point;
            if (G.equals(Rc, G.IDENTITY)) { throw new Error('musig2: R + T is the identity'); }
        }
        var e = compute_challenge(curve, G.encode(Rc), G.encode(ctx.Q), msg);
        return { b: b, R: R, Rc: Rc, T: Tp, e: e };
    }

    function check_nonce(s) {
        if (!s || s.k1 === 0n || s.k2 === 0n || s.k1 >= N || s.k2 >= N) { throw new Error('musig2: invalid secnonce'); }
    }

    /** One signer's partial signature: k₁ + b·k₂ + e·a·x. */
    function sign(secnonce, secret, ctx, aggnonce, msg, T) {
        check_nonce(secnonce);
        var sv = session_values(ctx, aggnonce, msg, T);
        var x = deserialize_scalar(curve, secret);
        if (x === 0n) { throw new Error('musig2: invalid secret key'); }
        var pk = G.encode(G.base_mul(x));
        for (var i = 0; i < Ne; i++) { if (pk[i] !== secnonce.pk[i]) { throw new Error('musig2: secnonce does not belong to this key'); } }
        return mod(secnonce.k1 + sv.b * secnonce.k2 + sv.e * coeff_of(ctx, pk) * x, N);
    }

    /** s·G == R₁ + b·R₂ + e·a·P: the check that names a wrong partial's sender. */
    function partial_verify(psig, pubnonce, pubkey, ctx, aggnonce, msg, T) {
        if (typeof psig !== 'bigint' || psig < 0n || psig >= N) { return false; }
        if (!(pubnonce instanceof Uint8Array) || pubnonce.length !== 2 * Ne) { return false; }
        var r1 = G.decode(pubnonce.subarray(0, Ne)), r2 = G.decode(pubnonce.subarray(Ne)), P = G.decode(pubkey);
        if (r1 == null || r2 == null || P == null) { return false; }
        var sv = session_values(ctx, aggnonce, msg, T);
        /* every value here is public: one interleaved walk for b·R₂ + e·a·P */
        var rhs = G.add(r1, double_mul(C, sv.b, r2, mod(sv.e * coeff_of(ctx, pubkey), N), P, 5));
        return G.equals(G.base_mul(psig), rhs);
    }

    /** The signature (the suite's encoding), or with T adaptor.js's { R, T, s }. */
    function partial_sig_agg(psigs, ctx, aggnonce, msg, T) {
        var sv = session_values(ctx, aggnonce, msg, T), s = 0n;
        for (var i = 0; i < psigs.length; i++) {
            if (psigs[i] < 0n || psigs[i] >= N) { throw new Error('musig2: partial signature ' + i + ' out of range'); }
            s = mod(s + psigs[i], N);
        }
        s = mod(s + sv.e * ctx.tacc, N);
        if (T != null) { return { R: G.encode(sv.R), T: G.encode(sv.T), s: s }; }
        return serialize_signature(curve, G.encode(sv.R), s);
    }

    /**
     * A key brought along, as the scalar's encoding: an RFC 8032 seed
     * (ed25519 32 bytes, ed448 57) expanded as RFC 8032 does; an sr25519
     * 64-byte secret key (sr25519.js format); a ristretto255 scalar.
     */
    function secret_from(key) {
        var x;
        if (curve === 'ed25519') { x = ed25519_expand(key).scalar; }
        else if (curve === 'ed448') { x = ed448_expand(key).scalar; }
        else if (curve === 'sr25519') { x = sr25519_scalar(key); }
        else { x = deserialize_scalar(curve, key); }
        x = mod(x, N);
        if (x === 0n) { throw new Error('musig2: the key is zero'); }
        return serialize_scalar(curve, x);
    }

    return {
        curve: curve, GROUP: G,
        key_sort: key_sort, key_agg: key_agg, get_plain_pubkey: get_plain_pubkey, apply_tweak: apply_tweak,
        nonce_gen: nonce_gen, nonce_agg: nonce_agg, session_values: session_values,
        sign: sign, partial_verify: partial_verify, partial_sig_agg: partial_sig_agg, secret_from: secret_from
    };
}

export { key_sort };
