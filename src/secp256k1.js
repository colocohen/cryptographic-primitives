/**
 * secp256k1  -  SEC 2, and the curve Bitcoin and Ethereum are built on
 *
 * y^2 = x^3 + 7 over a 256-bit prime field. Its a coefficient is zero and its
 * prime is very close to 2^256, both chosen for implementation speed rather
 * than for any security property - which is also why it was standardised
 * outside NIST and why the cryptocurrency world adopted it: nothing about its
 * parameters is unexplained.
 *
 * Provides ECDSA, Schnorr signatures per BIP-340, ECDH, and public-key
 * recovery.
 *
 * ECDSA'S NONCE IS THE WHOLE STORY. A signature uses a per-message secret k.
 * If k ever repeats across two signatures under the same key, the private key
 * falls out of two subtractions - this is how the PlayStation 3 signing key
 * was extracted in 2010, and how a long series of Bitcoin wallets were
 * emptied. If k is merely BIASED, lattice attacks recover the key from a few
 * hundred signatures.
 *
 * This implementation derives k per RFC 6979, from the key and the message,
 * HEDGED with 32 fresh bytes from the platform as the RFC's additional data
 * k' (section 3.6) unless the caller passes their own: the nonce never rests
 * on the randomness alone, so a bad rng cannot repeat it, and there is no
 * way for a caller to supply a bad nonce. An empty `extra` is classic
 * RFC 6979 - identical messages, identical signatures.
 */

import { ecdsa_group } from './commons/group.js';
import { ecdsa } from './commons/ecdsa.js';
import { SECP256K1_BETA, SECP256K1_BASIS } from './commons/glv.js';
import { sha256 } from './sha2.js';

/*
 * Everything below is one call into commons/ecdsa.js. The generic scheme was
 * extracted before the second curve was written; P-256 and the rest are the
 * same three lines with different numbers.
 */
export var CURVE = {
    name: 'secp256k1',
    oid: '1.3.132.0.10',      /* the namedCurve OBJECT IDENTIFIER */
    /* scalars are big-endian on this curve - see commons/group.js */
    little_endian: false,
    p:  (1n << 256n) - (1n << 32n) - 977n,
    n:  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
    a:  0n,
    b:  7n,
    Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
    hash: sha256,

    /*
     * secp256k1 admits an efficiently computable endomorphism, which the NIST
     * and Brainpool curves of the same size do not. It halves the doublings
     * in verification - see commons/glv.js - and it is the reason this curve
     * verifies faster than P-256 despite the same field size.
     */
    endomorphism: { beta: SECP256K1_BETA, basis: SECP256K1_BASIS }
};

var E = /* @__PURE__ */ ecdsa(CURVE);

/*
 * ⭐ k*G through the table the signing path already builds. It was
 *   unreachable before - measured 1.25 ms through it against 4.50 ms
 *   without, a factor of 3.6 lost to a missing export.
 */
export var mul_vartime      = E.mul_vartime;
/* keygen(seed) -> { sk: 32 bytes, pk: 33 bytes compressed }, for sign/verify/ecdh;
   schnorr_keygen below is the BIP-340 pair */
export var keygen           = E.keygen;
export var base_mul         = E.base_mul;
export var is_valid_secret  = E.is_valid_secret;
export var get_public_key   = E.get_public_key;
export var encode_point     = E.encode_point;
export var decode_point     = E.decode_point;

/**
 * Lift an x-only key to the point with EVEN y, as BIP 340 defines.
 *
 * Exported because blind.js needs it (adaptor.js did too): BIP 340 keys carry
 * only x, and every scheme built on them has to reconstruct the point the
 * verifier will use. Two copies of a three-line function is two places for
 * the parity convention to drift.
 *
 * @return {object|null} null when x is not on the curve
 */
export function lift_x_even(b) {
    if (b.length !== 32) { return null; }
    /*
     * The same lift as _lift_x below, which schnorr_verify uses. This used
     * to go round through a 0x02-prefixed SEC 1 encoding and decode_point -
     * a second route to the identical answer (x < p, a square root, even y)
     * that had to be kept in step with the first.
     */
    return _lift_x(FIELD.from_bytes(b));
}
export var sign             = E.sign;
export var verify           = E.verify;
/* sign(msg_hash, secret, extra) - extra as commons/ecdsa.js: omitted or null hedged with
   fresh bytes, an empty Uint8Array classic RFC 6979. Over a whole message, the hash
   given: sign_message(hash, msg, secret, extra), verify_message(hash, msg, sig, public_key) */
export var sign_message     = E.sign_message;
export var signer_create    = E.signer_create;
export var verifier_create  = E.verifier_create;
export var verify_message   = E.verify_message;
export var recover          = E.recover;

/*
 * Exposed for threshold signers, who assemble r and s from shares and never
 * call sign() - so the normalisation inside its loop never runs for them.
 * A signature that skips it verifies here and is rejected by Bitcoin.
 */
export var normalize_s      = E.normalize_s;
export var recovery_id      = E.recovery_id;
export var ecdh             = E.ecdh;
export var sig_to_der       = E.sig_to_der;
export var sig_from_der     = E.sig_from_der;
/* ECPrivateKey (RFC 5915), with the curve OID 1.3.132.0.10 */
export var private_key_to_der   = E.private_key_to_der;
export var private_key_from_der = E.private_key_from_der;
export var sig_to_compact   = E.sig_to_compact;
export var sig_from_compact = E.sig_from_compact;

/* exposed so schnorr can share the curve rather than rebuild it */
export var POINT = E.POINT;
export var FIELD = E.FIELD;
export var SCALAR = E.SCALAR;
export var G = E.G;

/* ---------------- Schnorr signatures, BIP-340 ---------------- */
/*
 * Bitcoin's Taproot signature scheme, active since 2021.
 *
 * It shares the curve with ECDSA above and nothing else. Different key
 * format, different hashing, different signature equation - which is exactly
 * why it lives here rather than in commons/ecdsa.js. Generalising it would
 * mean inventing a family that has one member.
 *
 * WHAT IT BUYS OVER ECDSA
 *   - Signatures are LINEAR in the key and nonce, so several signers can add
 *     their partial signatures into one that verifies against the sum of
 *     their keys. That is what makes MuSig and Taproot key aggregation
 *     possible; ECDSA's inversion makes the same trick very hard.
 *   - No inversion when signing, so no RFC 6979 machinery is needed and the
 *     nonce is a plain hash.
 *   - No malleability. ECDSA needed the low-s rule bolted on; here the
 *     encoding is canonical by construction.
 *   - A security proof under simpler assumptions.
 *
 * X-ONLY KEYS. A public key is 32 bytes - just x. The y coordinate is defined
 * to be the even one, so the sign bit that ECDSA spends a byte on is simply
 * legislated away. The same rule applies to R inside the signature. This is
 * why a Taproot output is 32 bytes where a legacy pubkey is 33.
 *
 * TAGGED HASHES. Every hash is SHA256(SHA256(tag) || SHA256(tag) || m) with a
 * distinct tag per purpose. Prefixing the 64-byte doubled tag guarantees the
 * hash input can never collide with a hash from a different context - and it
 * is exactly one SHA-256 block, so the midstate can be precomputed.
 */

import { sha256 as _sha256 } from './sha2.js';
import { ascii } from './commons/bytes.js';

var _P = CURVE.p, _N = CURVE.n;

/**
 * The BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || parts).
 *
 * EXPORTED because musig2.js needs exactly this - it reuses BIP 340's
 * challenge tag so that its aggregate signature verifies under the ordinary
 * Schnorr verifier, and a second implementation of the doubled-tag prefix
 * would be a place for the two to drift apart.
 *
 * The doubled tag hash is not decoration: it makes the outer hash's input
 * begin with 64 bytes no other tag can produce, so two tags cannot collide
 * even on chosen messages.
 */
export function tagged_hash(tag, parts) { return _tagged(tag, parts); }


function _tagged(tag, parts) {
    var t = _sha256(ascii(tag));
    var total = 64;
    var i;
    for (i = 0; i < parts.length; i++) { total += parts[i].length; }
    var buf = new Uint8Array(total);
    buf.set(t, 0); buf.set(t, 32);
    var o = 64;
    for (i = 0; i < parts.length; i++) { buf.set(parts[i], o); o += parts[i].length; }
    return _sha256(buf);
}

/**
 * The BIP 340 challenge e = int(H_challenge(R.x || P.x || m)) mod n.
 *
 * EXPORTED because blind.js and musig2.js (and the old adaptor.js) each computed it as
 * `mod_n(bytes_to_bigint(tagged_hash('BIP0340/challenge', [...])))`, and
 * frost_codec.js wrote the tag out as byte values. Every one of them must
 * produce exactly the value schnorr_verify recomputes, so it lives once.
 *
 * @param {Uint8Array} rx  32 bytes, R's x coordinate
 * @param {Uint8Array} px  32 bytes, the x-only public key
 */
export function bip340_challenge(rx, px, msg) {
    return _int(_tagged('BIP0340/challenge', [rx, px, msg])) % _N;
}

function _x32(x) { return FIELD.to_bytes(x); }
function _int(b) { return FIELD.from_bytes(b); }

/**
 * lift_x: recover the point with this x and EVEN y.
 *
 * Returns null when x is not on the curve. That check is the whole defence
 * against a caller passing an arbitrary 32 bytes as a public key.
 */
function _lift_x(x) {
    if (x <= 0n || x >= _P) { return null; }
    var y = POINT.decompress(x, false);      /* false = want the even y */
    if (y === null) { return null; }
    return POINT.of(x, y);
}

/**
 * The x-only public key: 32 bytes.
 *
 * @param  {Uint8Array} secret  32 bytes
 * @return {Uint8Array} 32 bytes
 */
export function schnorr_get_public_key(secret) {
    var d = _int(secret);
    if (!(d > 0n && d < _N)) { throw new Error('schnorr: invalid secret key'); }
    /* d*G through the comb table every other k*G here uses - it was the
       ladder on the generator, the one place in this file that bypassed it */
    var A = POINT.to_affine(E.base_mul_point(d));
    return _x32(A.x);
}

/**
 * A BIP-340 key pair: { sk: 32 bytes, pk: the 32-byte x-only key }, as
 * schnorr_sign and schnorr_verify take them. The secret is any scalar in
 * [1, n) - schnorr_sign negates it itself when its point has odd y, as the
 * BIP does - so it is the same secret keygen() would give.
 *
 * @param {Uint8Array} [seed]  the secret key itself, checked as
 *   schnorr_get_public_key checks it; omitted or null draws a fresh one
 *   from the platform
 */
export function schnorr_keygen(seed) {
    var sk = E.keygen(seed).sk;
    return { sk: sk, pk: schnorr_get_public_key(sk) };
}

/**
 * @param  {Uint8Array} msg     any length - BIP-340 does not fix it
 * @param  {Uint8Array} secret  32 bytes
 * @param  {Uint8Array} [aux]   32 bytes of auxiliary randomness; omitted or
 *                              null draws fresh ones from the platform
 * @return {Uint8Array} 64 bytes
 *
 * The aux argument is BIP-340's hedge. With fresh randomness the nonce is
 * unpredictable even if the signing device leaks through a side channel,
 * which is what the BIP recommends and what an omitted aux gets. 32 zero
 * bytes passed explicitly give the fully deterministic, reproducible
 * signature of the BIP's zero-aux test vectors. The nonce still hashes the
 * key and the message either way, so a weak rng weakens only the hedge.
 */
export function schnorr_sign(msg, secret, aux) {
    var d0 = _int(secret);
    if (!(d0 > 0n && d0 < _N)) { throw new Error('schnorr: invalid secret key'); }

    var Pt = POINT.to_affine(E.base_mul_point(d0));
    /* the key is defined to have even y, so flip the scalar when it does not */
    var d = (Pt.y & 1n) === 0n ? d0 : _N - d0;

    var a = aux == null ? _secure_random(32) : aux;
    if (a.length !== 32) { throw new Error('schnorr: aux must be 32 bytes'); }

    var mask = _tagged('BIP0340/aux', [a]);
    var db = _x32(d);
    var td = new Uint8Array(32);
    for (var i = 0; i < 32; i++) { td[i] = db[i] ^ mask[i]; }

    var rand = _tagged('BIP0340/nonce', [td, _x32(Pt.x), msg]);
    var k0 = _int(rand) % _N;
    if (k0 === 0n) { throw new Error('schnorr: nonce was zero'); }

    var R = POINT.to_affine(E.base_mul_point(k0));
    var k = (R.y & 1n) === 0n ? k0 : _N - k0;

    var e = bip340_challenge(_x32(R.x), _x32(Pt.x), msg);

    var sig = new Uint8Array(64);
    sig.set(_x32(R.x), 0);
    sig.set(_x32((k + e * d) % _N), 32);

    /* a signature that does not verify means something is wrong with the
       inputs or this code - never hand one out */
    if (!schnorr_verify(msg, sig, _x32(Pt.x))) {
        throw new Error('schnorr: produced an invalid signature');
    }
    return sig;
}

/**
 * @param  {Uint8Array} msg
 * @param  {Uint8Array} sig         64 bytes
 * @param  {Uint8Array} public_key  32 bytes, x-only
 * @return {boolean}
 */
export function schnorr_verify(msg, sig, public_key) {
    var v = _verify_input(msg, sig, public_key);
    if (v === null) { return false; }
    var Pt = v.P, r = v.r, s = v.s, e = v.e;

    /* R = s*G - e*P = s*G + (n - e)*P. Verification: s and e are public,
       so one interleaved walk with the endomorphism (ECDSA's), and the
       variable-time inverse for a point about to be compared */
    var R = E.double_mul_vartime(s, E.G, (_N - e) % _N, Pt);
    var A = POINT.to_affine_public(R);
    if (A === null) { return false; }
    /* R must have even y and the right x - both are part of the encoding rule */
    if ((A.y & 1n) !== 0n) { return false; }
    return A.x === r;
}


/*
 * BIP-340 verification steps 1-4: everything schnorr_verify checks before
 * the equation, giving { P, r, s, e }, or null. ⭐ ONE FUNCTION for
 * schnorr_verify and both batch checks, so they cannot disagree on an input.
 */
function _verify_input(msg, sig, public_key, P) {
    if (sig.length !== 64 || public_key.length !== 32) { return null; }

    /* P: the key already lifted (a batch, for a key it has seen), or lifted here */
    var Pt = P || _lift_x(_int(public_key));
    if (Pt === null) { return null; }

    var r = _int(sig.subarray(0, 32));
    var s = _int(sig.subarray(32));
    if (r >= _P || s >= _N) { return null; }

    var e = bip340_challenge(sig.subarray(0, 32), public_key, msg);
    return { P: Pt, r: r, s: s, e: e };
}

/**
 * ⭐ BIP-340 BATCH VERIFICATION (BIP-340, "Batch Verification"): true when
 *    every { msg, sig, pk } verifies, checked as one equation over random
 *    128-bit weights z_i,
 *
 *        Σ z_i·R_i + Σ (z_i·e_i)·P_i − (Σ z_i·s_i)·G == O,
 *
 *    R_i = lift_x(r_i), in one msm. The same answers as schnorr_verify:
 *    every item goes through its checks (_verify_input), and on a curve of
 *    prime order "s·G − e·P has x = r and even y" is exactly
 *    "s·G − e·P = lift_x(r)" - an r that is no point's x fails both. So a
 *    valid batch always passes, and one with an invalid item passes with
 *    probability 2^-128 (commons/batch.js) - the one difference any batch
 *    check has.
 *
 * @param items  [{ msg, sig, pk }]  (pk: 32 bytes, x-only)
 * @param opts   { rng } — 16 bytes per item; the CSPRNG by default
 */
export function schnorr_verify_batch(items, opts) {
    var c = _batch_checks(items, opts, 'schnorr_verify_batch');
    return batch_all(items, c.holds, c.one, _BATCH_MIN);
}

/** The indices of the items schnorr_verify rejects, ascending (commons/batch.js). */
export function schnorr_verify_batch_find(items, opts) {
    var c = _batch_checks(items, opts, 'schnorr_verify_batch_find');
    return batch_find(items, c.holds, c.one, _BATCH_MIN);
}

import { msm, msm_group } from './commons/fixed_window.js';
import { glv_msm_terms } from './commons/glv.js';
import { secure_random as _secure_random } from './commons/bytes.js';
import { batch_weight, batch_all, batch_find, batch_items } from './commons/batch.js';

/*
 * Below this many, one by one (the answer is the same). Measured with
 * tools/bench/batch_verify.mjs bip340, the endomorphism split in: 8 is
 * between 0.75x and 1.15x of verify (noise), 16 about 1.3x faster.
 */
var _BATCH_MIN = 16;
var _MSM_G = /* @__PURE__ */ msm_group(POINT);

function _batch_checks(items, opts, who) {
    batch_items(items, who);
    var rng = (opts && opts.rng) || _secure_random;
    return {
        holds: function (sub) { return _batch_holds(sub, rng, who); },
        one: function (it) { return schnorr_verify(it.msg, it.sig, it.pk); }
    };
}

/* the equation, items sharing a public key sharing its lift and one msm term */
function _batch_holds(items, rng, who) {
    var scalars = [], points = [], by_key = new Map(), sG = 0n;
    for (var i = 0; i < items.length; i++) {
        var it = items[i];
        var key = it.pk instanceof Uint8Array && it.pk.length === 32 ? String.fromCharCode.apply(null, it.pk) : null;
        var at = key === null ? undefined : by_key.get(key);
        var v = _verify_input(it.msg, it.sig, it.pk, at === undefined ? null : points[at]);
        if (v === null) { return false; }
        var R = _lift_x(v.r);
        if (R === null) { return false; }
        var z = batch_weight(rng, who);
        sG = (sG + z * v.s) % _N;
        scalars.push(z);
        points.push(R);
        var ze = (z * v.e) % _N;
        if (at === undefined) {
            if (key !== null) { by_key.set(key, scalars.length); }
            scalars.push(ze);
            points.push(v.P);
        } else {
            scalars[at] = (scalars[at] + ze) % _N;
        }
    }
    scalars.push((_N - sG) % _N);
    points.push(E.G);
    /*
     * The full-width terms (each key's z·e, and G's) split with the
     * endomorphism, as the single verify's walk does (commons/glv.js): about
     * 1.25x on the msm. Every scalar is public - a weight drawn here or a
     * value from a signature - so the variable-time msm is right.
     */
    var t = glv_msm_terms(POINT, FIELD, SECP256K1_BETA, _N, SECP256K1_BASIS, scalars, points);
    /* is_zero is the constant-time compare, which answers 1n / 0n */
    return POINT.is_zero(msm(_MSM_G, t.scalars, t.points)) ? true : false;
}


/* ---------------- hash to curve, RFC 9380 ---------------- */
/**
 * secp256k1_XMD:SHA-256_SSWU_RO_
 *
 * secp256k1 CANNOT use the simplified SWU map directly: that map needs both
 * curve coefficients nonzero, and secp256k1's a is zero. The RFC's answer is
 * to map onto a DIFFERENT curve E' that does have a nonzero a, then carry
 * the point across by a 3-isogeny.
 *
 * An isogeny is a rational map between curves that respects the group law -
 * so a point mapped through it is still a point, addition still works, and
 * crucially the discrete logarithm is not preserved in any way an attacker
 * can use. The rational functions and their thirteen coefficients are fixed
 * by the RFC; they were extracted programmatically from appendix E.1 rather
 * than typed.
 *
 * Note that this is the same shape of trick BLS12-381 needs, which is why
 * this code will be reused there rather than written twice.
 */

import { h2c_suite, map_to_curve_sswu, expand_message_xmd, horner } from './commons/h2c.js';
import { sha256 as _sha256_h2c } from './sha2.js';

/* The isogenous curve E', which has a nonzero a and so admits plain SSWU */
var ISO_A = 0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533n;
var ISO_B = 1771n;
var ISO_Z = CURVE.p - 11n;

var ISO_K1 = [
    0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7n,
    0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581n,
    0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262n,
    0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88cn
];

var ISO_K2 = [
    0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49bn,
    0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14n
];

var ISO_K3 = [
    0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23cn,
    0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3n,
    0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931n,
    0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84n
];

var ISO_K4 = [
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93bn,
    0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573n,
    0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76fn
];

/**
 * The 3-isogeny from E' to secp256k1.
 *
 * x = x_num/x_den and y = y' * y_num/y_den, with the four polynomials
 * evaluated by Horner's rule. A single inversion at the end covers both
 * denominators.
 */
function iso_map(x, y) {
    var F = FIELD;
    var m = F.mul;

    /*
     * commons/h2c.js's horner, which the BLS12-381 isogenies already use.
     * This file had its own non-monic Horner and wrote the two monic
     * denominators out by hand - x^2 + k21*x + k20 and
     * x^3 + k42*x^2 + k41*x + k40 - which is what `monic = true` computes.
     */
    var x_num = horner(F, ISO_K1, x, false);
    var x_den = horner(F, ISO_K2, x, true);
    var y_num = horner(F, ISO_K3, x, false);
    var y_den = horner(F, ISO_K4, x, true);

    var inv_xd = F.inv(x_den);
    var inv_yd = F.inv(y_den);
    return { x: m(x_num, inv_xd), y: m(y, m(y_num, inv_yd)) };
}

export var secp256k1_h2c = /* @__PURE__ */ h2c_suite({
    F: FIELD, C: POINT, p: CURVE.p, L: 48, cofactor: 1n,
    order_bits: 256,
    expand: function (msg, dst, len) { return expand_message_xmd(msg, dst, len, _sha256_h2c); },
    map: function (u) {
        var q = map_to_curve_sswu(FIELD, ISO_A, ISO_B, ISO_Z, u);
        return iso_map(q.x, q.y);
    }
});


/* =========================================================================
 * The prime-order group interface - see commons/group.js
 *
 * Cofactor 1, so SEC1 validation is the whole of it: on the curve, in range,
 * not infinity. `decode_point` already does all three, which leaves nothing
 * for in_subgroup to add - every point on this curve is in the prime-order
 * group.
 * ======================================================================= */

export var GROUP = /* @__PURE__ */ ecdsa_group('secp256k1', E, function (msg, dst) {
    return secp256k1_h2c.hash_to_curve(msg, dst);
});
