/**
 * RedDSA  -  Zcash's Schnorr signature, with keys that can be re-randomized
 *
 * The Zcash Protocol Specification, section 5.4.7: RedJubjub over Jubjub for
 * Sapling, RedPallas over Pallas for Orchard, each with two parameter sets -
 * one for spend authorization, one for the binding signature.
 *
 * ==================== WHAT IS DIFFERENT FROM EdDSA ====================
 *
 * The signature is an ordinary Schnorr signature - R, then S = r + c·sk -
 * and a FROST group can produce one (frost_codec.js's redjubjub and redpallas
 * suites, ZIP 312). Three things set it apart:
 *
 *   THE BASE IS NOT THE CURVE'S. Each role multiplies by its own point, found
 *   by hashing a fixed string to the curve. They are the constants below,
 *   taken from the reddsa crate and checked through the oracle vectors.
 *
 *   THE HASH IS PERSONALIZED. H* is BLAKE2b-512 with a 16-byte
 *   personalization ("Zcash_RedJubjubH", "Zcash_RedPallasH") - not a prefix
 *   inside the input, a field in BLAKE2b's parameter block.
 *
 *   THE KEY CAN BE RE-RANDOMIZED. A spend authorization key is used under a
 *   fresh disguise in every transaction:
 *
 *       sk' = sk + α        vk' = vk + α·B
 *
 *   A signature under vk' verifies under vk' only, and without α nobody can
 *   tell vk' came from vk - which is what keeps two spends by one wallet
 *   unlinkable on the chain. The binding signature has no such step; its key
 *   is fresh for every transaction already.
 *
 * ==================== VERIFICATION IS COFACTORED ====================
 *
 * Jubjub has cofactor 8 and the specification checks
 *
 *       [8](S·B - R - c·vk) = O
 *
 * accepting a key or an R with a small-order component, so every verifier
 * agrees on the same set of signatures. Pallas has prime order and the
 * cofactor is 1. Keys and R are decoded with the raw curve codecs (abst_J,
 * abst_P), not GROUP.decode, for exactly this reason. Small-order keys are
 * therefore accepted here: Sapling refuses them for rk as a separate
 * consensus rule, outside the signature scheme, as the reddsa crate does.
 *
 * Checked against the Zcash Foundation's reddsa crate (test/vectors/curves/
 * zcash.json): keys, signatures byte for byte from the same randomness,
 * re-randomized keys and signatures under them.
 */

import * as jubjub from './jubjub.js';
import { pallas } from './pasta.js';
import { blake2b } from './blake2.js';
import { rebased } from './commons/group.js';
import { fixed_base, wnaf_mul } from './commons/fixed_window.js';
import { concat, ascii, bytes_to_bigint_le, bigint_to_bytes_le, from_hex as unhex } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';


/*
 * What a parameter set needs from its curve, in one shape: the raw codec,
 * the point operations verification runs on (any point, not only the
 * subgroup), and the GROUP a FROST suite builds on.
 */
var CURVES = {
    jubjub: {
        GROUP: jubjub.GROUP,
        POINT: jubjub.POINT,
        bits: 252,
        cofactor: 8n,
        encode: jubjub.encode,
        decode: jubjub.decode,
        is_zero: function (P) { return jubjub.POINT.eq(P, jubjub.POINT.ZERO); },
        mul_vartime: function (k, P) { return wnaf_mul(jubjub.POINT, k, P, 5); }
    },
    pallas: {
        GROUP: pallas.GROUP,
        POINT: pallas.POINT,
        bits: 255,
        cofactor: 1n,
        encode: pallas.encode_point,
        decode: pallas.decode_point,
        is_zero: function (P) { return !!pallas.POINT.is_zero(P); },
        mul_vartime: function (k, P) { return pallas.POINT.mul(k, P, 255); }
    }
};

/**
 * A parameter set: a curve, a base point, a personalization.
 *
 * ⭐ IT CARRIES ITS OWN GROUP - the curve's GROUP rebased on this set's base
 *   (commons/group.js rebased). That is the group a FROST suite producing
 *   these signatures runs on, and the group the randomizer α multiplies.
 */
function parameter_set(name, curve, base_hex, personal, randomizable) {
    var C = CURVES[curve];
    var B = C.decode(unhex(base_hex));
    if (B === null) { throw new Error('reddsa: ' + name + ' base does not decode'); }
    var table = fixed_base(C.POINT, B, C.bits, 4);
    return {
        name: name,
        curve: curve,
        personal: ascii(personal),
        randomizable: randomizable,
        BASE: B,
        GROUP: rebased(C.GROUP, name, B, table),
        C: C
    };
}

/** Sapling spend authorization: Jubjub, base FindGroupHash("Zcash_G_", ""). */
export var REDJUBJUB_SPEND_AUTH = /* @__PURE__ */ parameter_set('redjubjub', 'jubjub',
    '30b5f2aaad325630bcdddbce4d67656d05fd1cc2d037bb5375b6e96d9e01a1d7', 'Zcash_RedJubjubH', true);

/** Sapling binding signature: Jubjub, base FindGroupHash("Zcash_cv", "r"). */
export var REDJUBJUB_BINDING = /* @__PURE__ */ parameter_set('redjubjub-binding', 'jubjub',
    '8b6a0b38b9faae3c3b803b47b0f146ad50ab221e6e2afbe6dbde45cba9d381ed', 'Zcash_RedJubjubH', false);

/** Orchard spend authorization: Pallas, base GroupHash("z.cash:Orchard", "G"). */
export var REDPALLAS_SPEND_AUTH = /* @__PURE__ */ parameter_set('redpallas', 'pallas',
    '63c975b884721a8d0ca1707be30c7f0c5f445f3e7c188d3b06d6f128b32355b7', 'Zcash_RedPallasH', true);

/** Orchard binding signature: Pallas, base GroupHash("z.cash:Orchard-cv", "r"). */
export var REDPALLAS_BINDING = /* @__PURE__ */ parameter_set('redpallas-binding', 'pallas',
    '915a3c8868c6c30e2f8090ee45d76e4048208dea5b23664fbb09a40f5544f407', 'Zcash_RedPallasH', false);

/* ---------------------------------------------------------------- scalars */

/**
 * H*(parts...): BLAKE2b-512 under the set's personalization, read
 * little-endian and reduced - 512 bits into a 252- or 255-bit order, so the
 * result is uniform.
 */
export function h_star(S, parts) {
    var d = blake2b(concat(parts), 64, undefined, { personal: S.personal });
    return bytes_to_bigint_le(d) % S.GROUP.ORDER;
}

function scalar_in(S, b, what) {
    var v = S.GROUP.scalar_from_bytes(b);
    if (v === null) { throw new Error('reddsa: ' + what + ' must be ' + S.GROUP.SCALAR_BYTES + ' canonical bytes'); }
    return v;
}

function scalar_out(S, v) { return bigint_to_bytes_le(v, 32); }

/* (ℓ_H + 128) / 8 = 80 bytes: the randomness the specification draws for a
   nonce and for a randomizer */
var T_BYTES = 80;

/* ------------------------------------------------------------------- keys */

/** A fresh signing key: 32 bytes, little-endian, below the order. */
export function keygen(S, rng) {
    rng = require_rng('reddsa.keygen', rng);
    return scalar_out(S, S.GROUP.random_scalar(rng));
}

/** vk = sk·B, 32 bytes. */
export function public_key(S, sk) {
    return S.C.encode(S.GROUP.base_mul(scalar_in(S, sk, 'the signing key')));
}

/* -------------------------------------------------------- re-randomizing */

function require_randomizable(S) {
    if (!S.randomizable) {
        throw new Error('reddsa: ' + S.name + ' keys are not re-randomized - only spend authorization keys are');
    }
}

/**
 * GenRandom: α = H*(T), T fresh randomness. Uniform, as unlinkability needs.
 */
export function randomizer(S, rng) {
    require_randomizable(S);
    rng = require_rng('reddsa.randomizer', rng);
    return scalar_out(S, h_star(S, [rng(T_BYTES)]));
}

/** RandomizedPrivate: sk + α. */
export function randomize_private(S, sk, alpha) {
    require_randomizable(S);
    var v = S.GROUP.scalar_mod(scalar_in(S, sk, 'the signing key') + scalar_in(S, alpha, 'the randomizer'));
    return scalar_out(S, v);
}

/**
 * RandomizedPublic: vk + α·B.
 *
 * vk may have a small-order component (see the header); the sum is taken on
 * the raw curve, so it keeps it.
 *
 * @return {Uint8Array|null} null when vk does not decode
 */
export function randomize_public(S, vk, alpha) {
    require_randomizable(S);
    var P = S.C.decode(vk);
    if (P === null) { return null; }
    var a = scalar_in(S, alpha, 'the randomizer');
    return S.C.encode(S.C.POINT.add(P, S.GROUP.base_mul(a)));
}

/* ------------------------------------------------------------- signatures */

/**
 * RedDSA.Sign.
 *
 *   r = H*(T ‖ vk ‖ M)   R = r·B   c = H*(R ‖ vk ‖ M)   S = r + c·sk
 *
 * T is 80 bytes of fresh randomness - hedged as Ed25519 is not: the nonce
 * depends on the key and the message too, so a weak RNG alone does not
 * repeat it across messages.
 *
 * @param {function} rng  n -> n random bytes
 * @return {Uint8Array} 64 bytes: R ‖ S
 */
export function sign(S, sk, msg, rng) {
    rng = require_rng('reddsa.sign', rng);
    var x = scalar_in(S, sk, 'the signing key');
    var vk = S.C.encode(S.GROUP.base_mul(x));
    var r = h_star(S, [rng(T_BYTES), vk, msg]);
    var R = S.C.encode(S.GROUP.base_mul(r));
    var c = h_star(S, [R, vk, msg]);
    return concat([R, scalar_out(S, S.GROUP.scalar_mod(r + c * x))]);
}

/**
 * RedDSA.Validate: [h](S·B - R - c·vk) = O, with c over the bytes as given.
 *
 * ⚠ S MUST BE BELOW THE ORDER. Without that check S and S + r_J both
 *   verify - a second valid signature from one, which is malleability and
 *   breaks anything that identifies a transaction by its signatures.
 *
 * @return {boolean}
 */
export function verify(S, vk, msg, sig) {
    if (!(sig instanceof Uint8Array) || sig.length !== 64) { return false; }
    if (!(vk instanceof Uint8Array) || vk.length !== 32) { return false; }
    var C = S.C;
    var A = C.decode(vk);
    var Rb = sig.subarray(0, 32);
    var R = C.decode(Rb);
    var s = S.GROUP.scalar_from_bytes(sig.subarray(32));
    if (A === null || R === null || s === null) { return false; }
    var c = h_star(S, [Rb, vk, msg]);
    /* public scalars throughout - the variable-time multiplies are right */
    var check = C.POINT.add(C.mul_vartime(s, S.BASE), C.POINT.neg(C.POINT.add(R, C.mul_vartime(c, A))));
    if (C.cofactor !== 1n) { check = C.mul_vartime(C.cofactor, check); }
    return C.is_zero(check);
}
