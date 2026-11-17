/**
 * frost_codec.js — RFC 9591, byte for byte.
 *
 * WHY THIS IS ITS OWN FILE
 *
 * Everything here is dictated by someone else and verified against someone
 * else's test vectors. That is the same boundary lemon-tls draws around
 * wire.js, and it earns a file for the same reason.
 *
 * But there is a difference worth stating, because it changes how carefully
 * this has to be read. A mistake in wire.js fails loudly: the peer cannot
 * parse the message and you find out immediately. A mistake here fails
 * silently. The binding factor is a hash over the serialized commitment list,
 * so a wrong byte order or an unsorted list produces a signature that is
 * perfectly well-formed, that every party agrees on, and that no verifier
 * will accept. There is no error to catch — just a signature that does not
 * work, discovered by whoever was relying on it.
 *
 * That is what the RFC 9591 test vectors are for, and why test/rfc9591.mjs
 * runs before anything else in the suite.
 *
 * WHAT IS HERE AND WHAT IS NOT
 *
 * Here: the ciphersuite table, Scalar serialization, the five domain-
 * separated hashes, expand_message_xmd, the commitment-list encoding - and
 * for ZIP 312's two suites, the randomizer hash.
 * All of it is hashing, byte shuffling and modular reduction — no curve
 * arithmetic at all, which is why it can be verified against the RFC before
 * a single Element is multiplied.
 *
 * Shared rather than restated: expand_message_xmd comes from commons/h2c.js,
 * the Lagrange coefficient from shamir.js and the BIP 340 challenge from
 * secp256k1.js. Each had a private copy here; outputs were checked byte for
 * byte before the copies went. The secp256k1 import is for its tagged hash
 * only, and the sr25519 import for its Merlin challenge (challenge_of) only -
 * nothing in this file multiplies a point.
 *
 * Not here: point arithmetic, Element validation, the protocol itself.
 * Elements pass through as opaque fixed-length byte strings; validating that
 * a given 32 or 33 bytes is a real, non-identity, prime-order point is
 * cryptographic-primitives' job and happens in frost.js at the point of use.
 */

import { sha256, sha512 } from './sha2.js';
import { shake256 } from './sha3.js';
import { concat as concatUint8Arrays, ascii as utf8, bytes_to_bigint, bytes_to_bigint_le,
         bigint_to_bytes, bigint_to_bytes_le } from './commons/bytes.js';
import { mod_inverse, mod as primes_mod } from './commons/primes.js';
import { expand_message_xmd as h2c_expand_message_xmd } from './commons/h2c.js';
import { lagrange_at_zero } from './shamir.js';
import { bip340_challenge } from './secp256k1.js';
import { challenge_of as sr25519_challenge } from './sr25519.js';
import { blake2b } from './blake2.js';

// =====================================================================
//  ciphersuites
// =====================================================================

/**
 * The five suites of RFC 9591 §6.
 *
 * `Ne` and `Ns` are the serialized sizes of an Element and a Scalar. They
 * differ per suite and are load-bearing: the commitment list is a flat
 * concatenation with no length prefixes anywhere, so parsing it depends
 * entirely on knowing these two numbers.
 *
 * `scalar_endian` is the one that bites. Ed25519 and ristretto255 encode
 * Scalars little-endian (RFC 8032 heritage); P-256 and secp256k1 encode them
 * big-endian (SEC1). Identifier 1 is `0100…00` in the first pair and
 * `00…0001` in the second, and both appear verbatim in the RFC's
 * binding_factor_input vectors.
 *
 * `h2_context` is null for Ed25519 and Ed448 only. Every other hash in every
 * suite is domain-separated with the context string; H2 for those two omits
 * it deliberately so the output verifies as a plain RFC 8032 signature. The
 * RFC calls this out twice as an intentional exception to its own rule, so
 * it is spelled out here rather than left as a missing entry.
 */
var CIPHERSUITES = {

  ed25519: {
    name: 'FROST(Ed25519, SHA-512)',
    contextString: 'FROST-ED25519-SHA512-v1',
    Ne: 32,
    Ns: 32,
    scalar_endian: 'le',
    order: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
    hash: sha512,
    hash_len: 64,
    // little-endian wide reduction, not hash_to_field
    scalar_from_hash: 'le_wide',
    h1_context: 'rho',
    h2_context: null,        // omitted for RFC 8032 compatibility
    h3_context: 'nonce',
    h4_context: 'msg',
    h5_context: 'com'
  },

  ristretto255: {
    name: 'FROST(ristretto255, SHA-512)',
    contextString: 'FROST-RISTRETTO255-SHA512-v1',
    Ne: 32,
    Ns: 32,
    scalar_endian: 'le',
    order: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
    hash: sha512,
    hash_len: 64,
    scalar_from_hash: 'le_wide',
    h1_context: 'rho',
    h2_context: 'chal',
    h3_context: 'nonce',
    h4_context: 'msg',
    h5_context: 'com'
  },

  p256: {
    name: 'FROST(P-256, SHA-256)',
    contextString: 'FROST-P256-SHA256-v1',
    Ne: 33,
    Ns: 32,
    scalar_endian: 'be',
    order: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    hash: sha256,
    hash_len: 32,
    hash_block: 64,
    // hash_to_field(m, 1) with expand_message_xmd, L = 48
    scalar_from_hash: 'xmd',
    L: 48,
    h1_context: 'rho',
    h2_context: 'chal',
    h3_context: 'nonce',
    h4_context: 'msg',
    h5_context: 'com'
  },

  secp256k1: {
    name: 'FROST(secp256k1, SHA-256)',
    contextString: 'FROST-secp256k1-SHA256-v1',
    Ne: 33,
    Ns: 32,
    scalar_endian: 'be',
    order: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
    hash: sha256,
    hash_len: 32,
    hash_block: 64,
    scalar_from_hash: 'xmd',
    L: 48,
    h1_context: 'rho',
    h2_context: 'chal',
    h3_context: 'nonce',
    h4_context: 'msg',
    h5_context: 'com'
  },

  taproot: {
    name: 'FROST(secp256k1, SHA-256) with BIP-340 encoding',
    contextString: 'FROST-secp256k1-SHA256-v1',
    bip340: true, Ne: 33, Ns: 32, scalar_endian: 'be',
    order: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
    hash: sha256, hash_len: 32, hash_block: 64,
    scalar_from_hash: 'xmd', L: 48,
    h1_context: 'rho', h2_context: 'chal', h3_context: 'nonce',
    h4_context: 'msg', h5_context: 'com'
  },

  /*
   * sr25519 — FROST on ristretto255 whose signature is schnorrkel's.
   *
   * ⭐ NOT AN RFC 9591 SUITE, and its own context string for that reason.
   *    H1, H3, H4 and H5 are ristretto255's (SHA-512, wide reduction) under
   *    "FROST-SR25519-SHA512-v1"; H2 — the challenge — is not a hash here
   *    but schnorrkel's Merlin transcript (sr25519.js challenge_of), so the
   *    aggregate verifies as an ordinary sr25519 signature.
   *
   * ⭐ THE MESSAGE IS sr25519.signing_message(context, message): the signing
   *    context travels with the message, so the binding factors bind it too.
   *
   * ⭐ THE SIGNATURE CARRIES schnorrkel's MARKER bit (serialize_signature).
   */
  sr25519: {
    name: 'FROST(ristretto255, SHA-512) with the schnorrkel challenge',
    contextString: 'FROST-SR25519-SHA512-v1',
    sr25519: true, Ne: 32, Ns: 32, scalar_endian: 'le',
    order: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
    hash: sha512, hash_len: 64, scalar_from_hash: 'le_wide',
    h1_context: 'rho', h2_context: 'chal', h3_context: 'nonce',
    h4_context: 'msg', h5_context: 'com'
  },

  /*
   * FROST(Ed448, SHAKE256) — RFC 9591 §6.3.
   *
   * ⚠️ THE ONLY SUITE HERE WITH 57-BYTE ELEMENTS AND A VARIABLE-OUTPUT HASH.
   *    Everything else is 32 or 33 bytes with a fixed digest, so any size
   *    assumed rather than read from the suite surfaces here first — which is
   *    part of why it is worth having.
   *
   * ⛔ H2 IS NOT THE BARE HASH HERE, unlike Ed25519. RFC 8032 defines the
   *    Ed448 challenge as SHAKE256(dom4(0, "") ‖ R ‖ A ‖ M), and RFC 9591
   *    §6.3 says the same: H2(m) = H("SigEd448" ‖ 0x00 ‖ 0x00 ‖ m). The
   *    earlier comment here claimed the prefix would break standard
   *    verifiers; it was the other way round — without it, every Ed448
   *    signature failed RFC 8032 verification while our own verify agreed.
   */
  ed448: {
    name: 'FROST(Ed448, SHAKE256)',
    contextString: 'FROST-ED448-SHAKE256-v1',
    Ne: 57,
    Ns: 57,
    scalar_endian: 'le',
    order: 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3n,
    hash: function (bytes) { return shake256(bytes, 114); },
    hash_len: 114,
    scalar_from_hash: 'le_wide',
    h1_context: 'rho',
    h2_context: null,
    h2_prefix: new Uint8Array([0x53, 0x69, 0x67, 0x45, 0x64, 0x34, 0x34, 0x38, 0x00, 0x00]), // "SigEd448" ‖ 0 ‖ 0 (dom4)
    h3_context: 'nonce',
    h4_context: 'msg',
    h5_context: 'com'
  },

  // Ed448/SHAKE256 is specified in §6.3 and implemented above: it needs SHAKE256
  // at 114 bytes of output and Ne = Ns = 57, and nothing in the roadmap
  // reaches for it. Adding it is a table entry plus a hash import.

  /*
   * ZIP 312: FROST(Jubjub, BLAKE2b-512) and FROST(Pallas, BLAKE2b-512) -
   * signatures indistinguishable from Zcash spend authorization signatures,
   * Sapling's and Orchard's (reddsa.js).
   *
   * ⭐ THE HASHES ARE PERSONALIZED, NOT PREFIXED. Every H is BLAKE2b-512 with
   *    a 16-byte personalization per role, and the input is the message
   *    alone - no contextString in front of it. H2 is RedDSA's own H*, so
   *    the challenge is the one a Zcash validator recomputes.
   *
   * ⭐ HR - the randomizer - is ZIP 312's addition: re-randomized FROST signs
   *    under vk + α·B (randomizer_from_seed below, frost_pure's rerandomize).
   *
   * ⚠ LABELS OUTSIDE THE ZIP (this library's own: 'dkg-pok', 'adaptor nonce',
   *    'musig2 …') hash under the "D" personalization - the one the reddsa
   *    crate reserves for its DKG - with contextString ‖ label in front, as
   *    every other suite separates them. They are this library's protocols,
   *    and nothing outside it recomputes them.
   *
   * ⚠ THE GROUP GENERATOR IS THE SPEND AUTHORIZATION BASE, not the curve's:
   *    reddsa.js REDJUBJUB_SPEND_AUTH.GROUP and REDPALLAS_SPEND_AUTH.GROUP.
   */
  redjubjub: {
    name: 'FROST(Jubjub, BLAKE2b-512)',
    contextString: 'FROST-RedJubjub-BLAKE2b-512-v1',
    rerandomized: true,
    Ne: 32, Ns: 32, scalar_endian: 'le',
    order: 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7n,
    hash: blake2b, hash_len: 64, scalar_from_hash: 'personal',
    personal: { rho: 'FROST_RedJubjubR', chal: 'Zcash_RedJubjubH', nonce: 'FROST_RedJubjubN',
                msg: 'FROST_RedJubjubM', com: 'FROST_RedJubjubC', randomizer: 'FROST_RedJubjubA',
                other: 'FROST_RedJubjubD' },
    h1_context: 'rho', h2_context: 'chal', h3_context: 'nonce',
    h4_context: 'msg', h5_context: 'com'
  },

  redpallas: {
    name: 'FROST(Pallas, BLAKE2b-512)',
    contextString: 'FROST-RedPallas-BLAKE2b-512-v1',
    rerandomized: true,
    Ne: 32, Ns: 32, scalar_endian: 'le',
    order: 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001n,
    hash: blake2b, hash_len: 64, scalar_from_hash: 'personal',
    personal: { rho: 'FROST_RedPallasR', chal: 'Zcash_RedPallasH', nonce: 'FROST_RedPallasN',
                msg: 'FROST_RedPallasM', com: 'FROST_RedPallasC', randomizer: 'FROST_RedPallasA',
                other: 'FROST_RedPallasD' },
    h1_context: 'rho', h2_context: 'chal', h3_context: 'nonce',
    h4_context: 'msg', h5_context: 'com'
  }
};

function suite(curve) {
  var cs = CIPHERSUITES[curve];
  if (!cs) throw new Error('unknown ciphersuite: ' + curve);
  return cs;
}

// =====================================================================
//  Scalars
// =====================================================================

/**
 * SerializeScalar — RFC 9591 §6, per suite.
 *
 * Fixed width, no length prefix, endianness from the table. Values are
 * reduced first: a Scalar is by definition already in [0, order), so a
 * caller handing over something larger has a bug, but reducing costs
 * nothing and produces canonical output either way.
 */
function serialize_scalar(curve, value) {
  var cs = suite(curve);
  var v = mod(BigInt(value), cs.order);
  return cs.scalar_endian === 'le' ? bigint_to_bytes_le(v, cs.Ns) : bigint_to_bytes(v, cs.Ns);
}

/**
 * DeserializeScalar — with the range check the RFC requires.
 *
 * "This function can fail if the input does not represent a Scalar in the
 * range [0, Order - 1]." That check is not decoration: it is what stops a
 * peer from smuggling a non-canonical encoding past a comparison that would
 * otherwise treat two different byte strings as the same value.
 */
function deserialize_scalar(curve, bytes) {
  var cs = suite(curve);
  if (!(bytes instanceof Uint8Array) || bytes.length !== cs.Ns) {
    throw new Error('scalar must be exactly ' + cs.Ns + ' bytes');
  }

  var v = cs.scalar_endian === 'le' ? bytes_to_bigint_le(bytes) : bytes_to_bigint(bytes);
  if (v >= cs.order) throw new Error('scalar out of range');
  return v;
}

/** A NonZeroScalar: identifiers and interpolation inputs may never be zero. */
function deserialize_nonzero_scalar(curve, bytes) {
  var v = deserialize_scalar(curve, bytes);
  if (v === 0n) throw new Error('scalar must be non-zero');
  return v;
}

// =====================================================================
//  Elements
// =====================================================================

/**
 * Elements travel as opaque fixed-width byte strings.
 *
 * Everything this file does with an Element is concatenate it, so it never
 * needs to know what a point is. Real validation — on the curve, not the
 * identity, in the prime-order subgroup — is specified per suite in §6 and
 * belongs where the point is actually used. Passing an unvalidated element
 * through here and forgetting to validate it later is a real bug, which is
 * why frost.js validates on receipt rather than on use.
 */
function check_element(curve, bytes) {
  var cs = suite(curve);
  if (!(bytes instanceof Uint8Array) || bytes.length !== cs.Ne) {
    throw new Error('element must be exactly ' + cs.Ne + ' bytes');
  }
  return bytes;
}

// =====================================================================
//  expand_message_xmd — RFC 9380 §5.3.1
// =====================================================================

/**
 * Needed by P-256 and secp256k1, whose H1/H2/H3 are hash_to_field rather
 * than a plain wide reduction.
 *
 * ⭐ THIS IS commons/h2c.js's expand_message_xmd NOW. It used to be
 *   implemented here as well, on the argument that this file should depend on
 *   a hash and nothing else - which bought nothing, since the two had to
 *   agree byte for byte anyway and a fix to one would not have reached the
 *   other. The suite's hash is bound with its sizes and handed over.
 *
 * ⚠ THE BLOCK-SIZE CHECK STAYS. A missing block size silently gave Z_pad = 0
 *   bytes, producing outputs no other implementation produces (it happened
 *   for P-384 and P-521); h2c reads hash.BLOCK_SIZE without checking, so the
 *   refusal is made here before the hash is bound.
 */
function expand_message_xmd(cs, msg, dst, len_in_bytes) {
  var s_in_bytes = cs.hash_block;
  if (!Number.isInteger(s_in_bytes) || s_in_bytes <= 0) {
    throw new Error('expand_message_xmd: ciphersuite ' + cs.name + ' has no hash_block');
  }
  var h = function (b) { return cs.hash(b); };
  h.DIGEST_SIZE = cs.hash_len;
  h.BLOCK_SIZE = s_in_bytes;
  return h2c_expand_message_xmd(msg, dst, len_in_bytes, h);
}

// =====================================================================
//  H1 – H5, RFC 9591 §6
// =====================================================================


/** Interpret a digest as a little-endian integer and reduce. */
function le_reduce(bytes, order) { return bytes_to_bigint_le(bytes) % order; }

function be_reduce(bytes, order) { return bytes_to_bigint(bytes) % order; }

/**
 * The three Scalar-valued hashes share everything but their domain string,
 * so they share an implementation. The branch on scalar_from_hash is the
 * only real difference between the Edwards suites and the SEC1 ones.
 */
/**
 * A personalized suite's digest for one role (ZIP 312): BLAKE2b-512 under
 * that role's personalization, over the message alone. A label the ZIP does
 * not name goes under the suite's "other" personalization with
 * contextString ‖ label in front - see the suite table.
 */
function personal_digest(cs, context, msg) {
  var p = cs.personal[context];
  if (p) return blake2b(msg, 64, undefined, { personal: utf8(p) });
  return blake2b(concatUint8Arrays([utf8(cs.contextString), utf8(context), msg]), 64, undefined,
                 { personal: utf8(cs.personal.other) });
}

function hash_to_scalar(cs, context, msg) {
  if (cs.scalar_from_hash === 'personal') {
    return le_reduce(personal_digest(cs, context, msg), cs.order);
  }
  if (cs.scalar_from_hash === 'le_wide') {
    // H(contextString || context || m), little-endian, mod order.
    // A null context is Ed25519's H2: hash the message alone.
    var input = context === null
      ? (cs.h2_prefix ? concatUint8Arrays([cs.h2_prefix, msg]) : msg)
      : concatUint8Arrays([utf8(cs.contextString), utf8(context), msg]);
    return le_reduce(cs.hash(input), cs.order);
  }

  // hash_to_field(m, 1) with DST = contextString || context, L = 48.
  var dst = utf8(cs.contextString + context);
  return be_reduce(expand_message_xmd(cs, msg, dst, cs.L), cs.order);
}

/**
 * A Scalar-valued hash under an arbitrary domain label.
 *
 * H1/H2/H3 are the RFC's three; the DKG needs its own, because RFC 9591 does
 * not specify key generation at all and reusing "rho" or "chal" would let a
 * value computed for one purpose be replayed as the other. Everything else
 * about the derivation — endianness, reduction, expand_message_xmd for the
 * SEC1 suites — stays identical, which is the point of routing through here
 * rather than hashing by hand.
 */
function hash_to_scalar_labelled(curve, label, msg) {
  return hash_to_scalar(suite(curve), label, msg);
}

/** H1 — the binding factor. */
function H1(curve, msg) {
  var cs = suite(curve);
  return hash_to_scalar(cs, cs.h1_context, msg);
}

/** H2 — the signature challenge. Undomain-separated on Ed25519, by design. */
function H2(curve, msg) {
  var cs = suite(curve);
  return hash_to_scalar(cs, cs.h2_context, msg);
}

/** H3 — nonce generation. */
function H3(curve, msg) {
  var cs = suite(curve);
  return hash_to_scalar(cs, cs.h3_context, msg);
}

/* H4 and H5 are digests, not scalars: H(contextString ‖ label ‖ m), or the
   label's personalization on a ZIP 312 suite */
function digest(cs, context, msg) {
  if (cs.personal) return personal_digest(cs, context, msg);
  return cs.hash(concatUint8Arrays([utf8(cs.contextString), utf8(context), msg]));
}

/** H4 — the message digest that goes into the binding factor input. */
function H4(curve, msg) {
  var cs = suite(curve);
  return digest(cs, cs.h4_context, msg);
}

/** H5 — the commitment-list digest. */
function H5(curve, msg) {
  var cs = suite(curve);
  return digest(cs, cs.h5_context, msg);
}

/**
 * The randomizer α of re-randomized FROST — ZIP 312, as frost-rerandomized
 * 3.0 computes it:
 *
 *   α = HR(seed ‖ encode_group_commitment_list(commitments))
 *
 * The coordinator draws `seed` (Ns random bytes) and sends it to the signers
 * over a CONFIDENTIAL channel - α is what links the signature to the
 * long-term key, so whoever learns it can link the spend. Each signer
 * recomputes α from the seed and the commitments it was given, rather than
 * taking α itself: a coordinator with a bad RNG still yields a randomizer
 * bound to this signing run.
 */
function randomizer_from_seed(curve, seed, commitment_list) {
  var cs = suite(curve);
  if (!cs.rerandomized) throw new Error('the ' + cs.name + ' suite is not re-randomized');
  if (!(seed instanceof Uint8Array) || seed.length !== cs.Ns) {
    throw new Error('randomizer seed must be exactly ' + cs.Ns + ' bytes');
  }
  return hash_to_scalar(cs, 'randomizer',
    concatUint8Arrays([seed, encode_group_commitment_list(curve, commitment_list)]));
}

// =====================================================================
//  list encoding — RFC 9591 §4.3
// =====================================================================

/**
 * encode_group_commitment_list.
 *
 * A flat concatenation of (identifier ‖ hiding ‖ binding) with no separators
 * and no length prefixes, hashed by H5 into every participant's binding
 * factor.
 *
 * THE SORT IS NOT COSMETIC. The RFC says the list MUST be sorted in
 * ascending order by identifier, and that sentence is the whole reason two
 * honest parties produce combinable signature shares. Sort differently and
 * every party computes a different binding factor from the same inputs,
 * every share is individually well-formed, and the aggregate verifies
 * against nothing. Sorting here rather than trusting the caller means there
 * is one place this can be got wrong instead of one per call site.
 *
 * Sorting is by numeric identifier, not by encoded bytes: on little-endian
 * suites those orders differ, and the RFC compares Scalars by value.
 */
function encode_group_commitment_list(curve, commitment_list) {
  var cs = suite(curve);

  var sorted = commitment_list.slice().sort(function (a, b) {
    return a.identifier < b.identifier ? -1 : a.identifier > b.identifier ? 1 : 0;
  });

  for (var i = 1; i < sorted.length; i++) {
    if (sorted[i].identifier === sorted[i - 1].identifier) {
      throw new Error('duplicate identifier ' + sorted[i].identifier);
    }
  }

  var parts = [];
  for (var i = 0; i < sorted.length; i++) {
    var c = sorted[i];
    if (c.identifier === 0n) throw new Error('identifier must be non-zero');
    parts.push(serialize_scalar(curve, c.identifier));
    parts.push(check_element(curve, c.hiding));
    parts.push(check_element(curve, c.binding));
  }
  return concatUint8Arrays(parts);
}

/** participants_from_commitment_list — §4.3, sorted to match the encoding. */
function participants_from_commitment_list(commitment_list) {
  return commitment_list
    .map(function (c) { return c.identifier; })
    .sort(function (a, b) { return a < b ? -1 : a > b ? 1 : 0; });
}

// =====================================================================
//  binding factors — RFC 9591 §4.4
// =====================================================================

/**
 * The prefix every participant's binding factor is computed from:
 *
 *   SerializeElement(PK) ‖ H4(msg) ‖ H5(encode_group_commitment_list(...))
 *
 * Both hashes are there to make the input fixed-length, so appending the
 * identifier cannot be confused with a longer message — the RFC's own
 * comments say as much. Exposed separately from compute_binding_factors
 * because the test vectors publish it under the name binding_factor_input,
 * which makes it the single most useful intermediate value to check.
 */
function binding_factor_input(curve, group_public_key, msg, commitment_list, identifier) {
  return concatUint8Arrays([
    check_element(curve, group_public_key),
    H4(curve, msg),
    H5(curve, encode_group_commitment_list(curve, commitment_list)),
    serialize_scalar(curve, identifier)
  ]);
}

/**
 * compute_binding_factors — §4.4. One Scalar per participant, keyed by
 * identifier as a decimal string so the map is usable from ordinary JS.
 */
function compute_binding_factors(curve, group_public_key, msg, commitment_list) {
  var out = {};
  var ids = participants_from_commitment_list(commitment_list);
  for (var i = 0; i < ids.length; i++) {
    out[ids[i].toString()] = H1(curve,
      binding_factor_input(curve, group_public_key, msg, commitment_list, ids[i]));
  }
  return out;
}

/**
 * compute_challenge — §4.6.
 *
 * challenge_input = SerializeElement(R) ‖ SerializeElement(PK) ‖ msg
 *
 * The message goes in raw and unhashed: FROST does not pre-hash, so the full
 * message must be in hand. §7.6 permits pre-hashing at the application
 * layer, with its own distinct prefix — never by silently reusing H4.
 */
function compute_challenge(curve, group_commitment, group_public_key, msg) {
  if (suite(curve).bip340) {
    /*
     * BIP 340's own challenge over the x coordinates, from secp256k1.js.
     * This used to spell the tagged hash out with "BIP0340/challenge" as
     * seventeen byte values - a third copy of a construction the verifier
     * on the other end computes from secp256k1.js, and must match exactly.
     */
    return bip340_challenge(check_element(curve, group_commitment).slice(1),
                            check_element(curve, group_public_key).slice(1), msg);
  }
  if (suite(curve).sr25519) {
    /* schnorrkel's Merlin challenge; msg is sr25519.signing_message(context, message) */
    return sr25519_challenge(msg, check_element(curve, group_public_key), check_element(curve, group_commitment));
  }
  return H2(curve, concatUint8Arrays([
    check_element(curve, group_commitment),
    check_element(curve, group_public_key),
    msg
  ]));
}

// =====================================================================
//  interpolation — RFC 9591 §4.2
// =====================================================================

/**
 * derive_interpolating_value: the Lagrange coefficient for x_i over the set
 * L, computed in the Scalar field.
 *
 * This is where "who is signing" enters the arithmetic. The same share
 * produces different intermediate values with {1,2} than with {1,3}, and the
 * same final signature — which is why the signer subset has to be agreed
 * before round two and cannot change midway.
 */
function derive_interpolating_value(curve, L, x_i) {
  var cs = suite(curve);

  if (L.indexOf(x_i) < 0) throw new Error('x_i is not in L');
  for (var i = 0; i < L.length; i++) {
    for (var j = i + 1; j < L.length; j++) {
      if (L[i] === L[j]) throw new Error('duplicate x-coordinate in L');
    }
  }

  /*
   * ⛔ THE INVERSE IS shamir.js's FERMAT, NOT invert() BELOW.
   *
   *   This used to compute the product here and invert the denominator with
   *   the extended Euclidean algorithm, on the argument that identifiers are
   *   public. frost.js makes the opposite argument - a timing signal on the
   *   Lagrange coefficient reveals WHICH participants signed, which is part
   *   of what threshold signing hides - and shamir.lagrange_at_zero is the
   *   constant-time version both now share. Same value; the checks above
   *   stay, so the errors a caller sees are unchanged.
   */
  return lagrange_at_zero(x_i, L, cs.order);
}

/* commons/primes.js's mod - same semantics, it was a local copy */
var mod = primes_mod;

/**
 * Modular inverse by the extended Euclidean algorithm.
 *
 * Variable-time, and that is stated rather than assumed. The only inputs it
 * ever sees are Lagrange denominators built from participant identifiers,
 * which are public — every party knows who is signing. A secret Scalar must
 * never reach this function; §7.1 is explicit that the operations touching
 * secrets need to be constant time.
 */
function invert(a, m) {
    var v = mod_inverse(a, m);                 /* commons/primes */
    if (v === null) { throw new Error('frost: not invertible'); }
    return v;
}

// =====================================================================
//  signature encoding — RFC 9591 Appendix A
// =====================================================================

/** (R, z) → R_encoded ‖ z_encoded, Ne + Ns bytes. */
function serialize_signature(curve, R, z) {
  var out = concatUint8Arrays([check_element(curve, R), serialize_scalar(curve, z)]);
  if (suite(curve).sr25519) out[63] |= 0x80;      // schnorrkel's marker (z < 2^253 leaves the bit free)
  return out;
}

function deserialize_signature(curve, bytes) {
  var cs = suite(curve);
  if (!(bytes instanceof Uint8Array) || bytes.length !== cs.Ne + cs.Ns) {
    throw new Error('signature must be ' + (cs.Ne + cs.Ns) + ' bytes');
  }
  var zb = bytes.subarray(cs.Ne);
  if (cs.sr25519) {
    if ((zb[31] & 0x80) === 0) throw new Error('signature: the schnorrkel marker is missing');
    zb = Uint8Array.from(zb); zb[31] &= 0x7f;
  }
  return {
    R: bytes.subarray(0, cs.Ne),
    z: deserialize_scalar(curve, zb)
  };
}

export {
  CIPHERSUITES,
  suite,
  serialize_scalar,
  deserialize_scalar,
  H1,
  H2,
  H3,
  H4,
  H5,
  hash_to_scalar_labelled,
  encode_group_commitment_list,
  binding_factor_input,
  compute_binding_factors,
  compute_challenge,
  randomizer_from_seed,
  derive_interpolating_value,
  serialize_signature,
  deserialize_signature,
  invert,
  mod
};
