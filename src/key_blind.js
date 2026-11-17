/**
 * Key blinding  -  one key, many unlinkable identities
 *
 * A signer holds one long-term key and derives an unbounded number of public
 * keys from it, each looking independent to anyone who does not hold the
 * blind. Signatures made under a blinded key verify against that key and
 * nothing else.
 *
 *     blind_public_key(pk, bk, ctx)    ->  pk', unlinkable to pk
 *     blind_sign(sk, bk, ctx, msg)     ->  a signature that verifies under pk'
 *     unblind_public_key(pk', bk, ctx) ->  pk again
 *
 * ==================== WHAT IT IS FOR ====================
 *
 * A DIFFERENT IDENTITY PER SERVICE, ONE KEY TO BACK UP. The holder can prove
 * to each service that it controls that service's key, and no two services
 * can determine they are talking to the same person - even in collusion.
 *
 * Tor uses this for onion service addresses: the long-term identity stays put
 * while the published address rotates, so a directory server cannot build a
 * history. The construction here is the generalisation, standardised by CFRG.
 *
 * =============== HOW IT DIFFERS FROM WHAT IS HERE ALREADY ===============
 *
 * BBS gives unlinkable PRESENTATIONS of one credential. This gives unlinkable
 * KEYS. Different layer: BBS hides which signature you are showing, key
 * blinding hides which signer you are.
 *
 * And it is not derivation in the BIP 32 sense. BIP 32 derives children whose
 * relationship is public - anyone with the extended public key can enumerate
 * them. Here the relationship is hidden behind the blind, and without it the
 * keys are independent.
 *
 * ===================== THE MECHANISM =====================
 *
 * The blind is hashed to a scalar and the key is MULTIPLIED by it:
 *
 *     s  = H(bk || 0x00 || ctx)  as a scalar
 *     pk' = s * pk
 *     sk' = s1 * s  where s1 is the usual Ed25519 secret scalar
 *
 * Multiplicative rather than additive, which is what makes unblinding a
 * modular inverse rather than a subtraction, and what keeps the blinded key
 * in the prime-order subgroup without extra checks.
 *
 * THE PRUNING STEP IS DELIBERATELY SKIPPED. RFC 8032 clamps the hashed secret
 * - clears the low three bits, fixes the top two - and the draft says
 * explicitly not to do that here. Clamping would restrict the blind to a
 * subset of scalars and make blinded keys distinguishable, which defeats the
 * point. That instruction looks like an error when read quickly, and it is
 * not.
 *
 * ========================= CAVEATS =========================
 *
 * THE CONTEXT SEPARATES USES, NOT USERS. Two services that agree on the same
 * ctx and are shown keys from the same blind will see the same key. The ctx
 * is a domain separator - the per-service unlinkability comes from using a
 * different ctx, a different bk, or both.
 *
 * THE BLIND IS AS SENSITIVE AS THE KEY. Anyone holding bk and ctx can link
 * every identity derived from them back to the root, and with sk can sign
 * under any of them.
 *
 * THIS IS A DRAFT, not yet an RFC: draft-irtf-cfrg-signature-key-blinding-11,
 * all three of its sections - Ed25519, Ed448, and ECDSA (P-256 and P-384).
 * Ed25519 and ECDSA(P-384) are checked against the draft's own vectors;
 * Ed448, for which the draft has none, against OpenSSL's Ed448 verifier.
 *
 * ⚠ THE DRAFT WARNS ABOUT ITS ECDSA SECTION, and the warning belongs here:
 *   multiplicative blinding of ECDSA is NOT strongly unforgeable when an
 *   adversary chooses the blind (related-key forgeries, [MSMHI15]). The blind
 *   must be the signer's own secret, never a value someone else supplies.
 */

import { mod } from './commons/primes.js';
import * as ed25519 from './ed25519.js';
import * as ed448 from './ed448.js';
import { concat, bytes_to_bigint_le, bytes_to_bigint, bigint_to_bytes } from './commons/bytes.js';
import { inv_prime } from './commons/modp.js';
import { sha256, sha384, sha512 } from './sha2.js';
import { shake256 } from './sha3.js';
import { P256_GROUP, P384_GROUP, p256, p384 } from './nist.js';
import { hash_to_field, expand_message_xmd } from './commons/h2c.js';

/* =========================================================================
 * EdDSA - draft sections 4 (Ed25519) and 5 (Ed448)
 *
 * ⭐ ONE IMPLEMENTATION, TWO CURVES. The sections differ in the hash and the
 *   sizes only: SHA-512 to 64 bytes and 32-byte halves on Ed25519, SHAKE256
 *   to 114 bytes and 57-byte halves on Ed448 - RFC 8032's own expansion for
 *   each curve.
 *
 * ⚠ Ed448's section reads "SHAKE256(..., 117)" and then takes halves at 57
 *   and 114. SHAKE256 is an XOF: the first 114 bytes of a 117-byte output
 *   ARE the 114-byte output, so both readings give the same scalar and
 *   prefix, and this uses RFC 8032's 114. The draft has no Ed448 test
 *   vectors; the test checks that what this signs verifies under OpenSSL's
 *   Ed448, which knows nothing of blinding.
 * ======================================================================= */

/*
 * A clamped scalar is wider than L - 255 bits on Ed25519, 448 on Ed448 - so
 * the ladder takes the full width. The same trap ecvrf.js documents: at L's
 * width the top bits are dropped silently, and the result is a point on the
 * curve that encodes fine and is wrong.
 */
function eddsa_suite(name, C, hash, half, scalar_bits) {
    var L = C.CURVE.L;

    /**
     * The blinding scalar AND the nonce prefix, from the blind and the
     * context. NO PRUNING - see the note at the top: the digest's lower half
     * is read little-endian and reduced, with none of RFC 8032's clamping.
     */
    function expand(bk, ctx) {
        if (!(bk instanceof Uint8Array) || bk.length !== half) {
            throw new Error('key_blind: an ' + name + ' blind must be ' + half + ' bytes');
        }
        var h = hash(concat([bk, new Uint8Array([0x00]), ctx || new Uint8Array(0)]));
        return { scalar: mod(bytes_to_bigint_le(h.subarray(0, half)), L), prefix: h.subarray(half, 2 * half) };
    }

    return {
        name: name,
        scalar: function (bk, ctx) { return expand(bk, ctx).scalar; },

        /**
         * BlindPublicKey: pk · s.
         * @return {Uint8Array|null} null when pk is not a valid point
         */
        blind_public_key: function (pk, bk, ctx) {
            var P = C.decode_point(pk);
            if (P === null) { return null; }
            return C.encode_point(C.POINT.mul(expand(bk, ctx).scalar, P, scalar_bits));
        },

        /**
         * UnblindPublicKey: pk' · s⁻¹ - which is why the blinding is
         * multiplicative: with an additive blind this would be a subtraction
         * and the blinded key could fall outside the prime-order subgroup.
         *
         * @return {Uint8Array|null} null when the key does not decode or s is zero
         */
        unblind_public_key: function (blinded_pk, bk, ctx) {
            var P = C.decode_point(blinded_pk);
            if (P === null) { return null; }
            var s = expand(bk, ctx).scalar;
            if (s === 0n) { return null; }
            return C.encode_point(C.POINT.mul(inv_prime(s, L), P, scalar_bits));
        },

        /**
         * BlindKeySign: the signing scalar is s1 · s2 and the nonce prefix
         * is prefix1 ‖ prefix2 - so the nonce depends on the blind as well
         * as the key. Without that, two signatures under different blinds
         * would share a nonce for one message, and a nonce shared across two
         * secret scalars leaks both.
         *
         * @param  {Uint8Array} seed  the RFC 8032 seed (32 or 57 bytes)
         * @return {Uint8Array} a signature the curve's ordinary verify accepts
         */
        blind_sign: function (seed, bk, ctx, msg) {
            /* the ordinary expansion, WITH clamping - the curve's own */
            var e1 = C.expand_seed(seed);
            /* the blind, WITHOUT clamping */
            var e2 = expand(bk, ctx);
            /* from here it is RFC 8032's Sign from step 2: the curve's sign_expanded */
            return C.sign_expanded(msg, { scalar: mod(e1.scalar * e2.scalar, L), prefix: concat([e1.prefix, e2.prefix]) }, null, 0);
        },

        /** The blinded public key blind_sign's output verifies against. */
        blind_public_key_from_seed: function (seed, bk, ctx) {
            return C.encode_point(C.base_mul(mod(C.expand_seed(seed).scalar * expand(bk, ctx).scalar, L)));
        }
    };
}

/** Ed25519 (section 4) and Ed448 (section 5). */
export var ED25519 = /* @__PURE__ */ eddsa_suite('Ed25519', ed25519, function (m) { return sha512(m); }, 32, 255);
export var ED448   = /* @__PURE__ */ eddsa_suite('Ed448', ed448, function (m) { return shake256(m, 114); }, 57, 448);

/* the Ed25519 functions under their original names */
export var blind_public_key           = ED25519.blind_public_key;
export var unblind_public_key         = ED25519.unblind_public_key;
export var blind_sign                 = ED25519.blind_sign;
export var blind_public_key_from_seed = ED25519.blind_public_key_from_seed;

/* =========================================================================
 * ECDSA - draft section 6
 *
 * The same idea on a prime-order Weierstrass curve: the blind becomes a
 * scalar, the key is multiplied by it, and signing is ordinary ECDSA under
 * the multiplied key. The scalar is hash_to_field (RFC 9380 section 5) with
 * DST "ECDSA Key Blind", expand_message_xmd under the signature's own hash,
 * L = 48 for P-256 and 72 for P-384, modulo the group order.
 *
 * Keys travel as this library's ECDSA keys do: secrets as big-endian scalar
 * bytes, public keys as SEC 1 points (the draft's vectors use compressed).
 * ======================================================================= */

var ECDSA_DST = /* @__PURE__ */ new TextEncoder().encode('ECDSA Key Blind');

function ecdsa_suite(name, E, G, hash, L) { return { name: name, E: E, G: G, hash: hash, L: L }; }

/** ECDSA(P-256, SHA-256) and ECDSA(P-384, SHA-384): the curve, its hash, L. */
export var ECDSA_P256 = /* @__PURE__ */ ecdsa_suite('ECDSA(P-256, SHA-256)', p256, P256_GROUP, sha256, 48);
export var ECDSA_P384 = /* @__PURE__ */ ecdsa_suite('ECDSA(P-384, SHA-384)', p384, P384_GROUP, sha384, 72);

/* HashToScalar(concat(bk, 0x00, ctx)) */
function ecdsa_blind_scalar(S, bk, ctx) {
    var input = concat([bk, new Uint8Array([0x00]), ctx || new Uint8Array(0)]);
    var s = hash_to_field(input, 1, ECDSA_DST, S.G.ORDER, 1, S.L,
        function (m, d, n) { return expand_message_xmd(m, d, n, S.hash); })[0];
    if (s === 0n) { throw new Error('key_blind: the blind hashed to zero'); }
    return s;
}

/* a secret key: big-endian, the order's width, in [1, order) - as commons/ecdsa.js reads it */
function scalar_of(S, b) {
    var v = b instanceof Uint8Array && b.length === S.G.SCALAR_BYTES ? bytes_to_bigint(b) : 0n;
    if (!(v > 0n && v < S.G.ORDER)) { throw new Error('key_blind: ' + S.name + ' secret key out of range'); }
    return v;
}

/**
 * BlindPublicKey for ECDSA: pk · HashToScalar(bk ‖ 0x00 ‖ ctx).
 *
 * @param {object}     S    ECDSA_P256 or ECDSA_P384
 * @param {Uint8Array} pk   a SEC 1 point
 * @return {Uint8Array|null} the blinded key, compressed; null when pk does not decode
 */
export function ecdsa_blind_public_key(S, pk, bk, ctx) {
    var P = S.G.decode(pk);
    if (P === null) { return null; }
    /* constant time: the scalar comes from the blind, a secret */
    return S.G.encode(S.G.mul(ecdsa_blind_scalar(S, bk, ctx), P));
}

/** UnblindPublicKey for ECDSA: pkR times the scalar's inverse. */
export function ecdsa_unblind_public_key(S, pkR, bk, ctx) {
    var P = S.G.decode(pkR);
    if (P === null) { return null; }
    return S.G.encode(S.G.mul(inv_prime(ecdsa_blind_scalar(S, bk, ctx), S.G.ORDER), P));
}

/**
 * The blinded signing key, skR = skS · HashToScalar(bk ‖ 0x00 ‖ ctx).
 * Exposed because ECDSA signing is the caller's hash and the curve's sign;
 * ecdsa_blind_sign below is the two together.
 */
export function ecdsa_blind_secret(S, sk, bk, ctx) {
    var v = (scalar_of(S, sk) * ecdsa_blind_scalar(S, bk, ctx)) % S.G.ORDER;
    return bigint_to_bytes(v, S.G.SCALAR_BYTES);
}

/**
 * BlindKeySign for ECDSA: ordinary ECDSA under skR. The message is hashed
 * with the suite's hash, as the draft's vectors do.
 *
 * @param {Uint8Array} [extra]  RFC 6979 section 3.6 k', as the curve's sign
 *                              takes it: omitted or null draws fresh bytes,
 *                              an empty array gives classic RFC 6979
 * @return {{r: bigint, s: bigint, recovery: number}}
 */
export function ecdsa_blind_sign(S, sk, bk, ctx, msg, extra) {
    return S.E.sign(S.hash(msg), ecdsa_blind_secret(S, sk, bk, ctx), extra);
}

/**
 * The blinding scalar for a key on `curve`, by the draft's rule for that
 * curve: Ed25519's (SHA-512, no pruning) or ECDSA's (hash_to_field). For a
 * caller holding the key in a form these functions do not take - a threshold
 * key, split into shares, whose holders multiply their shares by it and so
 * hold the blinded key without anyone assembling either.
 *
 * @param {string} curve  'ed25519', 'ed448', 'p256' or 'p384'
 * @return {bigint} the scalar, never zero
 */
export function blinding_scalar(curve, bk, ctx) {
    var S = curve === 'ed25519' ? ED25519 : curve === 'ed448' ? ED448 : null;
    if (S !== null) {
        var s = S.scalar(bk, ctx);
        if (s === 0n) { throw new Error('key_blind: the blind hashed to zero'); }
        return s;
    }
    if (curve === 'p256') { return ecdsa_blind_scalar(ECDSA_P256, bk, ctx); }
    if (curve === 'p384') { return ecdsa_blind_scalar(ECDSA_P384, bk, ctx); }
    throw new Error('key_blind: the draft defines blinding for ed25519, ed448, p256 and p384 - not ' + curve);
}
