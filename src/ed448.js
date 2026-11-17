/**
 * Ed448  -  RFC 8032
 *
 * The larger EdDSA curve, sometimes called Ed448-Goldilocks after Mike
 * Hamburg's original. Its prime, 2^448 - 2^224 - 1, is a "golden-ratio"
 * shape chosen so that reduction can be done with a single Karatsuba-style
 * split - which is where the name comes from.
 *
 * About 224 bits of security against 128 for Ed25519, which in practice
 * means it exists for the profiles that require a higher level on paper:
 * CNSA, some government PKI, TLS 1.3's ed448 signature algorithm. Ed25519 is
 * already beyond any foreseeable classical attack, so the choice is usually
 * about compliance rather than threat.
 *
 * FOUR THINGS DIFFER FROM Ed25519, and every one of them is a place an
 * implementation goes wrong:
 *
 *   - The curve is UNTWISTED: a = 1, not -1. commons/edwards.js takes a as
 *     an argument, so nothing changes there.
 *   - The hash is SHAKE256 with a 114-byte output, not SHA-512. It is an XOF,
 *     so the length is a parameter rather than a property of the function.
 *   - Every hash input is prefixed with a DOMAIN STRING, "SigEd448", a
 *     pre-hash flag and a context. Ed25519 has no such prefix; feeding one
 *     scheme's input to the other produces a valid-looking wrong answer.
 *   - Keys are 57 bytes and signatures 114, not 32 and 64. The extra byte
 *     carries the sign bit, since 448 bits fill 56 bytes exactly with nothing
 *     left over.
 *
 * The cofactor is 4 rather than 8, which the clamping reflects.
 */

import { h2c_suite, expand_message_xof, map_to_curve_elligator2 } from './commons/h2c.js';
import { make_group } from './commons/group.js';
import { subgroup_check } from './commons/edwards.js';
import { wnaf_mul } from './commons/fixed_window.js';
import { eddsa } from './commons/eddsa.js';
import { ascii } from './commons/bytes.js';
import { shake256 } from './sha3.js';

var P = (1n << 448n) - (1n << 224n) - 1n;

/** SHAKE256 with the 114-byte output Ed448 specifies. */
function h114(msg) { return shake256(msg, 114); }
h114.DIGEST_SIZE = 114;

var SIGED448 = /* @__PURE__ */ ascii('SigEd448');

export var CURVE = {
    name: 'ed448',
    /* scalars are little-endian on this curve - see commons/group.js */
    little_endian: true,
    scalar_bytes_length: 57,
    p: P,
    a: 1n,
    d: P - 39081n,
    L: 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3n,
    cofactor: 4n,
    Gx: 0x4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05en,
    Gy: 0x693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14n,
    hash: h114,
    bytes: 57,
    /* p = 3 mod 4, so the square root is a single exponentiation - simpler
       than Ed25519's p = 5 mod 8 case, which needs a correction factor */
    sqrt_mode: 4,
    scalar_bits: 448,
    pure_uses_dom: true,
    dom_prefix: SIGED448,
    /* Ed448ph reduces the message with SHAKE256 to 64 bytes */
    prehash: function (m) { return shake256(m, 64); },
    /**
     * Clamping. The low TWO bits are cleared - the cofactor is 4 here, not 8
     * - bit 447 is set to fix the length, and the top byte is zeroed because
     * the scalar occupies 56 of the 57 bytes.
     */
    clamp: function (s) {
        s[0] &= 252;
        s[55] |= 128;
        s[56] = 0;
    }
};

var E = /* @__PURE__ */ eddsa(CURVE);

/*
 * ⭐ k*G through the table the signing path already builds. It was
 *   unreachable from outside - measured on secp256k1 at 0.57 ms through
 *   the table against 4.42 ms without, a factor of 7.8 lost to a missing
 *   export line.
 */
export var base_mul       = E.base_mul;
export var get_public_key = E.get_public_key;
/* keygen(seed) -> { sk: the 57-byte seed (a copy), pk }; seed omitted or null: a fresh one */
export var keygen         = E.keygen;
export var sign           = E.sign;
export var verify         = E.verify;
/*
 * ⭐ one key, many messages: signer_create(seed, ctx?, variant?) -> { sign(msg) }
 *    expands the seed and computes A once; verifier_create(public_key, ctx?,
 *    variant?, mode?) -> { verify(msg, sig) } decodes the key once. Same
 *    bytes, same answers as sign and verify.
 */
export var signer_create   = E.signer_create;
export var verifier_create = E.verifier_create;
/*
 * ⭐ many signatures, one check: verify_batch(items) is true when every
 *    { msg, sig, pk } verifies, verify_batch_find(items) gives the indices
 *    of those that do not - the same answers as verify (commons/eddsa.js).
 */
export var verify_batch      = E.verify_batch;
export var verify_batch_find = E.verify_batch_find;

/** Ed448ph - the prehashed variant, using SHAKE256 with a 64-byte output. */
export function sign_ph(msg, seed, ctx)      { return E.sign_variant(msg, seed, ctx, 2); }
export function verify_ph(msg, sig, pk, ctx, mode) { return E.verify_variant(msg, sig, pk, ctx, 2, mode); }
/* RFC 8032's seed expansion - {scalar, prefix} - as ed25519.js exports it (a threshold key split from a seed) */
export var expand_seed    = E.expand;
/* RFC 8032 signing from an expanded key - key_blind.js signs under a blinded one */
export var sign_expanded  = E.sign_expanded;
export var encode_point   = E.encode_point;
export var decode_point   = E.decode_point;
export var POINT          = E.POINT;
export var FIELD          = E.FIELD;

/* =========================================================================
 * hash-to-curve: edwards448_XOF:SHAKE256_ELL2_RO_, RFC 9380 section 8.6
 *
 * ⭐ THE ONLY CURVE HERE WITH 57-BYTE ELEMENTS AND AN XOF.
 *
 *   Every other suite in this library expands with a fixed-output hash and
 *   works in 32 or 48-byte fields. edwards448 uses SHAKE256 with L = 84 and
 *   encodes to 57 bytes, so any size assumption written by accident - a
 *   hardcoded 32, an expand that ignores its length argument - shows up here
 *   and nowhere else.
 *
 * ==================== THE MAP GOES VIA CURVE448 ====================
 *
 * Elligator 2 lands on the MONTGOMERY curve K*t^2 = s^3 + J*s^2 + s with
 * J = 156326, and a 4-ISOGENY carries it to edwards448. That is not the
 * birational map edwards25519 uses: the two curves are isogenous rather than
 * isomorphic, so the map has degree four and RFC 7748 section 4.2 gives it
 * as a ratio of quintics.
 *
 * The isogeny already multiplies the order by four, which is exactly the
 * cofactor - so h_eff is 1 here rather than 4, and clearing again would
 * multiply by sixteen and land on the wrong point.
 * ======================================================================= */

var ELL_J = 156326n;
var ELL_Z448 = /* @__PURE__ */ FIELD.neg(1n);

/**
 * Elligator 2 onto curve448 - commons/h2c.js, with Z = -1 and K = 1 - then
 * the 4-isogeny onto edwards448.
 *
 * ⚠ THE SIGN OF y MATTERS ASYMMETRICALLY HERE. v appears linearly in the
 *   isogeny's x numerator and squared in its y, so a wrong step-19 sign gives
 *   a point whose y matches the vector exactly and whose x is p minus it -
 *   a far narrower signal than a wrong point, and what made this diagnosable
 *   in one step instead of five. The map used to be written out here; the
 *   shared one applies step 19 literally, which this copy already did.
 */
function map_elligator2_ed448(u) {
    var mp = map_to_curve_elligator2(FIELD, ELL_J, ELL_Z448, u);
    return isogeny_4(mp.s, mp.t);
}

/**
 * The 4-isogeny from curve448 to edwards448, RFC 7748 section 4.2.
 *
 *     x = 4*v*(u^2 - 1) / (u^4 - 2*u^2 + 4*v^2 + 1)
 *     y = -(u^5 - 2*u^3 - 4*u*v^2 + u)
 *         / (u^5 - 2*u^2*v^2 - 2*u^3 - 2*v^2 + u)
 *
 * A zero denominator means the input was one of the points the isogeny sends
 * to the identity, so it is mapped there deliberately rather than left to
 * produce a division error.
 */
function isogeny_4(u, v) {
    var F = FIELD, m = F.mul, ad = F.add, sb = F.sub, sq = F.sqr, neg = F.neg;

    var u2 = sq(u), u3 = m(u2, u), u4 = sq(u2), u5 = m(u4, u);
    var v2 = sq(v);

    var xn = m(m(4n, v), sb(u2, 1n));
    var xd = ad(ad(sb(u4, m(2n, u2)), m(4n, v2)), 1n);

    var yn = neg(ad(sb(sb(u5, m(2n, u3)), m(m(4n, u), v2)), u));
    var yd = ad(sb(sb(sb(u5, m(m(2n, u2), v2)), m(2n, u3)), m(2n, v2)), u);

    var ex = xd === 0n ? 0n : m(xn, F.inv(xd));
    var ey = yd === 0n ? 1n : m(yn, F.inv(yd));
    return { x: ex, y: ey };
}

export var ed448_h2c = /* @__PURE__ */ h2c_suite({
    F: FIELD, C: POINT, p: CURVE.p, L: 84,
    /*
     * h_eff = 4, READ FROM THE SPEC RATHER THAN REASONED ABOUT.
     *
     * RFC 9380 section 8.6 gives h_eff: 4 for curve448_XOF:SHAKE256_ELL2_RO_,
     * and edwards448 is defined as identical except for the parameters it
     * lists - which do not include h_eff.
     *
     * The first version here used 1, on the argument that the 4-isogeny has
     * already multiplied the order by four. That reasoning is plausible and
     * wrong: the vectors give Q0 and Q1 ALREADY ON edwards448, so the
     * isogeny is inside map_to_curve and the clearing still has to happen.
     *
     * Which is why the isolation mattered. With Q0 confirmed against the
     * vector, a wrong final point could only be the addition or this number -
     * and with only the final point to compare, the two are indistinguishable.
     */
    cofactor: 4n,
    order_bits: 448,
    expand: function (msg, dst, len) {
        return expand_message_xof(msg, dst, len, shake256);
    },
    map: map_elligator2_ed448
});
export var B              = E.B;

/* =========================================================================
 * The prime-order group interface - see commons/group.js
 *
 * COFACTOR 4, so decoding needs the subgroup test for the same reason
 * ed25519 does: a point of small order passes every check RFC 8032 asks for,
 * which is correct for verifying a signature and wrong for anything treating
 * the point as a group element.
 *
 * ed448 is a NIST-approved curve at a higher security level than ed25519 -
 * 224 bits against 128 - which is why systems with a formal assurance
 * requirement ask for it. It is also the sixth FROST ciphersuite in RFC 9591,
 * and without this export FROST could not run on it.
 *
 * `hash` is edwards448_XOF:SHAKE256_ELL2_RO_, above. (An earlier version of
 * this note said ed448 had no hash-to-curve suite; it was out of date.)
 * ======================================================================= */


export var GROUP = /* @__PURE__ */ make_group({
    name: 'ed448',
    /* scalars are little-endian on this curve - see commons/group.js */
    little_endian: true,
    scalar_bytes_length: 57,
    ORDER: CURVE.L,
    bits: CURVE.scalar_bits,
    IDENTITY: POINT.ZERO,
    GENERATOR: B,
    encoded_length: 57,
    add: POINT.add,
    neg: POINT.neg,
    equals: POINT.eq,
    mul_raw: POINT.mul,
    encode_raw: encode_point,
    decode_raw: decode_point,
    /* the comb table eddsa already builds, projective and constant time -
       make_group fell back to the ladder on the generator without it */
    base_mul: E.base_mul,
    /* ⭐ for verification only: wNAF on public scalars - see make_group */
    mul_vartime: function (k, P) { return wnaf_mul(POINT, k, P, 5); },
    /* cofactor 4: [L]P == O, commons/edwards.js's one copy of the check */
    in_subgroup: /* @__PURE__ */ subgroup_check(POINT, CURVE.L),
    /* the empty-DST refusal is make_group's */
    hash: function (msg, dst) { return ed448_h2c.hash_to_curve(msg, dst); }
});
