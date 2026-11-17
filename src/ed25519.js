/**
 * Ed25519  -  RFC 8032
 *
 * Bernstein, Duif, Lange, Schwabe and Yang, 2011. The signature scheme that
 * displaced ECDSA nearly everywhere it was not already mandated: SSH keys,
 * signify, Signal, Tor, DNSSEC, Git, WireGuard's handshake identities, and
 * most blockchains designed after 2015.
 *
 * The curve is birationally equivalent to Curve25519, so Ed25519 and X25519
 * share a field and can share a key - although sharing one is a bad idea and
 * this library keeps them apart.
 *
 * WHAT IT DOES BETTER THAN ECDSA, concretely:
 *   - No random nonce. The nonce is a hash of the key and the message, and
 *     was designed in rather than retrofitted through RFC 6979.
 *   - No inversion when signing.
 *   - Every 32-byte string is a valid private key.
 *   - Complete addition formulas, so no exceptional cases to branch on.
 *   - Faster, on both signing and verification.
 *
 * The private key is a SEED. The actual scalar comes from hashing it, which
 * is why a key can be stored as 32 bytes of anything at all.
 */

import { make_group } from './commons/group.js';
import { subgroup_check } from './commons/edwards.js';
import { wnaf_mul } from './commons/fixed_window.js';
import { eddsa } from './commons/eddsa.js';
import { ascii } from './commons/bytes.js';
import { sha512 } from './sha2.js';
import { field } from './commons/modp.js';

/* "SigEd25519 no Ed25519 collisions" - the domain string of RFC 8032 */
var SIGED25519 = /* @__PURE__ */ ascii('SigEd25519 no Ed25519 collisions');

var P = (1n << 255n) - 19n;
var Fp = field(P);

/* d = -121665/121666 */
var D = Fp.mul(Fp.neg(121665n), Fp.inv(121666n));

export var CURVE = {
    name: 'ed25519',
    /* scalars are little-endian on this curve - see commons/group.js */
    little_endian: true,
    scalar_bytes_length: 32,
    p: P,
    a: Fp.neg(1n),
    d: D,
    /* the prime order of the base point; the curve order is 8L */
    L: (1n << 252n) + 27742317777372353535851937790883648493n,
    cofactor: 8n,
    Gx: 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an,
    Gy: Fp.mul(4n, Fp.inv(5n)),
    hash: sha512,
    bytes: 32,
    sqrt_mode: 8,
    scalar_bits: 256,
    /*
     * Pure Ed25519 carries NO domain prefix - it predates the context
     * variants and adding one would have invalidated every signature already
     * in the world. Ed25519ctx and Ed25519ph do use the prefix below.
     */
    pure_uses_dom: false,
    dom_prefix: SIGED25519,
    prehash: sha512,
    /**
     * Clamping, RFC 8032 section 5.1.5.
     *
     * The low three bits are cleared so the scalar is a multiple of the
     * cofactor 8 - that is what makes small-subgroup attacks inert. Bit 254
     * is set and bit 255 cleared so every scalar has exactly the same length,
     * which stops a variable-time ladder from leaking it.
     */
    clamp: function (s) {
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
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
/* keygen(seed) -> { sk: the 32-byte seed (a copy), pk }; seed omitted or null: a fresh one */
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

/**
 * Ed25519ctx - RFC 8032 section 5.1.
 *
 * Binds a context string into the signature, so a signature made for one
 * purpose cannot be replayed in another. The context must match byte for byte
 * on both sides and may be 1 to 255 bytes; an empty context is NOT the same
 * as pure Ed25519, because the domain prefix is present either way.
 */
export function sign_ctx(msg, seed, ctx)   { return E.sign_variant(msg, seed, ctx, 1); }
export function verify_ctx(msg, sig, pk, ctx, mode) { return E.verify_variant(msg, sig, pk, ctx, 1, mode); }

/**
 * Ed25519ph - the prehashed variant.
 *
 * The message is reduced to SHA-512 before signing, so a signer that cannot
 * hold the whole message in memory - or that receives it as a stream - can
 * still sign it. The cost is that the security argument now rests on the
 * hash's collision resistance, which pure Ed25519 does not need.
 *
 * Note this takes the RAW message and hashes it internally, matching RFC
 * 8032's definition. Passing an already-hashed value would sign the wrong
 * thing.
 */
export function sign_ph(msg, seed, ctx)    { return E.sign_variant(msg, seed, ctx, 2); }
export function verify_ph(msg, sig, pk, ctx, mode) { return E.verify_variant(msg, sig, pk, ctx, 2, mode); }
/*
 * RFC 8032's seed expansion - {scalar, prefix} - for ecvrf.js and key_blind.js,
 * which need the same derivation and used to re-implement it.
 */
export var expand_seed    = E.expand;
/* RFC 8032 signing from {scalar, prefix} - for key_blind.js's blinded keys */
export var sign_expanded  = E.sign_expanded;
export var encode_point   = E.encode_point;
export var decode_point   = E.decode_point;
export var POINT          = E.POINT;
export var FIELD          = E.FIELD;
export var B              = E.B;


/* ---------------- hash to curve, RFC 9380 ---------------- */
/**
 * edwards25519_XMD:SHA-512_ELL2_RO_
 *
 * Edwards curves need a different map again. Simplified SWU wants a short
 * Weierstrass form; Ed25519 is a twisted Edwards curve, and converting to
 * Weierstrass and back would be slow and would lose the completeness that
 * makes Edwards pleasant.
 *
 * The route the RFC takes: Ed25519 is birationally equivalent to the
 * MONTGOMERY curve Curve25519, and Montgomery curves admit ELLIGATOR 2 - a
 * map that is simpler than SSWU and needs no isogeny. So the message is
 * mapped onto Curve25519 by Elligator, then carried to Ed25519 by the
 * rational map. The same equivalence is why X25519 and Ed25519 exist as a
 * pair at all.
 *
 * THE COFACTOR MUST BE CLEARED. Ed25519's group has order 8L, and Elligator
 * can land on a point of small order. Multiplying by 8 forces the result
 * into the prime-order subgroup - without it, a hashed point can carry a
 * small-order component and break the security argument that motivated
 * hashing to a curve in the first place.
 */

import { h2c_suite, expand_message_xmd, sgn0, map_to_curve_elligator2 } from './commons/h2c.js';

var _F = FIELD;
var _P = CURVE.p;

/* Curve25519's coefficient, and Elligator's non-square Z = 2 */
var MONT_A = 486662n;
var ELL_Z = 2n;

/*
 * sqrt(-486664), the constant of the rational map from Montgomery to Edwards.
 *
 * ⚠ THE ROOT WITH sgn0 = 0 - RFC 9380 G.2.2's c1, "sgn0(c1) MUST equal 0".
 *   It used to take the other root and pair it with a y-sign rule that was
 *   also the other one, so the point came out right - x = c1 * s / t, and
 *   both signs flipped. With the shared map in commons/h2c.js following step 19
 *   literally, the constant follows the RFC as well.
 */
var SQRT_M486664 = /* @__PURE__ */ (function () {
    var v = _F.sqrt(_F.neg(486664n));
    return sgn0(v) === 0 ? v : _F.neg(v);
}());

/**
 * Elligator 2 onto Curve25519 - commons/h2c.js - then the rational map onto
 * Ed25519.
 *
 * The Montgomery point (s, t) becomes the Edwards point
 * (sqrt(-486664)*s/t, (s-1)/(s+1)), with both denominators handled by the
 * zero-mapping inverse so the exceptional inputs land on the identity rather
 * than failing.
 */
function map_elligator2_edwards(u) {
    var F = _F, m = F.mul, ad = F.add, s = F.sub;

    var mp = map_to_curve_elligator2(F, MONT_A, ELL_Z, u);
    var xm = mp.s, ym = mp.t;

    /* the rational map Montgomery -> twisted Edwards */
    var xn = m(SQRT_M486664, xm);
    var xd = ym === 0n ? 0n : F.inv(ym);
    var ex = m(xn, xd);
    var dn = ad(xm, 1n);
    var ey = dn === 0n ? 1n : m(s(xm, 1n), F.inv(dn));

    return { x: ex, y: ey };
}

export var ed25519_h2c = /* @__PURE__ */ h2c_suite({
    F: _F, C: POINT, p: _P, L: 48, cofactor: 8n,
    order_bits: 256,
    expand: function (msg, dst, len) { return expand_message_xmd(msg, dst, len, sha512); },
    map: map_elligator2_edwards
});


/* =========================================================================
 * The prime-order group interface - see commons/group.js
 *
 * THIS IS THE ONE THAT NEEDS THE EXTRA MULTIPLICATION.
 *
 * edwards25519 has cofactor 8, so `decode_point` accepting a point says only
 * that it is on the curve - a point of order 8 passes every check RFC 8032
 * asks for. That is correct for verifying a signature, where the verification
 * equation tolerates it, and wrong for anything treating the point as a group
 * element: in FROST such a point steers the group commitment in exactly the
 * way the binding factor exists to prevent.
 *
 * `decode_point` itself is left alone. Ed25519 verifies far more signatures
 * than it does group operations, and charging every one of them a scalar
 * multiplication to protect a different caller would be the wrong trade. The
 * cost goes here, where it is needed.
 *
 * mul_unsafe rather than the ladder: the scalar is L, a public constant, so
 * there is nothing to hide and the variable-time routine is roughly twice as
 * fast.
 * ======================================================================= */

export var GROUP = /* @__PURE__ */ make_group({
    name: 'ed25519',
    /* scalars are little-endian on this curve - see commons/group.js */
    little_endian: true,
    scalar_bytes_length: 32,
    ORDER: CURVE.L,
    bits: CURVE.scalar_bits,
    IDENTITY: POINT.ZERO,
    GENERATOR: B,
    encoded_length: 32,
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
    /* cofactor 8: [L]P == O, commons/edwards.js's one copy of the check */
    in_subgroup: /* @__PURE__ */ subgroup_check(POINT, CURVE.L),
    /* the empty-DST refusal is make_group's */
    hash: function (msg, dst) { return ed25519_h2c.hash_to_curve(msg, dst); }
});


/* =========================================================================
 * Edwards <-> X25519 (RFC 7748 section 4.1): u = (1 + y) / (1 - y)
 *
 * ⭐ FOR A KEY THAT IS NOT A SEED. A threshold key on edwards25519 is a bare
 *   scalar s with public key s*B; the X25519 public key of the same s is the
 *   u-coordinate of s*B, and X25519(e, u) = clamp(e) * (s*B) = s * (clamp(e)*B)
 *   - so the holders of s answer any X25519 sender with s times the sender's
 *   point, never needing s itself to be clamped. These two maps are the
 *   bridge; the scalar multiplication stays the group's.
 * ======================================================================= */

function le_to_bigint(b) {
    var v = 0n;
    for (var i = b.length - 1; i >= 0; i--) { v = (v << 8n) | BigInt(b[i]); }
    return v;
}
function bigint_to_le(v, n) {
    var out = new Uint8Array(n);
    for (var i = 0; i < n; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
}

/**
 * The X25519 public key (u-coordinate, 32 bytes little-endian) of an encoded
 * Edwards point.
 *
 * @param {Uint8Array} point  32 bytes, an encoded edwards25519 point
 * @return {Uint8Array}
 */
export function to_x25519(point) {
    if (!(point instanceof Uint8Array) || point.length !== 32) { throw new Error('ed25519: a point is 32 bytes'); }
    var yb = new Uint8Array(point); yb[31] &= 0x7f;
    var y = le_to_bigint(yb);
    if (y >= _P) { throw new Error('ed25519: non-canonical y'); }
    var den = _F.sub(1n, y);
    if (den === 0n) { throw new Error('ed25519: the identity has no X25519 public key'); }
    return bigint_to_le(_F.mul(_F.add(1n, y), _F.inv(den)), 32);
}

/**
 * The Edwards point (encoded, x chosen even) whose X25519 u-coordinate is
 * `u` - or null if there is none (u = -1). Either sign of x gives the same u
 * after any scalar multiplication, so the choice costs nothing. The result is
 * NOT checked for the prime-order subgroup: decode it through GROUP.decode,
 * which is.
 *
 * @param {Uint8Array} u  32 bytes, little-endian; the top bit is masked (RFC 7748)
 * @return {Uint8Array|null}
 */
export function from_x25519(u) {
    if (!(u instanceof Uint8Array) || u.length !== 32) { throw new Error('ed25519: an X25519 key is 32 bytes'); }
    var ub = new Uint8Array(u); ub[31] &= 0x7f;
    var v = le_to_bigint(ub) % _P;
    var den = _F.add(v, 1n);
    if (den === 0n) { return null; }
    var y = _F.mul(_F.sub(v, 1n), _F.inv(den));
    return bigint_to_le(y, 32);
}
