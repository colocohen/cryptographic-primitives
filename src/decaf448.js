/**
 * decaf448  -  RFC 9496 section 5
 *
 * The prime-order group over Ed448, as ristretto255 is over Ed25519.
 *
 * Ed448's group has 4h points for prime h. decaf448 makes points that differ
 * by a point of order dividing 4 THE SAME ELEMENT, and gives each element
 * exactly one 56-byte encoding. The result is a clean prime-order group: no
 * cofactor to clear, no subgroup test, every non-identity element a
 * generator, and two byte strings equal exactly when the elements are.
 *
 * The internal representation is an edwards448 point (ed448.js's POINT), so
 * addition, negation and scalar multiplication are Ed448's own; only decode,
 * encode, equality and element derivation are decaf448's.
 *
 * IT IS NOT Ed448 and it is not X448: a decaf448 encoding is neither an Ed448
 * public key nor a curve448 u-coordinate.
 *
 * USED BY: CPace (CPACE-DECAF448-SHAKE256), OPRF (RFC 9497 decaf448-SHAKE256),
 * and the protocols that need a prime-order group at the 224-bit level.
 */

import { make_group, group_keygen } from './commons/group.js';
import { expand_message_xof } from './commons/h2c.js';
import { fixed_base, wnaf_mul } from './commons/fixed_window.js';
import { bytes_to_bigint_le, bigint_to_bytes_le } from './commons/bytes.js';
import { mod } from './commons/primes.js';
import { FIELD, POINT, CURVE } from './ed448.js';
import { shake256 } from './sha3.js';

var F = FIELD;
var P = CURVE.p;

/*
 * The constants of RFC 9496 section 5.1, derived from the curve rather than
 * transcribed; the test suite checks each against the decimal in the RFC.
 * D is Ed448's d = -39081.
 */
var D = CURVE.d;
var ONE_MINUS_D = /* @__PURE__ */ F.sub(1n, D);
var ONE_MINUS_TWO_D = /* @__PURE__ */ F.sub(1n, F.add(D, D));
/*
 * A square root has two values; the RFC names the NONNEGATIVE one (low bit
 * clear), and INVSQRT_MINUS_D is the inverse of that same root.
 */
var SQRT_MINUS_D = /* @__PURE__ */ ct_abs(F.sqrt(F.neg(D)));
var INVSQRT_MINUS_D = /* @__PURE__ */ F.inv(SQRT_MINUS_D);

/* field elements are 56 bytes, little-endian */
function fe_bytes(x) { return bigint_to_bytes_le(x, 56); }

/** "Negative" means the low bit of the canonical value is set. */
function is_negative(x) { return (x & 1n) === 1n; }

function ct_abs(x) { return is_negative(x) ? F.neg(x) : x; }

/**
 * SQRT_RATIO_M1(u, v) - section 5.2. p = 3 mod 4, so the candidate is one
 * exponentiation, and when u/v is not a square it is sqrt(-u/v) - a defined
 * value that the derivation function below relies on.
 *
 * @return {{square: boolean, r: bigint}}
 */
function sqrt_ratio_m1(u, v) {
    var r = F.mul(u, F.pow(F.mul(u, v), (P - 3n) / 4n));
    var square = F.mul(v, F.sqr(r)) === u;
    return { square: square, r: ct_abs(r) };
}

/* ---------------- the group ---------------- */

/** The generator: 2*B for Ed448's base point B (section 5). */
export var BASE = /* @__PURE__ */ (function () {
    var B = POINT.of(CURVE.Gx, CURVE.Gy);
    return POINT.add(B, B);
}());

/** The identity. */
export var IDENTITY = POINT.ZERO;

/**
 * Decode 56 bytes into a group element - section 5.3.1.
 *
 * REJECTS a value at or above p and a negative s, so there is exactly one
 * byte string per element; unlike RFC 7748, nothing is reduced or masked.
 *
 * @return {object|null} null when the encoding is invalid
 */
export function decode(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 56) { return null; }
    var s = bytes_to_bigint_le(bytes);
    if (s >= P || is_negative(s)) { return null; }

    var ss = F.sqr(s);
    var u1 = F.add(1n, ss);
    var u1_sq = F.sqr(u1);
    var u2 = F.sub(u1_sq, F.mul(F.mul(4n, D), ss));
    var sr = sqrt_ratio_m1(1n, F.mul(u2, u1_sq));
    if (!sr.square) { return null; }
    var invsqrt = sr.r;
    var u3 = ct_abs(F.mul(F.mul(F.mul(F.mul(2n, s), invsqrt), u1), SQRT_MINUS_D));
    var x = F.mul(F.mul(F.mul(u3, invsqrt), u2), INVSQRT_MINUS_D);
    var y = F.mul(F.mul(F.sub(1n, ss), invsqrt), u1);
    return { X: x, Y: y, Z: 1n, T: F.mul(x, y) };
}

/**
 * Encode a group element as 56 bytes - section 5.3.2. Every internal
 * representation of one element encodes identically.
 */
export function encode(pt) {
    var x0 = pt.X, z0 = pt.Z, t0 = pt.T;
    var u1 = F.mul(F.add(x0, t0), F.sub(x0, t0));
    var invsqrt = sqrt_ratio_m1(1n, F.mul(F.mul(u1, ONE_MINUS_D), F.sqr(x0))).r;
    var ratio = ct_abs(F.mul(F.mul(invsqrt, u1), SQRT_MINUS_D));
    var u2 = F.sub(F.mul(F.mul(INVSQRT_MINUS_D, ratio), z0), t0);
    var s = ct_abs(F.mul(F.mul(F.mul(ONE_MINUS_D, invsqrt), x0), u2));
    return fe_bytes(s);
}

/**
 * Equality - section 5.3.3. Internal representations of one element differ
 * as coordinates, so comparing them directly would be wrong; this is the
 * RFC's cross-multiplied test.
 */
export function equals(p1, p2) {
    return F.mul(p1.X, p2.Y) === F.mul(p1.Y, p2.X);
}

export function add(p1, p2) { return POINT.add(p1, p2); }
export function neg(p) { return POINT.neg(p); }
export function sub(p1, p2) { return POINT.add(p1, POINT.neg(p2)); }

/* the order has 446 bits */
var BITS = 446;

/** Scalar multiplication, constant time. No clamping: there is no cofactor. */
export function mul(k, p) { return POINT.mul(k, p, BITS); }

/**
 * VARIABLE-TIME scalar multiplication, for PUBLIC scalars only - signature
 * and proof verification. A secret scalar goes through `mul`.
 */
export function mul_vartime(k, p) { return wnaf_mul(POINT, k, p, 5); }

/* k*BASE through a table built once at load */
var BASE_TABLE = /* @__PURE__ */ fixed_base(POINT, BASE, BITS, 4);

export function base_mul(k) { return BASE_TABLE(k); }

/* ---------------- derivation from bytes ---------------- */

/** The MAP of section 5.3.4, on one 56-byte half; non-canonical input is reduced. */
function map(bytes) {
    var t = mod(bytes_to_bigint_le(bytes), P);
    var r = F.neg(F.sqr(t));
    var u0 = F.mul(D, F.sub(r, 1n));
    var u1 = F.mul(F.add(u0, 1n), F.sub(u0, r));
    var sr = sqrt_ratio_m1(ONE_MINUS_TWO_D, F.mul(F.add(r, 1n), u1));
    var v_prime = sr.square ? sr.r : F.mul(t, sr.r);
    var sgn = sr.square ? 1n : F.neg(1n);
    var s = F.mul(v_prime, F.add(r, 1n));
    var s2 = F.sqr(s);
    var w0 = F.mul(2n, ct_abs(s));
    var w1 = F.add(s2, 1n);
    var w2 = F.sub(s2, 1n);
    var w3 = F.add(F.mul(F.mul(F.mul(v_prime, s), F.sub(r, 1n)), ONE_MINUS_TWO_D), sgn);
    return { X: F.mul(w0, w3), Y: F.mul(w2, w1), Z: F.mul(w1, w3), T: F.mul(w0, w2) };
}

/**
 * Map 112 uniform bytes to a group element - the element derivation
 * function. Two MAPs added, because one alone is not quite uniform.
 */
export function from_uniform_bytes(b) {
    if (!(b instanceof Uint8Array) || b.length !== 112) { throw new Error('decaf448: need 112 bytes'); }
    return POINT.add(map(b.subarray(0, 56)), map(b.subarray(56)));
}

/**
 * Map bytes to a group element: expand_message_xof with SHAKE256 to 112
 * bytes, then element derivation - decaf448_XOF:SHAKE256_D448MAP_RO_ (RFC 9380
 * appendix B), which is RFC 9497's HashToGroup for decaf448-SHAKE256.
 *
 * @param {Uint8Array} msg
 * @param {Uint8Array} dst  non-empty domain separator
 */
export function hash_to_group(msg, dst) {
    if (!dst || dst.length === 0) {
        throw new Error('decaf448: hash needs a non-empty domain separator');
    }
    return from_uniform_bytes(expand_message_xof(msg, dst, 112, shake256));
}

/* ---------------- the scalar field ---------------- */

/** The group order l, the same as Ed448's prime subgroup. */
export var ORDER = CURVE.L;

/** Scalars are 56 bytes little-endian (section 5.4). */
export function scalar_bytes(k) { return bigint_to_bytes_le(mod(k, ORDER), 56); }

/** A scalar arriving on the wire: 56 bytes, below the order - or null. */
export function scalar_from_canonical_bytes(b) {
    if (!(b instanceof Uint8Array) || b.length !== 56) { return null; }
    var v = bytes_to_bigint_le(b);
    return v < ORDER ? v : null;
}

/** The prime-order group interface - see commons/group.js. */
export var GROUP = /* @__PURE__ */ make_group({
    name: 'decaf448',
    little_endian: true,
    scalar_bytes_length: 56,
    ORDER: ORDER,
    bits: BITS,
    IDENTITY: IDENTITY,
    GENERATOR: BASE,
    encoded_length: 56,
    add: add,
    neg: neg,
    equals: equals,
    mul_raw: function (k, p) { return mul(k, p); },
    base_mul: base_mul,
    mul_vartime: mul_vartime,
    encode_raw: encode,
    decode_raw: decode,
    hash: hash_to_group
    /* no in_subgroup: the encoding is canonical and there is no cofactor */
});

/* the derived constants, for the test suite to check against section 5.1 */
export var CONSTANTS = { D: D, ONE_MINUS_D: ONE_MINUS_D, ONE_MINUS_TWO_D: ONE_MINUS_TWO_D,
                         SQRT_MINUS_D: SQRT_MINUS_D, INVSQRT_MINUS_D: INVSQRT_MINUS_D };

/**
 * A key pair: { sk: the secret scalar's 56 little-endian bytes (as
 * scalar_bytes writes it), pk: the encoded point sk·BASE }.
 *
 * @param {Uint8Array} [seed]  the secret scalar's bytes - canonical and
 *   nonzero, or refused; omitted or null draws a fresh one from the
 *   platform, uniform in [1, ORDER) - commons/group.js group_keygen
 */
export function keygen(seed) { return group_keygen(GROUP, seed); }
