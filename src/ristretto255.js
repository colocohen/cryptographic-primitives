/**
 * ristretto255  -  RFC 9496
 *
 * A PRIME-ORDER GROUP built on top of Curve25519, and the answer to a problem
 * this library documents in three separate places.
 *
 * THE PROBLEM. Curve25519's group has 8h points for prime h - a COFACTOR of
 * eight. That means there are points of small order, and it has consequences
 * that keep surfacing:
 *
 *   - Ed25519 signatures are MALLEABLE: adding a small-order point to a
 *     public key or a signature component can produce another valid
 *     signature. Implementations disagree about which of those to accept,
 *     which is a consensus split waiting to happen.
 *   - X25519 has to CLAMP the private key - clearing the low three bits - to
 *     force the scalar into the prime-order subgroup. That clamping then
 *     interacts badly with any protocol that needs to do arithmetic on the
 *     scalar afterwards.
 *   - Protocols that need "every element is a generator" - which is most
 *     protocols with a security proof - do not get it.
 *
 * THE FIX. Ristretto is a quotient construction: it defines an equivalence
 * relation where points differing by a small-order point are THE SAME
 * ELEMENT, and an encoding under which each equivalence class has exactly one
 * representative. The result behaves as a clean prime-order group with
 * 32-byte encodings, built entirely out of existing Curve25519 arithmetic.
 *
 * WHAT YOU GET:
 *
 *   - No cofactor. Every non-identity element generates the whole group.
 *   - CANONICAL ENCODING. Two byte strings are equal if and only if the
 *     elements are. That is what makes ristretto elements safe as map keys,
 *     as identifiers, and in equality checks - and it is exactly what raw
 *     Edwards points are not.
 *   - Non-canonical inputs are REJECTED rather than accepted and normalised,
 *     so an attacker cannot present the same element two ways.
 *
 * WHAT IT IS NOT. Ristretto elements are not Curve25519 points and do not
 * interoperate with X25519 or Ed25519 keys. It is a different group that
 * happens to be implemented with the same field arithmetic.
 *
 * USED BY: OPRF and VOPRF (RFC 9497), OPAQUE, Signal's private group system,
 * Zcash's note commitments, and most new protocol work that needs a
 * prime-order group over a 25519-family curve.
 */

import { make_group, group_keygen } from './commons/group.js';
import { sqrt_ratio_candidate } from './commons/edwards.js';
import { FIELD, POINT, CURVE } from './ed25519.js';
import { sha512 } from './sha2.js';
import { bytes_to_bigint_le, bigint_to_bytes_le, concat, be16 } from './commons/bytes.js';
import { fixed_base, wnaf_mul, double_mul, double_mul_base, base_table } from './commons/fixed_window.js';
import { inv_prime, batch_invert } from './commons/modp.js';
import { mod } from './commons/primes.js';

var F = FIELD;
var P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn;

/*
 * The constants of RFC 9496 section 4.1. Every one is DERIVED below from the
 * curve parameters rather than transcribed, and the derivations are checked
 * against the decimal values in the RFC by the test suite.
 */
var D = CURVE.d;
/*
 * ⭐ THE FIELD'S OWN sqrt(-1), through its named method - the same constant
 *   commons/edwards.js reads. This was the third copy, computed here as
 *   2^((p-1)/4) independently of modp's cache; edwards.js's note on why two
 *   caches of one constant is a hazard applies equally to three.
 */
var SQRT_M1 = /* @__PURE__ */ F.sqrt_of_neg_one();
var SQRT_AD_MINUS_ONE = /* @__PURE__ */ (function () {
    /*
     * a = -1 for this curve, so a*d - 1 = -d - 1.
     *
     * A square root has two values and the field's sqrt returns whichever
     * the exponentiation lands on; the RFC names a specific one. The
     * NEGATIVE root is the one wanted here - checked against the decimal in
     * section 4.1 by the test suite, because getting it wrong produces a
     * derivation function that runs, returns group elements, and agrees
     * with nobody.
     */
    var r = F.sqrt(F.sub(F.mul(F.neg(1n), D), 1n));
    return (r % 2n === 1n) ? r : F.neg(r);
}());
var INVSQRT_A_MINUS_D = /* @__PURE__ */ F.inv(F.sqrt(F.sub(F.neg(1n), D)));
var ONE_MINUS_D_SQ = /* @__PURE__ */ F.sub(1n, F.sqr(D));
var D_MINUS_ONE_SQ = /* @__PURE__ */ F.sqr(F.sub(D, 1n));

/* the 25519 family encodes field elements little-endian */
var fe_bytes = function (x) { return bigint_to_bytes_le(x, 32); };
var fe_from = bytes_to_bigint_le;

/**
 * "Negative" means the low bit of the canonical encoding is set.
 *
 * A field element has two square roots; this is what picks one of them
 * deterministically, and it is the same convention Ed25519 uses for the sign
 * of x.
 */
function is_negative(x) { return (F.to_positive ? F.to_positive(x) : x) % 2n === 1n; }

function ct_abs(x) { return is_negative(x) ? F.neg(x) : x; }

/**
 * SQRT_RATIO_M1(u, v) - section 4.2.
 *
 * Returns the square root of u/v when it exists, and the square root of
 * SQRT_M1*(u/v) when it does not. THE NON-SQUARE BRANCH IS NOT AN ERROR PATH:
 * the derivation function below relies on getting a defined value there, which
 * is what lets it map any field element to a group element without rejection
 * and therefore without a timing signal.
 *
 * @return {{square: boolean, r: bigint}}
 */
function sqrt_ratio_m1(u, v) {
    /* the candidate is commons/edwards.js's; only the classification below
       is ristretto's own */
    var r = sqrt_ratio_candidate(F, u, v);
    var check = F.mul(v, F.sqr(r));

    var uu = u;
    var neg_u = F.neg(u);
    var neg_u_i = F.mul(neg_u, SQRT_M1);

    var correct = check === uu;
    var flipped = check === neg_u;
    var flipped_i = check === neg_u_i;

    if (flipped || flipped_i) { r = F.mul(r, SQRT_M1); }
    r = ct_abs(r);

    return { square: correct || flipped, r: r };
}

/* ---------------- the group ---------------- */

/** The generator: the ristretto element corresponding to Ed25519's base point. */
export var BASE = POINT.of(CURVE.Gx, CURVE.Gy);

/** The identity. */
export var IDENTITY = POINT.ZERO;

/**
 * Decode 32 bytes into a group element.
 *
 * REJECTS non-canonical encodings, which is the whole point. Unlike RFC 7748's
 * field decoding the top bit is NOT masked, and a value at or above p fails
 * rather than being reduced - so there is exactly one byte string per element.
 *
 * @return {object|null} null when the encoding is invalid
 */
export function decode(bytes) {
    if (bytes.length !== 32) { return null; }
    var s = fe_from(bytes);
    /*
     * ⛔ s ≥ p MUST BE REFUSED FIRST. The re-encode check below compared the
     *    UNREDUCED s with itself and so passed for p+3, p+9, … and for the top
     *    bit — two byte strings per element, which breaks every transcript or
     *    dedup that compares encodings (RFC 9496 §4.3.1).
     */
    if (s >= P) { return null; }
    /* canonical check: re-encoding must give back the same bytes */
    var re = fe_bytes(s);
    for (var i = 0; i < 32; i++) { if (re[i] !== bytes[i]) { return null; } }
    if (is_negative(s)) { return null; }

    var ss = F.sqr(s);
    var u1 = F.sub(1n, ss);
    var u2 = F.add(1n, ss);
    var u2_sqr = F.sqr(u2);

    var v = F.sub(F.neg(F.mul(D, F.sqr(u1))), u2_sqr);
    var sr = sqrt_ratio_m1(1n, F.mul(v, u2_sqr));

    var den_x = F.mul(sr.r, u2);
    var den_y = F.mul(F.mul(sr.r, den_x), v);

    var x = ct_abs(F.mul(F.mul(2n, s), den_x));
    var y = F.mul(u1, den_y);
    var t = F.mul(x, y);

    if (!sr.square || is_negative(t) || y === 0n) { return null; }
    return { X: x, Y: y, Z: 1n, T: t };
}

/**
 * Encode a group element as 32 bytes.
 *
 * The "rotation" below is what collapses the equivalence class: four of the
 * eight points that represent the same ristretto element differ by a
 * multiplication that this undoes, so any representative encodes identically.
 */
export function encode(pt) {
    var x0 = pt.X, y0 = pt.Y, z0 = pt.Z, t0 = pt.T;

    var u1 = F.mul(F.add(z0, y0), F.sub(z0, y0));
    var u2 = F.mul(x0, y0);
    var sr = sqrt_ratio_m1(1n, F.mul(u1, F.sqr(u2)));

    var den1 = F.mul(sr.r, u1);
    var den2 = F.mul(sr.r, u2);
    var z_inv = F.mul(F.mul(den1, den2), t0);

    var ix0 = F.mul(x0, SQRT_M1);
    var iy0 = F.mul(y0, SQRT_M1);
    var enchanted = F.mul(den1, INVSQRT_A_MINUS_D);

    var rotate = is_negative(F.mul(t0, z_inv));

    var x = rotate ? iy0 : x0;
    var y = rotate ? ix0 : y0;
    var den_inv = rotate ? enchanted : den2;

    if (is_negative(F.mul(x, z_inv))) { y = F.neg(y); }

    var s = ct_abs(F.mul(den_inv, F.sub(z0, y)));
    return fe_bytes(s);
}

/**
 * Equality.
 *
 * Two internal representations of the same element are NOT equal as
 * coordinates, so comparing X and Y directly is wrong - which is exactly the
 * bug ristretto exists to prevent. This is the cross-multiplied test from the
 * RFC; comparing the encodings works too and is what most callers should do.
 */
export function equals(p1, p2) {
    var a = F.mul(p1.X, p2.Y) === F.mul(p1.Y, p2.X);
    var b = F.mul(p1.Y, p2.Y) === F.mul(p1.X, p2.X);
    return a || b;
}

export function add(p1, p2) { return POINT.add(p1, p2); }
export function neg(p) { return POINT.neg(p); }
export function sub(p1, p2) { return POINT.add(p1, POINT.neg(p2)); }

/** Scalar multiplication. The scalar needs no clamping - there is no cofactor. */
export function mul(k, p) { return POINT.mul(k, p, 253); }

/**
 * Scalar multiplication in VARIABLE time, through a width-5 wNAF.
 *
 * ⛔ THE NAME IS THE WARNING. Its addition pattern depends on the scalar's
 *   bits, so a scalar that must stay secret must go through `mul` above -
 *   the two return identical points and differ only in timing, which means a
 *   wrong choice gives correct answers and a side channel no test finds.
 *
 * ⭐ MEASURED ON THIS CURVE: 0.70 ms against 1.57 for the constant-time
 *   ladder, and 0.90 for the naive double-and-add that was the only
 *   variable-time path before.
 *
 * ⚠ WHERE IT IS SAFE: signature VERIFICATION, where every scalar is either
 *   published in the signature or derived by hashing published values. It is
 *   not safe in signing, in share generation, or anywhere a Lagrange
 *   coefficient could reveal which participants took part.
 */
export function mul_vartime(k, p) { return wnaf_mul(POINT, k, p, 5); }

/**
 * a*P + b*Q in one interleaved wNAF walk, for PUBLIC scalars.
 *
 * ⭐ ALMOST EVERY VERIFICATION EQUATION HAS THIS SHAPE - z*G + (n-c)*X for a
 *   Schnorr check, and the same for FROST, OPRF and each ring link. Done as
 *   two separate multiplications the doublings are performed twice; one walk
 *   shares them, which is where the factor of about two comes from. The
 *   generic routine already existed in fixed_window.js and this curve simply
 *   never exposed a wrapper for it.
 *
 * ⛔ BOTH SCALARS MUST BE PUBLIC, exactly as for mul_vartime - see there.
 */
export function double_mul_vartime(a, P, b, Q, w) {
    /* ⭐ the base point has a kept table (BASE_VTABLE): no table to build for it, and a wider window */
    if (P === BASE) { return double_mul_base(POINT, a, BASE_VTABLE, b, Q, w || 5); }
    if (Q === BASE) { return double_mul_base(POINT, b, BASE_VTABLE, a, P, w || 5); }
    return double_mul(POINT, a, P, b, Q, w || 5);
}
/* the base point's verification table: odd multiples at w = 8, cached form, built on first use */
var BASE_VTABLE = base_table(POINT, BASE, 8);

/**
 * k * BASE, through a PRECOMPUTED TABLE.
 *
 * ⭐ THE BASE POINT NEVER CHANGES, so its multiples can be computed once.
 *   fixed_base builds a windowed table and every later call is lookups and
 *   additions instead of 253 doublings.
 *
 * ⛔ THIS WAS `POINT.mul(k, BASE, 253)` - the generic variable-base routine,
 *   which throws away the one fact that makes base multiplication cheap.
 *   Measured before: base_mul 1.80 ms against a generic mul of 1.71 - the
 *   ratio was 0.95, when a working table gives 1.5 to 2.
 *
 *   commons/ecdsa.js already did this for the NIST curves; ristretto255 did
 *   not, and everything built on it - FROST, OPRF, VRF, bulletproofs - paid
 *   for it on every signature and every commitment.
 *
 * ⚠ THE TABLE IS BUILT ONCE AT MODULE LOAD, not per call. Building it per
 *   call would be slower than not having it, and that mistake looks
 *   identical from the outside: same answers, worse timing.
 */
var BASE_TABLE = /* @__PURE__ */ fixed_base(POINT, BASE, 253, 4);

export function base_mul(k) { return BASE_TABLE(k); }

/* ---------------- derivation from bytes ---------------- */

/** The MAP of section 4.3.4, one 32-byte half. */
function map(bytes) {
    var t = fe_from(bytes) % (1n << 255n);   /* mask the top bit */
    t = mod(t, P);

    var r = F.mul(SQRT_M1, F.sqr(t));
    var u = F.mul(F.add(r, 1n), ONE_MINUS_D_SQ);
    var v = F.mul(F.sub(F.neg(1n), F.mul(r, D)), F.add(r, D));

    var sr = sqrt_ratio_m1(u, v);
    var s = sr.r;
    var s_prime = F.neg(ct_abs(F.mul(s, t)));
    if (!sr.square) { s = s_prime; }
    var c = sr.square ? F.neg(1n) : r;

    var N = F.sub(F.mul(F.mul(c, F.sub(r, 1n)), D_MINUS_ONE_SQ), v);

    var w0 = F.mul(F.mul(2n, s), v);
    var w1 = F.mul(N, SQRT_AD_MINUS_ONE);
    var w2 = F.sub(1n, F.sqr(s));
    var w3 = F.add(1n, F.sqr(s));

    return { X: F.mul(w0, w3), Y: F.mul(w2, w1), Z: F.mul(w1, w3), T: F.mul(w0, w2) };
}

/**
 * Map 64 uniform bytes to a group element.
 *
 * THE OUTPUT IS UNIFORM OVER THE GROUP and reveals nothing about a discrete
 * log, which is what protocols need when they hash to a group element -
 * OPRFs, VRFs, Pedersen commitment bases. Sixty-four bytes rather than
 * thirty-two because one MAP call is not quite uniform; two added together
 * are.
 */
export function from_uniform_bytes(b) {
    if (b.length !== 64) { throw new Error('ristretto255: need 64 bytes'); }
    return POINT.add(map(b.subarray(0, 32)), map(b.subarray(32)));
}

/**
 * Map bytes to a group element, deterministically.
 *
 * With no known discrete log relative to the base point, which is the whole
 * requirement: a generator produced this way cannot be used to open a
 * commitment two ways, because nobody knows how it relates to the others.
 *
 * `dst` IS A DOMAIN SEPARATOR, and it used to be silently ignored.
 *
 * The signature took one argument. A caller passing a second got no error and
 * no separation - two applications hashing the same message received the same
 * point, which is precisely what a domain separator exists to prevent. Every
 * caller in this library had worked around it by prefixing a tag onto `msg`
 * themselves, which works and is what the parameter is for.
 *
 * Same family as a ladder with no bit count: something was handed in, it went
 * nowhere, and nothing said so.
 *
 * IT IS REQUIRED, AND MUST BE NON-EMPTY. RFC 9380 section 3.1 says so, and
 * the reason is the whole point of the parameter: an empty tag separates
 * nothing. Making it optional would let a caller omit it and believe they had
 * the separation anyway, which is the state this function was in.
 *
 * @param {Uint8Array} msg
 * @param {Uint8Array} dst  application separator, non-empty
 */
export function hash_to_group(msg, dst) {
    if (!dst || dst.length === 0) {
        throw new Error('ristretto255: hash needs a non-empty domain separator');
    }
    return from_uniform_bytes(sha512(concat([be16(dst.length), dst, msg])));
}

/* ---------------- the scalar field ---------------- */

/** The group order: 2^252 + 27742317777372353535851937790883648493. */
export var ORDER = CURVE.L;

/** Reduce 64 uniform bytes to a scalar, without bias. */
export function scalar_from_uniform_bytes(b) {
    /* at least the order's 253 bits + 128 (48 bytes), as GROUP's is: a
       32-byte value reduced here is a biased scalar or, from the wire, a
       non-canonical one - scalar_from_canonical_bytes is that job */
    if (!(b instanceof Uint8Array) || b.length < 48) {
        throw new RangeError('ristretto255: a uniform scalar needs at least 48 bytes, got ' + (b && b.length));
    }
    return bytes_to_bigint_le(b) % ORDER;
}

export function scalar_bytes(k) {
    return bigint_to_bytes_le(scalar_mod(k), 32);
}

/**
 * A scalar ARRIVING ON THE WIRE: exactly 32 bytes, little-endian, below the
 * order - or null. RFC 9496 / 9497 DeserializeScalar.
 *
 * ⛔ Not scalar_from_uniform_bytes: that one REDUCES, so c and c + ORDER (both
 *   fit in 32 bytes) decode alike and a received proof has a second encoding.
 */
export function scalar_from_canonical_bytes(b) {
    if (!(b instanceof Uint8Array) || b.length !== 32) { return null; }
    var v = bytes_to_bigint_le(b);
    return v < ORDER ? v : null;
}

/**
 * Arithmetic in the scalar field.
 *
 * Exported because four files build on this group - frost, oprf, pedersen and
 * bulletproofs - and each had written its own copy of the same three
 * operations. A modular inverse in particular is easy to get subtly wrong,
 * and one correct version is better than four hopefully-correct ones.
 */
export function scalar_mod(x) { return mod(x, ORDER); }

export function scalar_add(a, b) { return scalar_mod(a + b); }

export function scalar_sub(a, b) { return scalar_mod(a - b); }

export function scalar_mul(a, b) { return scalar_mod(a * b); }

/**
 * a^e mod ORDER, by square-and-multiply.
 *
 * NOT CONSTANT TIME - the loop branches on the exponent's bits. That is fine
 * for public exponents, which is what every caller here uses it for; a secret
 * exponent needs a ladder, not this.
 */
export function scalar_pow(a, e) {
    var r = 1n, b = scalar_mod(a), k = e;
    while (k > 0n) {
        if (k & 1n) { r = scalar_mod(r * b); }
        b = scalar_mod(b * b);
        k >>= 1n;
    }
    return r;
}

/**
 * The multiplicative inverse, by Fermat's little theorem: a^(p-2) = a^-1 when
 * p is prime, which the group order is. commons/modp.js's inv_prime, the
 * Fermat inverse kzg, bbs and shamir share; it was scalar_pow(a, ORDER - 2)
 * here, the same square-and-multiply under another name. Slower than the
 * extended Euclidean algorithm but branch-free on the INPUT, which matters because callers
 * invert secret blinding factors.
 */
export function scalar_inv(a) { return inv_prime(a, ORDER); }

/**
 * The inverses of many scalars, for the price of one.
 *
 * ⭐ MONTGOMERY'S TRICK, over the scalar field rather than the base field.
 *   n inversions become one plus 3n multiplications - and a scalar inversion
 *   here is scalar_pow by ORDER-2, which is 253 squarings.
 *
 *   Measured: one scalar_inv is 101 us against a scalar multiply at well
 *   under one, so the trade pays from n = 2 upward.
 *
 * ⛔ A ZERO ANYWHERE POISONS EVERY RESULT, as in the field version - the
 *   running product becomes zero and all n outputs come back zero, where
 *   scalar_inv alone would have returned zero for the zero and correct
 *   values for the rest.
 *
 * ⚠ IT DOES NOT THROW, matching scalar_inv and the field's inv, which return
 *   zero rather than throwing because throwing on a secret value is itself a
 *   timing signal.
 */
export function scalar_inv_batch(values) {
    return batch_invert(values, scalar_mul, scalar_inv, 1n);
}


/* =========================================================================
 * The prime-order group interface - see commons/group.js
 *
 * The cheapest of the four to satisfy: ristretto255 IS a prime-order group by
 * construction, so there is no subgroup to check and no cofactor to clear.
 * That is the whole point of the encoding.
 * ======================================================================= */

export var GROUP = /* @__PURE__ */ make_group({
    name: 'ristretto255',
    /* scalars are little-endian on this curve - see commons/group.js */
    little_endian: true,
    scalar_bytes_length: 32,
    ORDER: ORDER,
    bits: 253,
    IDENTITY: IDENTITY,
    GENERATOR: BASE,
    encoded_length: 32,
    add: add,
    neg: neg,
    equals: equals,
    mul_raw: function (k, P) { return mul(k, P); },
    base_mul: base_mul,
    /*
     * ⭐ wNAF, for PUBLIC inputs only. Without it GROUP.mul_vartime fell back
     *   to the constant-time ladder (it was === GROUP.mul), so every verifier
     *   working through the GROUP interface - zk_cmp, zk_sig, zk_dlenc,
     *   pedersen - paid full ladder cost on scalars that came off the wire.
     *   Every caller of GROUP.mul_vartime in the library was checked to be a
     *   verify path.
     */
    mul_vartime: mul_vartime,
    encode_raw: encode,
    decode_raw: decode,
    hash: hash_to_group
    /* no in_subgroup: canonical encoding, cofactor cleared by construction */
});

/**
 * A key pair: { sk: the secret scalar's 32 little-endian bytes (as
 * scalar_bytes writes it), pk: the encoded point sk·BASE }.
 *
 * @param {Uint8Array} [seed]  the secret scalar's bytes - canonical and
 *   nonzero, or refused; omitted or null draws a fresh one from the
 *   platform, uniform in [1, ORDER) - commons/group.js group_keygen
 */
export function keygen(seed) { return group_keygen(GROUP, seed); }
