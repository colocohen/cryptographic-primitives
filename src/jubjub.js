/**
 * Jubjub  -  the curve embedded in BLS12-381, Zcash Sapling's curve
 *
 * A twisted Edwards curve whose base field is BLS12-381's SCALAR field: the
 * same relationship Baby Jubjub (babyjubjub.js) has with BN254, for the same
 * reason. A circuit over BLS12-381 computes in that field, so Jubjub's point
 * arithmetic is native there - which is what let Sapling verify spend
 * authorizations, note commitments and key derivations inside a proof.
 *
 *     -x^2 + y^2 = 1 + d x^2 y^2,   d = -(10240/10241)   over F_q, q = r_BLS
 *
 * The NAMES. The Zcash protocol specification calls the coordinates (u, v);
 * this file says (x, y) like every other Edwards curve here. The jubjub
 * crate's `u` is our x, its `v` our y.
 *
 * ==================== THE COFACTOR IS 8 ====================
 *
 * The curve has order 8·r_J, and only the subgroup of order r_J is useful.
 * Two consequences, stated once:
 *
 *   decode     returns ANY point on the curve - abst_J of the specification,
 *              which is what RedJubjub's cofactored verification wants
 *              (reddsa.js). It does not check the subgroup.
 *   GROUP      is the prime-order subgroup: its decode refuses a point
 *              outside it, as the contract in commons/group.js requires.
 *
 * ==================== THE GENERATOR ====================
 *
 * Zcash itself never uses a "standard" generator: every protocol role has
 * its own base, found by hashing (the spend authorization base is in
 * reddsa.js). GROUP.GENERATOR is the jubjub crate's SubgroupPoint generator -
 * the point with the lowest positive y (y = 11) and positive x, times the
 * cofactor - so k·GENERATOR agrees with that crate for every k.
 *
 * Checked against the Zcash Foundation's jubjub crate (test/vectors/curves/
 * zcash.json): multiples, the encoding, and which byte strings decode.
 */

import { field, BLS12_381_FR } from './commons/modp.js';
import { edwards, subgroup_check, y_sign_codec } from './commons/edwards.js';
import { fixed_base, wnaf_mul } from './commons/fixed_window.js';
import { make_group, group_keygen } from './commons/group.js';

var Fq = /* @__PURE__ */ field(BLS12_381_FR);

export var CURVE = {
    name: 'jubjub',
    p: BLS12_381_FR,
    a: /* @__PURE__ */ Fq.neg(1n),
    d: /* @__PURE__ */ Fq.neg(Fq.mul(10240n, Fq.inv(10241n))),
    /* the prime-order subgroup's order; the curve's is 8 times it */
    r: 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7n,
    cofactor: 8n,
    /* the jubjub crate's FULL_GENERATOR: lowest positive y, positive x */
    Gx: 0x62edcbb8bf3787c88b0f03ddd60a8187caf55d1b29bf81afe4b3d35df1a7adfen,
    Gy: 11n
};

export var FIELD = Fq;
export var POINT = /* @__PURE__ */ edwards(Fq, CURVE.a, CURVE.d);

var SCALAR_BITS = 252;   /* r_J is 252 bits */

/** The subgroup's generator: the full generator, cofactor cleared. */
export var GENERATOR = /* @__PURE__ */ POINT.mul(CURVE.cofactor, POINT.of(CURVE.Gx, CURVE.Gy), 4);

export var IDENTITY = /* @__PURE__ */ POINT.ZERO;

/** Membership in the prime-order subgroup: [r]P = O. */
export var in_subgroup = /* @__PURE__ */ subgroup_check(POINT, CURVE.r);

/** Whether a point is in the small subgroup: [8]P = O. */
export function is_small_order(P) { return POINT.eq(POINT.mul_unsafe(CURVE.cofactor, P), POINT.ZERO); }

/*
 * repr_J and abst_J: y little-endian, x's PARITY in the top bit, and since
 * ZIP 216 the second encoding of x = 0 (sign bit set) refused - see
 * commons/edwards.js y_sign_codec. The identity encodes (0x01, 0, ..., 0).
 */
var CODEC = /* @__PURE__ */ y_sign_codec(POINT, { sign: 'parity', strict: true });

/** repr_J: any point, the identity included. */
export var encode = CODEC.encode;

/**
 * abst_J: any point on the curve, or null. NOT the subgroup - see the header.
 * Variable time; points being decoded are public.
 */
export var decode = CODEC.decode;

/* k·GENERATOR through a table built once - the reduction stays outside it,
   as babyjubjub.js explains */
var BASE_TABLE = /* @__PURE__ */ fixed_base(POINT, GENERATOR, SCALAR_BITS, 4);

function reduce(k) { var v = k % CURVE.r; return v < 0n ? v + CURVE.r : v; }

/** k·GENERATOR, constant time. */
export function base_mul(k) { return BASE_TABLE(reduce(k)); }

/** k·P, constant time. */
export function mul(k, P) { return POINT.mul(reduce(k), P, SCALAR_BITS); }

/** The prime-order subgroup, under the interface every protocol here takes. */
export var GROUP = /* @__PURE__ */ make_group({
    name: 'jubjub',
    little_endian: true,
    scalar_bytes_length: 32,
    ORDER: CURVE.r,
    bits: SCALAR_BITS,
    IDENTITY: POINT.ZERO,
    GENERATOR: GENERATOR,
    encoded_length: 32,
    add: POINT.add,
    neg: POINT.neg,
    equals: POINT.eq,
    mul_raw: POINT.mul,
    base_mul: BASE_TABLE,
    /* for verification only - see make_group */
    mul_vartime: function (k, P) { return wnaf_mul(POINT, k, P, 5); },
    encode_raw: encode,
    decode_raw: decode,
    in_subgroup: in_subgroup
    /*
     * NO hash. Zcash hashes to Jubjub with its own GroupHash (BLAKE2s over a
     * fixed random string), not an RFC 9380 suite; what Sapling needs from
     * it - the spend authorization and binding bases - is in reddsa.js as
     * the constants it produces.
     */
});

/**
 * A key pair: { sk: the secret scalar's 32 little-endian bytes (as
 * scalar_bytes writes it), pk: the encoded point sk·GENERATOR }.
 *
 * @param {Uint8Array} [seed]  the secret scalar's bytes - canonical and
 *   nonzero, or refused; omitted or null draws a fresh one from the
 *   platform, uniform in [1, ORDER) - commons/group.js group_keygen
 */
export function keygen(seed) { return group_keygen(GROUP, seed); }
