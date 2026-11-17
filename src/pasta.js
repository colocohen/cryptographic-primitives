/**
 * pasta.js - Pallas and Vesta, the curve CYCLE behind Halo2.
 *
 * ==================== WHAT A CYCLE IS AND WHY IT EXISTS ====================
 *
 * The two curves are chosen so that each one's GROUP ORDER is the other one's
 * FIELD:
 *
 *     |Pallas| = p_vesta      arithmetic on Pallas is arithmetic in F_vesta
 *     |Vesta|  = p_pallas
 *
 * That is the whole point, and it buys recursion. Proving that a proof is
 * valid means running the VERIFIER inside a circuit, and a verifier does
 * elliptic-curve arithmetic - that is, arithmetic modulo the group order.
 * A circuit computes modulo its own field. With a single curve those two
 * moduli differ, so the arithmetic has to be simulated, at a cost of
 * hundreds of constraints per operation.
 *
 * With a cycle they coincide: Pallas arithmetic runs natively in a Vesta
 * circuit and vice versa, so a proof can verify a proof, which can verify a
 * proof, without bound.
 *
 * ⚠ AND THAT IS ALSO WHY THIS FILE IS OF LIMITED USE ON ITS OWN. The cycle
 *   pays off inside a proving system - Halo2 - which this library does not
 *   have. What is here is the curve arithmetic: enough to verify a point,
 *   agree a key, or serve as the group for a protocol that wants these
 *   fields. Building the proving system is a project the size of this
 *   library.
 *
 * ==================== THE PARAMETERS ====================
 *
 * Both are y^2 = x^3 + 5 over a 255-bit prime, cofactor 1, and both have
 * the base point (-1, 2) - which checks by inspection: 2^2 = 4 = -1 + 5.
 *
 * The moduli were taken from zcash/pasta_curves rather than from memory:
 * src/fields/fp.rs and fq.rs, as four 64-bit limbs each. "Pasta" is Pallas
 * and Vesta together; they were built by the Electric Coin Company in 2020
 * for Halo2, the first proving system to achieve recursion with no trusted
 * setup, and Zcash Orchard has run on them in production since 2022.
 */

import { field } from './commons/modp.js';
import { weierstrass } from './commons/weierstrass.js';
import { make_group, group_keygen } from './commons/group.js';
import { bigint_to_bytes_le, bytes_to_bigint_le } from './commons/bytes.js';

/*
 * The two primes. Each is the other curve's group order - the defining
 * property, and asserted in the tests rather than left as a comment.
 */
var P_PALLAS = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n;
var P_VESTA  = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001n;

export var PALLAS = {
    name: 'pallas',
    p: P_PALLAS,
    /* the group order IS the Vesta field */
    n: P_VESTA,
    a: 0n,
    b: 5n,
    Gx: P_PALLAS - 1n,      /* -1 */
    Gy: 2n,
    cofactor: 1n,
    bytes: 32
};

export var VESTA = {
    name: 'vesta',
    p: P_VESTA,
    n: P_PALLAS,
    a: 0n,
    b: 5n,
    Gx: P_VESTA - 1n,
    Gy: 2n,
    cofactor: 1n,
    bytes: 32
};

/*
 * THE SQUARE ROOT IS commons/modp.js's sqrt_vartime - Tonelli-Shanks.
 *
 * modp's constant-time `sqrt` refuses these primes, and is right to: it has
 * closed forms for p = 3 mod 4 and p = 5 mod 8, and the Pasta primes are
 * 1 mod 4 with p - 1 = 2^32 * q. THE HIGH 2-ADICITY IS DELIBERATE - a proving
 * system needs a large power-of-two subgroup for its FFTs - and the awkward
 * square root is the price.
 *
 * This file used to carry its own Tonelli-Shanks for that reason. It and
 * sqrt_vartime returned the same root - not merely roots of the same value -
 * so the copy went.
 *
 * ⚠ IT IS VARIABLE TIME, and is only used to decompress a point. A point
 *   being decompressed is public - it arrived over the wire - so the timing
 *   reveals nothing. It must NOT be used on a secret.
 */

function build(spec) {
    var Fp = field(spec.p);
    var C = weierstrass(Fp, spec.a, spec.b);
    var G = C.of(spec.Gx, spec.Gy);
    var BITS = spec.n.toString(2).length;

    /**
     * Compressed encoding: the x coordinate, with the y parity in the top
     * bit of the LAST byte.
     *
     * ⚠ THE FIELD IS 255 BITS IN 32 BYTES, so the top bit is free and the
     *   sign goes there - the same trick Edwards curves use, and NOT the
     *   0x02/0x03 prefix byte of SEC 1. A caller moving points between this
     *   and secp256k1 has to convert; there is no shared format.
     */
    /*
     * ⭐ THE IDENTITY IS ALL ZEROS - repr_P of the Zcash specification, and
     *   what pasta_curves writes. (0, ±sqrt(5)) is not a point: x = 0 would
     *   be a point of order 3 and the group has prime order, so 5 is not a
     *   square and x = 0 is free to mean "infinity". With the sign bit set
     *   it means nothing, and decodes to null. GROUP.encode and
     *   GROUP.decode still refuse the identity, as their contract says;
     *   encode_point and decode_point are the raw codec.
     */
    function encode(P) {
        if (C.is_zero(P)) { return new Uint8Array(32); }
        var A = C.to_affine(P);
        /* little-endian, as the Rust implementation writes it */
        var out = bigint_to_bytes_le(A.x, 32);
        if (A.y & 1n) { out[31] |= 0x80; }
        return out;
    }

    function decode(bytes) {
        if (!bytes || bytes.length !== 32) { return null; }
        var b = new Uint8Array(bytes);
        var sign = (b[31] & 0x80) !== 0;
        b[31] &= 0x7f;
        var x = bytes_to_bigint_le(b);
        if (x >= spec.p) { return null; }
        if (x === 0n) { return sign ? null : C.ZERO; }

        /* y^2 = x^3 + 5 */
        var y2 = Fp.add(Fp.mul(Fp.sqr(x), x), spec.b);
        var y = Fp.sqrt_vartime(y2);
        if (y === null) { return null; }
        if (((y & 1n) === 1n) !== sign) { y = Fp.neg(y); }
        return C.of(x, y);
    }

    var API = {
        CURVE: spec,
        FIELD: Fp,
        POINT: C,
        G: G,
        encode_point: encode,
        decode_point: decode,

        /**
         * A key pair: { sk: the secret scalar's 32 little-endian bytes (as
         * GROUP.scalar_bytes writes it), pk: GROUP.encode(sk·G) }.
         *
         * @param {Uint8Array} [seed]  the secret scalar's bytes - canonical
         *   and nonzero, or refused; omitted or null draws a fresh one from
         *   the platform, uniform in [1, n) - commons/group.js group_keygen
         */
        keygen: function (seed) { return group_keygen(API.GROUP, seed); },

        GROUP: make_group({
            name: spec.name,
            ORDER: spec.n,
            bits: BITS,
            IDENTITY: C.ZERO,
            GENERATOR: G,
            encoded_length: 32,
            /* scalars are little-endian here, matching the field encoding */
            little_endian: true,
            scalar_bytes_length: 32,
            add: C.add,
            neg: C.neg,
            /*
             * weierstrass.js works in PROJECTIVE coordinates and offers no
             * equality - two representations of one point differ in their
             * limbs. Comparing affine forms is the correct test and costs an
             * inversion, which is why the curve does not offer it by default.
             */
            equals: function (P, Q) {
                var zp = C.is_zero(P), zq = C.is_zero(Q);
                if (zp || zq) { return !!zp === !!zq; }
                var A = C.to_affine(P), B = C.to_affine(Q);
                return A.x === B.x && A.y === B.y;
            },
            mul_raw: function (k, P) { return C.mul(k, P, BITS); },
            encode_raw: encode,
            decode_raw: decode,
            /*
             * COFACTOR 1, so every point on the curve is in the prime-order
             * group and decode has nothing further to check. That is not
             * true of ed25519 or ed448 and is worth stating: the subgroup
             * test other curves here perform would be a no-op.
             */
            in_subgroup: function () { return true; },

            /*
             * ⚠ NO hash. Every other GROUP here provides one, and this pair
             *   deliberately does not.
             *
             *   Hash-to-curve is not a formula that follows from the curve -
             *   it is a SUITE, with a named map, a Z constant and an
             *   expansion, and its output has to match whatever else claims
             *   to implement the same one. RFC 9380 registers suites for
             *   ed25519, ed448, P-256/384/521 and secp256k1, and none for
             *   Pallas or Vesta.
             *
             *   Halo2 uses its own hash-to-curve with Zcash-specific domain
             *   strings. Inventing one here would produce points that agree
             *   with nothing, which is worse than the method being absent:
             *   an absent method fails loudly at the call site.
             */
        })
    };
    return API;
}

var _pallas = /* @__PURE__ */ build(PALLAS);
var _vesta  = /* @__PURE__ */ build(VESTA);

export var pallas = _pallas;
export var vesta = _vesta;
export var PALLAS_GROUP = _pallas.GROUP;
export var VESTA_GROUP = _vesta.GROUP;
