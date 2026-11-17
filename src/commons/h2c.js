/**
 * Hashing to elliptic curves  -  RFC 9380
 *
 * The problem: given an arbitrary byte string, produce a point on a curve
 * such that NOBODY KNOWS ITS DISCRETE LOGARITHM. That last clause is the
 * whole difficulty and the whole point.
 *
 * WHY IT MATTERS. A Pedersen commitment C = v*G + r*H is binding only if
 * nobody knows k with H = k*G - if someone does, they can open the same
 * commitment to two different values. BLS signatures hash a message to a
 * point and sign it; if the signer could choose the point's discrete log,
 * they could forge. OPRFs, verifiable random functions and password-
 * authenticated key exchange all rest on the same requirement.
 *
 * THE OBVIOUS APPROACHES ARE ALL WRONG.
 *   - "Hash until you land on the curve" leaks through timing: the number of
 *     attempts depends on the message.
 *   - "Hash to an x coordinate and take a square root" fails half the time
 *     and, worse, produces a distribution that is not uniform over the curve.
 *   - "Multiply the generator by a hash" gives a point whose discrete log is
 *     exactly that hash - which the person who computed it knows.
 *
 * RFC 9380 gets a uniform distribution in constant time, and it took the
 * field about fifteen years to converge on it.
 *
 * DOMAIN SEPARATION IS MANDATORY, not advisory. Every call takes a DST - a
 * domain separation tag - and two protocols that share a curve but use the
 * same DST can have their points confused with one another. The RFC
 * prescribes the format; callers should follow it.
 */

import { concat, bytes_to_bigint } from './bytes.js';

/**
 * expand_message_xmd - RFC 9380 section 5.3.1.
 *
 * Stretch a message to any length using a fixed-output hash. The
 * construction is deliberately not plain HKDF: b_0 is xored into every
 * subsequent block so that the whole output depends on the whole input, and
 * the length and DST are bound in at both ends.
 *
 * The leading Z_pad - a full hash block of zeros - defends against length-
 * extension on Merkle-Damgard hashes. It is unnecessary for SHA-3 and
 * present anyway, because the construction has to be uniform across hashes.
 */
export function expand_message_xmd(msg, dst, len, hash) {
    var b_in_bytes = hash.DIGEST_SIZE;
    var s_in_bytes = hash.BLOCK_SIZE;
    var ell = Math.ceil(len / b_in_bytes);

    if (ell > 255) { throw new Error('h2c: requested length too long'); }
    if (dst.length > 255) { throw new Error('h2c: DST longer than 255 bytes'); }

    var dst_prime = concat([dst, new Uint8Array([dst.length])]);
    var z_pad = new Uint8Array(s_in_bytes);
    var l_i_b = new Uint8Array([(len >>> 8) & 0xff, len & 0xff]);

    var b_0 = hash(concat([z_pad, msg, l_i_b, new Uint8Array([0]), dst_prime]));
    var b_1 = hash(concat([b_0, new Uint8Array([1]), dst_prime]));

    var out = new Uint8Array(ell * b_in_bytes);
    out.set(b_1, 0);
    var prev = b_1;

    for (var i = 2; i <= ell; i++) {
        var x = new Uint8Array(b_in_bytes);
        for (var j = 0; j < b_in_bytes; j++) { x[j] = b_0[j] ^ prev[j]; }
        prev = hash(concat([x, new Uint8Array([i]), dst_prime]));
        out.set(prev, (i - 1) * b_in_bytes);
    }
    return out.subarray(0, len);
}

/**
 * expand_message_xof - the SHAKE variant, section 5.3.2.
 *
 * Simpler, because an XOF already produces arbitrary length. Used by the
 * suites built on SHAKE, and by Ed448's.
 */
export function expand_message_xof(msg, dst, len, xof) {
    if (dst.length > 255) { throw new Error('h2c: DST longer than 255 bytes'); }
    var dst_prime = concat([dst, new Uint8Array([dst.length])]);
    var l_i_b = new Uint8Array([(len >>> 8) & 0xff, len & 0xff]);
    return xof(concat([msg, l_i_b, dst_prime]), len);
}

/**
 * hash_to_field - section 5.2.
 *
 * Produce `count` field elements that are indistinguishable from uniform.
 *
 * The L parameter is why this is not simply "hash and reduce": taking
 * ceil(log2(p)) bits and reducing gives a measurably skewed distribution,
 * because p is not a power of two. L adds k extra bits - 128 for a
 * 128-bit-security curve - so the bias after reduction is below 2^-128 and
 * therefore undetectable.
 *
 * @param {number} count  how many elements
 * @param {number} m      extension degree - 1 for prime fields, 2 for Fp2
 */
export function hash_to_field(msg, count, dst, p, m, L, expand) {
    var len = count * m * L;
    var uniform = expand(msg, dst, len);
    var out = [];
    for (var i = 0; i < count; i++) {
        var elem = [];
        for (var j = 0; j < m; j++) {
            var off = L * (j + i * m);
            elem.push(bytes_to_bigint(uniform.subarray(off, off + L)) % p);
        }
        out.push(m === 1 ? elem[0] : elem);
    }
    return out;
}

/**
 * sgn0 - the "sign" of a field element, section 4.1.
 *
 * A prime field has no order, so "positive" is a convention: the low bit.
 * It exists so that the map below can pick one of the two square roots
 * deterministically, which is what makes hashing reproducible.
 */
export function sgn0(x) { return Number(x & 1n); }

/**
 * Simplified SWU - section 6.6.2. For curves with A and B both nonzero.
 *
 * Two candidate x values are computed and ONE OF THEM IS ALWAYS ON THE
 * CURVE - that is the theorem the map rests on. Both are computed either
 * way, so the running time does not depend on which one won.
 *
 * WORKS OVER ANY FIELD, prime or extension. P-256 and the Brainpool curves
 * use it directly; secp256k1 and BLS12-381's G1 use it on an isogenous curve
 * over Fp; BLS12-381's G2 uses it over Fp2. That last case is why the
 * square-root test below is written as "try it and see" rather than calling
 * is_square: Fp2 has a square root that returns null, and requiring both
 * methods would mean every field object had to implement both.
 *
 * The field object must supply mul, sqr, add, sub, neg, inv, sqrt, ZERO, ONE
 * and is_zero. sgn0 comes in as an argument because it differs between a
 * prime field and an extension.
 *
 * @param {bigint|Array} Z  a curve-specific non-square, from the RFC
 */
/*
 * ⭐ THE CONSTANT INVERSIONS, MEMOISED.
 *
 *   Two of the three inversions in the SSWU map are on the curve constants
 *   rather than on the input: 1/Z, and -B/A. Both are fixed for a given
 *   curve and were recomputed on every call - and an Fp2 inversion is 671 us
 *   here, against 0.8 for a multiplication.
 *
 * ⚠ THE KEY IS THE THREE CONSTANTS, not the field. Two curves over the same
 *   field have different A, B and Z, and keying on F alone would hand one
 *   curve's constants to the other - producing points on the wrong curve
 *   rather than an error.
 */
var SSWU_CONSTS = {};

function sswu_consts(F, A, B, Z) {
    var key = String(A) + '|' + String(B) + '|' + String(Z);
    var c = SSWU_CONSTS[key];
    if (c === undefined) {
        c = { z_inv: F.inv(Z), ba: F.mul(F.neg(B), F.inv(A)) };
        SSWU_CONSTS[key] = c;
    }
    return c;
}

export function map_to_curve_sswu(F, A, B, Z, u, sgn) {
    var m = F.mul, ad = F.add, sq = F.sqr, neg = F.neg;
    var sign = sgn || sgn0;
    var ONE = F.ONE === undefined ? 1n : F.ONE;
    var is_zero = F.is_zero ? F.is_zero : function (v) { return v === 0n; };

    var K = sswu_consts(F, A, B, Z);

    var tv1 = m(Z, sq(u));
    var tv2 = sq(tv1);
    var x1 = ad(tv1, tv2);

    /* inv0: the inverse, with zero mapping to zero rather than failing */
    var was_zero = is_zero(x1);
    x1 = was_zero ? x1 : F.inv(x1);
    x1 = ad(x1, ONE);
    x1 = was_zero ? K.z_inv : x1;
    x1 = m(x1, K.ba);

    var gx1 = ad(ad(m(sq(x1), x1), m(A, x1)), B);
    var x2 = m(tv1, x1);
    var gx2 = ad(ad(m(sq(x2), x2), m(A, x2)), B);

    var y = F.sqrt(gx1);
    var x;
    if (y !== null) { x = x1; }
    else { x = x2; y = F.sqrt(gx2); }

    /* match the sign of y to the sign of u, so the map is deterministic */
    if (sign(u) !== sign(y)) { y = neg(y); }

    return { x: x, y: y };
}

/**
 * Elligator 2 - section 6.7.1, for a Montgomery curve K*t^2 = s^3 + J*s^2 + s
 * with K = 1, which both curves here are (curve25519, J = 486662, Z = 2;
 * curve448, J = 156326, Z = -1).
 *
 * ⭐ ONE COPY, FOR BOTH 25519 AND 448. ed25519.js and ed448.js each had this
 *   map written out, line for line except for J, Z - and the SIGN of y, which
 *   is where they drifted: the ed25519 copy flipped y on sgn0(y) == 0 rather
 *   than the RFC's step 19, and compensated by taking sqrt(-486664) with
 *   sgn0 = 1 in its rational map. Two wrong signs that cancel give the right
 *   point, and a third caller of either piece would have got one wrong one.
 *   This is the RFC's literal rule; ed25519.js now takes the RFC's c1 too.
 *   Pinned against every edwards25519 and edwards448 vector in appendix J.
 *
 * NOT CONSTANT TIME, like the copies it replaces: the is_square choice and
 * the exceptional cases branch. Its inputs are hashes of public messages.
 *
 * @return {{s: bigint, t: bigint}} the point on the MONTGOMERY curve; the
 *         caller carries it to its Edwards form
 */
export function map_to_curve_elligator2(F, J, Z, u) {
    var m = F.mul, ad = F.add, sq = F.sqr, neg = F.neg;

    var tv1 = m(Z, sq(u));
    var e1 = tv1 === neg(1n);
    tv1 = e1 ? 0n : tv1;
    var x1 = F.inv(ad(tv1, 1n));
    x1 = m(x1, neg(J));
    x1 = x1 === 0n ? neg(J) : x1;
    var gx1 = ad(m(sq(x1), x1), ad(m(J, sq(x1)), x1));
    var x2 = F.sub(neg(x1), J);
    var gx2 = m(tv1, gx1);

    var e2 = F.is_square(gx1);
    var x = e2 ? x1 : x2;
    var y = F.sqrt(e2 ? gx1 : gx2);
    /* step 19: y = CMOV(y, -y, e2 XOR e3), e3 = sgn0(y) == 1 */
    if (e2 !== (sgn0(y) === 1)) { y = neg(y); }
    return { s: x, t: y };
}

/**
 * Evaluate a polynomial by Horner's rule, over any field.
 *
 * Used by every isogeny map here - secp256k1's 3-isogeny, BLS12-381's
 * 11-isogeny over Fp and its 3-isogeny over Fp2. The G1 and G2 versions were
 * written separately before this moved here.
 *
 * @param {boolean} monic  when true, the implied leading coefficient 1 is
 *                         supplied. RFC 9380 does NOT store it for the
 *                         denominators, and feeding the stored list straight
 *                         in evaluates a polynomial one degree too low - a
 *                         mistake that produces points off the curve.
 */
export function horner(F, k, x, monic) {
    var r = monic ? F.ONE : k[k.length - 1];
    var start = monic ? k.length - 1 : k.length - 2;
    for (var i = start; i >= 0; i--) { r = F.add(F.mul(r, x), k[i]); }
    return r;
}

/**
 * Build a hash-to-curve suite.
 *
 * @param {object}   opts
 *   F, C           the field and the curve group
 *   map            a map_to_curve function
 *   p, L, k        field modulus, element width, security parameter
 *   cofactor       cleared after mapping; 1n where the curve is prime order
 *   expand         expand_message_xmd or _xof, already bound to its hash
 *   order_bits     ladder width for the cofactor multiplication
 */
export function h2c_suite(opts) {
    var F = opts.F, C = opts.C;

    function clear_cofactor(P) {
        return opts.cofactor === 1n ? P : C.mul(opts.cofactor, P, opts.order_bits);
    }

    return {
        /*
         * The map is EXPOSED so a caller can check it against a vector on
         * its own. RFC 9380's appendix J gives u[0], u[1], Q0 and Q1 for
         * every suite, and without this the only comparable value is the
         * final point - which makes an error in the map, in the addition and
         * in the cofactor clearing all look identical.
         *
         * bn254 was debugged the other way and cost five wrong attempts.
         */
        map_to_curve: opts.map,

        /**
         * Uniform over the curve. Two field elements are mapped and the
         * results ADDED - one map alone is not uniform, and the difference is
         * detectable. Use this unless a spec says otherwise.
         */
        hash_to_curve: function (msg, dst) {
            var u = hash_to_field(msg, 2, dst, opts.p, 1, opts.L, opts.expand);
            var q0 = opts.map(u[0]);
            var q1 = opts.map(u[1]);
            var P = C.add(C.of(q0.x, q0.y), C.of(q1.x, q1.y));
            return clear_cofactor(P);
        },

        /**
         * Cheaper, and NOT uniform - the output distribution is
         * distinguishable from random. Fine where the spec asks for it and
         * wrong wherever uniformity is part of a security argument, which is
         * most places.
         */
        encode_to_curve: function (msg, dst) {
            var u = hash_to_field(msg, 1, dst, opts.p, 1, opts.L, opts.expand);
            var q = opts.map(u[0]);
            return clear_cofactor(C.of(q.x, q.y));
        },

        hash_to_field: function (msg, count, dst) {
            return hash_to_field(msg, count, dst, opts.p, 1, opts.L, opts.expand);
        }
    };
}
