/**
 * The NIST prime curves  -  FIPS 186-4, SEC 2
 *
 * P-256, P-384 and P-521. These are what TLS, X.509 certificates, JOSE,
 * WebAuthn, smart cards and every government profile actually use, and they
 * are what Web Crypto exposes.
 *
 * All three have a = -3. That is not decoration: it lets the point doubling
 * formulas drop a multiplication, and every NIST curve was chosen with it.
 * The complete formulas in commons/weierstrass.js do not exploit it - they
 * take a as an argument and stay correct for any curve - which costs a little
 * speed and buys one code path instead of three.
 *
 * Each curve is paired with a hash of matching strength, per SP 800-57:
 * SHA-256 with P-256, SHA-384 with P-384, SHA-512 with P-521. That pairing
 * is what RFC 6979 uses to derive the nonce, so it is part of the signature,
 * not a suggestion.
 *
 * P-521 IS THE AWKWARD ONE. Its field is 521 bits, so elements occupy 66
 * bytes with seven unused bits at the top, and its order is WIDER than
 * SHA-512's output. RFC 6979's bits2int therefore does not truncate there,
 * where it does for the other two - the one place these three curves are not
 * interchangeable by parameter substitution alone.
 *
 * ON THE PROVENANCE QUESTION: the NIST curves' seeds have never been
 * explained, which is why the cryptocurrency world chose secp256k1 instead.
 * No weakness has ever been demonstrated, and they remain mandatory almost
 * everywhere in traditional PKI. Both facts are true at once.
 */

import { ecdsa_group } from './commons/group.js';
import { ecdsa } from './commons/ecdsa.js';
import { h2c_suite, map_to_curve_sswu, expand_message_xmd } from './commons/h2c.js';
import { sha256, sha384, sha512 } from './sha2.js';

export var P256_CURVE = {
    name: 'p256',
    oid: '1.2.840.10045.3.1.7',      /* the namedCurve OBJECT IDENTIFIER */
    /* scalars are big-endian on this curve - see commons/group.js */
    little_endian: false,
    p:  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    n:  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    a:  0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,   /* -3 mod p */
    b:  0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
    Gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    Gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
    hash: sha256
};

export var P384_CURVE = {
    name: 'p384',
    oid: '1.3.132.0.34',      /* the namedCurve OBJECT IDENTIFIER */
    /* scalars are big-endian on this curve - see commons/group.js */
    little_endian: false,
    p:  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
    n:  0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
    a:  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffcn,
    b:  0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
    Gx: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
    Gy: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
    hash: sha384
};

export var P521_CURVE = {
    name: 'p521',
    oid: '1.3.132.0.35',      /* the namedCurve OBJECT IDENTIFIER */
    /* scalars are big-endian on this curve - see commons/group.js */
    little_endian: false,
    p:  (1n << 521n) - 1n,
    n:  0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409n,
    a:  (1n << 521n) - 4n,
    b:  0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
    Gx: 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66n,
    Gy: 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650n,
    hash: sha512
};

var E256 = /* @__PURE__ */ ecdsa(P256_CURVE);
var E384 = /* @__PURE__ */ ecdsa(P384_CURVE);
var E521 = /* @__PURE__ */ ecdsa(P521_CURVE);

/**
 * Each curve exposes the same API as secp256k1: keygen, is_valid_secret,
 * get_public_key, encode_point, decode_point, sign, verify, recover, ecdh,
 * sig_to_der, sig_to_compact, sig_from_compact.
 *
 * keygen(seed) gives { sk, pk } - sk 32, 48 or 66 bytes, pk compressed - and
 * sign(msg_hash, secret, extra) / sign_message(hash, msg, secret, extra) are
 * hedged unless `extra` is given: omitted or null draws fresh bytes from the
 * platform as RFC 6979's k', an empty Uint8Array is classic RFC 6979. See
 * commons/ecdsa.js.
 */
export var p256 = E256;
export var p384 = E384;
export var p521 = E521;

/* Aliases under the names X.509 and TLS use */
export var prime256v1 = E256;
export var secp256r1  = E256;
export var secp384r1  = E384;
export var secp521r1  = E521;


/* ---------------- hash to curve, RFC 9380 ---------------- */
/*
 * The registered suites are P256_XMD:SHA-256_SSWU_RO_ and its siblings. The
 * Z values below are curve-specific non-squares chosen by the RFC - they are
 * not free parameters, and a different Z gives a different, incompatible map.
 *
 * All three curves have cofactor 1, so no cofactor clearing is needed. That
 * is one of the practical advantages of the NIST curves over Ed25519 here.
 */

function nist_h2c(E, Z, hash, L) {
    var F = E.FIELD, C = E.POINT, p = E.CURVE.p;
    return h2c_suite({
        F: F, C: C, p: p, L: L, cofactor: 1n,
        order_bits: E.CURVE.n.toString(2).length,
        expand: function (msg, dst, len) { return expand_message_xmd(msg, dst, len, hash); },
        map: function (u) { return map_to_curve_sswu(F, E.CURVE.a, E.CURVE.b, Z, u); }
    });
}

/**
 * L = ceil((ceil(log2(p)) + k) / 8) with k the security parameter. The extra
 * k bits are what keep the reduction modulo p from skewing the distribution
 * detectably - see the note in commons/h2c.js.
 */
export var p256_h2c = /* @__PURE__ */ nist_h2c(E256, P256_CURVE.p - 10n, sha256, 48);
export var p384_h2c = /* @__PURE__ */ nist_h2c(E384, P384_CURVE.p - 12n, sha384, 72);
export var p521_h2c = /* @__PURE__ */ nist_h2c(E521, P521_CURVE.p - 4n,  sha512, 98);


/* =========================================================================
 * The prime-order group interface - see commons/group.js
 *
 * P-256 is the fourth RFC 9591 ciphersuite. Cofactor 1 like secp256k1, so
 * SEC1 validation is again the whole of the contract.
 * ======================================================================= */

/*
 * One constructor for every curve commons/ecdsa.js builds - group.js's
 * ecdsa_group. nist.js had its own for these three, which differed from
 * secp256k1's binding by having no mul_vartime and no comb-table base_mul;
 * both are forwarded now. The empty-DST refusal is make_group's.
 */
function nist_group(name, E, h2c) {
    return ecdsa_group(name, E, function (msg, dst) { return h2c.hash_to_curve(msg, dst); });
}

export var P256_GROUP = /* @__PURE__ */ nist_group('p256', p256, p256_h2c);

/*
 * ⚠ P-384 AND P-521 HAD NO GROUP AT ALL while P-256 did, which was an
 *   omission rather than a decision - found by tabulating the interface
 *   across every curve rather than by any test, since nothing fails when a
 *   binding simply is not there.
 *
 *   It meant FROST, VRF and OPRF could run on P-256 and not on the larger
 *   two, for no reason: the curves, the encodings and the hash-to-curve
 *   suites were all already here.
 */
export var P384_GROUP = /* @__PURE__ */ nist_group('p384', p384, p384_h2c);
export var P521_GROUP = /* @__PURE__ */ nist_group('p521', p521, p521_h2c);
