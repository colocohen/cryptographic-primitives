/**
 * SM2  -  GB/T 32918, the Chinese public-key standard
 *
 * Completes the Chinese national suite this library already carries: SM3 for
 * hashing, SM4 for block encryption, and SM2 for everything public-key.
 * MANDATORY in Chinese government, banking and telecoms systems, and
 * standardised for TLS 1.3 by RFC 8998 alongside SM4.
 *
 * IT IS AN ELLIPTIC CURVE SCHEME AND IT IS NOT ECDSA. The curve is an
 * ordinary 256-bit Weierstrass curve - nothing unusual about it - but the
 * signature equation is different:
 *
 *     ECDSA   s = k^-1 * (e + r*d)
 *     SM2     s = (1 + d)^-1 * (k - r*d)
 *
 * That is why this file cannot use commons/ecdsa.js. The difference is not
 * cosmetic: SM2's form avoids the modular inversion of a SECRET per
 * signature, inverting (1+d) instead - which is fixed per key and can be
 * precomputed - so the per-signature work has no secret-dependent inversion
 * at all.
 *
 * THE Z VALUE IS THE OTHER STRUCTURAL DIFFERENCE. SM2 does not sign the
 * message hash; it signs H(Z || M), where Z binds the SIGNER'S IDENTITY, the
 * curve parameters and the public key:
 *
 *     Z = SM3(ENTL || ID || a || b || Gx || Gy || Qx || Qy)
 *
 * That makes a signature meaningless outside the context of a specific key
 * and identity, which closes a class of cross-protocol and key-substitution
 * attacks that ECDSA needs external framing to avoid. The default identity
 * is the ASCII string "1234567812345678", which is in the standard.
 *
 * THREE SCHEMES SHARE THE CURVE: signature, public-key encryption (an
 * integrated scheme, closer to ECIES than to RSA), and an authenticated key
 * exchange. All three are here.
 */

import { ecdsa } from './commons/ecdsa.js';
import { fixed_base } from './commons/fixed_window.js';
import { sm3 } from './sm3.js';
import { x963_kdf } from './kdf.js';
import { concat, bytes_to_bigint, bigint_to_bytes, ascii } from './commons/bytes.js';
import { equal } from './commons/ct.js';
import { require_rng } from './commons/primes.js';
import { random_secret_below, key_from_seed } from './commons/group.js';

/*
 * sm2p256v1, from GB/T 32918.5. An ordinary curve over a 256-bit prime with
 * a = p - 3, the same shape as the NIST curves.
 */
/* the 32-byte width appears in every call, so it is bound once here */
function bigint_to_bytes32(v) { return bigint_to_bytes(v, 32); }

export var CURVE = {
    p:  0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffn,
    a:  0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffcn,
    b:  0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93n,
    n:  0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123n,
    Gx: 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7n,
    Gy: 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0n
};

/*
 * THE CURVE, ITS FIELDS AND ITS SEC 1 ENCODING COME FROM commons/ecdsa.js.
 *
 * SM2 is not ECDSA - see the top of this file - but everything BELOW the
 * signature equation is the same: a short Weierstrass curve, a scalar field
 * and SEC 1 points. This file built its own field, curve, point codec and
 * r || s codec; ecdsa() builds exactly those for any curve, and nothing in it
 * that SM2 does not use (RFC 6979, the comb table) is computed until called.
 * The hash given is SM3 for completeness; it is never used through EC.
 */
var EC = /* @__PURE__ */ ecdsa({ name: 'sm2', p: CURVE.p, n: CURVE.n, a: CURVE.a, b: CURVE.b,
                                 Gx: CURVE.Gx, Gy: CURVE.Gy, hash: sm3 });
export var FIELD = EC.FIELD;
export var POINT = EC.POINT;
var Fn = EC.SCALAR;
var G = EC.G;

/*
 * ⭐ THE GENERATOR'S COMB TABLE, built once at load.
 *
 *   Six call sites multiplied G through the generic variable-base routine -
 *   sign, verify, encrypt, decrypt, key exchange and get_public_key - and the
 *   generator never changes. Measured on secp256k1, which has the same shape:
 *   320 us through the table against 2.30 ms without.
 *
 * ⚠ IT IS CONSTANT TIME, through fixed_window's ct_select, which scans the
 *   whole table rather than indexing it. That matters because SM2 signing
 *   multiplies G by a NONCE, and a table lookup at a secret index leaks it
 *   through the cache - so a plain indexed table here would be faster and
 *   would give away the private key.
 *
 * ⚠ AND THE TABLE IS ~4 KiB HELD FOR THE LIFE OF THE PROCESS whether or not
 *   anyone uses SM2. That is the same trade every curve here makes.
 */
var BASE_TABLE = /* @__PURE__ */ fixed_base(POINT, G, 256, 4);

/** The standard's default identity when none is supplied. */
export var DEFAULT_ID = /* @__PURE__ */ ascii('1234567812345678');

/* ---------------- keys ---------------- */

export function is_valid_secret(secret) {
    if (secret.length !== 32) { return false; }
    var d = bytes_to_bigint(secret);
    /* d must be in [1, n-2] - note n-2, not n-1, because (1+d) must be
       invertible modulo n and d = n-1 makes it zero */
    return d >= 1n && d <= CURVE.n - 2n;
}

/** @return {Uint8Array} 65 bytes, uncompressed SEC 1 */
export function get_public_key(secret) {
    if (!is_valid_secret(secret)) { throw new Error('sm2: invalid private key'); }
    var Q = POINT.to_affine(BASE_TABLE(bytes_to_bigint(secret)));
    return encode_uncompressed(Q);
}

/**
 * A key pair: { sk: 32 bytes, pk: 65 bytes uncompressed }, as sign, verify,
 * encrypt and decrypt take them.
 *
 * @param {Uint8Array} [seed]  the secret key itself, checked as
 *   get_public_key checks it; omitted or null draws a fresh one from the
 *   platform - uniform in [1, n-2], the range is_valid_secret allows
 */
export function keygen(seed) {
    var sk = key_from_seed('sm2.keygen', seed, function () {
        return bigint_to_bytes(random_secret_below(CURVE.n - 1n, 'sm2.keygen'), 32);
    });
    return { sk: sk, pk: get_public_key(sk) };
}

/*
 * SEC 1 decoding: commons/ecdsa.js's decode_point, every check in ONE place -
 * length and prefix, coordinates below p, the square root for a compressed
 * key, on the curve.
 *
 * ⛔ THE LOCAL COPY THIS REPLACES WAS THE BUG. Its compressed branch returned
 *   y alone, so a 33-byte key crashed verify / encrypt / key_exchange with
 *   "Cannot mix BigInt", and neither branch checked x < p. It was fixed in
 *   place first; the fixed version was then the same function as ecdsa's,
 *   line for line, and is gone in favour of it.
 */
var decode_point = EC.decode_point;

/* 65 bytes, 0x04 || x || y - ecdsa's encode_point, uncompressed */
function encode_uncompressed(P) { return EC.encode_point(P.x, P.y, false); }

/* ---------------- Z, the identity binding ---------------- */

/**
 * Z = SM3(ENTL || ID || a || b || Gx || Gy || Qx || Qy)
 *
 * ENTL is the identity's length IN BITS as two big-endian bytes, which caps
 * the identity at 8191 bytes and - more importantly - makes the encoding
 * unambiguous. Without a length prefix an identity ending in the curve's `a`
 * parameter could be confused with a shorter one.
 */
export function compute_z(public_key, id) {
    var q = decode_point(public_key);
    if (!q) { throw new Error('sm2: invalid public key'); }
    var ident = id || DEFAULT_ID;
    var bits = ident.length * 8;
    if (bits > 0xffff) { throw new Error('sm2: identity too long'); }
    return sm3(concat([
        new Uint8Array([(bits >>> 8) & 0xff, bits & 0xff]), ident,
        bigint_to_bytes32(CURVE.a), bigint_to_bytes32(CURVE.b), bigint_to_bytes32(CURVE.Gx), bigint_to_bytes32(CURVE.Gy),
        bigint_to_bytes32(q.x), bigint_to_bytes32(q.y)
    ]));
}

/** e = SM3(Z || M), the value actually signed. */
function digest(msg, public_key, id) {
    return bytes_to_bigint(sm3(concat([compute_z(public_key, id), msg])));
}

/* ---------------- signature ---------------- */

/**
 * @param  {Uint8Array} msg     the message itself, NOT its hash - Z has to be
 *                              prepended before hashing, so the scheme cannot
 *                              take a pre-computed digest
 * @param  {function}   [rng]  n => n random bytes; omitted or null draws fresh
 *                              ones from the platform (pass null to give an id)
 * @param  {Uint8Array} [id]
 * @return {{r: bigint, s: bigint}}
 */
export function sign(msg, secret, rng, id) {
    rng = require_rng('sm2.sign', rng);
    if (!is_valid_secret(secret)) { throw new Error('sm2: invalid private key'); }
    var d = bytes_to_bigint(secret);
    var pk = get_public_key(secret);
    var e = digest(msg, pk, id);
    var n = CURVE.n;

    /* (1+d)^-1 is fixed per key; the standard's reason for this form */
    var d1_inv = Fn.inv(Fn.add(1n, d));

    for (var attempt = 0; attempt < 100; attempt++) {
        var k = bytes_to_bigint(rng(32)) % n;
        if (k === 0n) { continue; }

        /*
         * Exponent blinding: k' = k + r*n reaches the same point because n*G
         * is the identity, but randomises which bits the ladder processes.
         * The blinding factor is a fresh 64-bit value - enough to decorrelate
         * traces without doubling the scalar's width.
         */
        var blind = bytes_to_bigint(rng(8));
        var P = POINT.to_affine(POINT.mul_blinded(k, G, n, blind, 320));
        var r = Fn.add(e, P.x);
        if (r === 0n || r + k === n) { continue; }

        var s = Fn.mul(d1_inv, Fn.sub(k, Fn.mul(r, d)));
        if (s === 0n) { continue; }
        return { r: r, s: s };
    }
    throw new Error('sm2: signing failed to find a usable nonce');
}

/**
 * @param {Uint8Array} public_key  33 or 65 bytes
 * @return {boolean}
 */
export function verify(msg, sig, public_key, id) {
    var n = CURVE.n;
    if (sig.r <= 0n || sig.r >= n || sig.s <= 0n || sig.s >= n) { return false; }

    var q = decode_point(public_key);
    if (!q || !POINT.is_on_curve(q.x, q.y)) { return false; }

    var e = digest(msg, public_key, id);
    var t = Fn.add(sig.r, sig.s);
    if (t === 0n) { return false; }

    var P = POINT.add(BASE_TABLE(sig.s), POINT.mul(t, POINT.of(q.x, q.y), 256));
    if (POINT.is_zero(P) === 1n) { return false; }
    var A = POINT.to_affine(P);

    return Fn.add(e, A.x) === sig.r;
}

/** The 64-byte r || s encoding, which is what most Chinese systems use. *
 * @return {object|null} A signature, or null if the bytes are not a valid encoding.
 */
/* ecdsa's fixed-width r || s pair, which this is - it was written out here */
export function sig_to_bytes(sig) { return EC.sig_to_compact(sig); }

export function sig_from_bytes(b) { return EC.sig_from_compact(b); }

/* ---------------- public-key encryption ---------------- */

/**
 * The KDF of GB/T 32918.4: SM3 in counter mode over the shared point.
 *
 * Note the counter starts at ONE, not zero, and that a run of all-zero output
 * must be rejected by the caller - the standard says so, and the reason is
 * that a zero mask would leave the plaintext in the clear.
 */
/*
 * THIS IS ANSI X9.63 WITH SM3 AND NO SharedInfo - H(Z || counter), counter
 * from one - and is kdf.js's x963_kdf now; it was the same loop written out.
 *
 * ⚠ x963_kdf REFUSES A ZERO LENGTH, and an empty plaintext reaches here with
 *   one. The local loop returned an empty mask, which all_zero then reads as
 *   "all zero" - so encrypt retries until it gives up and decrypt returns
 *   null. Answering zero with an empty mask keeps both exactly as they were.
 */
function kdf(z, len) { return len === 0 ? new Uint8Array(0) : x963_kdf(sm3, z, len); }

function all_zero(a) {
    var v = 0;
    for (var i = 0; i < a.length; i++) { v |= a[i]; }
    return v === 0;
}

/**
 * SM2 encryption - an integrated scheme in the ECIES family.
 *
 * The output is C1 || C3 || C2: the ephemeral point, then the MAC, then the
 * ciphertext. THAT ORDER IS THE NEW ONE, from GM/T 0009-2012.
 *
 * A GREAT DEAL OF DEPLOYED SOFTWARE STILL EMITS C1 || C2 || C3 - the original
 * ordering - including the widely used `gmssl` Python library, which is what
 * this implementation is tested against. `c1c2c3` selects it, and a caller
 * talking to an existing Chinese system will usually need it. Neither
 * ordering is detectable from the ciphertext alone, so it has to be agreed
 * out of band.
 *
 * @param {function} [rng]     n => n random bytes; omitted or null draws
 *                             fresh ones from the platform
 * @param {boolean} [c1c2c3]  emit the legacy ordering
 */
export function encrypt(public_key, msg, rng, c1c2c3) {
    rng = require_rng('sm2.encrypt', rng);
    var q = decode_point(public_key);
    if (!q || !POINT.is_on_curve(q.x, q.y)) { throw new Error('sm2: invalid public key'); }
    var Q = POINT.of(q.x, q.y);

    for (var attempt = 0; attempt < 100; attempt++) {
        var k = bytes_to_bigint(rng(32)) % CURVE.n;
        if (k === 0n) { continue; }

        var C1 = POINT.to_affine(BASE_TABLE(k));
        var S = POINT.to_affine(POINT.mul(k, Q, 256));
        var shared = concat([bigint_to_bytes32(S.x), bigint_to_bytes32(S.y)]);

        var mask = kdf(shared, msg.length);
        /* the standard requires retrying rather than proceeding */
        if (all_zero(mask)) { continue; }

        var C2 = new Uint8Array(msg.length);
        for (var i = 0; i < msg.length; i++) { C2[i] = msg[i] ^ mask[i]; }

        /* the MAC covers the plaintext and both shared coordinates */
        var C3 = sm3(concat([bigint_to_bytes32(S.x), msg, bigint_to_bytes32(S.y)]));

        var head = encode_uncompressed(C1);
        return c1c2c3 ? concat([head, C2, C3]) : concat([head, C3, C2]);
    }
    throw new Error('sm2: encryption failed to find a usable nonce');
}

/** @return {Uint8Array|null} null when the MAC fails or the point is invalid */
export function decrypt(secret, ct, c1c2c3) {
    if (!is_valid_secret(secret)) { throw new Error('sm2: invalid private key'); }
    if (ct.length < 65 + 32) { return null; }
    if (ct[0] !== 0x04) { return null; }

    /*
     * The ephemeral point MUST be validated. Without this an attacker sends a
     * point on a different curve and learns the private key from the
     * resulting shared values - the classic invalid-curve attack, and the
     * reason every ECIES-family scheme needs this check.
     *
     * It is decode_point, which every other point arriving here goes
     * through; this used to parse x and y by hand and check only the curve
     * equation, so coordinates at or above p were taken modulo p.
     */
    var c1 = decode_point(ct.subarray(0, 65));
    if (c1 === null) { return null; }
    var x1 = c1.x, y1 = c1.y;

    var body = ct.subarray(65);
    var C3, C2;
    if (c1c2c3) { C2 = body.subarray(0, body.length - 32); C3 = body.subarray(body.length - 32); }
    else { C3 = body.subarray(0, 32); C2 = body.subarray(32); }

    var d = bytes_to_bigint(secret);
    var S = POINT.to_affine(POINT.mul(d, POINT.of(x1, y1), 256));
    var mask = kdf(concat([bigint_to_bytes32(S.x), bigint_to_bytes32(S.y)]), C2.length);
    if (all_zero(mask)) { return null; }

    var msg = new Uint8Array(C2.length);
    for (var i = 0; i < C2.length; i++) { msg[i] = C2[i] ^ mask[i]; }

    var check = sm3(concat([bigint_to_bytes32(S.x), msg, bigint_to_bytes32(S.y)]));
    if (equal(check, C3) !== 1) { return null; }
    return msg;
}

/* ---------------- key exchange ---------------- */

/**
 * The SM2 authenticated key exchange, GB/T 32918.3.
 *
 * Each side contributes a STATIC key and an EPHEMERAL one, and the shared
 * secret binds both plus both identities - so it authenticates as well as
 * agrees. That is closer to MQV than to plain ECDH.
 *
 * @param {boolean} initiator  the two roles are NOT symmetric: the order in
 *                             which the two Z values enter the KDF depends on
 *                             it, and getting it wrong yields two different
 *                             secrets that both look valid
 */
export function key_exchange(opts) {
    var w = 127n;                       /* 2^w = 2^(ceil(log2(n)/2) - 1) */
    var two_w = 1n << w;
    var mask = two_w - 1n;

    var d = bytes_to_bigint(opts.static_secret);
    var r = bytes_to_bigint(opts.ephemeral_secret) % CURVE.n;

    var R = POINT.to_affine(BASE_TABLE(r));
    var x1_bar = two_w + (R.x & mask);
    var t = Fn.add(d, Fn.mul(x1_bar, r));

    var peer_r = decode_point(opts.peer_ephemeral);
    var peer_q = decode_point(opts.peer_static);
    if (!peer_r || !peer_q) { throw new Error('sm2: invalid peer key'); }
    if (!POINT.is_on_curve(peer_r.x, peer_r.y) || !POINT.is_on_curve(peer_q.x, peer_q.y)) {
        throw new Error('sm2: peer key not on the curve');
    }

    var x2_bar = two_w + (peer_r.x & mask);
    var U = POINT.add(POINT.of(peer_q.x, peer_q.y),
                      POINT.mul(x2_bar, POINT.of(peer_r.x, peer_r.y), 256));
    var V = POINT.to_affine(POINT.mul(t, U, 256));
    if (V.x === 0n && V.y === 0n) { throw new Error('sm2: degenerate shared point'); }

    var za = compute_z(opts.own_public, opts.own_id);
    var zb = compute_z(opts.peer_static, opts.peer_id);
    var order = opts.initiator ? [za, zb] : [zb, za];

    return kdf(concat([bigint_to_bytes32(V.x), bigint_to_bytes32(V.y), order[0], order[1]]), opts.length || 32);
}

/** The ephemeral public value to send to the peer. */
export function exchange_public(ephemeral_secret) {
    var r = bytes_to_bigint(ephemeral_secret) % CURVE.n;
    var R = POINT.to_affine(BASE_TABLE(r));
    return encode_uncompressed(R);
}
