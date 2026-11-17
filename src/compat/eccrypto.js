/**
 * eccrypto compatibility
 *
 * A drop-in replacement for eccrypto, backed by this library:
 *
 *     const eccrypto = require('eccrypto');
 *     import eccrypto from 'cryptographic-primitives/compat/eccrypto.js';
 *
 * ==================== WHY THIS IS A REAL DROP-IN ====================
 *
 * eccrypto implements ECIES over secp256k1 with a fixed construction:
 *
 *     shared  = ECDH x-coordinate
 *     keys    = SHA-512(shared)         first half encrypts, second half MACs
 *     cipher  = AES-256-CBC with a random IV
 *     mac     = HMAC-SHA256(iv || ephemPublicKey || ciphertext)
 *
 * Every piece is standard and every piece is in this library, so ciphertexts
 * are interchangeable in both directions. That was checked against the real
 * eccrypto rather than assumed.
 *
 * ==================== IT IS ENCRYPT-THEN-MAC, NOT AEAD ====================
 *
 * And the MAC covers the IV and the ephemeral key as well as the ciphertext,
 * which is the ordering that makes Encrypt-then-MAC sound. Implementations
 * that MAC only the ciphertext, or that check the MAC after decrypting, have
 * been broken repeatedly - this checks the MAC FIRST and refuses to decrypt
 * if it fails, which is the only correct order.
 *
 * A modern design would use a single AEAD instead and get the same property
 * without the opportunity to get the order wrong. That is what hpke.js does,
 * and what new code should use; this exists for data that already exists.
 *
 * ==================== WHAT DIFFERS FROM eccrypto ====================
 *
 * THE PROMISES ARE RESOLVED SYNCHRONOUSLY. eccrypto wraps native bindings
 * that may be genuinely async; this computes and then resolves. Every
 * signature matches and every `await` works, but the work happens before the
 * promise settles.
 *
 * eccrypto's own error strings are reproduced where callers are known to
 * match on them - "Bad MAC" in particular, which is what its decrypt rejects
 * with and what surrounding code tends to catch.
 */

import { CURVE, POINT, G, encode_point, decode_point,
         sign as ecdsa_sign, verify as ecdsa_verify } from '../secp256k1.js';
import { sha512 } from '../sha2.js';
import { sha256 } from '../sha2.js';
import { hmac } from '../hmac.js';
import { aes_cbc_encrypt, aes_cbc_decrypt } from '../aes.js';
import { equal_bool } from '../commons/ct.js';
import { concat, bytes_to_bigint, bigint_to_bytes } from '../commons/bytes.js';
import { platform_random, text_or_bytes } from './_common.js';

var N = CURVE.n;

/* eccrypto copies whatever it is given into a fresh array, strings as UTF-8 */
function to_bytes(x) { return new Uint8Array(text_or_bytes(x)); }

function valid_secret(sk) {
    if (sk.length !== 32) { return false; }
    var d = bytes_to_bigint(sk);
    return d > 0n && d < N;
}

/** A 32-byte secret in range. */
export function generatePrivate() {
    for (var i = 0; i < 1000; i++) {
        var k = platform_random(32);
        if (valid_secret(k)) { return k; }
    }
    throw new Error('eccrypto: could not generate a private key');
}

/* the two public-key forms differ only in the encoding flag */
function public_key(sk, compressed) {
    if (!valid_secret(sk)) { throw new Error('Bad private key'); }
    var A = POINT.to_affine(POINT.mul(bytes_to_bigint(sk), G, 256));
    return encode_point(A.x, A.y, compressed);
}

/** 65 bytes, uncompressed - eccrypto's default form. */
export function getPublic(sk) { return public_key(sk, false); }

/** 33 bytes, compressed. */
export function getPublicCompressed(sk) { return public_key(sk, true); }

/**
 * sk * PK, as the 32-byte x-coordinate. derive(), encrypt() and decrypt()
 * each wrote out the decode, the multiplication and the two refusals.
 *
 * The caller checks sk first where eccrypto does; this checks only the point.
 */
function ecdh_x(sk, pk) {
    var d = decode_point(pk);
    if (d === null) { throw new Error('Bad public key'); }
    var A = POINT.to_affine(POINT.mul(bytes_to_bigint(sk), POINT.of(d.x, d.y), 256));
    if (A === null) { throw new Error('Bad public key'); }
    return bigint_to_bytes(A.x, 32);
}

/* SHA-512 of the shared x: the first half encrypts, the second MACs */
function ecies_keys(shared_x) {
    var h = sha512(shared_x);
    return { enc: h.subarray(0, 32), mac: h.subarray(32, 64) };
}

/**
 * The ECDH shared secret: the x-coordinate ONLY.
 *
 * Not the full point and not a hash of it. Using the whole encoded point here
 * would produce a scheme that works with itself and with nothing else - the
 * standard way an ECIES implementation ends up incompatible.
 */
export function derive(sk, pk) {
    return new Promise(function (resolve, reject) {
        try {
            if (!valid_secret(sk)) { throw new Error('Bad private key'); }
            resolve(ecdh_x(sk, pk));
        } catch (err) { reject(err); }
    });
}

/**
 * Encrypt to a public key.
 *
 * @param  {Uint8Array} pk   65-byte uncompressed, or 33-byte compressed
 * @param  {Uint8Array} msg
 * @param  {object}     [opts]  { iv, ephemPrivateKey } to override the
 *                              randomness, which eccrypto allows for testing
 * @return {Promise<{iv, ephemPublicKey, ciphertext, mac}>}
 */
export function encrypt(pk, msg, opts) {
    return new Promise(function (resolve, reject) {
        try {
            var o = opts || {};
            var eph_sk = o.ephemPrivateKey || generatePrivate();
            var iv = o.iv || platform_random(16);
            var message = to_bytes(msg);

            var k = ecies_keys(ecdh_x(eph_sk, pk));

            var eph_pk = getPublic(eph_sk);
            var ct = aes_cbc_encrypt(k.enc, iv, message);
            /* the MAC covers the IV and the ephemeral key, not just the
               ciphertext - which is what makes Encrypt-then-MAC sound */
            var mac = hmac(sha256, k.mac, concat([iv, eph_pk, ct]));

            resolve({ iv: iv, ephemPublicKey: eph_pk, ciphertext: ct, mac: mac });
        } catch (err) { reject(err); }
    });
}

/**
 * Decrypt with a private key.
 *
 * THE MAC IS CHECKED BEFORE ANYTHING IS DECRYPTED. Verifying afterwards, or
 * decrypting and then discarding on failure, has broken real systems -
 * padding-oracle attacks live in exactly that gap.
 *
 * @return {Promise<Uint8Array>} rejects with "Bad MAC" on failure, which is
 *         eccrypto's message and what surrounding code matches on
 */
export function decrypt(sk, opts) {
    return new Promise(function (resolve, reject) {
        try {
            if (!valid_secret(sk)) { throw new Error('Bad private key'); }
            if (!opts || !opts.iv || !opts.ephemPublicKey || !opts.ciphertext || !opts.mac) {
                throw new Error('Bad input');
            }
            var iv = new Uint8Array(opts.iv);
            var eph_pk = new Uint8Array(opts.ephemPublicKey);
            var ct = new Uint8Array(opts.ciphertext);
            var mac = new Uint8Array(opts.mac);

            var k = ecies_keys(ecdh_x(sk, eph_pk));

            var expect = hmac(sha256, k.mac, concat([iv, eph_pk, ct]));
            if (!equal_bool(mac, expect)) { throw new Error('Bad MAC'); }

            var pt = aes_cbc_decrypt(k.enc, iv, ct);
            if (pt === null) { throw new Error('Bad MAC'); }
            resolve(pt);
        } catch (err) { reject(err); }
    });
}

/*
 * ECDSA over secp256k1, DER-encoded.
 *
 * DER ENCODING IS DONE HERE RATHER THAN IN secp256k1.js, deliberately. This
 * library has no ASN.1 anywhere - parsing attacker-controlled structure is a
 * different problem from computing on bytes, and it is kept out on purpose.
 *
 * What follows is the minimum needed to read and write the ONE shape ECDSA
 * signatures take: SEQUENCE { INTEGER r, INTEGER s }. It is not a DER parser
 * and does not pretend to be - it rejects anything that is not exactly that
 * shape rather than attempting to interpret it.
 */

function der_encode(sig) {
    function int_bytes(v) {
        var b = bigint_to_bytes(v, 32);
        var i = 0;
        while (i < 31 && b[i] === 0) { i++; }
        var t = b.subarray(i);
        /* a leading bit of 1 would read as negative, so pad */
        return (t[0] & 0x80) ? concat([new Uint8Array([0]), t]) : t;
    }
    var r = int_bytes(sig.r), s = int_bytes(sig.s);
    var body = concat([new Uint8Array([0x02, r.length]), r,
                       new Uint8Array([0x02, s.length]), s]);
    return concat([new Uint8Array([0x30, body.length]), body]);
}

function der_decode(der) {
    if (der.length < 8 || der[0] !== 0x30) { return null; }
    if (der[1] !== der.length - 2) { return null; }
    if (der[2] !== 0x02) { return null; }
    var rlen = der[3];
    if (4 + rlen >= der.length) { return null; }
    var r = der.subarray(4, 4 + rlen);
    if (der[4 + rlen] !== 0x02) { return null; }
    var slen = der[5 + rlen];
    if (6 + rlen + slen !== der.length) { return null; }
    var s = der.subarray(6 + rlen, 6 + rlen + slen);
    return { r: bytes_to_bigint(r), s: bytes_to_bigint(s) };
}

/**
 * Sign a 32-byte hash.
 *
 * THE MESSAGE MUST ALREADY BE HASHED. eccrypto signs its input directly
 * rather than hashing it, so a raw message has its first 32 bytes signed and
 * the rest silently ignored - mirrored here, including the length check that
 * makes the mistake visible.
 */
export function sign(sk, msg32) {
    return new Promise(function (resolve, reject) {
        try {
            if (!valid_secret(sk)) { throw new Error('Bad private key'); }
            if (msg32.length !== 32) { throw new Error('Message should be 32 bytes'); }
            resolve(der_encode(ecdsa_sign(msg32, sk)));
        } catch (err) { reject(err); }
    });
}

/** Resolves on success and REJECTS on failure, which is eccrypto's shape. */
export function verify(pk, msg32, sig) {
    return new Promise(function (resolve, reject) {
        try {
            if (msg32.length !== 32) { throw new Error('Message should be 32 bytes'); }
            var raw = der_decode(sig);
            if (raw === null || !ecdsa_verify(msg32, raw, pk)) {
                throw new Error('Bad signature');
            }
            resolve(null);
        } catch (err) { reject(err); }
    });
}

export default {
    generatePrivate: generatePrivate,
    getPublic: getPublic,
    getPublicCompressed: getPublicCompressed,
    derive: derive,
    encrypt: encrypt,
    decrypt: decrypt,
    sign: sign,
    verify: verify
};
