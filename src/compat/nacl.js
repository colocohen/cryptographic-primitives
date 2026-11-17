/**
 * tweetnacl compatibility
 *
 * A drop-in replacement for tweetnacl's API, backed by this library. Change
 * the import and nothing else:
 *
 *     import nacl from 'tweetnacl';
 *     import nacl from 'cryptographic-primitives/compat/nacl.js';
 *
 * ==================== WHY THIS ONE IS A REAL DROP-IN ====================
 *
 * Because THE WIRE FORMAT IS ALREADY IDENTICAL. tweetnacl implements NaCl,
 * and every construction it exposes - XSalsa20-Poly1305, Ed25519, X25519,
 * SHA-512 - is the standard one, which this library also implements. Data
 * sealed by tweetnacl opens here and vice versa, byte for byte.
 *
 * That is not true of every library, and it is the test that matters. A shim
 * over a library whose format differs would compile and then fail to decrypt
 * anything, which is worse than no shim at all. See compat/cryptojs.js, which
 * is deliberately read-only for exactly this reason.
 *
 * ======================== WHAT IS NOT HERE ========================
 *
 * nacl.lowlevel is not provided. It exposes tweetnacl's internal field
 * arithmetic - gf(), pack(), unpackneg() and the rest - which is
 * implementation detail rather than API, and code reaching into it is not
 * doing something this shim can honestly mirror.
 *
 * nacl.setPRNG is not provided either. tweetnacl allowed replacing its random
 * source because it predated a universal crypto.getRandomValues; here the
 * random source is a parameter where it matters and the platform's otherwise.
 *
 * ==================== A NOTE ON verify() ====================
 *
 * nacl.verify is CONSTANT-TIME BYTE COMPARISON, not signature verification -
 * a naming choice that has confused people for a decade. It is mirrored here
 * with the same name and the same meaning, because a shim that fixed the
 * naming would not be a shim.
 */

import { secretbox as sb_seal, secretbox_open as sb_open }
    from '../salsa.js';
import { sign as ed_sign, verify as ed_verify, get_public_key as ed_pk }
    from '../ed25519.js';
import { x25519, get_public_key as x_pk } from '../x25519.js';
import { sha512 } from '../sha2.js';
import { equal_bool } from '../commons/ct.js';
import { concat } from '../commons/bytes.js';
import { platform_random } from './_common.js';
import { box_shared_key } from './_box.js';

/* ---------------- secretbox ---------------- */

/**
 * Authenticated encryption with a shared key.
 *
 * XSalsa20-Poly1305, and the output layout is NaCl's: the 16-byte tag first,
 * then the ciphertext. That ordering is the opposite of most modern AEADs and
 * is what makes the bytes interchangeable with tweetnacl's.
 */
export function secretbox(msg, nonce, key) {
    return sb_seal(key, nonce, msg);
}

secretbox.open = function (box, nonce, key) {
    return sb_open(key, nonce, box);
};
secretbox.keyLength = 32;
secretbox.nonceLength = 24;
secretbox.overheadLength = 16;

/* ---------------- box ---------------- */

/**
 * The shared key for a pair, which is what box() uses underneath.
 *
 * X25519 FOLLOWED BY HSalsa20, not the raw Diffie-Hellman output. The extra
 * step is what NaCl specifies and skipping it produces a key that works
 * consistently with itself and with nobody else - the usual way a
 * hand-rolled "compatible" implementation goes wrong.
 */
export function box_before(their_pk, my_sk) {
    /* shared with compat/sodium.js's crypto_box_beforenm: NaCl defines it */
    return box_shared_key(their_pk, my_sk);
}

/** Encrypt to a public key. */
export function box(msg, nonce, their_pk, my_sk) {
    return secretbox(msg, nonce, box_before(their_pk, my_sk));
}

box.before = box_before;
box.after = function (msg, nonce, shared_key) {
    return secretbox(msg, nonce, shared_key);
};
box.open = function (b, nonce, their_pk, my_sk) {
    return secretbox.open(b, nonce, box_before(their_pk, my_sk));
};
box.open.after = function (b, nonce, shared_key) {
    return secretbox.open(b, nonce, shared_key);
};
box.keyPair = function () {
    var sk = platform_random(32);
    return { publicKey: x_pk(sk), secretKey: sk };
};
box.keyPair.fromSecretKey = function (sk) {
    return { publicKey: x_pk(sk), secretKey: new Uint8Array(sk) };
};
box.publicKeyLength = 32;
box.secretKeyLength = 32;
box.sharedKeyLength = 32;
box.nonceLength = 24;
box.overheadLength = 16;

/* ---------------- sign ---------------- */

/**
 * Sign, with the signature PREPENDED to the message.
 *
 * That is NaCl's combined form. Most callers want sign.detached instead; this
 * exists because tweetnacl has it and code in the wild uses it.
 *
 * THE SECRET KEY IS 64 BYTES, seed followed by public key - tweetnacl's
 * layout. This library's ed25519 takes the 32-byte seed alone, so the shim
 * slices it.
 */
export function sign(msg, secret_key) {
    return concat([sign_detached(msg, secret_key), msg]);
}

function sign_detached(msg, secret_key) {
    if (secret_key.length !== 64) {
        throw new Error('nacl: secret key must be 64 bytes (seed || public key)');
    }
    return ed_sign(msg, secret_key.subarray(0, 32));
}

sign.detached = sign_detached;
sign.detached.verify = function (msg, sig, pk) {
    if (sig.length !== 64 || pk.length !== 32) { return false; }
    return ed_verify(msg, sig, pk);
};
sign.open = function (signed, pk) {
    if (signed.length < 64) { return null; }
    var sig = signed.subarray(0, 64);
    var msg = signed.subarray(64);
    return ed_verify(msg, sig, pk) ? new Uint8Array(msg) : null;
};
sign.keyPair = function () {
    return sign.keyPair.fromSeed(platform_random(32));
};
sign.keyPair.fromSeed = function (seed) {
    if (seed.length !== 32) { throw new Error('nacl: seed must be 32 bytes'); }
    var pk = ed_pk(seed);
    return { publicKey: pk, secretKey: concat([seed, pk]) };
};
sign.keyPair.fromSecretKey = function (sk) {
    if (sk.length !== 64) { throw new Error('nacl: secret key must be 64 bytes'); }
    return { publicKey: new Uint8Array(sk.subarray(32)), secretKey: new Uint8Array(sk) };
};
sign.publicKeyLength = 32;
sign.secretKeyLength = 64;
sign.seedLength = 32;
sign.signatureLength = 64;

/* ---------------- the rest ---------------- */

export function hash(msg) { return sha512(msg); }
hash.hashLength = 64;

export function scalarMult(n, p) { return x25519(n, p); }
scalarMult.base = function (n) { return x_pk(n); };
scalarMult.scalarLength = 32;
scalarMult.groupElementLength = 32;

/**
 * CONSTANT-TIME BYTE COMPARISON, not signature verification.
 *
 * The name is tweetnacl's and it has misled people for years. Mirrored as-is,
 * because a shim that renamed it would break the code it exists to support.
 */
export function verify(a, b) {
    if (a.length !== b.length || a.length === 0) { return false; }
    return equal_bool(a, b);
}

export function randomBytes(n) { return platform_random(n); }

/** The default export, so `import nacl from ...` works unchanged. */
export default {
    secretbox: secretbox,
    box: box,
    sign: sign,
    hash: hash,
    scalarMult: scalarMult,
    verify: verify,
    randomBytes: randomBytes
};
