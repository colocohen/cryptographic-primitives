/**
 * libsodium compatibility
 *
 * A drop-in replacement for the part of libsodium-wrappers that people
 * actually use:
 *
 *     import sodium from 'libsodium-wrappers';
 *     import sodium from 'cryptographic-primitives/compat/sodium.js';
 *
 * ==================== WHY THIS IS A REAL DROP-IN ====================
 *
 * Every construction below is a published standard that this library already
 * implements: XSalsa20-Poly1305, X25519, Ed25519, BLAKE2b, SipHash-2-4,
 * HMAC-SHA512, ChaCha20-Poly1305, Argon2id. The bytes are interchangeable in
 * both directions, so existing data opens unchanged.
 *
 * That was verified rather than assumed - crypto_generichash against blake2b,
 * crypto_shorthash against siphash24, crypto_auth against HMAC-SHA512
 * truncated to 32, and the box and sign families against the real library.
 *
 * ======================== NO `await sodium.ready` ========================
 *
 * libsodium is a WebAssembly build that has to finish instantiating, so every
 * program using it begins by awaiting a promise. This is JavaScript and needs
 * no such step - but `ready` is provided as an already-resolved promise so
 * that existing code keeps working without edits, which is the whole point of
 * a shim.
 *
 * ============================ SCOPE ============================
 *
 * libsodium exposes roughly 258 crypto_* functions. This covers the core -
 * secretbox, box, sealed box, sign, generichash, shorthash, auth, kdf, kx,
 * scalarmult, the AEADs and pwhash - which is what the overwhelming majority
 * of callers touch. What is NOT here:
 *
 *   crypto_secretstream_*  a STATEFUL protocol with rekeying and message
 *                          tags, not a primitive. Its state machine belongs
 *                          in a library that owns the framing.
 *   crypto_ipcrypt_*       recent and niche.
 *   crypto_core_*          libsodium's internals rather than its API.
 *   the _sumo build        password hashing beyond pwhash, and the exotic
 *                          curve operations.
 *
 * ==================== A WARNING ON MEMORY ====================
 *
 * libsodium provides memzero and mlock because it manages its own WASM heap.
 * memzero is mirrored here and does overwrite the array, but JAVASCRIPT
 * OFFERS NO GUARANTEE that the engine has not already copied the value
 * elsewhere - a garbage collector may have moved it, and there is no mlock.
 * Treat it as best-effort hygiene, not as erasure.
 */

import { secretbox as sb_seal, secretbox_open as sb_open }
    from '../salsa.js';
import { sign as ed_sign, verify as ed_verify, get_public_key as ed_pk }
    from '../ed25519.js';
import { x25519, get_public_key as x_pk } from '../x25519.js';
import { blake2b } from '../blake2.js';
import { siphash24 } from '../checksum.js';
import { hmac } from '../hmac.js';
import { sha256, sha512 } from '../sha2.js';
import { argon2id } from '../argon2.js';
import { chacha20poly1305_encrypt, chacha20poly1305_decrypt,
         xchacha20poly1305_encrypt, xchacha20poly1305_decrypt } from '../chacha.js';
import { equal_bool, wipe } from '../commons/ct.js';
import { concat, bigint_to_bytes_le, utf8, to_hex, from_hex } from '../commons/bytes.js';
import { platform_random, text_or_bytes } from './_common.js';
import { box_shared_key } from './_box.js';

/** Already resolved - there is no WebAssembly to wait for. */
export var ready = Promise.resolve();

/* ---------------- secretbox ---------------- */

export var crypto_secretbox_KEYBYTES = 32;
export var crypto_secretbox_NONCEBYTES = 24;
export var crypto_secretbox_MACBYTES = 16;

export function crypto_secretbox_easy(message, nonce, key) {
    return sb_seal(key, nonce, message);
}

/**
 * @return {Uint8Array}
 * @throws when authentication fails - libsodium throws rather than returning
 *         null, and code written against it relies on that
 */
export function crypto_secretbox_open_easy(box, nonce, key) {
    var out = sb_open(key, nonce, box);
    if (out === null) { throw new Error('incorrect secret key for the given ciphertext'); }
    return out;
}

export function crypto_secretbox_keygen() { return platform_random(32); }

/* ---------------- box ---------------- */

export var crypto_box_PUBLICKEYBYTES = 32;
export var crypto_box_SECRETKEYBYTES = 32;
export var crypto_box_NONCEBYTES = 24;
export var crypto_box_MACBYTES = 16;
export var crypto_box_SEALBYTES = 48;

export function crypto_box_keypair() {
    var sk = platform_random(32);
    return { publicKey: x_pk(sk), privateKey: sk, keyType: 'x25519' };
}

/**
 * The shared key: X25519 THEN HSalsa20.
 *
 * The second step is not optional and not decoration - it is what NaCl
 * specifies. Using the raw Diffie-Hellman output produces a scheme that
 * interoperates with nothing, and the mistake is invisible until someone
 * tries to open the data with a real implementation.
 *
 * compat/_box.js, shared with compat/nacl.js. Unlike the signing helpers
 * below, this is not one library's API choice but NaCl's definition, so the
 * two shims cannot legitimately differ on it.
 */
export function crypto_box_beforenm(their_pk, my_sk) {
    return box_shared_key(their_pk, my_sk);
}

export function crypto_box_easy(message, nonce, their_pk, my_sk) {
    return sb_seal(crypto_box_beforenm(their_pk, my_sk), nonce, message);
}

export function crypto_box_open_easy(box, nonce, their_pk, my_sk) {
    var out = sb_open(crypto_box_beforenm(their_pk, my_sk), nonce, box);
    if (out === null) { throw new Error('incorrect key pair for the given ciphertext'); }
    return out;
}

export function crypto_box_easy_afternm(message, nonce, shared) {
    return sb_seal(shared, nonce, message);
}

export function crypto_box_open_easy_afternm(box, nonce, shared) {
    var out = sb_open(shared, nonce, box);
    if (out === null) { throw new Error('incorrect shared key for the given ciphertext'); }
    return out;
}

/**
 * Anonymous encryption to a public key - the "sealed box".
 *
 * THE SENDER IS NOT AUTHENTICATED AND CANNOT DECRYPT AFTERWARDS. A fresh key
 * pair is generated for each message and its secret half is discarded, so
 * only the recipient can open it - and the recipient learns nothing about who
 * sent it.
 *
 * The nonce is DERIVED rather than random: BLAKE2b of the two public keys.
 * That is deliberate - a random nonce would have to be transmitted, and since
 * the ephemeral key is fresh for every message the nonce can never repeat
 * under the same key anyway.
 *
 * Layout: ephemeral public key (32) || secretbox output.
 */
export function crypto_box_seal(message, their_pk) {
    var eph_sk = platform_random(32);
    var eph_pk = x_pk(eph_sk);
    var nonce = blake2b(concat([eph_pk, their_pk]), 24);
    var boxed = sb_seal(crypto_box_beforenm(their_pk, eph_sk), nonce, message);
    wipe(eph_sk);
    return concat([eph_pk, boxed]);
}

export function crypto_box_seal_open(sealed, their_pk, their_sk) {
    if (sealed.length < 48) { throw new Error('incorrect ciphertext length'); }
    var eph_pk = sealed.subarray(0, 32);
    var nonce = blake2b(concat([eph_pk, their_pk]), 24);
    var out = sb_open(crypto_box_beforenm(eph_pk, their_sk), nonce, sealed.subarray(32));
    if (out === null) { throw new Error('incorrect key pair for the given ciphertext'); }
    return out;
}

/* ---------------- sign ---------------- */

export var crypto_sign_PUBLICKEYBYTES = 32;
export var crypto_sign_SECRETKEYBYTES = 64;
export var crypto_sign_SEEDBYTES = 32;
export var crypto_sign_BYTES = 64;

export function crypto_sign_keypair() {
    return crypto_sign_seed_keypair(platform_random(32));
}

/** The secret key is seed || public key, which is NaCl's layout. */
export function crypto_sign_seed_keypair(seed) {
    var pk = ed_pk(seed);
    return { publicKey: pk, privateKey: concat([seed, pk]), keyType: 'ed25519' };
}

/*
 * compat/nacl.js has the same three lines, and they stay separate: both
 * mirror APIs that happen to agree here, and tying one shim's behaviour to
 * the other's would mean a change made for tweetnacl's sake silently altering
 * libsodium's. A shim's job is to track ONE library.
 */
export function crypto_sign_detached(message, sk) {
    if (sk.length !== 64) { throw new Error('invalid signing key length'); }
    return ed_sign(message, sk.subarray(0, 32));
}

export function crypto_sign_verify_detached(sig, message, pk) {
    if (sig.length !== 64 || pk.length !== 32) { return false; }
    return ed_verify(message, sig, pk);
}

/** The combined form: signature prepended to the message. */
export function crypto_sign(message, sk) {
    return concat([crypto_sign_detached(message, sk), message]);
}

export function crypto_sign_open(signed, pk) {
    if (signed.length < 64) { throw new Error('incorrect signature'); }
    var msg = signed.subarray(64);
    if (!ed_verify(msg, signed.subarray(0, 64), pk)) {
        throw new Error('incorrect signature for the given public key');
    }
    return new Uint8Array(msg);
}

export function crypto_sign_ed25519_sk_to_seed(sk) {
    return new Uint8Array(sk.subarray(0, 32));
}

export function crypto_sign_ed25519_pk_to_curve25519(pk) {
    throw new Error('sodium: ed25519 to curve25519 conversion is not implemented');
}

/* ---------------- hashing ---------------- */

export var crypto_generichash_BYTES = 32;
export var crypto_generichash_KEYBYTES = 32;

/** BLAKE2b, with an optional key - byte-identical to libsodium's. */
export function crypto_generichash(out_len, message, key) {
    return blake2b(message, out_len || 32, key);
}

export function crypto_generichash_keygen() { return platform_random(32); }

export var crypto_hash_sha256 = function (m) { return sha256(m); };
export var crypto_hash_sha512 = function (m) { return sha512(m); };
export function crypto_hash(m) { return sha512(m); }

/** SipHash-2-4, for hash tables rather than for security. */
export var crypto_shorthash_BYTES = 8;
export var crypto_shorthash_KEYBYTES = 16;
export function crypto_shorthash(message, key) { return siphash24(message, key); }
export function crypto_shorthash_keygen() { return platform_random(16); }

/* ---------------- auth ---------------- */

export var crypto_auth_BYTES = 32;
export var crypto_auth_KEYBYTES = 32;

/** HMAC-SHA512 truncated to 32 bytes, which is libsodium's crypto_auth. */
export function crypto_auth(message, key) {
    return hmac(sha512, key, message).subarray(0, 32);
}

export function crypto_auth_verify(tag, message, key) {
    return equal_bool(tag, crypto_auth(message, key));
}

export function crypto_auth_keygen() { return platform_random(32); }

/* ---------------- AEAD ---------------- */

export var crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32;
export var crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12;
export var crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32;
export var crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24;

export function crypto_aead_chacha20poly1305_ietf_encrypt(message, ad, nsec, npub, key) {
    return chacha20poly1305_encrypt(key, npub, message, ad || new Uint8Array(0));
}

export function crypto_aead_chacha20poly1305_ietf_decrypt(nsec, ciphertext, ad, npub, key) {
    var out = chacha20poly1305_decrypt(key, npub, ciphertext, ad || new Uint8Array(0));
    if (out === null) { throw new Error('wrong secret key for the given ciphertext'); }
    return out;
}

export function crypto_aead_xchacha20poly1305_ietf_encrypt(message, ad, nsec, npub, key) {
    return xchacha20poly1305_encrypt(key, npub, message, ad || new Uint8Array(0));
}

export function crypto_aead_xchacha20poly1305_ietf_decrypt(nsec, ciphertext, ad, npub, key) {
    var out = xchacha20poly1305_decrypt(key, npub, ciphertext, ad || new Uint8Array(0));
    if (out === null) { throw new Error('wrong secret key for the given ciphertext'); }
    return out;
}

export function crypto_aead_chacha20poly1305_ietf_keygen() { return platform_random(32); }
export function crypto_aead_xchacha20poly1305_ietf_keygen() { return platform_random(32); }

/* ---------------- key derivation ---------------- */

export var crypto_kdf_KEYBYTES = 32;
export var crypto_kdf_CONTEXTBYTES = 8;

/**
 * Derive a subkey from a master key and a numbered context.
 *
 * BLAKE2b keyed with the master, over a personalisation built from the
 * subkey id and the 8-byte context string. The context is padded rather than
 * hashed, so two contexts sharing their first eight bytes give the SAME
 * subkey - which is libsodium's behaviour and a real trap.
 */
export function crypto_kdf_derive_from_key(subkey_len, subkey_id, context, key) {
    /*
     * libsodium's construction: BLAKE2b of the EMPTY message, keyed with the
     * master key, salt = LE64(subkey_id) || 0^8, personal = ctx || 0^8.
     *
     * ⛔ THIS USED TO HASH id || ctx AS THE MESSAGE - a KDF of the same shape
     *   whose subkeys matched nothing libsodium derives, which is the one
     *   thing a compat shim exists to do. blake2.js gained the salt and
     *   personal fields (RFC 7693 2.5) for it.
     */
    var ctx = text_or_bytes(context);
    if (ctx.length !== 8) { throw new Error('crypto_kdf: context must be 8 bytes'); }
    var salt = new Uint8Array(16);
    salt.set(bigint_to_bytes_le(BigInt(subkey_id), 8), 0);
    var personal = new Uint8Array(16);
    personal.set(ctx, 0);
    return blake2b(new Uint8Array(0), subkey_len, key, { salt: salt, personal: personal });
}

export function crypto_kdf_keygen() { return platform_random(32); }

/* ---------------- key exchange ---------------- */

export var crypto_kx_PUBLICKEYBYTES = 32;
export var crypto_kx_SECRETKEYBYTES = 32;
export var crypto_kx_SESSIONKEYBYTES = 32;

export function crypto_kx_keypair() {
    var sk = platform_random(32);
    return { publicKey: x_pk(sk), privateKey: sk, keyType: 'x25519' };
}

/**
 * Two session keys from one exchange, one per direction.
 *
 * THE ORDER OF THE PUBLIC KEYS IN THE HASH IS WHAT SEPARATES CLIENT FROM
 * SERVER, and it is why there are separate functions rather than one. Both
 * sides derive the same pair; each uses the opposite halves.
 */
export function crypto_kx_client_session_keys(client_pk, client_sk, server_pk) {
    var h = blake2b(concat([x25519(client_sk, server_pk), client_pk, server_pk]), 64);
    return { sharedRx: h.subarray(0, 32), sharedTx: h.subarray(32, 64) };
}

export function crypto_kx_server_session_keys(server_pk, server_sk, client_pk) {
    var h = blake2b(concat([x25519(server_sk, client_pk), client_pk, server_pk]), 64);
    return { sharedRx: h.subarray(32, 64), sharedTx: h.subarray(0, 32) };
}

/* ---------------- password hashing ---------------- */

export var crypto_pwhash_SALTBYTES = 16;
export var crypto_pwhash_ALG_ARGON2ID13 = 2;
export var crypto_pwhash_ALG_DEFAULT = 2;
export var crypto_pwhash_OPSLIMIT_INTERACTIVE = 2;
export var crypto_pwhash_MEMLIMIT_INTERACTIVE = 67108864;
export var crypto_pwhash_OPSLIMIT_MODERATE = 3;
export var crypto_pwhash_MEMLIMIT_MODERATE = 268435456;

/**
 * Argon2id.
 *
 * MEMLIMIT IS IN BYTES HERE AND KIBIBYTES IN ARGON2 ITSELF, which is
 * libsodium's convention and an easy place to be off by a factor of 1024.
 */
export function crypto_pwhash(out_len, password, salt, opslimit, memlimit, alg) {
    if (alg !== undefined && alg !== crypto_pwhash_ALG_ARGON2ID13) {
        throw new Error('sodium: only Argon2id is supported');
    }
    return argon2id({
        password: text_or_bytes(password),
        salt: salt,
        m: Math.floor(memlimit / 1024),
        t: opslimit,
        p: 1,
        length: out_len
    });
}

/* ---------------- utilities ---------------- */

export function randombytes_buf(n) { return platform_random(n); }

export function memcmp(a, b) {
    if (a.length !== b.length) { return false; }
    return equal_bool(a, b);
}

/** Best-effort only - see the note at the top of this file. */
export function memzero(a) { wipe(a); }

export { to_hex, from_hex };

export function to_string(a) { return new TextDecoder().decode(a); }
export function from_string(s) { return utf8(s); }

export default {
    ready: ready,
    crypto_secretbox_easy: crypto_secretbox_easy,
    crypto_secretbox_open_easy: crypto_secretbox_open_easy,
    crypto_secretbox_keygen: crypto_secretbox_keygen,
    crypto_box_keypair: crypto_box_keypair,
    crypto_box_beforenm: crypto_box_beforenm,
    crypto_box_easy: crypto_box_easy,
    crypto_box_open_easy: crypto_box_open_easy,
    crypto_box_easy_afternm: crypto_box_easy_afternm,
    crypto_box_open_easy_afternm: crypto_box_open_easy_afternm,
    crypto_box_seal: crypto_box_seal,
    crypto_box_seal_open: crypto_box_seal_open,
    crypto_sign_keypair: crypto_sign_keypair,
    crypto_sign_seed_keypair: crypto_sign_seed_keypair,
    crypto_sign: crypto_sign,
    crypto_sign_open: crypto_sign_open,
    crypto_sign_detached: crypto_sign_detached,
    crypto_sign_verify_detached: crypto_sign_verify_detached,
    crypto_sign_ed25519_sk_to_seed: crypto_sign_ed25519_sk_to_seed,
    crypto_generichash: crypto_generichash,
    crypto_generichash_keygen: crypto_generichash_keygen,
    crypto_hash: crypto_hash,
    crypto_hash_sha256: crypto_hash_sha256,
    crypto_hash_sha512: crypto_hash_sha512,
    crypto_shorthash: crypto_shorthash,
    crypto_shorthash_keygen: crypto_shorthash_keygen,
    crypto_auth: crypto_auth,
    crypto_auth_verify: crypto_auth_verify,
    crypto_auth_keygen: crypto_auth_keygen,
    crypto_aead_chacha20poly1305_ietf_encrypt: crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_aead_chacha20poly1305_ietf_decrypt: crypto_aead_chacha20poly1305_ietf_decrypt,
    crypto_aead_chacha20poly1305_ietf_keygen: crypto_aead_chacha20poly1305_ietf_keygen,
    crypto_aead_xchacha20poly1305_ietf_encrypt: crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt: crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_keygen: crypto_aead_xchacha20poly1305_ietf_keygen,
    crypto_kdf_derive_from_key: crypto_kdf_derive_from_key,
    crypto_kdf_keygen: crypto_kdf_keygen,
    crypto_kx_keypair: crypto_kx_keypair,
    crypto_kx_client_session_keys: crypto_kx_client_session_keys,
    crypto_kx_server_session_keys: crypto_kx_server_session_keys,
    crypto_pwhash: crypto_pwhash,
    crypto_scalarmult: function (n, p) { return x25519(n, p); },
    crypto_scalarmult_base: function (n) { return x_pk(n); },
    randombytes_buf: randombytes_buf,
    memcmp: memcmp,
    memzero: memzero,
    to_hex: to_hex,
    from_hex: from_hex,
    to_string: to_string,
    from_string: from_string,
    crypto_secretbox_KEYBYTES: crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES: crypto_secretbox_NONCEBYTES,
    crypto_secretbox_MACBYTES: crypto_secretbox_MACBYTES,
    crypto_box_PUBLICKEYBYTES: crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES: crypto_box_SECRETKEYBYTES,
    crypto_box_NONCEBYTES: crypto_box_NONCEBYTES,
    crypto_box_SEALBYTES: crypto_box_SEALBYTES,
    crypto_sign_PUBLICKEYBYTES: crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES: crypto_sign_SECRETKEYBYTES,
    crypto_sign_SEEDBYTES: crypto_sign_SEEDBYTES,
    crypto_sign_BYTES: crypto_sign_BYTES,
    crypto_pwhash_SALTBYTES: crypto_pwhash_SALTBYTES,
    crypto_pwhash_ALG_ARGON2ID13: crypto_pwhash_ALG_ARGON2ID13,
    crypto_pwhash_ALG_DEFAULT: crypto_pwhash_ALG_DEFAULT,
    crypto_pwhash_OPSLIMIT_INTERACTIVE: crypto_pwhash_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_MEMLIMIT_INTERACTIVE: crypto_pwhash_MEMLIMIT_INTERACTIVE
};
