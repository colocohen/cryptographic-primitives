/**
 * The node:crypto engine
 *
 * Every use of node:crypto in the library is in this file. Each entry runs
 * one operation natively in the forms Node offers; select.js falls back to
 * pure JavaScript for anything missing here.
 *
 * "node:crypto" is not one thing: Node's is OpenSSL, Bun's is BoringSSL,
 * and builds differ in what they have and in which options they take. So
 * every entry carries its check - kat() or probe(pure), select.js runs it
 * on first use - and an entry the platform cannot run as the pure code
 * would stays in JavaScript (select.js, NOTHING ABOUT THE PLATFORM IS
 * ASSUMED). The checks' inputs are in kat.js.
 *
 * Results are returned as plain Uint8Array views over Node's Buffers, so a
 * caller sees the same type whichever engine answered.
 */

import crypto from 'node:crypto';
/* imported, not the global: code that runs with Node's globals removed (a browser check) still loads this */
import { Buffer } from 'node:buffer';
import * as pure_ed25519 from '../ed25519.js';
import * as pure_x25519 from '../x25519.js';
import * as pure_x448 from '../x448.js';
import * as pure_ml_dsa from '../ml_dsa.js';
import * as pure_ml_kem from '../ml_kem.js';
import * as pure_nist from '../nist.js';
import * as pure_rsa from '../rsa.js';
import * as pure_secp256k1 from '../secp256k1.js';
import { mod_inverse, gcd, is_probable_prime } from '../commons/primes.js';
import { sha256 as pure_sha256 } from '../sha2.js';
import * as pure_paillier from '../paillier.js';
import * as pure_ring_pedersen from '../ring_pedersen.js';
import * as pure_easy from '../easy.js';
import { finish_task, done_task } from '../commons/task.js';
import { check_room } from '../commons/bytes.js';
import { MSG, K16, K32, N12, AAD, IV16, fill, GCM_SEALED, CP_SEALED, ARGON2_OPTS, ARGON2ID_TAG, RSA_KEY } from './kat.js';

function u8(buf) { return new Uint8Array(buf.buffer, buf.byteOffset, buf.length); }

/* ---------------- The checks' helpers (select.js, works) ---------------- */
/* the same bytes */
function eq(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) { return false; }
    for (var i = 0; i < a.length; i++) { if (a[i] !== b[i]) { return false; } }
    return true;
}
/* a check several entries share, run once: true, or false for an answer that is not true or a throw */
function once(check) {
    var answer;
    return function () {
        if (answer === undefined) { try { answer = check() === true; } catch (e) { answer = false; } }
        return answer;
    };
}
/* a keyed context against the pure one from the same arguments: each call the same answer */
function same_calls(native_ctx, pure_ctx, calls) {
    for (var i = 0; i < calls.length; i++) {
        var name = calls[i][0], args = calls[i].slice(1);
        var a = native_ctx[name].apply(native_ctx, args), b = pure_ctx[name].apply(pure_ctx, args);
        if (!(a === b || eq(a, b))) { return false; }
    }
    return true;
}

function wrap_hash(h) {
    return {
        update: function (msg) { h.update(msg); },
        copy: function () { return wrap_hash(h.copy()); },
        digest: function () { return u8(h.digest()); }
    };
}

/* one digest; crypto.hash, where it exists (Node 20.12, 21.7), skips the Hash object */
var one_hash = typeof crypto.hash === 'function'
    ? function (name, msg) { return u8(crypto.hash(name, msg, 'buffer')); }
    : function (name, msg) { return u8(crypto.createHash(name).update(msg).digest()); };

function hash_op(name) {
    return {
        sync: function (msg) { return one_hash(name, msg); },
        create: function () { return wrap_hash(crypto.createHash(name)); },
        kat: function () { return [MSG]; }
    };
}

/* Only what this Node build actually has: OpenSSL can be built without some. */
var available = crypto.getHashes();

function hashes(table) {
    var ops = {};
    for (var op in table) {
        if (available.indexOf(table[op]) >= 0) { ops[op] = hash_op(table[op]); }
    }
    return ops;
}

/*
 * BLAKE2 through OpenSSL has a fixed output length and no key, salt or
 * personalisation, so only the plain call runs natively.
 */
function blake2_op(name) {
    if (available.indexOf(name) < 0) { return undefined; }
    var op = hash_op(name);
    op.accepts = function (args) {
        return args.length <= 1 || (args[1] === undefined && args[2] === undefined && args[3] === undefined);
    };
    return op;
}

var HASH_NAMES = {
    sha256: 'sha256',
    sha224: 'sha224',
    sha512: 'sha512',
    sha384: 'sha384',
    sha512_224: 'sha512-224',
    sha512_256: 'sha512-256',
    sha1: 'sha1',
    md5: 'md5',
    md4: 'md4',
    ripemd160: 'ripemd160',
    sm3: 'sm3',
    whirlpool: 'whirlpool',
    sha3_224: 'sha3-224',
    sha3_256: 'sha3-256',
    sha3_384: 'sha3-384',
    sha3_512: 'sha3-512'
};

export var ops = hashes(HASH_NAMES);

/* the names this build has, looked up once: no prototype, so no stray hits */
var NATIVE_HASH = Object.create(null);
for (var hn in HASH_NAMES) { if (available.indexOf(HASH_NAMES[hn]) >= 0) { NATIVE_HASH[hn] = HASH_NAMES[hn]; } }
/* A hash argument, public form (.op) or pure function (.NAME), as node:crypto names it - or null. */
function hash_name_of(hash) {
    var id = hash && (hash.op || hash.NAME);
    return (typeof id === 'string' && NATIVE_HASH[id]) || null;
}

var blake2b = blake2_op('blake2b512');
var blake2s = blake2_op('blake2s256');
if (blake2b) { ops.blake2b = blake2b; }
if (blake2s) { ops.blake2s = blake2s; }

/*
 * SHAKE: node:crypto fixes the output length when the hash is created, so
 * the one-shot call runs natively and the incremental form - whose length
 * is given at the end, or read in pieces - runs in pure JavaScript.
 */
function shake_op(name) {
    if (available.indexOf(name) < 0) { return; }
    ops[name] = {
        sync: function (msg, out_len) {
            return u8(crypto.createHash(name, { outputLength: out_len }).update(msg).digest());
        },
        accepts: function (args) { return typeof args[1] === 'number' && args[1] > 0; },
        kat: function () { return [MSG, 64]; }
    };
}
shake_op('shake128');
shake_op('shake256');

/*
 * HMAC over any hash this build has natively, one-shot only: node:crypto's
 * Hmac has no copy(), which the incremental form promises, so hmac_create
 * runs in JavaScript. The hash argument is a public form from api/ (it
 * carries .op) or a pure function (it does not, and runs in JavaScript).
 */
ops.hmac = {
    sync: function (hash, key, msg) { return u8(crypto.createHmac(hash_name_of(hash), key).update(msg).digest()); },
    accepts: function (args) { return hash_name_of(args[0]) !== null; },
    kat: function () { return [pure_sha256, K16, MSG]; }
};

/* ---------------- Ciphers ---------------- */
/*
 * AES and ChaCha20 through OpenSSL. Every call makes its own Cipher object:
 * node:crypto takes the nonce when the object is made, so an object cannot
 * be reused across messages. A keyed context here holds the key and does
 * the same per call - the pure context (aes.js) is what saves the key
 * schedule, and the two are measured against each other.
 */
var ciphers = crypto.getCiphers();
function has(name) { return ciphers.indexOf(name) >= 0; }
/* OpenSSL's name for AES in `mode` with this key's length, looked up in a table made once - or null where this build lacks it */
var AES_NAMES = {};
['gcm', 'ctr', 'ecb'].forEach(function (mode) {
    AES_NAMES[mode] = {};
    [16, 24, 32].forEach(function (len) { var name = 'aes-' + (len * 8) + '-' + mode; AES_NAMES[mode][len] = has(name) ? name : null; });
});
function aes_name(key, mode) { return AES_NAMES[mode][key.length] || null; }
function aes_key_ok(key) { return key && (key.length === 16 || key.length === 24 || key.length === 32); }

/*
 * ⭐ ONE SEAL AND ONE OPEN FOR BOTH AEADs, writing into a given array: a
 *   Cipher or Decipher set up with its key, nonce, AAD (and tag), then the
 *   output written at out[offset..]. The one-shot forms pass a new array;
 *   a context's _into forms pass the caller's - so a record is encrypted
 *   into its own buffer with update()'s Buffer as the only allocation.
 *
 * Both are stream modes: the ciphertext is as long as the plaintext, so the
 * room needed is known before update() runs. update() reads its whole input
 * before anything is written, so `out` may be the input's own memory. On a
 * failed authentication open_to returns null and writes nothing.
 */
function seal_to(c, pt, out, offset) {
    var a = c.update(pt), b = c.final();
    out.set(a, offset); out.set(b, offset + a.length);
    out.set(c.getAuthTag(), offset + a.length + b.length);
    return a.length + b.length + 16;
}
function open_to(d, ct, out, offset) {
    var a = d.update(ct);
    try {
        var b = d.final();
    } catch (e) {
        return null;   /* authentication failed: null, as the pure form */
    }
    out.set(a, offset); out.set(b, offset + a.length);
    return a.length + b.length;
}
function gcm_cipher(key, iv, aad) {
    var c = crypto.createCipheriv(aes_name(key, 'gcm'), key, iv);
    if (aad && aad.length) { c.setAAD(aad); }
    return c;
}
function gcm_decipher(key, iv, tag, aad) {
    var d = crypto.createDecipheriv(aes_name(key, 'gcm'), key, iv);
    d.setAuthTag(tag);
    if (aad && aad.length) { d.setAAD(aad); }
    return d;
}
function gcm_seal(key, iv, pt, aad) {
    var out = new Uint8Array(pt.length + 16);
    seal_to(gcm_cipher(key, iv, aad), pt, out, 0);
    return out;
}
/*
 * The plaintext of a decryption: update()'s output and final()'s, which is
 * empty in GCM and ChaCha20-Poly1305. Then update()'s Buffer is the result as
 * it is, when it owns all of its memory - no copy; a slice of a larger buffer
 * is copied, so the result never keeps that buffer alive.
 */
function joined(a, b) {
    if (b.length === 0 && a.byteOffset === 0 && a.buffer.byteLength === a.length) { return u8(a); }
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
}
function gcm_open(key, iv, sealed, aad) {
    if (sealed.length < 16) { return null; }
    var d = gcm_decipher(key, iv, sealed.subarray(sealed.length - 16), aad);
    var a = d.update(sealed.subarray(0, sealed.length - 16));
    try {
        var b = d.final();
    } catch (e) {
        return null;   /* authentication failed: null, as the pure form */
    }
    return joined(a, b);
}

/*
 * A keyed AEAD context over seal_to/open_to: `cipher(key, nonce, aad)` and
 * `decipher(key, nonce, tag, aad)` set one up, `check(nonce)` throws
 * on a nonce the pure form refuses.
 */
function aead_context(key, cipher, decipher, check, seal, open) {
    var k = Buffer.from(key);
    return {
        encrypt: function (nonce, pt, aad) { check(nonce); return seal(k, nonce, pt, aad); },
        decrypt: function (nonce, sealed, aad) { check(nonce); return open(k, nonce, sealed, aad); },
        encrypt_into: function (out, offset, nonce, pt, aad) {
            check(nonce);
            check_room('encrypt_into', out, offset, pt.length + 16);
            return seal_to(cipher(k, nonce, aad), pt, out, offset);
        },
        decrypt_into: function (out, offset, nonce, sealed, aad) {
            check(nonce);
            if (sealed.length < 16) { return null; }
            var n = sealed.length - 16;
            check_room('decrypt_into', out, offset, n);
            return open_to(decipher(k, nonce, sealed.subarray(n), aad), sealed.subarray(0, n), out, offset);
        },
        wipe: function () { k.fill(0); }
    };
}

/* the pure forms throw on an empty IV; leave every unusual input to them */
function gcm_args_ok(args) { return aes_key_ok(args[0]) && args[1] && args[1].length > 0 && aes_name(args[0], 'gcm') !== null; }

ops.aes_gcm_encrypt = { sync: gcm_seal, accepts: gcm_args_ok, kat: function () { return [K16, N12, MSG, AAD]; } };
ops.aes_gcm_decrypt = { sync: gcm_open, accepts: gcm_args_ok, kat: function () { return [K16, N12, GCM_SEALED, AAD]; } };
function gcm_check(iv) { if (!iv || iv.length === 0) { throw new Error('aes_gcm: iv must not be empty'); } }
/* an AEAD context's check: encrypt, decrypt, and both _into forms, as the pure context answers */
function aead_probe(key, sealed) {
    return function (pure_create) {
        var ctx = this.create(key), out = new Uint8Array(sealed.length);
        return same_calls(ctx, pure_create(key), [['encrypt', N12, MSG, AAD], ['decrypt', N12, sealed, AAD]]) &&
               ctx.encrypt_into(out, 0, N12, MSG, AAD) === sealed.length && eq(out, sealed) &&
               ctx.decrypt_into(out, 0, N12, sealed, AAD) === MSG.length && eq(out.subarray(0, MSG.length), MSG);
    };
}
ops.aes_gcm = {
    create: function (key) { return aead_context(key, gcm_cipher, gcm_decipher, gcm_check, gcm_seal, gcm_open); },
    accepts: function (args) { return aes_key_ok(args[0]) && aes_name(args[0], 'gcm') !== null; },
    probe: aead_probe(K16, GCM_SEALED)
};

/*
 * ECB under a key: one Cipher and one Decipher, made once and fed every call.
 * With padding off and whole blocks in, update() gives the same blocks out
 * and keeps nothing between calls - so it never sees a partial block: that
 * one would stay buffered inside and shift every later call. final() is
 * never called, which would end the object.
 */
ops.aes_ecb = {
    create: function (key) {
        var name = aes_name(key, 'ecb');
        var c = crypto.createCipheriv(name, key, null), d = crypto.createDecipheriv(name, key, null);
        c.setAutoPadding(false); d.setAutoPadding(false);
        function run(x, data) {
            if (data.length % 16 !== 0) { throw new Error('aes_ecb: data must be a multiple of 16 bytes'); }
            return u8(x.update(data));
        }
        function run_into(x, out, offset, data) {
            if (data.length % 16 !== 0) { throw new Error('aes_ecb: data must be a multiple of 16 bytes'); }
            check_room('encrypt_into', out, offset, data.length);
            out.set(x.update(data), offset);
            return data.length;
        }
        return {
            encrypt: function (data) { return run(c, data); },
            decrypt: function (data) { return run(d, data); },
            encrypt_into: function (out, offset, data) { return run_into(c, out, offset, data); },
            decrypt_into: function (out, offset, data) { return run_into(d, out, offset, data); }
        };
    },
    accepts: function (args) { return aes_key_ok(args[0]) && aes_name(args[0], 'ecb') !== null; },
    probe: function (pure_create) {
        var blocks = MSG.subarray(0, 32), ctx = this.create(K16), out = new Uint8Array(32);
        return same_calls(ctx, pure_create(K16), [['encrypt', blocks], ['decrypt', blocks]]) &&
               ctx.encrypt_into(out, 0, blocks) === 32 && eq(out, pure_create(K16).encrypt(blocks));
    }
};

ops.aes_ctr = {
    /* a stream mode: update() gives every byte, and final() nothing - so it is not called, and nothing is joined */
    sync: function (key, iv, data) { return u8(crypto.createCipheriv(aes_name(key, 'ctr'), key, iv).update(data)); },
    accepts: function (args) { return aes_key_ok(args[0]) && aes_name(args[0], 'ctr') !== null && args[1] && args[1].length === 16; },
    kat: function () { return [K16, IV16, MSG]; }
};

/* ChaCha20-Poly1305 (RFC 8439): a 12-byte nonce, a 16-byte tag. */
/*
 * One options object for every call - node:crypto only reads it - and no
 * plaintextLength, which only CCM needs: nothing made per call that
 * OpenSSL does not need.
 */
var CP_OPTIONS = Object.freeze({ authTagLength: 16 });
function cp_cipher(key, nonce, aad) {
    var c = crypto.createCipheriv('chacha20-poly1305', key, nonce, CP_OPTIONS);
    if (aad && aad.length) { c.setAAD(aad); }
    return c;
}
function cp_decipher(key, nonce, tag, aad) {
    var d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, CP_OPTIONS);
    d.setAuthTag(tag);
    if (aad && aad.length) { d.setAAD(aad); }
    return d;
}
function cp_seal(key, nonce, pt, aad) {
    var out = new Uint8Array(pt.length + 16);
    seal_to(cp_cipher(key, nonce, aad), pt, out, 0);
    return out;
}
function cp_open(key, nonce, sealed, aad) {
    if (sealed.length < 16) { return null; }
    var d = cp_decipher(key, nonce, sealed.subarray(sealed.length - 16), aad);
    var a = d.update(sealed.subarray(0, sealed.length - 16));
    try {
        var b = d.final();
    } catch (e) {
        return null;
    }
    return joined(a, b);
}
/* looked up once: has() searches the whole list of OpenSSL's ciphers */
var HAS_CHACHA20_POLY1305 = has('chacha20-poly1305'), HAS_CHACHA20 = has('chacha20');
function cp_args_ok(args) { return HAS_CHACHA20_POLY1305 && args[0] && args[0].length === 32 && args[1] && args[1].length === 12; }

ops.chacha20poly1305_encrypt = { sync: cp_seal, accepts: cp_args_ok, kat: function () { return [K32, N12, MSG, AAD]; } };
ops.chacha20poly1305_decrypt = { sync: cp_open, accepts: cp_args_ok, kat: function () { return [K32, N12, CP_SEALED, AAD]; } };
function cp_check(nonce) { if (!nonce || nonce.length !== 12) { throw new Error('chacha20poly1305: nonce must be 12 bytes'); } }
ops.chacha20poly1305 = {
    create: function (key) { return aead_context(key, cp_cipher, cp_decipher, cp_check, cp_seal, cp_open); },
    accepts: function (args) { return HAS_CHACHA20_POLY1305 && args[0] && args[0].length === 32; },
    probe: aead_probe(K32, CP_SEALED)
};

/* Raw ChaCha20: OpenSSL's IV is the 32-bit counter (little-endian) then the nonce. */
ops.chacha20 = {
    sync: function (key, nonce, data, counter) {
        var iv = new Uint8Array(16);
        var c0 = counter === undefined ? 0 : counter >>> 0;
        iv[0] = c0 & 0xff; iv[1] = (c0 >>> 8) & 0xff; iv[2] = (c0 >>> 16) & 0xff; iv[3] = (c0 >>> 24) & 0xff;
        iv.set(nonce, 4);
        return u8(crypto.createCipheriv('chacha20', key, iv).update(data));
    },
    /* the pure form refuses a run past 2^32 blocks; keep those to it */
    accepts: function (args) {
        var c0 = args[3] === undefined ? 0 : args[3] >>> 0;
        return HAS_CHACHA20 && args[0] && args[0].length === 32 && args[1] && args[1].length === 12 &&
               c0 + Math.ceil(args[2].length / 64) <= 0x100000000;
    },
    kat: function () { return [K32, N12, MSG, 7]; }
};

/* ---------------- When native is worth it ---------------- */
/*
 * Every call into node:crypto pays a fixed price before the first byte: a
 * Hash or Cipher object is created and the arguments cross from JavaScript
 * into C++ - about 1 us for a hash, 3 to 6 us for a cipher. On a short
 * input the pure JavaScript is done before that, so these operations run
 * natively only from a size on:
 *
 *     from: { arg, bytes }   the one-shot form, by the length of args[arg]
 *     call_from: bytes       each encrypt/decrypt of a keyed context (from
 *                            create()), by the length of its message
 *
 * and select.js runs anything shorter in JavaScript, with the same result.
 *
 * Each size is the smallest at which native was faster in two runs of
 * bench/routing.js on Node 26.13 and two on Node 22, and stayed faster
 * above it (x86-64, AES-NI; the median of 9 pairs of batches of at
 * least 30 ms, so that each carries its share of the collector's work - a
 * native call's Cipher or Hmac is a native object the collector must
 * release, and the pure code's allocations are collected too). Where the
 * runs differ, the Node 26 sizes. The surrounding sizes are close to even,
 * so a size need not be exact - re-run the benchmark to re-derive them for
 * another machine. Every operation not listed was faster natively at every
 * size: SHA-384, the SHA-512 and SHA-3 families, BLAKE2b, HMAC, HKDF and
 * the password hashes, and every signature and key agreement (2x to 15x).
 *
 * ChaCha20-Poly1305's one-shot encryption and decryption differ: node:crypto
 * hands back the ciphertext and the tag apart, so encryption pays a new
 * array to join them, and decryption returns OpenSSL's own output.
 */
var NATIVE_FROM = {
    sha256: [0, 128], sha224: [0, 192], sha1: [0, 256], md5: [0, 768],
    ripemd160: [0, 128], sm3: [0, 128], blake2s: [0, 96],
    shake128: [0, 192], shake256: [0, 192],
    aes_gcm_encrypt: [2, 64], aes_gcm_decrypt: [2, 64],
    aes_ctr: [2, 96],
    chacha20: [2, 1024],
    chacha20poly1305_encrypt: [2, 768], chacha20poly1305_decrypt: [2, 512]
};
/*
 * One size for all four methods of a context, timed apart (encrypt and
 * decrypt, and their _into forms): AES-GCM 192 by encrypt_into, decrypt
 * and decrypt_into, 384 by encrypt; ChaCha20-Poly1305 768 by most;
 * ECB 192 by encrypt_into and 96 to 128 by the rest.
 */
var NATIVE_CALL_FROM = { aes_gcm: 192, chacha20poly1305: 768, aes_ecb: 128 };
for (var nf in NATIVE_FROM) {
    if (ops[nf]) { ops[nf].from = { arg: NATIVE_FROM[nf][0], bytes: NATIVE_FROM[nf][1] }; }
}
for (var nc in NATIVE_CALL_FROM) {
    if (ops[nc]) { ops[nc].call_from = NATIVE_CALL_FROM[nc]; }
}

/* ---------------- Key derivation and password hashing ---------------- */
/*
 * These have callback forms in node:crypto that run on libuv's thread pool,
 * so the callback form here leaves the event loop free for the whole
 * computation - no slicing needed.
 */
function ab(x) { return new Uint8Array(x); }

ops.hkdf = {
    sync: function (hash, ikm, length, salt, info) {
        return ab(crypto.hkdfSync(hash_name_of(hash), ikm, salt || new Uint8Array(0), info || new Uint8Array(0), length));
    },
    async: function (args, cb) {
        crypto.hkdf(hash_name_of(args[0]), args[1], args[3] || new Uint8Array(0), args[4] || new Uint8Array(0), args[2],
            function (err, out) { cb(err, err ? undefined : ab(out)); });
    },
    /* Node limits info to 1024 bytes; longer is legal and left to the pure form */
    accepts: function (args) { return hash_name_of(args[0]) !== null && (!args[4] || args[4].length <= 1024); },
    kat: function () { return [pure_sha256, MSG, 42, K16, AAD]; }
};

ops.pbkdf2 = {
    sync: function (hash, password, salt, iterations, length) {
        return u8(crypto.pbkdf2Sync(password, salt, iterations, length, hash_name_of(hash)));
    },
    async: function (args, cb) {
        crypto.pbkdf2(args[1], args[2], args[3], args[4], hash_name_of(args[0]),
            function (err, out) { cb(err, err ? undefined : u8(out)); });
    },
    accepts: function (args) { return hash_name_of(args[0]) !== null && args[3] >= 1 && args[4] >= 1; },
    kat: function () { return [pure_sha256, MSG, K16, 2, 32]; }
};

/* scrypt(password, salt, N, r, p, length); maxmem raised to what the parameters need */
function scrypt_opts(a) { return { N: a[2], r: a[3], p: a[4], maxmem: 128 * a[2] * a[3] * (a[4] + 1) + 1024 * 1024 }; }
if (typeof crypto.scryptSync === 'function') {
    ops.scrypt = {
        sync: function (password, salt, N, r, p, length) {
            return u8(crypto.scryptSync(password, salt, length, scrypt_opts([password, salt, N, r, p])));
        },
        async: function (args, cb) {
            crypto.scrypt(args[0], args[1], args[5], scrypt_opts(args),
                function (err, out) { cb(err, err ? undefined : u8(out)); });
        },
        kat: function () { return [MSG, K16, 16, 1, 1, 32]; }
    };
}

/* Argon2 (RFC 9106), where this Node has it: crypto.argon2 arrived in 24.7. */
function argon2_params(o) {
    var p = { message: o.password, nonce: o.salt, parallelism: o.p, tagLength: o.length, memory: o.m, passes: o.t };
    if (o.secret) { p.secret = o.secret; }
    if (o.ad) { p.associatedData = o.ad; }
    return p;
}
function argon2_op(name) {
    return {
        sync: function (opts) { return u8(crypto.argon2Sync(name, argon2_params(opts))); },
        async: function (args, cb) {
            crypto.argon2(name, argon2_params(args[0]), function (err, out) { cb(err, err ? undefined : u8(out)); });
        },
        /* the pure form's checks and messages for anything unusual */
        accepts: function (args) {
            var o = args[0];
            return !!o && o.password instanceof Uint8Array && o.salt instanceof Uint8Array && o.salt.length >= 8 &&
                   o.p >= 1 && o.t >= 1 && o.m >= 8 * o.p && o.length >= 4;
        },
        kat: function () { return [ARGON2_OPTS]; }
    };
}
if (typeof crypto.argon2Sync === 'function') {
    ops.argon2d = argon2_op('argon2d');
    ops.argon2i = argon2_op('argon2i');
    ops.argon2id = argon2_op('argon2id');

    /*
     * easy.js's password functions, each one Argon2id run: the pure task
     * with node:crypto's Argon2id in place of the pure one (each easy *_task
     * takes it last). 64 MiB, t = 3 - easy's defaults - is a fraction of a
     * second natively and many seconds in JavaScript.
     */
    var native_argon2id = function (o) { return done_task(u8(crypto.argon2Sync('argon2id', argon2_params(o)))); };
    /* each of them is the pure task around the one native call, so the check is that call's answer */
    var argon2id_ok = once(function () { return eq(u8(crypto.argon2Sync('argon2id', argon2_params(ARGON2_OPTS))), ARGON2ID_TAG); });
    var easy_op = function (task) {
        return {
            sync: function () {
                var args = Array.prototype.slice.call(arguments);
                while (args.length < task.length - 1) { args.push(undefined); }
                args.push(native_argon2id);
                return finish_task(task.apply(null, args));
            },
            probe: argon2id_ok
        };
    };
    ops['easy.hash_password'] = easy_op(pure_easy.hash_password_task);
    ops['easy.verify_password'] = easy_op(pure_easy.verify_password_task);
    ops['easy.seal_with_password'] = easy_op(pure_easy.seal_with_password_task);
    ops['easy.open_with_password'] = easy_op(pure_easy.open_with_password_task);
}

/* ---------------- Edwards and Montgomery curves ---------------- */
/*
 * node:crypto takes keys as KeyObjects, so a raw key is wrapped in its
 * fixed DER prefix (PKCS#8 for a private key, SPKI for a public one) and
 * imported. Importing a private key makes OpenSSL derive its public key -
 * about as costly as the operation itself - which is why a native engine is
 * not automatically faster here, and why these are measured against the
 * pure forms.
 *
 * Signing and key derivation are deterministic and give the same bytes
 * either way. Verification needs more care - see ed25519_verdict below.
 */
function hex(s) { return Buffer.from(s, 'hex'); }
var DER = {
    ed25519: { pkcs8: hex('302e020100300506032b657004220420'), spki: hex('302a300506032b6570032100'), len: 32 },
    x25519:  { pkcs8: hex('302e020100300506032b656e04220420'), spki: hex('302a300506032b656e032100'), len: 32 },
    ed448:   { pkcs8: hex('3047020100300506032b6571043b0439'), spki: hex('3043300506032b6571033a00'), len: 57 },
    x448:    { pkcs8: hex('3046020100300506032b656f043a0438'), spki: hex('3042300506032b656f033900'), len: 56 }
};
function private_key(kind, raw) {
    return import_private(Buffer.concat([DER[kind].pkcs8, raw]), 'pkcs8');
}
/*
 * A private key imported from a DER encoding that holds the secret: the
 * encoding is built with the secret written once into it, and zeroed once
 * OpenSSL has read it, as a context's copy is on wipe() - best effort, as
 * every wipe in JavaScript is (commons/ct.js).
 */
function import_private(der_bytes, type) {
    try { return crypto.createPrivateKey({ key: der_bytes, format: 'der', type: type }); } finally { der_bytes.fill(0); }
}
/* a DER header: the tag and the length of what follows */
function der_head(tag, n) { return Buffer.concat([Buffer.from([tag]), der_length(n)]); }
/*
 * PKCS #8 (RFC 5958) around a secret: version 0, the algorithm identifier,
 * and an OCTET STRING holding head ‖ secret - the secret written once, into
 * the encoding import_private zeroes.
 */
function pkcs8_private(alg, head, secret) {
    var octet = der_head(0x04, head.length + secret.length);
    var body = 3 + alg.length + octet.length + head.length + secret.length;
    return import_private(Buffer.concat([der_head(0x30, body), hex('020100'), alg, octet, head, secret]), 'pkcs8');
}
function public_key(kind, raw) {
    return crypto.createPublicKey({ key: Buffer.concat([DER[kind].spki, raw]), format: 'der', type: 'spki' });
}
function raw_public(kind, key) {
    var der = crypto.createPublicKey(key).export({ format: 'der', type: 'spki' });
    return u8(der.subarray(der.length - DER[kind].len));
}
function sized(kind, x) { return x && x.length === DER[kind].len; }

function edwards(kind) {
    var seed = fill(DER[kind].len, 3);
    var table = {
        get_public_key: {
            sync: function (seed) { return raw_public(kind, private_key(kind, seed)); },
            accepts: function (args) { return sized(kind, args[0]); },
            kat: function () { return [seed]; }
        },
        sign: {
            sync: function (msg, seed) { return u8(crypto.sign(null, msg, private_key(kind, seed))); },
            /* the pure form for a context string: Ed25519ctx/Ed448 contexts are its */
            accepts: function (args) { return sized(kind, args[1]) && (args[2] === undefined || args[2].length === 0); },
            kat: function () { return [MSG, seed]; }
        }
    };
    /*
     * signer_create(seed, ctx, variant): the key imported into OpenSSL once -
     * each sign() then skips the PKCS#8 import that sign() pays every call.
     * Pure Ed25519/Ed448 only, as sign above.
     */
    table.signer = {
        create: function (seed) {
            var key = private_key(kind, seed);
            return {
                sign: function (msg) {
                    if (key === null) { throw new Error(kind + ': the signer was wiped'); }
                    return u8(crypto.sign(null, msg, key));
                },
                wipe: function () { key = null; }
            };
        },
        accepts: function (args) {
            return sized(kind, args[0]) && (args[1] === undefined || args[1] === null || args[1].length === 0) &&
                   (args[2] === undefined || args[2] === 0);
        },
        probe: function (pure_create) { return same_calls(this.create(seed), pure_create(seed), [['sign', MSG]]); }
    };
    if (kind === 'ed25519') { ed25519_verification(table); }
    return table;
}

/*
 * ==================== Ed25519 VERIFICATION IN OpenSSL ====================
 *
 * OpenSSL's rule is neither of the library's two. It is cofactorless,
 * accepts a small-order R or A, and accepts a key or an R whose encoding
 * is not canonical (y not reduced mod p, or x = 0 with the sign bit set).
 * On the twelve ed25519-speccheck cases it says yes to 0, 1, 2, 3 and 11;
 * the cofactored default to 0-5; 'strict', libsodium's rule, to 3 alone. A
 * verdict that depended on the engine would split two nodes, so OpenSSL is
 * asked only where its answer IS the library's:
 *
 *   1. a key or an R that is not canonical, or an S not below L: false.
 *      Both modes refuse these, and OpenSSL might not.
 *   2. 'strict': a key or an R of small order - one of the eight points
 *      below - is false, as libsodium refuses them. What is left, OpenSSL
 *      decides: the same cofactorless equation over the same points, R
 *      compared by its (now canonical) bytes.
 *   3. the cofactored default: OpenSSL's yes is a yes - the cofactorless
 *      equation implies the cofactored one. Its no is not a no, since a
 *      key or an R with a small-order part can satisfy the cofactored
 *      equation alone, so a no is checked again in JavaScript.
 *
 * An honest signature takes OpenSSL's time in both modes; only a refused
 * one, in the default mode, also takes the pure verification's.
 * test/routing.test.mjs compares the two engines on ed25519-speccheck,
 * Wycheproof, and signatures built around every small-order point.
 */
var ED25519_P = (1n << 255n) - 19n;
var ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;
/* the eight points of order dividing 8, as their canonical encodings */
var ED25519_SMALL = {
    '0100000000000000000000000000000000000000000000000000000000000000': 1,
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a': 1,
    '0000000000000000000000000000000000000000000000000000000000000080': 1,
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05': 1,
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f': 1,
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85': 1,
    '0000000000000000000000000000000000000000000000000000000000000000': 1,
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa': 1
};
export var ed25519_small_order = Object.keys(ED25519_SMALL);
function le_value(b, mask_top) {
    var v = 0n;
    for (var i = b.length - 1; i >= 0; i--) { v = (v << 8n) | BigInt(i === b.length - 1 && mask_top ? b[i] & 0x7f : b[i]); }
    return v;
}
/* y < p, and not x = 0 written with the sign bit set (y = 1 or y = p - 1) */
function ed25519_canonical(b) {
    var y = le_value(b, true);
    return y < ED25519_P && !((b[31] & 0x80) && (y === 1n || y === ED25519_P - 1n));
}
function ed25519_small(b) { return ED25519_SMALL[Buffer.from(b).toString('hex')] === 1; }

/*
 * The verdict, given OpenSSL's key for pk (null when it would not import
 * one: not a point) and the pure verification to fall back on.
 */
function ed25519_verdict(msg, sig, pk, key, mode, pure_verify) {
    var R = sig.subarray(0, 32);
    if (!ed25519_canonical(pk) || !ed25519_canonical(R) || le_value(sig.subarray(32), false) >= ED25519_L) { return false; }
    if (mode === 'strict' && (ed25519_small(pk) || ed25519_small(R))) { return false; }
    var yes = false;
    if (key !== null) {
        try { yes = crypto.verify(null, msg, key, sig); } catch (e) { yes = false; }
    }
    if (yes || mode === 'strict') { return yes; }
    return pure_verify();
}
function ed25519_import(pk) {
    try { return public_key('ed25519', pk); } catch (e) { return null; }
}
/* any other mode is the pure form's error */
function ed25519_mode_ok(mode) { return mode === undefined || mode === 'cofactored' || mode === 'strict'; }
function no_context(ctx) { return ctx === undefined || ctx === null || (ctx instanceof Uint8Array && ctx.length === 0); }

function ed25519_verification(table) {
    /* verify(msg, sig, public_key, ctx, mode): plain Ed25519 only; Ed25519ctx and Ed25519ph stay pure */
    table.verify = {
        sync: function (msg, sig, pk, ctx, mode) {
            return ed25519_verdict(msg, sig, pk, ed25519_import(pk), mode, function () {
                return pure_ed25519.verify(msg, sig, pk, ctx, mode);
            });
        },
        accepts: function (args) {
            return args[0] instanceof Uint8Array && args[1] instanceof Uint8Array && args[1].length === 64 &&
                   args[2] instanceof Uint8Array && args[2].length === 32 && no_context(args[3]) && ed25519_mode_ok(args[4]);
        },
        /* a signature, and the same one with a bit flipped, in both modes: the pure verdicts */
        probe: function (pure) {
            for (var i = 0; i < 4; i++) {
                var args = ed25519_kat_args(i & 1, i & 2 ? 'strict' : undefined);
                if (this.sync.apply(null, args) !== pure.apply(null, args)) { return false; }
            }
            return true;
        }
    };
    /* verifier_create(public_key, ctx, variant, mode): the key imported, and checked, once */
    table.verifier = {
        create: function (pk, ctx, variant, mode) {
            var own = new Uint8Array(pk), key = ed25519_import(own), pure = null;
            return {
                verify: function (msg, sig) {
                    if (!(sig instanceof Uint8Array) || sig.length !== 64) { return false; }
                    return ed25519_verdict(msg, sig, own, key, mode, function () {
                        if (!pure) { pure = pure_ed25519.verifier_create(own, ctx, variant, mode); }
                        return pure.verify(msg, sig);
                    });
                }
            };
        },
        accepts: function (args) {
            return args[0] instanceof Uint8Array && args[0].length === 32 && no_context(args[1]) &&
                   (args[2] === undefined || args[2] === null || args[2] === 0) && ed25519_mode_ok(args[3]);
        },
        probe: function (pure_create) {
            var good = ed25519_kat_args(0)[1], bad = ed25519_kat_args(1)[1], pk = ed25519_kat_args(0)[2];
            for (var m = 0; m < 2; m++) {
                var mode = m ? 'strict' : undefined, v = this.create(pk, undefined, undefined, mode), p = pure_create(pk, undefined, undefined, mode);
                if (v.verify(MSG, good) !== true || p.verify(MSG, good) !== true || v.verify(MSG, bad) !== p.verify(MSG, bad)) { return false; }
            }
            return true;
        }
    };
}
/* verify's arguments for the checks: MSG, its signature by the seed fill(32, 3) - with flip 1, its first bit flipped - the key, and the mode */
var ed25519_material = null;
function ed25519_kat_args(flip, mode) {
    if (!ed25519_material) {
        var sk = fill(32, 3);
        ed25519_material = { sig: pure_ed25519.sign(MSG, sk), pk: pure_ed25519.get_public_key(sk) };
    }
    var sig = new Uint8Array(ed25519_material.sig);
    if (flip) { sig[0] ^= 1; }
    return [MSG, sig, ed25519_material.pk, undefined, mode];
}

function montgomery(kind) {
    /*
     * With keys of the right size, OpenSSL refuses only a result of all
     * zeros (a small-order peer, RFC 7748 section 6) - with an error whose
     * code differs between OpenSSL and BoringSSL. Whatever the error, the
     * pure function answers: those zeros from the unchecked form, null
     * from the _checked one, as it always does.
     */
    var pure_dh = pure_montgomery_of(kind);
    var dh = function (secret, u) {
        try {
            return u8(crypto.diffieHellman({ privateKey: private_key(kind, secret), publicKey: public_key(kind, u) }));
        } catch (e) {
            return pure_dh(secret, u);
        }
    };
    /* the checks' keys: ours, and a peer's secret and public key; and a small-order peer, u = 0 */
    var len = DER[kind].len, mine = fill(len, 3), theirs = fill(len, 9), their_pk = null;
    function peer() { return their_pk || (their_pk = pure_montgomery[kind].get_public_key(theirs)); }
    function agrees(pure) {
        var zero = new Uint8Array(len), a = this.sync(mine, peer()), b = this.sync(mine, zero);
        return eq(a, pure(mine, peer())) && (b === null ? pure(mine, zero) === null : eq(b, pure(mine, zero)));
    }
    return {
        dh: {
            sync: dh,
            accepts: function (args) { return sized(kind, args[0]) && sized(kind, args[1]); },
            probe: agrees
        },
        /* the pure _checked's null for the all-zero result of a small-order peer */
        dh_checked: {
            sync: function (secret, u) { var z = dh(secret, u); return all_zero(z) ? null : z; },
            accepts: function (args) { return sized(kind, args[0]) && sized(kind, args[1]); },
            probe: agrees
        },
        get_public_key: {
            sync: function (secret) { return raw_public(kind, private_key(kind, secret)); },
            accepts: function (args) { return sized(kind, args[0]); },
            kat: function () { return [mine]; }
        },
        /*
         * keygen() with the seed left out: OpenSSL draws the secret and
         * derives the public key in one call. Any 32 (56) bytes are an X25519
         * (X448) secret, so OpenSSL's are what the pure keygen would accept
         * as a seed, and its public key is the pure get_public_key's.
         */
        keygen: {
            sync: function () { var p = fresh_pair(kind); return { sk: p.sk, pk: p.pk }; },
            accepts: function (args) { return args[0] == null; },
            /* the pair OpenSSL drew: its public key is the pure one of its secret */
            probe: function () { var k = this.sync(); return eq(pure_montgomery[kind].get_public_key(k.sk), k.pk); }
        },
        /*
         * <kind>_create(secret?): the secret imported once - or drawn by
         * OpenSSL - and every agreement then skips the import, which costs
         * about as much as the agreement. A peer of the wrong size goes to
         * the pure context, made on first need, for its error.
         */
        context: {
            create: function (secret) {
                var sk, key, pk;
                if (secret == null) { var p = fresh_pair(kind); sk = p.sk; key = p.key; pk = p.pk; }
                else { sk = new Uint8Array(secret); key = private_key(kind, sk); pk = raw_public(kind, key); }
                var live = true, pure = null;
                function agree(peer, checked) {
                    if (!live) { throw new Error(kind + ': the context was wiped'); }
                    if (!sized(kind, peer)) {
                        if (!pure) { pure = pure_montgomery[kind][kind + '_create'](sk); }
                        return pure[checked ? kind + '_checked' : kind](peer);
                    }
                    var z;
                    try { z = u8(crypto.diffieHellman({ privateKey: key, publicKey: public_key(kind, peer) })); } catch (e) {
                        z = pure_dh(sk, peer);               /* a small-order peer: the pure answer, as dh above */
                    }
                    return checked && all_zero(z) ? null : z;
                }
                var ctx = { pk: pk, wipe: function () { sk.fill(0); key = null; live = false; if (pure) { pure.wipe(); } } };
                ctx[kind] = function (peer) { return agree(peer, false); };
                ctx[kind + '_checked'] = function (peer) { return agree(peer, true); };
                return ctx;
            },
            accepts: function (args) { return args[0] == null || sized(kind, args[0]); },
            /* from our secret, the pure context's answers; drawn by OpenSSL, the peer's pure agreement */
            probe: function (pure_create) {
                var p = peer(), zero = new Uint8Array(len), ctx = this.create(mine), fresh = this.create();
                return eq(ctx.pk, pure_create(mine).pk) &&
                       same_calls(ctx, pure_create(mine), [[kind, p], [kind + '_checked', p], [kind, zero], [kind + '_checked', zero]]) &&
                       eq(fresh[kind](p), pure_montgomery[kind][kind](theirs, fresh.pk));
            }
        }
    };
}
var pure_montgomery = { x25519: pure_x25519, x448: pure_x448 };
function pure_montgomery_of(kind) { return pure_montgomery[kind][kind]; }
function all_zero(b) { var acc = 0; for (var i = 0; i < b.length; i++) { acc |= b[i]; } return acc === 0; }
/* a fresh key pair from OpenSSL: its KeyObject, and both keys as bytes from one JWK export */
function fresh_pair(kind) {
    var key = crypto.generateKeyPairSync(kind).privateKey;
    var jwk = key.export({ format: 'jwk' });
    return { key: key, sk: u8(Buffer.from(jwk.d, 'base64url')), pk: u8(Buffer.from(jwk.x, 'base64url')) };
}

/* Registered as '<module>.<function>', the names api/<module>.js gives them. */
function register(module, table) {
    for (var fn in table) { ops[module + '.' + fn] = table[fn]; }
}
if (typeof crypto.diffieHellman === 'function') {
    var ed25519_ops = edwards('ed25519'), ed448_ops = edwards('ed448');
    register('ed25519', ed25519_ops);
    register('ed448', ed448_ops);
    var x25519_ops = montgomery('x25519'), x448_ops = montgomery('x448');
    register('x25519', { x25519: x25519_ops.dh, x25519_checked: x25519_ops.dh_checked, get_public_key: x25519_ops.get_public_key,
                         keygen: x25519_ops.keygen, x25519_create: x25519_ops.context });
    register('x448', { x448: x448_ops.dh, x448_checked: x448_ops.dh_checked, get_public_key: x448_ops.get_public_key,
                       keygen: x448_ops.keygen, x448_create: x448_ops.context });
}

/* ---------------- NIST curves ---------------- */
/*
 * ECDH only. ECDSA here signs a caller-made hash with an RFC 6979 nonce and
 * low-s; node:crypto hashes the message itself and draws a random nonce, so
 * its signatures would differ from the pure engine's, and it has no way to
 * verify a bare digest. ECDH is the x coordinate of one deterministic point,
 * the same bytes either way.
 */
/* the checks' secrets on a NIST curve: below the order, a leading zero byte seeing to it on P-521 */
function nist_secret(bytes, v) { var d = fill(bytes, v); d[0] = 0; return d; }
function nist_ecdh(curve, bytes, pure) {
    var peer = null;
    return {
        kat: function () { return [nist_secret(bytes, 3), peer || (peer = pure.get_public_key(nist_secret(bytes, 9)))]; },
        sync: function (secret, peer) {
            var e = crypto.createECDH(curve);
            e.setPrivateKey(secret);
            return u8(e.computeSecret(peer));
        },
        /*
         * The pure form's errors for a bad secret or peer point; OpenSSL's
         * differ in wording, so anything but a well-formed pair goes there.
         */
        accepts: function (args) {
            var s = args[0], q = args[1];
            if (!s || s.length !== bytes || !q) { return false; }
            if (!(q.length === 1 + 2 * bytes && q[0] === 4) && !(q.length === 1 + bytes && (q[0] === 2 || q[0] === 3))) { return false; }
            var nonzero = false;
            for (var i = 0; i < s.length; i++) { if (s[i]) { nonzero = true; break; } }
            return nonzero;
        }
    };
}
/*
 * get_public_key(secret, compressed): one deterministic point, the same
 * bytes either way. A secret that is not a valid scalar goes to the pure
 * form, for its error.
 */
function nist_public_key(curve, bytes, pure) {
    return {
        probe: function (pure_fn) {
            var d = nist_secret(bytes, 3);
            return eq(this.sync(d), pure_fn(d)) && eq(this.sync(d, false), pure_fn(d, false));
        },
        sync: function (secret, compressed) {
            var e = crypto.createECDH(curve);
            e.setPrivateKey(secret);
            return u8(e.getPublicKey(null, compressed === false ? 'uncompressed' : 'compressed'));
        },
        accepts: function (args) {
            return args[0] instanceof Uint8Array && args[0].length === bytes && pure.is_valid_secret(args[0]) &&
                   (args[1] === undefined || typeof args[1] === 'boolean');
        }
    };
}
/*
 * keygen() with the seed left out: OpenSSL draws d in [1, n - 1], as the
 * pure keygen does. getPrivateKey drops leading zero bytes, so d is padded
 * back to the curve's width; the public key is compressed, as the pure
 * keygen returns it.
 */
function nist_keygen(curve, bytes, pure) {
    return {
        /* the pair OpenSSL drew: its public key is the pure one of its secret */
        probe: function () { var k = this.sync(); return eq(pure.get_public_key(k.sk), k.pk); },
        sync: function () {
            var e = crypto.createECDH(curve);
            e.generateKeys();
            var d = e.getPrivateKey(), sk = new Uint8Array(bytes);
            sk.set(d, bytes - d.length);
            d.fill(0);
            return { sk: sk, pk: u8(e.getPublicKey(null, 'compressed')) };
        },
        accepts: function (args) { return args[0] == null; }
    };
}
/*
 * ecdh_create(secret?): the secret set into one ECDH object - or drawn by
 * OpenSSL - and each agreement computed with it. A peer point OpenSSL
 * refuses goes to the pure context, made on first need, for its error.
 */
function nist_context(curve, bytes, pure) {
    return {
        /* from our secret, the pure context's answers; drawn by OpenSSL, the peer's pure agreement */
        probe: function (pure_create) {
            var d = nist_secret(bytes, 3), e = nist_secret(bytes, 9), q = pure.get_public_key(e);
            var ctx = this.create(d), want = pure_create(d), fresh = this.create();
            return eq(ctx.pk, want.pk) && eq(ctx.pk_uncompressed, want.pk_uncompressed) && same_calls(ctx, want, [['ecdh', q]]) &&
                   eq(fresh.ecdh(q), pure.ecdh(e, fresh.pk));
        },
        create: function (secret) {
            var e = crypto.createECDH(curve), sk;
            if (secret == null) {
                e.generateKeys();
                var d = e.getPrivateKey();
                sk = new Uint8Array(bytes); sk.set(d, bytes - d.length); d.fill(0);
            } else {
                sk = new Uint8Array(secret); e.setPrivateKey(sk);
            }
            var live = true, fallback = null;
            return {
                pk: u8(e.getPublicKey(null, 'compressed')),
                pk_uncompressed: u8(e.getPublicKey(null, 'uncompressed')),
                ecdh: function (peer) {
                    if (!live) { throw new Error(curve + ': the context was wiped'); }
                    try { return u8(e.computeSecret(peer)); } catch (err) {
                        if (!fallback) { fallback = pure.ecdh_create(sk); }
                        return fallback.ecdh(peer);
                    }
                },
                wipe: function () { sk.fill(0); e = null; live = false; if (fallback) { fallback.wipe(); } }
            };
        },
        accepts: function (args) {
            return args[0] == null || (args[0] instanceof Uint8Array && args[0].length === bytes && pure.is_valid_secret(args[0]));
        }
    };
}
var NIST = [['prime256v1', 32, ['p256', 'prime256v1', 'secp256r1'], pure_nist.p256],
            ['secp384r1', 48, ['p384', 'secp384r1'], pure_nist.p384],
            ['secp521r1', 66, ['p521', 'secp521r1'], pure_nist.p521]];
var curves = crypto.getCurves();
for (var c = 0; c < NIST.length; c++) {
    if (curves.indexOf(NIST[c][0]) < 0) { continue; }
    /* one object per entry under each of the curve's names: checked once */
    var nist_ops = { ecdh: nist_ecdh(NIST[c][0], NIST[c][1], NIST[c][3]), get_public_key: nist_public_key(NIST[c][0], NIST[c][1], NIST[c][3]),
                     keygen: nist_keygen(NIST[c][0], NIST[c][1], NIST[c][3]), ecdh_create: nist_context(NIST[c][0], NIST[c][1], NIST[c][3]) };
    for (var a = 0; a < NIST[c][2].length; a++) { register(NIST[c][2][a], nist_ops); }
}

/* ---------------- Signatures over a whole message ---------------- */
/*
 * node:crypto hashes the message itself, so only the *_message forms can be
 * native - sign and verify take a digest, which it cannot be given.
 */
function b64url(bytes) { return Buffer.from(bytes).toString('base64url'); }
function big_bytes(x, len) {
    var hexs = x.toString(16);
    if (hexs.length % 2) { hexs = '0' + hexs; }
    var b = Buffer.from(hexs, 'hex');
    if (len === undefined || b.length === len) { return b; }
    if (b.length > len) { return null; }
    return Buffer.concat([Buffer.alloc(len - b.length), b]);
}

/*
 * ECDSA verification. The public key arrives as SEC 1 bytes, compressed or
 * not; wrapped in an SPKI structure OpenSSL takes either. The signature is
 * {r, s}, written as r || s.
 */
function der_length(n) {
    return n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
}
function der(tag, body) { return Buffer.concat([Buffer.from([tag]), der_length(body.length), body]); }
/* id-ecPublicKey, RFC 5480 */
var EC_PUBLIC_KEY = hex('06072a8648ce3d0201');
function ec_spki(curve_oid, point) {
    return der(0x30, Buffer.concat([
        der(0x30, Buffer.concat([EC_PUBLIC_KEY, curve_oid])),
        der(0x03, Buffer.concat([Buffer.from([0]), point]))
    ]));
}
/* the key as OpenSSL's, or null when it is not a point on the curve - the pure verdict on it is false too */
function ec_public(curve_oid, public_key) {
    try { return crypto.createPublicKey({ key: ec_spki(curve_oid, public_key), format: 'der', type: 'spki' }); } catch (e) { return null; }
}
/* a signature node:crypto can take: r and s positive BigInts */
function ec_sig_ok(sig) { return !!sig && typeof sig.r === 'bigint' && typeof sig.s === 'bigint' && sig.r > 0n && sig.s > 0n; }
function ec_key_ok(pk, bytes) {
    return pk instanceof Uint8Array && ((pk.length === 1 + 2 * bytes && pk[0] === 4) || (pk.length === 1 + bytes && (pk[0] === 2 || pk[0] === 3)));
}
function ec_verify_with(key, bytes, name, msg, sig) {
    var r = big_bytes(sig.r, bytes), s = big_bytes(sig.s, bytes);
    if (key === null || r === null || s === null) { return false; }
    return crypto.verify(name, msg, { key: key, dsaEncoding: 'ieee-p1363' }, Buffer.concat([r, s]));
}
/*
 * The ECDSA checks' material on a curve: the key of nist_secret(bytes, 3),
 * MSG's RFC 6979 signature by it over SHA-256, and that signature with s
 * changed - which no key verifies.
 */
var ecdsa_materials = [];
function ecdsa_material(curve, bytes) {
    for (var i = 0; i < ecdsa_materials.length; i++) { if (ecdsa_materials[i].curve === curve) { return ecdsa_materials[i]; } }
    var d = nist_secret(bytes, 3), sig = curve.sign_message(pure_sha256, MSG, d, new Uint8Array(0));
    var m = { curve: curve, d: d, pk: curve.get_public_key(d), sig: sig, bad: { r: sig.r, s: sig.s + 1n } };
    ecdsa_materials.push(m);
    return m;
}
/* a signature verifies, and the changed one does not */
function ecdsa_verifies(verify, m) { return verify(m.sig) === true && verify(m.bad) === false; }
/* sign(d) -> OpenSSL's signature of MSG over SHA-256: low s, and the pure code verifies it */
function ecdsa_signs(curve, bytes, sign) {
    var m = ecdsa_material(curve, bytes), sig = sign(m.d);
    return sig.s <= curve.CURVE.n >> 1n && curve.verify_message(pure_sha256, MSG, sig, m.pk) === true;
}
function ecdsa_verify_op(curve_oid, bytes, curve) {
    return {
        sync: function (hash, msg, sig, public_key) {
            return ec_verify_with(ec_public(curve_oid, public_key), bytes, hash_name_of(hash), msg, sig);
        },
        accepts: function (args) { return hash_name_of(args[0]) !== null && ec_sig_ok(args[2]) && ec_key_ok(args[3], bytes); },
        probe: function () {
            var op = this, m = ecdsa_material(curve, bytes);
            return ecdsa_verifies(function (sig) { return op.sync(pure_sha256, MSG, sig, m.pk); }, m);
        }
    };
}
/*
 * One public key for many verifications: imported into OpenSSL once.
 * verify_message is native where the one-shot would be; verify over a
 * digest, which node:crypto cannot take, and anything else go to the pure
 * verifier, made on first use - the same answers.
 */
function ecdsa_verifier(curve_oid, bytes, curve) {
    return {
        create: function (public_key) {
            var own = new Uint8Array(public_key), key = ec_public(curve_oid, own), pure = null;
            function fallback() { if (!pure) { pure = curve.verifier_create(own); } return pure; }
            return {
                verify: function (msg_hash, sig) { return fallback().verify(msg_hash, sig); },
                verify_message: function (hash, msg, sig) {
                    var name = msg instanceof Uint8Array && ec_sig_ok(sig) ? hash_name_of(hash) : null;
                    return name === null ? fallback().verify_message(hash, msg, sig) : ec_verify_with(key, bytes, name, msg, sig);
                }
            };
        },
        accepts: function (args) { return ec_key_ok(args[0], bytes); },
        probe: function () {
            var m = ecdsa_material(curve, bytes), v = this.create(m.pk);
            return ecdsa_verifies(function (sig) { return v.verify_message(pure_sha256, MSG, sig); }, m);
        }
    };
}
/*
 * ECDSA signing, when the caller left `extra` out: the signature is then
 * hedged with fresh randomness either way, and OpenSSL's is as good as
 * the pure form's (RFC 6979 with random k'). With extra given - bytes to
 * be deterministic over, or empty for classic RFC 6979 - the pure form
 * signs, because OpenSSL draws k itself.
 *
 * The secret arrives as its bytes and imports as an RFC 5915 ECPrivateKey
 * without the public key, which OpenSSL computes (ec_private). The result goes through
 * the curve's signature_from_rs: low s, as the pure form makes it, and
 * the recovery id worked out only if someone reads it.
 */
/*
 * ECPrivateKey (RFC 5915) without the public key, which OpenSSL computes,
 * inside PKCS #8 with the curve in its algorithm identifier (RFC 5480).
 * PKCS #8, not a bare ECPrivateKey: BoringSSL - Bun's node:crypto - refuses
 * a bare one that lacks the public key, and reads this form as OpenSSL does.
 */
function ec_private(curve_oid, secret) {
    var d = der_head(0x04, secret.length);
    var head = Buffer.concat([der_head(0x30, 3 + d.length + secret.length), hex('020101'), d]);
    return pkcs8_private(der(0x30, Buffer.concat([EC_PUBLIC_KEY, curve_oid])), head, secret);
}
/*
 * One ECDSA signature with an imported key: low s, as the pure form makes
 * it, and the public key the recovery id needs exported only if someone
 * reads recovery - a TLS signer never does, and the export cost three
 * times the signature.
 */
function ecdsa_sign_with(key, curve, bytes, name, msg) {
    /* r ‖ s as one hex string, cut in two: one conversion, not two */
    var rs = crypto.sign(name, msg, { key: key, dsaEncoding: 'ieee-p1363' }).toString('hex');
    return curve.signature_from_rs(one_hash(name, msg),
        BigInt('0x' + rs.slice(0, 2 * bytes)), BigInt('0x' + rs.slice(2 * bytes)),
        function () {
            var spki = crypto.createPublicKey(key).export({ format: 'der', type: 'spki' });
            return u8(spki.subarray(spki.length - 1 - 2 * bytes));
        });
}
function ecdsa_sign_op(curve_oid, bytes, curve) {
    return {
        sync: function (hash, msg, secret, extra) {
            if (!curve.is_valid_secret(secret)) { return curve.sign_message(hash.pure || hash, msg, secret, extra); }  /* its error */
            return ecdsa_sign_with(ec_private(curve_oid, secret), curve, bytes, hash_name_of(hash), msg);
        },
        accepts: function (args) {
            return args[3] == null && hash_name_of(args[0]) !== null && args[1] instanceof Uint8Array &&
                   args[2] instanceof Uint8Array && args[2].length === bytes;
        },
        probe: function () { var op = this; return ecdsa_signs(curve, bytes, function (d) { return op.sync(pure_sha256, MSG, d); }); }
    };
}
/*
 * [curve OID (DER), OpenSSL curve name, coordinate bytes, the library's
 *  names for it, the pure curve when signing natively pays]
 *
 * Only P-256 signs natively. Measured on Node 26 / OpenSSL 3.5, median of
 * 300 alternating runs, key import included:
 *
 *     p256          native 0.40 ms   pure 0.87 ms    OpenSSL's tuned P-256
 *     p384          native 3.53      pure 2.18
 *     p521          native 7.16      pure 4.09
 *     brainpool*    native 1.7-4.8   pure 0.9-2.9
 *     secp256k1     OpenSSL 0.42 against the pure form's 0.65 before the
 *                   import - no gain
 *
 * Verification is native on all of them: it was measured faster there.
 */
/*
 * signer_create(secret) on a NIST curve: the secret imported once, and
 * sign_message with the randomness left out signed by OpenSSL - with the
 * key held, it beats the pure form on all three curves (0.04 against 0.4
 * ms on P-256, 0.9 against 1.4 on P-384, 2.2 against 2.6 on P-521), where
 * a fresh import each call paid more than it saved on P-384 and P-521. A
 * digest to sign (sign), an `extra` (RFC 6979's, deterministic), or a hash
 * OpenSSL does not have, go to the pure signer the context also holds.
 */
function ecdsa_signer(curve_oid, bytes, curve) {
    return {
        create: function (secret) {
            var key = ec_private(curve_oid, secret), pure = curve.signer_create(secret);
            function live() { if (key === null) { throw new Error('ecdsa: the signer was wiped'); } }
            return {
                sign: function (msg_hash, extra) { live(); return pure.sign(msg_hash, extra); },
                sign_message: function (hash, msg, extra) {
                    live();
                    var name = extra == null && msg instanceof Uint8Array ? hash_name_of(hash) : null;
                    if (name !== null) { return ecdsa_sign_with(key, curve, bytes, name, msg); }
                    return pure.sign_message(hash, msg, extra);
                },
                wipe: function () { key = null; pure.wipe(); }
            };
        },
        /* an invalid secret: the pure form's error */
        accepts: function (args) { return args[0] instanceof Uint8Array && args[0].length === bytes && curve.is_valid_secret(args[0]); },
        probe: function () { var op = this; return ecdsa_signs(curve, bytes, function (d) { return op.create(d).sign_message(pure_sha256, MSG); }); }
    };
}
/*
 * [OID, OpenSSL's name, bytes, names here, the pure curve, whether a
 *  one-shot signature is native, whether a signer is]. A curve's entries
 * are one object under each of its names, so each is checked once.
 */
var ECDSA_CURVES = [[hex('06082a8648ce3d030107'), 'prime256v1', 32, ['p256', 'prime256v1', 'secp256r1'], pure_nist.p256, true, true],
                    [hex('06052b81040022'), 'secp384r1', 48, ['p384', 'secp384r1'], pure_nist.p384, false, true],
                    [hex('06052b81040023'), 'secp521r1', 66, ['p521', 'secp521r1'], pure_nist.p521, false, true],
                    [hex('06052b8104000a'), 'secp256k1', 32, ['secp256k1'], pure_secp256k1, false, false]];
for (var ej = 0; ej < ECDSA_CURVES.length; ej++) {
    var ec_row = ECDSA_CURVES[ej];
    if (curves.indexOf(ec_row[1]) < 0) { continue; }
    var ec_ops = {
        verify_message: ecdsa_verify_op(ec_row[0], ec_row[2], ec_row[4]),
        verifier_create: ecdsa_verifier(ec_row[0], ec_row[2], ec_row[4])
    };
    if (ec_row[5]) { ec_ops.sign_message = ecdsa_sign_op(ec_row[0], ec_row[2], ec_row[4]); }
    if (ec_row[6]) { ec_ops.signer_create = ecdsa_signer(ec_row[0], ec_row[2], ec_row[4]); }
    for (var en = 0; en < ec_row[3].length; en++) { register(ec_row[3][en], ec_ops); }
}

/* ---------------- ML-KEM and ML-DSA (FIPS 203, FIPS 204) ---------------- */
/*
 *     decaps        deterministic - the same shared secret, or the same
 *                   implicit-rejection secret, as the pure form
 *     verify        a yes or no
 *     encaps        only when the caller gave no m: Node draws its own, and
 *                   the pure form would have drawn one too
 *     sign          only when the caller gave no rnd, for the same reason -
 *                   Node's signature is always hedged with its own randomness
 *                   and ignores a request for the deterministic one
 *     keygen        ML-KEM, only when the caller gave no seed: Node hands back
 *                   the seed and ek, and the expanded dk is built from them
 *                   (ml_kem_keygen below)
 *     decaps_create ML-KEM's dk checked and imported once
 *
 * A caller's own seed, m or rnd, a deterministic signature, and ML-DSA's
 * keygen (its expanded secret key is not one Node hands back) stay in pure
 * JavaScript.
 *
 * The keys are the library's own bytes: a public key imports as raw bytes,
 * the expanded secret key as PKCS#8 in its expandedKey form
 * (draft-ietf-lamps-kyber-certificates, -dilithium-certificates).
 */
function nist_pq_oid(last) { return hex('0609608648016503040' + last); }
/* PKCS #8 with the expandedKey form (draft-ietf-lamps-kyber-certificates, -dilithium-certificates) */
function pq_private(oid, sk) {
    return pkcs8_private(der(0x30, oid), der_head(0x04, sk.length), sk);
}
/* [name here, Node's key type, the OID's last bytes, k, ciphertext bytes] */
var ML_KEM = [['ml_kem512', 'ml-kem-512', '401', 2, 768], ['ml_kem768', 'ml-kem-768', '402', 3, 1088], ['ml_kem1024', 'ml-kem-1024', '403', 4, 1568]];
/* [name here, Node's key type, public key bytes, the OID's last bytes, secret key bytes] */
var ML_DSA = [['ml_dsa44', 'ml-dsa-44', 1312, '311', 2560], ['ml_dsa65', 'ml-dsa-65', 1952, '312', 4032],
              ['ml_dsa87', 'ml-dsa-87', 2592, '313', 4896]];

/*
 * The checks' material, made by the pure code once per parameter set:
 * ML-KEM's key pair from a fixed seed and one encapsulation to it; ML-DSA's
 * key pair from a fixed seed, MSG's deterministic signature, and the same
 * with a byte changed.
 */
var pq_material = {};
function ml_kem_material(name) {
    if (!pq_material[name]) {
        var k = pure_ml_kem[name].keygen(fill(64, 3)), e = pure_ml_kem[name].encaps(k.ek, fill(32, 5));
        pq_material[name] = { ek: k.ek, dk: k.dk, ct: e.ct, ss: e.ss };
    }
    return pq_material[name];
}
function ml_dsa_material(name) {
    if (!pq_material[name]) {
        var seed = fill(32, 3), k = pure_ml_dsa[name].keygen(seed), sig = pure_ml_dsa[name].sign(k.sk, MSG, new Uint8Array(32));
        var bad = new Uint8Array(sig); bad[0] ^= 1;
        pq_material[name] = { seed: seed, sk: k.sk, pk: k.pk, sig: sig, bad: bad };
    }
    return pq_material[name];
}
/*
 * A context string node:crypto is given: none or an empty one always, and
 * up to 255 bytes where this platform takes one - context_ok, its check;
 * BoringSSL refuses the option.
 */
function ml_dsa_context_ok(ctx, context_ok) {
    if (ctx == null || (ctx instanceof Uint8Array && ctx.length === 0)) { return true; }
    return ctx instanceof Uint8Array && ctx.length <= 255 && context_ok();
}
function ml_dsa_context_check(name, oid) {
    return once(function () {
        var m = ml_dsa_material(name), ctx = fill(5, 7);
        var sig = u8(crypto.sign(null, MSG, { key: pq_private(oid, m.sk), context: ctx }));
        return pure_ml_dsa[name].verify(m.pk, MSG, sig, ctx) === true;
    });
}
/* sign(key) -> OpenSSL's signature of MSG; the pure code verifies it */
function ml_dsa_signs(name, sign, key_of) {
    var m = ml_dsa_material(name);
    return pure_ml_dsa[name].verify(m.pk, MSG, sign(key_of(m))) === true;
}

function ml_kem_encaps(name, type) {
    var pure = pure_ml_kem[name];
    return {
        /* OpenSSL's encapsulation to the checks' key: the pure decapsulation finds its secret */
        probe: function () { var m = ml_kem_material(name), r = this.sync(m.ek); return eq(pure.decaps(m.dk, r.ct), r.ss); },
        /* encaps(ek); a key failing FIPS 203's check gets the pure form's error */
        sync: function (ek) {
            if (!pure.check_ek(ek)) { return pure.encaps(ek); }
            var r = crypto.encapsulate(crypto.createPublicKey({ key: Buffer.from(ek), format: 'raw-public', asymmetricKeyType: type }));
            return { ct: u8(r.ciphertext), ss: u8(r.sharedKey) };
        },
        accepts: function (args) { return args[1] == null && args[0] instanceof Uint8Array; }
    };
}

function ml_dsa_sign(name, oid, sk_bytes, context_ok) {
    var pure = pure_ml_dsa[name];
    return {
        /* OpenSSL's own signature - sync() would hand a key it refuses to the pure form, and so pass */
        probe: function () { return ml_dsa_signs(name, function (sk) { return u8(crypto.sign(null, MSG, pq_private(oid, sk))); }, function (m) { return m.sk; }); },
        /* sign(sk, msg, rnd, ctx), rnd absent */
        sync: function (sk, msg, rnd, ctx) {
            var key;
            try {
                key = pq_private(oid, sk);
            } catch (e) {
                /* OpenSSL refuses a key the pure form signs with anyway: its answer, not a new error */
                return pure.sign(sk, msg, rnd, ctx);
            }
            return u8(crypto.sign(null, msg, { key: key, context: ctx || new Uint8Array(0) }));
        },
        /* a context over 255 bytes is the pure form's error; any context, where the platform takes none, the pure form's to sign */
        accepts: function (args) {
            return args[0] instanceof Uint8Array && args[0].length === sk_bytes &&
                   args[1] instanceof Uint8Array && args[2] == null && ml_dsa_context_ok(args[3], context_ok);
        }
    };
}

function ml_kem_decaps(name, oid, k, ct_bytes) {
    var dk_bytes = 768 * k + 96;
    return {
        kat: function () { var m = ml_kem_material(name); return [m.dk, m.ct]; },
        sync: function (dk, ct) {
            /* FIPS 203 section 7.3, as the pure form checks it, with its words */
            var ek = dk.subarray(384 * k, 768 * k + 32), h = dk.subarray(768 * k + 32, 768 * k + 64);
            if (!crypto.timingSafeEqual(crypto.createHash('sha3-256').update(ek).digest(), h)) {
                throw new Error('ml_kem: decapsulation key fails the FIPS 203 hash check');
            }
            var key = pq_private(oid, dk);
            return u8(crypto.decapsulate(key, ct));
        },
        /* other lengths: the pure form's own errors */
        accepts: function (args) {
            return args[0] instanceof Uint8Array && args[0].length === dk_bytes &&
                   args[1] instanceof Uint8Array && args[1].length === ct_bytes;
        }
    };
}

function ml_dsa_verify(name, type, pk_bytes, context_ok) {
    return {
        probe: function () {
            var m = ml_dsa_material(name);
            return this.sync(m.pk, MSG, m.sig) === true && this.sync(m.pk, MSG, m.bad) === false;
        },
        /* verify(pk, msg, sig, ctx) */
        sync: function (pk, msg, sig, ctx) {
            try {
                var key = crypto.createPublicKey({ key: Buffer.from(pk), format: 'raw-public', asymmetricKeyType: type });
                return crypto.verify(null, msg, { key: key, context: ctx || new Uint8Array(0) }, sig);
            } catch (e) {
                return false;   /* a signature that does not parse: the pure form says false too */
            }
        },
        /* a context over 255 bytes is the pure form's error; any context, where the platform takes none, the pure form's */
        accepts: function (args) {
            return args[0] instanceof Uint8Array && args[0].length === pk_bytes &&
                   args[1] instanceof Uint8Array && args[2] instanceof Uint8Array && ml_dsa_context_ok(args[3], context_ok);
        }
    };
}

/*
 * keygen() with the seed left out. OpenSSL draws the seed d || z and
 * computes ek = t || rho, the expensive half: A from rho, and A*s + e. The
 * expanded dk the library returns is s (from d alone, with no A), ek, H(ek)
 * and z - ml_kem.js's decapsulation_key, the same bytes as the pure
 * keygen(seed) of OpenSSL's seed.
 */
function ml_kem_keygen(name, type) {
    return {
        sync: function () {
            var pair = crypto.generateKeyPairSync(type);
            var seed = pair.privateKey.export({ format: 'raw-seed' });
            var ek = u8(pair.publicKey.export({ format: 'raw-public' }));
            try { return { ek: ek, dk: pure_ml_kem.decapsulation_key(name, seed, ek) }; } finally { seed.fill(0); }
        },
        accepts: function (args) { return args[0] == null; },
        /* the pair OpenSSL drew, in the pure code: an encapsulation to ek, and dk finds its secret */
        probe: function () {
            var k = this.sync(), e = pure_ml_kem[name].encaps(k.ek, fill(32, 5));
            return eq(pure_ml_kem[name].decaps(k.dk, e.ct), e.ss);
        }
    };
}
/*
 * decaps_create(dk?): dk checked (FIPS 203 section 7.3) and imported once -
 * or a fresh pair drawn by OpenSSL, whose dk is never needed here: OpenSSL
 * holds the key, and the context keeps no copy of it. A ciphertext of the
 * wrong length gets the pure form's error, which it raises before reading
 * the key.
 */
function ml_kem_context(name, type, oid, k, ct_bytes, fresh) {
    var pure = pure_ml_kem[name], dk_bytes = 768 * k + 96;
    return {
        create: function (dk) {
            var key, ek;
            if (dk == null) {
                var pair = crypto.generateKeyPairSync(type);
                key = pair.privateKey;
                ek = u8(pair.publicKey.export({ format: 'raw-public' }));
            } else {
                pure.decaps_create(dk).wipe();          /* its checks, and its errors */
                key = pq_private(oid, dk);
                ek = dk.slice(384 * k, 768 * k + 32);
            }
            return {
                ek: ek,
                decaps: function (ct) {
                    if (key === null) { throw new Error('ml_kem: the context was wiped'); }
                    if (!(ct instanceof Uint8Array) || ct.length !== ct_bytes) { return pure.decaps(new Uint8Array(dk_bytes), ct); }
                    return u8(crypto.decapsulate(key, ct));
                },
                wipe: function () { key = null; }
            };
        },
        accepts: function (args) {
            return args[0] == null ? fresh() : (args[0] instanceof Uint8Array && args[0].length === dk_bytes);
        },
        /* the checks' dk finds the pure encapsulation's secret; so does a fresh pair, where there is one */
        probe: function () {
            var m = ml_kem_material(name), ctx = this.create(m.dk);
            if (!eq(ctx.ek, m.ek) || !eq(ctx.decaps(m.ct), m.ss)) { return false; }
            if (!fresh()) { return true; }
            var mine = this.create(), e = pure.encaps(mine.ek, fill(32, 5));
            return eq(mine.decaps(e.ct), e.ss);
        }
    };
}
/*
 * Whether this platform draws a key pair of `type` and hands back its public
 * key as raw bytes - what a decaps_create() with no dk needs. Asked on the
 * first such call, not when this file loads.
 */
function fresh_pairs(type) {
    return once(function () { return crypto.generateKeyPairSync(type).publicKey.export({ format: 'raw-public' }).length > 0; });
}
/* registered where node:crypto has the calls at all; each entry's check says whether this parameter set works */
if (typeof crypto.decapsulate === 'function') {
    for (var mk = 0; mk < ML_KEM.length; mk++) {
        ops[ML_KEM[mk][0] + '.decaps'] = ml_kem_decaps(ML_KEM[mk][0], nist_pq_oid(ML_KEM[mk][2]), ML_KEM[mk][3], ML_KEM[mk][4]);
        ops[ML_KEM[mk][0] + '.decaps_create'] = ml_kem_context(ML_KEM[mk][0], ML_KEM[mk][1], nist_pq_oid(ML_KEM[mk][2]),
                                                             ML_KEM[mk][3], ML_KEM[mk][4], fresh_pairs(ML_KEM[mk][1]));
    }
}
if (typeof crypto.encapsulate === 'function') {
    for (var me = 0; me < ML_KEM.length; me++) {
        ops[ML_KEM[me][0] + '.encaps'] = ml_kem_encaps(ML_KEM[me][0], ML_KEM[me][1]);
        ops[ML_KEM[me][0] + '.keygen'] = ml_kem_keygen(ML_KEM[me][0], ML_KEM[me][1]);
    }
}
/*
 * signer_create(key) for ML-DSA: the expanded sk, or its 32-byte seed,
 * imported once. sign with the randomness left out is OpenSSL's (hedged,
 * as the pure form's is then); a caller's rnd - the deterministic variant
 * among them - and the pre-hash forms go to the pure signer, made on first
 * need (from a seed, that is a key generation in JavaScript). A key OpenSSL
 * will not import is the pure signer's alone.
 */
/* an ML-DSA private key as OpenSSL's: the 32-byte seed, or the expanded key */
function ml_dsa_key(type, oid, key) {
    return key.length === 32 ? crypto.createPrivateKey({ key: Buffer.from(key), format: 'raw-seed', asymmetricKeyType: type }) : pq_private(oid, key);
}
function ml_dsa_signer(name, type, oid, sk_bytes, context_ok) {
    var pure_set = pure_ml_dsa[name];
    return {
        /* from the expanded key and from the seed, as create() imports them: OpenSSL's signatures verify in the pure code */
        probe: function () {
            function sign(key) { return u8(crypto.sign(null, MSG, ml_dsa_key(type, oid, key))); }
            return ml_dsa_signs(name, sign, function (m) { return m.sk; }) && ml_dsa_signs(name, sign, function (m) { return m.seed; });
        },
        create: function (key) {
            var own = new Uint8Array(key), kobj = null, pure = null;
            try { kobj = ml_dsa_key(type, oid, own); } catch (e) { kobj = null; }
            var wiped = false;
            function fallback() {
                if (wiped) { throw new Error('ml_dsa: the signer was wiped'); }
                if (!pure) { pure = pure_set.signer_create(own); }
                return pure;
            }
            return {
                sign: function (msg, rnd, ctx) {
                    if (kobj !== null && !wiped && rnd == null && msg instanceof Uint8Array && ml_dsa_context_ok(ctx, context_ok)) {
                        return u8(crypto.sign(null, msg, { key: kobj, context: ctx || new Uint8Array(0) }));
                    }
                    return fallback().sign(msg, rnd, ctx);
                },
                hash_sign: function (msg, ph, rnd, ctx) { return fallback().hash_sign(msg, ph, rnd, ctx); },
                hash_sign_digest: function (digest, ph, rnd, ctx) { return fallback().hash_sign_digest(digest, ph, rnd, ctx); },
                wipe: function () { wiped = true; kobj = null; own.fill(0); if (pure) { pure.wipe(); } }
            };
        },
        /* other lengths: the pure form's error */
        accepts: function (args) { return args[0] instanceof Uint8Array && (args[0].length === sk_bytes || args[0].length === 32); }
    };
}
for (var md = 0; md < ML_DSA.length; md++) {
    if (typeof crypto.sign !== 'function') { break; }
    var dsa_name = ML_DSA[md][0], dsa_oid = nist_pq_oid(ML_DSA[md][3]), dsa_context_ok = ml_dsa_context_check(dsa_name, dsa_oid);
    ops[dsa_name + '.signer_create'] = ml_dsa_signer(dsa_name, ML_DSA[md][1], dsa_oid, ML_DSA[md][4], dsa_context_ok);
    ops[dsa_name + '.verify'] = ml_dsa_verify(dsa_name, ML_DSA[md][1], ML_DSA[md][2], dsa_context_ok);
    ops[dsa_name + '.sign'] = ml_dsa_sign(dsa_name, dsa_oid, ML_DSA[md][4], dsa_context_ok);
}

/*
 * rsa.signer_create(key): the key imported once, and the four signing
 * operations of the pure signer over OpenSSL's RSASP1 - the private
 * operation alone, blinded by OpenSSL (privateDecrypt with no padding).
 * The encoding (EMSA-PSS, EMSA-PKCS1-v1_5) is the pure code's, so the
 * output is the pure signer's byte for byte for the same salt, whoever
 * drew it; and the per-key setup OpenSSL does on a key's first use (its
 * Montgomery and blinding values, as much as a signature again) is paid
 * once instead of per call.
 */
/*
 * The RSA checks' material, from kat.js's RSA_KEY: its public half, MSG's
 * PSS and PKCS#1 v1.5 signatures by the pure code over SHA-256 (PSS with a
 * fixed salt), a 20-byte message and its OAEP encryption (a fixed seed).
 */
var rsa_material = null;
function rsa_kat() {
    if (!rsa_material) {
        var fixed = function (n) { return fill(n, 11); }, short = MSG.subarray(0, 20);
        rsa_material = {
            pub: pure_rsa.public_key(RSA_KEY),
            pss: pure_rsa.sign_pss_message(RSA_KEY, MSG, pure_sha256, fixed),
            pkcs1: pure_rsa.sign_pkcs1_message(RSA_KEY, MSG, pure_sha256),
            short: short,
            oaep: pure_rsa.encrypt_oaep(pure_rsa.public_key(RSA_KEY), short, pure_sha256, fixed)
        };
    }
    return rsa_material;
}
/* a signature with its first byte changed: no key verifies it */
function changed(sig) { var bad = new Uint8Array(sig); bad[0] ^= 1; return bad; }

ops['rsa.signer_create'] = {
    /* PKCS#1 v1.5 is the pure signer's bytes; PSS, with OpenSSL's salt, verifies in the pure code */
    probe: function (pure_create) {
        var m = rsa_kat(), s = this.create(RSA_KEY);
        return eq(s.sign_pkcs1_message(MSG, pure_sha256), pure_create(RSA_KEY).sign_pkcs1_message(MSG, pure_sha256)) &&
               pure_rsa.verify_pss_message(m.pub, MSG, s.sign_pss_message(MSG, pure_sha256), pure_sha256) === true;
    },
    create: function (key) {
        var kobj = rsa_private(key), size = rsa_bytes(key);
        var signer = pure_rsa.signer_with(key, function (em) {
            var input = Buffer.alloc(size);
            input.set(em, size - em.length);      /* EMSA-PSS is one byte shorter when modBits = 1 mod 8 */
            return u8(crypto.privateDecrypt({ key: kobj, padding: crypto.constants.RSA_NO_PADDING }, input));
        });
        var forget = signer.wipe;
        signer.wipe = function () { forget(); kobj = null; };
        return signer;
    },
    /* a key without its CRT values: the pure signer */
    accepts: function (args) { return rsa_key_ok(args[0], true); }
};

/* RSA: the key object {n, e, d, p, q, dp, dq, qinv} as a JWK. */
function rsa_public(key) {
    return crypto.createPublicKey({ format: 'jwk', key: { kty: 'RSA', n: b64url(big_bytes(key.n)), e: b64url(big_bytes(key.e)) } });
}
function rsa_private(key) {
    return crypto.createPrivateKey({ format: 'jwk', key: {
        kty: 'RSA', n: b64url(big_bytes(key.n)), e: b64url(big_bytes(key.e)), d: b64url(big_bytes(key.d)),
        p: b64url(big_bytes(key.p)), q: b64url(big_bytes(key.q)),
        dp: b64url(big_bytes(key.dp)), dq: b64url(big_bytes(key.dq)), qi: b64url(big_bytes(key.qinv)) } });
}
function rsa_key_ok(key, priv) {
    if (!key || typeof key.n !== 'bigint' || typeof key.e !== 'bigint') { return false; }
    return !priv || ['d', 'p', 'q', 'dp', 'dq', 'qinv'].every(function (k) { return typeof key[k] === 'bigint'; });
}
/* OpenSSL's key, or null when it refuses the numbers */
function rsa_public_or_null(key) { try { return rsa_public(key); } catch (e) { return null; } }
/* the verdict with OpenSSL's key; as the pure verifiers, never an exception on attacker input */
function rsa_verify_with(kobj, msg, sig, name, padding, salt) {
    try {
        var opts = { key: kobj, padding: padding };
        if (salt !== undefined) { opts.saltLength = salt; }
        return crypto.verify(name, msg, opts, sig);
    } catch (e) {
        return false;
    }
}
var PSS_PADDING = crypto.constants.RSA_PKCS1_PSS_PADDING, PKCS1_PADDING = crypto.constants.RSA_PKCS1_PADDING;
/* the pure default salt length is the digest size, never "any" */
function pss_salt(hash, salt_len) { return salt_len === undefined ? hash.DIGEST_SIZE || (hash.pure && hash.pure.DIGEST_SIZE) : salt_len; }
/* MGF1 over another hash (RFC 4055): node:crypto has no such option for an RSA key, so the pure form */
function same_mgf(hash, mgf_hash) { return mgf_hash == null || hash_name_of(mgf_hash) === hash_name_of(hash); }
ops['rsa.verify_pss_message'] = {
    probe: function () {
        var m = rsa_kat();
        return this.sync(m.pub, MSG, m.pss, pure_sha256) === true && this.sync(m.pub, MSG, changed(m.pss), pure_sha256) === false;
    },
    /* (key, msg, sig, hash, salt_len) */
    sync: function (key, msg, sig, hash, salt_len) {
        var kobj = rsa_public_or_null(key);
        return kobj !== null && rsa_verify_with(kobj, msg, sig, hash_name_of(hash), PSS_PADDING, pss_salt(hash, salt_len));
    },
    accepts: function (args) { return rsa_key_ok(args[0]) && hash_name_of(args[3]) !== null && args[2] instanceof Uint8Array && same_mgf(args[3], args[5]); }
};
ops['rsa.verify_pkcs1_message'] = {
    probe: function () {
        var m = rsa_kat();
        return this.sync(m.pub, MSG, m.pkcs1, pure_sha256) === true && this.sync(m.pub, MSG, changed(m.pkcs1), pure_sha256) === false;
    },
    sync: function (key, msg, sig, hash) {
        var kobj = rsa_public_or_null(key);
        return kobj !== null && rsa_verify_with(kobj, msg, sig, hash_name_of(hash), PKCS1_PADDING);
    },
    accepts: function (args) { return rsa_key_ok(args[0]) && hash_name_of(args[3]) !== null && args[2] instanceof Uint8Array; }
};
/*
 * One public key for many verifications: imported into OpenSSL once. The
 * _message forms are native where the one-shots would be; the digest forms,
 * which node:crypto cannot take, MGF1 over another hash, and a key OpenSSL
 * refuses go to the pure verifier - the same answers.
 */
ops['rsa.verifier_create'] = {
    probe: function () {
        var m = rsa_kat(), v = this.create(m.pub);
        return v.verify_pss_message(MSG, m.pss, pure_sha256) === true && v.verify_pss_message(MSG, changed(m.pss), pure_sha256) === false &&
               v.verify_pkcs1_message(MSG, m.pkcs1, pure_sha256) === true && v.verify_pkcs1_message(MSG, changed(m.pkcs1), pure_sha256) === false;
    },
    create: function (key) {
        var pure = pure_rsa.verifier_create(key), kobj = rsa_public_or_null(key);
        function native_name(sig, hash, mgf_hash) {
            return kobj !== null && sig instanceof Uint8Array && same_mgf(hash, mgf_hash) ? hash_name_of(hash) : null;
        }
        return {
            verify_pss: pure.verify_pss,
            verify_pkcs1: pure.verify_pkcs1,
            verify_pss_message: function (msg, sig, hash, salt_len, mgf_hash) {
                var name = native_name(sig, hash, mgf_hash);
                return name === null ? pure.verify_pss_message(msg, sig, hash, salt_len, mgf_hash)
                                     : rsa_verify_with(kobj, msg, sig, name, PSS_PADDING, pss_salt(hash, salt_len));
            },
            verify_pkcs1_message: function (msg, sig, hash) {
                var name = native_name(sig, hash);
                return name === null ? pure.verify_pkcs1_message(msg, sig, hash) : rsa_verify_with(kobj, msg, sig, name, PKCS1_PADDING);
            }
        };
    },
    accepts: function (args) { return rsa_key_ok(args[0]); }
};
/*
 * RSA with the randomness left to the platform - rng omitted or null, as
 * the library's rule has it. With the caller's rng each of these runs the
 * pure form, exact for that rng.
 *
 *   keygen          bits >= 512, e a safe integer. OpenSSL's primes, the key
 *                   in the pure form's shape: p > q, d = e^-1 mod lcm(p-1, q-1)
 *                   (FIPS 186-5 A.1.1) whatever OpenSSL chose, the CRT values
 *                   from that d
 *   sign_pss_message, encrypt_oaep, encrypt_pkcs1, decrypt_oaep
 *                   the same encodings; anything the pure form would refuse
 *                   (a message too long, a wrong ciphertext length) stays
 *                   with it, for its error
 */
function big_of(b64) { return BigInt('0x' + Buffer.from(b64, 'base64url').toString('hex')); }
function rsa_key_of(jwk, bits) {
    var e = big_of(jwk.e), p = big_of(jwk.p), q = big_of(jwk.q);
    if (p < q) { var t = p; p = q; q = t; }
    var order = (p - 1n) / gcd(p - 1n, q - 1n) * (q - 1n);
    var d = mod_inverse(e, order);
    return { n: p * q, e: e, d: d, p: p, q: q, dp: d % (p - 1n), dq: d % (q - 1n), qinv: mod_inverse(q, p),
             bits: bits, size: (bits + 7) >> 3 };
}
function rsa_keygen_opts(args) {
    return { modulusLength: args[0], publicExponent: args[2] === undefined ? 65537 : Number(args[2]) };
}
ops['rsa.keygen'] = {
    /* a 512-bit key from OpenSSL, in the pure shape: n = p q, and the pure code signs and verifies with it */
    probe: function () {
        var k = this.sync(512);
        return k.n === k.p * k.q &&
               pure_rsa.verify_pkcs1_message(pure_rsa.public_key(k), MSG, pure_rsa.sign_pkcs1_message(k, MSG, pure_sha256), pure_sha256) === true;
    },
    /* (bits, rng, e) */
    sync: function (bits, rng, e) {
        var k = crypto.generateKeyPairSync('rsa', rsa_keygen_opts([bits, rng, e]));
        return rsa_key_of(k.privateKey.export({ format: 'jwk' }), bits);
    },
    async: function (args, cb) {
        crypto.generateKeyPair('rsa', rsa_keygen_opts(args), function (err, pub, priv) {
            cb(err, err ? undefined : rsa_key_of(priv.export({ format: 'jwk' }), args[0]));
        });
    },
    accepts: function (args) {
        var e = args[2];
        return args[1] == null && typeof args[0] === 'number' && args[0] >= 512 && args[0] % 2 === 0 &&
               (e === undefined || (typeof e === 'bigint' && e >= 3n && e % 2n === 1n && e <= 0xffffffffn));
    }
};
function digest_size(hash) { return hash.DIGEST_SIZE || (hash.pure && hash.pure.DIGEST_SIZE); }
function rsa_bytes(key) { return (key.n.toString(2).length + 7) >> 3; }
ops['rsa.sign_pss_message'] = {
    probe: function () { return pure_rsa.verify_pss_message(rsa_kat().pub, MSG, this.sync(RSA_KEY, MSG, pure_sha256), pure_sha256) === true; },
    /* (key, msg, hash, rng, salt_len): the pure default salt length is the digest size */
    sync: function (key, msg, hash, rng, salt_len) {
        return u8(crypto.sign(hash_name_of(hash), msg, { key: rsa_private(key), padding: PSS_PADDING,
                                                         saltLength: salt_len === undefined ? digest_size(hash) : salt_len }));
    },
    accepts: function (args) {
        return args[3] == null && rsa_key_ok(args[0], true) && hash_name_of(args[2]) !== null && args[1] instanceof Uint8Array &&
               (args[4] === undefined || (typeof args[4] === 'number' && args[4] >= 0 &&
                                          args[4] <= rsa_bytes(args[0]) - digest_size(args[2]) - 2)) && same_mgf(args[2], args[5]);
    }
};
ops['rsa.encrypt_oaep'] = {
    probe: function () { var m = rsa_kat(); return eq(pure_rsa.decrypt_oaep(RSA_KEY, this.sync(m.pub, m.short, pure_sha256), pure_sha256), m.short); },
    /* (key, msg, hash, rng, label): one hash for OAEP and MGF1, as the pure form */
    sync: function (key, msg, hash, rng, label) {
        var opts = { key: rsa_public(key), padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: hash_name_of(hash) };
        if (label && label.length) { opts.oaepLabel = label; }
        return u8(crypto.publicEncrypt(opts, msg));
    },
    accepts: function (args) {
        return args[3] == null && rsa_key_ok(args[0]) && hash_name_of(args[2]) !== null && args[1] instanceof Uint8Array &&
               args[1].length <= rsa_bytes(args[0]) - 2 * digest_size(args[2]) - 2 && (args[4] == null || args[4] instanceof Uint8Array);
    }
};
ops['rsa.decrypt_oaep'] = {
    kat: function () { return [RSA_KEY, rsa_kat().oaep, pure_sha256]; },
    /* (key, ct, hash, rng, label): null on any failure, as the pure form */
    sync: function (key, ct, hash, rng, label) {
        var opts = { key: rsa_private(key), padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: hash_name_of(hash) };
        if (label && label.length) { opts.oaepLabel = label; }
        try { return u8(crypto.privateDecrypt(opts, ct)); } catch (e) { return null; }
    },
    accepts: function (args) {
        return args[3] == null && rsa_key_ok(args[0], true) && hash_name_of(args[2]) !== null && args[1] instanceof Uint8Array &&
               args[1].length === rsa_bytes(args[0]) && (args[4] == null || args[4] instanceof Uint8Array);
    }
};
ops['rsa.encrypt_pkcs1'] = {
    probe: function () { var m = rsa_kat(); return eq(pure_rsa.decrypt_pkcs1(RSA_KEY, this.sync(m.pub, m.short)), m.short); },
    /* (key, msg, rng) */
    sync: function (key, msg) {
        return u8(crypto.publicEncrypt({ key: rsa_public(key), padding: PKCS1_PADDING }, msg));
    },
    accepts: function (args) {
        return args[2] == null && rsa_key_ok(args[0]) && args[1] instanceof Uint8Array && args[1].length <= rsa_bytes(args[0]) - 11;
    }
};

/*
 * Paillier and ring-Pedersen keys, and CMP material, with the randomness
 * left to the platform and no progress callback: OpenSSL finds the primes
 * (crypto.generatePrime) and the pure form builds the key from them through
 * its own supplied-primes path, with every check it makes there.
 *
 * ⭐ THE PRIME SEARCH IS THE WHOLE COST. A pair of 512-bit safe primes:
 *   OpenSSL about 2.3 s against the pure search's minutes (344 s measured
 *   for one 1024-bit safe prime on a loaded machine). The callback forms
 *   draw the primes on Node's thread pool, in parallel, and leave the event
 *   loop free.
 */
function prime_opts(safe, blum) {
    return safe ? { safe: true, bigint: true } : blum ? { add: 4n, rem: 3n, bigint: true } : { bigint: true };
}
function distinct_primes(bits, opts) {
    var a = crypto.generatePrimeSync(bits, opts), b;
    do { b = crypto.generatePrimeSync(bits, opts); } while (b === a);
    return [a, b];
}
/* count primes of `bits`, in parallel; cb(err, [p...]) - all distinct */
function distinct_primes_async(bits, opts, count, cb) {
    var out = [], left = count, failed = false;
    function one() {
        crypto.generatePrime(bits, opts, function (err, p) {
            if (failed) { return; }
            if (err) { failed = true; cb(err); return; }
            if (out.indexOf(p) >= 0) { one(); return; }
            out.push(p);
            if (--left === 0) { cb(null, out); }
        });
    }
    for (var i = 0; i < count; i++) { one(); }
}
function safe_pair(p) { return { p: p, q: (p - 1n) >> 1n }; }
/* the entries' check: OpenSSL's primes of each kind asked for - safe, 3 mod 4, plain - are primes to the pure test */
var primes_ok = once(function () {
    var safe = crypto.generatePrimeSync(64, prime_opts(true)), blum = crypto.generatePrimeSync(64, prime_opts(false, true));
    var plain = crypto.generatePrimeSync(64, prime_opts());
    return is_probable_prime(safe) && is_probable_prime((safe - 1n) >> 1n) && blum % 4n === 3n && is_probable_prime(blum) && is_probable_prime(plain);
});

function paillier_from(bits, opts, primes) {
    return pure_paillier.keygen(bits, null, { safe: opts && opts.safe, blum: opts && opts.blum, primes: primes });
}
ops['paillier.keygen'] = {
    probe: primes_ok,
    /* (bits, rng, opts) */
    sync: function (bits, rng, opts) {
        var o = prime_opts(opts && opts.safe, opts && opts.blum);
        for (;;) {   /* a pair assemble refuses (vanishingly rare) is replaced */
            try { return paillier_from(bits, opts, distinct_primes(bits >> 1, o)); } catch (e) {
                if (!/unusable/.test(e.message)) { throw e; }
            }
        }
    },
    async: function (args, cb) {
        var bits = args[0], opts = args[2];
        distinct_primes_async(bits >> 1, prime_opts(opts && opts.safe, opts && opts.blum), 2, function (err, ps) {
            if (err) { cb(err); return; }
            try { cb(null, paillier_from(bits, opts, ps)); } catch (e) {
                if (/unusable/.test(e.message)) { ops['paillier.keygen'].async(args, cb); } else { cb(e); }
            }
        });
    },
    accepts: function (args) {
        var opts = args[2];
        return args[1] == null && typeof args[0] === 'number' && args[0] >= 512 &&
               !(opts && (opts.primes || opts.onCandidate));
    }
};
ops['ring_pedersen.keygen'] = {
    probe: primes_ok,
    /* (bits, rng, onCandidate, primes) */
    sync: function (bits) {
        var ps = distinct_primes(bits >> 1, prime_opts(true));
        return pure_ring_pedersen.keygen(bits, null, undefined, [safe_pair(ps[0]), safe_pair(ps[1])]);
    },
    async: function (args, cb) {
        distinct_primes_async(args[0] >> 1, prime_opts(true), 2, function (err, ps) {
            if (err) { cb(err); return; }
            try { cb(null, pure_ring_pedersen.keygen(args[0], null, undefined, [safe_pair(ps[0]), safe_pair(ps[1])])); } catch (e) { cb(e); }
        });
    },
    accepts: function (args) {
        return args[1] == null && !args[2] && !args[3] && typeof args[0] === 'number' && args[0] >= 512;
    }
};
function material_from(params, ps, rps) {
    var bits = params.bits, rp_bits = params.rpBits || bits, safe = params.safe === undefined ? true : !!params.safe;
    return {
        paillier: pure_paillier.keygen(bits, null, { safe: safe, primes: ps }),
        ring_pedersen: pure_ring_pedersen.keygen(rp_bits, null, undefined, [safe_pair(rps[0]), safe_pair(rps[1])])
    };
}
ops['material.generate_material'] = {
    probe: primes_ok,
    /* (params): bits, rpBits, rng, safe, onProgress */
    sync: function (params) {
        var safe = params.safe === undefined ? true : !!params.safe;
        return material_from(params, distinct_primes(params.bits >> 1, prime_opts(safe)),
                             distinct_primes((params.rpBits || params.bits) >> 1, prime_opts(true)));
    },
    async: function (args, cb) {
        var params = args[0], safe = params.safe === undefined ? true : !!params.safe;
        distinct_primes_async(params.bits >> 1, prime_opts(safe), 2, function (err, ps) {
            if (err) { cb(err); return; }
            distinct_primes_async((params.rpBits || params.bits) >> 1, prime_opts(true), 2, function (err2, rps) {
                if (err2) { cb(err2); return; }
                try { cb(null, material_from(params, ps, rps)); } catch (e) { cb(e); }
            });
        });
    },
    accepts: function (args) {
        var p = args[0];
        return !!p && p.rng == null && !p.onProgress && typeof p.bits === 'number' && p.bits >= 512;
    }
};

/* PKCS#1 v1.5 signing is deterministic, so OpenSSL's bytes are the pure form's */
ops['rsa.sign_pkcs1_message'] = {
    kat: function () { return [RSA_KEY, MSG, pure_sha256]; },
    sync: function (key, msg, hash) {
        return u8(crypto.sign(hash_name_of(hash), msg, { key: rsa_private(key), padding: PKCS1_PADDING }));
    },
    accepts: function (args) { return rsa_key_ok(args[0], true) && hash_name_of(args[2]) !== null; }
};
