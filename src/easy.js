/**
 * The convenient API
 *
 * Four functions for the two things people reach for a crypto library to do,
 * with every parameter already decided:
 *
 *     hash_password(password)             ->  a string to store
 *     verify_password(password, stored)   ->  true or false
 *
 *     seal_with_password(password, data)  ->  bytes
 *     open_with_password(password, bytes) ->  data, or null
 *
 * ==================== WHY THIS EXISTS ====================
 *
 * The rest of this library asks the caller for a salt, a nonce, a cost
 * parameter and a KDF. That is right for someone who knows what they are
 * choosing and wrong for someone who does not - and the library people
 * reached for instead was CryptoJS, whose one-line API hid MD5 with a single
 * iteration and CBC with no authentication.
 *
 * THE ANSWER IS NOT TO REFUSE A ONE-LINE API. It is to make the decisions
 * hidden behind it good ones, and to write down what they were. Every choice
 * below is stated, along with what it costs.
 *
 * ==================== WHAT WAS CHOSEN ====================
 *
 *     Key derivation   Argon2id, m=64 MiB, t=3, p=1
 *     Cipher           ChaCha20-Poly1305
 *     Salt             16 bytes, fresh per call
 *     Nonce            12 bytes, fresh per call
 *
 * ARGON2id RATHER THAN PBKDF2 OR BCRYPT: it is memory-hard, so the attacker's
 * GPU advantage is bounded by memory bandwidth rather than by core count.
 * 64 MiB takes roughly a tenth of a second here and makes a large parallel
 * attack expensive; a server hashing many passwords at once may want less,
 * and should call argon2.js directly rather than guessing at these.
 *
 * CHACHA20-POLY1305 RATHER THAN AES-GCM: it needs no lookup tables, so it
 * carries none of the cache-timing exposure a software AES does, and it is
 * faster here than this library's AES. On hardware with AES-NI the ordering
 * reverses - but this code cannot know, and the safe default is the one that
 * has no table.
 *
 * ==================== THE VERSION BYTE ====================
 *
 * Every sealed blob starts with a version, and that is the difference between
 * this and the format CryptoJS shipped. When Argon2 is superseded, a new
 * version can be written while old blobs still open - without it, changing
 * anything means every existing ciphertext becomes unreadable.
 *
 * ==================== WHAT THIS DOES NOT DO ====================
 *
 * NO STREAMING. Everything is held in memory, so a file larger than the
 * available heap will not work. Chunked encryption needs a framing decision -
 * how large a chunk, how chunks are ordered, what stops one being dropped -
 * and that is a protocol rather than a default.
 *
 * NO KEY SHARING. Sealing to a public key so that only its holder can open it
 * is hpke.js, which is already a single call.
 *
 * NO PASSWORD STRENGTH CHECK. Argon2id makes guessing expensive; it cannot
 * make "password123" safe.
 */

import { argon2id_task } from './argon2.js';
import { finish_task, map_task, done_task } from './commons/task.js';
import { chacha20poly1305_encrypt, chacha20poly1305_decrypt } from './chacha.js';
import { equal_bool } from './commons/ct.js';
import { concat, secure_random, to_base64, from_base64, text_or_bytes } from './commons/bytes.js';

/** m in KiB, as Argon2 counts it - 65536 KiB is 64 MiB. */
export var MEMORY_KIB = 65536;
export var TIME_COST = 3;
export var PARALLELISM = 1;
export var SALT_BYTES = 16;

var VERSION = 1;

var to_bytes = text_or_bytes;

/*
 * Each operation here is a task (commons/task.js) around one Argon2id run,
 * so its callback form runs in slices like argon2's. `kdf`, the last
 * parameter of each *_task, is the Argon2id task to run - left out, the
 * pure one; engines/node.js passes node:crypto's.
 */
function kdf_task(kdf, o) { return kdf ? kdf(o) : argon2id_task(o); }

/*
 * base64 without padding, for the PHC string format - commons/bytes.js's
 * codec both ways.
 *
 * ⚠ THE DECODER USED TO BE ITS OWN AND LENIENT: it accepted a length of
 *   1 mod 4 and non-zero trailing bits, so several strings decoded to the
 *   same salt or hash - a stored hash had more than one spelling. One strict
 *   decoder now, the library's.
 */
function b64_encode(bytes) {
    return to_base64(bytes).replace(/=+$/, '');
}

function b64_decode(str) { return from_base64(str); }

/* ---------------- password storage ---------------- */

/**
 * Hash a password for storage.
 *
 * @param  {string|Uint8Array} password
 * @param  {object} [opts]  {m, t, p} to override the defaults - raise them,
 *                          not lower them, unless something is measured
 * @return {string} the PHC string format:
 *                  $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
 *
 * THE PARAMETERS ARE STORED IN THE STRING, which is what lets them change
 * later: an old hash still verifies with the cost it was made at, and a new
 * one uses the new cost. A bare hash with the parameters in code cannot do
 * that.
 */
export function hash_password(password, opts) {
    return finish_task(hash_password_task(password, opts));
}
export function hash_password_task(password, opts, kdf) {
    var o = opts || {};
    var m = o.m || MEMORY_KIB;
    var t = o.t || TIME_COST;
    var p = o.p || PARALLELISM;

    var salt = secure_random(SALT_BYTES);
    return map_task(kdf_task(kdf, {
        password: to_bytes(password), salt: salt,
        m: m, t: t, p: p, length: 32
    }), function (h) {
        return '$argon2id$v=19$m=' + m + ',t=' + t + ',p=' + p + '$' +
               b64_encode(salt) + '$' + b64_encode(h);
    });
}

/**
 * Check a password against a stored hash.
 *
 * @return {boolean} false on a malformed string rather than throwing - a
 *         corrupted row should reject the login, not crash the request
 */
export function verify_password(password, stored) {
    return finish_task(verify_password_task(password, stored));
}
export function verify_password_task(password, stored, kdf) {
    try {
        if (typeof stored !== 'string') { return done_task(false); }
        var m = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/
                .exec(stored);
        if (!m) { return done_task(false); }

        var salt = b64_decode(m[4]);
        var expect = b64_decode(m[5]);
        if (salt === null || expect === null || expect.length === 0) { return done_task(false); }

        return map_task(kdf_task(kdf, {
            password: to_bytes(password), salt: salt,
            m: parseInt(m[1], 10), t: parseInt(m[2], 10), p: parseInt(m[3], 10),
            length: expect.length
        }), function (h) { return equal_bool(h, expect); });
    } catch (err) {
        return done_task(false);   /* parameters Argon2 refuses: a malformed row */
    }
}

/**
 * Whether a stored hash was made with weaker parameters than the current
 * defaults - the signal to re-hash on next successful login.
 */
export function needs_rehash(stored, opts) {
    var o = opts || {};
    var m = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(stored);
    if (!m) { return true; }
    return parseInt(m[1], 10) < (o.m || MEMORY_KIB) ||
           parseInt(m[2], 10) < (o.t || TIME_COST);
}

/* ---------------- encryption with a password ---------------- */

/**
 * Encrypt data under a password.
 *
 *     version(1) || salt(16) || nonce(12) || ciphertext+tag(n+16)
 *
 * 45 bytes of overhead. The salt and nonce are both fresh on every call, so
 * sealing the same data twice gives different bytes - which is required, not
 * incidental: a repeated nonce under one key breaks ChaCha20-Poly1305
 * completely.
 *
 * @return {Uint8Array}
 */
export function seal_with_password(password, data, opts) {
    return finish_task(seal_with_password_task(password, data, opts));
}
export function seal_with_password_task(password, data, opts, kdf) {
    var o = opts || {};
    var m = o.m || MEMORY_KIB;
    var t = o.t || TIME_COST;
    var p = o.p || PARALLELISM;

    var salt = secure_random(SALT_BYTES);
    var nonce = secure_random(12);
    return map_task(kdf_task(kdf, {
        password: to_bytes(password), salt: salt,
        m: m, t: t, p: p, length: 32
    }), function (key) {
        /*
         * The header is authenticated as associated data, so the parameters
         * and the salt cannot be altered without the tag failing. Without
         * that, an attacker could lower the recorded cost and make an
         * offline attack cheaper for whoever opens the blob next.
         */
        var header = concat([new Uint8Array([VERSION]), salt, nonce]);
        var ct = chacha20poly1305_encrypt(key, nonce, to_bytes(data), header);
        return concat([header, ct]);
    });
}

/**
 * @return {Uint8Array|null} null when the password is wrong, the data was
 *         altered, or the container is malformed - the three are deliberately
 *         indistinguishable, because telling them apart tells an attacker
 *         which one they got right
 */
export function open_with_password(password, sealed, opts) {
    return finish_task(open_with_password_task(password, sealed, opts));
}
export function open_with_password_task(password, sealed, opts, kdf) {
    try {
        if (!sealed || sealed.length < 45) { return done_task(null); }
        if (sealed[0] !== VERSION) { return done_task(null); }

        var o = opts || {};
        var salt = sealed.subarray(1, 17);
        var nonce = sealed.subarray(17, 29);
        var header = sealed.subarray(0, 29);
        var body = sealed.subarray(29);

        return map_task(kdf_task(kdf, {
            password: to_bytes(password), salt: salt,
            m: o.m || MEMORY_KIB, t: o.t || TIME_COST, p: o.p || PARALLELISM,
            length: 32
        }), function (key) { return chacha20poly1305_decrypt(key, nonce, body, header); });
    } catch (err) {
        return done_task(null);
    }
}
