/**
 * bcryptjs compatibility
 *
 * A drop-in replacement for bcryptjs, backed by this library:
 *
 *     import bcrypt from 'bcryptjs';
 *     import bcrypt from 'cryptographic-primitives/compat/bcrypt.js';
 *
 * ==================== WHY THIS IS A REAL DROP-IN ====================
 *
 * The output is the standard modular crypt format - $2b$10$... - which is the
 * same string OpenBSD, bcryptjs, node-bcrypt and every other implementation
 * produce. Hashes made by any of them verify here and vice versa, so a
 * migration is a changed import and nothing else. No re-hashing, no dual-read
 * period, no format column in the database.
 *
 * That is the test this library applies before offering a shim at all: if the
 * bytes differed, "drop-in" would mean code that compiles and then rejects
 * every existing password. See compat/cryptojs.js, which is read-only for
 * exactly that reason.
 *
 * ========================= WHAT DIFFERS =========================
 *
 * THE ASYNC FUNCTIONS ARE NOT ASYNC HERE. bcryptjs splits its work across
 * setImmediate callbacks so a browser stays responsive; this computes
 * synchronously and then calls the callback. The signatures match and
 * promises still resolve, but a long cost factor will block.
 *
 * That is a deliberate limit rather than an oversight: chunking the work
 * would mean reimplementing the Blowfish key schedule as a resumable state
 * machine, and the honest fix for a browser is a Worker, which the caller
 * controls and this file cannot.
 *
 * THE SHAPE IS READY FOR IT THOUGH. hash() and compare() already return a
 * promise when no callback is given and invoke the callback when one is, so
 * making the work genuinely asynchronous later - a Worker, or a resumable
 * schedule - changes nothing a caller can observe except that it stops
 * blocking. No signature has to change.
 *
 * setRandomFallback is not provided. bcryptjs needed it before
 * crypto.getRandomValues was universal.
 *
 * ============================ A WARNING ============================
 *
 * BCRYPT TRUNCATES AT 72 BYTES, silently, in every implementation. A
 * passphrase longer than that has its tail ignored, so two different long
 * passwords can share a hash. `truncates()` reports whether a given input is
 * affected, mirroring bcryptjs - but the right answer for new work is Argon2,
 * which has no such limit. See src/easy.js.
 */

import { bcrypt as bcrypt_hash, bcrypt_verify, bcrypt_base64_encode, bcrypt_base64_decode }
    from '../bcrypt.js';
import { platform_random, text_or_bytes } from './_common.js';

/*
 * bcrypt's own base64 alphabet is NOT the standard one - the ordering differs
 * and a standard decoder produces the wrong salt bytes.
 *
 * ⭐ THE CODEC IS bcrypt.js's, which is commons/bytes.js's base64 over the
 *   bcrypt alphabet. This file used to carry its own encoder and decoder,
 *   copies of the ones bcrypt.js had then. bcryptjs decodes leniently - it
 *   stops at the first bad character and returns what it has, where
 *   bcrypt.js throws - so the decoder is asked for its lenient form.
 */
function encode_b64(bytes) { return bcrypt_base64_encode(bytes, bytes.length); }

function decode_b64(str, len) { return bcrypt_base64_decode(str, len, true); }

/* strings as UTF-8, as bcryptjs does - the one compat helper */
var to_bytes = text_or_bytes;

/**
 * Generate a salt string, in the $2b$cost$salt form bcryptjs returns.
 *
 * The COST IS LOGARITHMIC: each increment doubles the work. 10 was the
 * default for years and is now on the low side; 12 is a reasonable current
 * choice, and above about 14 a login becomes noticeable.
 */
export function genSaltSync(rounds) {
    var cost = rounds === undefined ? 10 : rounds;
    if (cost < 4 || cost > 31) { throw new Error('bcrypt: cost must be 4..31'); }
    var salt = platform_random(16);
    return '$2b$' + (cost < 10 ? '0' + cost : '' + cost) + '$' + encode_b64(salt);
}

/** The callback form. Computed synchronously - see the note at the top. */
export function genSalt(rounds, cb) {
    var r = rounds, callback = cb;
    if (typeof rounds === 'function') { callback = rounds; r = 10; }
    if (!callback) {
        return new Promise(function (res, rej) {
            try { res(genSaltSync(r)); } catch (e) { rej(e); }
        });
    }
    try { callback(null, genSaltSync(r)); } catch (e) { callback(e); }
}

/**
 * Hash a password.
 *
 * `salt` may be a full $2b$ string, a salt-only string, or a cost number -
 * all three of which bcryptjs accepts.
 */
export function hashSync(password, salt) {
    var s = salt === undefined ? genSaltSync(10) : salt;
    if (typeof s === 'number') { s = genSaltSync(s); }
    if (typeof s !== 'string') { throw new Error('bcrypt: salt must be a string or a cost'); }

    /* $2a$, $2b$ and $2y$: $2x$ is crypt_blowfish's marker for its old
       sign-extension BUG, and this computes the correct hash, so it must not
       label one $2x$ */
    var m = /^\$2([aby])\$(\d\d)\$([./A-Za-z0-9]{22})/.exec(s);
    if (!m) { throw new Error('bcrypt: malformed salt'); }
    var cost = parseInt(m[2], 10);
    var salt_bytes = decode_b64(m[3], 16);
    if (salt_bytes.length !== 16) { throw new Error('bcrypt: malformed salt'); }

    /* ⚠ THE SALT'S MINOR VERSION IS KEPT, as bcryptjs does: hashSync(pw,
       '$2a$...') returns '$2a$...'. The hash bytes are the same for $2a$,
       $2b$ and $2y$; only the label differed, and it used to come back $2b$. */
    var out = bcrypt_hash(to_bytes(password), salt_bytes, cost);
    return '$2' + m[1] + out.slice(3);
}

export function hash(password, salt, cb) {
    if (!cb) {
        return new Promise(function (res, rej) {
            try { res(hashSync(password, salt)); } catch (e) { rej(e); }
        });
    }
    try { cb(null, hashSync(password, salt)); } catch (e) { cb(e); }
}

/**
 * Check a password against a hash.
 *
 * RETURNS FALSE RATHER THAN THROWING on a malformed hash, which is what
 * bcryptjs does and what a login path needs - a corrupted database row should
 * reject the login, not crash the request.
 */
export function compareSync(password, hashed) {
    try {
        if (typeof hashed !== 'string' || hashed.length < 60) { return false; }
        return bcrypt_verify(to_bytes(password), hashed);
    } catch (err) {
        return false;
    }
}

export function compare(password, hashed, cb) {
    if (!cb) {
        return new Promise(function (res) { res(compareSync(password, hashed)); });
    }
    try { cb(null, compareSync(password, hashed)); } catch (e) { cb(e); }
}

/** The cost factor embedded in a hash. */
export function getRounds(hashed) {
    var m = /^\$2[abxy]\$(\d\d)\$/.exec(hashed);
    if (!m) { throw new Error('bcrypt: malformed hash'); }
    return parseInt(m[1], 10);
}

/** The salt portion, including the $2b$cost$ prefix, as bcryptjs returns it. */
export function getSalt(hashed) {
    if (typeof hashed !== 'string' || hashed.length < 29) {
        throw new Error('bcrypt: malformed hash');
    }
    return hashed.substring(0, 29);
}

/**
 * Whether this password would be silently truncated.
 *
 * BCRYPT IGNORES EVERYTHING PAST 72 BYTES. Two passphrases sharing a 72-byte
 * prefix produce the same hash, which is a genuine weakness for the long
 * passphrases users are now encouraged to choose - and it cannot be fixed
 * within bcrypt.
 */
export function truncates(password) {
    return to_bytes(password).length > 72;
}

export function encodeBase64(bytes, length) {
    return encode_b64(bytes.subarray ? bytes.subarray(0, length) : bytes.slice(0, length));
}

export function decodeBase64(str, length) { return decode_b64(str, length); }

export default {
    genSaltSync: genSaltSync,
    genSalt: genSalt,
    hashSync: hashSync,
    hash: hash,
    compareSync: compareSync,
    compare: compare,
    getRounds: getRounds,
    getSalt: getSalt,
    truncates: truncates,
    encodeBase64: encodeBase64,
    decodeBase64: decodeBase64
};
