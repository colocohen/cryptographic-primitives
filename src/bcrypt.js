/**
 * bcrypt  -  Provos & Mazieres, 1999
 *
 * The oldest of the password hashes still in wide use, and the only one here
 * that shares no code with anything else in the library: it is built on
 * Blowfish, which appears nowhere else.
 *
 * Its idea was the "expensive key schedule". Blowfish's key setup is unusually
 * slow because it fills a 4 KiB table of S-boxes, and bcrypt runs that setup
 * 2^cost times before encrypting a fixed string. Raising cost by one doubles
 * the work.
 *
 * WHERE IT STANDS TODAY
 * The 4 KiB working set was large in 1999 and is nothing now - it fits in
 * every core's L1 cache, so a GPU or FPGA parallelises bcrypt far better than
 * it does scrypt or Argon2. bcrypt is still respectable and still far better
 * than a bare hash, but for new designs Argon2id is the answer.
 *
 * THE 72-BYTE LIMIT
 * bcrypt silently ignores everything past the 72nd byte of the password.
 * A 100-character passphrase and its first 72 characters produce the same
 * hash. This is not an implementation shortcut - it is how the key schedule
 * works, and every bcrypt implementation does it. Anything that pre-hashes
 * passwords into bcrypt has to be careful here: feeding it base64 of a SHA-256
 * is fine, feeding it raw bytes that may contain a zero is not, because the
 * key is null-terminated.
 *
 * The Blowfish machinery itself - the pi-derived tables, the block function
 * and the standard key schedule - lives in commons/blowfish.js, shared with
 * the Blowfish cipher. What stays here is the SALTED expansion and the cost
 * loop, which are exactly what turns Blowfish into bcrypt.
 */

import { equal } from './commons/ct.js';
import { sha512 } from './sha2.js';
import { wr_be32, wr_le32, b64_encode, b64_decode } from './commons/bytes.js';
import { finish_task, map_task, done_task } from './commons/task.js';
import { P, S, init_state, encipher, block, stream2word, expand_0state, expand_state }
    from './commons/blowfish.js';

var BLOCK_SIZE = 8;
var MAX_KEY = 72;

/**
 * An ASCII magic string as big-endian 32-bit words - the plaintext that both
 * bcrypt and bcrypt_pbkdf encrypt. Written once; the two used to build their
 * word arrays with separate copies of these shifts.
 */
function magic_words(s) {
    var w = new Int32Array(s.length >> 2);
    for (var i = 0; i < w.length; i++) {
        w[i] = ((s.charCodeAt(i * 4) << 24) | (s.charCodeAt(i * 4 + 1) << 16) |
                (s.charCodeAt(i * 4 + 2) << 8) | s.charCodeAt(i * 4 + 3)) | 0;
    }
    return w;
}

/* "OrpheanBeholderScryDoubt" - the 24 bytes bcrypt encrypts, as 6 words */
var MAGIC = /* @__PURE__ */ magic_words('OrpheanBeholderScryDoubt');

/* "OxychromaticBlowfishSwatDynamite" - bcrypt_pbkdf's, as 8 words */
var MAGIC_PBKDF = /* @__PURE__ */ magic_words('OxychromaticBlowfishSwatDynamite');

/**
 * The expensive part, shared by bcrypt and bcrypt_pbkdf: the salted key
 * schedule, then `rounds` pairs of unsalted ones.
 *
 * ⚠ THE PAIR'S ORDER DIFFERS BETWEEN THE TWO, which is why it is a parameter
 *   rather than fixed: bcrypt runs expand_0state(key) then (salt), OpenBSD's
 *   bcrypt_hash runs (salt) then (key). Both are what their references do;
 *   swapping either produces a key schedule that matches nothing.
 */
/*
 * As a task (commons/task.js), so the callback forms can run it a slice at a
 * time: STEP_ROUNDS pairs per step, about half a millisecond. Its result is
 * `magic` encrypted 64 times under the finished schedule.
 *
 * ⚠ THE SCHEDULE LIVES IN commons/blowfish.js's SHARED P AND S, which plain
 *   Blowfish and any other bcrypt use too - and between two steps, anything
 *   may run. So each task keeps its own copy: a step loads it into P and S,
 *   works, saves it back and zeroes P and S, leaving nothing of this
 *   password's schedule behind for the next caller. The copy (4 KiB) costs
 *   about a microsecond a step, against the step's half millisecond.
 */
var STEP_ROUNDS = 8;

function eks_task(salt, key, rounds, first, second, magic) {
    var own_p = null, own_s = null, r = 0, cdata = null;
    return {
        step: function () {
            if (cdata) { return true; }
            if (own_p) {
                P.set(own_p); S.set(own_s);
            } else {
                init_state();
                expand_state(salt, key);
            }
            var end = Math.min(rounds, r + STEP_ROUNDS);
            for (; r < end; r++) {
                expand_0state(first);
                expand_0state(second);
            }
            if (r === rounds) {
                cdata = new Int32Array(magic);
                encrypt_magic(cdata);
                if (own_p) { own_p.fill(0); own_s.fill(0); }
            } else {
                own_p = own_p || new Int32Array(18);
                own_s = own_s || new Int32Array(1024);
                own_p.set(P); own_s.set(S);
            }
            P.fill(0); S.fill(0);
            return cdata !== null;
        },
        result: function () { return cdata; }
    };
}

/**
 * Encrypt the magic words in place, 64 times over, one 8-byte block at a
 * time - the step both functions end with, written out twice before.
 */
function encrypt_magic(cdata) {
    for (var r = 0; r < 64; r++) {
        for (var i = 0; i < cdata.length; i += 2) {
            block[0] = cdata[i]; block[1] = cdata[i + 1];
            encipher();
            cdata[i] = block[0]; cdata[i + 1] = block[1];
        }
    }
}

/* expand_state (key into P, then P and S re-derived with the salt xored in)
   is commons/blowfish.js's - the same walk as expand_0state */

/**
 * The raw primitive.
 *
 * @param  {Uint8Array} password  truncated at 72 bytes, see above
 * @param  {Uint8Array} salt      exactly 16 bytes
 * @param  {number}     cost      4..31. Work is 2^cost key schedules.
 * @return {Uint8Array} 24 bytes. The textual form keeps only the first 23.
 */
export function bcrypt_raw(password, salt, cost) {
    return finish_task(bcrypt_raw_task(password, salt, cost));
}

/** bcrypt_raw as a task (commons/task.js): the same steps, run a slice at a time. */
export function bcrypt_raw_task(password, salt, cost) {
    if (salt.length !== 16) {
        throw new Error('bcrypt: salt must be exactly 16 bytes');
    }
    if (cost < 4 || cost > 31) {
        throw new Error('bcrypt: cost must be between 4 and 31');
    }

    /*
     * The key is the password followed by a zero byte, capped at 72 total.
     *
     * Note what the cap does at exactly 72: the terminator is what gets cut,
     * not a password byte. A 71-byte password is keyed as 71 bytes plus a
     * zero; a 72-byte password is keyed as 72 bytes with no terminator at
     * all. Copying only klen-1 bytes here silently drops the last character
     * of a 72-byte password, which matches no other implementation.
     *
     * The terminator being part of the key is also why an embedded zero byte
     * truncates the password early - relevant to anything that pre-hashes
     * passwords into raw bytes before calling this.
     */
    var i;
    var klen = password.length + 1;
    if (klen > MAX_KEY) { klen = MAX_KEY; }
    var copy = password.length < klen ? password.length : klen;
    var key = new Uint8Array(klen);
    for (i = 0; i < copy; i++) { key[i] = password[i]; }

    /* the schedule, then the magic string encrypted 64 times, three blocks at a time */
    var eks = eks_task(salt, key, 1 << cost, key, salt, MAGIC);
    return {
        step: function () {
            var finished = eks.step();
            if (finished) { key.fill(0); }
            return finished;
        },
        result: function () {
            /* big-endian out, unlike bcrypt_pbkdf below */
            var cdata = eks.result();
            var out = new Uint8Array(24);
            for (var w = 0; w < 6; w++) { wr_be32(out, w * 4, cdata[w]); }
            return out;
        }
    };
}

/* ---------------- the $2b$ text format ---------------- */
/*
 * bcrypt uses its own base64 alphabet, in its own order, and it is not
 * interchangeable with standard base64. Getting this wrong produces hashes
 * that look right and verify nowhere.
 */

/*
 * BCRYPT'S OWN ALPHABET - digits LAST, unlike the ./0-9A-Za-z ordering that
 * yescrypt and sha512-crypt use (see yescrypt.js). The bit packing differs
 * too. The two are not interchangeable despite both appearing in
 * /etc/shadow.
 */
var B64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';


/* ==================== bcrypt_pbkdf ==================== */

/**
 * bcrypt_pbkdf - OpenBSD's key derivation, used by encrypted
 * `openssh-key-v1` private key files.
 *
 * ⚠ IT IS NEITHER bcrypt NOR PBKDF2, despite the name carrying both.
 *
 *   bcrypt answers "is this password right" and returns a fixed 24 bytes.
 *   A key needs an arbitrary length, so this wraps Blowfish's expensive
 *   schedule in a PBKDF2-shaped loop: blocks numbered by a big-endian
 *   counter, each folded in by xor.
 *
 *   WHY NOT JUST PBKDF2: HMAC parallelises cheaply on a GPU. Blowfish's key
 *   schedule needs 4KB of state per attempt, which is what actually slows an
 *   attacker. That is the reason OpenBSD built it.
 *
 * ⚠ FOUR DETAILS, EACH SILENT IF WRONG:
 *
 *   - 64 rounds, FIXED. There is no cost parameter here at all.
 *   - the magic is "OxychromaticBlowfishSwatDynamite", not bcrypt's
 *     "OrpheanBeholderScryDoubt"
 *   - both inputs are SHA-512'd first, and the salt is hashed together with
 *     the block counter
 *   - the output words are written LITTLE-endian, where bcrypt is big-endian,
 *     and the bytes are scattered across the key at a stride rather than
 *     written contiguously
 *
 *   Any one of them wrong gives a key of the right length and the wrong
 *   value - which surfaces as "the private key will not decrypt", with
 *   nothing to say why.
 *
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {number} keylen  bytes wanted
 * @param {number} rounds  the outer count, taken from the key file
 */
export function bcrypt_pbkdf(password, salt, keylen, rounds) {
    return finish_task(bcrypt_pbkdf_task(password, salt, keylen, rounds));
}

/**
 * bcrypt_pbkdf as a task (commons/task.js). Each bcrypt_hash inside it - 64
 * rounds, about 5 ms - is itself a task, so a step stays as short as
 * bcrypt's.
 */
export function bcrypt_pbkdf_task(password, salt, keylen, rounds) {
    if (rounds < 1) { throw new Error('bcrypt_pbkdf: rounds must be at least 1'); }
    if (keylen < 1 || keylen > 1024) {
        throw new Error('bcrypt_pbkdf: keylen out of range');
    }

    var BLK = 32;
    var sha_pass = sha512(password);
    var out = new Uint8Array(keylen);
    var countsalt = new Uint8Array(salt.length + 4);
    countsalt.set(salt, 0);

    var stride = Math.floor((keylen + BLK - 1) / BLK);
    var amt = Math.floor((keylen + stride - 1) / stride);
    var left = keylen;

    /*
     * The loops of the synchronous form, unrolled into a state machine:
     * for each block `count`, `rounds` bcrypt_hash calls - the first of the
     * counted salt, each later one of the previous output - xored into res.
     */
    var count = 0, i = 0, res = null, hash = null;
    function next_hash(sha_salt) { hash = bcrypt_hash_task(sha_pass, sha_salt); }
    function start_block() {
        count++;
        wr_be32(countsalt, salt.length, count);
        i = 0;
        next_hash(sha512(countsalt));
    }
    start_block();

    return {
        step: function () {
            if (left <= 0) { return true; }
            if (!hash.step()) { return false; }
            var tmp = hash.result();
            if (i === 0) { res = new Uint8Array(tmp); }
            else { for (var j = 0; j < BLK; j++) { res[j] ^= tmp[j]; } }
            if (++i < rounds) { next_hash(sha512(tmp)); return false; }

            var use = amt < left ? amt : left;
            /* the scatter: byte k of this block lands at k*stride + count - 1 */
            for (var k = 0; k < use; k++) {
                var idx = k * stride + (count - 1);
                if (idx >= out.length) { use = k; break; }
                out[idx] = res[k];
            }
            left -= use;
            if (left > 0) { start_block(); return false; }
            return true;
        },
        result: function () { return out; }
    };
}

/** The 64-round inner function, as a task. Different magic, no cost parameter. */
function bcrypt_hash_task(sha_pass, sha_salt) {
    return map_task(eks_task(sha_salt, sha_pass, 64, sha_salt, sha_pass, MAGIC_PBKDF), function (cdata) {
        /* LITTLE-endian out - see the list of details at bcrypt_pbkdf */
        var out = new Uint8Array(32);
        for (var o = 0; o < 8; o++) { wr_le32(out, o * 4, cdata[o]); }
        return out;
    });
}

/*
 * ==================== THE $2b$ BASE64 ====================
 *
 * ⭐ IT IS STANDARD BASE64 WITH ANOTHER ALPHABET. The bit packing - three
 *   bytes to four characters, most significant bits first - is exactly RFC
 *   4648's, without padding; only the 64 characters differ. So both
 *   directions are commons/bytes.js's codec with B64 passed in.
 *
 *   History: this file and compat/bcrypt.js each carried a hand-written
 *   packer; then this file translated characters to and from the standard
 *   alphabet; now the codec takes the alphabet as a parameter and neither
 *   copy is left.
 *
 * ⚠ DECODING IS LOOSE, which RFC 4648 decoding must never be. bcrypt's
 *   reference ignores the unused bits of the last character - 22 characters
 *   carry 132 bits for a 128-bit salt - and stops at a character it does not
 *   know. Hashes in the wild rely on the first; bcryptjs, which
 *   compat/bcrypt.js mirrors, relies on the second.
 */

/**
 * The first `len` bytes in bcrypt's base64, unpadded.
 *
 * Exported for compat/bcrypt.js, whose encodeBase64 is this function.
 */
export function bcrypt_base64_encode(bytes, len) {
    var src = bytes.subarray ? bytes.subarray(0, len) : bytes.slice(0, len);
    return b64_encode(src, B64, false);
}

/**
 * `len` bytes back out of bcrypt's base64.
 *
 * STRICT BY DEFAULT: if the string runs out - or reaches a character outside
 * the alphabet - before `len` bytes, this throws, which bcrypt_verify turns
 * into a plain `false`. Characters past the `len` bytes are ignored.
 *
 * WITH `lenient` IT RETURNS WHAT IT HAS instead - fewer than `len` bytes if
 * that is all there is. That is bcryptjs's behaviour, for compat/bcrypt.js.
 *
 * Exported for compat/bcrypt.js.
 */
export function bcrypt_base64_decode(str, len, lenient) {
    var b = b64_decode(String(str), B64, { loose: true });
    if (b.length < len && !lenient) { throw new Error('bcrypt: invalid base64 in hash string'); }
    return b.slice(0, Math.max(0, len) || 0);
}

/**
 * Produce a modular crypt string: $2b$COST$SALT_HASH
 *
 * @param  {Uint8Array} password
 * @param  {Uint8Array} salt      exactly 16 bytes, random per password
 * @param  {number}     cost      4..31. 12 is a common current choice.
 * @return {string}
 */
export function bcrypt(password, salt, cost) {
    return finish_task(bcrypt_task(password, salt, cost));
}

/** bcrypt as a task (commons/task.js). */
export function bcrypt_task(password, salt, cost) {
    return map_task(bcrypt_raw_task(password, salt, cost), function (h) {
        var c = (cost < 10 ? '0' : '') + cost;
        /* only 23 of the 24 bytes are encoded - a quirk of the original */
        return '$2b$' + c + '$' + bcrypt_base64_encode(salt, 16) + bcrypt_base64_encode(h, 23);
    });
}

/**
 * Check a password against a stored $2a$/$2b$/$2y$ string.
 *
 * The comparison is constant time. A plain === here is a timing oracle that
 * leaks how many leading characters matched.
 *
 * @return {boolean}
 */
export function bcrypt_verify(password, stored) {
    return finish_task(bcrypt_verify_task(password, stored));
}

/** bcrypt_verify as a task (commons/task.js); a malformed string is false at once. */
export function bcrypt_verify_task(password, stored) {
    if (typeof stored !== 'string' || stored.length !== 60) { return done_task(false); }
    if (stored.charAt(0) !== '$' || stored.charAt(1) !== '2') { return done_task(false); }
    var variant = stored.charAt(2);
    if (variant !== 'a' && variant !== 'b' && variant !== 'y') { return done_task(false); }
    if (stored.charAt(3) !== '$' || stored.charAt(6) !== '$') { return done_task(false); }

    var cost = parseInt(stored.substr(4, 2), 10);
    if (!(cost >= 4 && cost <= 31)) { return done_task(false); }

    var salt, expected;
    try {
        salt = bcrypt_base64_decode(stored.substr(7, 22), 16);
        expected = bcrypt_base64_decode(stored.substr(29, 31), 23);
    } catch (e) { return done_task(false); }

    return map_task(bcrypt_raw_task(password, salt, cost), function (got) {
        return equal(got.subarray(0, 23), expected) === 1;
    });
}
