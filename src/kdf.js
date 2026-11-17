/**
 * Key derivation from existing key material  -  HKDF and PBKDF2
 *
 * Both are thin constructions over HMAC rather than algorithms of their own,
 * which is why they share a file with each other and not with the hash
 * families. scrypt, Argon2 and bcrypt get their own files when they arrive:
 * those are real algorithms with their own internals, not wrappers.
 *
 * The two here answer different questions, and using one where the other
 * belongs is the classic mistake:
 *
 *     HKDF     input is already high-entropy - a DH shared secret, a random
 *              key. Fast on purpose. Turning one strong key into several
 *              independent ones.
 *
 *     PBKDF2   input is a human password with maybe 30 bits of entropy.
 *              Slow on purpose. The iteration count is the whole defence.
 *
 * Running HKDF on a password gives an attacker a target they can grind at
 * millions of guesses per second. Running PBKDF2 on a DH secret just wastes
 * time for no gain.
 */

import { hmac, hmac_init } from './hmac.js';
import { concat, be32, wr_be32, ascii } from './commons/bytes.js';
import { finish_task } from './commons/task.js';

var EMPTY = new Uint8Array(0);

/* ================= HKDF  -  RFC 5869 ================= */
/*
 * Two stages, and the split is the point.
 *
 *   extract   concentrates whatever entropy the input has into one uniform
 *             pseudorandom key. The salt is a HMAC key here, not a secret -
 *             it may be public, and it may be absent.
 *
 *   expand    stretches that key into as many bytes as asked for, with an
 *             info string that binds the output to a purpose.
 *
 * The info parameter is what makes two derivations from the same master key
 * independent. Deriving an encryption key and a MAC key from one secret is
 * only safe if they carry different info strings.
 */

/**
 * @param  {function}   hash
 * @param  {Uint8Array} ikm    input key material
 * @param  {Uint8Array} [salt] optional, may be public. Defaults to zeros.
 * @return {Uint8Array} a pseudorandom key of the hash's digest length
 */
/**
 * A derived key of length zero is not a key.
 *
 * EVERY FUNCTION HERE USED TO RETURN ONE when `length` was omitted:
 * `new Uint8Array(undefined)` is an empty array, so hkdf(...) with the
 * argument forgotten produced [] and nothing complained. Used as an
 * encryption key that is a cipher with no key, and used as a MAC key it is a
 * MAC anyone can forge - neither of which shows up as an error anywhere
 * downstream.
 *
 * The guard is one line per entry point and it is the difference between a
 * loud failure and a silent one.
 */
function require_length(who, length) {
    if (typeof length !== 'number' || !isFinite(length) ||
        length <= 0 || (length | 0) !== length) {
        throw new TypeError(who + ': length must be a positive integer - got ' +
                            length);
    }
    return length;
}

export function hkdf_extract(hash, ikm, salt) {
    /* Absent salt means a string of zeros the length of the digest */
    var s = (salt && salt.length) ? salt : new Uint8Array(hash.DIGEST_SIZE);
    /* Note the argument order: the salt is the HMAC key, the material is the message */
    return hmac(hash, s, ikm);
}

/**
 * @param  {function}   hash
 * @param  {Uint8Array} prk     from hkdf_extract
 * @param  {number}     length  output bytes
 * @param  {Uint8Array} [info]  binds the output to a purpose
 * @return {Uint8Array}
 */
export function hkdf_expand(hash, prk, length, info) {
    require_length('hkdf_expand', length);
    var hash_len = hash.DIGEST_SIZE;
    var n = Math.ceil(length / hash_len);

    /*
     * The counter is a single byte, so no more than 255 blocks can ever be
     * produced. That is a hard ceiling in the spec, not an implementation
     * limit.
     */
    if (n > 255) {
        throw new Error('hkdf_expand: length must be at most 255 * ' + hash_len +
                        ' = ' + (255 * hash_len) + ' bytes');
    }

    var inf = info || EMPTY;
    var t = EMPTY;
    var i;

    /*
     * T(i) = HMAC(prk, T(i-1) || info || i) - each block feeds the next.
     *
     * ⭐ THROUGH counter_kdf, which used to be the only shape here this did
     *   not use. HKDF's counter is one byte where counter_kdf allows 32 bits,
     *   which is what the 255-block check above is for.
     *
     * ⛔ T IS THE CHAIN, SO A COPY IS RETURNED - counter_kdf wipes each block
     *   it is handed, and wiping T itself is the kbkdf_feedback bug.
     */
    var out = counter_kdf(function (n_i) {
        var block = new Uint8Array(t.length + inf.length + 1);
        block.set(t, 0);
        block.set(inf, t.length);
        block[block.length - 1] = n_i;
        t = hmac(hash, prk, block);
        for (var j = 0; j < block.length; j++) { block[j] = 0; }
        return Uint8Array.from(t);
    }, length, hash_len);

    for (i = 0; i < t.length; i++) { t[i] = 0; }
    return out;
}

/**
 * extract then expand, the usual one-shot form.
 *
 * @param  {function}   hash
 * @param  {Uint8Array} ikm
 * @param  {number}     length
 * @param  {Uint8Array} [salt]
 * @param  {Uint8Array} [info]
 * @return {Uint8Array}
 */
export function hkdf(hash, ikm, length, salt, info) {
    require_length('hkdf', length);
    var prk = hkdf_extract(hash, ikm, salt);
    var out = hkdf_expand(hash, prk, length, info);
    for (var i = 0; i < prk.length; i++) { prk[i] = 0; }
    return out;
}

/* ================= PBKDF2  -  RFC 8018 ================= */
/*
 * The iteration count is the entire security parameter. It has to rise as
 * hardware gets faster, and any number baked into old code is now too low:
 * PBKDF2-SHA1 shipped with 1000 iterations in 2000, and OWASP now suggests
 * on the order of 600,000 for SHA-256.
 *
 * The deeper limitation is that PBKDF2 is cheap in memory. A GPU or an ASIC
 * runs thousands of guesses in parallel at almost no extra cost, so the
 * defender's factor of N costs the attacker far less than N. Argon2 and
 * scrypt exist because of this: they force memory use, which parallel
 * hardware cannot supply cheaply.
 *
 * Reach for PBKDF2 when a standard requires it - WPA2, PKCS#5, Telegram's
 * 2FA - not when choosing freely.
 */

/**
 * @param  {function}   hash
 * @param  {Uint8Array} password
 * @param  {Uint8Array} salt        must be random and per-user
 * @param  {number}     iterations
 * @param  {number}     length      output bytes
 * @return {Uint8Array}
 */
export function pbkdf2(hash, password, salt, iterations, length) {
    return finish_task(pbkdf2_task(hash, password, salt, iterations, length));
}

/*
 * PBKDF2 as a task: each step() runs at most STEP_ITERATIONS rounds of the
 * PRF and returns true once the key is complete; result() gives it. pbkdf2()
 * above runs the steps back to back, and the callback form in api/kdf.js
 * runs them a few milliseconds at a time, yielding to the event loop
 * between - one implementation for both, so they cannot disagree.
 *
 * ⭐ THE LOOP IS THE SAME ONE, cut into pieces: the block index i, the
 *   iteration k and the running xor acc are what survives between steps.
 */
var STEP_ITERATIONS = 1024;

export function pbkdf2_task(hash, password, salt, iterations, length) {
    require_length('pbkdf2', length);
    if (iterations < 1) {
        throw new Error('pbkdf2: iterations must be at least 1');
    }

    var hash_len = hash.DIGEST_SIZE;
    var blocks = Math.ceil(length / hash_len);
    var out = new Uint8Array(length);
    var produced = 0;

    /* salt || block index, big-endian, per RFC 8018 */
    var input = new Uint8Array(salt.length + 4);
    input.set(salt, 0);

    var acc = new Uint8Array(hash_len);
    /*
     * ⭐ THE PAD BLOCKS ARE COMPRESSED ONCE, not per iteration. For sha256 and
     *   sha512 hmac_init hands back hmac_fast, which keeps the chaining state
     *   after each pad block and resumes from it - halving the compressions
     *   for the short messages this loop always has. Any other hash gets the
     *   cached-pad closure, so the choice is a speed one and never a
     *   correctness one.
     *
     * ⚠ THE CHOICE IS hmac_init's, NOT THIS FILE'S. This line used to test
     *   hash.PARAMS itself and pick hmac_fast directly - a second copy of the
     *   dispatch hmac.js already makes.
     */
    var prf = hmac_init(hash, password);

    var i = 1;          /* the block being computed, 1-based */
    var k = 0;          /* iterations done on it; 0 = not started */
    var u = null;
    var done = false;

    return {
        step: function () {
            if (done) { return true; }
            var j, budget = STEP_ITERATIONS;
            while (budget > 0) {
                if (k === 0) {
                    wr_be32(input, salt.length, i);
                    /*
                     * ⭐ U(1) GOES THROUGH THE SAME prf. It used to be a plain
                     *   hmac(hash, password, input), which rebuilt the key schedule - and
                     *   for sha256 a whole hmac_fast closure - once per output block.
                     */
                    u = prf(input);
                    for (j = 0; j < hash_len; j++) { acc[j] = u[j]; }
                    k = 1;
                    budget--;
                }
                /*
                 * U(n) = HMAC(password, U(n-1)), all xored together.
                 *
                 * ⭐ THE KEY SCHEDULE IS COMPUTED ONCE. `hmac` rebuilds the padded
                 *   key on every call, and this loop runs `iterations` times with
                 *   the same key - a hundred thousand rebuilds for a typical
                 *   parameter. Measured: 731 ms against 178 for noble before this,
                 *   and the gap was in the setup rather than the hashing.
                 */
                while (k < iterations && budget > 0) {
                    u = prf(u);
                    for (j = 0; j < hash_len; j++) { acc[j] ^= u[j]; }
                    k++;
                    budget--;
                }
                if (k < iterations) { return false; }

                for (j = 0; j < hash_len && produced < length; j++) {
                    out[produced++] = acc[j];
                }
                i++;
                k = 0;
                if (i > blocks) {
                    acc.fill(0);
                    input.fill(0);
                    done = true;
                    return true;
                }
            }
            return false;
        },
        result: function () { return out; }
    };
}

/* ================= ConcatKDF and X9.63  -  SP 800-56A, ANSI X9.63 ================= */
/*
 * The two simplest key derivations there are: hash a counter together with
 * the shared secret and some context, repeat until enough bytes exist.
 *
 * They differ in ONE thing - where the counter goes.
 *
 *     ConcatKDF   H( counter || Z || OtherInfo )
 *     X9.63       H( Z || counter || SharedInfo )
 *
 * That is the entire distinction, and it is a real interoperability trap: an
 * implementation that gets it backwards produces plausible-looking keys that
 * agree with nothing. ConcatKDF appears in NIST key-agreement schemes and in
 * JOSE's ECDH-ES; X9.63 appears in ECIES and in older financial standards.
 *
 * Neither has a salt or an iteration count. Both assume Z is ALREADY a
 * high-entropy shared secret from a key agreement - they are HKDF-expand
 * without the extract step, and they are wrong for passwords in exactly the
 * way described at the top of this file.
 */

/**
 * The block assembly every counter-shaped KDF here shares: call
 * produce(1), produce(2), ... until `length` bytes exist, take a prefix of
 * the last block, and wipe each block once it has been copied out.
 *
 * ⭐ EXPORTED because it is not only a kdf.js internal. drbg.js's Hash_df and
 *   Hashgen are the same loop - hash a counter-indexed input, append, stop at
 *   n - and wrote it out twice more. It stays in this file rather than
 *   moving to commons/ because the checks below are the point of it: one
 *   place refuses a hash without a real DIGEST_SIZE and a block of the wrong
 *   length, and every caller inherits that.
 *
 * ⛔ THE WIPE IS A HAZARD FOR FEEDBACK CHAINS. A produce() that returns the
 *   very array it will feed into the next call loses that state to the
 *   wipe - kbkdf_feedback did exactly that once, see the note there. A
 *   chaining caller returns a COPY.
 *
 * @param {function(number): Uint8Array} produce  block i, 1-based
 * @param {number} length    bytes wanted
 * @param {number} hash_len  every block's length - normally hash.DIGEST_SIZE
 */
export function counter_kdf(produce, length, hash_len) {
    /*
     * ⛔ hash_len MUST BE THE REAL OUTPUT SIZE. A hash object without
     *   DIGEST_SIZE made n = NaN, the loop never ran, and the KDF returned
     *   `length` ZERO BYTES without an error - a key. tls1_prf and x942_kdf
     *   counted the bytes they got before they were routed through here;
     *   both conditions are now refused instead.
     */
    if (!(Number.isInteger(hash_len) && hash_len > 0)) {
        throw new TypeError('kdf: the hash must declare a positive integer DIGEST_SIZE');
    }
    if (!(Number.isInteger(length) && length >= 0)) {
        throw new RangeError('kdf: length must be a non-negative integer');
    }
    var n = Math.ceil(length / hash_len);
    /* the counter is 32 bits, so this is a hard ceiling in both specs */
    if (n > 0xffffffff) { throw new Error('kdf: requested length is too large'); }

    var out = new Uint8Array(length);
    var produced = 0;
    for (var i = 1; i <= n; i++) {
        var block = produce(i);
        if (!block || block.length !== hash_len) {
            throw new Error('kdf: the hash returned ' + (block && block.length) + ' bytes, not its DIGEST_SIZE of ' + hash_len);
        }
        for (var j = 0; j < block.length && produced < length; j++) {
            out[produced++] = block[j];
        }
        for (j = 0; j < block.length; j++) { block[j] = 0; }
    }
    return out;
}

/**
 * ConcatKDF with a plain hash - SP 800-56A.
 *
 * @param  {function}   hash
 * @param  {Uint8Array} z            the shared secret
 * @param  {number}     length
 * @param  {Uint8Array} [other_info] algorithm id, party identities and so on
 * @return {Uint8Array}
 */
export function concat_kdf(hash, z, length, other_info) {
    require_length('concat_kdf', length);
    var info = other_info || EMPTY;
    return counter_kdf(function (i) {
        return hash(concat([be32(i), z, info]));
    }, length, hash.DIGEST_SIZE);
}

/**
 * ConcatKDF with HMAC as the auxiliary function.
 *
 * The salt is an HMAC key here, not a secret, and defaults to zeros - the same
 * role and the same convention as in hkdf_extract above.
 */
export function concat_kdf_hmac(hash, z, length, other_info, salt) {
    require_length('concat_kdf_hmac', length);
    var info = other_info || EMPTY;
    var s = (salt && salt.length) ? salt : new Uint8Array(hash.BLOCK_SIZE);
    return counter_kdf(function (i) {
        return hmac(hash, s, concat([be32(i), z, info]));
    }, length, hash.DIGEST_SIZE);
}

/**
 * ANSI X9.63 - the counter goes AFTER the secret. See the note above.
 */
export function x963_kdf(hash, z, length, shared_info) {
    require_length('x963_kdf', length);
    var info = shared_info || EMPTY;
    return counter_kdf(function (i) {
        return hash(concat([z, be32(i), info]));
    }, length, hash.DIGEST_SIZE);
}

/* ================= KBKDF  -  SP 800-108 ================= */
/*
 * Deriving many keys from one key that is already strong, using a PRF rather
 * than a hash directly. It is what TLS 1.2 exporters, IKEv2, and a good deal
 * of key-management hardware use.
 *
 * Three modes, in descending order of how often they appear:
 *
 *   counter    K(i) = PRF(key, [i] || fixed)
 *   feedback   K(i) = PRF(key, K(i-1) || [i] || fixed)
 *   pipeline   A(i) = PRF(key, A(i-1)); K(i) = PRF(key, A(i) || [i] || fixed)
 *
 * The fixed input is Label || 0x00 || Context || [L], and that zero byte is
 * load-bearing: without a separator, a label ending in bytes that look like
 * the start of a context could be reinterpreted, and two different (label,
 * context) pairs would derive the same key.
 *
 * The trailing [L] binds the OUTPUT LENGTH into the derivation, so asking for
 * 32 bytes and truncating to 16 does not give the same result as asking for
 * 16 - the same property KMAC has, and for the same reason.
 */

function kbkdf_fixed(label, context, length) {
    return concat([
        label || EMPTY,
        new Uint8Array([0]),
        context || EMPTY,
        be32(length * 8)
    ]);
}

/**
 * @param  {function}   hash      the hash underneath HMAC
 * @param  {Uint8Array} key       already high-entropy
 * @param  {Uint8Array} [label]
 * @param  {Uint8Array} [context]
 * @param  {number}     length
 * @return {Uint8Array}
 */
export function kbkdf_counter(hash, key, length, label, context) {
    require_length('kbkdf_counter', length);
    var fixed = kbkdf_fixed(label, context, length);
    return counter_kdf(function (i) {
        return hmac(hash, key, concat([be32(i), fixed]));
    }, length, hash.DIGEST_SIZE);
}

/**
 * Feedback mode. Each block depends on the previous one, so the blocks cannot
 * be computed out of order - which is the point when the derivation must be
 * sequential, and the drawback everywhere else.
 *
 * @param {Uint8Array} [iv]  seeds the chain; empty is permitted
 */
export function kbkdf_feedback(hash, key, length, label, context, iv) {
    require_length('kbkdf_feedback', length);
    var fixed = kbkdf_fixed(label, context, length);
    var prev = iv || EMPTY;
    return counter_kdf(function (i) {
        var block = hmac(hash, key, concat([prev, be32(i), fixed]));
        /*
         * ⛔ A COPY, NOT THE BLOCK ITSELF.
         *
         *   counter_kdf zeroes each block after copying it out - a wipe, so
         *   a derived key does not linger in a buffer nobody owns. Holding
         *   `prev` as the same array meant that wipe erased the FEEDBACK
         *   CHAIN STATE too, and every K(i-1) after the first was all zeros.
         *
         *   ⚠ THE OUTPUT WAS STILL WELL-FORMED AND STILL DETERMINISTIC. The
         *     first block was correct, every later block was a valid HMAC of
         *     the wrong input, and nothing failed - so a round trip, a
         *     length check and a "different inputs give different keys" test
         *     all passed. Only writing out SP 800-108 section 5.2 by hand
         *     and comparing showed it.
         */
        prev = new Uint8Array(block);
        return block;
    }, length, hash.DIGEST_SIZE);
}

/**
 * Double-pipeline mode. An inner chain A(i) runs independently of the output,
 * so each output block costs two PRF calls. It exists to keep the feedback
 * chain from being influenced by anything an attacker can see.
 */
export function kbkdf_pipeline(hash, key, length, label, context) {
    require_length('kbkdf_pipeline', length);
    var fixed = kbkdf_fixed(label, context, length);
    var a = fixed;
    return counter_kdf(function (i) {
        a = hmac(hash, key, a);
        return hmac(hash, key, concat([a, be32(i), fixed]));
    }, length, hash.DIGEST_SIZE);
}

/* ================= TLS 1.2 PRF  -  RFC 5246 ================= */
/**
 * The TLS 1.2 pseudorandom function.
 *
 * P_hash expands a secret into as many bytes as asked for by iterating
 * HMAC over a chain of A values:
 *
 *     A(0) = seed,  A(i) = HMAC(secret, A(i-1))
 *     output = HMAC(secret, A(1) || seed) || HMAC(secret, A(2) || seed) || ...
 *
 * WHY IT LOOKS LIKE THIS. TLS 1.0 and 1.1 ran two PRFs in parallel - one over
 * MD5, one over SHA-1 - and XORed them, so that a break of either alone would
 * not break the whole thing. TLS 1.2 dropped the construction and specified a
 * single hash, because by then MD5 was broken enough that the belt-and-braces
 * argument no longer held and SHA-256 was strong enough not to need it.
 *
 * HKDF SUPERSEDED IT IN TLS 1.3, and for a reason: P_hash has no extract
 * step, so it assumes the secret is already uniform. That is true for a TLS
 * master secret and not for a raw Diffie-Hellman output.
 *
 * @param {function}   hash   sha256 for most suites, sha384 for some
 * @param {Uint8Array} secret
 * @param {string}     label  e.g. 'key expansion', 'master secret'
 * @param {Uint8Array} seed   usually the two randoms concatenated
 */
export function tls1_prf(hash, secret, label, seed, length) {
    require_length('tls1_prf', length);
    var full = concat([ascii(label), seed]);
    var a = full;
    /*
     * ⭐ counter_kdf DOES THE BLOCK ASSEMBLY, which this used to write out as
     *   its own produced/take loop. P_hash has no counter in its input, so
     *   the index is ignored - the A chain is what moves.
     *
     * ⚠ SAFE AGAINST counter_kdf's WIPE because the chain value is `a`, not
     *   the block returned. The wipe of each output block is what broke
     *   kbkdf_feedback - see the note there - and it cannot reach `a`.
     */
    return counter_kdf(function () {
        a = hmac(hash, secret, a);
        return hmac(hash, secret, concat([a, full]));
    }, length, hash.DIGEST_SIZE);
}

/* ================= SSH key derivation  -  RFC 4253 section 7.2 ================= */
/**
 * SSH derives six keys from one shared secret and one exchange hash, each
 * distinguished by a single ASCII letter:
 *
 *     A  initial IV, client to server        D  encryption key, server to client
 *     B  initial IV, server to client        E  integrity key, client to server
 *     C  encryption key, client to server    F  integrity key, server to client
 *
 * THE LETTER IS THE ONLY DOMAIN SEPARATION. There is no length binding and no
 * context string beyond it, which is why the six letters must be used exactly
 * as specified - swapping C and D would leave both sides encrypting with the
 * key the other expects to decrypt with, and it would not fail loudly.
 *
 * The extension step for outputs longer than one digest FEEDS BACK the whole
 * output so far, not just the previous block - a detail that differs from
 * HKDF's counter mode and that an implementation reusing HKDF's shape would
 * get wrong.
 *
 * @param {Uint8Array} k        the shared secret, already mpint-encoded
 * @param {Uint8Array} h        the exchange hash
 * @param {string}     letter   one of 'A' through 'F'
 * @param {Uint8Array} session_id
 */
export function sshkdf(hash, k, h, letter, session_id, length) {
    require_length('sshkdf', length);
    var out = hash(concat([k, h, ascii(letter), session_id]));
    while (out.length < length) {
        out = concat([out, hash(concat([k, h, out]))]);
    }
    return out.subarray(0, length);
}

/* ================= ANSI X9.42 KDF ================= */
/**
 * The X9.42 key derivation, used by CMS for Diffie-Hellman key agreement.
 *
 * Structurally it is ConcatKDF with a DER-encoded parameter block instead of
 * a raw info string. This takes the encoded block as an argument rather than
 * building it, because constructing DER is a serialisation problem and this
 * library does not do those - a caller that needs the full CMS form should
 * assemble it with an ASN.1 library and pass the result in.
 *
 * @param {Uint8Array} shared_info  the DER-encoded OtherInfo, or any
 *                                  application-defined context
 */
export function x942_kdf(hash, z, length, shared_info) {
    /*
     * ⚠ THE ARGUMENT ORDER CHANGED to match x963_kdf and every other KDF in
     *   this file: (hash, secret, length, info). It used to be
     *   (hash, z, shared_info, length), the one exception. A caller still
     *   using the old order passes the info where the length goes, and that
     *   is refused here rather than read as a length.
     */
    if (typeof length !== 'number' && typeof shared_info === 'number') {
        throw new TypeError('x942_kdf: arguments are (hash, z, length, shared_info) - ' +
                            'the length now comes before shared_info');
    }
    require_length('x942_kdf', length);
    /*
     * ⭐ IT IS X9.63, byte for byte: H(Z || counter || SharedInfo) with the
     *   same 32-bit big-endian counter from 1. This used to be a second
     *   implementation of that loop, without the block wipe - checked equal
     *   over sha256, sha512 and sha3-256 at every length tried before it was
     *   replaced.
     */
    return x963_kdf(hash, z, length, shared_info);
}

/* ================= PKCS#12 KDF  -  RFC 7292 appendix B ================= */
/**
 * The key derivation inside .p12 and .pfx files.
 *
 * It is worth knowing what this is and worth not choosing it. The password is
 * converted to BIG-ENDIAN UTF-16 with a trailing null, then the password and
 * the salt are each repeated to fill a whole number of 64-byte blocks, and
 * the whole thing is hashed and re-hashed with a modular addition step
 * between rounds.
 *
 * IT IS NOT MEMORY-HARD AND ITS ITERATION COUNT IS USUALLY LOW - files in the
 * wild commonly use 2048 rounds of SHA-1. A .p12 protected only by this is
 * about as strong as the password itself against a GPU.
 *
 * Implemented for reading existing files. Use Argon2id for anything new.
 *
 * @param {string|Uint8Array} password  a string, or one byte per character
 * @param {number} id  1 for a key, 2 for an IV, 3 for a MAC key
 */
export function pkcs12_kdf(hash, password, salt, id, iterations, length) {
    require_length('pkcs12_kdf', length);
    var v = hash.BLOCK_SIZE || 64;
    var u = hash.DIGEST_SIZE;

    /*
     * The password becomes big-endian UTF-16 with a trailing NUL. A string is
     * encoded as such (its UTF-16 code units, as the format defines); bytes
     * are taken as one character each, the low byte of a UTF-16 unit.
     */
    var pw = new Uint8Array(password.length * 2 + 2);
    for (var i = 0; i < password.length; i++) {
        var unit = typeof password === 'string' ? password.charCodeAt(i) : password[i];
        pw[2 * i] = unit >>> 8;
        pw[2 * i + 1] = unit & 0xff;
    }

    function fill(src, n) {
        var out = new Uint8Array(n);
        if (src.length === 0) { return out; }
        for (var j = 0; j < n; j++) { out[j] = src[j % src.length]; }
        return out;
    }

    var D = new Uint8Array(v).fill(id);
    var S = fill(salt, v * Math.ceil(salt.length / v));
    var Pp = fill(pw, v * Math.ceil(pw.length / v));
    var I = concat([S, Pp]);

    var out = new Uint8Array(length);
    var produced = 0;

    while (produced < length) {
        var A = hash(concat([D, I]));
        for (var r = 1; r < iterations; r++) { A = hash(A); }

        var take = Math.min(u, length - produced);
        out.set(A.subarray(0, take), produced);
        produced += take;
        if (produced >= length) { break; }

        /* B is A repeated to v bytes; every v-byte chunk of I gets B+1 added
           to it as a big-endian integer */
        var B = fill(A, v);
        for (var k = 0; k < I.length; k += v) {
            var carry = 1;
            for (var m = v - 1; m >= 0; m--) {
                var s = I[k + m] + B[m] + carry;
                I[k + m] = s & 0xff;
                carry = s >> 8;
            }
        }
    }
    return out;
}
