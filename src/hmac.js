/**
 * HMAC  -  RFC 2104, FIPS 198-1
 *
 * Generic over any hash in this library. Not a family of its own - a
 * construction that wraps one, which is why it sits in its own file rather
 * than inside sha2.js or sha3.js.
 *
 *     HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
 *
 * WHY THE DOUBLE WRAP EXISTS
 * The obvious keyed hash, H(key || msg), is broken for Merkle-Damgard
 * functions. An attacker who has that tag holds the full internal state of H
 * and can continue hashing from it, producing a valid tag for msg || anything
 * without ever knowing the key. That is the length extension attack, and
 * HMAC's nesting is the fix: the outer hash conceals the inner state.
 *
 * WHICH HASHES ACTUALLY NEED IT
 * Only the length-extendable ones: SHA-1, SHA-2, MD5, RIPEMD-160. Sponge and
 * HAIFA constructions are not vulnerable, and they all ship a native keyed
 * mode that costs one pass where HMAC costs two:
 *
 *     instead of  hmac(sha3_256, k, m)   use  kmac256(k, m, 32)
 *     instead of  hmac(blake2b,  k, m)   use  blake2b(m, 64, k)
 *     instead of  hmac(blake3,   k, m)   use  blake3_keyed(m, k)
 *
 * HMAC over those still works and is not insecure - it is redundant and
 * roughly twice the work. It is left available because real protocols do
 * specify HMAC-SHA3, and interoperability beats purity.
 *
 * SHA-512/224 and SHA-512/256 are the interesting middle case: they are
 * Merkle-Damgard but truncate away half the state, so they are not
 * length-extendable either. HMAC over them is still the standard construction
 * and is what any peer will expect.
 */

import { equal } from './commons/ct.js';

import { hmac_fast, hmac_padded_key, IPAD, OPAD } from './commons/hmac_fast.js';

/*
 * hmac_padded_key LIVES IN commons/hmac_fast.js, together with the two pad
 * bytes, and is re-exported here under its old name. It used to be defined
 * here and imported back by hmac_fast.js, which made the two files import
 * each other - see the note there.
 */
export { hmac_padded_key };

/**
 * The block size, after checking the hash can carry HMAC at all: it must
 * declare both BLOCK_SIZE and a real DIGEST_SIZE.
 *
 * ⚠ THE DIGEST_SIZE CHECK IS NEW. A XOF called without a length - shake256
 *   - returns zero bytes, and the one-shot path below used to accept that and
 *   MAC with an empty inner digest, while hmac_init failed on it with a bare
 *   RangeError. Both now refuse it the same way, with a message.
 */
function hmac_block_size(hash, who) {
    var block_size = hash.BLOCK_SIZE;
    if (!block_size) {
        throw new Error(who + ': hash function must expose BLOCK_SIZE');
    }
    if (!(Number.isInteger(hash.DIGEST_SIZE) && hash.DIGEST_SIZE > 0)) {
        throw new Error(who + ': hash function must declare a fixed DIGEST_SIZE - ' +
                        'a XOF needs a length, and HMAC has nowhere to give it one');
    }
    return block_size;
}

/**
 * @param  {function}   hash  any hash export from this library. Must carry
 *                            BLOCK_SIZE - all of them do.
 * @param  {Uint8Array} key   any length
 * @param  {Uint8Array} msg
 * @return {Uint8Array} digest of the underlying hash
 */
export function hmac(hash, key, msg) {
    /*
     * ⭐ THROUGH THE MIDSTATE PATH WHEN THE HASH SUPPORTS IT.
     *
     *   The code below builds `inner` as one buffer of block_size + msg.length
     *   and copies the whole message into it. For a megabyte that is a
     *   megabyte of allocation and a megabyte of copying before any hashing
     *   starts - measured at 79 MB/s against 107 for the path that streams
     *   the message straight in.
     *
     * ⭐ hmac_init MAKES THE CHOICE, and this defers to it, so "which hashes
     *   take the midstate path" is decided in one place. kdf.js used to test
     *   hash.PARAMS itself as well.
     *
     * ⚠ THE FALLBACK IS NOT DEAD CODE. Only sha256 and sha512 expose their
     *   parameters; blake2, sha3 and the rest come through here, and they
     *   are also the ones for which HMAC is not the usual construction.
     */
    if (hash.PARAMS) { return hmac_init(hash, key)(msg); }

    var block_size = hmac_block_size(hash, 'hmac');

    var i;
    var k = hmac_padded_key(hash, key, block_size);

    /* inner: H(K ^ ipad || msg) */
    var inner = new Uint8Array(block_size + msg.length);
    for (i = 0; i < block_size; i++) { inner[i] = k[i] ^ IPAD; }
    for (i = 0; i < msg.length; i++) { inner[block_size + i] = msg[i]; }
    var ih = hash(inner);

    /* outer: H(K ^ opad || inner) - DIGEST_SIZE is checked above, so this
       is the same buffer hmac_init sizes from it */
    var outer = new Uint8Array(block_size + ih.length);
    for (i = 0; i < block_size; i++) { outer[i] = k[i] ^ OPAD; }
    for (i = 0; i < ih.length; i++) { outer[block_size + i] = ih[i]; }
    var out = hash(outer);

    /* the padded key is the secret here, and it outlives nothing */
    for (i = 0; i < block_size; i++) { k[i] = 0; inner[i] = 0; outer[i] = 0; }
    for (i = 0; i < ih.length; i++) { ih[i] = 0; }

    return out;
}

/**
 * Verify a tag in constant time.
 *
 * This exists so that callers never write equal(hmac(...), tag) themselves.
 * A plain === there is a timing oracle that lets an attacker forge a tag one
 * byte at a time, and it is the single most common way MAC verification is
 * got wrong.
 *
 * @return {boolean}
 */
export function hmac_verify(hash, key, msg, tag) {
    return equal(hmac(hash, key, msg), tag) === 1;
}

/**
 * An HMAC with the key schedule computed once.
 *
 * ⛔ WHY THIS EXISTS: `hmac` rebuilds the padded key on every call - it hashes
 *   an over-long key, copies it into a block, and xors both pads. That is
 *   correct and it is fine for one message. PBKDF2 calls it ONCE PER
 *   ITERATION, a hundred thousand times, with the same key every time.
 *
 *   Measured: pbkdf2-sha256 at 100k iterations took 731 ms here against
 *   noble's 178 - a gap far larger than the 0.7x between the two HMACs
 *   themselves, which is what pointed at the setup rather than the hashing.
 *
 * ⭐ THE ONE PLACE THAT PICKS hmac_fast. A hash exposing its Merkle-Damgard
 *   parameters gets the midstate form, which compresses the two pad blocks
 *   once; everything else gets the closure below, which caches the pads.
 *   Both give the same MAC - checked against each other and against node on
 *   every hash here.
 *
 * ⚠ THE RETURNED FUNCTION HOLDS THE PADDED KEY. It is a closure over
 *   key-derived material, so it lives as long as the caller keeps it - and
 *   `wipe` on it is not possible from outside. A caller that wants the key
 *   gone should not hold the closure; `hmac` above allocates and clears per
 *   call and remains the right choice for anything but a tight loop.
 *
 * @return {function(Uint8Array): Uint8Array}
 */
export function hmac_init(hash, key) {
    if (hash.PARAMS) { return hmac_fast(hash, key); }

    var block_size = hmac_block_size(hash, 'hmac_init');
    var i;
    /*
     * ⭐ THROUGH hmac_padded_key. This function used to carry its own inline
     *   copy of those lines - the same copy the note on hmac_padded_key says
     *   was removed, back again one function further down.
     */
    var k = hmac_padded_key(hash, key, block_size);

    var ipad = new Uint8Array(block_size);
    var opad = new Uint8Array(block_size);
    for (i = 0; i < block_size; i++) {
        ipad[i] = k[i] ^ IPAD;
        opad[i] = k[i] ^ OPAD;
    }
    for (i = 0; i < block_size; i++) { k[i] = 0; }

    var outer = new Uint8Array(block_size + hash.DIGEST_SIZE);
    outer.set(opad, 0);

    return function (msg) {
        var inner = new Uint8Array(block_size + msg.length);
        inner.set(ipad, 0);
        inner.set(msg, block_size);
        var ih = hash(inner);
        for (var j = 0; j < inner.length; j++) { inner[j] = 0; }
        outer.set(ih, block_size);
        return hash(outer);
    };
}

/**
 * HMAC fed in pieces: update() as often as needed, digest() once; copy()
 * forks the state. The hash must have an incremental form - every hash in
 * this library that HMAC is specified over does, as `hash.create`.
 *
 * ⭐ THE INNER HASH RUNS INCREMENTALLY and the outer one is computed whole
 *   at the end: it only ever sees one block of padded key and one digest.
 *
 * @param {function} hash  sha256, sha3_256, ... (with .create, BLOCK_SIZE, DIGEST_SIZE)
 * @param {Uint8Array} key
 * @return {{update: function(Uint8Array): object, copy: function(): object, digest: function(): Uint8Array}}
 */
export function hmac_create(hash, key) {
    var block_size = hmac_block_size(hash, 'hmac_create');
    if (typeof hash.create !== 'function') {
        throw new Error('hmac_create: this hash has no incremental form (hash.create)');
    }
    var k = hmac_padded_key(hash, key, block_size);
    var ipad = new Uint8Array(block_size);
    var opad = new Uint8Array(block_size);
    for (var i = 0; i < block_size; i++) {
        ipad[i] = k[i] ^ IPAD;
        opad[i] = k[i] ^ OPAD;
        k[i] = 0;
    }
    var inner = hash.create();
    inner.update(ipad);
    ipad.fill(0);
    return hmac_instance(hash, inner, opad);
}

function hmac_instance(hash, inner, opad) {
    var self = {
        update: function (msg) { inner.update(msg); return self; },
        copy: function () { return hmac_instance(hash, inner.copy(), new Uint8Array(opad)); },
        digest: function () {
            var ih = inner.digest();
            var out = hash.create().update(opad).update(ih).digest();
            opad.fill(0);
            ih.fill(0);
            return out;
        }
    };
    return self;
}
