/**
 * Ascon  -  NIST SP 800-232, final August 2025
 *
 * The newest symmetric standard NIST has published, and the winner of its
 * Lightweight Cryptography competition. Designed for constrained devices -
 * IoT sensors, RFID, embedded controllers - where AES-GCM and SHA-2 are too
 * heavy.
 *
 * WHAT MAKES IT LIGHTWEIGHT is that ONE permutation does everything. The
 * AEAD, the hash and both XOFs are sponge constructions over the same 320-bit
 * function in commons/ascon_p.js. A device that implements Ascon gets
 * authenticated encryption, hashing and an XOF for the silicon cost of one
 * primitive; AES-GCM plus SHA-256 needs two unrelated ones.
 *
 * The permutation has NO TABLES. Its S-box is applied bitsliced across five
 * words at once, so sixty-four substitutions happen as a handful of word
 * operations. That means no data-dependent memory access and therefore none
 * of the cache-timing exposure this library has to warn about for AES, SM4,
 * Camellia and the rest. On a constrained device that is not a nicety - it is
 * often the only defence available.
 *
 * TWO GENERATIONS, AND THEY ARE NOT COMPATIBLE. Ascon v1.2 is what has been
 * deployed since 2019 and what every existing implementation speaks. NIST's
 * SP 800-232 keeps the permutation unchanged but alters the initial values
 * and renames the variants, so the two produce different output for the same
 * input. Both are here: the NIST names for anything new, the v1.2 names for
 * reading what already exists.
 *
 * ON VERIFICATION. The permutation and the v1.2 modes are checked against two
 * independent references. The NIST variants are checked against SP 800-232's
 * own Table 12, which publishes the state after initialisation - that
 * confirms the initial values and the byte-order convention exactly. Full
 * NIST test vectors live in NIST's CAVP and are not yet in any JavaScript or
 * Python package, so the NIST modes are verified structurally rather than
 * end to end. Stated plainly rather than left implied.
 */

import { ascon_p, set_word, clear_state, sh, sl, xor_byte, byte_of, xor_word, load_word, store_word }
    from './commons/ascon_p.js';
import { equal } from './commons/ct.js';

/*
 * Initial values. The NIST ones were taken from SP 800-232 and confirmed
 * against its Table 12; the v1.2 ones are the CAESAR submission's.
 */
var IV = {
    /* NIST SP 800-232 */
    AEAD128:  [0x00001000, 0x808c0001],
    HASH256:  [0x00000801, 0x00cc0002],
    XOF128:   [0x00000800, 0x00cc0003],
    CXOF128:  [0x00000800, 0x00cc0004],
    /* Ascon v1.2 */
    V12_128:  [0x80400c06, 0x00000000],
    V12_128A: [0x80800c08, 0x00000000],
    /* Ascon-80pq: a 32-bit IV, because the 160-bit key needs the room */
    V12_80PQ: [0xa0400c06, 0x00000000],
    V12_HASH: [0x00400c00, 0x00000100],
    V12_XOF:  [0x00400c00, 0x00000000]
};

/*
 * BYTE ORDER: THE TWO GENERATIONS DISAGREE, and this is the only place they do
 * beyond the initial values.
 *
 * Ascon v1.2 maps the first byte of a block to the MOST significant byte of
 * the state word. NIST SP 800-232 reverses that - "the first element in the
 * sequence of bytes is the least significant byte of the integer" - so the
 * whole absorb and squeeze path is little-endian.
 *
 * The initial values are unaffected, because they are specified as integers
 * rather than byte sequences. That is why SP 800-232's Table 12 matched this
 * implementation while every actual message failed: the state was initialised
 * correctly and then fed bytes backwards. Only a full end-to-end reference
 * caught it.
 *
 * The padding bit follows the same reversal: 0x80 in v1.2, 0x01 for NIST.
 */
var LE = false;

/*
 * The byte-level helpers are commons/ascon_p.js's, called in the current
 * order. This file used to carry its own byte-order-aware copies - xor_block,
 * read_byte, pad_bit, load_pair, and the same lane write a fourth time inside
 * decryption - while ascon_p.js exported big-endian-only versions that nothing
 * imported. There is now one set.
 */

/** XOR len bytes of b into the rate, starting at word 0. */
function xor_block(b, off, len) {
    for (var w = 0; w * 8 < len; w++) {
        xor_word(w, b, off + w * 8, Math.min(8, len - w * 8), LE);
    }
}

function read_byte(k) { return byte_of(k >> 3, k & 7, LE); }

/** XOR the padding bit at byte position k of the rate. */
function pad_bit(k) { xor_byte(k >> 3, k & 7, LE ? 0x01 : 0x80, LE); }

/* ---------------- the sponge, shared by every variant ---------------- */

/**
 * Absorb a message and squeeze `out_len` bytes.
 *
 * @param {number} rate  bytes absorbed per permutation - 8 for every hash
 *                       and XOF variant here
 */
function sponge(iv, msg, out_len, rate, prefix, le) {
    LE = !!le;
    clear_state();
    set_word(0, iv[0], iv[1]);
    ascon_p(12);

    if (prefix) { absorb(prefix, rate, 12); }
    absorb(msg, rate, 12);

    var out = new Uint8Array(out_len);
    var produced = 0;
    while (produced < out_len) {
        for (var k = 0; k < rate && produced < out_len; k++) {
            out[produced++] = read_byte(k);
        }
        if (produced < out_len) { ascon_p(12); }
    }
    clear_state();
    return out;
}

/**
 * Absorb with 10* padding.
 *
 * The padding is never optional and never skipped for an exact multiple: a
 * message whose length is already a multiple of the rate still gets a full
 * extra block. Without that, "abc" and "abc" plus a zero block would absorb
 * identically, which is a collision by construction.
 */
function absorb(data, rate, rounds) {
    var i = 0;
    for (; i + rate <= data.length; i += rate) {
        xor_block(data, i, rate);
        ascon_p(rounds);
    }
    var rem = data.length - i;
    xor_block(data, i, rem);
    /* the pad byte - 0x80 in v1.2, 0x01 for NIST - then zeros */
    pad_bit(rem);
    ascon_p(rounds);
}

/* ---------------- hashes and XOFs ---------------- */

/** Ascon-Hash256, NIST SP 800-232. 32-byte digest. */
export var ascon_hash256 = /* @__PURE__ */ (function () {
    function f(msg) { return sponge(IV.HASH256, msg, 32, 8, null, true); }
    f.BLOCK_SIZE = 8; f.DIGEST_SIZE = 32;
    f.create = ascon_hash256_create;
    return f;
}());

/** Ascon-XOF128, NIST SP 800-232. Any output length. */
export function ascon_xof128(msg, out_len) {
    return sponge(IV.XOF128, msg, out_len === undefined ? 32 : out_len, 8, null, true);
}

/**
 * Ascon-CXOF128 - the customised XOF.
 *
 * The customisation string is absorbed first, length-prefixed, so two
 * different customisations can never produce the same output for the same
 * message. It is the same idea as cSHAKE's domain separation and serves the
 * same purpose: one primitive, many independent uses.
 */
export function ascon_cxof128(msg, out_len, custom) {
    var c = custom || new Uint8Array(0);
    if (c.length > 256) { throw new Error('ascon: customisation string too long'); }
    /*
     * The length goes in as a 64-bit little-endian BIT count.
     *
     * Only the low four bytes are computed by shifting: JavaScript masks
     * shift counts to five bits, so `bits >>> 32` is `bits >>> 0` and writing
     * the loop the obvious way puts the value into byte 4 as well as byte 0.
     * The customisation string is capped at 256 bytes, so the top four bytes
     * are always zero anyway - but the wrong version was zero only for an
     * EMPTY customisation, which is exactly the case that passed while every
     * other length failed.
     *
     * The same shift-masking rule is documented in commons/bytes.js, where it
     * makes a rotate-by-zero guard unnecessary. Here it makes one necessary.
     */
    var pre = new Uint8Array(8 + c.length);
    var bits = c.length * 8;
    for (var i = 0; i < 4; i++) { pre[i] = (bits >>> (8 * i)) & 0xff; }
    pre.set(c, 8);
    return sponge(IV.CXOF128, msg, out_len === undefined ? 32 : out_len, 8, pre, true);
}

/** Ascon-Hash, the v1.2 name. Different initial value, different output. */
export var ascon_hash_v12 = /* @__PURE__ */ (function () {
    function f(msg) { return sponge(IV.V12_HASH, msg, 32, 8, null); }
    f.BLOCK_SIZE = 8; f.DIGEST_SIZE = 32;
    f.create = ascon_hash_v12_create;
    return f;
}());

/** Ascon-Xof, the v1.2 name. */
export function ascon_xof_v12(msg, out_len) {
    return sponge(IV.V12_XOF, msg, out_len === undefined ? 32 : out_len, 8, null);
}

/* ---------------- authenticated encryption ---------------- */

/**
 * The AEAD sponge, shared by every variant.
 *
 * @param {number} rate  16 for Ascon-AEAD128 and v1.2's 128a, 8 for v1.2's 128
 * @param {number} b     rounds during data processing - 8 or 6
 */
function aead_init(iv, key, nonce) {
    clear_state();

    if (key.length === 20) {
        /*
         * ASCON-80PQ. The key is 160 bits, so the layout shifts: the IV
         * occupies only the top 32 bits of word 0 and the key fills the rest
         * of it plus words 1 and 2. Everything downstream - where the key
         * re-enters at initialisation and again at finalisation - moves with
         * it, which is why this is a branch rather than a parameter.
         *
         * The name is for "post-quantum": Grover halves an exhaustive key
         * search, so 160 bits leaves 80 against a quantum adversary where 128
         * would leave 64.
         */
        var q0 = ((iv[0] & 0xffffffff) | 0);
        /* the key's first four bytes are big-endian whatever LE says */
        var k0h = (key[0] << 24 | key[1] << 16 | key[2] << 8 | key[3]) | 0;
        set_word(0, q0, k0h);
        load_word(1, key, 4, LE);
        load_word(2, key, 12, LE);
        load_word(3, nonce, 0, LE);
        load_word(4, nonce, 8, LE);
        ascon_p(12);
        /* S ^= (0^160 || K): the last 160 bits, so word 2's low half and
           words 3 and 4 */
        sl[2] ^= k0h;
        xor_word(3, key, 4, 8, LE);
        xor_word(4, key, 12, 8, LE);
        return;
    }

    set_word(0, iv[0], iv[1]);
    load_word(1, key, 0, LE);
    load_word(2, key, 8, LE);
    load_word(3, nonce, 0, LE);
    load_word(4, nonce, 8, LE);
    ascon_p(12);
    /* the key is xored back into the capacity */
    xor_word(3, key, 0, 8, LE);
    xor_word(4, key, 8, 8, LE);
}

function aead_aad(aad, rate, b) {
    /* the same padded absorb as the hash, at the data-processing round
       count - this was a second copy of absorb() with 12 replaced by b */
    if (aad && aad.length) { absorb(aad, rate, b); }
    /*
     * Domain separation between the associated data and the plaintext phases.
     * The spec writes it as S XOR (0^319 || 1) - the LAST bit of the 320-bit
     * state - and without it an attacker could move the boundary between the
     * two.
     *
     * WHICH BIT THAT IS depends on the generation. Under v1.2's big-endian
     * convention the last bit is the least significant bit of S4. Under
     * NIST's little-endian one, where the first element of a bitstring is the
     * LEAST significant bit of the integer, the last bit is the MOST
     * significant. The ciphertext is identical either way and only the tag
     * differs, which is exactly how this surfaced: encryption matched the
     * reference byte for byte and authentication did not.
     */
    if (LE) { sh[4] ^= 0x80000000 | 0; }
    else    { sl[4] ^= 1; }
}

/*
 * ⚠ `b` IS UNUSED AND STAYS ON PURPOSE. Every other function in the AEAD
 *   path takes (rate, b) together - the rate and the round count - and
 *   finalisation always uses twelve rounds regardless. Dropping the
 *   parameter would make this the one call in the sequence with a different
 *   shape, which is the sort of asymmetry a caller gets wrong once.
 */
function aead_finalize(key, rate, b, tag) {
    if (key.length === 20) {
        /*
         * S ^= (0^64 || K || 0^96) - the key starts one word in and runs 160
         * bits, so it straddles word 3's high half.
         */
        var ftail = (key[16] << 24 | key[17] << 16 | key[18] << 8 | key[19]) | 0;
        xor_word(1, key, 0, 8, LE);
        xor_word(2, key, 8, 8, LE);
        sh[3] ^= ftail;
        ascon_p(12);

        /*
         * T = ceil(S)^128 xor ceil(K)^128 - the LAST 128 bits of each. With a
         * 160-bit key that is bytes 4 through 19, NOT bytes 8 through 19: the
         * first attempt here took the last 96 bits and produced a tag of the
         * right length and the wrong value, which the vectors caught at once
         * and nothing else would have.
         */
        /*
         * The tag is the key xored into the state's last two words, read out
         * - big-endian here even under LE, as this variant always was. The
         * state is cleared by the caller straight after.
         */
        xor_word(3, key, 4, 8, LE);
        xor_word(4, key, 12, 8, LE);
        store_word(3, tag, 0, false);
        store_word(4, tag, 8, false);
        return;
    }
    /* the key enters at the rate boundary, which differs between variants */
    var off = rate === 16 ? 2 : 1;
    xor_word(off, key, 0, 8, LE);
    xor_word(off + 1, key, 8, 8, LE);
    ascon_p(12);
    /* T = last 128 bits of S xor K, read out in the current order; the
       caller clears the state straight after */
    xor_word(3, key, 0, 8, LE);
    xor_word(4, key, 8, 8, LE);
    store_word(3, tag, 0, LE);
    store_word(4, tag, 8, LE);
}

function aead_encrypt(iv, key, nonce, pt, aad, rate, b, le) {
    LE = !!le;
    if (key.length !== 16 && key.length !== 20) {
        throw new Error('ascon: key must be 16 bytes, or 20 for Ascon-80pq');
    }
    if (nonce.length !== 16) { throw new Error('ascon: nonce must be 16 bytes'); }

    aead_init(iv, key, nonce);
    aead_aad(aad, rate, b);

    var out = new Uint8Array(pt.length + 16);
    var i = 0;
    for (; i + rate <= pt.length; i += rate) {
        xor_block(pt, i, rate);
        for (var k = 0; k < rate; k++) { out[i + k] = read_byte(k); }
        ascon_p(b);
    }
    var rem = pt.length - i;
    xor_block(pt, i, rem);
    for (var k2 = 0; k2 < rem; k2++) { out[i + k2] = read_byte(k2); }
    pad_bit(rem);

    var tag = new Uint8Array(16);
    aead_finalize(key, rate, b, tag);
    out.set(tag, pt.length);
    clear_state();
    return out;
}

function aead_decrypt(iv, key, nonce, sealed, aad, rate, b, le) {
    LE = !!le;
    if (key.length !== 16 && key.length !== 20) {
        throw new Error('ascon: key must be 16 bytes, or 20 for Ascon-80pq');
    }
    if (nonce.length !== 16) { throw new Error('ascon: nonce must be 16 bytes'); }
    if (sealed.length < 16) { return null; }

    var ct_len = sealed.length - 16;
    aead_init(iv, key, nonce);
    aead_aad(aad, rate, b);

    var out = new Uint8Array(ct_len);
    var i = 0, k;

    /*
     * Decryption replaces the state's rate with the CIPHERTEXT rather than
     * xoring the plaintext in. Writing the delta is the same thing and avoids
     * having to reconstruct the rate word by word.
     */
    function put_delta(off, len) {
        for (var j = 0; j < len; j++) {
            xor_byte(j >> 3, j & 7, read_byte(j) ^ sealed[off + j], LE);
        }
    }

    for (; i + rate <= ct_len; i += rate) {
        for (k = 0; k < rate; k++) { out[i + k] = read_byte(k) ^ sealed[i + k]; }
        put_delta(i, rate);
        ascon_p(b);
    }
    var rem = ct_len - i;
    for (k = 0; k < rem; k++) { out[i + k] = read_byte(k) ^ sealed[i + k]; }
    put_delta(i, rem);
    pad_bit(rem);

    var tag = new Uint8Array(16);
    aead_finalize(key, rate, b, tag);
    clear_state();

    /* constant-time comparison, and NOTHING returned on failure */
    if (equal(tag, sealed.subarray(ct_len)) !== 1) { return null; }
    return out;
}

/**
 * Ascon-AEAD128, NIST SP 800-232.
 *
 * @param {Uint8Array} nonce  16 bytes, and it MUST NOT REPEAT under one key.
 *
 * Ascon's nonce-reuse failure is less total than GCM's - it does not leak an
 * authentication subkey - but it still reveals the relationship between the
 * two plaintexts. Treat uniqueness as mandatory.
 */
export function ascon_aead128_encrypt(key, nonce, pt, aad) {
    return aead_encrypt(IV.AEAD128, key, nonce, pt, aad, 16, 8, true);
}

/** @return {Uint8Array|null} null when authentication fails */
export function ascon_aead128_decrypt(key, nonce, sealed, aad) {
    return aead_decrypt(IV.AEAD128, key, nonce, sealed, aad, 16, 8, true);
}

/** Ascon-128, the v1.2 name. Rate 8, six rounds per block. */
export function ascon128_encrypt(key, nonce, pt, aad) {
    return aead_encrypt(IV.V12_128, key, nonce, pt, aad, 8, 6);
}
export function ascon128_decrypt(key, nonce, sealed, aad) {
    return aead_decrypt(IV.V12_128, key, nonce, sealed, aad, 8, 6);
}

/** Ascon-128a, the v1.2 name. Rate 16, eight rounds - faster, same security. */
export function ascon128a_encrypt(key, nonce, pt, aad) {
    return aead_encrypt(IV.V12_128A, key, nonce, pt, aad, 16, 8);
}
export function ascon128a_decrypt(key, nonce, sealed, aad) {
    return aead_decrypt(IV.V12_128A, key, nonce, sealed, aad, 16, 8);
}

/**
 * Ascon-80pq, the v1.2 variant with a 160-bit key.
 *
 * "pq" is for post-quantum: Grover's algorithm halves the cost of an
 * exhaustive key search, so 160 bits leaves 80 against a quantum adversary
 * where 128 would leave 64. Everything else - the rate, the round count, the
 * permutation - is Ascon-128.
 */
export function ascon80pq_encrypt(key, nonce, pt, aad) {
    return aead_encrypt(IV.V12_80PQ, key, nonce, pt, aad, 8, 6);
}

/** @return {Uint8Array|null} null when authentication fails */
export function ascon80pq_decrypt(key, nonce, sealed, aad) {
    return aead_decrypt(IV.V12_80PQ, key, nonce, sealed, aad, 8, 6);
}

/* ---------------- Incremental hashing ---------------- */
/*
 * Ascon-Hash256, the XOFs and their v1.2 forms fed in pieces:
 *
 *     ascon_hash256_create()          { update(msg), copy(), digest() }
 *     ascon_xof128_create()           { update(msg), copy(), digest(n), read(n) }
 *     ascon_cxof128_create(custom)    the same, customised
 *
 * ⭐ THE PERMUTATION'S STATE IS SWAPPED IN AND OUT. commons/ascon_p.js keeps
 *   one 320-bit state for the module, which the one-shot functions use and
 *   which is safe because none of them yields. An incremental instance stays
 *   open between calls, so it keeps its own copy of the ten state words and
 *   loads it before each step and saves it after - ten words each way, and
 *   the permutation itself is untouched.
 */
function ascon_sponge_create(iv, prefix, le, fixed_len) {
    var saved = new Int32Array(10);
    LE = !!le;
    clear_state();
    set_word(0, iv[0], iv[1]);
    ascon_p(12);
    if (prefix) { absorb(prefix, 8, 12); }
    save(saved);
    clear_state();
    return ascon_instance(saved, new Uint8Array(8), 0, !!le, fixed_len);
}

function save(into) {
    for (var i = 0; i < 5; i++) { into[i] = sh[i]; into[5 + i] = sl[i]; }
}
function load(from) {
    for (var i = 0; i < 5; i++) { set_word(i, from[i], from[5 + i]); }
}

function ascon_instance(saved, buf, buf_len, le, fixed_len) {
    var finished = false, done = false, out_pos = 0;

    /* Run fn with this instance's state loaded, then put it back. */
    function with_state(fn) {
        LE = le;
        load(saved);
        try { return fn(); } finally { save(saved); clear_state(); }
    }

    function feed(msg) {
        var len = msg.length, off = 0, i;
        if (buf_len > 0) {
            var take = Math.min(8 - buf_len, len);
            for (i = 0; i < take; i++) { buf[buf_len + i] = msg[i]; }
            buf_len += take;
            off = take;
            if (buf_len < 8) { return; }
            xor_block(buf, 0, 8);
            ascon_p(12);
            buf_len = 0;
        }
        for (; len - off >= 8; off += 8) { xor_block(msg, off, 8); ascon_p(12); }
        for (i = 0; off + i < len; i++) { buf[i] = msg[off + i]; }
        buf_len = len - off;
    }

    function finish() {
        xor_block(buf, 0, buf_len);
        pad_bit(buf_len);
        ascon_p(12);
        buf.fill(0);
        finished = true;
    }

    function squeeze(n) {
        var out = new Uint8Array(n), produced = 0;
        while (produced < n) {
            if (out_pos === 8) { ascon_p(12); out_pos = 0; }
            out[produced++] = read_byte(out_pos++);
        }
        return out;
    }

    var self = {
        update: function (msg) {
            if (finished || done) { throw new Error('ascon: update() after the output was read'); }
            with_state(function () { feed(msg); });
            return self;
        },
        copy: function () {
            if (finished || done) { throw new Error('ascon: copy() after the output was read'); }
            return ascon_instance(new Int32Array(saved), new Uint8Array(buf), buf_len, le, fixed_len);
        },
        digest: function (out_len) {
            if (done) { throw new Error('ascon: digest() was already called on this instance'); }
            if (finished) { throw new Error('ascon: digest() after read(); keep calling read()'); }
            var n = fixed_len !== undefined ? fixed_len : (out_len === undefined ? 32 : out_len);
            done = true;
            var out = with_state(function () { finish(); return squeeze(n); });
            saved.fill(0);
            return out;
        }
    };
    if (fixed_len === undefined) {
        self.read = function (n) {
            if (done) { throw new Error('ascon: read() after digest()'); }
            return with_state(function () {
                if (!finished) { finish(); }
                return squeeze(n);
            });
        };
    }
    return self;
}

export function ascon_hash256_create()  { return ascon_sponge_create(IV.HASH256, null, true, 32); }
export function ascon_xof128_create()   { return ascon_sponge_create(IV.XOF128, null, true); }
export function ascon_hash_v12_create() { return ascon_sponge_create(IV.V12_HASH, null, false, 32); }
export function ascon_xof_v12_create()  { return ascon_sponge_create(IV.V12_XOF, null, false); }

/** As ascon_cxof128: the customisation string is fixed when the instance is made. */
export function ascon_cxof128_create(custom) {
    var c = custom || new Uint8Array(0);
    if (c.length > 256) { throw new Error('ascon: customisation string too long'); }
    var pre = new Uint8Array(8 + c.length);
    var bits = c.length * 8;
    for (var i = 0; i < 4; i++) { pre[i] = (bits >>> (8 * i)) & 0xff; }
    pre.set(c, 8);
    return ascon_sponge_create(IV.CXOF128, pre, true);
}
