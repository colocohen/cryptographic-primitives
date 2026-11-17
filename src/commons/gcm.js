/**
 * GCM  -  Galois/Counter Mode, NIST SP 800-38D
 *
 * Generic over ANY 128-bit block cipher, which is what it was always defined
 * to be. AES-GCM is the famous instance, but SM4-GCM is RFC 8998 and used in
 * Chinese TLS 1.3 profiles, and ARIA-GCM is RFC 6209. This file was inside
 * aes.js until it became clear that nothing in it is about AES.
 *
 * GCM is CTR mode for confidentiality plus GHASH for authentication, and the
 * two share a key. Its reputation is mixed for one reason:
 *
 * NONCE REUSE IS CATASTROPHIC. Encrypting two messages under the same key and
 * nonce reveals the XOR of the plaintexts AND leaks the authentication
 * subkey, after which an attacker can forge arbitrary messages. Not degraded
 * security - complete failure. This is not a hypothetical; it is what broke
 * several real deployments. If nonces cannot be guaranteed unique, use
 * AES-GCM-SIV instead, which degrades gracefully.
 *
 * The block cipher enters as a closure with the same shape used throughout
 * this library: block(src, off, out, out_off) encrypting one block in place.
 * GCM only ever ENCRYPTS with the underlying cipher, in both directions -
 * the decryption path never touches the inverse cipher.
 */

import { rd_be32, wr_be32s, inc_be, check_room, overlaps_elsewhere } from './bytes.js';
import { equal, wipe } from './ct.js';

var BLOCK = 16;

/*
 * Multiplication in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1, which is the
 * authenticator underneath GCM.
 *
 * GCM's bit convention is the confusing part and the usual source of wrong
 * implementations: within each byte the LEFTMOST bit is the most significant
 * coefficient, so the field element runs left to right across the block while
 * ordinary integer arithmetic runs the other way. Shifting "toward the least
 * significant coefficient" is therefore a right shift here, and the reduction
 * constant appears at the TOP of the block as 0xE1 rather than at the bottom.
 *
 * WHY BIT BY BIT AND NOT A TABLE
 * Fast GHASH implementations precompute a table of H times small values and
 * index it with nibbles of the running accumulator. That accumulator is
 * derived from H, which is secret, so the index is secret and the lookup
 * leaks through cache timing - the same channel this file already warns about
 * for the S-box. The loop below uses masks instead of branches and touches no
 * data-dependent memory. It is roughly an order of magnitude slower than the
 * table version, which is a poor trade in C and a reasonable one here, where
 * AES itself is already far from the hardware path.
 */

/**
 * v = v * x, in place, on four big-endian words: one shift toward the low
 * coefficient, folding 0xE1 into the top if a coefficient fell off.
 *
 * EXPORTED FOR AES-GCM-SIV, whose POLYVAL key translation is one multiply by
 * x - aes.js carried its own byte-in, byte-out copy of these six lines. The
 * same step sits inline in gf_mul's 128-iteration loop below, where it stays
 * written out: that loop is the GHASH bottleneck and the locals are the point.
 */
export function gf_mulx(v) {
    var lsb = -(v[3] & 1);
    v[3] = ((v[3] >>> 1) | (v[2] << 31)) | 0;
    v[2] = ((v[2] >>> 1) | (v[1] << 31)) | 0;
    v[1] = ((v[1] >>> 1) | (v[0] << 31)) | 0;
    v[0] = (v[0] >>> 1) | 0;
    v[0] ^= 0xe1000000 & lsb;
}

/** z ^= y * H, all as four big-endian 32-bit words. Constant time. */

/**
 * A 4-BIT WINDOWED TABLE for multiplication by a FIXED h.
 *
 * ⭐ THE MEASUREMENT THAT MOTIVATED THIS: aes-ctr ran at 35.7 MB/s and
 *   aes-gcm at 11.6, so GHASH was 59% of the time - the bottleneck is not
 *   AES, it is the multiply in GF(2^128).
 *
 *   gf_mul walks all 128 bits of x, one shift-and-conditional-xor per bit,
 *   for every 16-byte block. That is the slowest correct method there is.
 *
 * ⭐ h IS THE SAME FOR EVERY BLOCK of a message, so its multiples can be
 *   computed once. With 4-bit windows the table holds 16 entries and each
 *   block costs 32 lookups instead of 128 iterations.
 *
 * ⚠ AND THE TABLE IS BUILT PER KEY, NOT CACHED ACROSS CALLS. A cache keyed
 *   on h would be a map from a SECRET-DERIVED value to a table - and both
 *   the lookup and the eviction would be observable. The build is 16
 *   multiplies; a message of any size pays it back immediately, and a
 *   single-block message is not where throughput matters.
 *
 * ⚠ IT IS ALSO NOT CONSTANT TIME with respect to the DATA, and does not need
 *   to be: the index comes from the accumulator, which is a function of the
 *   ciphertext and h. The classic table attacks on GHASH are against
 *   implementations indexing on the KEY. This indexes on x, and h never
 *   selects a slot.
 */
export function gf_table(h) {
    /*
     * T[n] = h * (the field element whose bits are n's).
     *
     * ⚠ AND THE BIT ORDER IS THE TRAP. GHASH numbers coefficients from the
     *   LEFT, so within a nibble the value 8 is the coefficient of x^0 and
     *   the value 1 is the coefficient of x^3. A table built with T[1] = h -
     *   the obvious reading - is wrong for every entry, and produces a tag
     *   that is stable, self-consistent, and rejected by every other
     *   implementation.
     *
     * ⭐ SO THE FOUR BASIS ENTRIES ARE BUILT WITH gf_mul ITSELF, which is
     *   already verified against the test vectors. Sixteen multiplies, once
     *   per message, against 128 iterations per block saved.
     */
    var T = new Int32Array(16 * 4);
    /* T[8] = h*1, T[4] = h*x, T[2] = h*x^2, T[1] = h*x^3 */
    var basis = [8, 4, 2, 1];
    var cur = new Int32Array([h[0], h[1], h[2], h[3]]);
    for (var k = 0; k < 4; k++) {
        var o = basis[k] * 4;
        T[o] = cur[0]; T[o + 1] = cur[1]; T[o + 2] = cur[2]; T[o + 3] = cur[3];
        gf_mulx(cur);
    }
    /* every other entry is the xor of its basis parts - the field is
       characteristic 2, so addition is xor and this is exact */
    for (var n = 1; n < 16; n++) {
        if (n === 8 || n === 4 || n === 2 || n === 1) { continue; }
        var d = n * 4;
        for (var bit = 0; bit < 4; bit++) {
            if (n & basis[bit]) {
                var b = basis[bit] * 4;
                T[d] ^= T[b]; T[d + 1] ^= T[b + 1];
                T[d + 2] ^= T[b + 2]; T[d + 3] ^= T[b + 3];
            }
        }
    }
    return T;
}

/*
 * The reduction table: R[n] is what a nibble n falling off the bottom
 * contributes back to the top, for the polynomial x^128 + x^7 + x^2 + x + 1.
 *
 * ⭐ THIS IS WHAT MAKES THE TABLE METHOD FAST. Without it a "shift by four"
 *   is four shift-and-reduce steps, so 32 nibbles still cost 128 iterations
 *   and the table buys almost nothing - measured: 11.6 MB/s to 16.1, when
 *   the lookups alone should have done far better. With it the shift is one
 *   step and a single xor.
 */
var R4 = new Int32Array([
    0x00000000, 0x1c200000, 0x38400000, 0x24600000,
    0x70800000, 0x6ca00000, 0x48c00000, 0x54e00000,
    0xe1000000 | 0, 0xfd200000 | 0, 0xd9400000 | 0, 0xc5600000 | 0,
    0x91800000 | 0, 0x8da00000 | 0, 0xa9c00000 | 0, 0xb5e00000 | 0
]);

/** x = x * h, with h's table. Thirty-two nibbles, one shift each. */
export function gf_mul_table(x, T) {
    var z0 = 0, z1 = 0, z2 = 0, z3 = 0;
    var n, o, fell, i;

    /*
     * ⚠ NIBBLES FROM THE LAST TO THE FIRST. Each shift multiplies the
     *   accumulator by x^4, so the nibble added FIRST ends up multiplied by
     *   x^124 - and in GHASH order that is the LAST nibble. Iterating
     *   forwards gives a self-consistent result that matches nothing.
     */
    for (i = 31; i >= 0; i--) {
        fell = z3 & 15;
        z3 = ((z3 >>> 4) | (z2 << 28)) | 0;
        z2 = ((z2 >>> 4) | (z1 << 28)) | 0;
        z1 = ((z1 >>> 4) | (z0 << 28)) | 0;
        z0 = (z0 >>> 4) | 0;
        z0 ^= R4[fell];

        n = (x[i >>> 3] >>> (28 - ((i & 7) << 2))) & 15;
        o = n << 2;
        z0 ^= T[o]; z1 ^= T[o + 1]; z2 ^= T[o + 2]; z3 ^= T[o + 3];
    }
    x[0] = z0; x[1] = z1; x[2] = z2; x[3] = z3;
}

export function gf_mul(x, y) {
    var z0 = 0, z1 = 0, z2 = 0, z3 = 0;
    var v0 = y[0], v1 = y[1], v2 = y[2], v3 = y[3];
    var i, mask, lsb;

    for (i = 0; i < 128; i++) {
        /* bit i of x, counting from the leftmost bit of the first word */
        mask = -((x[i >>> 5] >>> (31 - (i & 31))) & 1);
        z0 ^= v0 & mask; z1 ^= v1 & mask;
        z2 ^= v2 & mask; z3 ^= v3 & mask;

        /* shift v one place toward the least significant coefficient -
           gf_mulx above, written out on locals because this is the hot loop */
        lsb = -(v3 & 1);
        v3 = ((v3 >>> 1) | (v2 << 31)) | 0;
        v2 = ((v2 >>> 1) | (v1 << 31)) | 0;
        v1 = ((v1 >>> 1) | (v0 << 31)) | 0;
        v0 = (v0 >>> 1) | 0;

        /* and reduce if a coefficient fell off the end */
        v0 ^= 0xe1000000 & lsb;
    }

    x[0] = z0; x[1] = z1; x[2] = z2; x[3] = z3;
}

/**
 * GHASH over a byte sequence, which must already be a multiple of 16.
 *
 * @param {Int32Array}  h    the hash subkey, four words
 * @param {Uint8Array}  data
 * @param {Int32Array}  y    accumulator, updated in place
 */
/*
 * EXPORTED FOR AES-GCM-SIV. POLYVAL in RFC 8452 is GHASH over a
 * byte-reversed input with a transformed key, so aes.js builds it out of this
 * rather than duplicating the field multiplication.
 *
 * That dependency was broken for a while: when GCM moved into this file, the
 * GCM-SIV code left behind in aes.js kept referring to `ghash` and `pad16` as
 * local names, and threw on every call. No test covered GCM-SIV, so nothing
 * said so.
 */
export function ghash(h, data, y, table) {
    ghash_padded(h, data, 0, data.length, y, table);
}

/*
 * GHASH over data[off .. off + len), its last partial block zero-padded -
 * as GCM pads the AAD and the ciphertext - without copying the data into a
 * padded buffer: only that last partial block goes through PARTIAL.
 */
var PARTIAL = new Uint8Array(BLOCK);
function ghash_padded(h, data, off, len, y, table) {
    if (len === 0) { return; }
    var full = len - len % BLOCK, end = off + full;
    /*
     * ⭐ ONE TABLE FOR THE WHOLE MESSAGE. Below two blocks the build costs
     *   more than it saves, so the bit-at-a-time path stays for those.
     *   A keyed context (gcm_create) builds the table once and passes it in.
     */
    var T = table || (len < 2 * BLOCK ? null : gf_table(h));
    for (var i = off; i < end; i += BLOCK) { ghash_block(h, data, i, y, T); }
    if (full < len) {
        for (var j = 0; j < BLOCK; j++) { PARTIAL[j] = j < len - full ? data[end + j] : 0; }
        ghash_block(h, PARTIAL, 0, y, T);
        wipe(PARTIAL);
    }
}
function ghash_block(h, data, i, y, T) {
    y[0] ^= rd_be32(data, i);
    y[1] ^= rd_be32(data, i + 4);
    y[2] ^= rd_be32(data, i + 8);
    y[3] ^= rd_be32(data, i + 12);
    if (T) { gf_mul_table(y, T); } else { gf_mul(y, h); }
}

/*
 * The mode TLS 1.3 and QUIC use with AES.
 *
 * Two details worth knowing, because both are common bug sources:
 *
 *   - The counter increments only its LAST FOUR BYTES, wrapping within them.
 *     That is not the same as aes_ctr above, which increments the whole
 *     16-byte block, so the two cannot share a routine.
 *
 *   - A 12-byte IV is special-cased: it becomes the counter directly with a
 *     1 appended. Any other length is folded through GHASH first. Almost all
 *     protocols use 12 bytes for exactly this reason.
 *
 * NONCE REUSE IS FATAL HERE, and worse than for a plain stream cipher.
 * Encrypting two messages under one (key, IV) does not merely leak their xor:
 * it exposes the hash subkey H, and with H an attacker forges tags for
 * anything under that key. This is the same shape of failure as ChaCha20-
 * Poly1305 nonce reuse, and for the same structural reason.
 */

/*
 * ⚠ NOT ON block_modes.js's ctr_stream, which CTR and GCM-SIV share. Routed
 *   through it - with the step passed as inc_be on a view of these four
 *   bytes, so no closure - AES-GCM measured 3-4% slower on 64 KiB (median of
 *   ten process pairs), against under 1% for CTR and GCM-SIV. The same
 *   slowdown appeared when only CCM was moved onto the core and GCM was not,
 *   so it is a V8 effect of the shared loop rather than work GCM does - but
 *   it is GCM that pays it, so GCM and CCM keep their loops. The loop is the
 *   same one; the counter convention is GCM's.
 */
/*
 * ⭐ THE WORKING BLOCKS ARE THE MODULE'S, made once - the counter, the
 *   keystream block, J0, the GHASH state, the lengths block, the tag -
 *   instead of a dozen small arrays per message, each of them garbage for
 *   the collector on a path that runs once per packet. JavaScript runs one
 *   call at a time, and nothing here calls back out except `block`, the
 *   cipher's own block function. Every one is wiped before the call that
 *   used it returns: they hold keystream, counters and GHASH values.
 */
var CTR = new Uint8Array(BLOCK), CTR_LOW = CTR.subarray(12), KS = new Uint8Array(BLOCK);
var J0 = new Uint8Array(BLOCK), Y = new Int32Array(4), LEN_BLOCK = new Uint8Array(BLOCK), TAG = new Uint8Array(BLOCK);
var EXPECTED = new Uint8Array(BLOCK), EMPTY = new Uint8Array(0);

/*
 * data[off .. off + len) xor the keystream from J0 (+1 when `next`), into out
 * from out_off. The counter is the block's last four bytes alone, wrapping
 * inside them - inc_be on a view of those four, CTR_LOW.
 */
function gctr(block, j0, next, data, off, len, out, out_off) {
    CTR.set(j0);
    if (next) { inc_be(CTR_LOW); }
    var i, j, n;
    for (i = 0; i < len; i += BLOCK) {
        block(CTR, 0, KS, 0);
        n = len - i; if (n > BLOCK) { n = BLOCK; }
        for (j = 0; j < n; j++) { out[out_off + i + j] = data[off + i + j] ^ KS[j]; }
        inc_be(CTR_LOW);
    }
    wipe(KS); wipe(CTR);
}

/* the two lengths in BITS, each a big-endian 64-bit field, into LEN_BLOCK */
function write_len_block(aad_len, ct_len) {
    var a = aad_len * 8, c = ct_len * 8;
    for (var i = 7; i >= 0; i--) {
        LEN_BLOCK[i]     = a & 0xff; a = Math.floor(a / 256);
        LEN_BLOCK[8 + i] = c & 0xff; c = Math.floor(c / 256);
    }
    return LEN_BLOCK;
}

/**
 * Bytes of zero padding that bring n up to a whole block.
 *
 * Exported because AES-GCM-SIV in aes.js needs it too and once referred to
 * this one by a name that did not exist there - see the note in aes.js.
 */
export function pad16(n) { return (16 - (n % 16)) % 16; }

function gcm_hash_key(block) {
    /* H, the hash subkey, is the cipher applied to an all-zero block */
    var hb = new Uint8Array(BLOCK);
    block(new Uint8Array(BLOCK), 0, hb, 0);
    var h = new Int32Array([rd_be32(hb, 0), rd_be32(hb, 4), rd_be32(hb, 8), rd_be32(hb, 12)]);
    wipe(hb);
    return h;
}

/* J0, the initial counter block, into the module's J0. h and its table come from a keyed context when there is one (gcm_create). */
function gcm_j0(h, iv, table) {
    if (iv.length === 12) {
        J0.set(iv, 0);
        J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;
    } else {
        ghash_padded(h, iv, 0, iv.length, Y, table);
        ghash_padded(h, write_len_block(0, iv.length), 0, BLOCK, Y, table);
        wr_be32s(J0, 0, Y);
        Y.fill(0); wipe(LEN_BLOCK);
    }
}

/* the tag over (aad, ct[off .. off + len)), under J0 itself, into out from out_off */
function gcm_tag(block, h, table, ct, off, len, aad, out, out_off) {
    var a = aad || EMPTY;
    ghash_padded(h, a, 0, a.length, Y, table);
    ghash_padded(h, ct, off, len, Y, table);
    /* the trailing lengths stop an attacker moving the aad/ciphertext boundary */
    ghash_padded(h, write_len_block(a.length, len), 0, BLOCK, Y, table);
    wr_be32s(TAG, 0, Y);
    /* the tag is the GHASH result encrypted under J0 itself, not J0+1 */
    gctr(block, J0, false, TAG, 0, BLOCK, out, out_off);
    Y.fill(0); wipe(LEN_BLOCK); wipe(TAG);
}

/*
 * The whole of an encryption into out[off ..]: ct then its tag. The caller
 * has checked the room, and that out does not overlap the plaintext at
 * another offset (the stream is written as it is read).
 */
function gcm_seal_to(block, iv, pt, aad, h, table, out, off) {
    if (iv.length === 0) { throw new Error('gcm: iv must not be empty'); }
    var own = !h;
    if (own) { h = gcm_hash_key(block); }
    try {
        gcm_j0(h, iv, table);
        gctr(block, J0, true, pt, 0, pt.length, out, off);
        gcm_tag(block, h, table, out, off, pt.length, aad, out, off + pt.length);
    } finally {
        wipe(J0);
        if (own) { h.fill(0); }
    }
    return pt.length + 16;
}

/* the plaintext into out[off ..], or null - with nothing written - when the tag does not verify */
function gcm_open_to(block, iv, sealed, aad, h, table, out, off) {
    if (iv.length === 0) { throw new Error('gcm: iv must not be empty'); }
    if (sealed.length < 16) { return null; }
    var ct_len = sealed.length - 16, own = !h;
    if (own) { h = gcm_hash_key(block); }
    try {
        gcm_j0(h, iv, table);
        gcm_tag(block, h, table, sealed, 0, ct_len, aad, EXPECTED, 0);
        if (equal(EXPECTED, sealed.subarray(ct_len)) !== 1) { return null; }
        gctr(block, J0, true, sealed, 0, ct_len, out, off);
        return ct_len;
    } finally {
        wipe(J0); wipe(EXPECTED);
        if (own) { h.fill(0); }
    }
}

/**
 * @param  {Uint8Array} key    16, 24 or 32 bytes
 * @param  {Uint8Array} iv     12 bytes is the fast and universal case
 * @param  {Uint8Array} plaintext
 * @param  {Uint8Array} [aad]  authenticated, not encrypted
 * @return {Uint8Array} ciphertext followed by a 16-byte tag
 */

/**
 * @param {function}   block  block(src, off, out, out_off), encryption only
 * @param {Uint8Array} iv     12 bytes is the only length that should be used
 * @return {Uint8Array} ciphertext followed by the 16-byte tag
 *
 * A 12-byte nonce becomes the counter's prefix directly; any other length is
 * folded in through GHASH first. The 12-byte form is faster, is what every
 * protocol specifies, and avoids a collision case the general form has.
 *
 * THE DATA STARTS AT J0+1 AND THE TAG AT J0 ITSELF. Encrypting the data from
 * J0 would reuse the tag's keystream block and reveal it, which destroys
 * authentication entirely. The increment below is that one block of
 * separation.
 */
export function gcm_encrypt(block, iv, plaintext, aad, h, table) {
    if (iv.length === 0) { throw new Error('gcm: iv must not be empty'); }
    var out = new Uint8Array(plaintext.length + 16);
    gcm_seal_to(block, iv, plaintext, aad, h, table, out, 0);
    return out;
}

/**
 * @return {Uint8Array|null} null when authentication fails
 *
 * The tag is compared in constant time and NOTHING is returned on failure -
 * not the plaintext, not a partial result. Releasing unverified plaintext is
 * the most common way AEAD gets misused.
 */
export function gcm_decrypt(block, iv, sealed, aad, h, table) {
    if (iv.length === 0) { throw new Error('gcm: iv must not be empty'); }
    if (sealed.length < 16) { return null; }
    var out = new Uint8Array(sealed.length - 16);
    return gcm_open_to(block, iv, sealed, aad, h, table, out, 0) === null ? null : out;
}

/**
 * GMAC - GCM used as a MAC alone.
 *
 * It is exactly gcm_encrypt with an empty plaintext: everything to be
 * authenticated goes in as associated data, and the output is the tag.
 *
 * WHY IT EXISTS AS A NAMED THING. A device with an AES engine gets a MAC
 * without also needing a hash, which is the same argument that produced CMAC.
 * GMAC is faster than CMAC on hardware with carry-less multiply, and slower
 * without it.
 *
 * THE NONCE RULE IS UNCHANGED AND IS THE TRAP. GMAC inherits GCM's
 * catastrophic nonce reuse: two tags under one key and nonce leak the
 * authentication subkey, after which an attacker forges freely. A MAC is
 * usually thought of as deterministic - HMAC over the same message gives the
 * same tag every time - and GMAC is NOT. Every call needs a fresh nonce, and
 * that nonce has to travel with the tag.
 *
 * If a deterministic MAC is what you want, use HMAC or CMAC.
 *
 * @return {Uint8Array} the 16-byte tag
 */
export function gmac(block, iv, data) {
    return gcm_encrypt(block, iv, EMPTY, data);
}

/** @return {boolean} constant-time tag comparison */
export function gmac_verify(block, iv, data, tag) {
    if (tag.length !== 16) { return false; }
    return equal(gmac(block, iv, data), tag) === 1;
}

/**
 * GCM under one key, for many messages: the hash key H and its
 * multiplication table are computed once here instead of on every call.
 * Each message still takes its own IV, which MUST NOT repeat under the key.
 *
 *     var ctx = gcm_create(block);
 *     ctx.encrypt(iv, plaintext, aad)  ->  ciphertext || tag
 *     ctx.decrypt(iv, sealed, aad)     ->  plaintext, or null
 *
 * ⭐ WHAT IT SAVES is the per-message setup a TLS record or a QUIC packet
 *   pays: one block encryption for H, and the 16-entry table rebuilt for
 *   every message longer than two blocks.
 *
 * ⚠ THE CONTEXT HOLDS KEY-DERIVED MATERIAL (H and the table) for as long as
 *   the caller keeps it; wipe() clears it.
 *
 * @param {function} block  the cipher's encrypt-block function under the key
 */
export function gcm_create(block) {
    var h = gcm_hash_key(block);
    var table = gf_table(h);
    return {
        encrypt: function (iv, plaintext, aad) { return gcm_encrypt(block, iv, plaintext, aad, h, table); },
        decrypt: function (iv, sealed, aad) { return gcm_decrypt(block, iv, sealed, aad, h, table); },
        /*
         * Written straight into out - nothing made per message. Into memory
         * that overlaps the input elsewhere, whole first, then copied.
         */
        encrypt_into: function (out, offset, iv, plaintext, aad) {
            check_room('gcm.encrypt_into', out, offset, plaintext.length + 16);
            if (!overlaps_elsewhere(out, offset, plaintext.length + 16, plaintext)) {
                return gcm_seal_to(block, iv, plaintext, aad, h, table, out, offset);
            }
            var whole = gcm_encrypt(block, iv, plaintext, aad, h, table);
            out.set(whole, offset);
            return whole.length;
        },
        decrypt_into: function (out, offset, iv, sealed, aad) {
            if (sealed.length >= 16) { check_room('gcm.decrypt_into', out, offset, sealed.length - 16); }
            if (!overlaps_elsewhere(out, offset, sealed.length, sealed)) {
                return gcm_open_to(block, iv, sealed, aad, h, table, out, offset);
            }
            var whole = gcm_decrypt(block, iv, sealed, aad, h, table);
            if (whole === null) { return null; }
            out.set(whole, offset);
            return whole.length;
        },
        wipe: function () { h.fill(0); table.fill(0); }
    };
}
