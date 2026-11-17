/**
 * BLAKE2 family  -  RFC 7693
 *
 * BLAKE2b (64-bit words, 128-byte blocks, up to 64-byte digest) and
 * BLAKE2s (32-bit words, 64-byte blocks, up to 32-byte digest).
 *
 * An ARX design: addition, rotation and xor only. No S-box and no tables, so
 * no cache-timing exposure - a real advantage in JS compared to AES.
 *
 * The construction is HAIFA, neither Merkle-Damgard nor a sponge: the
 * compression function also receives the byte counter and a last-block flag.
 * Those two prevent length extension, which is why BLAKE2 needs no HMAC - it
 * has a built-in keyed mode that costs one pass instead of two.
 *
 * The core derives from ChaCha20. The G function is almost the same
 * quarter-round, with different rotation amounts.
 *
 * The two variants share the message permutation and the entire driver -
 * parameter block, key handling, block loop, counter bookkeeping,
 * last-block detection, output writing - which turned out identical verbatim
 * when they were written separately. They share nothing in the compression
 * function: BLAKE2b is 64-bit with manual carry, BLAKE2s plain 32-bit.
 *
 * CHOOSING BETWEEN THEM IN JS
 * Measured on 64 KB: BLAKE2s 56 MB/s, BLAKE2b 23 MB/s. BLAKE2s is roughly
 * 2.3x faster despite being the "small" one, the opposite of the picture in
 * languages with native 64-bit integers - every 64-bit word here pays for
 * manual carry propagation. If a 256-bit digest is enough, prefer BLAKE2s.
 *
 * BigInt was benchmarked for the 64-bit half and rejected: 39 MB/s hi/lo vs
 * 3.1 MB/s BigInt on 1 KB (12.8x). The cost is allocation - every BigInt
 * operation produces a heap object, and this runs 12 rounds of eight G calls
 * per 128-byte block.
 */

import { arx_g32, arx_round32 } from './commons/arx32.js';

/**
 * Message permutation. Ten rows; BLAKE2s runs all of them once, and BLAKE2b
 * wraps back to the first two for rounds 10 and 11.
 */
var SIGMA = new Int32Array([
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3,
    11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4,
     7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8,
     9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13,
     2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9,
    12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11,
    13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10,
     6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5,
    10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0
]);

/*
 * The chaining value after the parameter block: output length, key length,
 * fanout, depth, salt and personalisation. Shared by the one-shot and the
 * incremental form, so the two cannot drift apart.
 */
function blake2_init(p, out_len, key, opts) {
    if (out_len === undefined) { out_len = p.max_digest; }
    if (out_len < 1 || out_len > p.max_digest) {
        throw new Error(p.name + ': out_len must be 1..' + p.max_digest);
    }
    var key_len = key ? key.length : 0;
    if (key_len > p.max_key) {
        throw new Error(p.name + ': key must be at most ' + p.max_key + ' bytes');
    }

    var h = new Int32Array(p.iv);
    var i;

    /* Parameter block: output length, key length, fanout and depth */
    h[0] ^= 0x01010000 ^ (key_len << 8) ^ out_len;
    /* salt and personalisation: the third and fourth quarters of the block's
       first half (bytes 32 and 48 for BLAKE2b, 16 and 24 for BLAKE2s), xored
       into the IV little-endian like the rest of the parameter block */
    if (opts && (opts.salt || opts.personal)) {
        var q = p.max_digest >> 2;
        var fields = [[opts.salt, 2 * q], [opts.personal, 3 * q]];
        for (var f = 0; f < 2; f++) {
            var v = fields[f][0], at = fields[f][1];
            if (!v) { continue; }
            if (!(v instanceof Uint8Array) || v.length > q) {
                throw new Error(p.name + ': salt and personal must be at most ' + q + ' bytes');
            }
            for (i = 0; i < v.length; i++) { h[(at + i) >> 2] ^= v[i] << (8 * ((at + i) & 3)); }
        }
    }

    return h;
}

/**
 * @param {object} p
 *   p.compress    function(h, buf, off, t_lo, t_hi, last)
 *   p.iv          Int32Array - initial hash values
 *   p.block_size  128 (BLAKE2b) or 64 (BLAKE2s)
 *   p.max_digest  64 or 32
 *   p.max_key     64 or 32
 *   p.name        used in error messages
 * @param {Uint8Array} msg
 * @param {number}     [out_len]  defaults to max_digest
 * @param {Uint8Array} [key]      keyed mode, in place of HMAC
 * @param {object}     [opts]     { salt, personal } - RFC 7693 section 2.5's
 *                                parameter-block fields, up to max_digest/4
 *                                bytes each, zero-padded (libsodium's
 *                                crypto_kdf and crypto_generichash_salt_personal
 *                                use them)
 * @return {Uint8Array}
 */
function blake2_hash(p, msg, out_len, key, opts) {
    var block_size = p.block_size;

    if (out_len === undefined) { out_len = p.max_digest; }
    var key_len = key ? key.length : 0;
    var h = blake2_init(p, out_len, key, opts);
    var i;

    var len = msg.length;
    var t_lo = 0, t_hi = 0;
    var block = new Uint8Array(block_size);

    /* The key, if present, goes in as a full first block, zero padded */
    if (key_len > 0) {
        for (i = 0; i < key_len; i++) { block[i] = key[i]; }
        for (i = key_len; i < block_size; i++) { block[i] = 0; }
        if (len === 0) {
            /* key only - this block is also the last */
            p.compress(h, block, 0, block_size, 0, true);
            return finish(h, out_len, block);
        }
        p.compress(h, block, 0, block_size, 0, false);
        t_lo = block_size;
    }

    /*
     * Every block except the last. Note the condition: a block that lands exactly
     * at the end still counts as the last one, hence < and not <=.
     */
    var off = 0;
    while (len - off > block_size) {
        t_lo = (t_lo + block_size) | 0;
        if ((t_lo >>> 0) < block_size) { t_hi = (t_hi + 1) | 0; }
        p.compress(h, msg, off, t_lo, t_hi, false);
        off += block_size;
    }

    /* The last block - zero padded, and the counter tracks real bytes only */
    var rem = len - off;
    for (i = 0; i < rem; i++) { block[i] = msg[off + i]; }
    for (i = rem; i < block_size; i++) { block[i] = 0; }
    t_lo = (t_lo + rem) | 0;
    if ((t_lo >>> 0) < (rem >>> 0)) { t_hi = (t_hi + 1) | 0; }
    p.compress(h, block, 0, t_lo, t_hi, true);

    return finish(h, out_len, block);
}

function finish(h, out_len, scratch) {
    var out = new Uint8Array(out_len), i;
    for (i = 0; i < out_len; i++) {
        out[i] = (h[i >>> 2] >>> ((i & 3) * 8)) & 0xff;
    }
    for (i = 0; i < h.length; i++) { h[i] = 0; }
    for (i = 0; i < scratch.length; i++) { scratch[i] = 0; }
    return out;
}

/* ---------------- BLAKE2b: 64-bit ---------------- */

var BLOCK_SIZE_BLAKE2B  = 128;
var MAX_DIGEST_BLAKE2B  = 64;
var MAX_KEY_BLAKE2B     = 64;
var ROUNDS_BLAKE2B      = 12;

/* Same IV as SHA-512, as lo/hi pairs */
var IV_BLAKE2B = new Int32Array([
    0xf3bcc908|0, 0x6a09e667|0,  0x84caa73b|0, 0xbb67ae85|0,
    0xfe94f82b|0, 0x3c6ef372|0,  0x5f1d36f1|0, 0xa54ff53a|0,
    0xade682d1|0, 0x510e527f|0,  0x2b3e6c1f|0, 0x9b05688c|0,
    0xfb41bd6b|0, 0x1f83d9ab|0,  0x137e2179|0, 0x5be0cd19|0
]);

/* Working state - allocated once, not per block */
var v_blake2b = new Int32Array(32);
var m_blake2b = new Int32Array(32);

/**
 * The G function. Operates on v in place.
 * Each step: a 64-bit add with manual carry, then xor and rotate right.
 */
function G_b(a, b, c, d, x, y) {
    var a2 = a * 2, b2 = b * 2, c2 = c * 2, d2 = d * 2;
    var lo, hi, carry, t_lo, t_hi;

    /* va = va + vb + x */
    lo = (v_blake2b[a2] + v_blake2b[b2]) | 0;
    carry = ((lo >>> 0) < (v_blake2b[b2] >>> 0)) ? 1 : 0;
    hi = (((v_blake2b[a2 + 1] + v_blake2b[b2 + 1]) | 0) + carry) | 0;
    lo = (lo + m_blake2b[x * 2]) | 0;
    carry = ((lo >>> 0) < (m_blake2b[x * 2] >>> 0)) ? 1 : 0;
    hi = (((hi + m_blake2b[x * 2 + 1]) | 0) + carry) | 0;
    v_blake2b[a2] = lo; v_blake2b[a2 + 1] = hi;

    /* vd = rotr64(vd ^ va, 32) - a rotation by 32 is just swapping lo and hi */
    t_lo = v_blake2b[d2] ^ lo; t_hi = v_blake2b[d2 + 1] ^ hi;
    v_blake2b[d2] = t_hi; v_blake2b[d2 + 1] = t_lo;

    /* vc = vc + vd */
    lo = (v_blake2b[c2] + v_blake2b[d2]) | 0;
    carry = ((lo >>> 0) < (v_blake2b[d2] >>> 0)) ? 1 : 0;
    hi = (((v_blake2b[c2 + 1] + v_blake2b[d2 + 1]) | 0) + carry) | 0;
    v_blake2b[c2] = lo; v_blake2b[c2 + 1] = hi;

    /* vb = rotr64(vb ^ vc, 24) */
    t_lo = v_blake2b[b2] ^ lo; t_hi = v_blake2b[b2 + 1] ^ hi;
    v_blake2b[b2]     = ((t_lo >>> 24) | (t_hi << 8)) | 0;
    v_blake2b[b2 + 1] = ((t_hi >>> 24) | (t_lo << 8)) | 0;

    /* va = va + vb + y */
    lo = (v_blake2b[a2] + v_blake2b[b2]) | 0;
    carry = ((lo >>> 0) < (v_blake2b[b2] >>> 0)) ? 1 : 0;
    hi = (((v_blake2b[a2 + 1] + v_blake2b[b2 + 1]) | 0) + carry) | 0;
    lo = (lo + m_blake2b[y * 2]) | 0;
    carry = ((lo >>> 0) < (m_blake2b[y * 2] >>> 0)) ? 1 : 0;
    hi = (((hi + m_blake2b[y * 2 + 1]) | 0) + carry) | 0;
    v_blake2b[a2] = lo; v_blake2b[a2 + 1] = hi;

    /* vd = rotr64(vd ^ va, 16) */
    t_lo = v_blake2b[d2] ^ lo; t_hi = v_blake2b[d2 + 1] ^ hi;
    v_blake2b[d2]     = ((t_lo >>> 16) | (t_hi << 16)) | 0;
    v_blake2b[d2 + 1] = ((t_hi >>> 16) | (t_lo << 16)) | 0;

    /* vc = vc + vd */
    lo = (v_blake2b[c2] + v_blake2b[d2]) | 0;
    carry = ((lo >>> 0) < (v_blake2b[d2] >>> 0)) ? 1 : 0;
    hi = (((v_blake2b[c2 + 1] + v_blake2b[d2 + 1]) | 0) + carry) | 0;
    v_blake2b[c2] = lo; v_blake2b[c2 + 1] = hi;

    /* vb = rotr64(vb ^ vc, 63) - equivalent to rotl64 by 1 */
    t_lo = v_blake2b[b2] ^ lo; t_hi = v_blake2b[b2 + 1] ^ hi;
    v_blake2b[b2]     = ((t_hi >>> 31) | (t_lo << 1)) | 0;
    v_blake2b[b2 + 1] = ((t_lo >>> 31) | (t_hi << 1)) | 0;
}

/**
 * Compresses one 128-byte block into h.
 *
 * @param {Int32Array}  h      hash state, 8 words as pairs
 * @param {Uint8Array}  buf
 * @param {number}      off
 * @param {number}      t_lo   count of bytes consumed so far
 * @param {number}      t_hi
 * @param {boolean}     last   last-block flag
 */
function compress_blake2b(h, buf, off, t_lo, t_hi, last) {
    var i, r, s;

    for (i = 0; i < 32; i++) {
        m_blake2b[i] = ((buf[off]) | (buf[off + 1] << 8) |
                (buf[off + 2] << 16) | (buf[off + 3] << 24)) | 0;
        off += 4;
    }

    for (i = 0; i < 16; i++) { v_blake2b[i] = h[i]; }
    for (i = 0; i < 16; i++) { v_blake2b[16 + i] = IV_BLAKE2B[i]; }

    /* The byte counter goes into v_blake2b[12], and the final flag inverts v_blake2b[14] */
    v_blake2b[24] ^= t_lo;
    v_blake2b[25] ^= t_hi;
    if (last) { v_blake2b[28] = ~v_blake2b[28]; v_blake2b[29] = ~v_blake2b[29]; }

    for (r = 0; r < ROUNDS_BLAKE2B; r++) {
        s = (r % 10) * 16;
        G_b(0, 4,  8, 12, SIGMA[s],      SIGMA[s + 1]);
        G_b(1, 5,  9, 13, SIGMA[s + 2],  SIGMA[s + 3]);
        G_b(2, 6, 10, 14, SIGMA[s + 4],  SIGMA[s + 5]);
        G_b(3, 7, 11, 15, SIGMA[s + 6],  SIGMA[s + 7]);
        G_b(0, 5, 10, 15, SIGMA[s + 8],  SIGMA[s + 9]);
        G_b(1, 6, 11, 12, SIGMA[s + 10], SIGMA[s + 11]);
        G_b(2, 7,  8, 13, SIGMA[s + 12], SIGMA[s + 13]);
        G_b(3, 4,  9, 14, SIGMA[s + 14], SIGMA[s + 15]);
    }

    for (i = 0; i < 16; i++) { h[i] ^= v_blake2b[i] ^ v_blake2b[16 + i]; }
}


/**
 * @param {Uint8Array} msg
 * @param {number}     [out_len=64]  1..64 bytes
 * @param {Uint8Array} [key]         up to 64 bytes - keyed mode, in place of HMAC
 * @return {Uint8Array}
 */
/*
 * ⛔ NOT ATTACHED AS blake2b.PARAMS. hmac() takes a hash with a PARAMS property
 *   to be Merkle-Damgard and computes it through hmac_fast's midstate, which
 *   would be wrong for BLAKE2. The incremental form reads it from here.
 */
var PARAMS_BLAKE2B = {
    compress:   compress_blake2b,
    iv:         IV_BLAKE2B,
    block_size: 128,
    max_digest: 64,
    max_key:    64,
    name:       'blake2b'
};

export var blake2b = /* @__PURE__ */ (function () {
    var PARAMS = PARAMS_BLAKE2B;
    function blake2b(msg, out_len, key, opts) { return blake2_hash(PARAMS, msg, out_len, key, opts); }
    blake2b.BLOCK_SIZE  = 128;
    blake2b.DIGEST_SIZE = 64;
    blake2b.MAX_KEY     = 64;
    blake2b.create = blake2b_create;
    return blake2b;
}());

/* ---------------- BLAKE2s: 32-bit ---------------- */

var BLOCK_SIZE_BLAKE2S = 64;
var MAX_DIGEST_BLAKE2S = 32;
var MAX_KEY_BLAKE2S    = 32;
var ROUNDS_BLAKE2S     = 10;

/* Same IV as SHA-256, by design. Not shared as code - see the note in
   commons/arx32.js on extracting behaviour rather than equal values. */
var IV_BLAKE2S = new Int32Array([
    0x6a09e667|0, 0xbb67ae85|0, 0x3c6ef372|0, 0xa54ff53a|0,
    0x510e527f|0, 0x9b05688c|0, 0x1f83d9ab|0, 0x5be0cd19|0
]);

var v_blake2s = new Int32Array(16);
var m_blake2s = new Int32Array(16);

/**
 * Compresses one 64-byte block into h.
 * The G function is written inline rather than called - otherwise it would be
 * 80 calls per block.
 */
function compress_blake2s(h, buf, off, t_lo, t_hi, last) {
    var i, r, s, a, b, c, d;

    for (i = 0; i < 16; i++) {
        m_blake2s[i] = ((buf[off]) | (buf[off + 1] << 8) |
                (buf[off + 2] << 16) | (buf[off + 3] << 24)) | 0;
        off += 4;
    }

    for (i = 0; i < 8; i++) { v_blake2s[i] = h[i]; }
    for (i = 0; i < 8; i++) { v_blake2s[8 + i] = IV_BLAKE2S[i]; }

    v_blake2s[12] ^= t_lo;
    v_blake2s[13] ^= t_hi;
    if (last) { v_blake2s[14] = ~v_blake2s[14]; }

    for (r = 0; r < ROUNDS_BLAKE2S; r++) { arx_round32(v_blake2s, m_blake2s, SIGMA, r * 16); }

    for (i = 0; i < 8; i++) { h[i] ^= v_blake2s[i] ^ v_blake2s[8 + i]; }
}


/**
 * @param {Uint8Array} msg
 * @param {number}     [out_len=32]  1..32 bytes
 * @param {Uint8Array} [key]         up to 32 bytes - keyed mode, in place of HMAC
 * @return {Uint8Array}
 */
/*
 * ⛔ NOT ATTACHED AS blake2s.PARAMS. hmac() takes a hash with a PARAMS property
 *   to be Merkle-Damgard and computes it through hmac_fast's midstate, which
 *   would be wrong for BLAKE2. The incremental form reads it from here.
 */
var PARAMS_BLAKE2S = {
    compress:   compress_blake2s,
    iv:         IV_BLAKE2S,
    block_size: 64,
    max_digest: 32,
    max_key:    32,
    name:       'blake2s'
};

export var blake2s = /* @__PURE__ */ (function () {
    var PARAMS = PARAMS_BLAKE2S;
    function blake2s(msg, out_len, key, opts) { return blake2_hash(PARAMS, msg, out_len, key, opts); }
    blake2s.BLOCK_SIZE  = 64;
    blake2s.DIGEST_SIZE = 32;
    blake2s.MAX_KEY     = 32;
    blake2s.create = blake2s_create;
    return blake2s;
}());

/* ---------------- Incremental ---------------- */

/*
 * The same hashes, fed in pieces: update() as often as needed, digest()
 * once; copy() forks the state. Same arguments as the one-shot form, minus
 * the message.
 *
 * ⭐ ONE FULL BLOCK IS ALWAYS HELD BACK. BLAKE2 flags the LAST block in its
 *   compression, and a block that fills exactly is not known to be the last
 *   until more data arrives or digest() is called - so it is compressed only
 *   then. A key goes in the same way, as a pending first block.
 */
function blake2_create(p, out_len, key, opts) {
    if (out_len === undefined) { out_len = p.max_digest; }
    var h = blake2_init(p, out_len, key, opts);
    var buf = new Uint8Array(p.block_size);
    var buf_len = 0;
    if (key && key.length > 0) {
        buf.set(key);
        buf_len = p.block_size;
    }
    return blake2_instance(p, out_len, h, buf, buf_len, 0, 0);
}

function blake2_instance(p, out_len, h, buf, buf_len, t_lo, t_hi) {
    var block_size = p.block_size;
    var done = false;

    function check() {
        if (done) { throw new Error(p.name + ': digest() was already called on this instance'); }
    }
    function count(n) {
        t_lo = (t_lo + n) | 0;
        if ((t_lo >>> 0) < (n >>> 0)) { t_hi = (t_hi + 1) | 0; }
    }

    var self = {
        update: function (msg) {
            check();
            var len = msg.length, off = 0, i;
            while (off < len) {
                if (buf_len === block_size) {
                    count(block_size);
                    p.compress(h, buf, 0, t_lo, t_hi, false);
                    buf_len = 0;
                }
                /* whole blocks straight from msg, all but a final one */
                while (buf_len === 0 && len - off > block_size) {
                    count(block_size);
                    p.compress(h, msg, off, t_lo, t_hi, false);
                    off += block_size;
                }
                var take = Math.min(block_size - buf_len, len - off);
                for (i = 0; i < take; i++) { buf[buf_len + i] = msg[off + i]; }
                buf_len += take;
                off += take;
            }
            return self;
        },
        copy: function () {
            check();
            return blake2_instance(p, out_len, new Int32Array(h), new Uint8Array(buf), buf_len, t_lo, t_hi);
        },
        digest: function () {
            check();
            done = true;
            count(buf_len);
            for (var i = buf_len; i < block_size; i++) { buf[i] = 0; }
            p.compress(h, buf, 0, t_lo, t_hi, true);
            return finish(h, out_len, buf);
        }
    };
    return self;
}

/** @return {{update: function(Uint8Array): object, copy: function(): object, digest: function(): Uint8Array}} */
export function blake2b_create(out_len, key, opts) { return blake2_create(PARAMS_BLAKE2B, out_len, key, opts); }

/** @return {{update: function(Uint8Array): object, copy: function(): object, digest: function(): Uint8Array}} */
export function blake2s_create(out_len, key, opts) { return blake2_create(PARAMS_BLAKE2S, out_len, key, opts); }
