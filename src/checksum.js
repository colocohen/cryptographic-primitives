/**
 * Non-cryptographic checksums
 *
 * XXH32, XXH64, CRC-32, CRC-32C, SipHash-2-4, FNV-1a.
 *
 * NOT CRYPTOGRAPHIC. Collisions are cheap to construct on purpose. Never use
 * these for integrity against an adversary, for signatures, or for anything
 * security-bearing. Use them for what they are good at: deduplicating chunks,
 * cache keys, change detection, shard routing, wire-format error detection.
 *
 * They live in their own file, apart from the cryptographic hashes, so that
 * nobody reaches one by autocomplete while looking for the other. That
 * separation is the point of the file, not an organisational accident.
 *
 * Structurally unlike everything else in this library. There is no
 * compression function and no padding scheme - just accumulator lanes fed
 * fixed-size stripes, merged, then an avalanche finish. Nothing here is
 * shared with the cryptographic hashes, and the two variants share nothing
 * with each other either: XXH32 is plain 32-bit through Math.imul, XXH64
 * needs full 64-bit multiplication.
 *
 * WHY hi/lo AND NOT BigInt (XXH64)
 * Benchmarked and rejected: 230 MB/s hi/lo vs 34 MB/s BigInt on 1 KB (6.7x).
 * For a checksum the speed is the entire justification for existing - at
 * 34 MB/s XXH64 would be slower than this library's SHA-256, and then there
 * is no reason to give up the security. The gap here is the smallest in the
 * library because xxHash performs far fewer 64-bit operations per byte than
 * SHA-512 does.
 */

import { wr_be32, wr_le32, rd_le32 } from './commons/bytes.js';

/**
 * A 32-bit word as four big-endian bytes.
 *
 * ⭐ SHARED because jscpd found this block repeated across every 32-bit hash
 *   in this file. Nine identical lines in five places is how one gets a
 *   correction and the others do not - and here a divergence would be
 *   SILENT: a hash that returns its bytes in the other order still looks
 *   like a hash, and only a comparison with another implementation shows it.
 */
function w32(h) {
    var out = new Uint8Array(4);
    wr_be32(out, 0, h);
    return out;
}

/**
 * A 64-bit (hi, lo) pair as eight big-endian bytes - what xxhash64 and both
 * CRC-64s return, and what each of them used to write out by hand.
 */
function w64(hi, lo) {
    var out = new Uint8Array(8);
    wr_be32(out, 0, hi);
    wr_be32(out, 4, lo);
    return out;
}

/* ================= XXH32 ================= */

var P1_32 = 0x9e3779b1 | 0;
var P2_32 = 0x85ebca77 | 0;
var P3_32 = 0xc2b2ae3d | 0;
var P4_32 = 0x27d4eb2f | 0;
var P5_32 = 0x165667b1 | 0;

/** One accumulator step: acc = rotl(acc + lane * P2_32, 13) * P1_32 */
function round32(acc, lane) {
    acc = (acc + Math.imul(lane, P2_32)) | 0;
    acc = (acc << 13) | (acc >>> 19);
    return Math.imul(acc, P1_32);
}

/**
 * @param  {Uint8Array} msg
 * @param  {number}     [seed=0]  uint32
 * @return {Uint8Array} 4 bytes, big-endian (the canonical XXH32 encoding)
 */
export var xxhash32 = /* @__PURE__ */ (function () {
function xxhash32(msg, seed) {
    seed = (seed === undefined ? 0 : seed) | 0;

    var len = msg.length;
    var off = 0;
    var h;

    if (len >= 16) {
        /* Four lanes, each seeded differently so they never stay in step */
        var v1 = (seed + P1_32 + P2_32) | 0;
        var v2 = (seed + P2_32) | 0;
        var v3 = seed | 0;
        var v4 = (seed - P1_32) | 0;

        var limit = len - 16;
        do {
            v1 = round32(v1, ((msg[off]) | (msg[off + 1] << 8) |
                            (msg[off + 2] << 16) | (msg[off + 3] << 24)) | 0);
            v2 = round32(v2, ((msg[off + 4]) | (msg[off + 5] << 8) |
                            (msg[off + 6] << 16) | (msg[off + 7] << 24)) | 0);
            v3 = round32(v3, ((msg[off + 8]) | (msg[off + 9] << 8) |
                            (msg[off + 10] << 16) | (msg[off + 11] << 24)) | 0);
            v4 = round32(v4, ((msg[off + 12]) | (msg[off + 13] << 8) |
                            (msg[off + 14] << 16) | (msg[off + 15] << 24)) | 0);
            off += 16;
        } while (off <= limit);

        h = (((v1 << 1)  | (v1 >>> 31)) +
             ((v2 << 7)  | (v2 >>> 25)) +
             ((v3 << 12) | (v3 >>> 20)) +
             ((v4 << 18) | (v4 >>> 14))) | 0;
    } else {
        h = (seed + P5_32) | 0;
    }

    h = (h + len) | 0;

    /* Trailing 4-byte words */
    while (off + 4 <= len) {
        h = (h + Math.imul(((msg[off]) | (msg[off + 1] << 8) |
                            (msg[off + 2] << 16) | (msg[off + 3] << 24)) | 0, P3_32)) | 0;
        h = Math.imul((h << 17) | (h >>> 15), P4_32);
        off += 4;
    }

    /* Trailing single bytes */
    while (off < len) {
        h = (h + Math.imul(msg[off], P5_32)) | 0;
        h = Math.imul((h << 11) | (h >>> 21), P1_32);
        off++;
    }

    /* Avalanche - spreads every input bit across the whole output */
    h ^= h >>> 15;
    h = Math.imul(h, P2_32);
    h ^= h >>> 13;
    h = Math.imul(h, P3_32);
    h ^= h >>> 16;

    return w32(h);
}

    xxhash32.DIGEST_SIZE = 4;
    return xxhash32;
}());

/* ================= XXH64 ================= */

/* PRIME64_1..5, as hi/lo pairs */
var P1H = 0x9e3779b1 | 0, P1L = 0x85ebca87 | 0;
var P2H = 0xc2b2ae3d | 0, P2L = 0x27d4eb4f | 0;
var P3H = 0x165667b1 | 0, P3L = 0x9e3779f9 | 0;
var P4H = 0x85ebca77 | 0, P4L = 0xc2b2ae63 | 0;
var P5H = 0x27d4eb2f | 0, P5L = 0x165667c5 | 0;

/* -PRIME64_1 mod 2^64, so that seed - P1 is a plain 64-bit add */
var NEG_P1H = 0x61c8864e | 0, NEG_P1L = 0x7a143579 | 0;

/* Scratch accumulator. Avoids allocating a pair on every operation. */
var r_hi = 0, r_lo = 0;

/**
 * (a_hi:a_lo) * (b_hi:b_lo) mod 2^64, into r_hi/r_lo.
 *
 * Both operands are split into four 16-bit limbs. Every partial product
 * is at most (2^16-1)^2, well inside exact double range, so the carries
 * can be propagated by hand without losing bits.
 */
function mul64(a_hi, a_lo, b_hi, b_lo) {
    var a48 = a_hi >>> 16, a32 = a_hi & 0xffff;
    var a16 = a_lo >>> 16, a00 = a_lo & 0xffff;
    var b48 = b_hi >>> 16, b32 = b_hi & 0xffff;
    var b16 = b_lo >>> 16, b00 = b_lo & 0xffff;

    var c48 = 0, c32 = 0, c16 = 0, c00 = 0;

    c00 += a00 * b00;
    c16 += c00 >>> 16; c00 &= 0xffff;

    c16 += a16 * b00;
    c32 += c16 >>> 16; c16 &= 0xffff;
    c16 += a00 * b16;
    c32 += c16 >>> 16; c16 &= 0xffff;

    c32 += a32 * b00;
    c48 += c32 >>> 16; c32 &= 0xffff;
    c32 += a16 * b16;
    c48 += c32 >>> 16; c32 &= 0xffff;
    c32 += a00 * b32;
    c48 += c32 >>> 16; c32 &= 0xffff;

    /* Anything carrying past bit 63 is discarded - this is mod 2^64 */
    c48 += a48 * b00 + a32 * b16 + a16 * b32 + a00 * b48;
    c48 &= 0xffff;

    r_hi = ((c48 << 16) | c32) | 0;
    r_lo = ((c16 << 16) | c00) | 0;
}

/**
 * r = a + b, 64-bit, on (hi, lo) pairs, writing to r_hi and r_lo.
 *
 * ARGUMENT ORDER IS (hi, lo), following the big-endian convention xxHash64
 * is specified in.
 *
 * ⚠ argon2.js USED TO CARRY A TWIN with the opposite order, (lo, hi), and
 *   both files had a note explaining why the two must not be merged: a
 *   shared helper would silently reverse every call site in one of them,
 *   which for addition goes wrong only when a carry occurs. That twin turned
 *   out to have no callers - argon2's GB inlines its arithmetic - and was
 *   deleted, so this is the only add64 left. The warning still applies to
 *   anyone tempted to move it into commons/: commons/bytes.js shows what a
 *   shared version would need, two differently NAMED functions, one per
 *   convention.
 */
function add64(a_hi, a_lo, b_hi, b_lo) {
    var lo = (a_lo + b_lo) | 0;
    var carry = ((lo >>> 0) < (b_lo >>> 0)) ? 1 : 0;
    r_lo = lo;
    r_hi = (((a_hi + b_hi) | 0) + carry) | 0;
}

/** One accumulator step: acc = rotl64(acc + lane * P2, 31) * P1 */
function round64(acc_hi, acc_lo, lane_hi, lane_lo) {
    mul64(lane_hi, lane_lo, P2H, P2L);
    add64(acc_hi, acc_lo, r_hi, r_lo);

    /* rotl64 by 31 */
    var hi = r_hi, lo = r_lo;
    var n_hi = ((hi << 31) | (lo >>> 1)) | 0;
    var n_lo = ((lo << 31) | (hi >>> 1)) | 0;

    mul64(n_hi, n_lo, P1H, P1L);
}

/** h = (h ^ round64(0, v)) * P1 + P4 */
function merge_round64(h_hi, h_lo, v_hi, v_lo) {
    round64(0, 0, v_hi, v_lo);
    var x_hi = h_hi ^ r_hi, x_lo = h_lo ^ r_lo;
    mul64(x_hi, x_lo, P1H, P1L);
    add64(r_hi, r_lo, P4H, P4L);
}

/**
 * @param  {Uint8Array} msg
 * @param  {number}     [seed=0]  uint32. The 64-bit seed is rarely used;
 *                                pass a plain number for the common case.
 * @return {Uint8Array} 8 bytes, big-endian (the canonical XXH64 encoding)
 */
export var xxhash64 = /* @__PURE__ */ (function () {
function xxhash64(msg, seed) {
    var s_lo = (seed === undefined ? 0 : seed) | 0;
    var s_hi = 0;

    var len = msg.length;
    var off = 0;
    var h_hi, h_lo;
    var i;

    if (len >= 32) {
        /* Four lanes, seeded apart so they never move in lockstep */
        add64(s_hi, s_lo, P1H, P1L); add64(r_hi, r_lo, P2H, P2L);
        var v1h = r_hi, v1l = r_lo;
        add64(s_hi, s_lo, P2H, P2L);
        var v2h = r_hi, v2l = r_lo;
        var v3h = s_hi, v3l = s_lo;
        /* v4 = seed - P1, added as the precomputed two's complement of P1 */
        add64(s_hi, s_lo, NEG_P1H, NEG_P1L);
        var v4h = r_hi, v4l = r_lo;

        var limit = len - 32;
        do {
            round64(v1h, v1l,
                  ((msg[off + 4]) | (msg[off + 5] << 8) | (msg[off + 6] << 16) | (msg[off + 7] << 24)) | 0,
                  ((msg[off])     | (msg[off + 1] << 8) | (msg[off + 2] << 16) | (msg[off + 3] << 24)) | 0);
            v1h = r_hi; v1l = r_lo;

            round64(v2h, v2l,
                  ((msg[off + 12]) | (msg[off + 13] << 8) | (msg[off + 14] << 16) | (msg[off + 15] << 24)) | 0,
                  ((msg[off + 8])  | (msg[off + 9] << 8)  | (msg[off + 10] << 16) | (msg[off + 11] << 24)) | 0);
            v2h = r_hi; v2l = r_lo;

            round64(v3h, v3l,
                  ((msg[off + 20]) | (msg[off + 21] << 8) | (msg[off + 22] << 16) | (msg[off + 23] << 24)) | 0,
                  ((msg[off + 16]) | (msg[off + 17] << 8) | (msg[off + 18] << 16) | (msg[off + 19] << 24)) | 0);
            v3h = r_hi; v3l = r_lo;

            round64(v4h, v4l,
                  ((msg[off + 28]) | (msg[off + 29] << 8) | (msg[off + 30] << 16) | (msg[off + 31] << 24)) | 0,
                  ((msg[off + 24]) | (msg[off + 25] << 8) | (msg[off + 26] << 16) | (msg[off + 27] << 24)) | 0);
            v4h = r_hi; v4l = r_lo;

            off += 32;
        } while (off <= limit);

        /* h = rotl(v1,1) + rotl(v2,7) + rotl(v3,12) + rotl(v4,18) */
        h_hi = ((v1h << 1) | (v1l >>> 31)) | 0;
        h_lo = ((v1l << 1) | (v1h >>> 31)) | 0;
        add64(h_hi, h_lo, ((v2h << 7) | (v2l >>> 25)) | 0, ((v2l << 7) | (v2h >>> 25)) | 0);
        add64(r_hi, r_lo, ((v3h << 12) | (v3l >>> 20)) | 0, ((v3l << 12) | (v3h >>> 20)) | 0);
        add64(r_hi, r_lo, ((v4h << 18) | (v4l >>> 14)) | 0, ((v4l << 18) | (v4h >>> 14)) | 0);
        h_hi = r_hi; h_lo = r_lo;

        merge_round64(h_hi, h_lo, v1h, v1l); h_hi = r_hi; h_lo = r_lo;
        merge_round64(h_hi, h_lo, v2h, v2l); h_hi = r_hi; h_lo = r_lo;
        merge_round64(h_hi, h_lo, v3h, v3l); h_hi = r_hi; h_lo = r_lo;
        merge_round64(h_hi, h_lo, v4h, v4l); h_hi = r_hi; h_lo = r_lo;
    } else {
        add64(s_hi, s_lo, P5H, P5L);
        h_hi = r_hi; h_lo = r_lo;
    }

    add64(h_hi, h_lo, 0, len | 0);
    /* len is bounded well under 2^32 in practice, so no hi carry needed */
    h_hi = r_hi; h_lo = r_lo;

    /* Trailing 8-byte words */
    while (off + 8 <= len) {
        round64(0, 0,
              ((msg[off + 4]) | (msg[off + 5] << 8) | (msg[off + 6] << 16) | (msg[off + 7] << 24)) | 0,
              ((msg[off])     | (msg[off + 1] << 8) | (msg[off + 2] << 16) | (msg[off + 3] << 24)) | 0);
        var k_hi = r_hi, k_lo = r_lo;
        var x_hi = h_hi ^ k_hi, x_lo = h_lo ^ k_lo;
        /* h = rotl64(h ^ k, 27) * P1 + P4 */
        mul64(((x_hi << 27) | (x_lo >>> 5)) | 0, ((x_lo << 27) | (x_hi >>> 5)) | 0, P1H, P1L);
        add64(r_hi, r_lo, P4H, P4L);
        h_hi = r_hi; h_lo = r_lo;
        off += 8;
    }

    /* Trailing 4-byte word */
    if (off + 4 <= len) {
        var w = ((msg[off]) | (msg[off + 1] << 8) |
                 (msg[off + 2] << 16) | (msg[off + 3] << 24)) | 0;
        mul64(0, w, P1H, P1L);
        h_hi ^= r_hi; h_lo ^= r_lo;
        /* h = rotl64(h, 23) * P2 + P3 */
        mul64(((h_hi << 23) | (h_lo >>> 9)) | 0, ((h_lo << 23) | (h_hi >>> 9)) | 0, P2H, P2L);
        add64(r_hi, r_lo, P3H, P3L);
        h_hi = r_hi; h_lo = r_lo;
        off += 4;
    }

    /* Trailing single bytes */
    while (off < len) {
        mul64(0, msg[off] | 0, P5H, P5L);
        h_hi ^= r_hi; h_lo ^= r_lo;
        /* h = rotl64(h, 11) * P1 */
        mul64(((h_hi << 11) | (h_lo >>> 21)) | 0, ((h_lo << 11) | (h_hi >>> 21)) | 0, P1H, P1L);
        h_hi = r_hi; h_lo = r_lo;
        off++;
    }

    /*
     * Avalanche. Each shift is a 64-bit shift expressed over the pair:
     * for n >= 32 the high word goes to zero and the low word takes
     * hi >>> (n-32); for n < 32 both halves move and hi spills into lo.
     */

    /* h ^= h >>> 33 */
    h_lo ^= h_hi >>> 1;

    mul64(h_hi, h_lo, P2H, P2L); h_hi = r_hi; h_lo = r_lo;

    /* h ^= h >>> 29 */
    var t_hi = h_hi >>> 29;
    var t_lo = ((h_lo >>> 29) | (h_hi << 3)) | 0;
    h_hi ^= t_hi; h_lo ^= t_lo;

    mul64(h_hi, h_lo, P3H, P3L); h_hi = r_hi; h_lo = r_lo;

    /* h ^= h >>> 32 */
    h_lo ^= h_hi;

    return w64(h_hi, h_lo);
}

    xxhash64.DIGEST_SIZE = 8;
    return xxhash64;
}());


/* ================= CRC-32 ================= */
/*
 * Not a hash at all - a linear checksum over GF(2). Designed to catch burst
 * errors on a wire or in storage, and it does that provably well. It offers
 * no resistance whatever to deliberate modification: given any message and
 * any target checksum, the bytes to append are computed directly.
 *
 * Two polynomials are in use and they are not interchangeable:
 *   CRC-32   0xEDB88320 reflected - zip, gzip, PNG, Ethernet
 *   CRC-32C  0x82F63B78 reflected - iSCSI, ext4, Btrfs, SSE4.2 hardware
 */

function crc_table(poly) {
    var t = new Int32Array(256), c, i, k;
    for (i = 0; i < 256; i++) {
        c = i;
        for (k = 0; k < 8; k++) { c = (c & 1) ? ((c >>> 1) ^ poly) : (c >>> 1); }
        t[i] = c | 0;
    }
    return t;
}

var CRC32_TABLE  = /* @__PURE__ */ crc_table(0xedb88320 | 0);
var CRC32C_TABLE = /* @__PURE__ */ crc_table(0x82f63b78 | 0);

function crc32_run(table, msg, seed) {
    var c = ~(seed === undefined ? 0 : seed);
    for (var i = 0; i < msg.length; i++) {
        c = table[(c ^ msg[i]) & 0xff] ^ (c >>> 8);
    }
    /* through w32 like every other 32-bit result here - this was the one
       copy of its body jscpd did not catch */
    return w32(~c);
}

/**
 * @param  {Uint8Array} msg
 * @param  {number}     [seed=0]  a previous crc, to continue a running sum
 * @return {Uint8Array} 4 bytes, big-endian
 */
export var crc32 = /* @__PURE__ */ (function () {
    function crc32(msg, seed) { return crc32_run(CRC32_TABLE, msg, seed); }
    crc32.DIGEST_SIZE = 4;
    return crc32;
}());

export var crc32c = /* @__PURE__ */ (function () {
    function crc32c(msg, seed) { return crc32_run(CRC32C_TABLE, msg, seed); }
    crc32c.DIGEST_SIZE = 4;
    return crc32c;
}());

/* ================= CRC-64 ================= */

/**
 * A CRC-64 table, built once per polynomial.
 *
 * ⚠ 32-BIT WORDS, NOT BigInt. A BigInt table would allocate on every one of
 *   the 256 * 8 shifts that build it and on every byte that uses it - and
 *   the whole point of a table-driven CRC is that the inner loop is a
 *   lookup and an xor. The value is carried as (hi, lo) pairs in an
 *   Int32Array, which is the same shape the GHASH work landed on for the
 *   same reason.
 */
function crc64_table(poly_hi, poly_lo) {
    var t = new Int32Array(512);
    for (var n = 0; n < 256; n++) {
        var hi = 0, lo = n | 0;
        for (var k = 0; k < 8; k++) {
            var lsb = lo & 1;
            lo = ((lo >>> 1) | (hi << 31)) | 0;
            hi = (hi >>> 1) | 0;
            if (lsb) { hi ^= poly_hi; lo ^= poly_lo; }
        }
        t[n * 2] = hi; t[n * 2 + 1] = lo;
    }
    return t;
}

function crc64_run(table, msg) {
    /* start at all ones, finish inverted - the usual CRC framing */
    var hi = -1, lo = -1;
    for (var i = 0; i < msg.length; i++) {
        var idx = ((lo ^ msg[i]) & 0xff) * 2;
        var nlo = ((lo >>> 8) | (hi << 24)) | 0;
        var nhi = (hi >>> 8) | 0;
        hi = (nhi ^ table[idx]) | 0;
        lo = (nlo ^ table[idx + 1]) | 0;
    }
    return w64(~hi, ~lo);
}

/*
 * ⚠ TWO POLYNOMIALS, AND THEY DO NOT INTEROPERATE. Both are called
 *   "CRC-64" and a caller who picks the wrong one gets a well-formed value
 *   that matches nothing:
 *
 *     ECMA-182   0xC96C5795D7870F42   xz, Btrfs, zstd
 *     ISO 3309   0xD800000000000000   HDLC, some tape formats
 *
 *   Both are shipped rather than one chosen, because choosing would leave
 *   half the callers with a checksum that looks right.
 */
var CRC64_ECMA_TABLE = /* @__PURE__ */ crc64_table(0xc96c5795 | 0, 0xd7870f42 | 0);
var CRC64_ISO_TABLE  = /* @__PURE__ */ crc64_table(0xd8000000 | 0, 0x00000000 | 0);

/** CRC-64/XZ, the ECMA-182 polynomial. What xz and Btrfs write. */
export var crc64 = /* @__PURE__ */ (function () {
    function crc64(msg) { return crc64_run(CRC64_ECMA_TABLE, msg); }
    crc64.DIGEST_SIZE = 8;
    return crc64;
}());

/** CRC-64 with the ISO 3309 polynomial. NOT interchangeable with crc64. */
export var crc64_iso = /* @__PURE__ */ (function () {
    function crc64_iso(msg) { return crc64_run(CRC64_ISO_TABLE, msg); }
    crc64_iso.DIGEST_SIZE = 8;
    return crc64_iso;
}());

/* ================= FNV-1a ================= */
/*
 * The simplest useful hash there is: xor a byte, multiply by a prime, repeat.
 * Fast on very short inputs where xxHash's setup does not pay for itself, and
 * small enough to inline anywhere. Poor avalanche - only for hash tables.
 */

export var fnv1a32 = /* @__PURE__ */ (function () {
    function fnv1a32(msg, seed) {
        var h = (seed === undefined ? 0x811c9dc5 : seed) | 0;
        for (var i = 0; i < msg.length; i++) {
            h = Math.imul(h ^ msg[i], 0x01000193);
        }
        return w32(h);
    }
    fnv1a32.DIGEST_SIZE = 4;
    return fnv1a32;
}());

/* ================= SipHash-2-4 ================= */
/*
 * The one keyed function in this file, and the one that is arguably not in the
 * right place. SipHash is a PRF with a real security claim: with a secret
 * 128-bit key an attacker cannot find colliding inputs, which is exactly what
 * hash-flooding denial of service needs. Language runtimes use it to key their
 * built-in hash tables for that reason.
 *
 * It is filed here because its output is 64 bits - too short to be a MAC for
 * anything but this purpose. Do not use it as one.
 *
 * 64-bit, so the same manual hi/lo arithmetic as XXH64 above.
 */

var sv0h = 0, sv0l = 0, sv1h = 0, sv1l = 0;
var sv2h = 0, sv2l = 0, sv3h = 0, sv3l = 0;

/* One SipRound: four adds, four rotations, four xors, two 32-bit swaps. */
function sip_round() {
    var lo, carry;

    lo = (sv0l + sv1l) | 0; carry = ((lo >>> 0) < (sv1l >>> 0)) ? 1 : 0;
    sv0h = (((sv0h + sv1h) | 0) + carry) | 0; sv0l = lo;
    /* v1 = rotl(v1, 13) */
    var t = sv1h; sv1h = ((sv1h << 13) | (sv1l >>> 19)) | 0;
                  sv1l = ((sv1l << 13) | (t    >>> 19)) | 0;
    sv1h ^= sv0h; sv1l ^= sv0l;
    /* v0 = rotl(v0, 32) */
    t = sv0h; sv0h = sv0l; sv0l = t;

    lo = (sv2l + sv3l) | 0; carry = ((lo >>> 0) < (sv3l >>> 0)) ? 1 : 0;
    sv2h = (((sv2h + sv3h) | 0) + carry) | 0; sv2l = lo;
    /* v3 = rotl(v3, 16) */
    t = sv3h; sv3h = ((sv3h << 16) | (sv3l >>> 16)) | 0;
              sv3l = ((sv3l << 16) | (t    >>> 16)) | 0;
    sv3h ^= sv2h; sv3l ^= sv2l;

    lo = (sv0l + sv3l) | 0; carry = ((lo >>> 0) < (sv3l >>> 0)) ? 1 : 0;
    sv0h = (((sv0h + sv3h) | 0) + carry) | 0; sv0l = lo;
    /* v3 = rotl(v3, 21) */
    t = sv3h; sv3h = ((sv3h << 21) | (sv3l >>> 11)) | 0;
              sv3l = ((sv3l << 21) | (t    >>> 11)) | 0;
    sv3h ^= sv0h; sv3l ^= sv0l;

    lo = (sv2l + sv1l) | 0; carry = ((lo >>> 0) < (sv1l >>> 0)) ? 1 : 0;
    sv2h = (((sv2h + sv1h) | 0) + carry) | 0; sv2l = lo;
    /* v1 = rotl(v1, 17) */
    t = sv1h; sv1h = ((sv1h << 17) | (sv1l >>> 15)) | 0;
              sv1l = ((sv1l << 17) | (t    >>> 15)) | 0;
    sv1h ^= sv2h; sv1l ^= sv2l;
    /* v2 = rotl(v2, 32) */
    t = sv2h; sv2h = sv2l; sv2l = t;
}

/**
 * @param  {Uint8Array} msg
 * @param  {Uint8Array} key  exactly 16 bytes
 * @return {Uint8Array} 8 bytes, little-endian
 */
export var siphash24 = /* @__PURE__ */ (function () {
    function siphash24(msg, key) {
        if (key.length !== 16) {
            throw new Error('siphash24: key must be exactly 16 bytes');
        }
        var k0l = rd_le32(key, 0), k0h = rd_le32(key, 4);
        var k1l = rd_le32(key, 8), k1h = rd_le32(key, 12);

        /* "somepseudorandomlygeneratedbytes" xor the key */
        sv0h = 0x736f6d65 ^ k0h; sv0l = 0x70736575 ^ k0l;
        sv1h = 0x646f7261 ^ k1h; sv1l = 0x6e646f6d ^ k1l;
        sv2h = 0x6c796765 ^ k0h; sv2l = 0x6e657261 ^ k0l;
        sv3h = 0x74656462 ^ k1h; sv3l = 0x79746573 ^ k1l;

        var len = msg.length;
        var full = len - (len & 7);
        var i, mh, ml;

        for (i = 0; i < full; i += 8) {
            ml = ((msg[i]) | (msg[i+1] << 8) | (msg[i+2] << 16) | (msg[i+3] << 24)) | 0;
            mh = ((msg[i+4]) | (msg[i+5] << 8) | (msg[i+6] << 16) | (msg[i+7] << 24)) | 0;
            sv3h ^= mh; sv3l ^= ml;
            sip_round(); sip_round();
            sv0h ^= mh; sv0l ^= ml;
        }

        /* Final partial word, with the message length in the top byte */
        ml = 0; mh = (len & 0xff) << 24;
        for (i = full; i < len; i++) {
            if (i - full < 4) { ml |= msg[i] << ((i - full) * 8); }
            else              { mh |= msg[i] << ((i - full - 4) * 8); }
        }
        sv3h ^= mh; sv3l ^= ml;
        sip_round(); sip_round();
        sv0h ^= mh; sv0l ^= ml;

        sv2l ^= 0xff;
        sip_round(); sip_round(); sip_round(); sip_round();

        var rh = sv0h ^ sv1h ^ sv2h ^ sv3h;
        var rl = sv0l ^ sv1l ^ sv2l ^ sv3l;

        var out = new Uint8Array(8);
        wr_le32(out, 0, rl);
        wr_le32(out, 4, rh);
        return out;
    }
    siphash24.DIGEST_SIZE = 8;
    return siphash24;
}());

/* ==================== MurmurHash3, 32-bit ==================== */

/**
 * MurmurHash3 x86 32-bit, Austin Appleby's final version.
 *
 * ⭐ HERE FOR INTEROPERABILITY, which is the only reason anything in this
 *   file exists. Cassandra partitions on Murmur3, Kafka hashes keys with it,
 *   Guava exposes it, and most Bloom filter implementations use it - so
 *   reading data another system hashed means computing the same function.
 *
 * ⚠ NOT CRYPTOGRAPHIC AND NOT KEYED. `seed` separates instances, not
 *   attackers: anyone who knows it can construct colliding inputs in
 *   seconds. For a hash table exposed to untrusted keys use siphash24 above,
 *   which is keyed and was designed for exactly that.
 *
 * ⛔ AND WHAT setrecon CALLED `mix32` IS ONLY THE FINALIZER - the last five
 *   lines of this function. It is a fine integer mixer and it is NOT
 *   MurmurHash3: it matches no other implementation, because it never reads
 *   a byte stream. Exposing it under the Murmur name would be the worse
 *   error of the two.
 */
export function murmur3_32(msg, seed) {
    var h = (seed === undefined ? 0 : seed) | 0;
    var len = msg.length;
    var i = 0;
    var C1 = 0xcc9e2d51, C2 = 0x1b873593;

    /* body: four bytes at a time, little-endian */
    var blocks = len - (len % 4);
    for (; i < blocks; i += 4) {
        var k = (msg[i] | (msg[i + 1] << 8) | (msg[i + 2] << 16) |
                 (msg[i + 3] << 24)) | 0;
        k = Math.imul(k, C1);
        k = ((k << 15) | (k >>> 17)) | 0;
        k = Math.imul(k, C2);
        h ^= k;
        h = ((h << 13) | (h >>> 19)) | 0;
        h = (Math.imul(h, 5) + 0xe6546b64) | 0;
    }

    /* tail: the remaining one to three bytes, no rotation of h */
    var k1 = 0;
    switch (len & 3) {
    case 3: k1 ^= msg[i + 2] << 16;
        /* falls through */
    case 2: k1 ^= msg[i + 1] << 8;
        /* falls through */
    case 1:
        k1 ^= msg[i];
        k1 = Math.imul(k1, C1);
        k1 = ((k1 << 15) | (k1 >>> 17)) | 0;
        k1 = Math.imul(k1, C2);
        h ^= k1;
    }

    /* finalisation - this is the part setrecon uses on its own */
    h ^= len;
    h ^= h >>> 16;
    h = Math.imul(h, 0x85ebca6b);
    h ^= h >>> 13;
    h = Math.imul(h, 0xc2b2ae35);
    h ^= h >>> 16;
    return w32(h);
}
murmur3_32.DIGEST_SIZE = 4;

/* ==================== Adler-32 ==================== */

/**
 * Adler-32, RFC 1950 - the checksum zlib appends to every stream.
 *
 * ⭐ ALSO PURELY FOR INTEROPERABILITY: PNG carries it, rsync uses a rolling
 *   variant of it, and anything reading a zlib stream has to verify it.
 *
 * ⚠ IT IS A WEAK CHECKSUM AND KNOWN TO BE. Mark Adler designed it for speed
 *   over long streams, and it detects almost nothing on SHORT inputs - the
 *   sums barely move. RFC 3309 removed it from SCTP for that reason. Use it
 *   to match zlib, not to decide whether data is intact.
 *
 * ⚠ THE MODULUS IS 65521, THE LARGEST PRIME BELOW 2^16. A power of two would
 *   be faster and would throw away the high bits' contribution entirely.
 */
export function adler32(msg) {
    var a = 1, b = 0;
    var i = 0, n = msg.length;
    /*
     * 5552 is the most bytes that can accumulate before b can overflow a
     * 32-bit signed integer, so the modulus is taken once per block rather
     * than once per byte.
     */
    while (i < n) {
        var end = i + 5552;
        if (end > n) { end = n; }
        for (; i < end; i++) {
            a += msg[i];
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    var v = ((b << 16) | a) >>> 0;
    return w32(v);
}
adler32.DIGEST_SIZE = 4;

/* ================= HighwayHash ================= */

/**
 * HighwayHash-64, Google 2016 - a KEYED hash for untrusted input.
 *
 * ⭐ THE ONLY OTHER KEYED FUNCTION IN THIS FILE. crc32, xxhash, murmur3 and
 *   adler32 all break against an adversary who knows the input: they are
 *   unkeyed, and colliding inputs can be constructed offline. siphash24 was
 *   the only alternative, and it is the slowest thing here.
 *
 * ==================== 🔴 IT IS SLOWER THAN siphash24 ====================
 *
 * ⛔ MEASURED, and the number is the point: 4 MB/s against siphash24's 42,
 *   and 44 microseconds on a 64-byte input against 1.6. Ten times slower
 *   than the function it was meant to improve on.
 *
 * ⚠ THE CAUSE IS BigInt, NOT THE ALGORITHM. HighwayHash is specified in
 *   64-bit arithmetic and this is the direct translation, so every operation
 *   in the inner loop allocates - about forty per 32-byte packet. The
 *   four-lane structure that makes it fast on AVX-2 buys nothing when the
 *   allocator dominates.
 *
 *   A rewrite on (hi, lo) pairs of 32-bit words - the shape siphash24 and
 *   the GHASH table use - is what would fix it. ⚠ AND IT IS NOT A
 *   TRANSCRIPTION: ZipperMerge adds MASKED 64-BIT VALUES and then shifts, so
 *   the carries cross byte boundaries and a byte-by-byte decomposition is
 *   wrong. One was attempted and abandoned for exactly that reason.
 *
 * ⭐ SO: USE siphash24 UNLESS YOU NEED HighwayHash's OUTPUT. This is here to
 *   interoperate with something that already computes it - which is the same
 *   reason everything else in this file is here - and not because it is
 *   faster, because in JavaScript it is not.
 *
 * ⛔ NOT CRYPTOGRAPHIC. Keyed and hard to collide is not the same as
 *   collision-resistant: use sha256 where that is the requirement. This is
 *   for hash tables, checksums over untrusted data, and fingerprints where a
 *   determined adversary must not be able to force collisions cheaply.
 *
 * @param {Uint8Array} msg
 * @param {Uint8Array} key  exactly 32 bytes
 * @return {Uint8Array} 8 bytes, big-endian
 */
export var highwayhash64 = /* @__PURE__ */ (function () {
    var M64 = (1n << 64n) - 1n;

    var INIT0 = [0xdbe6d5d5fe4cce2fn, 0xa4093822299f31d0n,
                 0x13198a2e03707344n, 0x243f6a8885a308d3n];
    var INIT1 = [0x3bd39e10cb0ef593n, 0xc0acf169b5f18a8cn,
                 0xbe5466cf34e90c6cn, 0x452821e638d01377n];

    function rot32(x) { return ((x >> 32n) | (x << 32n)) & M64; }

    function mask(v, byte) { return v & (0xffn << BigInt(byte * 8)); }

    /*
     * ⚠ ZipperMerge IS WHERE A TRANSCRIPTION ERROR HIDES. It is seven byte
     *   selections per lane with different shifts, and a wrong shift gives a
     *   hash that is stable, well distributed, and matches nothing. The
     *   official vectors below are the only thing that catches it.
     */
    function zipper(v1, v0) {
        var a0 = (((mask(v0, 3) + mask(v1, 4)) >> 24n) +
                  ((mask(v0, 5) + mask(v1, 6)) >> 16n) +
                  mask(v0, 2) + (mask(v0, 1) << 32n) +
                  (mask(v1, 7) >> 8n) + (v0 << 56n)) & M64;
        var a1 = (((mask(v1, 3) + mask(v0, 4)) >> 24n) + mask(v1, 2) +
                  (mask(v1, 5) >> 16n) + (mask(v1, 1) << 24n) +
                  (mask(v0, 6) >> 8n) + (mask(v1, 0) << 48n) +
                  mask(v0, 7)) & M64;
        return [a0, a1];
    }

    function make_state(key) {
        var v0 = [], v1 = [], mul0 = [], mul1 = [];
        /* the key is read exactly as a 32-byte packet is - four little-endian
           64-bit lanes - so lanes_from does it, rather than a copy of its loop */
        var ks = lanes_from(key, 0);
        for (var i = 0; i < 4; i++) {
            var k = ks[i];
            mul0.push(INIT0[i]);
            mul1.push(INIT1[i]);
            v0.push(INIT0[i] ^ k);
            v1.push(INIT1[i] ^ rot32(k));
        }
        return { v0: v0, v1: v1, mul0: mul0, mul1: mul1 };
    }

    function update(s, lanes) {
        var i;
        for (i = 0; i < 4; i++) {
            s.v1[i] = (s.v1[i] + lanes[i] + s.mul0[i]) & M64;
            var v1_32 = s.v1[i] & 0xffffffffn;
            s.mul0[i] ^= (v1_32 * (s.v0[i] >> 32n)) & M64;
            s.v0[i] = (s.v0[i] + s.mul1[i]) & M64;
            var v0_32 = s.v0[i] & 0xffffffffn;
            s.mul1[i] ^= (v0_32 * (s.v1[i] >> 32n)) & M64;
        }
        var z;
        z = zipper(s.v1[1], s.v1[0]);
        s.v0[0] = (s.v0[0] + z[0]) & M64; s.v0[1] = (s.v0[1] + z[1]) & M64;
        z = zipper(s.v1[3], s.v1[2]);
        s.v0[2] = (s.v0[2] + z[0]) & M64; s.v0[3] = (s.v0[3] + z[1]) & M64;
        z = zipper(s.v0[1], s.v0[0]);
        s.v1[0] = (s.v1[0] + z[0]) & M64; s.v1[1] = (s.v1[1] + z[1]) & M64;
        z = zipper(s.v0[3], s.v0[2]);
        s.v1[2] = (s.v1[2] + z[0]) & M64; s.v1[3] = (s.v1[3] + z[1]) & M64;
    }

    function lanes_from(buf, off) {
        var out = [];
        for (var i = 0; i < 4; i++) {
            var v = 0n;
            for (var b = 7; b >= 0; b--) { v = (v << 8n) | BigInt(buf[off + i * 8 + b]); }
            out.push(v);
        }
        return out;
    }

    /*
     * The tail, and it is the fiddly part: bytes 16..31 take a different
     * path from bytes 0..15, and the length itself is folded into v0 and
     * rotates v1 before any of it.
     */
    function remainder(s, msg, off, n) {
        var i;
        var mod32 = BigInt(n);
        var pair = ((mod32 << 32n) + mod32) & M64;
        for (i = 0; i < 4; i++) { s.v0[i] = (s.v0[i] + pair) & M64; }

        /* Rotate32By: each 32-bit half of v1 rotates left by n mod 32 */
        var r = n & 31;
        if (r !== 0) {
            var rb = BigInt(r);
            for (i = 0; i < 4; i++) {
                var lo = s.v1[i] & 0xffffffffn, hi = s.v1[i] >> 32n;
                lo = ((lo << rb) | (lo >> (32n - rb))) & 0xffffffffn;
                hi = ((hi << rb) | (hi >> (32n - rb))) & 0xffffffffn;
                s.v1[i] = (hi << 32n) | lo;
            }
        }

        var packet = new Uint8Array(32);
        var mod4 = n & 3;
        var whole = n & ~3;
        for (i = 0; i < whole; i++) { packet[i] = msg[off + i]; }

        if (n & 16) {
            /*
             * ⚠ 16..31 BYTES READ THE LAST FOUR OF THE MESSAGE, not the
             *   trailing mod4. Load3::AllowReadBeforeAndReturn takes
             *   from + size_mod4 - 4, which reaches BACK over bytes already
             *   copied. Copying only the trailing mod4 gives the right
             *   answer for every length under 16 and the wrong one from 16
             *   up - measured: 33 of 65 vectors.
             */
            for (i = 0; i < 4; i++) { packet[28 + i] = msg[off + n - 4 + i]; }
        } else {
            /* under 16: last4 = first, middle, last of the remaining bytes */
            if (mod4 !== 0) {
                packet[16] = msg[off + whole];
                packet[17] = msg[off + whole + (mod4 >> 1)];
                packet[18] = msg[off + whole + mod4 - 1];
            }
        }
        update(s, lanes_from(packet, 0));
    }

    function permute_update(s) {
        update(s, [rot32(s.v0[2]), rot32(s.v0[3]),
                   rot32(s.v0[0]), rot32(s.v0[1])]);
    }

    function highwayhash64(msg, key) {
        if (!key || key.length !== 32) {
            throw new Error('highwayhash64: key must be exactly 32 bytes');
        }
        var s = make_state(key);
        var n = msg.length;
        var off = 0;
        while (n - off >= 32) {
            update(s, lanes_from(msg, off));
            off += 32;
        }
        if (off < n) { remainder(s, msg, off, n - off); }

        for (var r = 0; r < 4; r++) { permute_update(s); }
        var h = (s.v0[0] + s.v1[0] + s.mul0[0] + s.mul1[0]) & M64;

        var out = new Uint8Array(8);
        for (var i = 7; i >= 0; i--) { out[i] = Number(h & 0xffn); h >>= 8n; }
        return out;
    }
    highwayhash64.DIGEST_SIZE = 8;
    return highwayhash64;
}());
