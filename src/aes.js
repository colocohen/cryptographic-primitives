/**
 * AES and its block-cipher modes  -  FIPS 197
 *
 * The most deployed cipher there is, and the one this library is least happy
 * to provide in software.
 *
 * THE CACHE-TIMING PROBLEM - READ THIS BEFORE CHOOSING AES HERE
 * AES is built on a 256-byte substitution table indexed by secret data. On
 * real hardware, which entries land in cache depends on which indices were
 * used, and an attacker who can observe cache behaviour - a process on the
 * same machine, another tenant on the same host, in some settings another
 * tab - can recover the key from that alone. This is not theoretical; it is
 * the reason AES-NI exists as a CPU instruction.
 *
 * A software AES cannot fully avoid this. Bitslicing can, at several times
 * the cost and considerable complexity. This implementation uses the plain
 * 256-byte S-box rather than the 4 KiB T-tables most fast implementations
 * use: four cache lines of exposure instead of sixty-four. That narrows the
 * channel; it does not close it.
 *
 * WHAT TO DO INSTEAD
 * Where AES-GCM is available through Web Crypto, use it. It runs on AES-NI,
 * is genuinely constant time, and is far faster than anything here. This file
 * is for the cases where that is not an option: Node without Web Crypto,
 * modes Web Crypto does not expose (ECB, IGE, SIV), and interoperability.
 *
 * Where the choice is free, ChaCha20-Poly1305 in chacha.js has no tables at
 * all and no such exposure.
 *
 * ---------------------------------------------------------------------------
 * PERFORMANCE - WHAT WAS DONE.
 *
 * Measured on 64 KB, single-threaded, all figures from the same run:
 *
 *     node aes-256-gcm (AES-NI)   130.1 MB/s
 *     chacha20poly1305 (this lib)  25.7 MB/s
 *     aes_ctr          (this lib)  24.8 MB/s
 *     aes_cbc_decrypt  (this lib)  21.9 MB/s
 *     aes_cbc_encrypt  (this lib)  17.9 MB/s
 *     aes_gcm_encrypt  (this lib)  12.0 MB/s
 *
 * TWO THINGS WERE SUSPECTED, AND THE FIRST WAS RIGHT. gmul() was being called
 * per byte inside MixColumns, looping eight times through shifts and
 * conditional xors. Folding SubBytes, ShiftRows and MixColumns into ONE
 * 32-bit table lookup per column took CTR from 1.6 MB/s to 24.8.
 *
 * DECRYPTION WAS LEFT BEHIND FOR A WHILE, and the gap was the more
 * interesting number: 148 ms per 64 KiB against encryption's 1.4, a factor of
 * a hundred, purely because the inverse still walked the byte-oriented path.
 * The inverse needs its own tables - 9, 11, 13 and 14 rather than 2 and 3 -
 * and a key schedule with InvMixColumns pre-applied to the middle rounds
 * (FIPS-197 section 5.3.5). With those it runs at the same speed as
 * encryption, as it should.
 *
 * THE COST IS A WIDER CACHE-TIMING CHANNEL, and it is a trade rather than a
 * free win. The 256-byte S-box spans four cache lines, so an observer who can
 * see which line was touched learns two bits per lookup; the 4 KiB tables
 * span sixty-four and yield four. The long note above encrypt_block sets out
 * why that was accepted and why it does not make AES safe on shared hardware.
 *
 * THE SECOND SUSPICION IS STILL UNTESTED, and it is now the dominant cost:
 * GHASH runs 128 iterations per block. A word-level carry-less multiply built
 * from shifts and masks should beat the bit loop while staying
 * data-independent, which is what keeps GCM at 12 MB/s while CTR runs at 25.
 *
 * Measure before changing anything, and measure interleaved, since JIT
 */

import { dbl128 } from './commons/cmac.js';
import { equal, wipe } from './commons/ct.js';
import { gmul, POLY_AES, AES_SBOX, AES_INV_SBOX } from './commons/gf256.js';
import { ghash, gf_mulx, pad16 } from './commons/gcm.js';
import { bind_modes } from './commons/cipher_modes.js';
import { AES_T0 } from './commons/aes_round.js';
import { rd_be32, wr_be32s, rd_le32, wr_le32, rotr32, le64 } from './commons/bytes.js';
import { ctr_stream } from './commons/block_modes.js';

var BLOCK = 16;

/* ---------------- S-box ---------------- */
/*
 * Derived in commons/gf256.js, shared with ARIA - whose specification calls
 * for the AES box by name, so this is a real dependency rather than two
 * tables that happen to be equal.
 */

var SBOX = AES_SBOX;
var INV_SBOX = AES_INV_SBOX;

/* Round constants for the key schedule: 1, 2, 4, 8 ... in GF(2^8) */
var RCON = /* @__PURE__ */ (function () {
    var r = new Uint8Array(11), v = 1;
    for (var i = 1; i <= 10; i++) { r[i] = v; v = gmul(v, 2, POLY_AES); }
    return r;
}());

/**
 * Expand a key into round keys.
 *
 * @param  {Uint8Array} key  16, 24 or 32 bytes
 * @return {Uint8Array} (rounds+1) * 16 bytes
 */
function expand_key(key) {
    var nk = key.length / 4;
    if (nk !== 4 && nk !== 6 && nk !== 8) {
        throw new Error('aes: key must be 16, 24 or 32 bytes');
    }
    var nr = nk + 6;
    var total = (nr + 1) * 4;
    var w = new Uint8Array(total * 4);
    var i, j;

    for (i = 0; i < key.length; i++) { w[i] = key[i]; }

    for (i = nk; i < total; i++) {
        var o = i * 4, p = (i - 1) * 4;
        var t0 = w[p], t1 = w[p + 1], t2 = w[p + 2], t3 = w[p + 3];

        if (i % nk === 0) {
            /* rotate, substitute, then xor the round constant */
            var tmp = t0;
            t0 = SBOX[t1] ^ RCON[i / nk];
            t1 = SBOX[t2];
            t2 = SBOX[t3];
            t3 = SBOX[tmp];
        } else if (nk > 6 && i % nk === 4) {
            /* AES-256 substitutes again at the halfway point of each cycle */
            t0 = SBOX[t0]; t1 = SBOX[t1]; t2 = SBOX[t2]; t3 = SBOX[t3];
        }

        var q = (i - nk) * 4;
        w[o]     = w[q]     ^ t0;
        w[o + 1] = w[q + 1] ^ t1;
        w[o + 2] = w[q + 2] ^ t2;
        w[o + 3] = w[q + 3] ^ t3;
    }
    return w;
}

/**
 * Expand a key and derive the round count together.
 *
 * These two always travel as a pair and the round count is a function of the
 * key length, yet the pair was written out in seventeen separate places. One
 * of them getting the formula wrong would be a silent wrong answer, so it
 * lives here instead.
 */
function setup(key) {
    var rk = expand_key(key);
    /*
     * ⭐ THE ROUND KEYS AS 32-BIT WORDS, alongside the bytes.
     *
     *   The round read them with rd_be32, which is four array accesses and
     *   three shifts - fifty-six times per block. Precomputing the words
     *   once per key turns that into a single indexed read.
     *
     * ⚠ BOTH VIEWS ARE KEPT. Other modes and the key schedule itself work in
     *   bytes, and deriving one from the other at each use is what this is
     *   removing.
     */
    return { rk: rk, rkw: key_words(rk), nr: key.length / 4 + 6 };
}

/*
 * The byte schedule read as big-endian words. setup, aes_expand_key and XTS
 * each wrote this loop.
 */
function key_words(rk) {
    var w = new Int32Array(rk.length >>> 2);
    for (var i = 0; i < w.length; i++) { w[i] = rd_be32(rk, i * 4); }
    return w;
}

/**
 * Bind a key schedule into a one-block callback for the shared modes in
 * commons/. The schedule stays in the closure, so the mode code never sees a
 * key.
 *
 * This is the ONE binding. There used to be four - this, block_fn,
 * block_fn_dec and a closure written inline in aes_cmac - and outside this
 * file ff1.js and drbg.js each rebuilt it from aes_expand_key with their own
 * copy of the round-count formula. aes_block_fn below is for them.
 */
function blocks(key, decrypting) {
    var s = setup(key);
    return function (src, off, out, out_off) {
        if (decrypting) { decrypt_block(s.rk, s.nr, src, off, out, out_off); }
        else            { encrypt_block(s.rkw, s.nr, src, off, out, out_off); }
    };
}

/**
 * Argument checks, centralised.
 *
 * Every mode validates its IV and its block alignment the same way, and each
 * of them had its own copy - which means an encrypt function and its matching
 * decrypt function could drift apart. They are one line each here instead.
 */
function require_iv(iv, len, name) {
    if (iv.length !== len) {
        throw new Error(name + ': iv must be ' + len + ' bytes');
    }
}

function require_blocks(data, name) {
    if (data.length % BLOCK !== 0) {
        throw new Error(name + ': data must be a multiple of 16 bytes');
    }
}

/*
 * ============================ THE T-TABLES ============================
 *
 * SubBytes, ShiftRows and MixColumns folded into one 32-bit lookup per
 * column, which is the standard software AES and what every fast
 * implementation in any language uses.
 *
 * IT MAKES THE CACHE-TIMING LEAK WORSE, AND THAT IS A DELIBERATE CHOICE.
 *
 * The byte-oriented version this replaced indexed a 256-byte S-box, which
 * spans four cache lines - so an attacker who can see which line was touched
 * learns two bits of the index per lookup. These tables are 4 KiB and span
 * sixty-four lines, so the same observation yields four bits. Twice the
 * information per measurement, and less noise to filter.
 *
 * AND THE INDEX IS KEY MATERIAL. In the first round the state is
 * plaintext XOR key, so the table index IS that value; an attacker who knows
 * the plaintext - and in CTR and GCM the "plaintext" is a counter derived
 * from the public IV, so they always do - recovers key bits directly. That is
 * the mechanism behind Osvik-Shamir-Tromer (2005), which took 65 ms of
 * measurement, and behind the 2015 cross-VM recovery from a co-resident
 * tenant.
 *
 * WHY IT IS STILL THE RIGHT CALL HERE: the old version leaked too, just more
 * slowly, so this trades a factor of two in the attacker's resolution for a
 * factor of six in speed. What it does NOT do is make AES safe on shared
 * hardware; nothing in JavaScript can.
 *
 * A CONSTANT-TIME PATH WAS BUILT AND MEASURED. A bitsliced S-box - derived as
 * x^254 in the field and verified exhaustively against the table - runs at
 * 271 ns for 32 bytes, and a full bitsliced AES would land near 2630 ns per
 * block against this version's 530. It is the only option that improves both
 * axes at once, and it is five times slower than this one. The generator for
 * it is preserved in commons/aes_bitslice.js.
 *
 * IF YOU ARE ON SHARED HARDWARE, USE ChaCha20-Poly1305. It has no tables at
 * all, so the question does not arise, and in this library it is faster than
 * AES-GCM anyway.
 * ======================================================================
 */

/*
 * T0[x] is the column [2x, x, x, 3x]; T1, T2 and T3 are its rotations.
 *
 * ⭐ ALL FOUR ARE MATERIALISED. The round used to hold only T0 and rotate it
 *   at each use - three rotr32 calls per output word, four words per round,
 *   fourteen rounds: 168 rotations per block that three extra kilobytes of
 *   table remove entirely.
 *
 * ⚠ THE ROTATIONS ARE BY BYTES, and T1 = rotr32(T0, 8) is what the round
 *   was already computing - so the tables are generated from T0 rather than
 *   from the field, and a mistake in them would have to be a mistake in T0.
 */
/*
 * T0 itself is commons/aes_round.js's table - AEGIS uses it on its own, and
 * both files derived it from the S-box with the same loop.
 */
var T0 = AES_T0;
var T1 = /* @__PURE__ */ (function () {
    var t = new Int32Array(256);
    for (var i = 0; i < 256; i++) { t[i] = rotr32(T0[i], 8); }
    return t;
}());
var T2 = /* @__PURE__ */ (function () {
    var t = new Int32Array(256);
    for (var i = 0; i < 256; i++) { t[i] = rotr32(T0[i], 16); }
    return t;
}());
var T3 = /* @__PURE__ */ (function () {
    var t = new Int32Array(256);
    for (var i = 0; i < 256; i++) { t[i] = rotr32(T0[i], 24); }
    return t;
}());

/**
 * Write four state words into `out` as sixteen big-endian bytes.
 *
 * ⭐ SHARED between encrypt_block and decrypt_block, which jscpd found
 *   holding the same eleven lines. It is the block's final step in both, and
 *   two copies of a byte order is how one gets a correction and the other
 *   does not - a swapped pair there produces ciphertext this library would
 *   decrypt back correctly and nothing else would touch.
 */
function store_state(out, out_off, t0, t1, t2, t3) {
    out[out_off]      = (t0 >>> 24) & 0xff; out[out_off + 1]  = (t0 >>> 16) & 0xff;
    out[out_off + 2]  = (t0 >>> 8) & 0xff;  out[out_off + 3]  = t0 & 0xff;
    out[out_off + 4]  = (t1 >>> 24) & 0xff; out[out_off + 5]  = (t1 >>> 16) & 0xff;
    out[out_off + 6]  = (t1 >>> 8) & 0xff;  out[out_off + 7]  = t1 & 0xff;
    out[out_off + 8]  = (t2 >>> 24) & 0xff; out[out_off + 9]  = (t2 >>> 16) & 0xff;
    out[out_off + 10] = (t2 >>> 8) & 0xff;  out[out_off + 11] = t2 & 0xff;
    out[out_off + 12] = (t3 >>> 24) & 0xff; out[out_off + 13] = (t3 >>> 16) & 0xff;
    out[out_off + 14] = (t3 >>> 8) & 0xff;  out[out_off + 15] = t3 & 0xff;
}

/** Encrypt one 16-byte block from src[off] into out[out_off]. */
function encrypt_block(rkw, nr, src, off, out, out_off) {
    var s0 = ((src[off] << 24) | (src[off + 1] << 16) | (src[off + 2] << 8) | src[off + 3]) ^ rkw[0];
    var s1 = ((src[off + 4] << 24) | (src[off + 5] << 16) | (src[off + 6] << 8) | src[off + 7]) ^ rkw[1];
    var s2 = ((src[off + 8] << 24) | (src[off + 9] << 16) | (src[off + 10] << 8) | src[off + 11]) ^ rkw[2];
    var s3 = ((src[off + 12] << 24) | (src[off + 13] << 16) | (src[off + 14] << 8) | src[off + 15]) ^ rkw[3];

    var t0, t1, t2, t3, r, kw;

    for (r = 1; r < nr; r++) {
        kw = r * 4;
        /* the byte selection here IS ShiftRows - column j reads from
           columns j, j+1, j+2, j+3, which is what the shift amounts to */
        t0 = T0[(s0 >>> 24) & 0xff] ^ T1[(s1 >>> 16) & 0xff] ^
             T2[(s2 >>> 8) & 0xff] ^ T3[s3 & 0xff] ^ rkw[kw];
        t1 = T0[(s1 >>> 24) & 0xff] ^ T1[(s2 >>> 16) & 0xff] ^
             T2[(s3 >>> 8) & 0xff] ^ T3[s0 & 0xff] ^ rkw[kw + 1];
        t2 = T0[(s2 >>> 24) & 0xff] ^ T1[(s3 >>> 16) & 0xff] ^
             T2[(s0 >>> 8) & 0xff] ^ T3[s1 & 0xff] ^ rkw[kw + 2];
        t3 = T0[(s3 >>> 24) & 0xff] ^ T1[(s0 >>> 16) & 0xff] ^
             T2[(s1 >>> 8) & 0xff] ^ T3[s2 & 0xff] ^ rkw[kw + 3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* the last round omits MixColumns, so it uses the plain S-box */
    kw = nr * 4;
    t0 = ((SBOX[(s0 >>> 24) & 0xff] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) |
          (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ rkw[kw];
    t1 = ((SBOX[(s1 >>> 24) & 0xff] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) |
          (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ rkw[kw + 1];
    t2 = ((SBOX[(s2 >>> 24) & 0xff] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) |
          (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ rkw[kw + 2];
    t3 = ((SBOX[(s3 >>> 24) & 0xff] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) |
          (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ rkw[kw + 3];

    store_state(out, out_off, t0, t1, t2, t3);
}


/*
 * The inverse T-table: [14x, 9x, 13x, 11x] for the inverse S-box output.
 *
 * The forward direction needs one table because MixColumns multiplies by 2 and
 * 3; the inverse needs 9, 11, 13 and 14, which is why a byte-oriented inverse
 * costs so much more than a byte-oriented forward round. Folded into a word
 * lookup they cost the same.
 */
var T0_INV = /* @__PURE__ */ (function () {
    var t = new Int32Array(256);
    for (var i = 0; i < 256; i++) {
        var sb = INV_SBOX[i];
        t[i] = ((gmul(sb, 14, POLY_AES) << 24) | (gmul(sb, 9, POLY_AES) << 16) |
                (gmul(sb, 13, POLY_AES) << 8) | gmul(sb, 11, POLY_AES)) | 0;
    }
    return t;
}());

/*
 * The key schedule has to be transformed too.
 *
 * The equivalent-inverse-cipher form of AES applies InvMixColumns to every
 * round key except the first and last, which is what lets decryption use the
 * same structure as encryption rather than a mirrored one. FIPS-197 section
 * 5.3.5 sets this out; without it the round order cannot be rearranged and the
 * table form does not apply.
 *
 * CACHED PER KEY SCHEDULE, because computing it costs more than a block does.
 *
 * The cache is keyed on OBJECT IDENTITY, which is safe here only because
 * expand_key returns a fresh array on every call - so two different keys can
 * never share a schedule object, and a schedule object's contents never
 * change after it is built. If expand_key is ever changed to reuse a buffer,
 * this cache silently decrypts with the wrong key.
 *
 * Verified against interleaved keys and against a caller mutating its own key
 * array between calls; both are in the test suite.
 */
var DEC_CACHE = null, DEC_CACHE_KEY = null;

function inv_schedule(rk, nr) {
    if (DEC_CACHE_KEY === rk) { return DEC_CACHE; }
    var d = new Uint8Array(rk.length);
    d.set(rk);
    for (var r = 1; r < nr; r++) {
        for (var c = 0; c < 4; c++) {
            var o = r * 16 + c * 4;
            var a0 = d[o], a1 = d[o + 1], a2 = d[o + 2], a3 = d[o + 3];
            d[o]     = gmul(a0, 14, POLY_AES) ^ gmul(a1, 11, POLY_AES) ^
                       gmul(a2, 13, POLY_AES) ^ gmul(a3,  9, POLY_AES);
            d[o + 1] = gmul(a0,  9, POLY_AES) ^ gmul(a1, 14, POLY_AES) ^
                       gmul(a2, 11, POLY_AES) ^ gmul(a3, 13, POLY_AES);
            d[o + 2] = gmul(a0, 13, POLY_AES) ^ gmul(a1,  9, POLY_AES) ^
                       gmul(a2, 14, POLY_AES) ^ gmul(a3, 11, POLY_AES);
            d[o + 3] = gmul(a0, 11, POLY_AES) ^ gmul(a1, 13, POLY_AES) ^
                       gmul(a2,  9, POLY_AES) ^ gmul(a3, 14, POLY_AES);
        }
    }
    DEC_CACHE_KEY = rk;
    DEC_CACHE = d;
    return d;
}

/** Decrypt one 16-byte block. Same cache-timing trade as encrypt_block. */
function decrypt_block(rk, nr, src, off, out, out_off) {
    var dk = inv_schedule(rk, nr);
    var k = nr * 16;

    var s0 = ((src[off] << 24) | (src[off + 1] << 16) | (src[off + 2] << 8) | src[off + 3]) ^ rd_be32(dk, k);
    var s1 = ((src[off + 4] << 24) | (src[off + 5] << 16) | (src[off + 6] << 8) | src[off + 7]) ^ rd_be32(dk, k + 4);
    var s2 = ((src[off + 8] << 24) | (src[off + 9] << 16) | (src[off + 10] << 8) | src[off + 11]) ^ rd_be32(dk, k + 8);
    var s3 = ((src[off + 12] << 24) | (src[off + 13] << 16) | (src[off + 14] << 8) | src[off + 15]) ^ rd_be32(dk, k + 12);

    var t0, t1, t2, t3, r;

    for (r = nr - 1; r > 0; r--) {
        k = r * 16;
        /* the column selection runs the OTHER WAY from encryption - that is
           InvShiftRows, and it is the only structural difference */
        t0 = T0_INV[(s0 >>> 24) & 0xff] ^ rotr32(T0_INV[(s3 >>> 16) & 0xff], 8) ^
             rotr32(T0_INV[(s2 >>> 8) & 0xff], 16) ^ rotr32(T0_INV[s1 & 0xff], 24) ^ rd_be32(dk, k);
        t1 = T0_INV[(s1 >>> 24) & 0xff] ^ rotr32(T0_INV[(s0 >>> 16) & 0xff], 8) ^
             rotr32(T0_INV[(s3 >>> 8) & 0xff], 16) ^ rotr32(T0_INV[s2 & 0xff], 24) ^ rd_be32(dk, k + 4);
        t2 = T0_INV[(s2 >>> 24) & 0xff] ^ rotr32(T0_INV[(s1 >>> 16) & 0xff], 8) ^
             rotr32(T0_INV[(s0 >>> 8) & 0xff], 16) ^ rotr32(T0_INV[s3 & 0xff], 24) ^ rd_be32(dk, k + 8);
        t3 = T0_INV[(s3 >>> 24) & 0xff] ^ rotr32(T0_INV[(s2 >>> 16) & 0xff], 8) ^
             rotr32(T0_INV[(s1 >>> 8) & 0xff], 16) ^ rotr32(T0_INV[s0 & 0xff], 24) ^ rd_be32(dk, k + 12);
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* the last round has no InvMixColumns, so it uses the plain inverse S-box */
    t0 = ((INV_SBOX[(s0 >>> 24) & 0xff] << 24) | (INV_SBOX[(s3 >>> 16) & 0xff] << 16) |
          (INV_SBOX[(s2 >>> 8) & 0xff] << 8) | INV_SBOX[s1 & 0xff]) ^ rd_be32(dk, 0);
    t1 = ((INV_SBOX[(s1 >>> 24) & 0xff] << 24) | (INV_SBOX[(s0 >>> 16) & 0xff] << 16) |
          (INV_SBOX[(s3 >>> 8) & 0xff] << 8) | INV_SBOX[s2 & 0xff]) ^ rd_be32(dk, 4);
    t2 = ((INV_SBOX[(s2 >>> 24) & 0xff] << 24) | (INV_SBOX[(s1 >>> 16) & 0xff] << 16) |
          (INV_SBOX[(s0 >>> 8) & 0xff] << 8) | INV_SBOX[s3 & 0xff]) ^ rd_be32(dk, 8);
    t3 = ((INV_SBOX[(s3 >>> 24) & 0xff] << 24) | (INV_SBOX[(s2 >>> 16) & 0xff] << 16) |
          (INV_SBOX[(s1 >>> 8) & 0xff] << 8) | INV_SBOX[s0 & 0xff]) ^ rd_be32(dk, 12);

    store_state(out, out_off, t0, t1, t2, t3);
}

/* ---------------- ECB ---------------- */
/*
 * Raw block-by-block encryption, with no chaining and no nonce.
 *
 * ECB is NOT a general-purpose mode and should never be used to encrypt a
 * message. Identical plaintext blocks produce identical ciphertext blocks,
 * so structure in the data survives encryption - the famous penguin image.
 *
 * It is here for the narrow uses where a single block is being permuted with
 * no message semantics at all: QUIC header protection (RFC 9001) applies
 * AES-ECB to a 16-byte sample to mask the packet number, and key-wrapping
 * constructions build on the bare block function.
 */

/*
 * ECB, CTR, CBC, CMAC, key wrap, GCM, CCM, GMAC and EAX are generated by
 * commons/cipher_modes.js - the same wrappers ARIA, Camellia, SEED and SM4
 * use, and which each of the five used to write out. The modes AES alone has
 * (IGE, CFB, OFB, XTS, OCB, SIV, GCM-SIV) stay below.
 */
var M = bind_modes('aes', BLOCK, blocks);

/**
 * @param {Uint8Array} key   16, 24 or 32 bytes
 * @param {Uint8Array} data  a multiple of 16 bytes
 */
export var aes_ecb_encrypt = M.ecb_encrypt;
export var aes_ecb_decrypt = M.ecb_decrypt;

/**
 * ECB under one key for many calls: the key schedule is computed once, so a
 * 16-byte block costs only its rounds - QUIC's header protection encrypts
 * one per packet.
 *
 *     var ecb = aes_ecb_create(key);
 *     ecb.encrypt(sample)  ->  16 bytes
 *     ecb.decrypt(block)   ->  16 bytes
 *
 * @param {Uint8Array} key   16, 24 or 32 bytes
 * @return {{ encrypt: function(Uint8Array): Uint8Array, decrypt: function(Uint8Array): Uint8Array }}
 *         each takes a multiple of 16 bytes
 */
export var aes_ecb_create = M.ecb_create;

/* ---------------- CTR ---------------- */
/*
 * Turns AES into a stream cipher: encrypt a counter, xor the result.
 *
 * Encryption and decryption are the same operation, no padding is needed, and
 * any length works. Like every stream cipher it offers no integrity, and
 * reusing a counter value under one key is catastrophic in the same way as
 * reusing a ChaCha20 nonce.
 */

/**
 * @param {Uint8Array} key
 * @param {Uint8Array} iv    16 bytes. The whole block is the counter, and it
 *                           increments as a big-endian 128-bit integer.
 * @param {Uint8Array} data
 */
export var aes_ctr = M.ctr;

/* ---------------- CBC ---------------- */
/*
 * Each plaintext block is xored with the previous ciphertext block before
 * encryption, so identical blocks no longer look identical.
 *
 * CBC has no integrity protection, and combining it with a MAC incorrectly is
 * the source of a long line of padding-oracle attacks. If a MAC is needed,
 * authenticate the ciphertext, and prefer GCM below.
 *
 * aes_cbc_decrypt returns null on invalid padding rather than throwing. A
 * distinguishable padding error is exactly what a padding oracle needs, so
 * the failure is deliberately indistinguishable from any other rejection.
 * That mitigates but does not remove the risk - the real fix is to
 * authenticate the ciphertext.
 */
export var aes_cbc_encrypt = M.cbc_encrypt;
export var aes_cbc_decrypt = M.cbc_decrypt;

/*
 * Exposed for modes built elsewhere on the raw block function.
 *
 * ⚠ THIS RETURNS THE WORD VIEW, not the bytes. encrypt_block reads the round
 *   keys as 32-bit words - the byte form cost four accesses and three shifts
 *   per word, fifty-six times a block - and handing it a Uint8Array would
 *   index past the end and produce a wrong block rather than an error.
 */
export function aes_expand_key(key) {
    var rk = expand_key(key);
    var w = key_words(rk);
    wipe(rk);
    return w;
}
export function aes_encrypt_block(rkw, nr, src, off, out, out_off) {
    encrypt_block(rkw, nr, src, off, out, out_off);
}

/**
 * The forward block function for a key, in the shape every mode in commons/
 * takes: block(src, src_off, out, out_off).
 *
 * For code that builds its own construction on AES - ff1.js, drbg.js - so it
 * needs neither the word schedule nor the round count. Both used to compute
 * `nr` from the key length themselves.
 *
 * @param {Uint8Array} key  16, 24 or 32 bytes
 */
export function aes_block_fn(key) {
    /* encryption reads only the word schedule, so the byte copy is wiped -
       as aes_expand_key does, which ff1 and the CTR_DRBG used before */
    var rkw = aes_expand_key(key), nr = key.length / 4 + 6;
    return function (src, off, out, out_off) { encrypt_block(rkw, nr, src, off, out, out_off); };
}

/* ---------------- GCM ---------------- */
/*
 * The mode itself lives in commons/gcm.js: nothing in GCM or GHASH is about
 * AES, and SM4-GCM (RFC 8998) and ARIA-GCM (RFC 6209) are real standards that
 * now come for free. What stays here is the binding of AES to it.
 */

/* ---------------- IGE ---------------- */
/*
 * Infinite Garble Extension. Almost nothing uses it, and the one thing that
 * does is Telegram: MTProto encrypts every message with AES-256-IGE.
 *
 * It resembles CBC with a second chain. Each block is xored with the previous
 * CIPHERTEXT before encryption, as in CBC, and with the previous PLAINTEXT
 * after it. The name comes from the claim that a single flipped bit corrupts
 * everything downstream; that claim was disproven, and analysis of MTProto
 * found IGE to be about as strong as CBC and vulnerable to the same
 * manipulation when plaintext is partly known.
 *
 * Like CBC it provides no integrity of its own. MTProto adds that separately
 * with a SHA-256 based msg_key. Anything new should use GCM or
 * ChaCha20-Poly1305 instead; this exists for interoperability.
 *
 * The IV is 32 bytes, not 16: it seeds both chains at once.
 */

/**
 * @param  {Uint8Array} key   16, 24 or 32 bytes
 * @param  {Uint8Array} iv    32 bytes - previous ciphertext then previous plaintext
 * @param  {Uint8Array} data  a multiple of 16 bytes
 * @return {Uint8Array}
 */
export function aes_ige_encrypt(key, iv, data) {
    require_iv(iv, 32, 'aes_ige');
    require_blocks(data, 'aes_ige');
    var s0_ = setup(key), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var out = new Uint8Array(data.length);
    var prev_c = new Uint8Array(iv.subarray(0, 16));
    var prev_p = new Uint8Array(iv.subarray(16, 32));
    var blk = new Uint8Array(BLOCK);
    var i, j;

    for (i = 0; i < data.length; i += BLOCK) {
        for (j = 0; j < BLOCK; j++) { blk[j] = data[i + j] ^ prev_c[j]; }
        encrypt_block(rkw, nr, blk, 0, out, i);
        for (j = 0; j < BLOCK; j++) { out[i + j] ^= prev_p[j]; }
        for (j = 0; j < BLOCK; j++) { prev_c[j] = out[i + j]; prev_p[j] = data[i + j]; }
    }
    wipe(rk); wipe(blk); wipe(prev_c); wipe(prev_p);
    return out;
}

export function aes_ige_decrypt(key, iv, data) {
    require_iv(iv, 32, 'aes_ige');
    require_blocks(data, 'aes_ige');
    var s0_ = setup(key), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var out = new Uint8Array(data.length);
    var prev_c = new Uint8Array(iv.subarray(0, 16));
    var prev_p = new Uint8Array(iv.subarray(16, 32));
    var blk = new Uint8Array(BLOCK);
    var i, j;

    for (i = 0; i < data.length; i += BLOCK) {
        for (j = 0; j < BLOCK; j++) { blk[j] = data[i + j] ^ prev_p[j]; }
        decrypt_block(rk, nr, blk, 0, out, i);
        for (j = 0; j < BLOCK; j++) { out[i + j] ^= prev_c[j]; }
        for (j = 0; j < BLOCK; j++) { prev_c[j] = data[i + j]; prev_p[j] = out[i + j]; }
    }
    wipe(rk); wipe(blk); wipe(prev_c); wipe(prev_p);
    return out;
}

/* ---------------- CMAC ---------------- */
/*
 * NIST SP 800-38B. A message authentication code built from a block cipher
 * rather than a hash.
 *
 * It lives in this file rather than beside HMAC because it belongs to AES the
 * way KMAC belongs to Keccak - it is a mode of the cipher, not a construction
 * that works over anything. hmac.js stays generic because HMAC genuinely is.
 *
 * CMAC exists because the obvious block-cipher MAC, plain CBC-MAC with a zero
 * IV, is only secure for messages of one fixed length. Given tags for two
 * messages an attacker can splice them into a third with a predictable tag.
 * CMAC fixes that by xoring a derived subkey into the final block, and by
 * using a DIFFERENT subkey depending on whether that block was full. Those
 * two subkeys are what make a padded short message unable to collide with an
 * unpadded full one.
 *
 * Where it turns up: WPA2's AES-CMAC, Bluetooth pairing, TLS 1.2 PSK
 * ciphersuites, and as the PRF inside AES-SIV below.
 */

/*
 * The doubling CMAC, OCB and S2V share - a LEFT shift with 0x87 folded in at
 * the bottom, the opposite orientation to GHASH, which shifts right and folds
 * 0xE1 at the top - is commons/cmac.js's dbl128. This file held a second,
 * identical copy.
 */

/**
 * AES-CMAC, per NIST SP 800-38B.
 *
 * The construction moved to commons/cmac.js when ARIA, Camellia and SM4
 * needed it too - all four are 128-bit block ciphers and the difference is
 * only which block function goes in. aes_cmac_verify is constant time, so
 * callers never write === on a tag.
 *
 * @param  {Uint8Array} key  16, 24 or 32 bytes
 * @param  {Uint8Array} msg  any length, including empty
 * @return {Uint8Array} 16-byte tag
 */
export var aes_cmac = M.cmac;
export var aes_cmac_verify = M.cmac_verify;
/* CMAC under a key set once: update(msg), copy(), digest() - see commons/cmac.js */
export var aes_cmac_create = M.cmac_create;

/* ---------------- Key wrapping: KW and KWP ---------------- */
/*
 * RFC 3394 and RFC 5649. Encrypting one key with another.
 *
 * This looks like something GCM could do, and the reason it exists separately
 * is that key wrapping has no nonce. A wrapped key must be reproducible and
 * often must be stored without room for extra state, so the construction has
 * to be deterministic AND still authenticated. It buys that by running six
 * passes over the data, each mixing every block into every other, with a
 * fixed check value that unwrapping verifies.
 *
 * The cost is that identical keys wrap to identical ciphertext. That is
 * accepted here because the plaintext is a random key, not a message.
 *
 * KW takes lengths that are a multiple of 8 and at least 16 bytes. KWP wraps
 * anything by prefixing the true length and padding, which is what JOSE and
 * PKCS#11 generally use.
 */



/**
 * aes_kw_wrap(kek, data): data a multiple of 8 bytes, at least 16, and the
 * result 8 bytes longer. aes_kwp_wrap (RFC 5649) wraps any length by
 * recording the true length up front.
 *
 * The unwraps return null if the check value does not match - the integrity
 * of a wrapped key is the whole point, so a failure must never yield key
 * material.
 */
export var aes_kw_wrap = M.kw_wrap;
export var aes_kw_unwrap = M.kw_unwrap;
export var aes_kwp_wrap = M.kwp_wrap;
export var aes_kwp_unwrap = M.kwp_unwrap;

/* ---------------- SIV ---------------- */
/*
 * RFC 5297. Synthetic Initialisation Vector - deterministic authenticated
 * encryption, and the answer to the failure mode this file and chacha.js keep
 * warning about.
 *
 * Every other AEAD here breaks catastrophically on nonce reuse: GCM leaks its
 * hash subkey, ChaCha20-Poly1305 leaks the authenticator key. SIV does not.
 * Reusing a nonce with the same plaintext reveals only that the two messages
 * were identical - which is the least an attacker could possibly learn from a
 * deterministic scheme, and nothing more.
 *
 * It buys that by deriving the IV FROM the message rather than choosing one.
 * A PRF called S2V runs over the associated data and the plaintext, and its
 * output becomes both the authentication tag and the CTR starting block. That
 * ordering is why SIV cannot stream: nothing can be encrypted until the whole
 * plaintext has been read.
 *
 * The other cost is the key: SIV takes twice the usual length, split into one
 * key for the PRF and one for the cipher. A 32-byte SIV key is AES-128 twice,
 * not AES-256.
 *
 * Where it fits: wrapping keys with associated context, encrypting database
 * fields where a nonce column is unwelcome, and any protocol where nonce
 * uniqueness cannot be guaranteed by construction.
 */

/** Pad to a full block with 0x80 then zeros, per RFC 5297. */
function siv_pad(x) {
    var b = new Uint8Array(BLOCK);
    var n = x.length < BLOCK ? x.length : BLOCK;
    for (var i = 0; i < n; i++) { b[i] = x[i]; }
    if (n < BLOCK) { b[n] = 0x80; }
    return b;
}

/**
 * S2V - the PRF that turns a vector of strings into one synthetic IV.
 *
 * The doubling between elements is what makes the vector positional: moving a
 * string from one slot to another changes the result, so associated data
 * cannot be reordered or merged without detection.
 */
function s2v(k, ads, plaintext) {
    var i, j;

    /*
     * RFC 5297 defines an n = 0 case that returns CMAC of <one>. It is NOT
     * reachable from SIV: SIV always passes the plaintext as the final
     * component, so n is at least one even when everything is empty. An
     * earlier version special-cased empty-plaintext-and-no-AD here and got a
     * different answer from every other implementation for exactly that
     * input. The n = 0 branch belongs to S2V used standalone as a PRF.
     */
    var d = aes_cmac(k, new Uint8Array(BLOCK));
    for (i = 0; i < ads.length; i++) {
        dbl128(d);
        var c = aes_cmac(k, ads[i]);
        for (j = 0; j < BLOCK; j++) { d[j] ^= c[j]; }
        wipe(c);
    }

    var t;
    if (plaintext.length >= BLOCK) {
        /* xorend: fold D into the LAST block of the plaintext */
        t = new Uint8Array(plaintext);
        var off = t.length - BLOCK;
        for (j = 0; j < BLOCK; j++) { t[off + j] ^= d[j]; }
    } else {
        dbl128(d);
        t = siv_pad(plaintext);
        for (j = 0; j < BLOCK; j++) { t[j] ^= d[j]; }
    }

    var v = aes_cmac(k, t);
    wipe(d); wipe(t);
    return v;
}

/**
 * The CTR counter is the synthetic IV with two bits cleared.
 *
 * RFC 5297 zeroes bit 31 and bit 63 counting from the right of each half, so
 * that the 32-bit counter can increment without ever carrying into the rest
 * of the block. Without it a long message could roll the counter into the
 * authentication material.
 */
function siv_ctr_block(v) {
    var q = new Uint8Array(v);
    q[8] &= 0x7f;
    q[12] &= 0x7f;
    return q;
}

/**
 * @param  {Uint8Array}   key   32, 48 or 64 bytes - twice an AES key
 * @param  {Uint8Array}   plaintext
 * @param  {Uint8Array[]} [ads] a VECTOR of associated data strings, in order
 * @return {Uint8Array} 16-byte synthetic IV followed by the ciphertext
 */
export function aes_siv_encrypt(key, plaintext, ads) {
    if (key.length !== 32 && key.length !== 48 && key.length !== 64) {
        throw new Error('aes_siv: key must be 32, 48 or 64 bytes - twice an AES key');
    }
    var half = key.length / 2;
    var k1 = key.subarray(0, half), k2 = key.subarray(half);
    var a = ads || [];

    var v = s2v(k1, a, plaintext);
    var ct = aes_ctr(k2, siv_ctr_block(v), plaintext);

    var out = new Uint8Array(BLOCK + ct.length);
    out.set(v, 0);
    out.set(ct, BLOCK);
    return out;
}

/**
 * Returns null on authentication failure.
 *
 * The order here is forced by the design: the tag cannot be checked before
 * decrypting, because the tag is computed over the PLAINTEXT. So the
 * plaintext is produced first and discarded if it does not verify - which is
 * safe only because nothing is returned until the check passes.
 *
 * @return {Uint8Array|null}
 */
export function aes_siv_decrypt(key, sealed, ads) {
    if (key.length !== 32 && key.length !== 48 && key.length !== 64) {
        throw new Error('aes_siv: key must be 32, 48 or 64 bytes - twice an AES key');
    }
    if (sealed.length < BLOCK) { return null; }

    var half = key.length / 2;
    var k1 = key.subarray(0, half), k2 = key.subarray(half);
    var a = ads || [];

    var v = sealed.subarray(0, BLOCK);
    var ct = sealed.subarray(BLOCK);

    var pt = aes_ctr(k2, siv_ctr_block(v), ct);
    var expected = s2v(k1, a, pt);

    if (equal(expected, v) !== 1) { wipe(pt); return null; }
    return pt;
}

/* ---------------- GCM-SIV ---------------- */
/*
 * RFC 8452. GCM's speed with SIV's tolerance for a repeated nonce.
 *
 * Plain SIV above pays for that tolerance twice: a double-length key, and two
 * passes over the plaintext with no possibility of streaming. GCM-SIV keeps
 * the second cost but drops the first, and it is close enough to GCM that
 * hardware built for one accelerates the other.
 *
 * Three things differ from GCM, and each is a place implementations go wrong:
 *
 *   1. POLYVAL replaces GHASH. Same field, opposite bit order - GHASH counts
 *      coefficients from the left of each byte, POLYVAL from the right. RFC
 *      8452 gives an exact translation between them, used below rather than
 *      writing a second field implementation.
 *
 *   2. The keys are DERIVED per nonce. The caller's key never encrypts
 *      anything directly; it generates a fresh authentication key and
 *      encryption key for each message. That derivation is what keeps a
 *      repeated nonce from being fatal.
 *
 *   3. The counter increments its first four bytes LITTLE-endian. GCM
 *      increments its last four bytes big-endian, and aes_ctr increments the
 *      whole block. Three counters, three conventions, in one file.
 *
 * On nonce reuse it degrades the way SIV does: two identical messages under
 * one nonce are visibly identical, and nothing worse leaks. The tag is still
 * only 128 bits, so the usual birthday limits on total data under one key
 * apply.
 */

function byte_reverse(b) {
    var out = new Uint8Array(16);
    for (var i = 0; i < 16; i++) { out[i] = b[15 - i]; }
    return out;
}

/**
 * POLYVAL, expressed through GHASH per RFC 8452 appendix A:
 *
 *   POLYVAL(H, X...) = reverse(GHASH(mulX(reverse(H)), reverse(X)...))
 *
 * Reusing the tested GHASH is worth the byte shuffling - a second hand-written
 * field multiplication in the opposite bit order is exactly the kind of code
 * that looks right and is not.
 */
function polyval(h_bytes, data) {
    /*
     * mulX is commons/gcm.js's gf_mulx, applied to the words directly. This
     * file had its own byte-in, byte-out copy of that shift (mulx_ghash),
     * which then had to be read back into words for ghash.
     */
    var hr = byte_reverse(h_bytes);
    var h = new Int32Array([rd_be32(hr, 0), rd_be32(hr, 4), rd_be32(hr, 8), rd_be32(hr, 12)]);
    gf_mulx(h);

    var rev = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i += BLOCK) {
        for (var j = 0; j < BLOCK; j++) { rev[i + j] = data[i + 15 - j]; }
    }

    var y = new Int32Array(4);
    ghash(h, rev, y);

    var out = new Uint8Array(16);
    wr_be32s(out, 0, y);
    wipe(rev);
    return byte_reverse(out);
}

/**
 * Per-nonce key derivation. Encrypts counter blocks under the caller's key
 * and keeps only the low half of each output - discarding half is what stops
 * the derived keys from revealing anything about the master key.
 */
function gcmsiv_derive(key, nonce) {
    var s0_ = setup(key), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var n_blocks = (key.length === 16) ? 4 : 6;
    var blk = new Uint8Array(BLOCK);
    var out = new Uint8Array(BLOCK);
    var derived = new Uint8Array(n_blocks * 8);
    var i, j;

    for (i = 0; i < n_blocks; i++) {
        blk[0] = i & 0xff; blk[1] = (i >>> 8) & 0xff;
        blk[2] = 0; blk[3] = 0;
        for (j = 0; j < 12; j++) { blk[4 + j] = nonce[j]; }
        encrypt_block(rkw, nr, blk, 0, out, 0);
        for (j = 0; j < 8; j++) { derived[i * 8 + j] = out[j]; }
    }
    wipe(rk); wipe(blk); wipe(out);

    return {
        auth: derived.subarray(0, 16),
        enc:  derived.subarray(16),
        all:  derived
    };
}

/** CTR with a 32-bit little-endian counter in the FIRST four bytes. */
function gcmsiv_ctr(rkw, nr, icb, data) {
    var ctr = new Uint8Array(icb);
    /* block_modes.js's counter-mode core; the step wraps at 2^32 */
    var out = ctr_stream(function (src, off, o, o_off) { encrypt_block(rkw, nr, src, off, o, o_off); },
                         ctr, data, BLOCK, gcmsiv_step);
    wipe(ctr);
    return out;
}
function gcmsiv_step(c) { wr_le32(c, 0, rd_le32(c, 0) + 1); }

/*
 * pad16 - how many bytes of padding bring `n` up to a whole block - is
 * commons/gcm.js's, now exported. It was not at first, and this file
 * referred to it by a name that did not exist here: AES-GCM-SIV threw on
 * every call, and nothing noticed because the mode had no test. A local copy
 * fixed that; importing the one GCM uses fixes it without a second copy.
 */

function gcmsiv_tag(k, nonce, aad, pt) {
    /* POLYVAL input: each field padded to a block, then the two bit lengths */
    var ap = aad.length + pad16(aad.length);
    var pp = pt.length + pad16(pt.length);
    var buf = new Uint8Array(ap + pp + 16);
    buf.set(aad, 0);
    buf.set(pt, ap);

    var i;
    buf.set(le64(aad.length * 8), ap + pp);
    buf.set(le64(pt.length * 8), ap + pp + 8);

    var s = polyval(k.auth, buf);
    wipe(buf);

    for (i = 0; i < 12; i++) { s[i] ^= nonce[i]; }
    s[15] &= 0x7f;

    var s0_ = setup(k.enc), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var tag = new Uint8Array(BLOCK);
    encrypt_block(rkw, nr, s, 0, tag, 0);
    wipe(rk); wipe(s);
    return tag;
}

/*
 * AES-GCM-SIV, RFC 8452. Verified against the specification's own vectors for
 * both key sizes.
 *
 * IT WAS BROKEN UNTIL RECENTLY, AND THE WAY IT BROKE IS WORTH RECORDING. When
 * GCM moved into commons/gcm.js, this code kept referring to `ghash` and
 * `pad16` as local names - both had moved - so every call threw a
 * ReferenceError. The mode had no test, so nothing said so, and it stayed
 * that way through several reviews.
 *
 * It was then briefly believed to be computing the wrong answer as well,
 * because the first comparison ran an AES-256 key against RFC 8452's AES-128
 * vector. It was not. A wrong test looks exactly like a wrong implementation
 * until you check which one you changed.
 */

/**
 * @param  {Uint8Array} key    16 or 32 bytes
 * @param  {Uint8Array} nonce  exactly 12 bytes
 * @param  {Uint8Array} plaintext
 * @param  {Uint8Array} [aad]
 * @return {Uint8Array} ciphertext followed by a 16-byte tag
 */
export function aes_gcm_siv_encrypt(key, nonce, plaintext, aad) {
    if (key.length !== 16 && key.length !== 32) {
        throw new Error('aes_gcm_siv: key must be 16 or 32 bytes');
    }
    if (nonce.length !== 12) {
        throw new Error('aes_gcm_siv: nonce must be 12 bytes');
    }
    var a = aad || new Uint8Array(0);
    var k = gcmsiv_derive(key, nonce);
    var tag = gcmsiv_tag(k, nonce, a, plaintext);

    /* the counter is the tag with its top bit set, so it can never collide
       with the value that produced the tag */
    var icb = new Uint8Array(tag);
    icb[15] |= 0x80;

    var s0_ = setup(k.enc), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var ct = gcmsiv_ctr(rkw, nr, icb, plaintext);
    wipe(rk); wipe(k.all);

    var out = new Uint8Array(ct.length + 16);
    out.set(ct, 0);
    out.set(tag, ct.length);
    return out;
}

/** @return {Uint8Array|null} */
export function aes_gcm_siv_decrypt(key, nonce, sealed, aad) {
    if (key.length !== 16 && key.length !== 32) {
        throw new Error('aes_gcm_siv: key must be 16 or 32 bytes');
    }
    if (nonce.length !== 12) {
        throw new Error('aes_gcm_siv: nonce must be 12 bytes');
    }
    if (sealed.length < 16) { return null; }

    var a = aad || new Uint8Array(0);
    var ct = sealed.subarray(0, sealed.length - 16);
    var tag = sealed.subarray(sealed.length - 16);

    var k = gcmsiv_derive(key, nonce);
    var icb = new Uint8Array(tag);
    icb[15] |= 0x80;

    var s0_ = setup(k.enc), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var pt = gcmsiv_ctr(rkw, nr, icb, ct);
    wipe(rk);

    /* like SIV, the tag covers the plaintext, so it can only be checked after
       decrypting - and nothing is returned unless it matches */
    var expected = gcmsiv_tag(k, nonce, a, pt);
    wipe(k.all);

    if (equal(expected, tag) !== 1) { wipe(pt); return null; }
    return pt;
}

/* ---------------- CCM ---------------- */
/*
 * The mode lives in commons/ccm.js: nothing in CCM is about AES, and SM4-CCM
 * (RFC 8998) and ARIA-CCM (RFC 6209) come with it. What stays here is the
 * binding.
 */

/* ---------------- CFB and OFB ---------------- */
/*
 * Two ways of turning a block cipher into a stream cipher, both predating
 * CTR and both largely superseded by it.
 *
 * OFB encrypts its own output repeatedly, so the keystream depends only on
 * the key and IV. CFB encrypts the previous CIPHERTEXT, so the keystream
 * depends on the data too - which is what makes CFB self-synchronising: a
 * receiver that loses bytes recovers after one block, while OFB never does.
 *
 * Neither authenticates anything. CFB has an additional trap: because its
 * keystream depends on ciphertext, an attacker who can modify ciphertext
 * controls the following block's keystream in a predictable way.
 *
 * Present for interoperability - OpenVPN, PGP, older TLS, SSH-1, and a long
 * tail of protocols that predate AEAD. Reach for GCM or ChaCha20-Poly1305
 * for anything new.
 *
 * CFB comes in bit-width variants. CFB128 processes a full block at a time
 * and is what "CFB" means in almost all modern use; CFB8 and CFB1 shift one
 * byte or one bit per cipher call, which costs 16 or 128 times as much and
 * exists for legacy synchronous links.
 */

/**
 * @param {Uint8Array} key
 * @param {Uint8Array} iv    16 bytes, must never repeat under one key
 * @param {Uint8Array} data  any length
 */
export function aes_ofb(key, iv, data) {
    require_iv(iv, BLOCK, 'aes_ofb');
    var s0_ = setup(key), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var out = new Uint8Array(data.length);
    var ks = new Uint8Array(iv);
    var i, j, n;
    for (i = 0; i < data.length; i += BLOCK) {
        /* the feedback is the keystream itself, so it never touches the data */
        encrypt_block(rkw, nr, ks, 0, ks, 0);
        n = data.length - i; if (n > BLOCK) { n = BLOCK; }
        for (j = 0; j < n; j++) { out[i + j] = data[i + j] ^ ks[j]; }
    }
    wipe(rk); wipe(ks);
    return out;
}

/** CFB128. Encryption and decryption differ - the feedback is the ciphertext. */
export function aes_cfb_encrypt(key, iv, data) {
    require_iv(iv, BLOCK, 'aes_cfb');
    var s0_ = setup(key), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var out = new Uint8Array(data.length);
    var fb = new Uint8Array(iv);
    var ks = new Uint8Array(BLOCK);
    var i, j, n;
    for (i = 0; i < data.length; i += BLOCK) {
        encrypt_block(rkw, nr, fb, 0, ks, 0);
        n = data.length - i; if (n > BLOCK) { n = BLOCK; }
        for (j = 0; j < n; j++) { out[i + j] = data[i + j] ^ ks[j]; }
        for (j = 0; j < n; j++) { fb[j] = out[i + j]; }
    }
    wipe(rk); wipe(fb); wipe(ks);
    return out;
}

export function aes_cfb_decrypt(key, iv, data) {
    require_iv(iv, BLOCK, 'aes_cfb');
    var s0_ = setup(key), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var out = new Uint8Array(data.length);
    var fb = new Uint8Array(iv);
    var ks = new Uint8Array(BLOCK);
    var i, j, n;
    for (i = 0; i < data.length; i += BLOCK) {
        encrypt_block(rkw, nr, fb, 0, ks, 0);
        n = data.length - i; if (n > BLOCK) { n = BLOCK; }
        /* feedback is taken from the INPUT here, which is the ciphertext */
        for (j = 0; j < n; j++) { fb[j] = data[i + j]; }
        for (j = 0; j < n; j++) { out[i + j] = data[i + j] ^ ks[j]; }
    }
    wipe(rk); wipe(fb); wipe(ks);
    return out;
}

/**
 * CFB8 - one byte per cipher call. Sixteen times the work of CFB128, and
 * present only because some legacy protocols specify it.
 */
export function aes_cfb8_encrypt(key, iv, data) {
    require_iv(iv, BLOCK, 'aes_cfb8');
    var s0_ = setup(key), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var out = new Uint8Array(data.length);
    var fb = new Uint8Array(iv);
    var ks = new Uint8Array(BLOCK);
    var i, j;
    for (i = 0; i < data.length; i++) {
        encrypt_block(rkw, nr, fb, 0, ks, 0);
        out[i] = data[i] ^ ks[0];
        for (j = 0; j < BLOCK - 1; j++) { fb[j] = fb[j + 1]; }
        fb[BLOCK - 1] = out[i];
    }
    wipe(rk); wipe(fb); wipe(ks);
    return out;
}

export function aes_cfb8_decrypt(key, iv, data) {
    require_iv(iv, BLOCK, 'aes_cfb8');
    var s0_ = setup(key), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var out = new Uint8Array(data.length);
    var fb = new Uint8Array(iv);
    var ks = new Uint8Array(BLOCK);
    var i, j;
    for (i = 0; i < data.length; i++) {
        encrypt_block(rkw, nr, fb, 0, ks, 0);
        out[i] = data[i] ^ ks[0];
        for (j = 0; j < BLOCK - 1; j++) { fb[j] = fb[j + 1]; }
        fb[BLOCK - 1] = data[i];
    }
    wipe(rk); wipe(fb); wipe(ks);
    return out;
}

/* ---------------- XTS ---------------- */
/*
 * IEEE 1619. Disk encryption, and shaped entirely by that setting's
 * constraints.
 *
 * A disk sector must encrypt to exactly its own size - there is nowhere to
 * put a nonce or a tag - and any sector must be readable without touching the
 * others. So XTS has no authentication at all and takes its "nonce" from the
 * sector number, which is already known.
 *
 * WHAT IT DOES AND DOES NOT PROTECT
 * XTS hides sector contents. It does NOT detect modification: an attacker who
 * can write to the disk can flip ciphertext bits and the sector will decrypt
 * to different plaintext without complaint. It also cannot hide that a sector
 * changed, or that two sectors are identical - the same plaintext in the same
 * sector always gives the same ciphertext. Full-disk encryption accepts all
 * of this because the alternative costs space it does not have.
 *
 * Never use XTS for messages. It is for storage at a fixed address.
 *
 * The key is TWICE the AES key size: one half encrypts, the other generates
 * a per-block tweak. A 64-byte XTS key is AES-256 twice.
 *
 * Sectors that are not a multiple of 16 use ciphertext stealing, which
 * borrows bytes from the second-to-last block rather than padding.
 */

/** Multiply the tweak by the field generator - a left shift with 0x87. */
function xts_shift(t) {
    var carry = 0, i, next;
    for (i = 0; i < BLOCK; i++) {
        next = (t[i] >>> 7) & 1;
        t[i] = ((t[i] << 1) | carry) & 0xff;
        carry = next;
    }
    /* constant time: fold the reduction in under a mask */
    t[0] ^= 0x87 & (-carry);
}

function xts_run(key, sector, data, encrypting) {
    if (key.length !== 32 && key.length !== 64) {
        throw new Error('aes_xts: key must be 32 or 64 bytes - twice an AES key');
    }
    if (sector.length !== BLOCK) {
        throw new Error('aes_xts: sector tweak must be 16 bytes');
    }
    if (data.length < BLOCK) {
        throw new Error('aes_xts: data must be at least 16 bytes');
    }

    var half = key.length / 2;
    var k1 = key.subarray(0, half), k2 = key.subarray(half);
    var rk1 = expand_key(k1), rk2 = expand_key(k2);
    /*
     * ⚠ XTS NEEDS BOTH VIEWS. encrypt_block reads 32-bit words; decrypt_block
     *   still takes the bytes, because its inverse schedule is derived from
     *   them. Passing the wrong one indexes past the end and yields a wrong
     *   block rather than an error.
     */
    var w1 = key_words(rk1), w2 = key_words(rk2);
    var nr = half / 4 + 6;

    /* the tweak is the encrypted sector number, then doubled per block */
    var t = new Uint8Array(BLOCK);
    encrypt_block(w2, nr, sector, 0, t, 0);
    wipe(rk2);

    var out = new Uint8Array(data.length);
    var blk = new Uint8Array(BLOCK);
    var full = Math.floor(data.length / BLOCK);
    var rem = data.length % BLOCK;
    var i, j;

    /* if there is a tail, the last full block is handled with it */
    var whole = rem ? full - 1 : full;

    for (i = 0; i < whole; i++) {
        for (j = 0; j < BLOCK; j++) { blk[j] = data[i * BLOCK + j] ^ t[j]; }
        if (encrypting) { encrypt_block(w1, nr, blk, 0, out, i * BLOCK); }
        else            { decrypt_block(rk1, nr, blk, 0, out, i * BLOCK); }
        for (j = 0; j < BLOCK; j++) { out[i * BLOCK + j] ^= t[j]; }
        xts_shift(t);
    }

    if (rem) {
        /*
         * Ciphertext stealing. The last full block is encrypted with the tweak
         * it would have had, then its tail is swapped with the short block -
         * which is how the output stays exactly as long as the input.
         */
        var t_last = new Uint8Array(t);
        if (!encrypting) { xts_shift(t_last); }

        var p = whole * BLOCK;
        for (j = 0; j < BLOCK; j++) { blk[j] = data[p + j] ^ t_last[j]; }
        var cc = new Uint8Array(BLOCK);
        if (encrypting) { encrypt_block(w1, nr, blk, 0, cc, 0); }
        else            { decrypt_block(rk1, nr, blk, 0, cc, 0); }
        for (j = 0; j < BLOCK; j++) { cc[j] ^= t_last[j]; }

        /* the short block takes the head of that result */
        for (j = 0; j < rem; j++) { out[p + BLOCK + j] = cc[j]; }

        /* and the stolen tail completes the final full block */
        for (j = 0; j < rem; j++) { blk[j] = data[p + BLOCK + j]; }
        for (j = rem; j < BLOCK; j++) { blk[j] = cc[j]; }

        var t2 = new Uint8Array(t);
        if (encrypting) { xts_shift(t2); } else { /* t already correct */ }
        var tt = encrypting ? t2 : t;
        for (j = 0; j < BLOCK; j++) { blk[j] ^= tt[j]; }
        if (encrypting) { encrypt_block(w1, nr, blk, 0, out, p); }
        else            { decrypt_block(rk1, nr, blk, 0, out, p); }
        for (j = 0; j < BLOCK; j++) { out[p + j] ^= tt[j]; }

        wipe(cc); wipe(t_last); wipe(t2);
    }

    wipe(rk1); wipe(t); wipe(blk);
    return out;
}

/**
 * @param  {Uint8Array} key     32 or 64 bytes - twice an AES key
 * @param  {Uint8Array} sector  16 bytes, normally the sector number little-endian
 * @param  {Uint8Array} data    at least 16 bytes
 */
export function aes_xts_encrypt(key, sector, data) {
    return xts_run(key, sector, data, true);
}

export function aes_xts_decrypt(key, sector, data) {
    return xts_run(key, sector, data, false);
}

/* ---------------- OCB3 ---------------- */
/*
 * RFC 7253. The fastest AEAD of the classical designs, and for two decades
 * the one almost nobody could use.
 *
 * OCB needs ONE block-cipher call per block of data and nothing else - no
 * field multiplication like GCM, no second pass like CCM, no CBC-MAC. That
 * makes it roughly as fast as raw CTR while also authenticating. It was
 * patented from 2001, which is why GCM won the standards it should have lost;
 * the patents were released in 2021 and it is now free for any use.
 *
 * How it gets there: each block is masked by an offset before and after
 * encryption, and the offsets are generated by a Gray-code walk over a small
 * precomputed table. Updating the offset for block i costs one XOR against
 * L[ntz(i)], where ntz is the number of trailing zeros in i - so consecutive
 * blocks usually need L[0], occasionally L[1], and so on. Authentication
 * comes free from the running checksum of the plaintext.
 *
 * NONCE REUSE IS FATAL, in the same way as GCM: the offsets repeat, and the
 * xor of two ciphertexts under one nonce reveals the xor of the plaintexts
 * and enough structure to forge. There is no misuse-resistant variant; if
 * nonce uniqueness is not guaranteed, use SIV or GCM-SIV above.
 */

/** Number of trailing zero bits - how far to walk the L table. */
function ntz(n) {
    var c = 0;
    while ((n & 1) === 0) { n >>>= 1; c++; }
    return c;
}

/**
 * Build the L table. L[*] is AES of a zero block, and each entry after it is
 * the previous one doubled in GF(2^128) - the same doubling CMAC uses.
 */
function ocb_l_table(rkw, nr, depth) {
    var l_star = new Uint8Array(BLOCK);
    encrypt_block(rkw, nr, new Uint8Array(BLOCK), 0, l_star, 0);

    var l_dollar = new Uint8Array(l_star); dbl128(l_dollar);

    var l = [];
    var cur = new Uint8Array(l_dollar); dbl128(cur);
    l.push(cur);
    for (var i = 1; i <= depth; i++) {
        var next = new Uint8Array(l[i - 1]); dbl128(next);
        l.push(next);
    }
    return { star: l_star, dollar: l_dollar, l: l };
}

/**
 * The initial offset.
 *
 * The nonce is padded into a block, the low six bits are split off as a bit
 * shift, and the encryption of the rest is stretched to 24 bytes and shifted.
 * The point of that shift is to let a sequence of nonces share one cipher
 * call - consecutive nonces differing only in those six bits reuse the same
 * Ktop. It is an optimisation baked into the format.
 */
function ocb_offset0(rkw, nr, nonce, tag_len) {
    var nb = new Uint8Array(BLOCK);
    for (var i = 0; i < nonce.length; i++) { nb[BLOCK - nonce.length + i] = nonce[i]; }
    nb[0] = ((tag_len * 8) % 128) << 1;
    nb[BLOCK - nonce.length - 1] |= 1;

    var bottom = nb[15] & 0x3f;
    nb[15] &= 0xc0;

    var ktop = new Uint8Array(BLOCK);
    encrypt_block(rkw, nr, nb, 0, ktop, 0);

    /* stretch: Ktop followed by Ktop xor (Ktop shifted one byte) */
    var stretch = new Uint8Array(24);
    stretch.set(ktop, 0);
    for (i = 0; i < 8; i++) { stretch[16 + i] = ktop[i] ^ ktop[i + 1]; }

    /* offset = the 128 bits of stretch starting at bit position `bottom` */
    var off = new Uint8Array(BLOCK);
    var byte_shift = bottom >>> 3, bit_shift = bottom & 7;
    for (i = 0; i < BLOCK; i++) {
        off[i] = ((stretch[byte_shift + i] << bit_shift) |
                  (stretch[byte_shift + i + 1] >>> (8 - bit_shift))) & 0xff;
    }
    /* a bit_shift of zero would shift right by 8, which JS treats as 0 */
    if (bit_shift === 0) {
        for (i = 0; i < BLOCK; i++) { off[i] = stretch[byte_shift + i]; }
    }

    wipe(nb); wipe(ktop); wipe(stretch);
    return off;
}

/** HASH(K, A) - the associated data half, with its own offset walk. */
function ocb_hash(rkw, nr, tab, aad) {
    var sum = new Uint8Array(BLOCK);
    var off = new Uint8Array(BLOCK);
    var blk = new Uint8Array(BLOCK);
    var tmp = new Uint8Array(BLOCK);
    var full = Math.floor(aad.length / BLOCK);
    var i, j;

    for (i = 1; i <= full; i++) {
        var t = ntz(i);
        for (j = 0; j < BLOCK; j++) { off[j] ^= tab.l[t][j]; }
        for (j = 0; j < BLOCK; j++) { blk[j] = aad[(i - 1) * BLOCK + j] ^ off[j]; }
        encrypt_block(rkw, nr, blk, 0, tmp, 0);
        for (j = 0; j < BLOCK; j++) { sum[j] ^= tmp[j]; }
    }

    var rem = aad.length - full * BLOCK;
    if (rem) {
        for (j = 0; j < BLOCK; j++) { off[j] ^= tab.star[j]; }
        for (j = 0; j < BLOCK; j++) { blk[j] = 0; }
        for (j = 0; j < rem; j++) { blk[j] = aad[full * BLOCK + j]; }
        blk[rem] = 0x80;
        for (j = 0; j < BLOCK; j++) { blk[j] ^= off[j]; }
        encrypt_block(rkw, nr, blk, 0, tmp, 0);
        for (j = 0; j < BLOCK; j++) { sum[j] ^= tmp[j]; }
    }

    wipe(off); wipe(blk); wipe(tmp);
    return sum;
}

function ocb_run(key, nonce, data, aad, tag_len, encrypting) {
    if (nonce.length < 1 || nonce.length > 15) {
        throw new Error('aes_ocb: nonce must be 1 to 15 bytes');
    }
    if (tag_len < 1 || tag_len > 16) {
        throw new Error('aes_ocb: tag length must be 1 to 16 bytes');
    }

    var s0_ = setup(key), rk = s0_.rk, rkw = s0_.rkw, nr = s0_.nr;
    var full = Math.floor(data.length / BLOCK);

    /*
     * The table has to cover BOTH walks. The associated data runs its own
     * offset sequence in ocb_hash, so a short message with long AAD still
     * reaches deep entries - sizing this from the plaintext alone was a
     * crash waiting for the first caller with more AAD than data.
     */
    var a_full = Math.floor((aad ? aad.length : 0) / BLOCK);
    var depth = Math.max(1, ntz_depth(Math.max(full, a_full)));
    var tab = ocb_l_table(rkw, nr, depth);

    var off = ocb_offset0(rkw, nr, nonce, tag_len);
    var checksum = new Uint8Array(BLOCK);
    var out = new Uint8Array(data.length);
    var blk = new Uint8Array(BLOCK);
    var tmp = new Uint8Array(BLOCK);
    var i, j;

    for (i = 1; i <= full; i++) {
        var t = ntz(i);
        for (j = 0; j < BLOCK; j++) { off[j] ^= tab.l[t][j]; }
        var p = (i - 1) * BLOCK;
        for (j = 0; j < BLOCK; j++) { blk[j] = data[p + j] ^ off[j]; }
        if (encrypting) {
            encrypt_block(rkw, nr, blk, 0, tmp, 0);
            for (j = 0; j < BLOCK; j++) { out[p + j] = tmp[j] ^ off[j]; }
            /* the checksum is always over the PLAINTEXT */
            for (j = 0; j < BLOCK; j++) { checksum[j] ^= data[p + j]; }
        } else {
            decrypt_block(rk, nr, blk, 0, tmp, 0);
            for (j = 0; j < BLOCK; j++) { out[p + j] = tmp[j] ^ off[j]; }
            for (j = 0; j < BLOCK; j++) { checksum[j] ^= out[p + j]; }
        }
    }

    var rem = data.length - full * BLOCK;
    if (rem) {
        for (j = 0; j < BLOCK; j++) { off[j] ^= tab.star[j]; }
        /* the short block is handled as a stream: encrypt the offset, xor */
        encrypt_block(rkw, nr, off, 0, tmp, 0);
        var q = full * BLOCK;
        for (j = 0; j < rem; j++) { out[q + j] = data[q + j] ^ tmp[j]; }

        var src = encrypting ? data : out;
        for (j = 0; j < BLOCK; j++) { blk[j] = 0; }
        for (j = 0; j < rem; j++) { blk[j] = src[q + j]; }
        blk[rem] = 0x80;
        for (j = 0; j < BLOCK; j++) { checksum[j] ^= blk[j]; }
    }

    /* tag = E(checksum xor offset xor L_$) xor HASH(K, A) */
    for (j = 0; j < BLOCK; j++) {
        blk[j] = checksum[j] ^ off[j] ^ tab.dollar[j];
    }
    encrypt_block(rkw, nr, blk, 0, tmp, 0);
    var ah = ocb_hash(rkw, nr, tab, aad || new Uint8Array(0));
    for (j = 0; j < BLOCK; j++) { tmp[j] ^= ah[j]; }

    wipe(rk); wipe(off); wipe(checksum); wipe(blk); wipe(ah);
    return { data: out, tag: tmp.subarray(0, tag_len) };
}

/** How many L entries a message of `blocks` blocks can reach. */
function ntz_depth(blocks) {
    var d = 0, n = blocks;
    while (n > 1) { n >>>= 1; d++; }
    return d + 1;
}

/**
 * @param  {Uint8Array} key    16, 24 or 32 bytes
 * @param  {Uint8Array} nonce  1 to 15 bytes. 12 is standard.
 * @param  {Uint8Array} plaintext
 * @param  {Uint8Array} [aad]
 * @param  {number}     [tag_len=16]
 * @return {Uint8Array} ciphertext followed by the tag
 */
export function aes_ocb_encrypt(key, nonce, plaintext, aad, tag_len) {
    var t = (tag_len === undefined) ? 16 : tag_len;
    var r = ocb_run(key, nonce, plaintext, aad, t, true);
    var out = new Uint8Array(r.data.length + t);
    out.set(r.data, 0);
    out.set(r.tag, r.data.length);
    return out;
}

/** @return {Uint8Array|null} */
export function aes_ocb_decrypt(key, nonce, sealed, aad, tag_len) {
    var t = (tag_len === undefined) ? 16 : tag_len;
    if (sealed.length < t) { return null; }

    var ct = sealed.subarray(0, sealed.length - t);
    var tag = sealed.subarray(sealed.length - t);

    var r = ocb_run(key, nonce, ct, aad, t, false);
    if (equal(r.tag, tag) !== 1) { wipe(r.data); return null; }
    return r.data;
}


/* ---------------- AES-GCM ---------------- */
/**
 * @param {Uint8Array} iv  12 bytes, and it MUST NOT REPEAT under one key.
 *
 * Nonce reuse in GCM is catastrophic rather than merely weakening: it reveals
 * the xor of the two plaintexts and leaks the authentication subkey, after
 * which forgery is trivial. Use aes_gcm_siv_encrypt where uniqueness cannot
 * be guaranteed.
 */
export var aes_gcm_encrypt = M.gcm_encrypt;

/** @return {Uint8Array|null} null when authentication fails */
export var aes_gcm_decrypt = M.gcm_decrypt;

/**
 * The same modes under one key for many messages - the key schedule (and
 * GCM's hash key and table) computed once. Each message takes its own
 * nonce, which MUST NOT repeat under the key.
 *
 *     var ctx = aes_gcm_create(key);
 *     ctx.encrypt(nonce, plaintext, aad)  ->  ciphertext || tag
 *     ctx.decrypt(nonce, sealed, aad)     ->  plaintext, or null
 *
 * aes_ccm_create and aes_eax_create take tag_len as a fourth argument, as
 * their one-shot forms do. aes_ctr_create(key, iv) is CTR fed in pieces:
 * update(data) returns data xor the next bytes of keystream, in either
 * direction.
 */
export var aes_gcm_create = M.gcm_create;
export var aes_ccm_create = M.ccm_create;
export var aes_eax_create = M.eax_create;
export var aes_ctr_create = M.ctr_create;


/* ---------------- AES-CCM ---------------- */
/**
 * @param {Uint8Array} nonce      7 to 13 bytes
 * @param {number}     [tag_len]  4 to 16, even. 16 unless a profile says less.
 *
 * The nonce length caps the message length: they share fifteen bytes between
 * them. A 13-byte nonce leaves two bytes of length and so a 64 KiB maximum.
 */
export var aes_ccm_encrypt = M.ccm_encrypt;

/** @return {Uint8Array|null} null when authentication fails */
export var aes_ccm_decrypt = M.ccm_decrypt;

/**
 * AES-GMAC. The nonce must be fresh for every call - see commons/gcm.js.
 *
 * @return {Uint8Array} the 16-byte tag
 */
export var aes_gmac = M.gmac;

/** @return {boolean} */
export var aes_gmac_verify = M.gmac_verify;

/* ==================== EAX ==================== */

/**
 * AES-EAX. An AEAD built from CTR and CMAC alone - see commons/eax.js.
 *
 * The nonce may be ANY length, including empty: EAX runs it through CMAC
 * rather than special-casing one size the way GCM does with 96 bits.
 *
 * @return {Uint8Array} ciphertext followed by the tag
 */
export var aes_eax_encrypt = M.eax_encrypt;

/** @return {Uint8Array|null} null when authentication fails */
export var aes_eax_decrypt = M.eax_decrypt;
