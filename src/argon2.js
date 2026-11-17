/**
 * Argon2  -  RFC 9106
 *
 * Winner of the Password Hashing Competition in 2015 and the current default
 * recommendation for turning a password into a key. scrypt got there first;
 * Argon2 is the refinement.
 *
 * WHAT IT ADDS OVER scrypt
 * scrypt's memory access pattern depends on the password, which makes it
 * leak through cache timing to anyone running code on the same machine.
 * Argon2 splits the difference across three variants:
 *
 *     Argon2d   data-dependent addressing. Fastest, best against GPUs,
 *               but the same cache-timing exposure as scrypt.
 *     Argon2i   data-independent addressing. Immune to that side channel,
 *               weaker against time-memory tradeoffs.
 *     Argon2id  Argon2i for the first half of the first pass, Argon2d for
 *               everything after. Takes both properties. Use this one
 *               unless a spec says otherwise - RFC 9106 says so too.
 *
 * PARAMETERS, AND WHICH ONE ACTUALLY MATTERS
 *     m   memory in KiB. This is the security parameter.
 *     t   passes over that memory. Raising t is a poor substitute for m.
 *     p   lanes. Parallelism, not extra cost - an attacker gets it free.
 *
 * RFC 9106 gives two settings: m=2097152 (2 GiB), t=1, p=4 where memory is
 * available, or m=65536 (64 MiB), t=3, p=4 where it is constrained. Browser
 * code lives in the second world and often lower still.
 *
 * THE SAME BROWSER CAUTION AS scrypt
 * The memory is allocated up front and the work is synchronous. 64 MiB is
 * already a visible pause; anything larger belongs in a worker. Note also
 * that p > 1 buys nothing here - the lanes are computed one after another,
 * since this is single-threaded. It still has to be honoured because it
 * changes the output.
 *
 * Built entirely on blake2b. The compression function G is a BLAKE2b round
 * with one change - a fused 32x32 multiply that makes each step depend on
 * a full multiplication rather than only additions and rotations. That is
 * deliberate: it raises the cost of building dedicated hardware.
 */

import { finish_task } from './commons/task.js';
import { blake2b } from './blake2.js';
import { concat, le32, rd_le32, wr_le32s } from './commons/bytes.js';

var BLOCK_SIZE  = 1024;          /* bytes */
var BLOCK_WORDS = 128;           /* 64-bit words */
var BLOCK_INTS  = 256;           /* int32 slots, as [lo, hi] pairs */
var SYNC_POINTS = 4;

export var ARGON2D  = 0;
export var ARGON2I  = 1;
export var ARGON2ID = 2;

var VERSION = 0x13;

/* ---------------- 64-bit arithmetic ---------------- */
/* Same reason as sha512 and xxhash64: BigInt is an order of magnitude
   slower, and this is the innermost loop of a deliberately expensive
   function - the one place where the cost has to land on the attacker,
   not on us.

   ⭐ THERE ARE NO 64-BIT HELPERS HERE ANY MORE. add64 and mul2_lo32 used to
     sit in this spot, returning through two module-level variables, with a
     long note explaining why add64 must never be merged with the one in
     checksum.js (opposite argument order). Then GB below inlined both for a
     1.8x speedup, and the helpers stayed behind with no caller - so the note
     was defending a twin that no longer ran. Both were removed; the
     arithmetic now exists only inside GB, and checksum.js's add64 is the
     library's one copy of that helper. */

/* ---------------- the Argon2 round ---------------- */

var v = new Int32Array(32);   /* 16 words as [lo, hi] pairs */

/**
 * GB: the BLAKE2b quarter-round with a fused multiply.
 *
 *     a = a + b + 2 * lo32(a) * lo32(b)
 *
 * The multiply is what separates this from BLAKE2b. It forces any hardware
 * implementation to include a 32x32 multiplier per lane, which is far more
 * expensive in silicon than the adders and shifters an ARX design needs.
 */
/*
 * ⭐ GB WORKS IN PLACE, on whatever array the caller names.
 *
 *   It used to read and write a module-level scratch of 32 words, which
 *   meant every row of a block was copied into that scratch and back out
 *   again: 64 element copies per P(), sixteen P() calls per block, and about
 *   a million blocks for a 64 MiB run. That is on the order of a billion
 *   copies for one argon2id call.
 *
 * ⚠ `v` AND `off` REPLACE THE SCRATCH, so the caller now owns the aliasing.
 *   Passing two overlapping regions would corrupt both, which the previous
 *   copy-in-copy-out made impossible - the safety came at the cost above.
 */
function GB(v, off, a, b, c, d) {
    var a2 = off + a * 2, b2 = off + b * 2, c2 = off + c * 2, d2 = off + d * 2;

    /*
     * ⭐ EVERYTHING IN LOCALS, INCLUDING THE 64-BIT ADD AND MULTIPLY.
     *
     *   add64 and mul2_lo32 returned through two module-level variables,
     *   because JavaScript has no multiple return and allocating a pair per
     *   call would be worse. GB calls them six times, P calls GB eight
     *   times, and a 64 MiB argon2 run reaches this about 130 million times -
     *   so every global write is paid 800 million times over.
     *
     *   Measured on the pattern alone: 38 ns through the globals against 26
     *   inlined.
     *
     * ⛔ AND THE FOUR MULTIPLY-ADD BLOCKS BELOW ARE DELIBERATE DUPLICATION.
     *   jscpd flags them, and factoring them back into a helper is exactly
     *   what was just removed - the helper would have to return two words,
     *   which in JavaScript means either a module-level pair (the 38 ns
     *   path) or an allocation per call (worse). Overall duplication went
     *   from 0.70% to 0.74% for a 1.8x speedup on the slowest KDF here.
     *
     *   ⚠ THE RISK IS REAL: four copies of the same arithmetic is four
     *     places to fix a bug in. What makes it acceptable is that RFC 9106
     *     publishes vectors for all three argon2 types, every one of them
     *     runs through this function, and a divergence between the copies
     *     fails them.
     *
     * ⚠ THE MULTIPLY IS 2 * lo(x) * lo(y) AS A FULL 64-BIT PRODUCT. The two
     *   32-bit halves are multiplied through their 16-bit pieces because
     *   JavaScript's * on two 32-bit values loses the top bits - and the
     *   result feeds an addition where those bits matter. Using Math.imul
     *   here would give a stable, well-distributed, wrong digest.
     */
    var al = v[a2], ah = v[a2 + 1];
    var bl = v[b2], bh = v[b2 + 1];
    var cl = v[c2], ch = v[c2 + 1];
    var dl = v[d2], dh = v[d2 + 1];
    var lo, hi, m0, m1, m2, m3, mid, tl, th;

    /* --- a = a + b + 2*lo(a)*lo(b) --- */
    lo = (al >>> 0) + (bl >>> 0);
    hi = (ah + bh + ((lo / 4294967296) | 0)) | 0;
    tl = lo | 0;
    m0 = (al & 0xffff) * (bl & 0xffff);
    m1 = (al >>> 16) * (bl & 0xffff);
    m2 = (al & 0xffff) * (bl >>> 16);
    m3 = (al >>> 16) * (bl >>> 16);
    mid = (m1 & 0xffff) + (m2 & 0xffff) + (m0 >>> 16);
    var pl = (((mid & 0xffff) << 16) | (m0 & 0xffff)) >>> 0;
    var ph = (m3 + (m1 >>> 16) + (m2 >>> 16) + (mid >>> 16)) >>> 0;
    /* times two */
    ph = ((ph << 1) | (pl >>> 31)) >>> 0;
    pl = (pl << 1) >>> 0;
    lo = (tl >>> 0) + pl;
    al = lo | 0;
    ah = (hi + (ph | 0) + ((lo / 4294967296) | 0)) | 0;

    /* --- d = rotr64(d ^ a, 32): a swap --- */
    tl = dl ^ al; th = dh ^ ah;
    dl = th; dh = tl;

    /* --- c = c + d + 2*lo(c)*lo(d) --- */
    lo = (cl >>> 0) + (dl >>> 0);
    hi = (ch + dh + ((lo / 4294967296) | 0)) | 0;
    tl = lo | 0;
    m0 = (cl & 0xffff) * (dl & 0xffff);
    m1 = (cl >>> 16) * (dl & 0xffff);
    m2 = (cl & 0xffff) * (dl >>> 16);
    m3 = (cl >>> 16) * (dl >>> 16);
    mid = (m1 & 0xffff) + (m2 & 0xffff) + (m0 >>> 16);
    pl = (((mid & 0xffff) << 16) | (m0 & 0xffff)) >>> 0;
    ph = (m3 + (m1 >>> 16) + (m2 >>> 16) + (mid >>> 16)) >>> 0;
    ph = ((ph << 1) | (pl >>> 31)) >>> 0;
    pl = (pl << 1) >>> 0;
    lo = (tl >>> 0) + pl;
    cl = lo | 0;
    ch = (hi + (ph | 0) + ((lo / 4294967296) | 0)) | 0;

    /* --- b = rotr64(b ^ c, 24) --- */
    tl = bl ^ cl; th = bh ^ ch;
    bl = ((tl >>> 24) | (th << 8)) | 0;
    bh = ((th >>> 24) | (tl << 8)) | 0;

    /* --- a = a + b + 2*lo(a)*lo(b) --- */
    lo = (al >>> 0) + (bl >>> 0);
    hi = (ah + bh + ((lo / 4294967296) | 0)) | 0;
    tl = lo | 0;
    m0 = (al & 0xffff) * (bl & 0xffff);
    m1 = (al >>> 16) * (bl & 0xffff);
    m2 = (al & 0xffff) * (bl >>> 16);
    m3 = (al >>> 16) * (bl >>> 16);
    mid = (m1 & 0xffff) + (m2 & 0xffff) + (m0 >>> 16);
    pl = (((mid & 0xffff) << 16) | (m0 & 0xffff)) >>> 0;
    ph = (m3 + (m1 >>> 16) + (m2 >>> 16) + (mid >>> 16)) >>> 0;
    ph = ((ph << 1) | (pl >>> 31)) >>> 0;
    pl = (pl << 1) >>> 0;
    lo = (tl >>> 0) + pl;
    al = lo | 0;
    ah = (hi + (ph | 0) + ((lo / 4294967296) | 0)) | 0;

    /* --- d = rotr64(d ^ a, 16) --- */
    tl = dl ^ al; th = dh ^ ah;
    dl = ((tl >>> 16) | (th << 16)) | 0;
    dh = ((th >>> 16) | (tl << 16)) | 0;

    /* --- c = c + d + 2*lo(c)*lo(d) --- */
    lo = (cl >>> 0) + (dl >>> 0);
    hi = (ch + dh + ((lo / 4294967296) | 0)) | 0;
    tl = lo | 0;
    m0 = (cl & 0xffff) * (dl & 0xffff);
    m1 = (cl >>> 16) * (dl & 0xffff);
    m2 = (cl & 0xffff) * (dl >>> 16);
    m3 = (cl >>> 16) * (dl >>> 16);
    mid = (m1 & 0xffff) + (m2 & 0xffff) + (m0 >>> 16);
    pl = (((mid & 0xffff) << 16) | (m0 & 0xffff)) >>> 0;
    ph = (m3 + (m1 >>> 16) + (m2 >>> 16) + (mid >>> 16)) >>> 0;
    ph = ((ph << 1) | (pl >>> 31)) >>> 0;
    pl = (pl << 1) >>> 0;
    lo = (tl >>> 0) + pl;
    cl = lo | 0;
    ch = (hi + (ph | 0) + ((lo / 4294967296) | 0)) | 0;

    /* --- b = rotr64(b ^ c, 63) --- */
    tl = bl ^ cl; th = bh ^ ch;
    bl = ((th >>> 31) | (tl << 1)) | 0;
    bh = ((tl >>> 31) | (th << 1)) | 0;

    v[a2] = al; v[a2 + 1] = ah;
    v[b2] = bl; v[b2 + 1] = bh;
    v[c2] = cl; v[c2 + 1] = ch;
    v[d2] = dl; v[d2 + 1] = dh;
}

/** P: eight GB calls over 16 words - four columns, four diagonals. */
function P(v, off) {
    GB(v, off, 0, 4,  8, 12); GB(v, off, 1, 5,  9, 13);
    GB(v, off, 2, 6, 10, 14); GB(v, off, 3, 7, 11, 15);
    GB(v, off, 0, 5, 10, 15); GB(v, off, 1, 6, 11, 12);
    GB(v, off, 2, 7,  8, 13); GB(v, off, 3, 4,  9, 14);
}

/**
 * G(X, Y): the compression function over two 1024-byte blocks.
 *
 *   R = X xor Y
 *   Q = P applied to each of the 8 rows of R
 *   Z = P applied to each of the 8 columns of Q
 *   result = Z xor R
 *
 * The final xor with R is what makes G non-invertible, which is what stops
 * an attacker from walking the memory array backwards.
 */
function fill_block(mem, x_off, y_off, out_off, with_xor, R, Z) {
    var i, j, k;

    for (i = 0; i < BLOCK_INTS; i++) { R[i] = mem[x_off + i] ^ mem[y_off + i]; }
    for (i = 0; i < BLOCK_INTS; i++) { Z[i] = R[i]; }

    /* rows: 8 groups of 16 consecutive words */
    /* ⭐ rows are contiguous, so P runs on Z directly - no copy */
    for (i = 0; i < 8; i++) { P(Z, i * 32); }

    /*
     * ⚠ THE COLUMN PASS STILL GATHERS. Its sixteen words are strided across
     *   the block rather than contiguous, so P cannot run in place here and
     *   the copy is unavoidable - unlike the row pass above, where the words
     *   already sit together and the copy was pure waste.
     */
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            for (k = 0; k < 4; k++) {
                v[j * 4 + k] = Z[j * 32 + i * 4 + k];
            }
        }
        P(v, 0);
        for (j = 0; j < 8; j++) {
            for (k = 0; k < 4; k++) {
                Z[j * 32 + i * 4 + k] = v[j * 4 + k];
            }
        }
    }

    if (with_xor) {
        for (i = 0; i < BLOCK_INTS; i++) { mem[out_off + i] ^= Z[i] ^ R[i]; }
    } else {
        for (i = 0; i < BLOCK_INTS; i++) { mem[out_off + i] = Z[i] ^ R[i]; }
    }
}

/* ---------------- variable-length hash H' ---------------- */


/**
 * H': BLAKE2b stretched past its 64-byte ceiling.
 *
 * Up to 64 bytes it is just BLAKE2b of LE32(len) || X. Beyond that it chains
 * 64-byte hashes and takes the first 32 bytes of each, so consecutive output
 * chunks overlap in their inputs but not in their outputs.
 */
function hash_prime(x, out_len) {
    var prefix = le32(out_len);
    if (out_len <= 64) {
        return blake2b(concat([prefix, x]), out_len);
    }

    var r = Math.ceil(out_len / 32) - 2;
    var out = new Uint8Array(out_len);
    var vblock = blake2b(concat([prefix, x]), 64);
    var pos = 0, i, j;

    for (j = 0; j < 32; j++) { out[pos++] = vblock[j]; }
    for (i = 1; i < r; i++) {
        vblock = blake2b(vblock, 64);
        for (j = 0; j < 32; j++) { out[pos++] = vblock[j]; }
    }
    var last = blake2b(vblock, out_len - 32 * r);
    for (j = 0; j < last.length; j++) { out[pos++] = last[j]; }
    return out;
}

/* ---------------- the driver ---------------- */

/**
 * @param {object} opts
 *   opts.password    Uint8Array
 *   opts.salt        Uint8Array, at least 8 bytes, random and per-user
 *   opts.m           memory in KiB
 *   opts.t           passes
 *   opts.p           lanes
 *   opts.length      output bytes
 *   opts.type        ARGON2D | ARGON2I | ARGON2ID
 *   opts.secret      optional keyed pepper
 *   opts.ad          optional associated data
 * @return {Uint8Array}
 */
function argon2(opts) {
    return finish_task(argon2_task(opts));
}

/*
 * Argon2 as a task (commons/task.js): each step() fills at most STEP_BLOCKS
 * blocks of one segment and returns true once the tag is ready. argon2()
 * above runs the steps back to back; the callback form in api/argon2.js runs
 * them a few milliseconds at a time, yielding to the event loop between.
 *
 * ⭐ THE LOOPS ARE THE SAME ONES, cut between blocks. pass, slice, lane and
 *   idx are what survives between steps; the address block (addr) already
 *   carried its counter from one block to the next, so a segment resumed
 *   mid-way generates exactly the addresses it would have without the pause.
 */
var STEP_BLOCKS = 64;

function argon2_task(opts) {
    var P_pw   = opts.password;
    var S      = opts.salt;
    var m      = opts.m;
    var t      = opts.t;
    var p      = opts.p;
    var out_len = opts.length;
    var type   = opts.type;
    var K      = opts.secret || new Uint8Array(0);
    var X      = opts.ad || new Uint8Array(0);

    if (!(P_pw instanceof Uint8Array) || !(S instanceof Uint8Array)) {
        throw new TypeError('argon2: password and salt must be Uint8Arrays (the api/ forms take a string as UTF-8)');
    }
    if (p < 1) { throw new Error('argon2: p must be at least 1'); }
    if (t < 1) { throw new Error('argon2: t must be at least 1'); }
    if (m < 8 * p) { throw new Error('argon2: m must be at least 8 * p'); }
    if (out_len < 4) { throw new Error('argon2: length must be at least 4'); }
    if (S.length < 8) { throw new Error('argon2: salt must be at least 8 bytes'); }

    /* Round the memory down so every lane holds a whole number of segments */
    var blocks = Math.floor(m / (SYNC_POINTS * p)) * (SYNC_POINTS * p);
    var lane_len = blocks / p;
    var seg_len  = lane_len / SYNC_POINTS;

    /* H0 commits to every parameter, so no two configurations can collide */
    var H0 = blake2b(concat([
        le32(p), le32(out_len), le32(m), le32(t), le32(VERSION), le32(type),
        le32(P_pw.length), P_pw,
        le32(S.length), S,
        le32(K.length), K,
        le32(X.length), X
    ]), 64);

    var mem = new Int32Array(blocks * BLOCK_INTS);
    var R = new Int32Array(BLOCK_INTS);
    var Z = new Int32Array(BLOCK_INTS);
    var i, j, lane, slice, idx;

    /* First two columns of every lane come straight from H0 */
    for (lane = 0; lane < p; lane++) {
        for (j = 0; j < 2; j++) {
            var b = hash_prime(concat([H0, le32(j), le32(lane)]), BLOCK_SIZE);
            var base = (lane * lane_len + j) * BLOCK_INTS;
            for (i = 0; i < BLOCK_INTS; i++) { mem[base + i] = rd_le32(b, i * 4); }
        }
    }

    /*
     * Argon2i address generation.
     *
     * The addresses come from G(zero, G(zero, counter_block)) - two nested
     * applications against an all-zero block, not the counter block against
     * itself. One buffer holds all three slots so fill_block can read and
     * write within it.
     */
    var ZERO_OFF = 0;
    var IN_OFF   = BLOCK_INTS;
    var OUT_OFF  = BLOCK_INTS * 2;
    var addr = new Int32Array(BLOCK_INTS * 3);

    function reset_addr_input(pass, lane, slice) {
        for (i = 0; i < BLOCK_INTS; i++) { addr[IN_OFF + i] = 0; }
        /* one 64-bit word each, so word k lives at slot 2k */
        addr[IN_OFF]      = pass;
        addr[IN_OFF + 2]  = lane;
        addr[IN_OFF + 4]  = slice;
        addr[IN_OFF + 6]  = blocks;
        addr[IN_OFF + 8]  = t;
        addr[IN_OFF + 10] = type;
        addr[IN_OFF + 12] = 0;   /* counter, bumped by next_addresses */
    }

    function next_addresses() {
        /* the counter lives in the input block and survives between calls */
        addr[IN_OFF + 12] = (addr[IN_OFF + 12] + 1) | 0;
        fill_block(addr, ZERO_OFF, IN_OFF,  OUT_OFF, false, R, Z);
        fill_block(addr, ZERO_OFF, OUT_OFF, OUT_OFF, false, R, Z);
    }

    /*
     * The position: pass, slice and lane name the segment, idx the next
     * block in it. `independent` and `start` are per segment, set when it
     * begins.
     */
    var pass = 0, independent = false, start = 0;
    slice = 0; lane = 0; idx = -1;   /* -1: the segment has not begun */

    function begin_segment() {
        /*
         * Argon2id uses data-independent addressing only for the
         * first half of the first pass - the window where an
         * attacker could otherwise learn something from cache
         * behaviour before any secret-dependent data exists.
         */
        independent = (type === ARGON2I) ||
            (type === ARGON2ID && pass === 0 && slice < SYNC_POINTS / 2);

        start = (pass === 0 && slice === 0) ? 2 : 0;

        if (independent) {
            reset_addr_input(pass, lane, slice);
            /*
             * The first segment skips two columns that are already
             * filled, but the address index still tracks the raw loop
             * counter - so the block has to be generated up front and
             * its first two entries simply go unused.
             */
            if (start === 2) { next_addresses(); }
        }

        idx = start;
    }

    /* Fill blocks idx .. end-1 of the current segment. */
    function fill_range(end) {
        for (; idx < end; idx++) {
            var col = slice * seg_len + idx;
            var cur = lane * lane_len + col;
            var prev = (col === 0)
                ? lane * lane_len + lane_len - 1
                : cur - 1;

            var J1, J2;
            if (independent) {
                if (idx % BLOCK_WORDS === 0) { next_addresses(); }
                var ap = idx % BLOCK_WORDS;
                J1 = addr[OUT_OFF + ap * 2] >>> 0;
                J2 = addr[OUT_OFF + ap * 2 + 1] >>> 0;
            } else {
                J1 = mem[prev * BLOCK_INTS] >>> 0;
                J2 = mem[prev * BLOCK_INTS + 1] >>> 0;
            }

            /* Which lane to read from */
            var ref_lane = (pass === 0 && slice === 0) ? lane : (J2 % p);

            /*
             * Reference area: every finished block in that lane, plus
             * the part of the current segment already written when
             * reading from our own lane.
             */
            var ref_area;
            if (pass === 0) {
                if (ref_lane === lane) { ref_area = col - 1; }
                else { ref_area = slice * seg_len - ((idx === 0) ? 1 : 0); }
            } else {
                if (ref_lane === lane) { ref_area = lane_len - seg_len + idx - 1; }
                else { ref_area = lane_len - seg_len - ((idx === 0) ? 1 : 0); }
            }

            /*
             * Non-uniform mapping, on purpose: recent blocks are far
             * more likely to be picked. That is what makes storing
             * only part of the array expensive.
             */
            var rel = (J1 * J1) / 0x100000000;
            rel = ref_area - 1 - Math.floor((ref_area * rel) / 0x100000000);

            var start_pos = (pass !== 0 && slice !== SYNC_POINTS - 1)
                ? (slice + 1) * seg_len : 0;
            var ref_col = (start_pos + rel) % lane_len;
            var ref = ref_lane * lane_len + ref_col;

            fill_block(mem, prev * BLOCK_INTS, ref * BLOCK_INTS,
                       cur * BLOCK_INTS, pass !== 0, R, Z);
        }
    }

    /* Move to the next segment: lanes within a slice, slices within a pass. */
    function next_segment() {
        idx = -1;
        if (++lane < p) { return; }
        lane = 0;
        if (++slice < SYNC_POINTS) { return; }
        slice = 0;
        pass++;
    }

    function finish() {
        /* The final block of every lane, xored together, then stretched to length */
        var final_block = new Int32Array(BLOCK_INTS);
        for (lane = 0; lane < p; lane++) {
            var last = (lane * lane_len + lane_len - 1) * BLOCK_INTS;
            for (i = 0; i < BLOCK_INTS; i++) { final_block[i] ^= mem[last + i]; }
        }
        var fb = new Uint8Array(BLOCK_SIZE);
        wr_le32s(fb, 0, final_block);
        var out = hash_prime(fb, out_len);

        /* The memory is derived from the password; leaving it to the GC is careless */
        for (i = 0; i < mem.length; i++) { mem[i] = 0; }
        for (i = 0; i < fb.length; i++) { fb[i] = 0; }

        return out;
    }

    var out = null;
    return {
        step: function () {
            if (out) { return true; }
            if (pass < t) {
                if (idx < 0) { begin_segment(); }
                fill_range(Math.min(idx + STEP_BLOCKS, seg_len));
                if (idx >= seg_len) { next_segment(); }
                if (pass < t) { return false; }
            }
            out = finish();
            return true;
        },
        result: function () { return out; }
    };
}

/* the caller's options with the variant set - a copy, never their object */
function typed(opts, type) {
    var o = {};
    for (var k in opts) { o[k] = opts[k]; }
    o.type = type;
    return o;
}

/** Data-dependent. Strongest against GPUs, leaks through cache timing. */
export function argon2d(opts)  { return argon2(typed(opts, ARGON2D)); }

/** Data-independent. Side-channel free, weaker against tradeoff attacks. */
export function argon2i(opts)  { return argon2(typed(opts, ARGON2I)); }

/** Both. The one to use unless something else is mandated. */
export function argon2id(opts) { return argon2(typed(opts, ARGON2ID)); }

/* The same three as tasks, for the callback forms (commons/task.js). */
export function argon2d_task(opts)  { return argon2_task(typed(opts, ARGON2D)); }
export function argon2i_task(opts)  { return argon2_task(typed(opts, ARGON2I)); }
export function argon2id_task(opts) { return argon2_task(typed(opts, ARGON2ID)); }
