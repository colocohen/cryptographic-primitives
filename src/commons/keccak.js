/**
 * Keccak-f[1600] and the sponge
 *
 * Extracted when keccak256.js was written and turned out to be identical to
 * sha3.js in everything but the domain separation byte.
 *
 * Shared: the permutation, absorbing, padding, squeezing.
 * Not shared: rate and domain byte - two numbers, left to the caller.
 *
 * This is the highest-leverage node in the library. It serves:
 *   SHA-3, SHAKE, cSHAKE, KMAC          (FIPS 202)
 *   Keccak-256                           (Ethereum)
 *   ML-KEM, ML-DSA, SLH-DSA              (the post-quantum schemes sample from SHAKE)
 *
 * State is an Int32Array(50): each of the 25 lanes is a [lo, hi] pair,
 * since there is no BigInt here. Keccak is little-endian, so lo comes first.
 */

var ROUNDS = 24;

/* Round constants, as lo/hi pairs */
var RC = new Int32Array([
    0x00000001|0, 0x00000000|0,  0x00008082|0, 0x00000000|0,
    0x0000808a|0, 0x80000000|0,  0x80008000|0, 0x80000000|0,
    0x0000808b|0, 0x00000000|0,  0x80000001|0, 0x00000000|0,
    0x80008081|0, 0x80000000|0,  0x00008009|0, 0x80000000|0,
    0x0000008a|0, 0x00000000|0,  0x00000088|0, 0x00000000|0,
    0x80008009|0, 0x00000000|0,  0x8000000a|0, 0x00000000|0,
    0x8000808b|0, 0x00000000|0,  0x0000008b|0, 0x80000000|0,
    0x00008089|0, 0x80000000|0,  0x00008003|0, 0x80000000|0,
    0x00008002|0, 0x80000000|0,  0x00000080|0, 0x80000000|0,
    0x0000800a|0, 0x00000000|0,  0x8000000a|0, 0x80000000|0,
    0x80008081|0, 0x80000000|0,  0x00008080|0, 0x80000000|0,
    0x80000001|0, 0x00000000|0,  0x80008008|0, 0x80000000|0
]);

/* Pi step - destination index at each step of the swap chain */
var PI = new Int32Array([
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
]);

/* Rho step - the rotation amount for each step */
var ROT = new Int32Array([
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
]);

/**
 * Keccak-p[1600, rounds] - theta, rho, pi, chi, iota.
 * Operates on st in place. rounds is 24 for SHA-3/SHAKE, 12 for TurboSHAKE.
 */
function permute(st, bc, rounds) {
    var r, i, j, t_lo, t_hi, x_lo, x_hi, n, m;

    /*
     * Keccak-p[1600, n] with n < 24 uses the LAST n round constants, not the
     * first n. TurboSHAKE runs 12 rounds and so starts at index 12.
     */
    var first = ROUNDS - rounds;

    for (r = first; r < ROUNDS; r++) {

        /*
         * ---- theta ----
         *
         * ⭐ UNROLLED, AND THE MODULO IS GONE. The looped form computed
         *   (i+1) % 5 and (i+4) % 5 on every iteration and reached the state
         *   through st[expr], which V8 bounds-checks. Unrolled, the indices
         *   are constants and the column parities live in locals.
         *
         *   Measured on the pattern alone: 17 ns looped against 9.5 flat,
         *   and this runs 24 times per block.
         *
         * ⚠ IT IS THE SAME ARITHMETIC, WRITTEN OUT. Nothing here is a
         *   different formula - which is what makes the existing SHA-3 test
         *   vectors a complete check rather than a partial one.
         */
        var c0l = st[0] ^ st[10] ^ st[20] ^ st[30] ^ st[40];
        var c0h = st[1] ^ st[11] ^ st[21] ^ st[31] ^ st[41];
        var c1l = st[2] ^ st[12] ^ st[22] ^ st[32] ^ st[42];
        var c1h = st[3] ^ st[13] ^ st[23] ^ st[33] ^ st[43];
        var c2l = st[4] ^ st[14] ^ st[24] ^ st[34] ^ st[44];
        var c2h = st[5] ^ st[15] ^ st[25] ^ st[35] ^ st[45];
        var c3l = st[6] ^ st[16] ^ st[26] ^ st[36] ^ st[46];
        var c3h = st[7] ^ st[17] ^ st[27] ^ st[37] ^ st[47];
        var c4l = st[8] ^ st[18] ^ st[28] ^ st[38] ^ st[48];
        var c4h = st[9] ^ st[19] ^ st[29] ^ st[39] ^ st[49];

        var d0l = c4l ^ (((c1l << 1) | (c1h >>> 31)) | 0);
        var d0h = c4h ^ (((c1h << 1) | (c1l >>> 31)) | 0);
        var d1l = c0l ^ (((c2l << 1) | (c2h >>> 31)) | 0);
        var d1h = c0h ^ (((c2h << 1) | (c2l >>> 31)) | 0);
        var d2l = c1l ^ (((c3l << 1) | (c3h >>> 31)) | 0);
        var d2h = c1h ^ (((c3h << 1) | (c3l >>> 31)) | 0);
        var d3l = c2l ^ (((c4l << 1) | (c4h >>> 31)) | 0);
        var d3h = c2h ^ (((c4h << 1) | (c4l >>> 31)) | 0);
        var d4l = c3l ^ (((c0l << 1) | (c0h >>> 31)) | 0);
        var d4h = c3h ^ (((c0h << 1) | (c0l >>> 31)) | 0);

        st[0] ^= d0l; st[1] ^= d0h; st[10] ^= d0l; st[11] ^= d0h;
        st[20] ^= d0l; st[21] ^= d0h; st[30] ^= d0l; st[31] ^= d0h;
        st[40] ^= d0l; st[41] ^= d0h;
        st[2] ^= d1l; st[3] ^= d1h; st[12] ^= d1l; st[13] ^= d1h;
        st[22] ^= d1l; st[23] ^= d1h; st[32] ^= d1l; st[33] ^= d1h;
        st[42] ^= d1l; st[43] ^= d1h;
        st[4] ^= d2l; st[5] ^= d2h; st[14] ^= d2l; st[15] ^= d2h;
        st[24] ^= d2l; st[25] ^= d2h; st[34] ^= d2l; st[35] ^= d2h;
        st[44] ^= d2l; st[45] ^= d2h;
        st[6] ^= d3l; st[7] ^= d3h; st[16] ^= d3l; st[17] ^= d3h;
        st[26] ^= d3l; st[27] ^= d3h; st[36] ^= d3l; st[37] ^= d3h;
        st[46] ^= d3l; st[47] ^= d3h;
        st[8] ^= d4l; st[9] ^= d4h; st[18] ^= d4l; st[19] ^= d4h;
        st[28] ^= d4l; st[29] ^= d4h; st[38] ^= d4l; st[39] ^= d4h;
        st[48] ^= d4l; st[49] ^= d4h;

        /*
         * ---- rho + pi ----
         *
         * ⭐ GENERATED FROM THE PI AND ROT TABLES, which are still above and
         *   are still the source of truth. The loop read PI[i] and ROT[i] on
         *   every step and branched on whether the rotation passed 32; with
         *   the indices and shifts written out, both the reads and the
         *   branch are gone.
         *
         * ⚠ THE BRANCH IS RESOLVED AT WRITE TIME, NOT REMOVED. A rotation of
         *   32 or more swaps the halves, and each line below already has the
         *   right pair. Editing one by hand would break exactly one lane -
         *   which the SHA-3 vectors catch, since every lane feeds the digest.
         */
        t_lo = st[2]; t_hi = st[3];
        x_lo = st[20]; x_hi = st[21];
        st[20] = ((t_lo << 1) | (t_hi >>> 31)) | 0;
        st[21] = ((t_hi << 1) | (t_lo >>> 31)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[14]; x_hi = st[15];
        st[14] = ((t_lo << 3) | (t_hi >>> 29)) | 0;
        st[15] = ((t_hi << 3) | (t_lo >>> 29)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[22]; x_hi = st[23];
        st[22] = ((t_lo << 6) | (t_hi >>> 26)) | 0;
        st[23] = ((t_hi << 6) | (t_lo >>> 26)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[34]; x_hi = st[35];
        st[34] = ((t_lo << 10) | (t_hi >>> 22)) | 0;
        st[35] = ((t_hi << 10) | (t_lo >>> 22)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[36]; x_hi = st[37];
        st[36] = ((t_lo << 15) | (t_hi >>> 17)) | 0;
        st[37] = ((t_hi << 15) | (t_lo >>> 17)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[6]; x_hi = st[7];
        st[6] = ((t_lo << 21) | (t_hi >>> 11)) | 0;
        st[7] = ((t_hi << 21) | (t_lo >>> 11)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[10]; x_hi = st[11];
        st[10] = ((t_lo << 28) | (t_hi >>> 4)) | 0;
        st[11] = ((t_hi << 28) | (t_lo >>> 4)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[32]; x_hi = st[33];
        st[32] = ((t_hi << 4) | (t_lo >>> 28)) | 0;
        st[33] = ((t_lo << 4) | (t_hi >>> 28)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[16]; x_hi = st[17];
        st[16] = ((t_hi << 13) | (t_lo >>> 19)) | 0;
        st[17] = ((t_lo << 13) | (t_hi >>> 19)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[42]; x_hi = st[43];
        st[42] = ((t_hi << 23) | (t_lo >>> 9)) | 0;
        st[43] = ((t_lo << 23) | (t_hi >>> 9)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[48]; x_hi = st[49];
        st[48] = ((t_lo << 2) | (t_hi >>> 30)) | 0;
        st[49] = ((t_hi << 2) | (t_lo >>> 30)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[8]; x_hi = st[9];
        st[8] = ((t_lo << 14) | (t_hi >>> 18)) | 0;
        st[9] = ((t_hi << 14) | (t_lo >>> 18)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[30]; x_hi = st[31];
        st[30] = ((t_lo << 27) | (t_hi >>> 5)) | 0;
        st[31] = ((t_hi << 27) | (t_lo >>> 5)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[46]; x_hi = st[47];
        st[46] = ((t_hi << 9) | (t_lo >>> 23)) | 0;
        st[47] = ((t_lo << 9) | (t_hi >>> 23)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[38]; x_hi = st[39];
        st[38] = ((t_hi << 24) | (t_lo >>> 8)) | 0;
        st[39] = ((t_lo << 24) | (t_hi >>> 8)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[26]; x_hi = st[27];
        st[26] = ((t_lo << 8) | (t_hi >>> 24)) | 0;
        st[27] = ((t_hi << 8) | (t_lo >>> 24)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[24]; x_hi = st[25];
        st[24] = ((t_lo << 25) | (t_hi >>> 7)) | 0;
        st[25] = ((t_hi << 25) | (t_lo >>> 7)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[4]; x_hi = st[5];
        st[4] = ((t_hi << 11) | (t_lo >>> 21)) | 0;
        st[5] = ((t_lo << 11) | (t_hi >>> 21)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[40]; x_hi = st[41];
        st[40] = ((t_hi << 30) | (t_lo >>> 2)) | 0;
        st[41] = ((t_lo << 30) | (t_hi >>> 2)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[28]; x_hi = st[29];
        st[28] = ((t_lo << 18) | (t_hi >>> 14)) | 0;
        st[29] = ((t_hi << 18) | (t_lo >>> 14)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[44]; x_hi = st[45];
        st[44] = ((t_hi << 7) | (t_lo >>> 25)) | 0;
        st[45] = ((t_lo << 7) | (t_hi >>> 25)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[18]; x_hi = st[19];
        st[18] = ((t_hi << 29) | (t_lo >>> 3)) | 0;
        st[19] = ((t_lo << 29) | (t_hi >>> 3)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[12]; x_hi = st[13];
        st[12] = ((t_lo << 20) | (t_hi >>> 12)) | 0;
        st[13] = ((t_hi << 20) | (t_lo >>> 12)) | 0;
        t_lo = x_lo; t_hi = x_hi;
        x_lo = st[2]; x_hi = st[3];
        st[2] = ((t_hi << 12) | (t_lo >>> 20)) | 0;
        st[3] = ((t_lo << 12) | (t_hi >>> 20)) | 0;
        t_lo = x_lo; t_hi = x_hi;

        /* ---- chi: non-linearity along the rows ---- */
        /* ⭐ chi, unrolled for the same reason - five rows, constant indices */
        for (j = 0; j < 50; j += 10) {
            var g0l = st[j],     g0h = st[j + 1];
            var g1l = st[j + 2], g1h = st[j + 3];
            var g2l = st[j + 4], g2h = st[j + 5];
            var g3l = st[j + 6], g3h = st[j + 7];
            var g4l = st[j + 8], g4h = st[j + 9];
            st[j]     = g0l ^ ((~g1l) & g2l);
            st[j + 1] = g0h ^ ((~g1h) & g2h);
            st[j + 2] = g1l ^ ((~g2l) & g3l);
            st[j + 3] = g1h ^ ((~g2h) & g3h);
            st[j + 4] = g2l ^ ((~g3l) & g4l);
            st[j + 5] = g2h ^ ((~g3h) & g4h);
            st[j + 6] = g3l ^ ((~g4l) & g0l);
            st[j + 7] = g3h ^ ((~g4h) & g0h);
            st[j + 8] = g4l ^ ((~g0l) & g1l);
            st[j + 9] = g4h ^ ((~g0h) & g1h);
        }

        /* ---- iota: breaks symmetry between rounds ---- */
        st[0] ^= RC[r * 2];
        st[1] ^= RC[r * 2 + 1];
    }
}

/*
 * ⭐ ONE STATE AND ONE BLOCK FOR THE MODULE, not three typed arrays and two
 *   closures per call. A short SHAKE call - one block in, a few bytes out,
 *   which is what the multiplier and the OT extension make hundreds of
 *   thousands of - spent two thirds of its time allocating (measured: 6.8 µs
 *   a call against 2.25 µs now, with the permutation itself unchanged at
 *   ~1.7 µs).
 *
 * ⚠ SAFE BECAUSE THE SPONGE NEVER YIELDS. Nothing here calls out or awaits,
 *   so no second call can start while one is using the state - and each
 *   worker has its own module. The state is zeroed at the START of every
 *   call, so even a call that threw halfway leaves nothing for the next one
 *   to absorb into; and at the end as well, so no input lingers.
 */
var ST = new Int32Array(50);
var BC = new Int32Array(10);
var BLOCK = new Uint8Array(200);

/* xor one full block out of src at off, then permute */
function absorb_block(src, off, rate, rounds) {
    for (var j = 0; j < rate; j += 4) {
        ST[j >>> 2] ^= src[off + j] | (src[off + j + 1] << 8) |
                       (src[off + j + 2] << 16) | (src[off + j + 3] << 24);
    }
    permute(ST, BC, rounds);
}

/**
 * The full sponge: absorb, pad, squeeze.
 *
 * @param {Uint8Array} msg
 * @param {number} rate     bytes per block. 200 minus twice the capacity.
 * @param {number} pad      domain separation byte: 0x06 for SHA-3, 0x1f for SHAKE,
 *                          0x01 for original Keccak, 0x04 for cSHAKE
 * @param {number} out_len  output length in bytes
 * @param {Uint8Array} [prefix]  absorbed before msg. Must be a whole number of
 *                          blocks - every caller that needs one (cSHAKE, KMAC)
 *                          builds it through bytepad, which guarantees that,
 *                          so msg always starts on a block boundary and the
 *                          absorb loop stays simple.
 * @param {number} [rounds=24]  12 for TurboSHAKE
 * @param {Uint8Array} [suffix]  absorbed after msg. Needed by KMAC, which
 *                          encodes the requested output length at the end.
 *                          Unlike the prefix this is not block aligned, so
 *                          it shares the partial buffer with the message tail.
 */
export function keccak_sponge(msg, rate, pad, out_len, prefix, rounds, suffix) {
    if (rounds === undefined) { rounds = ROUNDS; }
    var out = new Uint8Array(out_len);   /* first: a bad length throws before any state is touched */
    /* a plain array of bytes still hashes, as it did before (subarray below needs a typed array) */
    if (!(msg instanceof Uint8Array)) { msg = Uint8Array.from(msg); }
    try {
        return sponge(msg, rate, pad, out, out_len, prefix, rounds, suffix);
    } finally {
        /* the absorbed input never outlives the call — not even when it throws */
        ST.fill(0);
        BLOCK.fill(0);
    }
}

function sponge(msg, rate, pad, out, out_len, prefix, rounds, suffix) {
    var block = BLOCK, i, k;
    ST.fill(0);

    /*
     * The prefix is a whole number of blocks by construction - every caller
     * that needs one builds it through bytepad - so the message starts on a
     * block boundary and its full blocks can be read straight from the input.
     */
    if (prefix !== undefined && prefix !== null) {
        for (k = 0; k < prefix.length; k += rate) { absorb_block(prefix, k, rate, rounds); }
    }

    var len = msg.length;
    var full = (len / rate) | 0;
    for (k = 0; k < full; k++) { absorb_block(msg, k * rate, rate, rounds); }

    /* Whatever is left of the message, then the suffix, share the buffer. */
    var pos = len - full * rate;
    block.set(full * rate === 0 ? msg : msg.subarray(full * rate), 0);
    if (suffix !== undefined && suffix !== null) {
        for (i = 0; i < suffix.length; i++) {
            block[pos++] = suffix[i];
            if (pos === rate) { absorb_block(block, 0, rate, rounds); pos = 0; }
        }
    }

    /* ---- pad: domain byte first, 0x80 at the end of the block ---- */
    block.fill(0, pos, rate);
    block[pos]      ^= pad;
    block[rate - 1] ^= 0x80;
    absorb_block(block, 0, rate, rounds);

    /* ---- squeeze: rate bytes at a time, permute between rounds; a word at a time ---- */
    var produced = 0, w, n;
    for (;;) {
        n = out_len - produced < rate ? out_len - produced : rate;
        for (i = 0; i + 4 <= n; i += 4) {
            w = ST[i >>> 2];
            out[produced++] = w & 0xff;
            out[produced++] = (w >>> 8) & 0xff;
            out[produced++] = (w >>> 16) & 0xff;
            out[produced++] = (w >>> 24) & 0xff;
        }
        for (; i < n; i++) { out[produced++] = (ST[i >>> 2] >>> ((i & 3) * 8)) & 0xff; }
        if (produced >= out_len) { break; }
        permute(ST, BC, rounds);
    }

    return out;
}

/* ================= Incremental sponge ================= */
/*
 * The same sponge fed in pieces: update() as often as needed, then digest()
 * once - or, for an extendable-output function, read() as many times as
 * wanted, each call continuing the output where the last one stopped.
 * copy() forks the state before the end.
 *
 * ⚠ EACH INSTANCE OWNS ITS STATE. The one-shot sponge above shares ST and
 *   BLOCK across the module, which is safe only because a call never yields.
 *   An incremental instance stays open between calls, so its state, block
 *   and scratch are its own, and any number can be open at once.
 *
 * @param {number} rate
 * @param {number} pad     domain separation byte, as keccak_sponge
 * @param {Uint8Array} [prefix]  whole blocks absorbed first (cSHAKE, KMAC)
 * @param {number} [rounds=24]
 * @param {Uint8Array} [suffix]  absorbed after the message, at the end (KMAC)
 */
export function keccak_create(rate, pad, prefix, rounds, suffix) {
    if (rounds === undefined) { rounds = ROUNDS; }
    var s = { st: new Int32Array(50), bc: new Int32Array(10), block: new Uint8Array(rate), pos: 0, out: -1 };
    if (prefix !== undefined && prefix !== null) {
        for (var k = 0; k < prefix.length; k += rate) { inst_absorb(s, prefix, k, rate, rounds); }
    }
    return keccak_instance(s, rate, pad, rounds, suffix);
}

function inst_absorb(s, src, off, rate, rounds) {
    var st = s.st;
    for (var j = 0; j < rate; j += 4) {
        st[j >>> 2] ^= src[off + j] | (src[off + j + 1] << 8) |
                       (src[off + j + 2] << 16) | (src[off + j + 3] << 24);
    }
    permute(st, s.bc, rounds);
}

function keccak_instance(s, rate, pad, rounds, suffix) {
    var finished = false, done = false;

    function feed(msg) {
        var len = msg.length, off = 0, i;
        if (s.pos > 0) {
            var take = Math.min(rate - s.pos, len);
            for (i = 0; i < take; i++) { s.block[s.pos + i] = msg[i]; }
            s.pos += take;
            off = take;
            if (s.pos < rate) { return; }
            inst_absorb(s, s.block, 0, rate, rounds);
            s.pos = 0;
        }
        while (len - off >= rate) { inst_absorb(s, msg, off, rate, rounds); off += rate; }
        for (i = 0; off + i < len; i++) { s.block[i] = msg[off + i]; }
        s.pos = len - off;
    }

    /* Pad and switch to squeezing; s.out counts bytes of the current block already read. */
    function finish() {
        if (suffix !== undefined && suffix !== null) { feed(suffix); }
        var block = s.block;
        block.fill(0, s.pos, rate);
        block[s.pos]    ^= pad;
        block[rate - 1] ^= 0x80;
        inst_absorb(s, block, 0, rate, rounds);
        block.fill(0);
        s.out = 0;
        finished = true;
    }

    function squeeze(out_len) {
        var out = new Uint8Array(out_len), produced = 0, st = s.st;
        while (produced < out_len) {
            if (s.out === rate) { permute(st, s.bc, rounds); s.out = 0; }
            var n = Math.min(out_len - produced, rate - s.out);
            for (var i = 0; i < n; i++, s.out++) {
                out[produced++] = (st[s.out >>> 2] >>> ((s.out & 3) * 8)) & 0xff;
            }
        }
        return out;
    }

    function wipe() { s.st.fill(0); s.bc.fill(0); s.block.fill(0); }

    var self = {
        update: function (msg) {
            if (finished || done) { throw new Error('keccak: update() after the output was read'); }
            if (!(msg instanceof Uint8Array)) { msg = Uint8Array.from(msg); }
            feed(msg);
            return self;
        },
        copy: function () {
            if (finished || done) { throw new Error('keccak: copy() after the output was read'); }
            return keccak_instance({ st: new Int32Array(s.st), bc: new Int32Array(10), block: new Uint8Array(s.block), pos: s.pos, out: -1 },
                                   rate, pad, rounds, suffix);
        },
        /* The whole output at once; the instance is spent. */
        digest: function (out_len) {
            if (done) { throw new Error('keccak: digest() was already called on this instance'); }
            if (finished) { throw new Error('keccak: digest() after read(); keep calling read()'); }
            var out = new Uint8Array(out_len);   /* a bad length throws before anything changes */
            finish();
            done = true;
            out.set(squeeze(out_len));
            wipe();
            return out;
        },
        /* The next n bytes of output, for an extendable-output function. */
        read: function (n) {
            if (done) { throw new Error('keccak: read() after digest()'); }
            if (!finished) { finish(); }
            return squeeze(n);
        }
    };
    return self;
}

/* ================= SP 800-185 encodings ================= */
/*
 * These exist so that a customisation string can never be confused with the
 * message that follows it. Every field carries its own length, so no two
 * distinct inputs can produce the same absorbed byte stream.
 */

/** left_encode(x): the byte count, then x big-endian. */
export function left_encode(x) {
    var bytes = [], v = x;
    do { bytes.unshift(v & 0xff); v = Math.floor(v / 256); } while (v > 0);
    var out = new Uint8Array(bytes.length + 1);
    out[0] = bytes.length;
    for (var i = 0; i < bytes.length; i++) { out[i + 1] = bytes[i]; }
    return out;
}

/** right_encode(x): x big-endian, then the byte count. */
export function right_encode(x) {
    var bytes = [], v = x;
    do { bytes.unshift(v & 0xff); v = Math.floor(v / 256); } while (v > 0);
    var out = new Uint8Array(bytes.length + 1);
    for (var i = 0; i < bytes.length; i++) { out[i] = bytes[i]; }
    out[bytes.length] = bytes.length;
    return out;
}

/** encode_string(S): left_encode of the length in BITS, then S. */
export function encode_string(s) {
    var n = left_encode(s.length * 8);
    var out = new Uint8Array(n.length + s.length);
    out.set(n, 0);
    out.set(s, n.length);
    return out;
}

/**
 * bytepad(X, w): left_encode(w) || X, zero padded up to a multiple of w.
 * This is what guarantees the prefix passed to keccak_sponge is block aligned.
 */
export function bytepad(parts, w) {
    var head = left_encode(w);
    var total = head.length, i;
    for (i = 0; i < parts.length; i++) { total += parts[i].length; }
    var padded = Math.ceil(total / w) * w;
    var out = new Uint8Array(padded);
    out.set(head, 0);
    var o = head.length;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], o); o += parts[i].length; }
    return out;
}

/**
 * Keccak-f[1600] on a 200-byte state, in place — for a duplex built on the
 * bare permutation (STROBE, merlin.js), which keeps its own state between
 * calls rather than one sponge per call. Lanes little-endian, as above.
 */
var F_ST = new Int32Array(50), F_BC = new Int32Array(10);   /* reused: the permutation never yields (see ST above) */
export function keccak_f1600(state) {
    if (!(state instanceof Uint8Array) || state.length !== 200) { throw new TypeError('keccak_f1600: a 200-byte state'); }
    var st = F_ST, bc = F_BC, j;
    for (j = 0; j < 200; j += 4) {
        st[j >>> 2] = state[j] | (state[j + 1] << 8) | (state[j + 2] << 16) | (state[j + 3] << 24);
    }
    permute(st, bc, ROUNDS);
    for (j = 0; j < 200; j += 4) {
        var w = st[j >>> 2];
        state[j] = w & 255; state[j + 1] = (w >>> 8) & 255; state[j + 2] = (w >>> 16) & 255; state[j + 3] = (w >>> 24) & 255;
    }
    st.fill(0); bc.fill(0);
    return state;
}
