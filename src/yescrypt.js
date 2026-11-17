/**
 * yescrypt  -  Solar Designer, 2015
 *
 * The password hash in /etc/shadow on every modern Linux distribution.
 * Fedora, Debian, Ubuntu, RHEL and SUSE all switched to it from
 * SHA-512-crypt, so any tool that reads or writes system password files needs
 * it - and it is the reason a `$y$` prefix appears where `$6$` used to.
 *
 * IT IS SCRYPT WITH ONE ADDITION THAT MATTERS. scrypt's inner mixing is
 * Salsa20/8: additions, XORs and rotations. A GPU does those about as well as
 * a CPU does, so scrypt's defence is entirely its memory footprint.
 *
 * yescrypt adds PWXFORM, whose core operation is a 32x32 -> 64 bit INTEGER
 * MULTIPLY with data-dependent S-box lookups. That is deliberately the thing
 * GPUs are worst at relative to CPUs: multipliers are expensive in silicon,
 * so a GPU spends most of its area on ALUs that cannot do them at full rate,
 * while every CPU core has a fast pipelined multiplier sitting idle. The
 * result is that yescrypt gets more attacker-cost per unit of defender-cost
 * than scrypt at the same memory setting.
 *
 * The S-boxes are 8 KiB per lane and are themselves derived from the
 * password, so they live in L1 cache and are indexed by secret data - which
 * means yescrypt is INTENTIONALLY not cache-timing resistant, exactly as
 * scrypt and Argon2d are. For password hashing that is the right trade: the
 * attacker's advantage from a shared-cache side channel is far smaller than
 * their advantage from cheap parallel hardware.
 *
 * YESCRYPT_RW is the mode everything uses, and it is what makes the memory
 * WRITTEN as well as read - the second loop writes back to V, so an attacker
 * cannot trade memory for recomputation the way a read-only access pattern
 * would allow.
 *
 * ON THE ORDERING OF THIS FILE: the operations below are the reference
 * implementation's, in its order, because the algorithm is a chain of
 * transformations where nearly every step depends on the exact layout the
 * previous one produced.
 */

import { sha256 } from './sha2.js';
import { hmac } from './hmac.js';
import { pbkdf2 } from './kdf.js';
import { scrypt_task } from './scrypt.js';
import { finish_task, map_task, done_task, then_task } from './commons/task.js';
import { salsa_core } from './commons/salsa.js';
import { ascii, rd_le32, wr_le32 } from './commons/bytes.js';
import { equal_bool } from './commons/ct.js';

/* pwxform geometry, fixed by the specification */
var PWXsimple = 2;
var PWXgather = 4;
var PWXrounds = 6;
var Swidth = 8;
var PWXbytes = PWXgather * PWXsimple * 8;      /* 64 */
var PWXwords = PWXbytes / 4;                    /* 16 */
var Sbytes = 3 * (1 << Swidth) * PWXsimple * 8; /* 12288 */
var Swords = Sbytes / 4;                        /* 3072 */
var Smask = ((1 << Swidth) - 1) * PWXsimple * 8;

export var YESCRYPT_RW = 0x002;
export var YESCRYPT_ROUNDS_6 = 0x004;
export var YESCRYPT_GATHER_4 = 0x010;
export var YESCRYPT_SIMPLE_2 = 0x020;
export var YESCRYPT_SBOX_12K = 0x080;
export var YESCRYPT_DEFAULTS = /* @__PURE__ */
    (YESCRYPT_RW | YESCRYPT_ROUNDS_6 | YESCRYPT_GATHER_4 |
     YESCRYPT_SIMPLE_2 | YESCRYPT_SBOX_12K);
var YESCRYPT_PREHASH = 0x100000;

/* ---------------- block helpers ---------------- */

function blkcpy(dst, doff, src, soff, count) {
    for (var i = 0; i < count; i++) { dst[doff + i] = src[soff + i]; }
}

function blkxor(dst, doff, src, soff, count) {
    for (var i = 0; i < count; i++) { dst[doff + i] ^= src[soff + i]; }
}

var salsa_in = new Int32Array(16);
var salsa_out = new Int32Array(16);

/**
 * Salsa20/`rounds` in place on 16 words at `off`.
 *
 * THE UNSHUFFLE AND RESHUFFLE ARE PART OF THIS FUNCTION, not of the caller.
 * yescrypt keeps its blocks permuted by (i*5 mod 16) - the order SIMD wants
 * for the column rounds - and every block-level operation works on that
 * layout. Only Salsa itself needs the words in their natural positions, so it
 * undoes the permutation, runs, and redoes it.
 *
 * Getting this wrong produces a completely self-consistent implementation
 * that disagrees with every other one, and it is why yescrypt with no flags
 * would not reproduce plain scrypt.
 */
function salsa(B, off, rounds) {
    var i;
    for (i = 0; i < 16; i++) { salsa_in[(i * 5) % 16] = B[off + i] | 0; }
    salsa_core(salsa_in, salsa_out, rounds);
    /* salsa_core already adds the feed-forward, so take its output directly */
    for (i = 0; i < 16; i++) { B[off + i] = salsa_out[(i * 5) % 16] | 0; }
}

/** scrypt's BlockMix, used when pwxform is disabled. */
function blockmix_salsa8(B, Y, r) {
    var X = new Int32Array(16);
    blkcpy(X, 0, B, (2 * r - 1) * 16, 16);
    for (var i = 0; i < 2 * r; i++) {
        blkxor(X, 0, B, i * 16, 16);
        salsa(X, 0, 8);
        blkcpy(Y, i * 16, X, 0, 16);
    }
    for (var k = 0; k < r; k++) {
        blkcpy(B, k * 16, Y, k * 2 * 16, 16);
        blkcpy(B, (k + r) * 16, Y, (k * 2 + 1) * 16, 16);
    }
}

/* ---------------- pwxform ---------------- */

/**
 * The core.
 *
 * Each round multiplies the high and low halves of a 64-bit lane together,
 * adds one S-box entry and XORs another, where both S-box indices come from
 * the lane's own value. The multiply is the point; the data-dependent lookups
 * are what make it impossible to precompute.
 *
 * IN JAVASCRIPT THE MULTIPLY IS THE HARD PART. A 32x32 product reaches 2^64,
 * far past the 2^53 that a double represents exactly, so it is split into
 * 16-bit halves and reassembled - the same problem this library met in
 * ML-DSA's Montgomery reduction, and solved the same way.
 */
function pwxform(X, ctx) {
    var S = ctx.S;
    var S0 = ctx.S0, S1 = ctx.S1, S2 = ctx.S2;
    var w = ctx.w;
    var i, j, k;

    for (i = 0; i < PWXrounds; i++) {
        for (j = 0; j < PWXgather; j++) {
            /* lane j's first word selects both S-box offsets */
            var xl = X[j * PWXsimple * 2] >>> 0;
            var xh = X[j * PWXsimple * 2 + 1] >>> 0;

            var p0 = S0 + ((xl & Smask) >>> 3) * 2;
            var p1 = S1 + ((xh & Smask) >>> 3) * 2;

            for (k = 0; k < PWXsimple; k++) {
                var idx = (j * PWXsimple + k) * 2;
                var lo = X[idx] >>> 0;
                var hi = X[idx + 1] >>> 0;

                /* x = hi * lo, as a 64-bit product from 16-bit pieces */
                var a0 = lo & 0xffff, a1 = lo >>> 16;
                var b0 = hi & 0xffff, b1 = hi >>> 16;
                var m0 = a0 * b0;
                var m1 = a1 * b0;
                var m2 = a0 * b1;
                var m3 = a1 * b1;
                var mid = (m1 + m2) >>> 0;
                var carry_mid = (m1 + m2 > 0xffffffff) ? 1 : 0;
                var xlo = (m0 + ((mid & 0xffff) * 0x10000)) >>> 0;
                var carry_lo = (m0 + (mid & 0xffff) * 0x10000 > 0xffffffff) ? 1 : 0;
                var xhi = (m3 + (mid >>> 16) + carry_mid * 0x10000 + carry_lo) >>> 0;

                /* + S0[p0][k] */
                var s0l = S[p0 + k * 2] >>> 0, s0h = S[p0 + k * 2 + 1] >>> 0;
                var sum = xlo + s0l;
                xlo = sum >>> 0;
                xhi = (xhi + s0h + (sum > 0xffffffff ? 1 : 0)) >>> 0;

                /* ^ S1[p1][k] */
                xlo = (xlo ^ (S[p1 + k * 2] >>> 0)) >>> 0;
                xhi = (xhi ^ (S[p1 + k * 2 + 1] >>> 0)) >>> 0;

                X[idx] = xlo | 0;
                X[idx + 1] = xhi | 0;

                /* the middle rounds write back into S2, so the S-boxes evolve */
                if (i !== 0 && i !== PWXrounds - 1) {
                    S[S2 + w * 2] = xlo | 0;
                    S[S2 + w * 2 + 1] = xhi | 0;
                    w++;
                }
            }
        }
    }

    /* rotate the three S-box windows, so the one just written becomes S0 */
    ctx.S0 = S2;
    ctx.S1 = S0;
    ctx.S2 = S1;
    ctx.w = w & ((1 << Swidth) * PWXsimple - 1);
}

function blockmix_pwxform(B, ctx, r) {
    var X = new Int32Array(PWXwords);
    var r1 = 128 * r / PWXbytes;
    var i;

    blkcpy(X, 0, B, (r1 - 1) * PWXwords, PWXwords);

    for (i = 0; i < r1; i++) {
        if (r1 > 1) { blkxor(X, 0, B, i * PWXwords, PWXwords); }
        pwxform(X, ctx);
        blkcpy(B, i * PWXwords, X, 0, PWXwords);
    }

    i = ((r1 - 1) * PWXbytes / 64) | 0;
    salsa(B, i * 16, 2);
    for (i++; i < 2 * r; i++) {
        blkxor(B, i * 16, B, (i - 1) * 16, 16);
        salsa(B, i * 16, 2);
    }
}

/* ---------------- SMix ---------------- */

/**
 * The index into V, taken from the LAST block.
 *
 * Words 13 and 0 rather than 1 and 0, because the reference implementation
 * keeps its blocks in the shuffled order that SIMD wants. Reading the
 * "obvious" words gives a self-consistent implementation that agrees with
 * nobody.
 */
function integerify(B, r) {
    var off = (2 * r - 1) * 16;
    return [B[off + 13] >>> 0, B[off] >>> 0];   /* [high, low] */
}

function p2floor(x) {
    var y;
    while ((y = x & (x - 1))) { x = y; }
    return x;
}

/** Wrap into [0, i), biased so the low region stays reachable. */
function wrap(lo, i) {
    var n = p2floor(i);
    return ((lo & (n - 1)) >>> 0) % n + (i - n);
}

/* the (i*5 % 16) shuffle — the SIMD layout the whole file assumes — into XY and back */
function shuffle_in(XY, B, boff, r) {
    for (var k = 0; k < 2 * r; k++) {
        for (var i = 0; i < 16; i++) { XY[k * 16 + i] = B[boff + k * 16 + ((i * 5) % 16)]; }
    }
}
function shuffle_out(B, boff, XY, r) {
    for (var k = 0; k < 2 * r; k++) {
        for (var i = 0; i < 16; i++) { B[boff + k * 16 + ((i * 5) % 16)] = XY[k * 16 + i]; }
    }
}

/*
 * ==================== PASSES ====================
 *
 * SMix is a sequence of loops over the big array V - SMix1 fills it, SMix2
 * reads it back - and each is a PASS here: { count, begin, run(from, to),
 * end }. begin and end move the block into and out of the working buffer
 * XY, and run does iterations [from, to) of the loop. Running every pass
 * from begin to end is the original SMix; stopping between two iterations
 * and resuming at the next is what lets the callback form run it in slices
 * (yescrypt_task, below). XY carries the state from one iteration to the
 * next, so a pass may stop anywhere.
 */
function smix1_pass(B, boff, r, N, flags, V, voff, XY, ctx) {
    var s = 32 * r;
    return {
        count: N,
        begin: function () { shuffle_in(XY, B, boff, r); },
        run: function (from, to) {
            for (var i = from; i < to; i++) {
                blkcpy(V, voff + i * s, XY, 0, s);

                if ((flags & YESCRYPT_RW) && i > 1) {
                    var iv = integerify(XY, r);
                    var j = wrap(iv[1], i);
                    blkxor(XY, 0, V, voff + j * s, s);
                }

                if (ctx) { blockmix_pwxform(XY, ctx, r); }
                else { blockmix_salsa8(XY, XY.subarray(s), r); }
            }
        },
        end: function () { shuffle_out(B, boff, XY, r); }
    };
}

function smix2_pass(B, boff, r, N, Nloop, flags, V, voff, XY, ctx) {
    var s = 32 * r;
    return {
        count: Nloop,
        begin: function () { shuffle_in(XY, B, boff, r); },
        run: function (from, to) {
            for (var i = from; i < to; i++) {
                var iv = integerify(XY, r);
                /* N is well under 2^32 here, so the low word of the index is all
                   of it - a guard that assigned j to itself used to say so in code */
                var j = (iv[1] & (N - 1)) >>> 0;
                blkxor(XY, 0, V, voff + j * s, s);
                /* the write-back is what makes the region read-WRITE */
                if (flags & YESCRYPT_RW) { blkcpy(V, voff + j * s, XY, 0, s); }

                if (ctx) { blockmix_pwxform(XY, ctx, r); }
                else { blockmix_salsa8(XY, XY.subarray(s), r); }
            }
        },
        end: function () { shuffle_out(B, boff, XY, r); }
    };
}

/* A pass of no iterations: one piece of setup, run in order with the rest. */
function setup_pass(fn) {
    return { count: 0, begin: fn, run: function () {}, end: function () {} };
}

function run_pass(pass) {
    pass.begin();
    pass.run(0, pass.count);
    pass.end();
}

/* SMix's passes, in order - appended to `passes`. */
function smix_passes(passes, B, r, N, p, t, flags, V, XY, ctxs, passwd) {
    var s = 32 * r;
    var Nchunk = Math.floor(N / p);
    var Nloop_all = Nchunk;
    var i;

    if (flags & YESCRYPT_RW) {
        if (t <= 1) {
            if (t) { Nloop_all *= 2; }
            Nloop_all = Math.floor((Nloop_all + 2) / 3);
        } else {
            Nloop_all *= (t - 1);
        }
    } else if (t) {
        if (t === 1) { Nloop_all += Math.floor((Nloop_all + 1) / 2); }
        Nloop_all *= t;
    }

    var Nloop_rw = 0;
    if (flags & YESCRYPT_RW) { Nloop_rw = Math.floor(Nloop_all / p); }

    Nchunk &= ~1;
    Nloop_all++; Nloop_all &= ~1;
    Nloop_rw++; Nloop_rw &= ~1;

    var Vchunk = 0;
    for (i = 0; i < p; i++, Vchunk += Nchunk) {
        var Np = (i < p - 1) ? Nchunk : (N - Vchunk);
        var boff = i * s;
        var voff = Vchunk * s;
        var ctx = null;

        if (flags & YESCRYPT_RW) {
            ctx = ctxs[i];
            passes.push(setup_pass(lane_setup(B, boff, s, ctx, XY, i === 0 ? passwd : null)));
        }

        passes.push(smix1_pass(B, boff, r, Np, flags, V, voff, XY, ctx));
        passes.push(smix2_pass(B, boff, r, p2floor(Np), Nloop_rw, flags, V, voff, XY, ctx));
    }

    for (i = 0; i < p; i++) {
        passes.push(smix2_pass(B, i * s, r, N, Nloop_all - Nloop_rw, flags & ~YESCRYPT_RW,
                               V, 0, XY, (flags & YESCRYPT_RW) ? ctxs[i] : null));
    }
}

/*
 * A lane's pwxform S-boxes, and for the first lane the password re-derived.
 * Made when its pass begins: it reads the lane's block as the passes before
 * have left it.
 */
function lane_setup(B, boff, s, ctx, XY, passwd) {
    return function () {
        /*
         * The S-boxes are themselves filled by a small SMix pass over the
         * password-derived block - so they differ per password, which is
         * what stops an attacker precomputing them.
         */
        run_pass(smix1_pass(B, boff, 1, Sbytes / 128, 0, ctx.S, 0, XY, null));
        ctx.S2 = 0;
        ctx.S1 = (1 << Swidth) * PWXsimple * 2;
        ctx.S0 = ctx.S1 + (1 << Swidth) * PWXsimple * 2;
        ctx.w = 0;
        if (passwd) {
            /* the password is re-derived from the first lane's last block,
               which binds every later step to this one */
            var mac = hmac(sha256, i32_to_bytes(B, boff + s - 16, 64), passwd.slice(0, 32));
            for (var q = 0; q < 32; q++) { passwd[q] = mac[q]; }
        }
    };
}

/*
 * The passes as a task (commons/task.js): each step runs iterations worth
 * about STEP_BLOCKS BlockMix blocks - well under a millisecond - crossing
 * from one pass into the next as they end. finish() runs once all are done.
 */
var STEP_BLOCKS = 512;

function passes_task(passes, r, finish) {
    var k = 0, at = 0, begun = false, out, finished = false;
    var per_step = Math.max(1, Math.floor(STEP_BLOCKS / r));
    return {
        step: function () {
            var budget = per_step;
            while (k < passes.length) {
                var pass = passes[k];
                if (!begun) { pass.begin(); begun = true; }
                var to = Math.min(pass.count, at + budget);
                pass.run(at, to);
                budget -= to - at;
                at = to;
                if (at < pass.count) { return false; }
                pass.end();
                k++; at = 0; begun = false;
                if (budget <= 0) { return false; }
            }
            if (!finished) { out = finish(); finished = true; }
            return true;
        },
        result: function () { return out; }
    };
}

/* ---------------- conversions ---------------- */

/* little-endian words and bytes, through the commons/bytes.js helpers
   rather than the hand-written shifts these used to carry */
function bytes_to_i32(bytes) {
    var out = new Int32Array(bytes.length / 4);
    for (var i = 0; i < out.length; i++) { out[i] = rd_le32(bytes, i * 4); }
    return out;
}

function i32_to_bytes(arr, off, len) {
    var out = new Uint8Array(len);
    for (var i = 0; i < len / 4; i++) { wr_le32(out, i * 4, arr[off + i]); }
    return out;
}

/* ---------------- the KDF ---------------- */

/* The KDF as a task: the setup now, SMix in steps, the final PBKDF2 at the end. */
function kdf_task(password, salt, flags, N, r, p, t, length) {
    var passwd = new Uint8Array(password);

    /*
     * The domain tag is "yescrypt" or "yescrypt-prehash" - the SAME string
     * truncated to 8 or 16 bytes. The prehash pass must use the longer form,
     * or the two passes would derive from identical material and the
     * pre-hashing would add nothing.
     */
    if (flags) {
        var tag = ascii('yescrypt-prehash');
        passwd = hmac(sha256, tag.subarray(0, (flags & YESCRYPT_PREHASH) ? 16 : 8), passwd);
    }

    var B_bytes = 128 * r * p;
    var B = bytes_to_i32(pbkdf2(sha256, passwd, salt, 1, B_bytes));

    /*
     * THE REFERENCE ALIASES TWO THINGS THAT LOOK SEPARATE. In the C, `passwd`
     * is reassigned to point at the same 32-byte buffer that later holds the
     * SHA-256 working value - so overwriting that buffer silently overwrites
     * the password used by the FINAL PBKDF2 at the bottom of this function.
     *
     * The chain is: passwd = HMAC(tag, password), then PBKDF2 fills B, then
     * the first 32 bytes of B are copied over passwd, then SMix's step 24
     * overwrites it again with HMAC(last block, passwd) - and only then is it
     * used. A port that keeps the two as separate arrays produces a
     * self-consistent hash that matches nothing.
     */
    if (flags) {
        for (var q = 0; q < 8; q++) { wr_le32(passwd, q * 4, B[q]); }
    }
    var sha = passwd;

    var V = new Int32Array(32 * r * N);
    var XY = new Int32Array(64 * r);

    var passes = [];
    if (flags & YESCRYPT_RW) {
        var ctxs = [];
        for (var i = 0; i < p; i++) {
            ctxs.push({ S: new Int32Array(Swords), S0: 0, S1: 0, S2: 0, w: 0 });
        }
        smix_passes(passes, B, r, N, p, t, flags, V, XY, ctxs, sha);
    } else {
        for (var j = 0; j < p; j++) {
            smix_passes(passes, B.subarray(32 * r * j), r, N, 1, t, flags, V, XY, null, null);
        }
    }
    return passes_task(passes, r, function () { return kdf_finish(passwd, B, B_bytes, flags, length); });
}

/* After SMix: the final PBKDF2, and for yescrypt proper the SCRAM steps. */
function kdf_finish(passwd, B, B_bytes, flags, length) {
    var Bb = i32_to_bytes(B, 0, B_bytes);
    var out = pbkdf2(sha256, passwd, Bb, 1, Math.max(length, 32));

    /*
     * The last two steps mirror SCRAM (RFC 5802), so that an extension of
     * SCRAM could use yescrypt hashes directly - the client can do everything
     * up to here and the server stores only the final digest.
     */
    if (flags && !(flags & YESCRYPT_PREHASH)) {
        var client_key = hmac(sha256, out.subarray(0, 32), ascii('Client Key'));
        var stored = sha256(client_key);
        /*
         * ONLY THE FIRST 32 BYTES ARE REPLACED. Anything the caller asked for
         * beyond that keeps the PBKDF2 output underneath - the SCRAM step
         * overwrites a prefix rather than producing the whole result. For the
         * 32-byte output that crypt(3) uses this is invisible; for a longer
         * KDF output it is the difference between matching and not.
         */
        var res = new Uint8Array(length);
        res.set(out.subarray(0, length), 0);
        res.set(stored.subarray(0, Math.min(length, 32)), 0);
        return res;
    }

    return out.subarray(0, length);
}

/**
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {object}     params  {N, r, p, t, flags} - N a power of two
 * @param {number}     length
 * @return {Uint8Array}
 */
export function yescrypt(password, salt, params, length) {
    return finish_task(yescrypt_task(password, salt, params, length));
}

/** yescrypt as a task (commons/task.js): the same steps, run a slice at a time. */
export function yescrypt_task(password, salt, params, length) {
    var flags = params.flags === undefined ? YESCRYPT_DEFAULTS : params.flags;
    var N = params.N, r = params.r, p = params.p || 1, t = params.t || 0;

    if (N < 2 || (N & (N - 1)) !== 0) { throw new Error('yescrypt: N must be a power of two > 1'); }

    /*
     * ⭐ WITH NO FLAGS AND t = 0 THIS IS scrypt, and scrypt.js computes it.
     *
     *   yescrypt's design keeps classic scrypt as its flags = 0 case: no
     *   pre-hash HMAC, no pwxform, Salsa20/8 BlockMix, one write pass and N
     *   reads. Run through the code below it was a second ROMix - correct,
     *   but over the reordered SIMD layout and allocating per BlockMix.
     *   Checked identical to scrypt.js, and both to node's scrypt, over
     *   (N, r, p) from (2,1,1) to (1024,8,1) with p up to 4, empty and long
     *   passwords and salts, before this shortcut was added.
     *
     * ⚠ scrypt's VALIDATION NOW APPLIES TO THIS MODE. The shortcut used to
     *   be limited to inputs where the two agreed on the edges; the long path
     *   returned an empty or rounded result for a zero or fractional length
     *   and simply ran for r * p >= 2^30, all of which scrypt refuses. Those
     *   inputs now throw, which is what a KDF asked for zero bytes should do.
     *   t > 0 is not scrypt at all and never comes here.
     */
    if (flags === 0 && t === 0) {
        return scrypt_task(password, salt, N, r, p, length);
    }

    /*
     * THE PRE-HASH PASS. At large N the reference runs a cheap pass at N/64
     * first and feeds its output in as the password. It exists so that an
     * optimized implementation can make one big allocation and reuse it, and
     * it CHANGES THE RESULT - omitting it produces a different hash for the
     * same inputs whenever the condition below holds.
     */
    if ((flags & YESCRYPT_RW) && p >= 1 && Math.floor(N / p) >= 0x100 &&
        Math.floor(N / p) * r >= 0x20000) {
        return then_task(kdf_task(password, salt, flags | YESCRYPT_PREHASH, N >> 6, r, p, 0, 32), function (dk) {
            return kdf_task(dk, salt, flags, N, r, p, t, length);
        });
    }

    return kdf_task(password, salt, flags, N, r, p, t, length);
}

/* ---------------- the crypt(3) encoding ---------------- */

/*
 * THE CRYPT(3) ALPHABET, AND IT IS NOT BCRYPT'S. Two incompatible orderings
 * exist in the same /etc/shadow ecosystem:
 *
 *   yescrypt, sha512-crypt   ./0123456789ABC...XYZabc...xyz
 *   bcrypt (see bcrypt.js)   ./ABC...XYZabc...xyz0123456789
 *
 * and they also pack bits in opposite directions - yescrypt is
 * little-endian within each group, bcrypt big-endian. Using one where the
 * other belongs produces a string of the right length and shape that no
 * implementation accepts.
 */
var ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function atoi64(c) {
    var i = ITOA64.indexOf(c);
    return i < 0 ? 64 : i;
}

/**
 * The variable-length integer encoding.
 *
 * NOT plain base64. Small values take one character, larger ones take more,
 * with the FIRST character's position in the alphabet indicating how many
 * follow. That is what keeps a `$y$` string short for ordinary parameters
 * while still admitting large ones.
 */
function encode64_uint32(src, min) {
    var start = 0, end = 47, chars = 1, bits = 0;
    if (src < min) { return null; }
    src -= min;
    for (;;) {
        var count = (end + 1 - start) * Math.pow(2, bits);
        if (src < count) { break; }
        if (start >= 63) { return null; }
        start = end + 1;
        end = start + Math.floor((62 - end) / 2);
        src -= count;
        chars++;
        bits += 6;
    }
    var out = ITOA64[start + Math.floor(src / Math.pow(2, bits))];
    while (--chars) {
        bits -= 6;
        out += ITOA64[Math.floor(src / Math.pow(2, bits)) & 0x3f];
    }
    return out;
}

function decode64_uint32(s, pos, min) {
    var c = atoi64(s[pos++]);
    if (c > 63) { return null; }
    /*
     * Find the bucket the first character falls in, and the offset that all
     * the smaller buckets account for.
     *
     * ⭐ ONE PASS. This used to walk the buckets twice: a first loop
     *   accumulated an offset it then threw away (it added zero) and could
     *   exit early only when the bucket start passed 63 - which cannot happen
     *   for c <= 63, already checked above - and then this loop recomputed
     *   everything. The first was removed; every character and every
     *   two-character prefix decodes as before.
     */
    var s2 = 0, e2 = 47, b2 = 0, acc = 0;
    while (c > e2) {
        acc += (e2 + 1 - s2) * Math.pow(2, b2);
        s2 = e2 + 1;
        e2 = s2 + Math.floor((62 - e2) / 2);
        b2 += 6;
    }
    var dst = acc + (c - s2) * Math.pow(2, b2);
    var nb = b2;
    while (nb > 0) {
        nb -= 6;
        var d = atoi64(s[pos++]);
        if (d > 63) { return null; }
        dst += d * Math.pow(2, nb);
    }
    return { value: dst + min, pos: pos };
}

/** Bytes to the crypt alphabet, little-endian in 3-byte groups. */
function encode64(bytes) {
    var out = '';
    var i = 0;
    while (i < bytes.length) {
        var v = 0, bits = 0;
        do {
            v |= bytes[i++] * Math.pow(2, bits);
            bits += 8;
        } while (bits < 24 && i < bytes.length);
        while (bits > 0) {
            out += ITOA64[Math.floor(v) & 0x3f];
            v = Math.floor(v / 64);
            bits -= 6;
        }
    }
    return out;
}

function decode64(s) {
    var bytes = [];
    var i = 0;
    while (i < s.length) {
        var v = 0, bits = 0, chars = 0;
        while (bits < 24 && i < s.length) {
            var c = atoi64(s[i]);
            if (c > 63) { break; }
            i++;
            v += c * Math.pow(2, bits);
            bits += 6;
            chars++;
        }
        if (chars === 0) { break; }
        var nbytes = Math.floor(bits / 8);
        for (var k = 0; k < nbytes; k++) {
            bytes.push(Math.floor(v / Math.pow(2, 8 * k)) & 0xff);
        }
    }
    return new Uint8Array(bytes);
}

function n2log2(N) {
    var l = 0;
    while ((1 << l) < N && l < 32) { l++; }
    return (1 << l) === N ? l : 0;
}

/**
 * Format a hash as a crypt(3) string: $y$params$salt$hash
 *
 * The flavor field encodes the flags: values below YESCRYPT_RW are the flags
 * themselves, and anything at or above is `YESCRYPT_RW + (flags >> 2)`. The
 * common `j9T` is flavor 6 (the defaults), N=4096, r=32.
 */
export function encode_setting(params, salt) {
    var flags = params.flags === undefined ? YESCRYPT_DEFAULTS : params.flags;
    var flavor;
    if (flags < YESCRYPT_RW) { flavor = flags; }
    else { flavor = YESCRYPT_RW + (flags >> 2); }

    var nl = n2log2(params.N);
    if (!nl) { throw new Error('yescrypt: N must be a power of two'); }

    var out = '$y$' + encode64_uint32(flavor, 0) +
              encode64_uint32(nl, 1) + encode64_uint32(params.r, 1);
    if (params.p && params.p !== 1) {
        out += encode64_uint32(1, 1) + encode64_uint32(params.p, 2);
    }
    return out + '$' + encode64(salt);
}

/**
 * Parse a `$y$` setting string.
 * @return {{params, salt}|null}
 */
export function decode_setting(setting) {
    if (setting.slice(0, 3) !== '$y$') { return null; }
    var s = setting.slice(3);
    var pos = 0;

    var f = decode64_uint32(s, pos, 0); if (!f) { return null; }
    pos = f.pos;
    var nl = decode64_uint32(s, pos, 1); if (!nl) { return null; }
    pos = nl.pos;
    var rr = decode64_uint32(s, pos, 1); if (!rr) { return null; }
    pos = rr.pos;

    var flags = f.value < YESCRYPT_RW ? f.value : ((f.value - YESCRYPT_RW) << 2) | YESCRYPT_RW;
    var p = 1, t = 0;

    while (pos < s.length && s[pos] !== '$') {
        var which = decode64_uint32(s, pos, 1);
        if (!which) { return null; }
        pos = which.pos;
        var val = decode64_uint32(s, pos, which.value === 1 ? 2 : 1);
        if (!val) { return null; }
        pos = val.pos;
        if (which.value === 1) { p = val.value; }
        else if (which.value === 2) { t = val.value; }
    }

    var salt_str = '';
    if (s[pos] === '$') {
        pos++;
        var end = s.indexOf('$', pos);
        salt_str = end < 0 ? s.slice(pos) : s.slice(pos, end);
    }

    return {
        params: { flags: flags, N: 1 << nl.value, r: rr.value, p: p, t: t },
        /*
         * THE SALT IS DECODED, NOT PASSED THROUGH. `$y$` decodes its salt
         * field from the crypt alphabet before hashing; only the older `$7$`
         * scrypt format hashes the characters verbatim. Hashing the ASCII
         * gives a self-consistent result that libxcrypt disagrees with.
         */
        salt: decode64(salt_str),
        salt_encoded: salt_str
    };
}

/**
 * The full crypt(3) interface: hash a password against a setting string and
 * return the complete `$y$...$...$...` value found in /etc/shadow.
 *
 * The salt in the setting is DECODED from the crypt alphabet before hashing -
 * see decode_setting.
 *
 * @param {Uint8Array} password
 * @param {string}     setting  e.g. '$y$j9T$SALTsaltSALTsalt'
 * @return {string|null}
 */
export function crypt(password, setting) {
    return finish_task(crypt_task(password, setting));
}

/** crypt as a task (commons/task.js); a setting that does not parse is null at once. */
export function crypt_task(password, setting) {
    var d = decode_setting(setting);
    if (!d) { return done_task(null); }
    return map_task(yescrypt_task(password, d.salt, d.params, 32), function (out) {
        /* keep everything up to and including the salt, then append the hash */
        var base = setting;
        if (base.charAt(base.length - 1) === '$') { base = base.slice(0, -1); }
        return base + '$' + encode64(out);
    });
}

/** @return {boolean} constant-time comparison of the hash portion */
export function crypt_verify(password, stored) {
    return finish_task(crypt_verify_task(password, stored));
}

/** crypt_verify as a task (commons/task.js). */
export function crypt_verify_task(password, stored) {
    var last = stored.lastIndexOf('$');
    if (last < 0) { return done_task(false); }
    return map_task(crypt_task(password, stored.slice(0, last)), function (got) {
        if (got === null) { return false; }
        /* ⭐ commons/ct.js rather than the hand-written xor loop this used to
           carry - the same length check and the same comparison */
        return equal_bool(ascii(got), ascii(stored));
    });
}
