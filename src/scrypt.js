/**
 * scrypt  -  RFC 7914
 *
 * The first widely used memory-hard password hash. PBKDF2 can be attacked by
 * throwing parallel hardware at it almost for free; scrypt's answer is to
 * force the attacker to hold a large array in RAM for every guess in flight.
 * Silicon is cheap, memory bandwidth is not.
 *
 * The Salsa20 core it mixes with is shared with salsa.js through
 * commons/salsa.js - the same rounds, run eight times instead of twenty.
 *
 * yescrypt.js CALLS THIS for its flags = 0, t = 0 case, which is classic
 * scrypt by design. It used to compute it through its own ROMix; the two were
 * checked identical, and against node, before that path was routed here - so
 * a change to this file is now a change to that yescrypt mode as well.
 *
 * The core is ROMix: fill V with N sequential states, then walk it in an
 * order that depends on the data itself. An attacker who keeps only part of V
 * has to recompute the missing entries, and the recomputation cost rises
 * sharply as the stored fraction shrinks. That is the whole idea - a
 * time-memory tradeoff that is deliberately bad.
 *
 * PARAMETERS
 *     N   cost. Must be a power of two. Memory is N * 128 * r bytes.
 *     r   block size. 8 is standard and rarely changed.
 *     p   parallelism. Independent ROMix passes; does not change memory.
 *
 * The common settings are N=16384, r=8, p=1, which is 16 MB. Interactive
 * logins sometimes use N=32768. Raising N is what buys security; raising p
 * only buys time, and an attacker parallelises it for free.
 *
 * ONE CAUTION THAT MATTERS IN A BROWSER
 * The memory is allocated up front and the work is synchronous. N=1048576
 * asks for 1 GB and will freeze the tab. Whatever runs this in a UI belongs
 * in a worker.
 *
 * The data-dependent access pattern also means scrypt is not constant time
 * with respect to the password. That is inherent to the design, accepted by
 * the spec, and irrelevant for the offline-guessing threat it addresses -
 * but it does make scrypt unsuitable where a local attacker can watch cache
 * behaviour. Argon2id exists partly to soften exactly that.
 */

import { finish_task } from './commons/task.js';
import { pbkdf2 } from './kdf.js';
import { sha256 } from './sha2.js';
import { salsa_core } from './commons/salsa.js';
import { rd_le32, wr_le32 } from './commons/bytes.js';

/**
 * BlockMix: run Salsa through 2r sub-blocks, then interleave the results so
 * that the even outputs come first. The shuffle is what stops an attacker
 * from processing sub-blocks independently.
 */
function block_mix(B, Y, r, tmp) {
    var i, j;
    var last = (2 * r - 1) * 16;

    for (j = 0; j < 16; j++) { tmp[j] = B[last + j]; }

    for (i = 0; i < 2 * r; i++) {
        var off = i * 16;
        for (j = 0; j < 16; j++) { tmp[j] ^= B[off + j]; }
        /* eight rounds, not the cipher's twenty - scrypt needs diffusion,
           not encryption, and its strength comes from the memory-hard
           structure around this core */
        salsa_core(tmp, tmp, 8);
        /* even sub-blocks to the front half, odd to the back */
        var dst = ((i >>> 1) + (i & 1) * r) * 16;
        for (j = 0; j < 16; j++) { Y[dst + j] = tmp[j]; }
    }
}

/**
 * @param  {Uint8Array} password
 * @param  {Uint8Array} salt        must be random and per-user
 * @param  {number}     N           cost, a power of two. Memory is N*128*r bytes.
 * @param  {number}     r           block size, normally 8
 * @param  {number}     p           parallelism, normally 1
 * @param  {number}     length      output bytes
 * @return {Uint8Array}
 */
export function scrypt(password, salt, N, r, p, length) {
    return finish_task(scrypt_task(password, salt, N, r, p, length));
}

/*
 * scrypt as a task (commons/task.js): each step() runs at most STEP_ITERS
 * iterations of ROMix's two loops and returns true once the key is ready.
 * scrypt() above runs the steps back to back; the callback form in
 * api/scrypt.js runs them a few milliseconds at a time, yielding to the
 * event loop between.
 *
 * ⭐ ROMix'S TWO LOOPS, cut between iterations: the block being mixed
 *   (lane), the loop (phase) and its counter (it) survive between steps,
 *   and so do X and Y - including which of the two is current, since they
 *   are swapped rather than copied (see the note on mix below).
 */
var STEP_ITERS = 64;

export function scrypt_task(password, salt, N, r, p, length) {
    if (N < 2 || (N & (N - 1)) !== 0) {
        throw new Error('scrypt: N must be a power of two greater than 1');
    }
    if (r < 1 || p < 1) {
        throw new Error('scrypt: r and p must be at least 1');
    }
    if (r * p >= (1 << 30)) {
        throw new Error('scrypt: r * p is too large');
    }

    var words = 32 * r;
    var i, j;

    /* Stretch the password across p independent blocks */
    var B_bytes = pbkdf2(sha256, password, salt, 1, p * 128 * r);
    var B = new Int32Array(p * words);
    for (i = 0; i < B.length; i++) { B[i] = rd_le32(B_bytes, i * 4); }

    /* The expensive part. V is the memory the attacker has to match. */
    var V   = new Int32Array(N * words);
    var X   = new Int32Array(words);
    var Y   = new Int32Array(words);
    var tmp = new Int32Array(16);

    var lane = 0, phase = 0, it = 0, out = null;

    /*
     * ROMix on the current lane: N sequential states into V, then N
     * data-dependent reads back out - at most `budget` iterations per call.
     *
     * ⭐ THE BUFFERS ARE SWAPPED, NOT COPIED.
     *
     *   block_mix reads X and writes Y, and the loop then copied Y back over
     *   X - 32*r words per iteration, 2N iterations. For N = 16384 and r = 8
     *   that is 256 words copied 32,768 times: eight million element writes
     *   whose only purpose was to rename a buffer.
     *
     * ⚠ X AND Y SWAP ROLES EACH ROUND, so neither name means what it did
     *   before the loop. Everything after must read whichever one holds the
     *   current value - which is why the final copy-out and the second loop
     *   below both use `X` after an explicit re-sync, rather than assuming.
     */
    function mix(budget) {
        var j2, k, swap, off = lane * words;
        if (phase === 0 && it === 0) {
            for (j2 = 0; j2 < words; j2++) { X[j2] = B[off + j2]; }
        }
        while (budget-- > 0) {
            if (phase === 0) {
                for (j2 = 0; j2 < words; j2++) { V[it * words + j2] = X[j2]; }
                block_mix(X, Y, r, tmp);
                swap = X; X = Y; Y = swap;
                if (++it === N) { phase = 1; it = 0; }
            } else {
                /*
                 * Integerify: the last 64-byte sub-block, read little-endian. N is a
                 * power of two so the modulus is a mask, and only the low word of
                 * that sub-block can matter.
                 */
                k = X[(2 * r - 1) * 16] & (N - 1);
                for (j2 = 0; j2 < words; j2++) { X[j2] ^= V[k * words + j2]; }
                block_mix(X, Y, r, tmp);
                swap = X; X = Y; Y = swap;
                if (++it === N) {
                    for (j2 = 0; j2 < words; j2++) { B[off + j2] = X[j2]; }
                    lane++; phase = 0; it = 0;
                    return;
                }
            }
        }
    }

    function finish() {
        for (i = 0; i < B.length; i++) { wr_le32(B_bytes, i * 4, B[i]); }

        var out = pbkdf2(sha256, password, B_bytes, 1, length);

        /* V holds password-derived state; leaving it for the GC is careless */
        for (i = 0; i < V.length; i++) { V[i] = 0; }
        for (i = 0; i < B.length; i++) { B[i] = 0; }
        for (i = 0; i < B_bytes.length; i++) { B_bytes[i] = 0; }
        for (i = 0; i < X.length; i++) { X[i] = 0; Y[i] = 0; }
        return out;
    }

    return {
        step: function () {
            if (out) { return true; }
            if (lane < p) {
                mix(STEP_ITERS);
                if (lane < p) { return false; }
            }
            out = finish();
            return true;
        },
        result: function () { return out; }
    };
}
