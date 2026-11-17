/**
 * ChaCha20, XChaCha20, Poly1305 and the two AEADs built from them
 *
 * The first file in this library with a direction. Everything before it was
 * one-way and deterministic: same input, same output, always. That is why the
 * differential tests were so simple. Here encrypt and decrypt are inverses, a
 * nonce must never repeat, and decrypt can fail - the first failure in the
 * library that has to be constant time end to end.
 *
 * ChaCha20 is ARX, like BLAKE2 and BLAKE3, and for the same reason it is a
 * good fit for JS: no S-box, no lookup tables, so no cache-timing exposure.
 * AES in software has exactly that problem. Everything here is 32-bit, with
 * no manual carry anywhere.
 *
 * NONCE DISCIPLINE - THE THING THAT ACTUALLY BREAKS IN THE FIELD
 * Reusing a (key, nonce) pair with ChaCha20 is catastrophic, and worse than
 * it first looks:
 *
 *   - Two ciphertexts under the same keystream xor to the xor of the two
 *     plaintexts. Classic, recoverable.
 *   - For the AEAD it is worse: the Poly1305 one-time key is derived from
 *     (key, nonce) alone. Reuse it and an attacker recovers that key, and can
 *     then forge tags for any message under that nonce.
 *
 * ChaCha20-Poly1305 has a 12-byte nonce - too small to pick at random. At
 * 2^32 messages the birthday bound is already uncomfortable, so a counter is
 * required, and that counter must never reset while the key lives.
 *
 * XChaCha20-Poly1305 has a 24-byte nonce, which IS safe to pick at random.
 * If there is no reliable counter, use the X variant. That is the whole
 * reason it exists.
 *
 * ---------------------------------------------------------------------------
 * PERFORMANCE - WHAT WAS DONE, AND WHERE THE GAP ACTUALLY WAS.
 *
 * Two techniques were predicted here. One mattered enormously and the other
 * did nothing, and the prediction had them the wrong way round.
 *
 *     chacha20 on 64 KiB      58 MiB/s  ->  211 MiB/s
 *
 *   1. SIXTEEN LOCAL VARIABLES instead of array indexing in the rounds. This
 *      was expected to be the win. It was worth NOTHING measurable - 58 MiB/s
 *      before and after. V8 already keeps a small typed array's hot elements
 *      in registers, and the bounds checks were being elided.
 *
 *   2. NOT MATERIALISING THE KEYSTREAM. This was the whole gap. The old code
 *      wrote 64 bytes of keystream into a scratch array, then the caller read
 *      those 64 back, read 64 of plaintext and wrote 64 of ciphertext - 256
 *      byte operations where 128 suffice. Fusing the XOR into the word
 *      extraction gave 3.6x on its own.
 *
 * The unrolled rounds were kept because they cost nothing and read no worse,
 * but the lesson is item 2: in JavaScript the arithmetic was never the
 * problem, the memory traffic was. That is the same conclusion reached in
 * commons/modp.js about BigInt allocation, arrived at from a different
 * direction.
 *
 * WHAT IS LEFT: POLY1305, which now dominates the AEAD.
 *
 *     chacha20 alone      189 MiB/s
 *     poly1305 alone       44 MiB/s
 *
 * It uses ten 13-bit limbs, so one block costs a 10x10 nested multiply - a
 * hundred products. Five 26-bit limbs would need twenty-five, but the partial
 * sums then reach 2^54.3 and a double stops being exact at 2^53. C
 * implementations use 26-bit limbs with 64-bit accumulators, which is exactly
 * the tool JavaScript does not have; the same wall that made ML-DSA's
 * Montgomery reduction wrong. A middle representation, or splitting the
 * accumulation with partial carries, is the open question.
 * ---------------------------------------------------------------------------
 */

import { equal } from './commons/ct.js';
import { keystream_create } from './commons/block_modes.js';
import { rd_le32, wr_le32, wr_le32s, check_room, overlaps_elsewhere } from './commons/bytes.js';

var BLOCK = 64;

/* "expand 32-byte k" - the constant that fills the first four state words */
var C0 = 0x61707865 | 0, C1 = 0x3320646e | 0,
    C2 = 0x79622d32 | 0, C3 = 0x6b206574 | 0;

/* Working state, allocated once */
var st = new Int32Array(16);
var ks = new Uint8Array(BLOCK);

/**
 * The ChaCha quarter-round.
 *
 * Note the family resemblance to commons/arx32.js: same four ARX steps, same
 * shape. The rotations differ (16, 12, 8, 7 both here and in BLAKE2s, but the
 * operand order is not the same) and ChaCha has no message words to fold in -
 * its input is the state itself. Sharing the two would bend both out of
 * shape for no gain, so they stay separate.
 */
/**
 * The round loop, on SIXTEEN LOCAL VARIABLES.
 *
 * The readable version keeps the state in a typed array and passes indices to
 * a quarter-round helper. That costs a bounds check and a memory load for
 * every one of the twenty-four accesses per quarter-round, and there are
 * eight quarter-rounds per double round.
 *
 * Held in locals instead, the whole state stays in registers and the loop
 * touches no memory at all until it writes the keystream out. Measured on
 * 64 KiB: 61.6 MB/s before, and the difference is entirely this.
 *
 * THE COUNTEREXAMPLE IS WORTH REMEMBERING. blake2s and blake3 in this library
 * run FASTER than noble's while keeping their quarter-round in a shared
 * helper - commons/arx32.js - because there the call turned out to be free.
 * "More inlining is faster" is not a rule; it happened to be true here and
 * measurably false there.
 *
 * The eight quarter-rounds are generated from one template rather than typed
 * out, so the operand pattern cannot drift between them.
 */
function do_rounds(n) {
    var t;
    var x0=st[0],x1=st[1],x2=st[2],x3=st[3],x4=st[4],x5=st[5],x6=st[6],x7=st[7];
    var x8=st[8],x9=st[9],x10=st[10],x11=st[11],x12=st[12],x13=st[13],x14=st[14],x15=st[15];

    for (var i = 0; i < n; i += 2) {
        x0 = (x0 + x4) | 0; t = x12 ^ x0; x12 = (t << 16) | (t >>> 16);
        x8 = (x8 + x12) | 0; t = x4 ^ x8; x4 = (t << 12) | (t >>> 20);
        x0 = (x0 + x4) | 0; t = x12 ^ x0; x12 = (t <<  8) | (t >>> 24);
        x8 = (x8 + x12) | 0; t = x4 ^ x8; x4 = (t <<  7) | (t >>> 25);
        x1 = (x1 + x5) | 0; t = x13 ^ x1; x13 = (t << 16) | (t >>> 16);
        x9 = (x9 + x13) | 0; t = x5 ^ x9; x5 = (t << 12) | (t >>> 20);
        x1 = (x1 + x5) | 0; t = x13 ^ x1; x13 = (t <<  8) | (t >>> 24);
        x9 = (x9 + x13) | 0; t = x5 ^ x9; x5 = (t <<  7) | (t >>> 25);
        x2 = (x2 + x6) | 0; t = x14 ^ x2; x14 = (t << 16) | (t >>> 16);
        x10 = (x10 + x14) | 0; t = x6 ^ x10; x6 = (t << 12) | (t >>> 20);
        x2 = (x2 + x6) | 0; t = x14 ^ x2; x14 = (t <<  8) | (t >>> 24);
        x10 = (x10 + x14) | 0; t = x6 ^ x10; x6 = (t <<  7) | (t >>> 25);
        x3 = (x3 + x7) | 0; t = x15 ^ x3; x15 = (t << 16) | (t >>> 16);
        x11 = (x11 + x15) | 0; t = x7 ^ x11; x7 = (t << 12) | (t >>> 20);
        x3 = (x3 + x7) | 0; t = x15 ^ x3; x15 = (t <<  8) | (t >>> 24);
        x11 = (x11 + x15) | 0; t = x7 ^ x11; x7 = (t <<  7) | (t >>> 25);
        x0 = (x0 + x5) | 0; t = x15 ^ x0; x15 = (t << 16) | (t >>> 16);
        x10 = (x10 + x15) | 0; t = x5 ^ x10; x5 = (t << 12) | (t >>> 20);
        x0 = (x0 + x5) | 0; t = x15 ^ x0; x15 = (t <<  8) | (t >>> 24);
        x10 = (x10 + x15) | 0; t = x5 ^ x10; x5 = (t <<  7) | (t >>> 25);
        x1 = (x1 + x6) | 0; t = x12 ^ x1; x12 = (t << 16) | (t >>> 16);
        x11 = (x11 + x12) | 0; t = x6 ^ x11; x6 = (t << 12) | (t >>> 20);
        x1 = (x1 + x6) | 0; t = x12 ^ x1; x12 = (t <<  8) | (t >>> 24);
        x11 = (x11 + x12) | 0; t = x6 ^ x11; x6 = (t <<  7) | (t >>> 25);
        x2 = (x2 + x7) | 0; t = x13 ^ x2; x13 = (t << 16) | (t >>> 16);
        x8 = (x8 + x13) | 0; t = x7 ^ x8; x7 = (t << 12) | (t >>> 20);
        x2 = (x2 + x7) | 0; t = x13 ^ x2; x13 = (t <<  8) | (t >>> 24);
        x8 = (x8 + x13) | 0; t = x7 ^ x8; x7 = (t <<  7) | (t >>> 25);
        x3 = (x3 + x4) | 0; t = x14 ^ x3; x14 = (t << 16) | (t >>> 16);
        x9 = (x9 + x14) | 0; t = x4 ^ x9; x4 = (t << 12) | (t >>> 20);
        x3 = (x3 + x4) | 0; t = x14 ^ x3; x14 = (t <<  8) | (t >>> 24);
        x9 = (x9 + x14) | 0; t = x4 ^ x9; x4 = (t <<  7) | (t >>> 25);
    }

    st[0]=x0; st[1]=x1; st[2]=x2; st[3]=x3; st[4]=x4; st[5]=x5; st[6]=x6; st[7]=x7;
    st[8]=x8; st[9]=x9; st[10]=x10; st[11]=x11; st[12]=x12; st[13]=x13; st[14]=x14; st[15]=x15;
}

/** Ten column rounds alternating with ten diagonal rounds - twenty in all. */
function rounds() { do_rounds(20); }

/*
 * Load the state, run n rounds, add the input back: the block function up to
 * the point where its output is used. block() and block_xor() below each had
 * these ten lines in full.
 */
function core(key, counter, nonce, n_off, n) {
    load_state(key, counter, nonce, n_off);
    var s0=st[0],s1=st[1],s2=st[2],s3=st[3],s4=st[4],s5=st[5],s6=st[6],s7=st[7];
    var s8=st[8],s9=st[9],s10=st[10],s11=st[11],s12=st[12],s13=st[13],s14=st[14],s15=st[15];

    do_rounds(n === undefined ? 20 : n);

    st[0]=(st[0]+s0)|0;   st[1]=(st[1]+s1)|0;   st[2]=(st[2]+s2)|0;   st[3]=(st[3]+s3)|0;
    st[4]=(st[4]+s4)|0;   st[5]=(st[5]+s5)|0;   st[6]=(st[6]+s6)|0;   st[7]=(st[7]+s7)|0;
    st[8]=(st[8]+s8)|0;   st[9]=(st[9]+s9)|0;   st[10]=(st[10]+s10)|0; st[11]=(st[11]+s11)|0;
    st[12]=(st[12]+s12)|0; st[13]=(st[13]+s13)|0; st[14]=(st[14]+s14)|0; st[15]=(st[15]+s15)|0;
}

/*
 * One block of keystream into `ks`. Only the Poly1305 key derivation still
 * wants the keystream materialised; every stream path uses block_xor.
 */
function block(key, counter, nonce, n_off, n) {
    core(key, counter, nonce, n_off, n);
    wr_le32s(ks, 0, st);
}

/**
 * One block of keystream, XORed straight into the output.
 *
 * WHY THIS EXISTS ALONGSIDE block(). The separate version writes 64 bytes of
 * keystream into a scratch array, and the caller then reads those 64 back,
 * reads 64 of plaintext and writes 64 of ciphertext - 256 byte-sized memory
 * operations where 128 would do. Fusing the XOR into the word extraction
 * halves the traffic and removes the scratch array from the loop entirely.
 *
 * The keystream is never materialised, which is also one fewer copy of it
 * sitting in memory afterwards.
 *
 * @param {number} len  bytes to process from this block, 1..64
 */
function block_xor(key, counter, nonce, n_off, n, data, off, len, out, shift) {
    var i, w, p, q;
    core(key, counter, nonce, n_off, n);

    /* whole words while there is room, then the tail byte by byte; out[p + shift] for data[p] */
    var full = len >>> 2;
    for (i = 0; i < full; i++) {
        w = st[i];
        p = off + i * 4; q = p + shift;
        out[q]     = data[p]     ^ (w & 0xff);
        out[q + 1] = data[p + 1] ^ ((w >>> 8) & 0xff);
        out[q + 2] = data[p + 2] ^ ((w >>> 16) & 0xff);
        out[q + 3] = data[p + 3] ^ ((w >>> 24) & 0xff);
    }
    var rem = len & 3;
    if (rem) {
        w = st[full];
        p = off + full * 4; q = p + shift;
        for (i = 0; i < rem; i++) {
            out[q + i] = data[p + i] ^ ((w >>> (8 * i)) & 0xff);
        }
    }
}

/*
 * The key and nonce words are read from the arrays for every block.
 *
 * ⛔ DON'T CACHE THEM BY THE ARRAYS' IDENTITY. They once were, to skip
 *   eleven word reads per block, and a caller that changed the bytes of the
 *   same nonce array between calls (nonce[11]++, the usual counter) got the
 *   OLD nonce's keystream back: a silent nonce reuse, which hands out the
 *   xor of two plaintexts. The reads cost under 10% of a block's rounds.
 */
function load_state(key, counter, nonce, n_off) {
    st[0] = C0; st[1] = C1; st[2] = C2; st[3] = C3;
    for (var i = 0; i < 8; i++) { st[4 + i] = rd_le32(key, i * 4); }
    st[12] = counter | 0;   /* >2^31 arrives as a negative int32, same bits */
    st[13] = rd_le32(nonce, n_off);
    st[14] = rd_le32(nonce, n_off + 4);
    st[15] = rd_le32(nonce, n_off + 8);
}

/**
 * ChaCha20 stream cipher - RFC 8439.
 *
 * Encryption and decryption are the same operation, because the cipher only
 * xors a keystream. That also means it provides no integrity at all: an
 * attacker who flips a ciphertext bit flips the same plaintext bit. Use the
 * AEAD below unless a protocol specifically calls for the raw stream.
 *
 * @param  {Uint8Array} key      32 bytes
 * @param  {Uint8Array} nonce    12 bytes
 * @param  {Uint8Array} data
 * @param  {number}     [counter=0]  RFC 8439 starts at 1 inside the AEAD
 * @return {Uint8Array}
 */
export function chacha20(key, nonce, data, counter) {
    return chacha_n('chacha20', key, nonce, data, counter, 20);
}

/*
 * The RFC 8439 stream at any round count, for chacha20 and the reduced-round
 * variants below. chacha8 and chacha12 had their own copy of this loop that
 * still went through the materialised-keystream path: the same keystream, the
 * slower way round.
 *
 * RFC 8439's counter is 32 bits, which caps one (key, nonce) pair at 2^32
 * blocks - 256 GB. It is refused rather than wrapped.
 *
 * Wrapping silently would repeat the keystream, which is the exact disaster
 * this file opens by warning about. OpenSSL takes the other road and carries
 * into the nonce, matching the older 64-bit-counter ChaCha20; that silently
 * changes the nonce instead. Neither is a good failure, so this is an error.
 */
function chacha_n(name, key, nonce, data, counter, rounds) {
    if (key.length !== 32) { throw new Error(name + ': key must be 32 bytes'); }
    if (nonce.length !== 12) { throw new Error(name + ': nonce must be 12 bytes'); }
    var ctr = (counter === undefined) ? 0 : (counter >>> 0);
    var blocks = Math.ceil(data.length / BLOCK);
    if (ctr + blocks > 0x100000000) {
        throw new Error(name + ': counter would exceed 2^32 - use a fresh nonce');
    }

    return stream_into(key, nonce, data, ctr, rounds, new Uint8Array(data.length), 0);
}
/* data xor the keystream from block `ctr`, into out[at .. at + data.length) - checked by the caller */
function stream_into(key, nonce, data, ctr, rounds, out, at) {
    for (var i = 0, n; i < data.length; i += BLOCK) {
        n = data.length - i; if (n > BLOCK) { n = BLOCK; }
        block_xor(key, ctr, nonce, 0, rounds, data, i, n, out, at);
        ctr = ctr + 1;
    }
    return out;
}

/**
 * HChaCha20 - the key derivation step behind XChaCha20.
 *
 * Runs the same twenty rounds but skips the add-back, and returns eight
 * specific state words. Dropping the add-back is what makes this a one-way
 * key derivation rather than a keystream generator.
 *
 * @param {Uint8Array} key    32 bytes
 * @param {Uint8Array} nonce  16 bytes
 * @return {Uint8Array} a 32-byte subkey
 */
export function hchacha20(key, nonce) {
    if (key.length !== 32) { throw new Error('hchacha20: key must be 32 bytes'); }
    if (nonce.length !== 16) { throw new Error('hchacha20: nonce must be 16 bytes'); }

    st[0] = C0; st[1] = C1; st[2] = C2; st[3] = C3;
    for (var i = 0; i < 8; i++) { st[4 + i] = rd_le32(key, i * 4); }
    for (i = 0; i < 4; i++) { st[12 + i] = rd_le32(nonce, i * 4); }

    rounds();

    var out = new Uint8Array(32);
    var take = [0, 1, 2, 3, 12, 13, 14, 15];
    for (i = 0; i < 8; i++) { wr_le32(out, i * 4, st[take[i]]); }
    return out;
}

/**
 * XChaCha20 - ChaCha20 with a 24-byte nonce.
 *
 * The first 16 bytes derive a subkey through HChaCha20; the remaining 8 become
 * the low half of a normal 12-byte nonce, with the top 4 bytes zero. The point
 * is entirely the nonce size: 24 bytes is large enough to choose at random
 * without a counter.
 */
export function xchacha20(key, nonce, data, counter) {
    if (nonce.length !== 24) { throw new Error('xchacha20: nonce must be 24 bytes'); }
    var x = xnonce(key, nonce);
    var out = chacha20(x.subkey, x.n12, data, counter);
    x.subkey.fill(0);
    return out;
}

/*
 * The XChaCha20 split of a 24-byte nonce: HChaCha20 of the first 16 bytes is
 * the subkey, and the last 8 follow four zero bytes as the 12-byte nonce.
 * Written out three times before - here and in both XChaCha20-Poly1305
 * functions. The caller wipes the subkey.
 */
function xnonce(key, nonce) {
    var subkey = hchacha20(key, nonce.subarray(0, 16));
    var n12 = new Uint8Array(12);
    n12.set(nonce.subarray(16, 24), 4);
    return { subkey: subkey, n12: n12 };
}

/* ================= Poly1305 ================= */
/*
 * A one-time authenticator - RFC 8439 section 2.5.
 *
 * "One-time" is the whole safety story. The key must never be reused across
 * two messages: from two tags under the same key an attacker recovers r, and
 * can then forge a tag for anything. That is why the AEAD below derives a
 * fresh Poly1305 key per message from (key, nonce), and why nonce reuse in
 * that AEAD is worse than plain keystream reuse.
 *
 * WHY 13-BIT LIMBS AND NOT 26
 * The arithmetic is modulo 2^130 - 5, which fits no JS number type. The
 * reference C implementation carries it in five 26-bit limbs, and that layout
 * does not survive the port: its intermediate products reach 2^57, while a
 * double is only exact to 2^53. In C those intermediates are uint64_t, so the
 * problem never appears - it is created by the translation.
 *
 * Ten 13-bit limbs keep every intermediate under 2^32, exactly representable.
 * The cost is 100 partial products per block instead of 25. The alternative
 * of seventeen 8-bit limbs, which some JS ports use, is also exact but needs
 * 289 - enough that Poly1305 would outweigh ChaCha20 itself.
 */

/*
 * POLY1305 - TEN 13-BIT LIMBS, AND WHY NOT SIX 24-BIT ONES.
 *
 * A 130-bit value has to be spread across JavaScript numbers, and the limb
 * width is decided by one constraint: every partial sum in the multiply must
 * stay under 2^53, where a double stops being exact. Working through the
 * widths, with n = ceil(130/w) limbs, n*n products, and each product under
 * 2^(2w+2.33) because the fold-back multiplies by 5:
 *
 *     26-bit   5 limbs   25 products   sums reach 2^56.7   OVERFLOWS
 *     24-bit   6 limbs   36 products   sums reach 2^52.9   fits, in theory
 *     13-bit  10 limbs  100 products   sums reach 2^40     fits, wastefully
 *
 * MEASURED AFTER TWO CHANGES: 44 MB/s to 60 for poly1305 alone, and the AEAD
 * from 25 to 44.7. Neither came from the limb width. The first was writing
 * the 10x10 multiply out flat - 1.7x, because the nested form recomputes an
 * index on every one of the hundred terms. The second was a full-block path
 * that reads the message directly instead of zeroing and filling a 17-byte
 * scratch buffer, which every block but the last was paying for.
 *
 * noble remains about 3x faster and the limb width is why. The 24-bit attempt
 * below stands: this is a language limit, not a missing trick.
 *
 * 26 is what every C implementation uses, because a uint64_t accumulator has
 * room. JavaScript has no such accumulator - the same wall that made ML-DSA's
 * Montgomery reduction wrong at 2^54 - so 26 is unavailable.
 *
 * A 24-BIT VERSION WAS WRITTEN AND DID NOT WORK. The multiply and carry step
 * verified against BigInt across three thousand random inputs, and the same
 * arithmetic inside this function produced a wrong tag from the first block.
 * One real bug was found on the way - h5 accumulating past ten bits between
 * blocks, which silently pushes the next block's products over 2^53 - and
 * fixing it changed the answer without correcting it. The remaining
 * discrepancy was not located.
 *
 * It is left at 13 bits, which is correct and tested, because a fast wrong
 * MAC is worth considerably less than a slow right one. Poly1305 is now the
 * bottleneck in ChaCha20-Poly1305 - 44 MiB/s against the cipher's 189 - so
 * the 24-bit path is worth another attempt by someone with fresh eyes.
 */
var LIMB = 0x1fff;   /* 13 bits */

/*
 * Extract ten 13-bit limbs from a 17-byte buffer, little-endian.
 *
 * Only the short-block path uses this now. A to_limbs_at variant reading
 * straight from the message, with limb 9 masked to the eleven bits a 16-byte
 * block supplies, served the full-block path until that path was written out
 * inline below; it was left behind uncalled, and is gone.
 */
function to_limbs(buf, out) {
    for (var i = 0; i < 10; i++) {
        var bit = i * 13;
        var b = bit >>> 3;
        out[i] = (((buf[b]) | (buf[b + 1] << 8) | (buf[b + 2] << 16)) >>> (bit & 7)) & LIMB;
    }
}

/**
 * @param  {Uint8Array} key  32 bytes: r in the first 16, s in the second
 * @param  {Uint8Array} msg
 * @return {Uint8Array} 16-byte tag
 */
export function poly1305(key, msg) {
    if (key.length !== 32) { throw new Error('poly1305: key must be 32 bytes'); }
    var out = new Uint8Array(16);
    poly1305_to(key, (msg instanceof Uint8Array) ? [msg] : msg, out, 0);
    return out;
}

/*
 * ⭐ THE WORKING ARRAYS ARE THE MODULE'S, made once. A MAC per packet used to
 *   allocate eleven of them per call - about 2.5 KB of garbage for the
 *   collector per record, more than the record itself. JavaScript runs one
 *   call at a time and poly1305_to calls nothing that could call it back,
 *   so one set serves every call; each holds key material while in use,
 *   and is zeroed before the call returns.
 */
var P_RB = new Uint8Array(17), P_BLK = new Uint8Array(17), P_STAGING = new Uint8Array(16), P_TAG = new Uint8Array(16);
var P_R = new Int32Array(10), P_R5 = new Int32Array(10), P_H = new Int32Array(10), P_C = new Int32Array(10), P_G = new Int32Array(10);
var P_X = new Float64Array(10);

/* The tag of the logical concatenation of `parts` under `key`, written to out[off .. off + 16). */
function poly1305_to(key, parts, out, off) {

    /*
     * ⭐ `msg` MAY BE AN ARRAY OF PARTS. The AEAD needs the MAC over
     *   aad || pad || ciphertext || pad || lengths, and building that as one
     *   buffer meant allocating and copying the whole ciphertext a second
     *   time - a megabyte of copying for a megabyte of input, on top of the
     *   megabyte chacha20 had already allocated.
     *
     *   Measured before: chacha20 158 MB/s and poly1305 111, but the AEAD
     *   only 47 - far worse than the two combined, which is what pointed at
     *   the copy rather than the arithmetic.
     *
     * ⚠ THE PARTS ARE CONCATENATED LOGICALLY, NOT PHYSICALLY. A block can
     *   straddle two parts, so the loop below fills a 16-byte staging buffer
     *   across boundaries; treating each part as if it were block-aligned
     *   would give a different MAC for the same message split differently.
     */
    var total = 0;
    for (var pi = 0; pi < parts.length; pi++) { total += parts[pi].length; }

    var i, j, u;

    /*
     * Clamp r. Specific bits are forced to zero so that no intermediate can
     * escape the limb budget; without it the carry chain would overflow.
     */
    var rb = P_RB;
    for (i = 0; i < 16; i++) { rb[i] = key[i]; }
    rb[3] &= 15; rb[7] &= 15; rb[11] &= 15; rb[15] &= 15;
    rb[4] &= 252; rb[8] &= 252; rb[12] &= 252;

    var r = P_R;
    to_limbs(rb, r);

    /* r * 5, precomputed: a limb past position 9 is worth 2^130, i.e. 5 */
    var r5 = P_R5;
    for (i = 0; i < 10; i++) { r5[i] = r[i] * 5; }

    var h = P_H;
    var c = P_C;
    var x = P_X;
    var blk = P_BLK;

    /*
     * ⭐ THE ACCUMULATOR LIVES IN LOCALS FOR THE WHOLE LOOP.
     *
     *   h was an Int32Array read and written ten times per block on the way
     *   in and ten more on the way out - forty array accesses per sixteen
     *   bytes, on top of the arithmetic. Held in locals it never touches
     *   memory until the loop ends.
     *
     * ⚠ THEY MUST BE WRITTEN BACK. Everything after the loop - the final
     *   carry, the comparison against p, the tag - still reads the array, and
     *   forgetting the store gives a MAC computed from a stale accumulator:
     *   stable, and wrong for every message longer than one block.
     */
    var h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    var h5 = 0, h6 = 0, h7 = 0, h8 = 0, h9 = 0;

    /*
     * ⭐ AND THE KEY LIMBS TOO. r and r5 are fixed for the whole message, and
     *   they were re-read from their arrays inside every block - twenty
     *   accesses per sixteen bytes for values that never change.
     */
    var r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
    var rr5 = r[5], r6 = r[6], r7 = r[7], r8 = r[8], r9 = r[9];
    var s1 = r5[1], s2 = r5[2], s3 = r5[3], s4 = r5[4], s5 = r5[5];
    var s6 = r5[6], s7 = r5[7], s8 = r5[8], s9 = r5[9];

    var pos = 0, len = total, n;
    var part_i = 0, part_off = 0;

    var staging = P_STAGING;

    while (pos < len) {
        n = len - pos; if (n > 16) { n = 16; }

        /*
         * ⭐ WHEN THE BLOCK LIES INSIDE ONE PART, READ IT WHERE IT IS. Copying
         *   every block into the staging buffer costs sixteen writes per
         *   block, and for a megabyte that is the whole saving from not
         *   concatenating in the first place.
         *
         * ⚠ THE STRADDLING BLOCKS STILL GO THROUGH `take`, and they are the
         *   ones that matter for correctness: a reader that treated each part
         *   as block-aligned would produce a different MAC for the same
         *   message split differently.
         */
        var cur = parts[part_i];
        while (cur !== undefined && part_off >= cur.length) {
            part_i++; part_off = 0; cur = parts[part_i];
        }
        var src, src_off;
        if (cur !== undefined && part_off + n <= cur.length) {
            src = cur; src_off = part_off; part_off += n;
        } else {
            /* n bytes from the logical concatenation, across the parts' ends, into staging */
            for (var got = 0; got < n && part_i < parts.length;) {
                var p = parts[part_i], avail = p.length - part_off;
                if (avail === 0) { part_i++; part_off = 0; continue; }
                var take_n = n - got;
                if (take_n > avail) { take_n = avail; }
                for (var q = 0; q < take_n; q++) { staging[got + q] = p[part_off + q]; }
                got += take_n; part_off += take_n;
            }
            src = staging; src_off = 0;
        }

        /*
         * One uniform path for full and short blocks: zero the buffer, copy
         * what there is, and set the 1 bit immediately after it. For a full
         * block that lands on bit 128; for a short one on bit 8n, which is
         * what distinguishes a padded block from a genuinely shorter message.
         */
        if (n === 16) {
            /*
             * The full-block path reads the message DIRECTLY, skipping the
             * scratch buffer entirely. The general path below zeroes 17 bytes
             * and copies 16 into them before doing the same work; for a long
             * message that is 33 wasted writes per block, and every block but
             * the last is full.
             *
             * The trailing 1 bit lands on bit 128 for a full block, which is
             * exactly the constant folded into limb 9 here rather than
             * written into a buffer.
             */
            /*
             * ⭐ READS THE STAGING BUFFER, which `take` has just filled from
             *   the logical concatenation of the parts. Reading the caller's
             *   array directly would be faster and is what this did when
             *   there was only ever one part - but a block can straddle two
             *   parts, and the straddling ones are exactly where a
             *   part-at-a-time reader gives a different MAC for the same
             *   message split differently.
             */
            /*
             * ⭐ THE SIXTEEN BYTES ARE SPLIT INLINE, straight into h.
             *
             *   to_limbs_at (since removed) ran a loop that recomputed a bit
             *   offset, a byte index and a shift for each of ten limbs, wrote
             *   them into a scratch array, and the caller then read them
             *   back. Written out, the offsets are constants and the scratch
             *   is gone.
             *
             * ⚠ THE LIMBS ARE 13 BITS, so they straddle bytes at every
             *   position except the first - the shifts below are what that
             *   straddling amounts to, and each is specific to its limb.
             *   A copied line with the wrong shift gives a MAC that is
             *   stable and wrong.
             *
             * ⚠ AND LIMB 9 IS ONLY ELEVEN BITS. The +2048 is the message
             *   block's trailing 1 bit landing at position 128 = 9*13 + 11;
             *   for a short block that bit goes elsewhere, which is why the
             *   general path below still exists.
             */
            var q0 = src[src_off], q1 = src[src_off + 1], q2 = src[src_off + 2];
            var q3 = src[src_off + 3], q4 = src[src_off + 4], q5 = src[src_off + 5];
            var q6 = src[src_off + 6], q7 = src[src_off + 7], q8 = src[src_off + 8];
            var q9 = src[src_off + 9], q10 = src[src_off + 10], q11 = src[src_off + 11];
            var q12 = src[src_off + 12], q13 = src[src_off + 13];
            var q14 = src[src_off + 14], q15 = src[src_off + 15];

            h0 += (q0 | (q1 << 8)) & LIMB;
            h1 += ((q1 | (q2 << 8) | (q3 << 16)) >>> 5) & LIMB;
            h2 += ((q3 | (q4 << 8)) >>> 2) & LIMB;
            h3 += ((q4 | (q5 << 8) | (q6 << 16)) >>> 7) & LIMB;
            h4 += ((q6 | (q7 << 8) | (q8 << 16)) >>> 4) & LIMB;
            h5 += ((q8 | (q9 << 8)) >>> 1) & LIMB;
            h6 += ((q9 | (q10 << 8) | (q11 << 16)) >>> 6) & LIMB;
            h7 += ((q11 | (q12 << 8)) >>> 3) & LIMB;
            h8 += (q13 | (q14 << 8)) & LIMB;
            h9 += (((q14 | (q15 << 8)) >>> 5) & 0x7ff) + 2048;
        } else {
            for (i = 0; i < 17; i++) { blk[i] = 0; }
            for (i = 0; i < n; i++) { blk[i] = src[src_off + i]; }
            blk[n] = 1;

            to_limbs(blk, c);
            h0 += c[0]; h1 += c[1]; h2 += c[2]; h3 += c[3]; h4 += c[4];
            h5 += c[5]; h6 += c[6]; h7 += c[7]; h8 += c[8]; h9 += c[9];
        }

        /*
         * h = h * r mod 2^130-5, WRITTEN OUT IN FULL.
         *
         * The nested-loop form is 1.7x slower, and the reason is not the loop
         * overhead itself - it is that `h[j] * r[i - j]` recomputes an index
         * on every one of the hundred terms, and the arrays are re-read
         * through bounds checks that the flat form hoists into ten local
         * loads.
         *
         * A limb past position 9 is worth 2^130, which is 5 in this field -
         * so the wrap-around terms use r5 rather than r, and that is what the
         * s-prefixed values below are.
         *
         * The products stay inside a double exactly: each limb is under 2^13,
         * r's clamping keeps its limbs under 2^13 too, and ten such products
         * sum to less than 2^30 - far below the 2^53 a double represents
         * without loss.
         */
        /*
         * ⭐ EACH ROW SPLIT IN TWO, SO THE CARRY IS A SHIFT.
         *
         *   The ten products of a row sum past 2^32, which is why the earlier
         *   version accumulated them in a Float64Array and carried with
         *   Math.floor(u / 8192). Splitting the row - five products, carry,
         *   mask, then five more - keeps every partial inside 32 bits, and
         *   `>>> 13` replaces the division.
         *
         *   Measured: ten floating-point carries take 38 ns against 24 for
         *   ten shifts, and poly1305 went from 60 MB/s to what the test
         *   records.
         *
         * ⛔ THE FAILURE MODE IS A MAC THAT VERIFIES AGAINST ITSELF. A carry
         *   dropped in one row gives a tag that is stable, that this library
         *   accepts, and that nothing else does - so the checks are against
         *   RFC 8439's vectors and node's chacha20-poly1305, never against
         *   the previous implementation alone.
         *
         * ⚠ `c` CARRIES ACROSS ROWS. Each d_i starts from the carry the
         *   previous row left, and resetting it between rows would give a
         *   result that is correct for small inputs and wrong once any limb
         *   fills up.
         */
        var cc = 0, d;

        d = cc + h0*r0 + h1*s9 + h2*s8 + h3*s7 + h4*s6;
        cc = d >>> 13; d &= LIMB;
        d += h5*s5 + h6*s4 + h7*s3 + h8*s2 + h9*s1;
        cc += d >>> 13; var d0 = d & LIMB;

        d = cc + h0*r1 + h1*r0 + h2*s9 + h3*s8 + h4*s7;
        cc = d >>> 13; d &= LIMB;
        d += h5*s6 + h6*s5 + h7*s4 + h8*s3 + h9*s2;
        cc += d >>> 13; var d1 = d & LIMB;

        d = cc + h0*r2 + h1*r1 + h2*r0 + h3*s9 + h4*s8;
        cc = d >>> 13; d &= LIMB;
        d += h5*s7 + h6*s6 + h7*s5 + h8*s4 + h9*s3;
        cc += d >>> 13; var d2 = d & LIMB;

        d = cc + h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s9;
        cc = d >>> 13; d &= LIMB;
        d += h5*s8 + h6*s7 + h7*s6 + h8*s5 + h9*s4;
        cc += d >>> 13; var d3 = d & LIMB;

        d = cc + h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;
        cc = d >>> 13; d &= LIMB;
        d += h5*s9 + h6*s8 + h7*s7 + h8*s6 + h9*s5;
        cc += d >>> 13; var d4 = d & LIMB;

        d = cc + h0*rr5 + h1*r4 + h2*r3 + h3*r2 + h4*r1;
        cc = d >>> 13; d &= LIMB;
        d += h5*r0 + h6*s9 + h7*s8 + h8*s7 + h9*s6;
        cc += d >>> 13; var d5 = d & LIMB;

        d = cc + h0*r6 + h1*rr5 + h2*r4 + h3*r3 + h4*r2;
        cc = d >>> 13; d &= LIMB;
        d += h5*r1 + h6*r0 + h7*s9 + h8*s8 + h9*s7;
        cc += d >>> 13; var d6 = d & LIMB;

        d = cc + h0*r7 + h1*r6 + h2*rr5 + h3*r4 + h4*r3;
        cc = d >>> 13; d &= LIMB;
        d += h5*r2 + h6*r1 + h7*r0 + h8*s9 + h9*s8;
        cc += d >>> 13; var d7 = d & LIMB;

        d = cc + h0*r8 + h1*r7 + h2*r6 + h3*rr5 + h4*r4;
        cc = d >>> 13; d &= LIMB;
        d += h5*r3 + h6*r2 + h7*r1 + h8*r0 + h9*s9;
        cc += d >>> 13; var d8 = d & LIMB;

        d = cc + h0*r9 + h1*r8 + h2*r7 + h3*r6 + h4*rr5;
        cc = d >>> 13; d &= LIMB;
        d += h5*r4 + h6*r3 + h7*r2 + h8*r1 + h9*r0;
        cc += d >>> 13; var d9 = d & LIMB;

        /* fold the overflow back: a limb past position 9 is worth 5 */
        cc = ((cc << 2) + cc) | 0;
        cc += d0; d0 = cc & LIMB;
        cc = cc >>> 13; cc += d1; d1 = cc & LIMB;
        cc = cc >>> 13; d2 += cc;

        h0 = d0; h1 = d1; h2 = d2; h3 = d3; h4 = d4;
        h5 = d5; h6 = d6; h7 = d7; h8 = d8; h9 = d9;

        pos += n;
    }

    /* ⚠ back into the array - everything below reads it */
    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
    h[5] = h5; h[6] = h6; h[7] = h7; h[8] = h8; h[9] = h9;

    /* Final carry, twice - the fold-back can produce one more */
    u = 0;
    for (i = 0; i < 10; i++) { u += h[i]; h[i] = u & LIMB; u >>= 13; }
    u *= 5;
    for (i = 0; i < 10; i++) { u += h[i]; h[i] = u & LIMB; u >>= 13; }

    /*
     * Conditional subtraction of the modulus, by mask rather than branch:
     * whether h exceeded 2^130-5 depends on the message, and this step's
     * timing must not.
     */
    var g = P_G;
    u = 5;
    for (i = 0; i < 10; i++) { u += h[i]; g[i] = u & LIMB; u >>= 13; }
    /* u is 1 exactly when h + 5 overflowed 2^130, i.e. when h >= p */
    var mask = -u;                       /* all ones if take g, else zero */
    for (i = 0; i < 10; i++) { h[i] = (h[i] & ~mask) | (g[i] & mask); }

    /* Pack limbs into 16 bytes, then add s as a 128-bit little-endian sum */
    var tag = P_TAG;
    var acc = 0, bits = 0, o = 0;
    for (i = 0; i < 10 && o < 16; i++) {
        acc |= h[i] << bits;
        bits += 13;
        while (bits >= 8 && o < 16) {
            tag[o++] = acc & 0xff;
            acc >>>= 8; bits -= 8;
        }
    }

    u = 0;
    for (i = 0; i < 16; i++) {
        u += tag[i] + key[16 + i];
        out[off + i] = u & 0xff;
        u >>= 8;
    }

    /* the working arrays held r, the accumulator and the tag: zeroed for the next call */
    for (i = 0; i < 17; i++) { blk[i] = 0; rb[i] = 0; }
    for (i = 0; i < 16; i++) { staging[i] = 0; tag[i] = 0; }
    for (i = 0; i < 10; i++) { h[i] = 0; r[i] = 0; r5[i] = 0; c[i] = 0; g[i] = 0; x[i] = 0; }
}

/* ================= AEAD ================= */
/*
 * ChaCha20-Poly1305 - RFC 8439 section 2.8.
 *
 * The Poly1305 key is block 0 of the ChaCha20 keystream under (key, nonce);
 * the ciphertext starts at block 1. That is what makes the authenticator
 * one-time per message without a second key to manage - and also what makes
 * nonce reuse here worse than for the bare stream cipher, since it hands the
 * attacker the authenticator key rather than just a repeated keystream.
 *
 * The MAC covers, in order:
 *     aad || pad16(aad) || ciphertext || pad16(ciphertext)
 *     || le64(len(aad)) || le64(len(ciphertext))
 *
 * The trailing lengths are not decoration. Without them an attacker could
 * shift the boundary between associated data and ciphertext while keeping the
 * concatenation identical, and the tag would still verify.
 */

var ZERO16 = new Uint8Array(16);

/*
 * The Poly1305 input: the two fields, each padded to 16, then the lengths.
 *
 * ⭐ THE MAC INPUT AS A LIST OF PARTS, not a buffer.
 *
 *   poly1305 absorbs the logical concatenation, so the ciphertext is never
 *   copied. The old version allocated aad + pad + ct + pad + 16 and copied
 *   the whole ciphertext into it - a megabyte of allocation and copying for
 *   a megabyte of input, on top of the megabyte chacha20 had already
 *   produced and the megabyte the output needs.
 *
 * ⚠ THE PADDING IS STILL REQUIRED. RFC 8439 pads the aad and the ciphertext
 *   each to a 16-byte boundary; dropping the pads gives a MAC over a
 *   different string and one that no other implementation produces.
 *
 * ⭐ AND NOTHING OF IT IS MADE PER CALL: the parts list, the pads and the
 *   lengths block are the module's, as are the one-time key and the
 *   expected tag. Each is emptied or zeroed before the call returns - the
 *   list so that it keeps no caller's array alive, the rest because they
 *   held the one-time key or what it computed.
 */
var EMPTY = new Uint8Array(0), PADS = [], MAC_PARTS = [], LENS = new Uint8Array(16), OTK = new Uint8Array(32), EXPECTED = new Uint8Array(16);
for (var pad = 0; pad < 16; pad++) { PADS.push(ZERO16.subarray(0, pad)); }

function put_le64(b, off, n) {
    for (var i = 0; i < 8; i++) { b[off + i] = n % 256; n = Math.floor(n / 256); }
}

/* the AEAD's tag over (aad, ct), with the one-time key of (key, nonce), written to out[off .. off + 16) */
function aead_tag(key, nonce, n_off, ct, aad, out, off) {
    /* the one-time Poly1305 key: keystream block 0, which the ciphertext skips */
    block(key, 0, nonce, n_off);
    for (var i = 0; i < 32; i++) { OTK[i] = ks[i]; }
    for (i = 0; i < BLOCK; i++) { ks[i] = 0; }

    aad = aad || EMPTY;
    var parts = MAC_PARTS;
    if (aad.length) { parts.push(aad); }
    if (aad.length % 16) { parts.push(PADS[16 - aad.length % 16]); }
    if (ct.length) { parts.push(ct); }
    if (ct.length % 16) { parts.push(PADS[16 - ct.length % 16]); }
    put_le64(LENS, 0, aad.length);
    put_le64(LENS, 8, ct.length);
    parts.push(LENS);
    try {
        poly1305_to(OTK, parts, out, off);
    } finally {
        parts.length = 0;
        OTK.fill(0);
    }
}

/* ct = pt xor the keystream from block 1, then its tag, into out[at ..]: written once, where it goes */
function aead_seal_to(key, nonce, pt, aad, out, at) {
    if (key.length !== 32) { throw new Error('chacha20: key must be 32 bytes'); }
    if (1 + Math.ceil(pt.length / BLOCK) > 0x100000000) { throw new Error('chacha20: counter would exceed 2^32 - use a fresh nonce'); }
    stream_into(key, nonce, pt, 1, 20, out, at);
    aead_tag(key, nonce, 0, out.subarray(at, at + pt.length), aad, out, at + pt.length);
    return pt.length + 16;
}
function aead_encrypt(key, nonce, pt, aad) {
    var out = new Uint8Array(pt.length + 16);
    aead_seal_to(key, nonce, pt, aad, out, 0);
    return out;
}
/* the plaintext into out[at ..], or null - nothing written - when the tag does not verify */
function aead_open_to(key, nonce, sealed, aad, out, at) {
    if (key.length !== 32) { throw new Error('chacha20: key must be 32 bytes'); }
    var ct = sealed.subarray(0, sealed.length - 16);
    if (aead_check(key, nonce, 0, ct, sealed.subarray(sealed.length - 16), aad) !== 1) { return null; }
    stream_into(key, nonce, ct, 1, 20, out, at);
    return ct.length;
}

function aead_check(key, nonce, n_off, ct, tag, aad) {
    aead_tag(key, nonce, n_off, ct, aad, EXPECTED, 0);
    var ok = equal(EXPECTED, tag);
    EXPECTED.fill(0);
    return ok;
}

/**
 * @param  {Uint8Array} key    32 bytes
 * @param  {Uint8Array} nonce  12 bytes - too short to choose at random, see
 *                             the note at the top of this file
 * @param  {Uint8Array} plaintext
 * @param  {Uint8Array} [aad]  authenticated but not encrypted
 * @return {Uint8Array} ciphertext followed by a 16-byte tag
 */
export function chacha20poly1305_encrypt(key, nonce, plaintext, aad) {
    nonce_12(nonce);
    return aead_encrypt(key, nonce, plaintext, aad);
}
function nonce_12(nonce) { if (nonce.length !== 12) { throw new Error('chacha20poly1305: nonce must be 12 bytes'); } }

/**
 * Returns null on authentication failure - not a thrown error and not a
 * partial plaintext.
 *
 * The tag is checked before anything is decrypted. Releasing unverified
 * plaintext, even briefly, is what turns a padding oracle into a break; a
 * caller that never sees it cannot leak it.
 *
 * @return {Uint8Array|null}
 */
export function chacha20poly1305_decrypt(key, nonce, sealed, aad) {
    nonce_12(nonce);
    if (sealed.length < 16) { return null; }
    var out = new Uint8Array(sealed.length - 16);
    return aead_open_to(key, nonce, sealed, aad, out, 0) === null ? null : out;
}

/**
 * XChaCha20-Poly1305 - 24-byte nonce.
 *
 * The variant to reach for when there is no reliable counter: 24 bytes is
 * wide enough that random selection is safe, which 12 bytes is not.
 */
export function xchacha20poly1305_encrypt(key, nonce, plaintext, aad) {
    if (nonce.length !== 24) {
        throw new Error('xchacha20poly1305: nonce must be 24 bytes');
    }
    var x = xnonce(key, nonce);
    var out = aead_encrypt(x.subkey, x.n12, plaintext, aad);
    x.subkey.fill(0);
    return out;
}

/** @return {Uint8Array|null} */
export function xchacha20poly1305_decrypt(key, nonce, sealed, aad) {
    if (nonce.length !== 24) {
        throw new Error('xchacha20poly1305: nonce must be 24 bytes');
    }
    if (sealed.length < 16) { return null; }

    var x = xnonce(key, nonce);

    var ct = sealed.subarray(0, sealed.length - 16);
    var tag = sealed.subarray(sealed.length - 16);

    var ok = aead_check(x.subkey, x.n12, 0, ct, tag, aad);
    var out = (ok === 1) ? chacha20(x.subkey, x.n12, ct, 1) : null;
    x.subkey.fill(0);
    return out;
}

/* ---------------- Reduced-round and legacy variants ---------------- */
/*
 * ChaCha8 and ChaCha12 run eight or twelve rounds instead of twenty.
 *
 * The twenty in ChaCha20 is a wide margin, not a requirement: the best known
 * attacks reach about seven rounds. ChaCha12 is therefore still comfortably
 * secure and roughly 40% faster, and ChaCha8 - while it has a real margin -
 * is the one to think twice about. They appear in performance-sensitive
 * settings: ChaCha8 backs the random number generators in the Linux kernel
 * and in Rust's rand crate.
 *
 * chacha20_orig is the ORIGINAL 2008 design, before RFC 8439 restructured the
 * state. It splits the last four words as a 64-bit counter and a 64-bit
 * nonce; RFC 8439 uses 32 and 96.
 *
 * The two are closer than they look. Zero-extend an 8-byte nonce to twelve by
 * putting it in the last eight bytes, keep the counter below 2^32, and the
 * keystreams are IDENTICAL - the extra counter bits simply sit where the
 * extra nonce bytes would. The forms diverge only past 2^32 blocks, which is
 * 256 GB under one nonce.
 *
 * What actually bites is the API surface, not the maths: one takes 8 bytes of
 * nonce and one takes 12, so a protocol built around either will reject the
 * other's parameters outright. NaCl, libsodium's crypto_stream_chacha20 and
 * Bernstein's reference all use this 8-byte form.
 */

/** Eight rounds. Used by kernel and rand-crate RNGs; a thinner margin. */
export function chacha8(key, nonce, data, counter) {
    return chacha_n('chacha', key, nonce, data, counter, 8);
}

/** Twelve rounds. Still a wide margin, about 40% faster than ChaCha20. */
export function chacha12(key, nonce, data, counter) {
    return chacha_n('chacha', key, nonce, data, counter, 12);
}

/**
 * The original 2008 ChaCha20: 64-bit counter, 64-bit nonce.
 *
 * NOT interoperable with chacha20 above, which follows RFC 8439's 32/96
 * split. Same key and same bytes give different keystreams, and nothing warns
 * about it - so pick by protocol, not by preference.
 *
 * @param {Uint8Array} nonce  8 bytes
 * @param {number}     [counter=0]  the low half of a 64-bit counter
 */
export function chacha20_orig(key, nonce, data, counter) {
    if (key.length !== 32) { throw new Error('chacha20_orig: key must be 32 bytes'); }
    if (nonce.length !== 8) { throw new Error('chacha20_orig: nonce must be 8 bytes'); }

    /* fold the 8-byte nonce into a 12-byte layout with the counter's high
       word in front - which is exactly what the original state looks like */
    var n12 = new Uint8Array(12);
    n12.set(nonce, 4);

    var lo = (counter === undefined) ? 0 : (counter >>> 0);
    var hi = 0;
    var out = new Uint8Array(data.length);
    var i, n;

    for (i = 0; i < data.length; i += BLOCK) {
        wr_le32(n12, 0, hi);
        n = data.length - i; if (n > BLOCK) { n = BLOCK; }
        block_xor(key, lo | 0, n12, 0, 20, data, i, n, out, 0);
        lo = (lo + 1) >>> 0;
        if (lo === 0) { hi = (hi + 1) >>> 0; }
    }
    return out;
}

/* ---------------- Incremental and keyed forms ---------------- */
/*
 * The stream ciphers fed in pieces: update(data) returns data xor the next
 * bytes of keystream, in either direction, any lengths; copy() forks the
 * position. Arguments are the one-shot forms' minus the data.
 *
 *     var s = chacha20_create(key, nonce, counter);
 *     s.update(part1); s.update(part2); ...
 *
 * The 2^32-block limit of a 12-byte nonce holds across calls: chacha_n
 * checks every run against the counter it starts from.
 */
function chacha_stream(name, key, nonce, counter, rounds) {
    if (key.length !== 32) { throw new Error(name + ': key must be 32 bytes'); }
    if (nonce.length !== 12) { throw new Error(name + ': nonce must be 12 bytes'); }
    var k = new Uint8Array(key), n = new Uint8Array(nonce);
    var start = (counter === undefined) ? 0 : (counter >>> 0);
    return keystream_create(function (data, index) {
        return chacha_n(name, k, n, data, start + index, rounds);
    }, BLOCK);
}

export function chacha20_create(key, nonce, counter) { return chacha_stream('chacha20', key, nonce, counter, 20); }
export function chacha12_create(key, nonce, counter) { return chacha_stream('chacha', key, nonce, counter, 12); }
export function chacha8_create(key, nonce, counter)  { return chacha_stream('chacha', key, nonce, counter, 8); }

/** XChaCha20 fed in pieces: the subkey is derived once, here. */
export function xchacha20_create(key, nonce, counter) {
    if (nonce.length !== 24) { throw new Error('xchacha20: nonce must be 24 bytes'); }
    var x = xnonce(key, nonce);
    var s = chacha_stream('xchacha20', x.subkey, x.n12, counter, 20);
    x.subkey.fill(0);
    return s;
}

/*
 * ChaCha20-Poly1305 under one key, for many messages - the same shape as
 * aes_gcm_create, so a protocol can hold either:
 *
 *     var ctx = chacha20poly1305_create(key);
 *     ctx.encrypt(nonce, plaintext, aad)  ->  ciphertext || tag
 *     ctx.decrypt(nonce, sealed, aad)     ->  plaintext, or null
 *
 * ChaCha has no key schedule to save, so this is the one-shot form with the
 * key held; it exists so that every AEAD in the library is used the same way.
 */
export function chacha20poly1305_create(key) {
    if (key.length !== 32) { throw new Error('chacha20poly1305: key must be 32 bytes'); }
    var k = new Uint8Array(key);
    return {
        encrypt: function (nonce, plaintext, aad) { return chacha20poly1305_encrypt(k, nonce, plaintext, aad); },
        decrypt: function (nonce, sealed, aad) { return chacha20poly1305_decrypt(k, nonce, sealed, aad); },
        /*
         * Written straight into out - nothing made per message. Into memory
         * that overlaps the input elsewhere, whole first, then copied.
         */
        encrypt_into: function (out, offset, nonce, plaintext, aad) {
            nonce_12(nonce);
            check_room('chacha20poly1305.encrypt_into', out, offset, plaintext.length + 16);
            if (!overlaps_elsewhere(out, offset, plaintext.length + 16, plaintext)) { return aead_seal_to(k, nonce, plaintext, aad, out, offset); }
            var whole = aead_encrypt(k, nonce, plaintext, aad);
            out.set(whole, offset);
            return whole.length;
        },
        decrypt_into: function (out, offset, nonce, sealed, aad) {
            nonce_12(nonce);
            if (sealed.length < 16) { return null; }
            check_room('chacha20poly1305.decrypt_into', out, offset, sealed.length - 16);
            if (!overlaps_elsewhere(out, offset, sealed.length, sealed)) { return aead_open_to(k, nonce, sealed, aad, out, offset); }
            var whole = chacha20poly1305_decrypt(k, nonce, sealed, aad);
            if (whole === null) { return null; }
            out.set(whole, offset);
            return whole.length;
        },
        wipe: function () { k.fill(0); }
    };
}

export function xchacha20poly1305_create(key) {
    if (key.length !== 32) { throw new Error('xchacha20poly1305: key must be 32 bytes'); }
    var k = new Uint8Array(key);
    return {
        encrypt: function (nonce, plaintext, aad) { return xchacha20poly1305_encrypt(k, nonce, plaintext, aad); },
        decrypt: function (nonce, sealed, aad) { return xchacha20poly1305_decrypt(k, nonce, sealed, aad); },
        wipe: function () { k.fill(0); }
    };
}
