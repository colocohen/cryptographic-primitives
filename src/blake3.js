/**
 * BLAKE3
 *
 * The G function is the same ARX quarter-round as BLAKE2s, with the same
 * rotations (16, 12, 8, 7). Everything around it is different.
 *
 * BLAKE2 is a chain: each block folds into a running state, so hashing is
 * inherently sequential. BLAKE3 is a binary Merkle tree. The message is cut
 * into 1024-byte chunks, each chunk is hashed independently, and the chunk
 * results are combined pairwise up to a single root. Chunks have no data
 * dependency on each other, which is what makes BLAKE3 parallelisable and
 * verifiable in pieces. This implementation is single-threaded and gets no
 * speed from that, but the tree shape is part of the output definition and
 * has to be reproduced exactly regardless.
 *
 * Two further consequences of the tree:
 *   - Output is an XOF. The root node is squeezed by incrementing a counter,
 *     so any output length is available at no extra cost.
 *   - Every node carries flags saying where it sits (chunk start, chunk end,
 *     parent, root). Domain separation is structural rather than a padding
 *     byte, which is what lets one compression function serve every role.
 *
 * All 32-bit. No manual carry anywhere, unlike sha512/blake2b/xxhash64.
 *
 * THREE MODES, ONE COMPRESSION FUNCTION
 * The BLAKE3 spec defines three modes, all exported here. They are all
 * one-way hashing - none of them encrypt - but they occupy three different
 * functional roles, separated only by flag bits:
 *
 *     blake3()             plain hash        unkeyed digest / XOF
 *     blake3_keyed()       MAC               the role HMAC plays for SHA-2
 *     blake3_derive_key()  KDF               the role HKDF plays for SHA-2
 *
 * Because the key enters through the IV rather than an outer wrapper, the
 * keyed mode costs exactly one pass - HMAC costs two. The same is true of
 * BLAKE2's keyed mode and of SHA-3, and it is a consequence of these
 * constructions not being vulnerable to length extension in the first place.
 *
 * PERFORMANCE IN JS - READ BEFORE CHOOSING THIS
 * Measured here on 64 KB, single-threaded:
 *
 *     xxhash64  185 MB/s      blake2s   58 MB/s
 *     sha256     94 MB/s      blake2b   23 MB/s
 *     blake3     64 MB/s      sha3_256  14 MB/s
 *
 * BLAKE3 is slower than SHA-256 here, which inverts its reputation. That
 * reputation is earned in compiled code, where its real advantage is
 * parallelism: independent chunks let it use SIMD lanes and multiple cores.
 * This implementation is single-threaded and gets none of that, so the tree
 * is pure overhead rather than a win. The tree shape is still mandatory -
 * it defines the output - so it cannot be simplified away.
 *
 * Pick BLAKE3 here for its XOF, its keyed mode, its derive_key mode, or for
 * wire compatibility with a BLAKE3 peer. Do not pick it in this library
 * expecting it to be the fast one.
 */

import { arx_g32, arx_round32 } from './commons/arx32.js';
import { equal_bool } from './commons/ct.js';
import { wr_le32, wr_le32s, rd_le32 } from './commons/bytes.js';

var BLOCK_LEN = 64;
var CHUNK_LEN = 1024;
var OUT_LEN   = 32;
var KEY_LEN   = 32;
var ROUNDS    = 7;

/* Node position flags. These are the domain separation. */
var CHUNK_START         = 1 << 0;
var CHUNK_END           = 1 << 1;
var PARENT              = 1 << 2;
var ROOT                = 1 << 3;
var KEYED_HASH          = 1 << 4;
var DERIVE_KEY_CONTEXT  = 1 << 5;
var DERIVE_KEY_MATERIAL = 1 << 6;

/* Same IV as SHA-256 and BLAKE2s, by design. Not shared as code - see
   the note in commons/arx32.js on behaviour versus equal values. */
var IV = new Int32Array([
    0x6a09e667|0, 0xbb67ae85|0, 0x3c6ef372|0, 0xa54ff53a|0,
    0x510e527f|0, 0x9b05688c|0, 0x1f83d9ab|0, 0x5be0cd19|0
]);

/* Applied between rounds instead of BLAKE2's per-round SIGMA table */
var PERM = new Int32Array([2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]);

var SIGMA3 = (function () { var t = new Int32Array(16 * 7), p = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    for (var r = 0; r < 7; r++) { for (var j = 0; j < 16; j++) t[r * 16 + j] = p[j]; p = p.map(function (_, j) { return p[PERM[j]]; }); } return t; }());
/* Working state, allocated once */
var st = new Int32Array(16);
var m  = new Int32Array(16);
var mp = new Int32Array(16);

/**
 * The single compression function. Every role in the tree - chunk block,
 * parent node, root output - goes through this, distinguished only by flags.
 *
 * Leaves the 16-word result in st. Callers take the first 8 words as a
 * chaining value, or all 16 as output bytes.
 */
function compress(cv, cv_off, block, block_off, ctr_lo, ctr_hi, block_len, flags) {
    var i, r, a, b, c, d;

    for (i = 0; i < 16; i++) {
        m[i] = ((block[block_off]) | (block[block_off + 1] << 8) |
                (block[block_off + 2] << 16) | (block[block_off + 3] << 24)) | 0;
        block_off += 4;
    }

    for (i = 0; i < 8; i++) { st[i] = cv[cv_off + i]; }
    st[8]  = IV[0]; st[9]  = IV[1]; st[10] = IV[2]; st[11] = IV[3];
    st[12] = ctr_lo; st[13] = ctr_hi; st[14] = block_len | 0; st[15] = flags | 0;

    for (r = 0; r < ROUNDS; r++) { arx_round32(st, m, SIGMA3, r * 16); }

    for (i = 0; i < 8; i++) {
        st[i]     ^= st[i + 8];
        st[i + 8] ^= cv[cv_off + i];
    }
}

/**
 * Hash one chunk into an 8-word chaining value.
 * The chunk's blocks chain through cv; the first carries CHUNK_START and
 * the last CHUNK_END, so a chunk's position is unforgeable.
 */
function chunk_cv(msg, off, len, ctr_lo, ctr_hi, key, flags, out, out_off) {
    var cv = new Int32Array(8);
    var i, block_len, start;
    var pos = 0;
    var pad = null;

    for (i = 0; i < 8; i++) { cv[i] = key[i]; }

    while (pos < len) {
        block_len = len - pos;
        if (block_len > BLOCK_LEN) { block_len = BLOCK_LEN; }
        start = (pos === 0) ? CHUNK_START : 0;

        var is_last = (pos + block_len >= len);
        var end = is_last ? CHUNK_END : 0;

        if (block_len === BLOCK_LEN) {
            compress(cv, 0, msg, off + pos, ctr_lo, ctr_hi, BLOCK_LEN, flags | start | end);
        } else {
            /* Short final block is zero padded, but block_len records the truth */
            if (pad === null) { pad = new Uint8Array(BLOCK_LEN); }
            for (i = 0; i < BLOCK_LEN; i++) { pad[i] = 0; }
            for (i = 0; i < block_len; i++) { pad[i] = msg[off + pos + i]; }
            compress(cv, 0, pad, 0, ctr_lo, ctr_hi, block_len, flags | start | end);
        }
        for (i = 0; i < 8; i++) { cv[i] = st[i]; }
        pos += block_len;
    }

    /* An empty message is still one chunk: a single empty block */
    if (len === 0) {
        if (pad === null) { pad = new Uint8Array(BLOCK_LEN); }
        for (i = 0; i < BLOCK_LEN; i++) { pad[i] = 0; }
        compress(cv, 0, pad, 0, ctr_lo, ctr_hi, 0, flags | CHUNK_START | CHUNK_END);
        for (i = 0; i < 8; i++) { cv[i] = st[i]; }
    }

    for (i = 0; i < 8; i++) { out[out_off + i] = cv[i]; }
}

/** Combine two child chaining values into a parent block. */
function parent_block(left, left_off, right, right_off, block) {
    for (var i = 0; i < 8; i++) {
        wr_le32(block, i * 4, left[left_off + i]);
        wr_le32(block, 32 + i * 4, right[right_off + i]);
    }
}

/**
 * A parent node's chaining value, written into out[0..8).
 *
 * ⭐ ONE COPY OF "BLOCK, COMPRESS, TAKE EIGHT WORDS". blake3_core wrote it out
 *   twice - once while pushing chunks, once while collapsing the stack - and
 *   tree_parent_cv a third time for the proof functions.
 *
 * ⚠ `out` MAY BE ONE OF THE CHILDREN, and blake3_core passes `cur` as both:
 *   parent_block has copied both children into the byte block before
 *   compress runs, so nothing is read after out is written.
 */
function parent_cv(left, left_off, right, right_off, key, flags, block, out) {
    parent_block(left, left_off, right, right_off, block);
    compress(key, 0, block, 0, 0, 0, BLOCK_LEN, flags | PARENT);
    for (var j = 0; j < 8; j++) { out[j] = st[j]; }
}

/**
 * Core driver. Builds the tree, then squeezes the root for out_len bytes.
 *
 * @param {Uint8Array} msg
 * @param {number}     out_len
 * @param {Int32Array} key    8 words - IV for plain hashing, key words otherwise
 * @param {number}     flags  0, KEYED_HASH, or DERIVE_KEY_MATERIAL
 */
function blake3_core(msg, out_len, key, flags) {
    var len = msg.length;
    var n_chunks = len === 0 ? 1 : Math.ceil(len / CHUNK_LEN);
    var i, j;

    /*
     * Subtree stack. Each entry is a completed subtree of some power-of-two
     * size. A new chunk merges with the top as long as the count of chunks
     * seen so far is even - exactly the condition for two complete subtrees
     * of equal size sitting adjacent. Depth is bounded by 54, covering 2^54
     * chunks, which is more than the addressable message space.
     */
    var stack = new Int32Array(54 * 8);
    var depth = 0;
    var cur = new Int32Array(8);
    var pblock = new Uint8Array(BLOCK_LEN);

    /*
     * Every chunk except the last. The final chunk is deliberately held back:
     * in BLAKE3 it never enters the stack, it becomes the pending node that
     * the stack collapses into, and that node is what carries ROOT.
     */
    for (i = 0; i < n_chunks - 1; i++) {
        chunk_cv(msg, i * CHUNK_LEN, CHUNK_LEN,
                 i | 0, (i / 0x100000000) | 0, key, flags, cur, 0);

        var total = i + 1;
        while ((total & 1) === 0) {
            depth--;
            parent_cv(stack, depth * 8, cur, 0, key, flags, pblock, cur);
            total >>= 1;
        }
        for (j = 0; j < 8; j++) { stack[depth * 8 + j] = cur[j]; }
        depth++;
    }

    /*
     * A message of one chunk or less has no parent nodes at all - the root is
     * the chunk's own final block, so it has to be squeezed rather than
     * finished into a chaining value.
     */
    if (depth === 0) {
        return squeeze_single_chunk(msg, len, out_len, key, flags);
    }

    var last = n_chunks - 1;
    var last_off = last * CHUNK_LEN;
    var last_len = len - last_off;
    chunk_cv(msg, last_off, last_len,
             last | 0, (last / 0x100000000) | 0, key, flags, cur, 0);

    /* Collapse the stack into the pending node, deepest entry last */
    while (depth > 1) {
        depth--;
        parent_cv(stack, depth * 8, cur, 0, key, flags, pblock, cur);
    }

    /*
     * The last merge is the root. It is squeezed instead of finished, and
     * only it carries ROOT - which is why a truncated BLAKE3 digest is never
     * the digest of some shorter input.
     */
    parent_block(stack, 0, cur, 0, pblock);
    return squeeze(key, pblock, 0, 0, BLOCK_LEN, flags | PARENT | ROOT, out_len);
}

/** A message of one chunk or less: the root is the chunk's last block. */
function squeeze_single_chunk(msg, len, out_len, key, flags) {
    var cv = new Int32Array(8);
    var pad = new Uint8Array(BLOCK_LEN);
    var i, pos = 0, block_len, start;

    for (i = 0; i < 8; i++) { cv[i] = key[i]; }

    while (len - pos > BLOCK_LEN) {
        start = (pos === 0) ? CHUNK_START : 0;
        compress(cv, 0, msg, pos, 0, 0, BLOCK_LEN, flags | start);
        for (i = 0; i < 8; i++) { cv[i] = st[i]; }
        pos += BLOCK_LEN;
    }

    block_len = len - pos;
    start = (pos === 0) ? CHUNK_START : 0;
    for (i = 0; i < BLOCK_LEN; i++) { pad[i] = 0; }
    for (i = 0; i < block_len; i++) { pad[i] = msg[pos + i]; }

    return squeeze(cv, pad, 0, 0, block_len, flags | start | CHUNK_END | ROOT, out_len);
}

/**
 * Extendable output. The root node is compressed repeatedly with an
 * increasing counter; each pass yields 64 bytes.
 */
function squeeze(cv, block, ctr_lo, ctr_hi, block_len, flags, out_len) {
    var out = new Uint8Array(out_len);
    var produced = 0, i, w, lo = ctr_lo, hi = ctr_hi;

    while (produced < out_len) {
        compress(cv, 0, block, 0, lo, hi, block_len, flags);
        for (i = 0; i < 16 && produced < out_len; i++) {
            w = st[i];
            out[produced++] = w & 0xff;
            if (produced < out_len) { out[produced++] = (w >>> 8) & 0xff; }
            if (produced < out_len) { out[produced++] = (w >>> 16) & 0xff; }
            if (produced < out_len) { out[produced++] = (w >>> 24) & 0xff; }
        }
        lo = (lo + 1) | 0;
        if (lo === 0) { hi = (hi + 1) | 0; }
    }
    return out;
}

/**
 * @param  {Uint8Array} msg
 * @param  {number}     [out_len=32]  any positive length - BLAKE3 is an XOF
 * @return {Uint8Array}
 */
export function blake3(msg, out_len) {
    if (out_len === undefined) { out_len = OUT_LEN; }
    return blake3_core(msg, out_len, IV, 0);
}

/**
 * Keyed mode. Replaces HMAC - the key goes into the IV rather than through
 * an outer construction, so there is no wrapping and no extra pass.
 *
 * @param  {Uint8Array} msg
 * @param  {Uint8Array} key           exactly 32 bytes
 * @param  {number}     [out_len=32]
 * @return {Uint8Array}
 */
export function blake3_keyed(msg, key, out_len) {
    if (key.length !== KEY_LEN) {
        throw new Error('blake3_keyed: key must be exactly ' + KEY_LEN + ' bytes');
    }
    if (out_len === undefined) { out_len = OUT_LEN; }
    return blake3_core(msg, out_len, key_words(key), KEYED_HASH);
}

/**
 * Key derivation. Two passes: the context string is hashed to 32 bytes, and
 * that result keys a second pass over the key material.
 *
 * The context string must be a hardcoded, globally unique application
 * constant - never user input, never a secret, and never assembled at
 * runtime. The convention is to include the application name and a fixed
 * timestamp, for example:
 *
 *     "example.com 2024-01-15 16:29:52 session tokens v1"
 *
 * Its only job is to make sure that two different uses of the same master
 * key produce unrelated output, so it must differ per purpose and must
 * never change for a given purpose once deployed.
 *
 * @param  {Uint8Array} context       UTF-8 bytes of the context string
 * @param  {Uint8Array} key_material
 * @param  {number}     [out_len=32]
 * @return {Uint8Array}
 */
export function blake3_derive_key(context, key_material, out_len) {
    if (out_len === undefined) { out_len = OUT_LEN; }
    var ck = blake3_core(context, 32, IV, DERIVE_KEY_CONTEXT);
    return blake3_core(key_material, out_len, key_words(ck), DERIVE_KEY_MATERIAL);
}

/* Sizes are attached inside a PURE-annotated wrapper so a bundler can drop
   the export entirely when it is unused. A bare top-level assignment is a
   side effect it cannot prove safe. */
blake3.BLOCK_SIZE  = BLOCK_LEN;
blake3.DIGEST_SIZE = OUT_LEN;
blake3.CHUNK_SIZE  = CHUNK_LEN;

/* ---------------- the tree: verified streaming ---------------- */
/**
 * BLAKE3's Merkle tree, exposed.
 *
 * This is the part that makes BLAKE3 different from every other hash here,
 * and hashing a whole buffer - which is all the API above does - hides it
 * entirely.
 *
 * THE INPUT IS A TREE, NOT A CHAIN. Data is split into 1024-byte chunks, each
 * hashed independently, and their chaining values combined pairwise up a
 * binary tree. SHA-2 and SHA-3 are strictly sequential: byte n cannot be
 * processed before byte n-1, so a digest says nothing about any part of the
 * message on its own.
 *
 * WHAT THE TREE BUYS:
 *
 *   - VERIFIED STREAMING. A peer sends chunk 4271 of a large file along with
 *     a short proof; the receiver checks it against the root hash it already
 *     trusts and can USE the chunk immediately, or discard it and ask someone
 *     else. No need to hold the whole file, and no need to trust the sender.
 *     This is what BitTorrent builds as a separate layer over SHA-1. Here it
 *     is the hash function.
 *
 *   - OUT-OF-ORDER AND PARALLEL HASHING. Chunks can be hashed on different
 *     cores, in any order, and combined afterwards.
 *
 *   - INCREMENTAL UPDATE. Changing one chunk of a large file requires
 *     recomputing one chunk and log2(n) parent nodes, not the whole thing.
 *
 * THE TREE SHAPE IS NOT BALANCED, and this is the detail an implementation
 * gets wrong. BLAKE3 splits a subtree so that the LEFT side holds the largest
 * power of two of chunks that is strictly less than the total. For five
 * chunks the split is 4 and 1, not 3 and 2. Getting that wrong produces a
 * tree that is self-consistent and computes a different root than every other
 * BLAKE3 implementation.
 */

/** A chaining value as 32 little-endian bytes, and back. */
function cv_bytes(cv) {
    var out = new Uint8Array(32);
    wr_le32s(out, 0, cv);
    return out;
}

/*
 * ⭐ THE OTHER DIRECTION IS key_words, which follows. A chaining value read
 *   back from bytes and a key read into words are the same eight
 *   little-endian loads, and this file used to write them four times: here
 *   as bytes_cv, in key_words, and inline in blake3_keyed and
 *   blake3_derive_key.
 */

/**
 * 32 bytes as eight little-endian words: a key, a derived context key, or a
 * chaining value carried in a proof.
 */
function key_words(key) {
    var kw = new Int32Array(8);
    for (var i = 0; i < 8; i++) { kw[i] = rd_le32(key, 4 * i); }
    return kw;
}

/** Chunks in the left subtree of a subtree spanning `chunks` chunks. */
function left_chunks(chunks) {
    var n = 1;
    while (n * 2 < chunks) { n *= 2; }
    return n;
}

/** The chaining value of one chunk, at its position in the tree. */
function tree_chunk_cv(msg, off, len, index, key, flags) {
    var out = new Int32Array(8);
    chunk_cv(msg, off, len, index & 0xffffffff, Math.floor(index / 4294967296),
             key, flags, out, 0);
    return out;
}

function tree_parent_cv(left, right, key, flags) {
    /* parent_block wants a BYTE buffer, and compress leaves its result in
       the module-level st rather than returning it - parent_cv handles both */
    var out = new Int32Array(8);
    parent_cv(left, 0, right, 0, key, flags, new Uint8Array(BLOCK_LEN), out);
    return out;
}

/**
 * The chaining value of the subtree covering chunks [start, start+count).
 *
 * Not the root: the ROOT flag is applied only once, at the very top, which is
 * why a subtree's value can never be mistaken for a whole file's digest.
 */
function subtree_cv(msg, start, count, key, flags) {
    if (count === 1) {
        var off = start * CHUNK_LEN;
        var len = Math.min(CHUNK_LEN, msg.length - off);
        return tree_chunk_cv(msg, off, len, start, key, flags);
    }
    var l = left_chunks(count);
    return tree_parent_cv(subtree_cv(msg, start, l, key, flags),
                          subtree_cv(msg, start + l, count - l, key, flags),
                          key, flags);
}

function chunk_count(len) {
    return len <= CHUNK_LEN ? 1 : Math.ceil(len / CHUNK_LEN);
}

/**
 * An inclusion proof for one chunk: the sibling chaining values from the
 * chunk up to the root, closest first.
 *
 * @return {{index: number, siblings: Array<Uint8Array>, is_right: Array<boolean>}}
 */
export function blake3_proof(msg, index, key) {
    var flags = 0, k = IV;
    if (key !== undefined) {
        if (key.length !== KEY_LEN) { throw new Error('blake3_proof: key must be 32 bytes'); }
        k = key_words(key); flags = KEYED_HASH;
    }
    var total = chunk_count(msg.length);
    if (index < 0 || index >= total) { throw new Error('blake3_proof: chunk index out of range'); }

    var siblings = [], is_right = [];
    var start = 0, count = total;

    while (count > 1) {
        var l = left_chunks(count);
        if (index - start < l) {
            /* our chunk is on the left, so the right subtree is the sibling */
            siblings.push(cv_bytes(subtree_cv(msg, start + l, count - l, k, flags)));
            is_right.push(false);
            count = l;
        } else {
            siblings.push(cv_bytes(subtree_cv(msg, start, l, k, flags)));
            is_right.push(true);
            start += l;
            count -= l;
        }
    }
    siblings.reverse();
    is_right.reverse();
    return { index: index, siblings: siblings, is_right: is_right, total_len: msg.length };
}

/**
 * Verify a chunk against a trusted root, without the rest of the file.
 *
 * @param {Uint8Array} root   32 bytes, the digest already trusted
 * @param {Uint8Array} chunk  the chunk's bytes
 * @param {object}     proof  from blake3_proof
 * @return {boolean}
 *
 * The chunk's INDEX and the file's TOTAL LENGTH are both bound in - the index
 * through the chunk counter, the length through the tree's shape. A chunk
 * cannot be moved to a different position or replayed into a different file.
 */
export function blake3_verify_chunk(root, chunk, proof, key) {
    var flags = 0, k = IV;
    if (key !== undefined) {
        if (key.length !== KEY_LEN) { return false; }
        k = key_words(key); flags = KEYED_HASH;
    }
    if (root.length !== 32) { return false; }

    var total = chunk_count(proof.total_len);
    if (proof.index < 0 || proof.index >= total) { return false; }
    if (proof.siblings.length !== proof.is_right.length) { return false; }

    var expected_len = Math.min(CHUNK_LEN, proof.total_len - proof.index * CHUNK_LEN);
    if (chunk.length !== expected_len) { return false; }

    var cv = tree_chunk_cv(chunk, 0, chunk.length, proof.index, k, flags);

    /* a single-chunk file has no parents, and the chunk itself carries ROOT */
    if (total === 1) {
        var single = squeeze_single_chunk(chunk, chunk.length, 32, k, flags);
        return equal_bool(single, root);
    }

    var i;
    for (i = 0; i < proof.siblings.length - 1; i++) {
        var s = key_words(proof.siblings[i]);
        cv = proof.is_right[i] ? tree_parent_cv(s, cv, k, flags)
                               : tree_parent_cv(cv, s, k, flags);
    }

    /* the topmost combination is the one that carries ROOT */
    var last = key_words(proof.siblings[proof.siblings.length - 1]);
    var l = proof.is_right[i] ? last : cv;
    var r = proof.is_right[i] ? cv : last;
    var block = new Uint8Array(BLOCK_LEN);
    parent_block(l, 0, r, 0, block);
    var out = squeeze(k, block, 0, 0, BLOCK_LEN, flags | PARENT | ROOT, 32);
    return equal_bool(out, root);
}

/** How many 1024-byte chunks a message of this length has. */
export function blake3_chunk_count(len) { return chunk_count(len); }

export var BLAKE3_CHUNK_LEN = CHUNK_LEN;

/* ---------------- Incremental ---------------- */

/*
 * The same hashes, fed in pieces: update() as often as needed, digest()
 * once; copy() forks the state. Same arguments as the one-shot forms, minus
 * the message.
 *
 * ⭐ THE TREE IS BUILT AS THE INPUT ARRIVES, the way the BLAKE3 paper's
 *   reference hasher does it: a chunk is finished only once more input
 *   arrives (the last chunk is the root's child, or the root itself, and is
 *   flagged differently), and a finished chunk's chaining value is merged
 *   into the stack as far as the chunk count's trailing zero bits allow. The
 *   stack holds one chaining value per set bit of the count - at most 54.
 *
 * ⚠ blake3_core above stays the one-shot path: it sees the whole message
 *   and does not need to hold a chunk back. Both are checked against each
 *   other at every length around the block and chunk boundaries.
 */
function blake3_create_core(out_len, key, flags) {
    if (out_len === undefined) { out_len = OUT_LEN; }
    var cv = new Int32Array(8);
    for (var i = 0; i < 8; i++) { cv[i] = key[i]; }
    return blake3_instance({
        out_len: out_len, key: key, flags: flags,
        cv: cv, block: new Uint8Array(BLOCK_LEN), block_len: 0,
        blocks: 0, chunk: 0,
        stack: new Int32Array(54 * 8), depth: 0
    });
}

function blake3_clone(s) {
    return {
        out_len: s.out_len, key: s.key, flags: s.flags,
        cv: new Int32Array(s.cv), block: new Uint8Array(s.block), block_len: s.block_len,
        blocks: s.blocks, chunk: s.chunk,
        stack: new Int32Array(s.stack), depth: s.depth
    };
}

function blake3_instance(s) {
    var done = false;
    var pblock = new Uint8Array(BLOCK_LEN);

    function check() {
        if (done) { throw new Error('blake3: digest() was already called on this instance'); }
    }

    /* Compress the buffered block into the chunk's chaining value. */
    function compress_block() {
        compress(s.cv, 0, s.block, 0, s.chunk | 0, (s.chunk / 0x100000000) | 0,
                 BLOCK_LEN, s.flags | (s.blocks === 0 ? CHUNK_START : 0));
        for (var i = 0; i < 8; i++) { s.cv[i] = st[i]; }
        s.blocks++;
        s.block_len = 0;
    }

    /* The full current chunk is not the last: finish it and merge it in. */
    function finish_chunk() {
        compress(s.cv, 0, s.block, 0, s.chunk | 0, (s.chunk / 0x100000000) | 0,
                 BLOCK_LEN, s.flags | (s.blocks === 0 ? CHUNK_START : 0) | CHUNK_END);
        var cur = new Int32Array(8), i;
        for (i = 0; i < 8; i++) { cur[i] = st[i]; }
        var total = s.chunk + 1;
        while (total % 2 === 0) {
            s.depth--;
            parent_cv(s.stack, s.depth * 8, cur, 0, s.key, s.flags, pblock, cur);
            total = total / 2;
        }
        for (i = 0; i < 8; i++) { s.stack[s.depth * 8 + i] = cur[i]; }
        s.depth++;
        s.chunk++;
        for (i = 0; i < 8; i++) { s.cv[i] = s.key[i]; }
        s.blocks = 0;
        s.block_len = 0;
    }

    var self = {
        update: function (msg) {
            check();
            var len = msg.length, off = 0, i;
            while (off < len) {
                if (s.block_len === BLOCK_LEN) {
                    if (s.blocks === CHUNK_LEN / BLOCK_LEN - 1) { finish_chunk(); }
                    else { compress_block(); }
                }
                var take = BLOCK_LEN - s.block_len;
                if (take > len - off) { take = len - off; }
                for (i = 0; i < take; i++) { s.block[s.block_len + i] = msg[off + i]; }
                s.block_len += take;
                off += take;
            }
            return self;
        },
        copy: function () {
            check();
            return blake3_instance(blake3_clone(s));
        },
        digest: function () {
            check();
            done = true;
            var i;
            for (i = s.block_len; i < BLOCK_LEN; i++) { s.block[i] = 0; }
            var chunk_flags = s.flags | (s.blocks === 0 ? CHUNK_START : 0) | CHUNK_END;
            if (s.depth === 0) {
                return squeeze(s.cv, s.block, 0, 0, s.block_len, chunk_flags | ROOT, s.out_len);
            }
            var cur = new Int32Array(8);
            compress(s.cv, 0, s.block, 0, s.chunk | 0, (s.chunk / 0x100000000) | 0, s.block_len, chunk_flags);
            for (i = 0; i < 8; i++) { cur[i] = st[i]; }
            var depth = s.depth;
            while (depth > 1) {
                depth--;
                parent_cv(s.stack, depth * 8, cur, 0, s.key, s.flags, pblock, cur);
            }
            parent_block(s.stack, 0, cur, 0, pblock);
            return squeeze(s.key, pblock, 0, 0, BLOCK_LEN, s.flags | PARENT | ROOT, s.out_len);
        }
    };
    return self;
}

/** @return {{update: function(Uint8Array): object, copy: function(): object, digest: function(): Uint8Array}} */
export function blake3_create(out_len) {
    return blake3_create_core(out_len, IV, 0);
}

/** @return {{update: function(Uint8Array): object, copy: function(): object, digest: function(): Uint8Array}} */
export function blake3_keyed_create(key, out_len) {
    if (key.length !== KEY_LEN) {
        throw new Error('blake3_keyed_create: key must be exactly ' + KEY_LEN + ' bytes');
    }
    return blake3_create_core(out_len, key_words(key), KEYED_HASH);
}

/** The key material fed in pieces; the context is given whole, as bytes, as in the one-shot form. */
export function blake3_derive_key_create(context, out_len) {
    var ck = blake3_core(context, 32, IV, DERIVE_KEY_CONTEXT);
    return blake3_create_core(out_len, key_words(ck), DERIVE_KEY_MATERIAL);
}
