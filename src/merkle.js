/**
 * Merkle trees over any hash
 *
 * A tree of hashes where each node is the hash of its two children, so a
 * single root value commits to every leaf. Proving that one leaf is in there
 * costs log2(n) hashes rather than the whole set.
 *
 * WHY THIS EXISTS ALONGSIDE blake3.js. That file has a Merkle tree too, but
 * it is BLAKE3's own - fixed 1024-byte chunks, BLAKE3's domain separation
 * flags, and its particular unbalanced split. It is the right thing when you
 * control both ends and want speed. This one is the right thing when the hash
 * is already decided: a chain that hashes with SHA-256, a certificate
 * transparency log, a peer that expects a specific format.
 *
 * ===================== SECOND-PREIMAGE, AND THE PREFIX BYTES =====================
 *
 * The naive construction is broken, and the break is subtle enough that it
 * shipped in Bitcoin and is still there.
 *
 * If leaves and internal nodes are hashed the same way, an attacker can take
 * an INTERNAL node and present it as a leaf. A tree of four leaves has the
 * same root as a tree of two leaves whose values happen to be the two
 * internal hashes - so a proof for one is a proof for the other, and "this
 * data is in the tree" stops meaning anything definite.
 *
 * The fix, from RFC 6962, is a domain separation byte:
 *
 *     leaf(x)      = H(0x00 || x)
 *     parent(l, r) = H(0x01 || l || r)
 *
 * One byte, and the two can never be confused. This library uses it, which
 * means these roots do NOT match a naive implementation's - that is
 * deliberate and is the same trade-off RFC 6962 made.
 *
 * ODD NODE COUNTS. Bitcoin duplicates the last hash when a level has an odd
 * count, which introduces a DIFFERENT vulnerability: two distinct transaction
 * lists can produce the same root (CVE-2012-2459). This implementation
 * PROMOTES the odd node to the next level unchanged instead, which is what
 * RFC 6962 does and what avoids the collision.
 */

import { concat, be32, rd_be32u } from './commons/bytes.js';
import { equal_bool } from './commons/ct.js';

var LEAF_PREFIX = /* @__PURE__ */ new Uint8Array([0x00]);
var NODE_PREFIX = /* @__PURE__ */ new Uint8Array([0x01]);

/** H(0x00 || data) - the domain-separated leaf hash. */
export function hash_leaf(hash, data) {
    return hash(concat([LEAF_PREFIX, data]));
}

/** H(0x01 || left || right) */
export function hash_node(hash, left, right) {
    return hash(concat([NODE_PREFIX, left, right]));
}

/**
 * Build the whole tree, bottom up.
 *
 * @param  {function}             hash    e.g. sha256
 * @param  {Array<Uint8Array>}    leaves  the raw values, NOT pre-hashed
 * @return {Array<Array<Uint8Array>>}  levels[0] is the leaf hashes,
 *                                     the last level is [root]
 */
export function build(hash, leaves) {
    if (leaves.length === 0) { throw new Error('merkle: no leaves'); }

    var level = [];
    for (var i = 0; i < leaves.length; i++) {
        level.push(hash_leaf(hash, leaves[i]));
    }

    var levels = [level];
    while (level.length > 1) {
        var next = [];
        for (var j = 0; j < level.length; j += 2) {
            if (j + 1 < level.length) {
                next.push(hash_node(hash, level[j], level[j + 1]));
            } else {
                /* an odd node is PROMOTED, not duplicated - see the note above */
                next.push(level[j]);
            }
        }
        levels.push(next);
        level = next;
    }
    return levels;
}

/** @return {Uint8Array} the root */
export function root(hash, leaves) {
    var levels = build(hash, leaves);
    return levels[levels.length - 1][0];
}

/**
 * The proof that leaf `index` is in the tree.
 *
 * @return {{index: number, count: number, path: Array<{hash, right}>}}
 *   `right` says which side the sibling is on, which the verifier needs
 *   because H(a||b) and H(b||a) differ. Sorting the pair instead - as some
 *   implementations do to avoid carrying the flag - loses the leaf's POSITION,
 *   and a proof that does not fix the position lets a leaf be relocated.
 */
export function proof(hash, leaves, index) {
    if (index < 0 || index >= leaves.length) { throw new Error('merkle: index out of range'); }
    var levels = build(hash, leaves);
    var path = [];
    var idx = index;

    for (var L = 0; L < levels.length - 1; L++) {
        var level = levels[L];
        var sibling = (idx & 1) ? idx - 1 : idx + 1;
        if (sibling < level.length) {
            path.push({ hash: level[idx & 1 ? idx - 1 : idx + 1], right: (idx & 1) === 0 });
            idx = idx >> 1;
        } else {
            /* promoted node: it moves up without a sibling and without a step
               in the proof, so the index halves the same way */
            idx = idx >> 1;
        }
    }
    return { index: index, count: leaves.length, path: path };
}

/**
 * Check a proof against a root.
 *
 * THE LEAF IS HASHED HERE, not passed in pre-hashed, so that a caller cannot
 * accidentally supply an internal node's hash and have it accepted as a leaf.
 * That is the second-preimage attack the prefix bytes defend against, and
 * taking raw data closes the last way to trip over it.
 *
 * @return {boolean}
 */
export function verify(hash, root_hash, leaf, prf) {
    if (!prf || !prf.path) { return false; }
    var acc = hash_leaf(hash, leaf);

    for (var i = 0; i < prf.path.length; i++) {
        var step = prf.path[i];
        acc = step.right ? hash_node(hash, acc, step.hash)
                         : hash_node(hash, step.hash, acc);
    }

    /* ⭐ commons/ct.js, which this used to write out by hand - same length
       check, same xor-or, same answer */
    return equal_bool(acc, root_hash);
}

/** Serialise a proof for transport: index, count, then each step. */
export function encode_proof(prf) {
    var parts = [be32(prf.index), be32(prf.count)];
    for (var i = 0; i < prf.path.length; i++) {
        parts.push(new Uint8Array([prf.path[i].right ? 1 : 0]));
        parts.push(prf.path[i].hash);
    }
    return concat(parts);
}

/** @param {number} hash_len  the digest size, needed to split the steps *
 * @return {object|null} A proof, or null if the encoding is malformed.
 */
export function decode_proof(bytes, hash_len) {
    if (bytes.length < 8) { return null; }
    var index = rd_be32u(bytes, 0);
    var count = rd_be32u(bytes, 4);
    var path = [];
    var p = 8;
    while (p < bytes.length) {
        if (p + 1 + hash_len > bytes.length) { return null; }
        path.push({ right: bytes[p] === 1, hash: bytes.subarray(p + 1, p + 1 + hash_len) });
        p += 1 + hash_len;
    }
    return { index: index, count: count, path: path };
}
