/**
 * Sparse Merkle Tree  -  proofs that a key is NOT there
 *
 * An ordinary Merkle tree proves a leaf IS present. That is a different
 * problem from proving one is ABSENT, and no amount of inclusion proofs
 * settles it: showing a hundred leaves that are not yours says nothing about
 * the hundred-and-first.
 *
 * THE IDEA IS TO GIVE EVERY POSSIBLE KEY A FIXED SEAT. Take a tree of depth
 * 256 - one level per bit of the key - so key k lives at exactly the leaf its
 * bits spell out. Then "not present" is just "the seat at that path is
 * empty", and the ordinary inclusion proof for that path proves it.
 *
 * A TREE OF 2^256 LEAVES IS NOT STORED, OBVIOUSLY. Almost all of it is empty,
 * and an empty subtree of a given height always has the same hash whatever
 * its position. So the hashes of empty subtrees are precomputed once - 257 of
 * them, one per height - and any branch that contains no keys collapses to a
 * single constant. What is actually stored is only the paths that hold real
 * keys.
 *
 * WHAT IT BUYS OVER A SORTED LIST WITH NEIGHBOURS. The other way to prove
 * absence is to sort the keys and show the two neighbours with nothing
 * between them. That works, but it requires the keys to be ordered and every
 * insertion to reshuffle the neighbours' proofs. Here insertion touches one
 * path of 256 nodes and nothing else, and the same proof structure serves
 * both questions.
 *
 * THE KEY IS HASHED BEFORE USE, which matters for a reason that is not about
 * secrecy: an attacker who could choose raw keys could pile them all into one
 * subtree and make every proof in that region as deep as possible. Hashing
 * spreads them uniformly whatever they choose.
 *
 * COST. A proof is up to 256 sibling hashes - 8 KiB with SHA-256 - which is
 * the honest downside against a plain Merkle tree's log2(n). Compressing it
 * by dropping the empty-subtree constants brings the typical case down to
 * roughly log2(number of keys) steps, and that compression is implemented
 * below.
 */

import { hash_leaf, hash_node } from './merkle.js';
import { equal_bool } from './commons/ct.js';

/**
 * Build the table of empty-subtree hashes.
 *
 * empty[0] is the hash of an empty leaf; empty[h] is the parent of two
 * empty[h-1]. Computed once per tree, and it is what lets an untouched
 * subtree of any size be represented by one value.
 */
function empty_table(hash, depth) {
    var t = new Array(depth + 1);
    t[0] = hash_leaf(hash, new Uint8Array(0));
    for (var h = 1; h <= depth; h++) {
        t[h] = hash_node(hash, t[h - 1], t[h - 1]);
    }
    return t;
}

/** Bit `i` of a key, counting from the most significant. */
function bit(key, i) {
    return (key[i >> 3] >> (7 - (i & 7))) & 1;
}

function hex_of(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) {
        s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    }
    return s;
}

/**
 * @param {function} hash    e.g. sha256
 * @param {number}   [depth] defaults to the hash's bit length, which gives
 *                           every hashed key its own leaf
 */
export function sparse_merkle(hash, depth) {
    var D = depth || (hash.DIGEST_SIZE * 8);
    var EMPTY = empty_table(hash, D);

    /* only the occupied leaves are stored: hashed key -> value hash */
    var store = {};

    /**
     * The node hash at `path` (the first `level` bits of some key), computed
     * on demand.
     *
     * RECURSION WITH AN EARLY EXIT is what makes this affordable: if no
     * stored key starts with this path, the whole subtree is empty and the
     * answer is a constant. Only branches that actually contain keys are
     * walked.
     */
    function node_at(prefix_bits, level, keys) {
        if (keys.length === 0) { return EMPTY[D - level]; }

        if (level === D) {
            return store[keys[0]].leaf;
        }

        var left = [], right = [];
        for (var i = 0; i < keys.length; i++) {
            var kb = store[keys[i]].key;
            if (bit(kb, level) === 0) { left.push(keys[i]); }
            else { right.push(keys[i]); }
        }
        return hash_node(hash,
                         node_at(prefix_bits, level + 1, left),
                         node_at(prefix_bits, level + 1, right));
    }

    function all_keys() { return Object.keys(store); }

    return {
        /**
         * Insert or replace a key.
         *
         * The key is HASHED first - see the note above about an attacker
         * choosing keys to unbalance the tree.
         */
        set: function (key, value) {
            /*
             * ⛔ AN EMPTY VALUE IS REFUSED. The empty seat is hash_leaf of
             *   zero bytes - exactly the leaf an empty VALUE hashes to - so a
             *   key set to empty left the root unchanged and its "absent"
             *   proof verified. Refusing it keeps every existing root as it
             *   is; a caller that needs "present, no content" encodes it
             *   (a single 0x00, say).
             */
            if (!(value instanceof Uint8Array) || value.length === 0) {
                throw new Error('sparse_merkle: the value must be non-empty bytes - an empty value is indistinguishable from an absent key');
            }
            var hk = hash(key);
            store[hex_of(hk)] = { key: hk, leaf: hash_leaf(hash, value), value: value };
        },

        /** Remove a key, which makes its seat empty again. */
        remove: function (key) {
            delete store[hex_of(hash(key))];
        },

        /** @return {Uint8Array|null} */
        get: function (key) {
            var e = store[hex_of(hash(key))];
            return e ? e.value : null;
        },

        has: function (key) {
            return Object.prototype.hasOwnProperty.call(store, hex_of(hash(key)));
        },

        size: function () { return Object.keys(store).length; },

        /** The commitment to the whole map. */
        root: function () {
            return node_at(null, 0, all_keys());
        },

        /**
         * A proof for `key` - the SAME structure whether the key is present
         * or absent.
         *
         * That symmetry is the point of the whole construction: the verifier
         * runs one algorithm and learns which case it is from whether the
         * leaf is the empty constant.
         *
         * The path is COMPRESSED: trailing steps whose sibling is the
         * empty-subtree constant are dropped, because the verifier can
         * regenerate them. For a tree holding a thousand keys that turns 256
         * steps into about ten.
         *
         * @return {{key, present, value, path, depth}}
         */
        prove: function (key) {
            var hk = hash(key);
            var hex = hex_of(hk);
            var present = Object.prototype.hasOwnProperty.call(store, hex);

            var keys = all_keys();
            var path = [];

            for (var level = 0; level < D; level++) {
                var mine = [], sibling = [];
                var b = bit(hk, level);
                for (var i = 0; i < keys.length; i++) {
                    if (bit(store[keys[i]].key, level) === b) { mine.push(keys[i]); }
                    else { sibling.push(keys[i]); }
                }
                path.push(node_at(null, level + 1, sibling));
                keys = mine;
            }

            /* drop the trailing empty-subtree hashes; the verifier rebuilds
               them from its own table */
            var last = path.length;
            while (last > 0) {
                var h = D - last;
                /* nothing secret here - this is a public node against a public
                   constant - but commons/ct.js already says "same bytes", and
                   the hand-written loop it replaces said it again */
                if (!equal_bool(path[last - 1], EMPTY[h])) { break; }
                last--;
            }

            return {
                key: key,
                present: present,
                value: present ? store[hex].value : null,
                path: path.slice(0, last),
                depth: D
            };
        },

        /** The empty-subtree table, so a verifier can be built independently. */
        empty_hashes: function () { return EMPTY; }
    };
}

/**
 * Verify a proof against a root, WITHOUT the tree.
 *
 * Returns true for both a valid presence proof and a valid absence proof -
 * the caller reads `prf.present` to know which was proved. A proof that
 * claims presence but carries no value, or claims absence while its leaf is
 * occupied, fails here.
 *
 * @return {boolean}
 */
export function verify_sparse(hash, root_hash, prf, depth) {
    if (!prf || !prf.path) { return false; }
    var D = depth || prf.depth || (hash.DIGEST_SIZE * 8);
    var EMPTY = empty_table(hash, D);

    if (prf.present && !(prf.value instanceof Uint8Array && prf.value.length > 0)) { return false; }

    var hk = hash(prf.key);

    /* the leaf: the value's hash if present, the empty constant if not */
    var acc = prf.present ? hash_leaf(hash, prf.value) : EMPTY[0];

    /* walk up, using the empty constant wherever the proof was compressed */
    for (var level = D - 1; level >= 0; level--) {
        var sib = (level < prf.path.length) ? prf.path[level] : EMPTY[D - level - 1];
        acc = bit(hk, level) === 0 ? hash_node(hash, acc, sib)
                                   : hash_node(hash, sib, acc);
    }

    return equal_bool(acc, root_hash);
}
