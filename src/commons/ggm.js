/**
 * GGM trees of seeds: a root expands, two children per node by the caller's
 * PRG, to 2^d leaves; all leaves but one can be handed over without the
 * hidden one - by the d siblings of its path (open / rebuild), or by the
 * XOR of each level's left and right children (level_sums / from_sums,
 * which an OT per level turns into a punctured tree the sender never sees
 * the puncture of).
 *
 *     var T = ggm(function (seed) { ... return [left, right]; });
 *
 * Leaf i sits under the path of i's bits, the most significant first.
 * dualring_prf.js and legendre_oprf.js use it; FAEST, MQOM and SDitH keep
 * the trees their specifications define.
 */

import { xor_into } from './bytes.js';

function log2(n) { return 31 - Math.clz32(n); }

export function ggm(children) {
    /** Levels 0 (the root) to depth. */
    function levels(root, depth) {
        var out = [[root]];
        for (var l = 0; l < depth; l++) {
            var nx = [], lv = out[l];
            for (var i = 0; i < lv.length; i++) { var c = children(lv[i]); nx.push(c[0], c[1]); }
            out.push(nx);
        }
        return out;
    }
    /** The n = 2^d leaves. */
    function leaves(root, n) { return levels(root, log2(n))[log2(n)]; }
    /** The siblings of leaf hidden's path, top down. */
    function open(root, n, hidden) {
        var out = [], node = root;
        for (var l = log2(n) - 1; l >= 0; l--) { var c = children(node), bit = (hidden >> l) & 1; out.push(c[1 - bit]); node = c[bit]; }
        return out;
    }
    /** Every leaf from open's siblings, null at hidden. */
    function rebuild(path, n, hidden) {
        var out = new Array(n).fill(null), d = log2(n);
        for (var l = d - 1, q = 0; l >= 0; l--, q++) {
            /* the sibling subtree at depth q: leaves whose top bits match hidden's except bit l */
            var base = ((hidden >> l) ^ 1) << l, sub = leaves(path[q], 1 << l);
            for (var j = 0; j < sub.length; j++) { out[base + j] = sub[j]; }
        }
        return out;
    }
    /** levels' output with, per level 1..depth, [XOR of the left children, XOR of the right]. */
    function level_sums(root, depth, seed_len) {
        var lv = levels(root, depth), sums = [];
        for (var l = 1; l <= depth; l++) {
            var s = [new Uint8Array(seed_len), new Uint8Array(seed_len)];
            for (var j = 0; j < lv[l].length; j++) { xor_into(s[j & 1], lv[l][j]); }
            sums.push(s);
        }
        return { levels: lv, sums: sums };
    }
    /**
     * Every leaf but hidden's, from one level sum per level: sum(l, side) is
     * level l's sum on the side off hidden's path (a fresh array).
     */
    function from_sums(depth, hidden, sum) {
        var known = [null];
        for (var l = 1; l <= depth; l++) {
            var prev = hidden >> (depth - l + 1), side = 1 - ((hidden >> (depth - l)) & 1), next = new Array(1 << l).fill(null), j;
            for (j = 0; j < known.length; j++) { if (j !== prev) { var c = children(known[j]); next[2 * j] = c[0]; next[2 * j + 1] = c[1]; } }
            var sib = sum(l, side);
            for (j = side; j < next.length; j += 2) { if (next[j]) { xor_into(sib, next[j]); } }
            next[2 * prev + side] = sib;
            known = next;
        }
        return known;
    }
    return { levels: levels, leaves: leaves, open: open, rebuild: rebuild, level_sums: level_sums, from_sums: from_sums };
}
