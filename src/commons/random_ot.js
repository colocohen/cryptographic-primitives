/**
 * Random OTs as protocol inputs: the checks, and a random 1-of-2^L OT built
 * from L random 1-of-2 OTs.
 *
 * A protocol here that runs over OTs takes them RANDOM and made in advance
 * (ot_kem.js for post-quantum base OTs, ot_extend.js to extend them): the
 * sender holds a pair [k0, k1] of 32-byte keys, the receiver {choice, key}
 * with key = k_choice. Each is spent once.
 *
 * THE 1-of-2^L OT (Naor-Pinkas): string k, w bits, is
 *
 *     s(k) = XOR over t < L of  field k of PRF(key_t[k_t])
 *
 * with bit t of k picking key t. The receiver holds the keys of its own
 * choice c and computes s(c); for any other k some key_t[k_t] is one it does
 * not hold, and that key's field k enters no other string - so every s(k),
 * k != c, carries a pseudorandom w bits of its own. (An XOR of the bare
 * keys, or of one PRF output per key, would not: four strings that differ
 * in two bits would XOR to zero.)
 */

import { shake256 } from '../sha3.js';
import { ascii, be32 } from './bytes.js';
import { bits_le } from './bitpack.js';
import { domain_xof } from './domain_xof.js';

var H = /* @__PURE__ */ domain_xof(shake256, /* @__PURE__ */ ascii('cryptographic-primitives/random-ot/v1'));

function is_key(k) { return k instanceof Uint8Array && k.length === 32; }

/** Refuse anything but n sent random OTs, each [k0, k1] of 32-byte keys. */
export function check_sender_ots(list, n, who) {
    if (!Array.isArray(list) || list.length !== n) { throw new Error(who + ': ' + n + ' random OTs to send'); }
    for (var i = 0; i < n; i++) {
        var p = list[i];
        if (!Array.isArray(p) || p.length !== 2 || !is_key(p[0]) || !is_key(p[1])) { throw new Error(who + ': a sent random OT is [k0, k1] of 32-byte keys'); }
    }
}
/** Refuse anything but n received random OTs, each {choice: 0 or 1, key: 32 bytes}. */
export function check_receiver_ots(list, n, who) {
    if (!Array.isArray(list) || list.length !== n) { throw new Error(who + ': ' + n + ' random OTs to receive'); }
    for (var i = 0; i < n; i++) {
        var o = list[i];
        if (!o || (o.choice !== 0 && o.choice !== 1) || !is_key(o.key)) { throw new Error(who + ': a received random OT is {choice: a bit, key: 32 bytes}'); }
    }
}

/* key t's PRF output: count fields of w bits, under the caller's tag */
function row(key, tag, t, count, w) { return H(0, [tag, be32(t), key], Math.ceil(count * w / 8)); }

/**
 * Sender: s(0) .. s(count - 1), w bits each (w <= 30), from L sent OTs
 * (count <= 2^L; a caller that needs fewer strings computes fewer). The tag
 * names the use: two uses of one key set need two tags.
 */
export function one_of_n_send(pairs, w, tag, count) {
    var L = pairs.length, n = count === undefined ? 1 << L : count, out = new Int32Array(n);
    if (!(n >= 1 && n <= (1 << L)) || !(w >= 1 && w <= 30)) { throw new Error('random_ot: 1 to 2^L strings of 1 to 30 bits'); }
    for (var t = 0; t < L; t++) {
        var r = [row(pairs[t][0], tag, t, n, w), row(pairs[t][1], tag, t, n, w)];
        for (var k = 0; k < n; k++) { out[k] ^= bits_le(r[(k >> t) & 1], k * w, w); }
    }
    return out;
}
/** Receiver: its choice c (bit t from OT t) and s(c). */
export function one_of_n_receive(recv, w, tag) {
    var c = 0, s = 0, t;
    for (t = 0; t < recv.length; t++) { c |= recv[t].choice << t; }
    for (t = 0; t < recv.length; t++) { s ^= bits_le(row(recv[t].key, tag, t, c + 1, w), c * w, w); }
    return { choice: c, string: s };
}
