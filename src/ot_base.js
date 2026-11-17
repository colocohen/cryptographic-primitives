/**
 * ot_base.js — "I send you two, you take one, and I never learn which."
 *
 * Oblivious transfer is the primitive DKLS is built on, and it is easier to
 * state than almost anything else in this library:
 *
 *     the sender    has two messages, m₀ and m₁
 *     the receiver  wants exactly one of them
 *     afterwards    the receiver knows only the one it chose
 *                   and the sender knows nothing about which
 *
 * Both halves matter and they pull in opposite directions. A protocol where
 * the receiver learns both is not oblivious transfer; neither is one where
 * the sender can tell what was taken.
 *
 * THIS IS THE SIMPLEST OT OF CHOU AND ORLANDI (eprint 2015/267)
 *
 *     sender     picks a, sends A = a·G
 *     receiver   picks b, sends B = b·G       when choosing 0
 *                                B = A + b·G  when choosing 1
 *     sender     derives k₀ = H(a·B)  and  k₁ = H(a·B − a·A)
 *     receiver   derives      H(b·A)
 *
 * The receiver's B is a uniformly random group element either way, so the
 * sender sees nothing. And the receiver can compute exactly one of the two
 * keys, because the other needs `a`, which it does not have.
 *
 * ⚠️ WHY THIS FILE EXISTS SEPARATELY FROM THE PROTOCOL THAT USES IT.
 *
 *    DKLS needs millions of transfers and this one costs three point
 *    multiplications, so nothing would ever use it directly. What OT
 *    EXTENSION does is turn a few hundred of these into millions, using only
 *    hashing and XOR — so this is the seed, run once per pair of parties, and
 *    everything after it is symmetric-key work.
 *
 * ⛔ AND THE PART THAT IS NOT ABOUT CORRECTNESS.
 *
 *    A correct implementation that branches on the choice bit leaks the
 *    choice through timing, and the choice is the entire secret. That failure
 *    does not produce a wrong answer — it produces a right one, slightly
 *    faster or slower — so no test of outputs can see it. Every selection
 *    here goes through `ct.select_bytes`, and `ot_base.mjs` measures that the
 *    two branches take the same time, with a control that proves the
 *    measurement can see a leak when there is one.
 *
 * Pure functions, no state, no parties, no rounds in the code. A transfer is
 * a back-and-forth, as mta's alice_encrypt, bob_respond, alice_decrypt are:
 * each step is a function and the caller drives them.
 *
 * ⛔ NO EXTERNAL ORACLE. Chou-Orlandi, eprint 2015/267.
 *
 * ⚠ The key-derivation domain string "cryptographic-primitives/..." is part
 *   of the protocol. Every key here is a hash over it, so two peers must use
 *   the same one - see ot_extend.js.
 */

import { sha256 } from './sha2.js';
import { select_bytes } from './commons/ct.js';
import { concat as concatUint8Arrays, ascii as utf8, be16 } from './commons/bytes.js';
import { random_below_biased, require_rng } from './commons/primes.js';

var DST_KEY = utf8('cryptographic-primitives/ot/base/v1/key');

/**
 * Sender, round 1: publish A and keep `a`.
 *
 * `a` is a one-time secret for this transfer. Reusing it across transfers
 * would let a receiver that saw two of them relate their choices.
 *
 * rng omitted or null draws fresh ones from the platform.
 */
function sender_setup(G, rng) {
  rng = require_rng('ot_base.sender_setup', rng);
  var a = random_scalar(G, rng);
  return { a: a, A: G.encode(G.base_mul(a)) };
}

/**
 * Receiver: choose, and produce B.
 *
 * ⛔ `choice` is the secret. It must be 0 or 1 exactly, and the branch on it
 *    is the only place in this protocol where a leak would matter — so it is
 *    a constant-time selection between two already-computed points rather
 *    than an `if`.
 *
 * rng omitted or null draws fresh ones from the platform.
 */
function receiver_choose(G, A_bytes, choice, rng) {
  rng = require_rng('ot_base.receiver_choose', rng);
  var A = G.decode(A_bytes);
  if (!A) throw new Error('ot_base: sender point A is invalid');
  if (choice !== 0 && choice !== 1) {
    throw new TypeError('ot_base: choice must be 0 or 1, got ' + choice);
  }

  var b = random_scalar(G, rng);
  var bG = G.base_mul(b);

  /*
   * Both candidates are computed, then one is selected without branching.
   *
   * The addition happens whether or not it is used. That is the cost —
   * one extra point addition per transfer — and it is what makes the two
   * choices indistinguishable to anything watching the clock.
   */
  var forZero = G.encode(bG);
  var forOne  = G.encode(G.add(A, bG));
  var B = select_bytes(choice, forOne, forZero);

  return { b: b, B: B };
}

/**
 * Sender: derive both keys.
 *
 * It can compute both and knows which is which — but not which one the
 * receiver will be able to open. That asymmetry is the whole protocol.
 */
function sender_keys(G, state, B_bytes, sid) {
  var B = G.decode(B_bytes);
  if (!B) throw new Error('ot_base: receiver point B is invalid');
  var A = G.base_mul(state.a);

  var aB = G.mul(state.a, B);
  return {
    k0: derive_key(G, sid, aB),
    k1: derive_key(G, sid, G.add(aB, G.neg(G.mul(state.a, A))))
  };
}

/**
 * Receiver: derive the one key it is entitled to.
 *
 * `b·A` equals `a·B` when the choice was 0, and `a·B − a·A` when it was 1 —
 * so the same expression yields whichever key matches the choice, without the
 * receiver ever knowing the other.
 */
function receiver_key(G, state, A_bytes, sid) {
  var A = G.decode(A_bytes);
  if (!A) throw new Error('ot_base: sender point A is invalid');
  return derive_key(G, sid, G.mul(state.b, A));
}

/**
 * A point becomes a key.
 *
 * ⚠️ `sid` IS NOT OPTIONAL and is bound in here rather than left to the
 *    caller. Two transfers between the same pair with the same `a` and `b`
 *    would otherwise produce the same keys, and OT extension performs many
 *    transfers against one setup — so the transfer index has to separate
 *    them. Making it an argument with no default is the only way to be sure
 *    it is passed.
 */
function derive_key(G, sid, point) {
  if (!(sid instanceof Uint8Array) || sid.length === 0) {
    throw new TypeError('ot_base: sid must be non-empty bytes — it separates ' +
                        'transfers that would otherwise derive the same key');
  }
  return sha256(concatUint8Arrays([
    DST_KEY,
    be16(sid.length), sid,
    G.encode(point)
  ]));
}

/**
 * One transfer, end to end, for a caller that has both sides in hand.
 *
 * Real use drives the four steps across a network; this is what the tests
 * and OT extension use, and it documents the order.
 *
 * rng omitted or null draws fresh ones from the platform.
 */
function transfer(G, m0, m1, choice, rng, sid) {
  rng = require_rng('ot_base.transfer', rng);
  var s = sender_setup(G, rng);
  var r = receiver_choose(G, s.A, choice, rng);
  var keys = sender_keys(G, s, r.B, sid);
  var key = receiver_key(G, r, s.A, sid);

  return {
    // what the sender puts on the wire: both messages, each masked
    e0: xor(m0, keys.k0),
    e1: xor(m1, keys.k1),
    // and what the receiver can unmask
    open: function (e0, e1) {
      return xor(select_bytes(choice, e1, e0), key);
    }
  };
}

/*
 * ⚠ NOT commons/bytes.xor_bytes. That one writes into a destination and
 *   demands equal lengths; this pads with zero when the key is shorter than
 *   the message, which is what masking a message of arbitrary length against
 *   a fixed-size key requires. Two different contracts, so two functions.
 */
function xor(a, b) {
  var n = Math.min(a.length, b.length);
  var o = new Uint8Array(a.length);
  for (var i = 0; i < a.length; i++) o[i] = a[i] ^ (i < n ? b[i] : 0);
  return o;
}

/*
 * Non-zero, mod the order, 128 bits of slack. The sampler is
 * commons/primes.random_below_biased — the "third caller" this file said
 * would move it to commons arrived (elgamal, rvole).
 */
function random_scalar(G, rng) {
    var r = random_below_biased(G.ORDER, rng);
    return r === 0n ? 1n : r;
}


export {
  sender_setup, receiver_choose, sender_keys, receiver_key, transfer
};
