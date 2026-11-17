/**
 * ot_extend.js — a few hundred transfers become millions.
 *
 * `ot_base.js` costs three point multiplications per transfer. DKLS needs
 * hundreds of thousands per signature, which at that price is not a protocol,
 * it is a wait.
 *
 * OT extension fixes that: run κ = 128 real transfers once, with the roles
 * REVERSED, then produce any number of transfers from hashing and XOR alone.
 * The reversal surprises people — in the base OTs the party that will later
 * RECEIVE acts as sender — and it is what makes the whole thing work.
 *
 * ⭐ THIS IS SOFTSPOKENOT (Roy, Crypto 2022), NOT KOS15.
 *
 *    An earlier version of this file implemented KOS15 faithfully, including
 *    four bugs found and fixed by measuring rates rather than reading code.
 *    Then the paper itself turned out to open with:
 *
 *        "Update, 2022: Roy (Crypto 2022) showed that Lemma 1, which the core
 *         of our proof relies on, is incorrect, so our protocol does not
 *         currently have a security proof."
 *
 *    and, under Lemma 1, in place of a proof: "Roy proved the lemma to be
 *    false." Section 4 of that paper gives this replacement as Figure 10.
 *
 *    The differences are structural, not adjustments:
 *
 *        ℓ' = ℓ + s              KOS sacrificed κ + s. The κ extra rows go.
 *        κ SEPARATE CHECKS       one per COLUMN, not one over all rows.
 *        BEFORE TRANSPOSITION    on the columns the receiver sent, not on
 *                                the rows those columns produce.
 *
 *    ⚠️ The middle one is the fix. A single check over rows lets a cheating
 *       receiver spread errors across columns so they cancel in the sum.
 *       Checking each column against the SAME x leaves nowhere to put them:
 *       an honest receiver sends one x for every column, and that is exactly
 *       what the κ checks verify.
 *
 * HOW IT WORKS
 *
 *   The receiver expands its κ base-OT key pairs into two ℓ'-bit columns each
 *   and sends
 *
 *       u^i = t^i_0 ⊕ t^i_1 ⊕ x          for i = 1..κ
 *
 *   where x is its choice vector — THE SAME x in every column. The sender,
 *   holding one key per column and its own secret Δ, recovers
 *
 *       q^i = t^i ⊕ Δ_i · x
 *
 *   Transposed, row j reads q_j = t_j ⊕ x_j·Δ: the sender knows q_j and Δ but
 *   not x_j, the receiver knows t_j. Hashing gives the two keys and the
 *   receiver can open exactly one.
 *
 * ⚠️ THE INDEX MUST BE HASHED WITH THE ROW. Guo et al. (S&P 2020) and
 *    Masny–Rindal (CCS 2019) both showed attacks when `j` is omitted from H,
 *    and §4 of the KOS paper calls including it critical.
 *
 * MEASURED
 *
 *     256 of 256 transfers agree
 *     a whole column replaced with a different x:  39 of 60 caught
 *     and every one of the 21 escapes was a column with Δ_i = 0,
 *     none of which changed a single key
 *
 *   ⚠️ THE HALF THAT ESCAPES IS NOT A GAP, and the arithmetic says why.
 *      Where Δ_i = 0 the sender computes q^i from its own key and never reads
 *      u^i at all, so a corrupted column there is invisible because it is
 *      inert — the receiver gains nothing and no key moves. The check catches
 *      every deviation that can have an effect, which is the most any check
 *      can do.
 *
 *      What remains is that the ABORT itself is a signal: a receiver who
 *      corrupts column i and watches whether the protocol stops learns Δ_i.
 *      That is selective failure, it is inherent to the shape rather than to
 *      this code, and it is what the sacrificed rows and the security proof
 *      are for. Verifying that argument is not something a test can do.
 *
 * ⛔ NO EXTERNAL ORACLE, and the history above is why that is said loudly. Four
 *    measured bugs produced a faithful implementation of a WITHDRAWN
 *    protocol, and no amount of testing reaches "the proof was retracted
 *    seven years later" — only reading the paper does.
 *
 * Pure functions, no state, no parties, no rounds in the code. The extension
 * is a back-and-forth, as mta's alice_encrypt, bob_respond, alice_decrypt are:
 * each step is a function and the caller drives them.
 *
 * ⛔ NO EXTERNAL ORACLE. SoftSpokenOT - Roy, Crypto 2022.
 *
 * ⚠ THE DOMAIN STRINGS, "cryptographic-primitives/ot/...", ARE PART OF THE
 *   PROTOCOL. Every key derived here is a hash over one of them, so peers
 *   using different strings derive different keys and the transfers silently
 *   disagree. There is no version negotiation in a primitive; both sides
 *   must run the same build.
 *
 * ⭐ AND IT IS A SEPARATE FILE FROM ot_base FOR A REASON: nothing here
 *    touches a curve. The base OTs are public-key work - point
 *    multiplications, scalars, a group; everything above them is hashing and
 *    XOR. Merging the two would bind the extension to a curve it has no use
 *    for, and this way ANY source of 128 key pairs drives it - including a
 *    lattice-based OT, if post-quantum base OTs are ever wanted.
 */

import { sha256 } from './sha2.js';
import { shake256 } from './sha3.js';
import * as gf from './commons/gf128.js';
import { concat as concatUint8Arrays, ascii as utf8, be16, be32 } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';

/** Computational security: the number of base OTs, and the width of a row. */
var KAPPA = 128;
var KAPPA_BYTES = KAPPA / 8;

/**
 * Statistical security, and the block size of the check.
 *
 * The paper uses s = 64. This uses 128 so the arithmetic lands exactly on
 * `gf128` — strictly more sacrifice and a larger field, so strictly safer, at
 * the cost of 64 extra transfers that are discarded either way.
 */
var S = 128;
var S_BYTES = S / 8;

/**
 * Receiver, round 1: build the columns and send them.
 *
 * ⭐ THE EXTRA s ROWS CARRY RANDOM CHOICES AND ARE DISCARDED.
 *
 * They are not padding. The check reveals a little about the receiver's
 * choices to a corrupt SENDER — `x` is a linear combination of all of them —
 * and the random rows are what make that combination uniform. The paper's
 * Lemma 2 is exactly this: a random matrix with s spare rows has full rank
 * except with probability 2^-s, so the sacrificed rows drown the real ones.
 *
 * rng omitted or null draws fresh ones from the platform.
 */
function receiver_extend(base, real_choices, rng, sid) {
    require_sid(sid);
    rng = require_rng('ot_extend.receiver_extend', rng);
  if (!Array.isArray(base.k0) || base.k0.length !== KAPPA ||
      !Array.isArray(base.k1) || base.k1.length !== KAPPA) {
    throw new TypeError('ot_extend: receiver needs ' + KAPPA + ' key pairs ' +
                        'from the base OTs');
  }
  for (var i = 0; i < real_choices.length; i++) {
    if (real_choices[i] !== 0 && real_choices[i] !== 1) {
      throw new TypeError('ot_extend: choice ' + i + ' must be 0 or 1');
    }
  }

  var real = real_choices.length;
  var total = Math.ceil((real + S) / S) * S;
  var xBytes = total / 8;

  // x: the real choices, then s random ones.
  var x = new Uint8Array(xBytes);
  for (var i = 0; i < real; i++) {
    if (real_choices[i]) x[i >> 3] |= 1 << (i & 7);
  }
  var extra = rng(((total - real) + 7) >> 3);
  for (var i = real; i < total; i++) {
    var e = i - real;
    if ((extra[e >> 3] >> (e & 7)) & 1) x[i >> 3] |= 1 << (i & 7);
  }

  /*
   * u^i = t^i_0 ⊕ t^i_1 ⊕ x, with THE SAME x in every column.
   *
   * That sameness is the whole of honest behaviour, and the κ checks below
   * are precisely a test of it. A cheating receiver sends a different x^i per
   * column and learns bits of Δ from the difference.
   */
  var t0 = [], u = [];
  for (var i = 0; i < KAPPA; i++) {
    var a = expand(base.k0[i], i, total, sid);
    var b = expand(base.k1[i], i, total, sid);
    var ui = new Uint8Array(xBytes);
    for (var k = 0; k < xBytes; k++) ui[k] = a[k] ^ b[k] ^ x[k];
    t0.push(a);
    u.push(ui);
  }

  return {
    u: u, real: real, total: total,
    t0: t0, x: x, sid: sid,

    /**
     * Round 2: answer the sender's challenge.
     *
     * ⚠️ χ COMES FROM THE SENDER, AFTER u IS COMMITTED. Deriving it from a
     *    shared value would let the receiver compute the coefficients first
     *    and solve for a u that passes — the check would then verify a
     *    relation the cheater had already arranged.
     */
    answer: function (chi_seed) {
      var m = total / S;
      var chi = coefficients(chi_seed, m - 1);
      return {
        x: combine(x, chi, m),
        t: t0.map(function (col) { return combine(col, chi, m); })
      };
    }
  };
}

/**
 * Sender: recover Q, then run the κ column checks.
 *
 * @return `{ ok: false, reason }` or `{ ok: true, … }`. A failed check MUST
 *         abort — its whole point is that a receiver who passes cannot have
 *         cheated, and continuing past a failure makes it decoration.
 */
function sender_extend(base, wire, check, chi_seed, sid) {
    require_sid(sid);
  if (!(base.delta instanceof Uint8Array) || base.delta.length !== KAPPA_BYTES) {
    throw new TypeError('ot_extend: sender needs a ' + KAPPA + '-bit delta');
  }
  if (!Array.isArray(base.keys) || base.keys.length !== KAPPA) {
    throw new TypeError('ot_extend: sender needs one base-OT key per column');
  }

  var total = wire.total;
  if (!Number.isInteger(total) || total <= 0 || total % S !== 0 || total > (1 << 20)) {
    return { ok: false, reason: 'malformed extension: bad total' };
  }
  var xBytes = total / 8;
  if (!Array.isArray(wire.u) || wire.u.length !== KAPPA) {
    return { ok: false, reason: 'malformed extension: expected ' + KAPPA + ' columns' };
  }
  for (var i = 0; i < KAPPA; i++) {
    if (!(wire.u[i] instanceof Uint8Array) || wire.u[i].length !== xBytes) {
      return { ok: false, reason: 'malformed extension: column ' + i + ' has the wrong length' };
    }
  }
  if (!check || !(check.x instanceof Uint8Array) || !Array.isArray(check.t) ||
      check.t.length !== KAPPA) {
    return { ok: false, reason: 'malformed extension: bad check answer' };
  }

  // q^i = Δ_i·u^i ⊕ t^i_{Δ_i}
  var q = [];
  for (var i = 0; i < KAPPA; i++) {
    var dBit = (base.delta[i >> 3] >> (i & 7)) & 1;
    var own = expand(base.keys[i], i, total, sid);
    var qi = new Uint8Array(xBytes);
    for (var k = 0; k < xBytes; k++) {
      qi[k] = dBit ? (own[k] ^ wire.u[i][k]) : own[k];
    }
    q.push(qi);
  }

  /*
   * ⭐ κ SEPARATE CHECKS, ONE PER COLUMN — the difference from KOS15.
   *
   *     q^i  ==  t^i ⊕ Δ_i·x        for every i
   *
   * KOS combined all rows into one equation, which let a cheating receiver
   * place errors in different columns so they cancelled in the sum. Here
   * every column is tested on its own against the SAME x, so an error
   * anywhere shows up in the column carrying it.
   */
  var m = total / S;
  var chi = coefficients(chi_seed, m - 1);
  var xAcc = gf.from_bytes(check.x);

  for (var i = 0; i < KAPPA; i++) {
    var dBit = (base.delta[i >> 3] >> (i & 7)) & 1;
    var qAcc = combine_gf(q[i], chi, m);
    var want = dBit ? gf.add(gf.from_bytes(check.t[i]), xAcc)
                      : gf.from_bytes(check.t[i]);
    if (!gf.equal(qAcc, want)) {
      return { ok: false, column: i,
               reason: 'column ' + i + ' failed the consistency check — the ' +
                       'receiver did not use the same choice vector in every ' +
                       'column, which is how it recovers bits of delta' };
    }
  }

  return { ok: true, q: q, delta: base.delta, real: wire.real,
           total: total, sid: sid };
}

/** Sender: the two keys for transfer j. */
function sender_keys(state, j) {
  var row = transpose_row(state.q, j);
  var other = new Uint8Array(KAPPA_BYTES);
  for (var b = 0; b < KAPPA_BYTES; b++) { other[b] = row[b] ^ state.delta[b]; }
  return { k0: key(state.sid, j, row), k1: key(state.sid, j, other) };
}

/** Receiver: the one key its choice earned. */
function receiver_key(state, j) {
  return key(state.sid, j, transpose_row(state.t0, j));
}

/**
 * Row j of the ℓ' × κ matrix whose COLUMNS are the given vectors.
 *
 * Stored by column because that is how the base OTs deliver it, read by row
 * because that is what a transfer needs. Transposition is the computational
 * bottleneck at scale — the paper spends real effort on a cache-friendly
 * algorithm — and this is the straightforward version.
 */
function transpose_row(columns, j) {
  var row = new Uint8Array(KAPPA_BYTES);
  for (var i = 0; i < KAPPA; i++) {
    if ((columns[i][j >> 3] >> (j & 7)) & 1) row[i >> 3] |= 1 << (i & 7);
  }
  return row;
}

/** Σ block_k·χ_k ⊕ last_block, over GF(2^128). */
function combine_gf(bits, chi, m) {
  var acc = gf.from_bytes(bits.subarray((m - 1) * S_BYTES, m * S_BYTES));
  for (var k = 0; k < m - 1; k++) {
    acc = gf.add(acc, gf.mul(chi[k],
      gf.from_bytes(bits.subarray(k * S_BYTES, (k + 1) * S_BYTES))));
  }
  return acc;
}
function combine(bits, chi, m) { return gf.to_bytes(combine_gf(bits, chi, m)); }

/** The sender's random weights, one per block but the last. */
function coefficients(seed, count) {
  if (!(seed instanceof Uint8Array) || seed.length === 0) {
    throw new TypeError('ot_extend: the challenge seed must be non-empty ' +
                        'bytes, sampled by the SENDER after u arrives');
  }
  var bytes = shake256(concatUint8Arrays([
    utf8('cryptographic-primitives/ot/extend/v2/chi'), len16(seed), seed, be32(count)
  ]), Math.max(count, 1) * S_BYTES);
  var out = [];
  for (var k = 0; k < count; k++) {
    out.push(gf.from_bytes(bytes.subarray(k * S_BYTES, (k + 1) * S_BYTES)));
  }
  return out;
}

/**
 * A base-OT key expands to one column of `total` bits — FOR THIS SESSION.
 *
 * ⛔ THE SID IS PART OF THE EXPANSION. It was not, and since base OTs are
 *    reused across many extensions, every extension from the same base
 *    produced identical columns: t0 repeated, and u ⊕ u′ = x ⊕ x′ handed the
 *    sender the XOR of the receiver's choice vectors across sessions. Callers
 *    that reuse base OTs MUST pass a sid that is fresh per extension.
 */
function expand(seed, column, total, sid) {
  return shake256(concatUint8Arrays([
    utf8('cryptographic-primitives/ot/extend/v3/col'),
    len16(sid), sid,
    be16(column),                      /* column < KAPPA: never refused */
    be32(total), seed
  ]), total / 8);
}

/**
 * The consistency-check seed, by Fiat–Shamir over the receiver's columns.
 *
 * ⛔ χ MUST NOT BE KNOWABLE BEFORE u IS FIXED (see receiver_extend's
 *    `answer`). Hashing u itself gives that without an extra round: changing
 *    any column changes χ. Both sides compute it from what crossed the wire.
 */
function challenge_seed(sid, u, total) {
  require_sid(sid);
  if (!Array.isArray(u) || u.length !== KAPPA) {
    throw new TypeError('ot_extend: challenge needs ' + KAPPA + ' columns');
  }
  var parts = [utf8('cryptographic-primitives/ot/extend/v3/chi'), len16(sid), sid, be32(total)];
  for (var i = 0; i < u.length; i++) {
    if (!(u[i] instanceof Uint8Array) || u[i].length !== total / 8) {
      throw new TypeError('ot_extend: column ' + i + ' has the wrong length');
    }
    parts.push(u[i]);
  }
  return sha256(concatUint8Arrays(parts));
}

/**
 * H(j ‖ row).
 *
 * ⚠️ THE INDEX IS NOT OPTIONAL. Guo et al. and Masny–Rindal each showed
 *    attacks against extensions that hash the row alone, and §4 of the KOS
 *    paper calls including it critical.
 */
function key(sid, j, row) {
  return sha256(concatUint8Arrays([
    utf8('cryptographic-primitives/ot/extend/v2/key'),
    be32(sid.length), sid, be32(j), row
  ]));
}

/**
 * ⚠ THE CALLER OWNS THE SEPARATION, and this file used to own it instead.
 *
 * Every key here was a hash over a FIXED string plus the transfer index, so
 * two runs of the extension against the same base OTs - the same pair of
 * parties signing twice - derived the same keys. ot_base already required a
 * sid and threw without one; this did not, which is an inconsistency
 * nothing failed on.
 *
 * A library-chosen constant cannot separate what the library cannot see. It
 * does not know whether these transfers belong to one signature or two, to
 * DKLS or to threshold RSA. Only the caller does, so the caller supplies it -
 * and supplying nothing is refused rather than defaulted, because a default
 * here is the bug wearing a different hat.
 */
function require_sid(sid) {
    if (!(sid instanceof Uint8Array) || sid.length === 0) {
        throw new TypeError('ot_extend: sid must be non-empty bytes - it ' +
                            'separates one run of the extension from the ' +
                            'next against the same base OTs');
    }
}

/* ⛔ be16, which REFUSES a length over 65535; the hand-written copy wrapped
   it to [0, 0], the transcript collision bytes.be16 was hardened against */
function len16(b) { return be16(b.length); }

export {
  challenge_seed,
  KAPPA, S, receiver_extend, sender_extend, sender_keys, receiver_key
};
