/**
 * rvole.js — random Vector OLE: two shares of a product, from oblivious transfer.
 *
 * This is the multiplication primitive DKLS23 is built on, and the last piece
 * below the signing protocol itself.
 *
 *     Bob    gets a random b
 *     Alice  supplies a vector a
 *     both   get shares: aᵢ·b = cᵢ + dᵢ
 *
 * Neither learns the other's value. It is oblivious transfer used as
 * arithmetic: Gilboa's schoolbook trick decomposes one multiplication in a
 * field of size q into |q| single-bit multiplications, each of which is one
 * OT. `ot_extend.js` makes those cheap.
 *
 * ⭐ WHY VECTOR, AND WHY LENGTH TWO. DKLS23 signing needs each party to
 *    multiply its counterparty's ONE inversion mask φ against TWO of its own
 *    values — its share of r, and its share of sk. Vectorising means the two
 *    products are forced to use the same φ, which removes a whole avenue of
 *    cheating: the paper's second listed attack is "a corrupt party could use
 *    inconsistent values of φ in the computations that produce v and u".
 *
 *    So the vectorisation is not an optimisation. It is a security property,
 *    and `ℓ = 2` is not a parameter anybody should change casually.
 *
 * THE PROTOCOL (Doerner, Kondi, Lee, shelat — eprint 2023/765, Protocol 5.2)
 *
 *     ξ = κ + 2λs        OT instances, κ = |q|
 *     ρ = ⌈κ/λc⌉         check values
 *     g                  a public gadget vector in Z_q^ξ
 *
 *   Bob picks ξ choice bits β and takes b = ⟨g, β⟩ — his input is the gadget
 *   vector read through his OT choices. Alice derandomises her OT messages
 *   with her input, and both derive shares from the transferred halves.
 *
 * ⛔ AND THE CHECK, which is what makes it maliciously secure.
 *
 *    Alice appends ρ random check values to her vector, and proves that the
 *    same derandomisation was applied to every OT instance by opening a
 *    Fiat–Shamir linear combination of them. A cheating Alice who used
 *    inconsistent inputs across instances passes only by guessing Bob's
 *    choice bits — 2^-ξ.
 *
 *    ⚠️ The paper is explicit that the challenge must be derived AFTER the
 *       derandomised messages are fixed, and the security proof turns on
 *       Bob's β being information-theoretically hidden at that moment.
 *
 * ⭐ UNLIKE THE OT LAYERS BELOW IT, THIS ONE HAS AN ORACLE:
 *    `silence-laboratories/silent-shard-dkls23-ll` implements the same paper,
 *    and `test/rvole.mjs` checks the algebraic
 *    relation the functionality demands rather than only that the protocol
 *    completes.
 *
 * Pure functions, no state, no parties, no rounds in the code. The exchange
 * is a back-and-forth, as mta's alice_encrypt, bob_respond, alice_decrypt are:
 * each step is a function and the caller drives them.
 *
 * DKLS23 Protocol 5.2, eprint 2023/765.
 */

import { sha256 } from './sha2.js';
import { shake256 } from './sha3.js';
import { concat as concatUint8Arrays, ascii as utf8, be32,
         bytes_to_bigint, bigint_to_bytes } from './commons/bytes.js';
import * as OTE from './ot_extend.js';
import { random_below_biased, require_rng } from './commons/primes.js';
import { equal } from './commons/ct.js';

/** Statistical security, per the paper's λs. */
var LAMBDA_S = 80;

/**
 * The gadget vector: ξ field elements, public and reusable.
 *
 * Bob's input is ⟨g, β⟩ — a subset sum of the gadget chosen by his OT bits.
 * With ξ = κ + 2λs entries the sum is statistically close to uniform over
 * Z_q even though β is only ξ bits, which is the paper's Lemma 2 and the
 * reason ξ exceeds κ.
 */
function gadget(q, xi, tag) {
  var bytes = Math.ceil(bit_length(q) / 8) + 16;
  var raw = shake256(concatUint8Arrays([
    utf8('cryptographic-primitives/rvole/v1/gadget'), be32(xi), tag
  ]), xi * bytes);
  var g = [];
  for (var j = 0; j < xi; j++) g.push(field_at(raw, j * bytes, bytes, q));
  return g;
}

/**
 * Parameters for a field of order q and vector length ℓ.
 *
 * ⚠️ ξ AND ρ ARE NOT TUNABLE. ξ = κ + 2λs is what makes Bob's subset sum
 *    uniform; ρ = ⌈κ/λc⌉ is how many check values are needed for the
 *    Fiat–Shamir combination to bind. Reducing either weakens the protocol in
 *    a way no test here would show.
 */
function params(q, ell) {
  var kappa = bit_length(q);
  return {
    q: q, ell: ell, kappa: kappa,
    xi: kappa + 2 * LAMBDA_S,
    rho: Math.ceil(kappa / 128)
  };
}

/**
 * Bob, round 1: choose, and learn his random input.
 *
 * His ξ OT choice bits ARE his secret. `b` is derived from them, so anything
 * that leaks a choice bit leaks part of `b` — which is why the OT layer below
 * is built the way it is.
 *
 * rng omitted or null draws fresh ones from the platform.
 */
function bob_sample(p, base, rng, sid) {
  rng = require_rng('rvole.bob_sample', rng);
  var bits = [];
  var raw = rng((p.xi + 7) >> 3);
  for (var j = 0; j < p.xi; j++) bits.push((raw[j >> 3] >> (j & 7)) & 1);

  var g = gadget(p.q, p.xi, sid);
  var b = 0n;
  for (var j = 0; j < p.xi; j++) if (bits[j]) b = (b + g[j]) % p.q;

  // ξ oblivious transfers, each carrying ℓ + ρ field elements.
  var ext = OTE.receiver_extend(base, bits, rng, sid);
  return { bits: bits, b: b, ext: ext, p: p, sid: sid };
}

/**
 * Alice: derandomise, prove consistency, and take her share.
 *
 * @param {function} [rng]  omitted or null draws fresh ones from the platform
 * @return `{ message, c }` — what crosses the wire, and her output share.
 */
function alice_multiply(p, base, wire, a, rng, sid, chi_seed) {
  rng = require_rng('rvole.alice_multiply', rng);
  if (a.length !== p.ell) {
    throw new TypeError('rvole: alice supplies exactly ' + p.ell + ' values');
  }
  /*
   * The OT extension's own consistency check runs first: `wire.answer(seed)`
   * is Bob's response to Alice's challenge. Two checks are stacked here and
   * they guard different things — the extension's protects Bob's choice bits
   * from a cheating receiver, the one below protects Alice's inputs from
   * being inconsistent across instances.
   */
  var st = OTE.sender_extend(base, wire, wire.answer(chi_seed), chi_seed, sid);
  if (!st.ok) return { ok: false, reason: st.reason };

  var g = gadget(p.q, p.xi, sid);

  /*
   * For each OT instance j, Alice holds both halves α⁰ and α¹ and sends the
   * difference plus her input. Bob, holding one half, recovers α⁰ + βⱼ·aᵢ —
   * so their shares differ by exactly βⱼ·aᵢ, and summing against the gadget
   * gives b·aᵢ.
   */
  var a_hat = [];
  for (var k = 0; k < p.rho; k++) a_hat.push(rand_field(p.q, rng));

  var alpha0 = [], alpha1 = [], tilde = [];
  for (var j = 0; j < p.xi; j++) {
    var k0 = expand_row(st, j, p, sid, 0);
    var k1 = expand_row(st, j, p, sid, 1);
    alpha0.push(k0); alpha1.push(k1);
    var row = [];
    for (var i = 0; i < p.ell; i++) {
      row.push(sub(add(sub(k0[i], k1[i], p.q), a[i], p.q), 0n, p.q));
    }
    for (var k = 0; k < p.rho; k++) {
      row.push(add(sub(k0[p.ell + k], k1[p.ell + k], p.q), a_hat[k], p.q));
    }
    tilde.push(row);
  }

  /*
   * ⛔ THE CHALLENGE IS DERIVED FROM ã, AFTER IT IS FIXED.
   *
   * Fiat–Shamir over the derandomised messages. If θ could be known before ã
   * were chosen, Alice could solve for a ã that passes while encoding
   * different inputs in different instances — which is precisely the cheat
   * the check exists to catch.
   */
  var theta = challenge(p, tilde, sid);

  var eta = [];
  for (var k = 0; k < p.rho; k++) {
    var acc = a_hat[k];
    for (var i = 0; i < p.ell; i++) {
      acc = add(acc, mul(theta[i][k], a[i], p.q), p.q);
    }
    eta.push(acc);
  }

  var mu = [];
  for (var j = 0; j < p.xi; j++) {
    var row = [];
    for (var k = 0; k < p.rho; k++) {
      var acc = alpha0[j][p.ell + k];
      for (var i = 0; i < p.ell; i++) {
        acc = add(acc, mul(theta[i][k], alpha0[j][i], p.q), p.q);
      }
      row.push(acc);
    }
    mu.push(row);
  }

  var c = [];
  for (var i = 0; i < p.ell; i++) {
    var acc = 0n;
    for (var j = 0; j < p.xi; j++) {
      acc = add(acc, mul(g[j], alpha0[j][i], p.q), p.q);
    }
    c.push(sub(0n, acc, p.q));
  }

  return {
    ok: true,
    message: { tilde: tilde, eta: eta, mu: digest(p, mu, sid) },
    c: c
  };
}

/**
 * Bob: verify Alice's consistency proof, then take his share.
 *
 * ⚠️ A FAILED CHECK MUST ABORT. Its purpose is that an Alice who passes
 *    cannot have used inconsistent inputs; continuing past a failure makes it
 *    decoration, which is the mistake the OT extension in this library made
 *    twice before it was measured.
 */
function bob_share(state, message) {
  var p = state.p;
  var theta = challenge(p, message.tilde, state.sid);
  var g = gadget(p.q, p.xi, state.sid);

  var gamma = [], mu2 = [];
  for (var j = 0; j < p.xi; j++) {
    var own = expand_row_receiver(state, j, p);
    var row = [];
    for (var i = 0; i < p.ell + p.rho; i++) {
      row.push(state.bits[j]
        ? add(own[i], message.tilde[j][i], p.q) : own[i]);
    }
    gamma.push(row);

    var check = [];
    for (var k = 0; k < p.rho; k++) {
      var acc = row[p.ell + k];
      for (var i = 0; i < p.ell; i++) {
        acc = add(acc, mul(theta[i][k], row[i], p.q), p.q);
      }
      if (state.bits[j]) acc = sub(acc, message.eta[k], p.q);
      check.push(acc);
    }
    mu2.push(check);
  }

  var want = digest(p, mu2, state.sid);
  /* ⛔ ct.equal, which checks the LENGTH: the hand-written loop ran over
     want.length only, so a mu with extra trailing bytes passed */
  if (!(message.mu instanceof Uint8Array) || equal(want, message.mu) !== 1) {
    return { ok: false, reason: 'rvole: the consistency check failed — alice ' +
             'did not derandomise every OT instance with the same input, ' +
             'which is how she would learn bob\'s choice bits' };
  }

  var d = [];
  for (var i = 0; i < p.ell; i++) {
    var acc = 0n;
    for (var j = 0; j < p.xi; j++) {
      acc = add(acc, mul(g[j], gamma[j][i], p.q), p.q);
    }
    d.push(acc);
  }
  return { ok: true, d: d };
}

/** One OT row expanded to ℓ + ρ field elements. */
function expand_row(st, j, p, sid, which) {
  var keys = OTE.sender_keys(st, j);
  return field_elements(which ? keys.k1 : keys.k0, p, sid, j);
}
function expand_row_receiver(state, j, p) {
  return field_elements(OTE.receiver_key(state.ext, j), p, state.sid, j);
}

function field_elements(seed, p, sid, j) {
  var bytes = Math.ceil(p.kappa / 8) + 16;
  var n = p.ell + p.rho;
  /*
   * ⚠ sid WAS ACCEPTED AND NEVER HASHED - in this function and in the two
   *   below. It exists to separate sessions, so leaving it out of the hash
   *   means it separates nothing: two runs with the same inputs derive the
   *   same row expansion and the same Fiat-Shamir challenge, which is the
   *   replay the identifier is there to stop.
   *
   *   Found by the dead-parameter scan, not by any test - nothing fails when
   *   an argument is simply ignored.
   */
  var raw = shake256(concatUint8Arrays([
    utf8('cryptographic-primitives/rvole/v1/row'), be32(sid.length), sid, be32(j), seed
  ]), n * bytes);
  var out = [];
  for (var i = 0; i < n; i++) out.push(field_at(raw, i * bytes, bytes, p.q));
  return out;
}

/** θ ∈ Z_q^{ℓ×ρ}, from the derandomised messages. */
function challenge(p, tilde, sid) {
  var parts = [utf8('cryptographic-primitives/rvole/v1/chi'),
               be32(sid.length), sid, be32(tilde.length)];
  for (var j = 0; j < tilde.length; j++) {
    for (var i = 0; i < tilde[j].length; i++) parts.push(field_bytes(tilde[j][i], p));
  }
  var bytes = Math.ceil(p.kappa / 8) + 16;
  var raw = shake256(concatUint8Arrays(parts), p.ell * p.rho * bytes);
  var theta = [];
  for (var i = 0; i < p.ell; i++) {
    var row = [];
    for (var k = 0; k < p.rho; k++) row.push(field_at(raw, (i * p.rho + k) * bytes, bytes, p.q));
    theta.push(row);
  }
  return theta;
}

/** The ξ×ρ check matrix, compressed — the paper hashes it rather than sending it. */
function digest(p, mu, sid) {
  var parts = [utf8('cryptographic-primitives/rvole/v1/mu'), be32(sid.length), sid];
  for (var j = 0; j < mu.length; j++) {
    for (var k = 0; k < mu[j].length; k++) parts.push(field_bytes(mu[j][k], p));
  }
  return sha256(concatUint8Arrays(parts));
}

/* a field element at the field's width - bigint_to_bytes, which this was a
   hand-written copy of */
function field_bytes(v, p) { return bigint_to_bytes(v, Math.ceil(p.kappa / 8)); }

/*
 * `bytes` hashed bytes at `off`, big-endian, reduced mod q: every expansion
 * here (the gadget, a row, the challenge) reads 16 bytes past the field's
 * width so the reduction's bias is 2^-128. The three loops that did this
 * inline are this one function.
 */
function field_at(raw, off, bytes, q) { return bytes_to_bigint(raw.subarray(off, off + bytes)) % q; }

function add(a, b, q) { return (a + b) % q; }
function sub(a, b, q) { var r = (a - b) % q; return r < 0n ? r + q : r; }
function mul(a, b, q) { return (a * b) % q; }

function rand_field(q, rng) { return random_below_biased(q, rng); }   /* commons/primes */

function bit_length(q) { return q.toString(2).length; }

export { LAMBDA_S, params, bob_sample, alice_multiply, bob_share };
