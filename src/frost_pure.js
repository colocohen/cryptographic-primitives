/**
 * FROST — the pure half, on a generic GROUP.
 *
 * ⭐ Every function below is arithmetic with no
 *    rounds, no parties and no state, and every one of them runs unchanged on
 *    SIX ciphersuites because it takes a GROUP rather than importing a curve.
 *
 * WHAT `cryptographic-primitives/frost.js` NEEDED, AND NOW TAKES FROM HERE
 *
 *   frost.js was written against ristretto255 alone and carried its own
 *   copies of the nonce, the signature share and share verification. The
 *   three scalar operations that kept it off the GROUP interface -
 *   scalar_bytes, scalar_from_uniform_bytes and scalar_mod - are on GROUP
 *   now, and frost.js is a ristretto255 wrapper over this file and
 *   frost_codec.js. What it keeps is the decoding boundary and its one-pass
 *   Pippenger group commitment.
 *
 * ⛔ AND ONE FUNCTION HERE IS NOT GENERIC, DELIBERATELY.
 *
 *    `verify_signature` branches on `bip340`, because BIP-340 is not a
 *    parameter change. It transmits x-only keys, so any point with odd y must
 *    be negated — and there are TWO independent parities, the group key and
 *    the group nonce, decided at different moments.
 *
 *    ⚠️ That cost four wrong versions to get right. The third passed about a
 *       quarter of runs and produced signatures BITCOIN'S OWN VERIFIER
 *       ACCEPTED, because roughly a quarter of (key, nonce) pairs need no
 *       negation at all. A test that ran once would have called it working.
 *
 *    If cryptographic-primitives takes this on, that branch is the part worth reading
 *    twice.
 */

/**
 * Nonce generation — RFC 9591 §4.1.
 *
 * H3(fresh randomness ‖ the secret share).
 *
 * MIXING THE SHARE IN IS NOT BELT AND BRACES. A nonce that repeats across two
 * signatures leaks the share outright, by the same arithmetic that breaks
 * ECDSA under a repeated k. Deriving from randomness alone makes a weak RNG a
 * single point of total failure; deriving deterministically from the share and
 * the message — as plain Ed25519 does — is a COMPLETE KEY-RECOVERY ATTACK in
 * the threshold setting, because a peer can replay the same message with a
 * different commitment list and get two signatures under one nonce. Both
 * inputs are load-bearing, and the RFC's introduction says so.
 */
import { suite, serialize_scalar, deserialize_scalar, derive_interpolating_value, compute_challenge, mod, hash_to_scalar_labelled } from './frost_codec.js';
import { concat as concatUint8Arrays, secure_random } from './commons/bytes.js';
import { batch_all, batch_find, batch_items, group_batch_holds } from './commons/batch.js';

/**
 * A nonce, from fresh randomness AND the secret share.
 *
 * ⚠ THE RNG IS AN ARGUMENT, and reached for globalThis.crypto directly
 *   before. Every generator in this library takes its randomness explicitly -
 *   see commons/primes.js - for three reasons that all apply here: a test can
 *   supply a deterministic one and check against the RFC's published nonces,
 *   the dependency is visible at the call site, and nothing silently falls
 *   back to a weak source if a platform check ever fails.
 *
 * ⚠ AND BOTH INPUTS ARE LOAD-BEARING. Randomness alone makes a weak RNG a
 *   total failure, the way a repeated k breaks ECDSA. Deriving purely
 *   deterministically from the share and the message - as plain Ed25519 does -
 *   is a COMPLETE KEY RECOVERY here, because a peer can replay one message
 *   with a different commitment list and get two signatures under one nonce.
 *
 * The GROUP is NOT an argument: a nonce is a scalar derived by hashing, and
 * nothing here touches a point. It was in the signature and unused, which is
 * the kind of parameter a caller passes something wrong to without noticing.
 *
 * @param {function} rng  returns n random bytes
 */
function nonce_generate(curve, secret, rng) {
  if (typeof rng !== 'function') {
    throw new TypeError('frost: nonce_generate needs an rng - pass a ' +
                        'function returning n random bytes, e.g. ' +
                        'secure_random from commons/bytes.js');
  }
  var r = rng(32);
  return hash_to_scalar_labelled(curve, 'nonce',
    concatUint8Arrays([r, serialize_scalar(curve, secret)]));
}

/**
 * One signer's share — RFC 9591 §5.2.
 *
 *   z_i = hiding + binding·ρ_i + λ_i·sk_i·c
 *
 * Exported because it is the one piece of signing that is pure, deterministic
 * and covered by the RFC's Appendix E vectors: given the nonces the vectors
 * publish, it must reproduce their sig_share exactly.
 */
/*
 * ⭐ ctx.lambda, WHEN GIVEN, IS THE SIGNER'S RECOMBINATION COEFFICIENT, in
 *   place of the Lagrange one over ctx.participants. Under a general access
 *   structure (access.js) the coefficient comes from the structure, not from
 *   identifiers; a caller that has already folded it into the secret passes 1.
 */
function sign_share(G, curve, ctx) {
  var rho = ctx.factors[ctx.identifier.toString()];
  var lam = ctx.lambda != null ? ctx.lambda : derive_interpolating_value(curve, ctx.participants, ctx.identifier);
  return mod(
    ctx.hiding +
    mod(ctx.binding * rho, G.ORDER) +
    mod(lam * mod(ctx.secret * ctx.challenge, G.ORDER), G.ORDER),
    G.ORDER
  );
}

/**
 * Check one signer's share before it poisons the aggregate — §5.3.
 *
 *   z_i·G  ==  (hiding_i + ρ_i·binding_i) + (c·λ_i)·PK_i
 *
 * THIS IS WHAT MAKES AN ABORT ATTRIBUTABLE. Without it, one bad share yields
 * an invalid signature with nothing to say who sent it, and the only recourse
 * is to retry blindly against the party that is breaking it.
 */
/**
 * ⚠ frost.js's verify_share IS THIS, behind a boundary. That one takes encoded
 *   byte strings and a commitment list, does the decoding, and then calls
 *   this with the decoded values. It used to restate the equation as well.
 */
function verify_share(G, curve, ctx) {
  var rho = ctx.factors[ctx.identifier.toString()];
  var lam = ctx.lambda != null ? ctx.lambda : derive_interpolating_value(curve, ctx.participants, ctx.identifier);

  var comm_share = G.add(ctx.hiding_pt, G.mul(rho, ctx.binding_pt));
  var PKi = ctx.PK_i;
  if (ctx.negN) comm_share = G.neg(comm_share);
  if (ctx.negK) PKi = G.neg(PKi);
  var lhs = G.base_mul(mod(ctx.z, G.ORDER));
  var rhs = G.add(comm_share, G.mul(mod(ctx.challenge * lam, G.ORDER), PKi));
  return G.equals(lhs, rhs);
}

/**
 * Ordinary Schnorr verification: z·G == R + c·PK.
 *
 * Nothing in it mentions thresholds or participants — that is the entire
 * selling point, and running it before handing the signature back is how the
 * library knows it produced something a verifier will accept rather than
 * something that merely looks like it.
 */
function verify_signature(G, curve, msg, R_bytes, z, PK_bytes) {
  var v = signature_input(G, curve, msg, R_bytes, z, PK_bytes);
  return v !== null && G.equals(G.base_mul(v.s), G.add(v.R, G.mul(v.c, v.P)));
}

/*
 * Everything verify_signature does before the equation: { R, P, s, c, key },
 * or null. ⭐ ONE FUNCTION for verify_signature and the batch checks.
 */
function signature_input(G, curve, msg, R_bytes, z, PK_bytes) {
  var R  = G.decode(R_bytes);
  var PK = G.decode(PK_bytes);
  if (!R || !PK) return null;

  /*
   * BIP-340 verifies against EVEN-Y points, because that is what an x-only
   * encoding means: the y coordinate is not transmitted and is defined to be
   * even. The signature was produced against those same forms, so the check
   * has to take them too.
   *
   * Idempotent by construction — R as published is already even, so this
   * negates nothing there; a stored public key is compressed and may need it.
   */
  if (suite(curve).bip340) {
    var Rv  = has_odd_y(G.encode(R))  ? G.neg(R)  : R;
    var PKv = has_odd_y(G.encode(PK)) ? G.neg(PK) : PK;
    var c2 = compute_challenge(curve, G.encode(Rv), G.encode(PKv), msg);
    return { R: Rv, P: PKv, s: mod(z, G.ORDER), c: c2, key: PK_bytes };
  }

  var c = compute_challenge(curve, R_bytes, PK_bytes, msg);
  return { R: R, P: PK, s: mod(z, G.ORDER), c: c, key: PK_bytes };
}

/*
 * ⭐ BATCH VERIFICATION of FROST signatures (commons/batch.js), every suite:
 *    items [{ msg, R (bytes), z (bigint), PK (bytes) }], as verify_signature
 *    takes them. verify_signature_batch is true when every item verifies;
 *    verify_signature_batch_find gives the indices of those it rejects. The
 *    same checks (signature_input), and the prime-order group's equation
 *    summed with random weights.
 */
var BATCH_MIN = 8;
function verify_signature_batch(G, curve, items, opts) {
  var c = signature_batch_checks(G, curve, items, opts, 'verify_signature_batch');
  return batch_all(items, c.holds, c.one, BATCH_MIN);
}
function verify_signature_batch_find(G, curve, items, opts) {
  var c = signature_batch_checks(G, curve, items, opts, 'verify_signature_batch_find');
  return batch_find(items, c.holds, c.one, BATCH_MIN);
}
function signature_batch_checks(G, curve, items, opts, who) {
  batch_items(items, who);
  var rng = (opts && opts.rng) || secure_random;
  return {
    holds: function (sub) {
      var entries = [];
      for (var i = 0; i < sub.length; i++) {
        var v = signature_input(G, curve, sub[i].msg, sub[i].R, sub[i].z, sub[i].PK);
        if (v === null) return false;
        entries.push(v);
      }
      return group_batch_holds(G, entries, rng, who);
    },
    one: function (it) { return verify_signature(G, curve, it.msg, it.R, it.z, it.PK); }
  };
}

/** Feldman commitment: one group element per coefficient. */
function poly_commit(G, coeffs) {
  return coeffs.map(function (c) { return G.base_mul(c); });
}

/**
 * Feldman's check: does this share lie on the polynomial that commitment
 * describes?
 *
 *   g^{f(x)} == ∏ C_j^{x^j}
 *
 * This is what stops a dealer from sending a share off the polynomial it
 * published. Without it, a party can hand out inconsistent shares and the
 * failure only surfaces at signing time, with nothing to say who caused it.
 */
function vss_verify(G, commitment, x, share) {
  return G.equals(G.base_mul(share), vss_eval(G, commitment, x));
}

/**
 * The polynomial evaluated in the exponent: Σ_j x^j·C_j = g^{f(x)}.
 *
 * Exported because a DKG needs the VALUE, not just the yes/no — every
 * party's verification share g^{f(i)} is this — and a protocol would
 * otherwise write the same loop at every use. The inputs are public.
 */
function vss_eval(G, commitment, x) {
  var acc = G.IDENTITY;
  var xp = 1n;
  for (var j = 0; j < commitment.length; j++) {
    acc = G.add(acc, G.mul(xp, commitment[j]));
    xp = mod(xp * x, G.ORDER);
  }
  return acc;
}

/**
 * Coefficient-wise sum of several commitments — the commitment to the sum
 * of the polynomials (Feldman is linear). Lengths may differ.
 */
function vss_combine(G, commitments) {
  var out = [];
  for (var i = 0; i < commitments.length; i++) {
    for (var k = 0; k < commitments[i].length; k++) {
      out[k] = out[k] === undefined ? commitments[i][k] : G.add(out[k], commitments[i][k]);
    }
  }
  return out;
}

/**
 * A Schnorr proof that the prover knows the constant term of its own
 * polynomial.
 *
 * WITHOUT THIS THERE IS A ROGUE-KEY ATTACK. The group public key is the sum
 * of every party's constant term. A party that publishes last can choose its
 * own commitment as a function of everyone else's — cancelling theirs out and
 * arriving at a group key it alone controls. Proving knowledge of the
 * discrete log of what you published makes that choice impossible, because
 * you cannot prove knowledge of a value you constructed by subtraction.
 *
 * The session id is bound into the challenge, so a proof from one run cannot
 * be replayed into another; the prover's identity is bound in too, so it
 * cannot be replayed by a different party in the same run.
 */
/**
 * A uniform scalar from an rng, RFC 9591 appendix D.2.
 *
 * ⚠ SAMPLE WIDE AND REDUCE, do not sample the field width and reduce.
 *
 *   Drawing exactly as many bytes as the order and reducing biases the low
 *   values: everything above the order wraps, so those results are twice as
 *   likely. One signature does not reveal it; thousands do, and the bias is
 *   in the nonce, which is the one place it is fatal.
 *
 *   Twice the width leaves the distribution statistically indistinguishable
 *   from uniform, which is what GROUP.scalar_from_uniform_bytes is for.
 *
 * ⚠ AND THIS FUNCTION DID NOT EXIST. pok_prove called `random_scalar` and
 *   nothing defined it - the module loaded, exported cleanly, and threw on
 *   the first call. Every other function here was exercised by a test and
 *   this one was not, which is the same shape as an import that is never
 *   called and a check that always passes.
 */
function random_scalar(G, rng) {
  if (typeof rng !== 'function') {
    throw new TypeError('frost: random_scalar needs an rng');
  }
  var width = G.scalar_bytes(1n).length;
  return G.scalar_from_uniform_bytes(rng(width * 2));
}

function pok_prove(G, curve, sid, self, a0, A0, rng) {
  var k = random_scalar(G, rng);
  var R = G.base_mul(k);
  var c = pok_challenge(G, curve, sid, self, A0, R);
  return { R: G.encode(R), mu: serialize_scalar(curve, mod(k + a0 * c, G.ORDER)) };
}

function pok_verify(G, curve, sid, party, A0, proof) {
  var R = G.decode(proof.R);
  if (!R) return false;
  var mu;
  try { mu = deserialize_scalar(curve, proof.mu); } catch (e) { return false; }
  var c = pok_challenge(G, curve, sid, party, A0, R);
  // g^mu == R + c·A0
  return G.equals(G.base_mul(mu), G.add(R, G.mul(c, A0)));
}

/**
 * The challenge a DKG proof-of-knowledge is bound to.
 *
 * ⚠ IT BINDS THE NUMBER, NOT THE NAME.
 *
 *   RFC 9591 defines a participant identifier as a NonZeroScalar, so that is
 *   what goes into the transcript - which removes an encoding question and is
 *   the right choice for interoperability.
 *
 *   But it means the proof says "the party whose identifier is 3 knows a0",
 *   not "alice knows a0". A caller whose parties are NAMED, with numbers
 *   derived from those names, gets a proof that stays valid under a
 *   DIFFERENT name-to-number mapping - so if a party can be renamed, or if a
 *   group assigns numbers by join order, a proof made under one mapping
 *   verifies under another.
 *
 *   THE sid DOES NOT CLOSE THIS. It stops replay into another session; it
 *   does not stop reinterpretation within one. If the mapping is not fixed
 *   for the lifetime of the sid, the caller must put whatever fixes it -
 *   the name, or a hash of the roster - into the sid itself. Concretely:
 *
 *       sid = concat([base_sid, sha256(ascii(names.sort().join('|')))])
 *
 *   Three lines at the call site, and it costs nothing here: the identifier
 *   stays a NonZeroScalar exactly as the RFC requires, so the encoding stays
 *   interoperable and only the sid grows. Verified to reject a proof made
 *   under a different roster.
 *
 *   Verified: a proof for identifier 1 fails for identifier 2 and fails under
 *   a different sid, and passes for identifier 1 regardless of who 1 is.
 */
function pok_challenge(G, curve, sid, self, A0, R) {
  return hash_to_scalar_labelled(curve, 'dkg-pok', concatUint8Arrays([
    sid,
    serialize_scalar(curve, self),
    G.encode(A0),
    G.encode(R)
  ]));
}

/** BIP-340 encodes 0x03 for a point with odd y. */
function has_odd_y(encoded) { return encoded[0] === 0x03; }

/*
 * sign_engine LIVED HERE AND HAS BEEN REMOVED - 282 lines of it.
 *
 * It drove the two rounds: collecting commitments, deciding who had
 * answered, assembling the list. That is the protocol, and by the rule this
 * file was split on - "does it change when the protocol changes?" - it
 * belongs to the caller, not here.
 *
 * It also referenced platform_rng and check_group_name, which are the
 * caller's helpers and do not exist in this library. So the file loaded,
 * exported ten functions, and carried a function that could not have run -
 * the same shape as pok_prove calling an undefined random_scalar.
 */


/**
 * The group commitment — RFC 9591 §4.5.
 *
 *   R = Σ ( hiding_i + binding_factor_i · binding_i )
 *
 * ⭐ AND THIS IS WHY FROST PRESIGNATURES ARE SAFE WHERE CGGMP'S ARE NOT.
 *
 * The binding factor is a hash over the commitment list AND THE MESSAGE, so R
 * does not exist until the message does. A FROST presignature is a pair of
 * nonces and their commitments — it does not fix R, and an attacker holding
 * one learns nothing they could aim a chosen digest at.
 *
 * A CGGMP presignature is R itself, decided in round three before any message
 * exists. That lets an attacker who knows R craft a digest whose signature
 * transforms into one on a different message — the Groth-Shoup class
 * (eprint 2021/1330), disclosed against CGGMP21 by DFNS in November 2025 and
 * unfixable inside that protocol. cmp_presign.js refuses the combination at
 * the API instead.
 *
 * So the binding factor is not bookkeeping to be simplified away. It is the
 * reason one of these two schemes needs a guard and the other does not.
 *
 * The binding factor is what stops Wagner's attack: a signer cannot influence
 * its own weight without changing a commitment it has already published.
 */
/**
 * Combine the commitments into R, from ALREADY-DECODED points.
 *
 * ⚠ NOT THE SAME FUNCTION AS frost.js's group_commitment, despite the name.
 *   That one takes encoded bytes and DECODES them, which is where a point
 *   off the curve or outside the prime-order subgroup gets refused. This one
 *   takes points and assumes that already happened.
 *
 *   The split is deliberate - validation belongs at the boundary where bytes
 *   arrive, not repeated in the arithmetic - but a caller who reaches for
 *   this one with unvalidated input has skipped the check silently.
 */
function group_commitment(G, list, factors) {
  var R = G.IDENTITY;
  for (var i = 0; i < list.length; i++) {
    var c = list[i];
    var rho = factors[c.identifier.toString()];
    R = G.add(R, G.add(c.hiding_pt, G.mul(rho, c.binding_pt)));
  }
  return R;
}

/**
 * Re-randomized FROST — ZIP 312. Signing and aggregation run unchanged on
 * shifted inputs:
 *
 *   sk_i  ->  sk_i + α        PK_i, PK  ->  PK_i + α·G, PK + α·G
 *
 * which works because the Lagrange coefficients of any signing set sum to 1:
 * Σ λ_i (sk_i + α) = sk + α. The aggregate is an ordinary signature under
 * the randomized key, and α comes from codec.randomizer_from_seed.
 */
function rerandomize_secret(G, secret, alpha) { return mod(secret + alpha, G.ORDER); }

/** P + α·G, for the group key and for each verifying share. */
function rerandomize_public(G, P, alpha) { return G.add(P, G.base_mul(alpha)); }

/*
 * ADAPTOR SIGNATURES live in adaptor.js: checking, completing and opening a
 * Schnorr pre-signature does not depend on who made it, so FROST, one signer
 * and MuSig2 share one copy there.
 */

export {
    nonce_generate,
    sign_share,
    verify_share,
    verify_signature,
    verify_signature_batch,
    verify_signature_batch_find,
    poly_commit,
    vss_verify,
    vss_eval,
    vss_combine,
    pok_prove,
    pok_verify,
    has_odd_y,
    group_commitment,
    rerandomize_secret,
    rerandomize_public,
    /*
     * pok_challenge is exported so a proof can be reconstructed from its
     * parts - a verifier that only gets {R, mu} cannot otherwise recompute
     * what was signed, and a caller debugging a rejected proof has nothing
     * to compare against.
     */
    pok_challenge,
    random_scalar
};
