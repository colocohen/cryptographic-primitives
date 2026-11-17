/**
 * Adaptor signatures  -  a signature with one piece missing
 *
 * A PRE-SIGNATURE is locked to a point T = t*G. Anybody checks it belongs to
 * the key, the message and T; it is not a signature; whoever knows t
 * completes it to an ORDINARY signature of the scheme; and from the
 * pre-signature and that signature, anybody recovers t.
 *
 *     verify(pre, msg, P)      ->  boolean
 *     complete(pre, t)         ->  an ordinary signature
 *     extract(pre, sig)        ->  t
 *
 * That last step is what makes the whole thing useful. The secret is not
 * merely protected until payment; it is REVEALED BY the payment, atomically,
 * with no third party and no extra protocol step: cross-chain atomic swaps
 * (each side an ordinary signature, nothing on either chain linking them),
 * Lightning's PTLCs, Discreet Log Contracts.
 *
 * ========================= WHAT LIVES IN THIS FILE =========================
 *
 * ⭐ EVERYTHING THAT DEPENDS ONLY ON THE KIND OF SIGNATURE, ONCE: checking,
 *   completing, extracting, the encoding, the proof. A Schnorr pre-signature
 *   is checked, completed and opened the same way whether one signer made
 *   it, a FROST quorum, or MuSig2; an ECDSA pre-signature is the same 162
 *   bytes whether one signer or a threshold ECDSA protocol produced it.
 *
 * MAKING ONE LIVES WITH THE PROTOCOL THAT MAKES IT. One signer is here
 * (`schnorr_pre_sign`, `ecdsa_pre_sign`), because for one signer there is no
 * other protocol. A threshold pre-signature belongs to the threshold
 * protocol, which calls the pieces below (`schnorr_nonce`, `dleq_challenge`,
 * `dleq_share_ok`).
 *
 * This was three files - a BIP-340-only adaptor.js, adaptor functions inside
 * frost_pure.js, and ecdsa_adaptor.js - with the first two doing the same
 * work on taproot in two different formats.
 *
 * ================================= SCHNORR =================================
 *
 *     c  = H(R + T, P, m)        s' = r + c*x        s'*G = R + c*P
 *
 * Adding t gives (R + T, s' + t), an ordinary signature of the suite; t is
 * s - s'. Every FROST ciphersuite (frost_codec.js): RFC 8032 on ed25519 and
 * ed448, and BIP-340 on taproot.
 *
 * BIP-340 signs with an EVEN-y nonce point: when R + T has odd y the nonce
 * is negated, so s' = -r + c*x, the check is s'*G = -R + c*P, and the
 * completed signature is (-(R + T), s' - t) - the sign of t flips. Both sides
 * derive it from R + T, so it is never transmitted.
 *
 * A Schnorr pre-signature is { R, T, s }: R (the nonce point WITHOUT T) and T
 * encoded points - for BIP-340 the 33-byte forms, since the parity of R + T
 * needs them - and s a scalar.
 *
 * ================================== ECDSA ==================================
 *
 * Two nonce points with the SAME secret k, one on each base:
 *
 *     R' = k*G        R = k*T        r = x(R) mod q
 *     s' = k^-1 (m + r*x)
 *
 * plus a Chaum-Pedersen proof that R' and R share k. The check is ordinary
 * ECDSA's, against R' rather than R:  R' == s'^-1 (m*G + r*X). Completing:
 * s = s' * t^-1 is the signature with nonce k*t, whose nonce point is R.
 * Extracting: t = s'/s, up to the sign low-s may have flipped, which T
 * settles.
 *
 * ⭐ THE FORMAT IS libsecp256k1-zkp's ecdsa_adaptor module (Jonas Nick,
 *   Jesse Posner; the DLC specification's ECDSA adaptor signatures), field
 *   for field, so a pre-signature made here verifies in every wallet and DLC
 *   implementation built on that library, and theirs verify here:
 *
 *     R (33) | R' (33) | s' (32) | proof e (32) | proof s (32)
 *
 *     DLEQ challenge  e = tagged_hash("DLEQ", R' | T | R | A1 | A2) mod q
 *     DLEQ response   s = rho + e*k
 *
 *   Their names: T is the "encryption key", t the "decryption key";
 *   complete is "decrypt", extract is "recover". The tests run the
 *   specification's vectors (test/vectors/curves/ecdsa_adaptor_zkp.json).
 *   P-256, P-384 and P-521 use the same construction at their own sizes - no
 *   standard covers them.
 *
 * ⚠ THE DLEQ HERE IS NOT dleq.js's. Same proof, but this challenge is pinned
 *   byte for byte by libsecp256k1-zkp, and dleq.js's carries the library's
 *   own domain-separated transcript - see the note above its `challenge`.
 *
 * ================================= CAVEATS =================================
 *
 * ⛔ ONE PRE-SIGNATURE PER NONCE. Two pre-signatures under one nonce reveal
 *   the key, as two signatures do; completing reveals t to everybody who saw
 *   the pre-signature - that is the point.
 */

import { mod, require_rng } from './commons/primes.js';
import { field } from './commons/modp.js';
import { bytes_to_bigint, bigint_to_bytes, concat, secure_random } from './commons/bytes.js';
import { bits2int_q } from './commons/ecdsa.js';
import { tagged_hash } from './secp256k1.js';
import { sha256 } from './sha2.js';
import { suite, serialize_scalar, serialize_signature, compute_challenge, hash_to_scalar_labelled } from './frost_codec.js';
import { has_odd_y } from './frost_pure.js';

function scalar_ok(G, v) { return v > 0n && v < G.ORDER; }

/*
 * The same refusal for every kind, so a caller can match one message.
 */
function not_this_one() { return new Error('adaptor: the signature does not complete this pre-signature'); }
function not_secret() { return new Error('adaptor: t is not the secret of T'); }

/* ===================================================================== *
 *  SCHNORR
 * ===================================================================== */

/** The point the challenge is over, R + T, and whether BIP-340 negates the nonce. */
export function schnorr_nonce(G, curve, R, T) {
    var full = G.add(R, T);
    var neg = !!suite(curve).bip340 && has_odd_y(G.encode(full));
    return { point: neg ? G.neg(full) : full, neg: neg };
}

/*
 * The key as the verifier uses it: BIP-340's x-only form (32 bytes) lifts to
 * even y, and a compressed key with odd y is negated - the same convention
 * frost_pure.verify_signature applies.
 */
function schnorr_key(G, curve, PK_bytes) {
    var bip = !!suite(curve).bip340;
    var b = bip && PK_bytes && PK_bytes.length === 32 ? concat([new Uint8Array([2]), PK_bytes]) : PK_bytes;
    var P = b ? G.decode(b) : null;
    if (!P) { return null; }
    return bip && has_odd_y(G.encode(P)) ? G.neg(P) : P;
}

/** Is `pre` a pre-signature of `msg` under the key PK_bytes and its T? */
export function schnorr_verify(G, curve, msg, pre, PK_bytes) {
    var R = G.decode(pre.R), T = G.decode(pre.T), P = schnorr_key(G, curve, PK_bytes);
    if (!R || !T || !P || G.equals(T, G.IDENTITY)) { return false; }
    var a = schnorr_nonce(G, curve, R, T);
    var c = compute_challenge(curve, G.encode(a.point), G.encode(P), msg);
    return G.equals(G.base_mul(mod(pre.s, G.ORDER)), G.add(a.neg ? G.neg(R) : R, G.mul_vartime(c, P)));
}

/**
 * The signature, from a pre-signature and t: { R, z, bytes } - R the encoded
 * nonce point, z the scalar, bytes the suite's encoding (x(R) | z on
 * BIP-340, R | z elsewhere, with schnorrkel's marker on sr25519).
 */
export function schnorr_complete(G, curve, pre, t) {
    var R = G.decode(pre.R), T = G.decode(pre.T);
    if (!R || !T) { throw new Error('adaptor: a malformed pre-signature'); }
    if (!scalar_ok(G, t) || !G.equals(G.base_mul(t), T)) { throw not_secret(); }
    var a = schnorr_nonce(G, curve, R, T);
    var Rb = G.encode(a.point), z = mod(a.neg ? pre.s - t : pre.s + t, G.ORDER), zb = serialize_scalar(curve, z);
    return { R: Rb, z: z, bytes: suite(curve).bip340 ? concat([Rb.subarray(1), zb]) : serialize_signature(curve, Rb, z) };
}

/** t, from the pre-signature and the signature's scalar z - checked against T. */
export function schnorr_extract(G, curve, pre, z) {
    var R = G.decode(pre.R), T = G.decode(pre.T);
    if (!R || !T) { throw new Error('adaptor: a malformed pre-signature'); }
    var t = mod(schnorr_nonce(G, curve, R, T).neg ? pre.s - z : z - pre.s, G.ORDER);
    if (t === 0n || !G.equals(G.base_mul(t), T)) { throw not_this_one(); }
    return t;
}

/**
 * A pre-signature by one signer holding x, on any FROST suite.
 *
 * The nonce is hedged: fresh randomness AND the key, the message and T, under
 * the suite's own hash - so a weak rng alone does not repeat a nonce, and two
 * pre-signatures of one message under two T never share one (which would
 * give the key away by the usual nonce-reuse arithmetic). rng omitted or
 * null draws fresh ones from the platform.
 */
export function schnorr_pre_sign(G, curve, msg, x, T_bytes, rng) {
    rng = require_rng('adaptor.schnorr_pre_sign', rng);
    if (!scalar_ok(G, x)) { throw new Error('adaptor: invalid secret key'); }
    var T = G.decode(T_bytes);
    if (!T) { throw new Error('adaptor: T is not a point of the group'); }
    var P = G.base_mul(x);
    if (suite(curve).bip340 && has_odd_y(G.encode(P))) { x = G.ORDER - x; P = G.neg(P); }
    var r = hash_to_scalar_labelled(curve, 'adaptor nonce',
        concat([rng(32), serialize_scalar(curve, x), G.encode(T), msg]));
    if (r === 0n) { throw new Error('adaptor: nonce was zero'); }
    var R = G.base_mul(r), a = schnorr_nonce(G, curve, R, T);
    var c = compute_challenge(curve, G.encode(a.point), G.encode(P), msg);
    return { R: G.encode(R), T: G.encode(T), s: mod((a.neg ? -r : r) + c * x, G.ORDER) };
}

/* ===================================================================== *
 *  ECDSA  -  libsecp256k1-zkp's format
 * ===================================================================== */

/**
 * Point and scalar widths for a group, and the pre-signature's length:
 * 2 compressed points and 3 scalars - 162 bytes on secp256k1.
 */
export function ecdsa_sizes(G) {
    var pl = G.encode(G.GENERATOR).length;
    var sl = G.SCALAR_BYTES;
    return { point: pl, scalar: sl, length: 2 * pl + 3 * sl };
}

/**
 * The message as a scalar: ECDSA's bits2int, reduced. On secp256k1 a 32-byte
 * hash is read whole and reduced mod n - libsecp256k1's scalar_set_b32.
 */
export function ecdsa_message_scalar(G, msg) {
    return mod(bits2int_q(msg, G.ORDER.toString(2).length), G.ORDER);
}

/** r = x(P) mod q, from the compressed encoding. */
export function ecdsa_x_scalar(G, P) {
    return mod(bytes_to_bigint(G.encode(P).subarray(1)), G.ORDER);
}

/* ---------------- the DLEQ proof ---------------- */

/**
 * The challenge for "P1 = k*G and P2 = k*T", with nonce points A1 = rho*G and
 * A2 = rho*T. libsecp256k1-zkp's secp256k1_dleq_challenge: the DLEQ tagged
 * hash over P1, T, P2, A1, A2 - in that order - reduced mod q.
 */
export function dleq_challenge(G, T, P1, P2, A1, A2) {
    var h = tagged_hash('DLEQ', [G.encode(P1), G.encode(T), G.encode(P2), G.encode(A1), G.encode(A2)]);
    return mod(bytes_to_bigint(h), G.ORDER);
}

/** Prove P1 = k*G, P2 = k*T for a known k. rho is the proof's own nonce. */
export function dleq_prove(G, k, T, rho) {
    if (!scalar_ok(G, rho)) { throw new Error('adaptor: the DLEQ nonce must be a non-zero scalar'); }
    var P1 = G.base_mul(k), P2 = G.mul(k, T);
    var e = dleq_challenge(G, T, P1, P2, G.base_mul(rho), G.mul(rho, T));
    return { e: e, s: mod(rho + e * k, G.ORDER) };
}

/**
 * Check a DLEQ proof. libsecp256k1-zkp's secp256k1_dleq_verify: rebuild
 * A1 = s*G - e*P1 and A2 = s*T - e*P2, refuse either as the identity, and
 * compare the challenge.
 */
export function dleq_verify(G, T, P1, P2, proof) {
    var q = G.ORDER, ne = mod(-proof.e, q);
    var A1 = G.add(G.base_mul(proof.s), G.mul_vartime(ne, P1));
    var A2 = G.add(G.mul_vartime(proof.s, T), G.mul_vartime(ne, P2));
    if (G.equals(A1, G.IDENTITY) || G.equals(A2, G.IDENTITY)) { return false; }
    return dleq_challenge(G, T, P1, P2, A1, A2) === mod(proof.e, q);
}

/**
 * ONE SHARE of a joint DLEQ response, checked on its own.
 *
 * A threshold signer splits the witness: k = c * sum(w_i), where party i
 * holds w_i and publishes W1_i = w_i*G, W2_i = w_i*T and nonce points
 * A1_i = rho_i*G, A2_i = rho_i*T. The joint challenge is over
 * A1 = c*sum(A1_i), A2 = c*sum(A2_i); party i answers z_i = rho_i + e*w_i and
 * the proof's response is c*sum(z_i). This is the check of one z_i - so a
 * wrong one names its sender instead of spoiling the proof anonymously.
 */
export function dleq_share_ok(G, T, e, A1, A2, W1, W2, z) {
    return G.equals(G.base_mul(z), G.add(A1, G.mul_vartime(e, W1))) &&
           G.equals(G.mul_vartime(z, T), G.add(A2, G.mul_vartime(e, W2)));
}

/* ---------------- encoding ---------------- */

/**
 * The pre-signature, as bytes: R | R' | s' | e | s. Fields are points
 * (R, Rp) and bigints (sp, e, z).
 */
export function ecdsa_encode(G, pre) {
    var sl = G.SCALAR_BYTES;
    return concat([G.encode(pre.R), G.encode(pre.Rp), bigint_to_bytes(pre.sp, sl),
                   bigint_to_bytes(pre.e, sl), bigint_to_bytes(pre.z, sl)]);
}

/**
 * Parse a pre-signature, or null. libsecp256k1-zkp's deserialisation rules:
 * both points on the curve; r = x(R) mod q not zero; s' in [1, q); the
 * proof's s below q. The proof's e is taken mod q, as a hash output is.
 */
export function ecdsa_decode(G, bytes) {
    var z = ecdsa_sizes(G);
    if (!(bytes instanceof Uint8Array) || bytes.length !== z.length) { return null; }
    var pl = z.point, sl = z.scalar;
    var R = G.decode(bytes.subarray(0, pl));
    var Rp = G.decode(bytes.subarray(pl, 2 * pl));
    if (R === null || Rp === null) { return null; }
    var o = 2 * pl;
    var sp = bytes_to_bigint(bytes.subarray(o, o + sl));
    var e = mod(bytes_to_bigint(bytes.subarray(o + sl, o + 2 * sl)), G.ORDER);
    var s = bytes_to_bigint(bytes.subarray(o + 2 * sl, o + 3 * sl));
    if (!scalar_ok(G, sp) || s >= G.ORDER || ecdsa_x_scalar(G, R) === 0n) { return null; }
    return { R: R, Rp: Rp, sp: sp, e: e, z: s };
}

function parsed(G, pre) { return pre instanceof Uint8Array ? ecdsa_decode(G, pre) : pre; }

/* ---------------- verify, complete, extract ---------------- */

/**
 * Is `pre` (bytes or parsed) a pre-signature by X on msg, locked to T? The
 * proof, then ordinary ECDSA's equation against R': R' == s'^-1 (m*G + r*X).
 * libsecp256k1-zkp's secp256k1_ecdsa_adaptor_verify.
 */
export function ecdsa_verify(G, msg, pre, X, T) {
    var p = parsed(G, pre);
    if (!p || !X || !T) { return false; }
    if (!dleq_verify(G, T, p.Rp, p.R, { e: p.e, s: p.z })) { return false; }
    var q = G.ORDER, w = field(q).inv_vartime(p.sp);
    var U = G.add(G.base_mul(mod(ecdsa_message_scalar(G, msg) * w, q)),
                  G.mul_vartime(mod(ecdsa_x_scalar(G, p.R) * w, q), X));
    if (G.equals(U, G.IDENTITY)) { return false; }
    return G.equals(U, p.Rp);
}

/**
 * Complete with t: s = s' * t^-1, then low-s - libsecp256k1-zkp's
 * secp256k1_ecdsa_adaptor_decrypt, with t checked against T first.
 *
 * Returns { r, s } as bigints, and `raw`, the s before low-s: the nonce point
 * is R for raw and -R for s when they differ, which a recovery id needs.
 * t is secret, so its inverse is Fermat's (constant time), not Euclid's.
 */
export function ecdsa_complete(G, pre, t, T) {
    var p = parsed(G, pre);
    if (!p) { throw new Error('adaptor: a malformed pre-signature'); }
    if (!scalar_ok(G, t) || !T || !G.equals(G.base_mul(t), T)) { throw not_secret(); }
    var q = G.ORDER, raw = mod(p.sp * field(q).inv(t), q);
    return { r: ecdsa_x_scalar(G, p.R), s: raw > q >> 1n ? q - raw : raw, raw: raw };
}

/**
 * t, from a signature { r, s } that completes this pre-signature -
 * libsecp256k1-zkp's secp256k1_ecdsa_adaptor_recover: r must be the
 * pre-signature's; t = s'/s; whichever of t and -t gives T. A high-s
 * signature is accepted - its t simply comes out with the other sign.
 */
export function ecdsa_extract(G, pre, sig, T) {
    var p = parsed(G, pre);
    if (!p || !sig || !T) { throw not_this_one(); }
    var q = G.ORDER;
    if (sig.r !== ecdsa_x_scalar(G, p.R) || !scalar_ok(G, sig.s)) { throw not_this_one(); }
    var t = mod(p.sp * field(q).inv_vartime(sig.s), q);
    if (G.equals(G.base_mul(t), T)) { return t; }
    if (G.equals(G.base_mul(q - t), T)) { return q - t; }
    throw not_this_one();
}

/* ---------------- one signer ---------------- */

/*
 * libsecp256k1-zkp's nonce function: BIP-340's, with its own tags. Hash
 * (key, masked by aux when given) | pk33 | msg32 under the algorithm's tag.
 * An EMPTY aux is no aux - libsecp256k1-zkp with no ndata - tested on its
 * length, since an empty Uint8Array is truthy.
 */
function zkp_nonce(key32, pk, msg32, algo, aux32) {
    var k = key32;
    if (aux32 && aux32.length) {
        var mask = tagged_hash('ECDSAadaptor/aux', [aux32]);
        k = new Uint8Array(32);
        for (var i = 0; i < 32; i++) { k[i] = key32[i] ^ mask[i]; }
    }
    return tagged_hash(algo, [k, pk, msg32]);
}

/**
 * A pre-signature by one signer holding x - secp256k1_ecdsa_adaptor_encrypt,
 * with its nonce derivation: k from (x, T, msg) under "ECDSAadaptor/non",
 * the proof's nonce from (k, T, sha256(R' | R)) under "DLEQ". `aux` (32
 * bytes) hedges both, as libsecp256k1-zkp's ndata does: omitted or null
 * draws fresh ones from the platform, and an EMPTY Uint8Array asks for no
 * hedge at all - the deterministic pre-signature of libsecp256k1-zkp called
 * without ndata.
 *
 * secp256k1 only: the nonce function reads a 32-byte key and message.
 * Returns the 162 bytes.
 */
export function ecdsa_pre_sign(G, msg32, x, T, aux) {
    if (G.name !== 'secp256k1') { throw new Error('adaptor: ecdsa_pre_sign follows libsecp256k1-zkp and is secp256k1-only'); }
    if (!(msg32 instanceof Uint8Array) || msg32.length !== 32) { throw new Error('adaptor: the message is a 32-byte hash'); }
    if (!scalar_ok(G, x)) { throw new Error('adaptor: invalid secret key'); }
    if (aux == null) { aux = secure_random(32); }
    var q = G.ORDER, xb = bigint_to_bytes(x, 32), Tb = G.encode(T);
    var k = mod(bytes_to_bigint(zkp_nonce(xb, Tb, msg32, 'ECDSAadaptor/non', aux)), q);
    if (k === 0n) { throw new Error('adaptor: nonce was zero'); }
    var R = G.mul(k, T), Rp = G.base_mul(k);
    var r = ecdsa_x_scalar(G, R);
    if (r === 0n) { throw new Error('adaptor: r is zero'); }
    var h = sha256(concat([G.encode(Rp), G.encode(R)]));
    var rho = mod(bytes_to_bigint(zkp_nonce(bigint_to_bytes(k, 32), Tb, h, 'DLEQ', aux)), q);
    var proof = dleq_prove(G, k, T, rho);
    var sp = mod(field(q).inv(k) * mod(ecdsa_message_scalar(G, msg32) + r * x, q), q);
    return ecdsa_encode(G, { R: R, Rp: Rp, sp: sp, e: proof.e, z: proof.s });
}
