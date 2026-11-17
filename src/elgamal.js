/**
 * elgamal.js - ElGamal encryption, and threshold decryption over it.
 *
 * ==================== WHY THIS, AND NOT SOMETHING BETTER ====================
 *
 * Classic ElGamal encryption is a museum piece. RSA-OAEP and ECIES do the same
 * job better, and this library's own docs list it among the dead. It is here
 * for a property none of the better schemes has: THE DECRYPTION KEY CAN BE
 * SPLIT, and the pieces can be used without ever being brought together.
 *
 * Decryption is C2 - x*C1. If x is shared additively across parties, each can
 * compute its own x_i*C1 and the pieces add up - so t of n parties can open a
 * ciphertext that none of them can open alone, and the key never exists
 * anywhere. RSA cannot do this, and neither can any block cipher.
 *
 * So: not chosen because it is good encryption, chosen because it is
 * encryption that splits.
 *
 * ==================== WHAT IS NOT REIMPLEMENTED HERE ====================
 *
 * Combining the shares is Lagrange interpolation over group elements, which
 * is `shamir.combine_points` and stays there. Proving a share is honest is a
 * discrete-log equality, which is `dleq` and stays there. This file is the
 * thin part: encrypt, decrypt, produce one share, and wire the other two
 * together.
 *
 * Rewriting either would put the load-bearing arithmetic in two places, and
 * the copy that drifts is the one nobody is testing.
 *
 * ==================== IDENTIFIABILITY ====================
 *
 * A party that returns a wrong share breaks the result and nothing says who.
 * `prove_share` closes that: it proves that the same x behind the party's
 * public V_i = x_i*G also produced D_i = x_i*C1. A verifier that checks every
 * share before combining knows exactly which party to blame, which is the
 * same guarantee threshold signing has.
 *
 * This is why dleq became parameterised by the group: without it, the
 * identifiable half existed only on ristretto255.
 */

import { mod, require_rng, random_below_biased } from './commons/primes.js';
import { concat, ascii, be16 } from './commons/bytes.js';
import { combine_points } from './shamir.js';
import { aes_gcm_encrypt, aes_gcm_decrypt } from './aes.js';
import { sha256, sha512 } from './sha2.js';
import * as dleq from './dleq.js';

/**
 * A keypair, or the public half of a shared key.
 *
 * @param {object}   G
 * @param {function} rng
 */
export function keygen(G, rng) {
    rng = require_rng('keygen', rng);
    var x = random_scalar(G, rng);
    return { secret: x, publicKey: G.base_mul(x) };
}

/* a scalar mod the order, 128 bits of slack: commons/primes (was a copy) */
function random_scalar(G, rng) { return random_below_biased(G.ORDER, rng); }

/**
 * Encrypt a group element.
 *
 * THE MESSAGE IS A POINT, not bytes, and that is not an oversight. ElGamal
 * multiplies; mapping arbitrary bytes onto the curve is a separate problem
 * with its own choices (hash-to-curve, padding, and what happens to a byte
 * string that has no preimage). Callers wanting to encrypt bytes should
 * encrypt a random point, hash it to a key, and use that key on the bytes -
 * which is what ECIES does and what this file deliberately does not decide
 * for them.
 *
 * THE RANDOMNESS COMES BACK, and that is not incidental.
 *
 * `r` is what every proof about this ciphertext needs as a witness -
 * prove_in_range cannot be constructed without it, and neither can any
 * equivalence proof a caller writes later. An API that generated it and threw
 * it away would make those proofs unconstructible two layers up, which is the
 * kind of mistake only discovered once the protocol is already built around
 * the wrong signature. mta.js says the same thing about alice_encrypt for the
 * same reason, and it was still missing here.
 *
 * Keeping it is safe: `r` becomes public the moment a proof about the
 * ciphertext is published, and callers who publish no proof can ignore it.
 *
 * @return {{C1: object, C2: object, r: bigint}}
 */
export function encrypt(G, publicKey, msgPoint, rng) {
    rng = require_rng('encrypt', rng);
    var k = random_scalar(G, rng);
    return {
        C1: G.base_mul(k),
        C2: G.add(msgPoint, G.mul(k, publicKey)),
        r: k
    };
}

/**
 * Encrypt with caller-supplied randomness.
 *
 * For a caller that derived `r` itself - deterministically, or as part of a
 * larger protocol - and needs the ciphertext to match.
 */
export function encrypt_with_randomness(G, publicKey, msgPoint, r) {
    var k = mod(r, G.ORDER);
    return {
        C1: G.base_mul(k),
        C2: G.add(msgPoint, G.mul(k, publicKey)),
        r: k
    };
}

/** Decrypt with the whole key. @return {object} the message point */
export function decrypt(G, secret, C1, C2) {
    return G.add(C2, G.neg(G.mul(mod(secret, G.ORDER), C1)));
}

/**
 * One party's contribution to a threshold decryption.
 *
 * A single scalar multiplication, and the reason the scheme splits at all:
 * the shares of x*C1 compose exactly as the shares of x do.
 *
 * @param {object} G
 * @param {bigint} share   this party's piece of the secret
 * @param {object} C1
 * @return {object} the point x_i * C1
 */
export function decrypt_share(G, share, C1) {
    return G.mul(mod(share, G.ORDER), C1);
}

/**
 * Prove that a decryption share came from the share the party published.
 *
 * The statement: the same x_i with V_i = x_i*G also has D_i = x_i*C1. Without
 * it a party can return anything, the combination is wrong, and nobody knows
 * which one to blame.
 *
 * `domain` IS REQUIRED. It is the separator that stops a share proof made in
 * one setting from being presented in another; a default would make the
 * unbound case the one a caller reaches by forgetting. Pass an empty
 * Uint8Array to opt out where that is genuinely wanted.
 *
 * @param {Uint8Array} domain  application separator, as in dleq
 */
export function prove_share(G, share, C1, rng, domain) {
    rng = require_rng('prove_share', rng);
    return dleq.prove(G, mod(share, G.ORDER), G.GENERATOR, C1, rng, domain);
}

/** @return {boolean} */
export function verify_share(G, V, C1, D, proof, domain) {
    return dleq.verify(G, G.GENERATOR, V, C1, D, proof, domain);
}

/**
 * Combine t shares into the message.
 *
 * `shares` is [{ index, point }] where point is that party's decrypt_share
 * output and index is its Shamir index - the SAME index it held at dealing,
 * because the Lagrange coefficients are computed from them.
 *
 * VERIFY THE SHARES FIRST. This cannot: it has no proofs and no party
 * identities, and a wrong share produces a wrong message with nothing to
 * indicate it. That is the caller's step, and `verify_share` is what it uses.
 *
 * @return {object} the message point
 */
export function combine_shares(G, shares, C2) {
    return G.add(C2, G.neg(interpolate_points(G, shares)));
}

/**
 * Lagrange interpolation at 0 IN THE EXPONENT, on the GROUP interface:
 * Σ λᵢ·Pᵢ for shares [{ index, point }]. The point x·B from t shares xᵢ·B.
 *
 * Exported because threshold VRF, OPRF and partial-decryption verifiers all
 * need the interpolated point itself, and the only way to get it was
 * combine_shares with C2 = identity and a negation — which callers wrote
 * five times. shamir.combine_points is the same sum on the POINT interface;
 * this is its adapter for GROUP.
 *
 * ⛔ DUPLICATE INDICES ARE REFUSED: two shares at one index make a Lagrange
 *    denominator zero, and a repeated contribution must not count twice.
 */
export function interpolate_points(G, shares) {
    var seen = {};
    for (var i = 0; i < shares.length; i++) {
        var k = String(shares[i].index);
        if (seen[k]) { throw new Error('elgamal: duplicate share index ' + k); }
        seen[k] = true;
    }
    var raw = {
        ZERO: G.IDENTITY,
        add: G.add,
        mul: function (k, P) { return G.mul(k, P); }
    };
    return combine_points(raw, shares, G.ORDER, G.ORDER.toString(2).length);
}

/* ==================== sealing arbitrary data ==================== */

/**
 * Encrypt bytes of any length to a threshold public key.
 *
 * THE SCHEME ENCRYPTS A POINT; THIS ENCRYPTS A FILE. `encrypt` above takes a
 * group element because that is what ElGamal multiplies, and mapping a byte
 * string onto the curve is a separate problem the primitive should not decide.
 * The standard construction is to encrypt a RANDOM point, derive a symmetric
 * key from it, and use that on the data - which is what this does, and what
 * every consumer would otherwise write for themselves.
 *
 * ==================== v2: THE ENVELOPE IS NON-MALLEABLE ====================
 *
 * v1 was plain ElGamal plus AES-GCM keyed by H(point). ElGamal is malleable:
 * from (C1, C2) anybody can build (a*C1 + s*G, a*C2 + s*PK), an unrelated-
 * looking ciphertext of a*M. A quorum asked to decrypt THAT - under any
 * innocent label - hands back a*M, and a^-1 of it opens the original
 * envelope. The parties could not tell what they were opening, so "t of n
 * must agree" protected nothing against anybody who could ask.
 *
 * v2 closes it the standard way (signed ElGamal / TDH1-style):
 *
 *   1. A Schnorr proof of knowledge of r with C1 = r*G, whose challenge hashes
 *      PK, C1, C2, the nonce, H(aad) and H(ciphertext). Only somebody who
 *      knows r can produce it, and a mauled C1 has an r nobody knows. Parties
 *      check it BEFORE releasing a share (`verify_sealed`), so the attack
 *      above is refused rather than detected afterwards.
 *   2. The symmetric key is derived from the point AND C1 and C2, so a
 *      re-randomised envelope does not open even if somebody decrypted it.
 *
 * The proof also binds the label (aad): the parties verify against the label
 * they are told, so a ciphertext sealed under one label cannot be presented
 * to them as a request under another.
 *
 * ==================== v3: A SECOND SECRET IN THE KEY ====================
 *
 * `mix`, when given, is called once with (C1, C2) and returns bytes that are
 * hashed into the data key next to the point (v3). The envelope then opens
 * only with BOTH: the point the threshold recovers and those bytes. This is
 * the hook for a hybrid envelope - the caller seals the extra secret some
 * other way (a post-quantum KEM, say), so recording the envelope today and
 * solving the discrete log tomorrow is no longer enough. What the bytes are
 * and how they are protected is the caller's; this only guarantees both are
 * needed.
 *
 * `mix` may instead return { key, bind }: `bind` is hashed into the proof's
 * challenge (under a v3 tag), so whatever the caller attached to the
 * envelope at seal time - its post-quantum block - cannot be altered without
 * the proof failing, and a v3 proof does not verify as a v2 one. Pass the
 * same `bind` to verify_sealed.
 *
 * @param {function} [mix]  (C1, C2) -> Uint8Array | { key, bind }
 * @return {{v: 2|3, C1, C2, nonce, ciphertext, proof: Uint8Array}}
 */
export function seal_to_threshold(G, publicKey, plaintext, rng, aad, mix) {
    rng = require_rng('seal_to_threshold', rng);
    var ad = aad || new Uint8Array(0);
    /* the point the threshold will recover, and the key derived from it */
    var secretPoint = G.base_mul(random_scalar(G, rng));
    var sealed = encrypt(G, publicKey, secretPoint, rng);

    var extra = null, bind = null;
    if (mix != null) {
        if (typeof mix !== 'function') { throw new TypeError('seal_to_threshold: mix must be a function'); }
        extra = mix(sealed.C1, sealed.C2);
        if (extra && !(extra instanceof Uint8Array) && typeof extra === 'object') {
            bind = extra.bind;
            extra = extra.key;
            if (!(bind instanceof Uint8Array)) { throw new TypeError('seal_to_threshold: mix bind must be bytes'); }
        }
        if (!(extra instanceof Uint8Array) || extra.length < 16) {
            throw new TypeError('seal_to_threshold: mix must return at least 16 bytes');
        }
    }

    /* a fresh nonce per seal - reusing one under the same key breaks GCM */
    var nonce = rng(12);
    var ciphertext = aes_gcm_encrypt(
        extra == null
            ? key_from_point_v2(G, secretPoint, sealed.C1, sealed.C2)
            : key_v3(G, secretPoint, sealed.C1, sealed.C2, extra),
        nonce, plaintext, ad);

    /* proof of knowledge of r, bound to everything in the envelope */
    var k = random_scalar(G, rng);
    var A = G.base_mul(k);
    var e = seal_challenge(G, publicKey, sealed.C1, sealed.C2, A, nonce,
                           ciphertext, ad, extra == null ? null : (bind || new Uint8Array(0)));
    var z = mod(k + e * sealed.r, G.ORDER);

    return {
        v: extra == null ? 2 : 3,
        C1: sealed.C1,
        C2: sealed.C2,
        nonce: nonce,
        ciphertext: ciphertext,
        proof: concat([G.encode(A), G.scalar_bytes(z)])
    };
}

/**
 * Check a sealed envelope's proof. What a decrypting party runs BEFORE it
 * releases its share; `aad` is the label it was told it is opening.
 *
 * @return {boolean}
 */
export function verify_sealed(G, publicKey, sealed, aad, bind) {
    if (!sealed || !(sealed.proof instanceof Uint8Array) ||
        !(sealed.nonce instanceof Uint8Array) ||
        !(sealed.ciphertext instanceof Uint8Array) ||
        sealed.C1 == null || sealed.C2 == null) { return false; }
    var pl = sealed.proof.length - G.SCALAR_BYTES;
    if (pl <= 0) { return false; }
    var A = G.decode(sealed.proof.subarray(0, pl));
    if (!A) { return false; }
    var z = G.scalar_from_bytes(sealed.proof.subarray(pl));
    if (z === null) { return false; }
    if (G.equals(sealed.C1, G.IDENTITY)) { return false; }
    /* v3 proofs are under their own tag and cover `bind`; v2 under the v2 tag */
    var b3 = null;
    if (sealed.v === 3) {
        b3 = bind == null ? new Uint8Array(0) : bind;
        if (!(b3 instanceof Uint8Array)) { return false; }
    }
    var e = seal_challenge(G, publicKey, sealed.C1, sealed.C2, A,
                           sealed.nonce, sealed.ciphertext,
                           aad || new Uint8Array(0), b3);
    /* z*G == A + e*C1 */
    /* public: z and A from the envelope, e a hash of published values */
    return G.equals(G.base_mul(z), G.add(A, G.mul_vartime(e, sealed.C1)));
}

/**
 * Open a sealed blob once the threshold has recovered the point.
 *
 * `point` is what combine_shares returned. Nothing here needs the secret key
 * or any share, which is the point: recovery and decryption are separable, so
 * the parties that hold shares never handle the data.
 *
 * A v2 envelope's key is bound to its C1 and C2; an envelope without `v`
 * is a v1 envelope and is opened with the v1 derivation, so data sealed
 * before the change still opens.
 *
 * @return {Uint8Array|null} null when authentication fails
 */
export function open_with_point(G, point, sealed, aad, extra) {
    var key;
    if (sealed.v === 3) {
        /* v3 needs the second secret too; without it there is nothing to try */
        if (!(extra instanceof Uint8Array) || extra.length < 16) { return null; }
        key = key_v3(G, point, sealed.C1, sealed.C2, extra);
    } else if (sealed.v === 2) {
        key = key_from_point_v2(G, point, sealed.C1, sealed.C2);
    } else {
        key = key_from_point(G, point);
    }
    return aes_gcm_decrypt(key, sealed.nonce, sealed.ciphertext,
                           aad || new Uint8Array(0));
}

/**
 * A symmetric key from a group element (v1 envelopes only).
 *
 * DOMAIN-TAGGED AND LENGTH-PREFIXED. Without the tag the same point hashed
 * for two purposes gives the same key, and a protocol that also hashes points
 * for anything else shares its keys with this one by accident.
 */
function key_from_point(G, P) {
    var e = G.encode(P);
    return sha256(concat([ascii('cryptographic-primitives/elgamal/seal/v1'), be16(e.length), e]));
}

/** v2: the key also commits to C1 and C2, so a mauled envelope cannot open. */
function key_from_point_v2(G, P, C1, C2) {
    var parts = [ascii('cryptographic-primitives/elgamal/seal/v2/key')];
    var pts = [P, C1, C2];
    for (var i = 0; i < pts.length; i++) {
        var e = G.encode(pts[i]);   /* constant time: P is the shared point */
        parts.push(be16(e.length), e);
    }
    return sha256(concat(parts));
}

/** v3: the v2 key and the caller's extra secret, length-prefixed. */
function key_v3(G, P, C1, C2, extra) {
    var k2 = key_from_point_v2(G, P, C1, C2);
    var tag = ascii('cryptographic-primitives/elgamal/seal/v3/key');
    return sha256(concat([tag, be16(k2.length), k2, be16(extra.length), extra]));
}

function seal_challenge(G, PK, C1, C2, A, nonce, ciphertext, aad, bind) {
    var parts = [ascii(bind == null ? 'cryptographic-primitives/elgamal/seal/v2/pok' : 'cryptographic-primitives/elgamal/seal/v3/pok'),
                 ascii(G.name || '')];
    var pts = [PK, C1, C2, A];
    for (var i = 0; i < pts.length; i++) {
        var e = G.encode(pts[i]);
        parts.push(be16(e.length), e);
    }
    parts.push(be16(nonce.length), nonce, sha512(ciphertext), sha512(aad));
    if (bind != null) { parts.push(sha512(bind)); }
    return G.hash_to_scalar(concat(parts));
}

/*
 * ⭐ THE PROOF'S SCALAR IS THE GROUP'S OWN ENCODING - G.scalar_bytes and
 *   G.scalar_from_bytes - and the challenges reduce through
 *   G.scalar_from_uniform_bytes. These used to be big-endian on every curve,
 *   at the ORDER's width (56 bytes on ed448 where the group writes 57), while
 *   dleq.js was little-endian on every curve. Envelopes sealed before the
 *   change do not verify after it; the format is the library's own, not a
 *   standard's.
 */

/* ==================== exponential ElGamal ==================== */

/**
 * Encrypt a NUMBER, additively homomorphically.
 *
 * The message goes in the exponent - m*G rather than m - and the whole point
 * is what that buys:
 *
 *     add(enc(a), enc(b)) == enc(a + b)
 *
 * Ciphertexts can be summed without anyone decrypting them. A tally of
 * encrypted votes is the standard example and the reason this variant
 * exists: every voter encrypts a 0 or a 1, anyone can add the ciphertexts,
 * and only the threshold can open the total. No individual vote is ever
 * decrypted, by anyone.
 *
 * ⚠ DECRYPTION IS A SEARCH, so the plaintext must be SMALL. Recovering m
 *   from m*G is a discrete log; `decrypt_number` walks the range and there is
 *   no faster way. Tallies of thousands are fine, arbitrary integers are not,
 *   and this is a property of the scheme rather than of this implementation.
 */
export function encrypt_number(G, publicKey, m, rng) {
    rng = require_rng('encrypt_number', rng);
    return encrypt(G, publicKey, G.base_mul(mod(BigInt(m), G.ORDER)), rng);
}

/**
 * A ballot: the ciphertext AND the proof that it holds a legal value.
 *
 * The two belong together because a ciphertext without its proof is exactly
 * the thing a tally must refuse, and building them separately means a caller
 * has to remember to keep `r` alive between the two calls - which is what was
 * impossible before `encrypt` returned it.
 *
 * @return {{C1, C2, r, proof}}
 */
export function encrypt_number_proved(G, publicKey, m, max, rng, domain) {
    rng = require_rng('encrypt_number_proved', rng);
    var ct = encrypt_number(G, publicKey, m, rng);
    ct.proof = prove_in_range(G, publicKey, ct, BigInt(m), ct.r, max, rng, domain);
    return ct;
}

/**
 * Add two ciphertexts, giving an encryption of the sum.
 *
 * Needs no key and no interaction - which is why a tally can be computed by
 * anyone, including someone with no right to see any of the votes.
 */
export function add_encrypted(G, a, b) {
    return { C1: G.add(a.C1, b.C1), C2: G.add(a.C2, b.C2) };
}

/**
 * Recover the number, by searching up to `max`.
 *
 * @param {object} point  m*G, from decrypt or combine_shares
 * @param {number} max    inclusive upper bound on the plaintext
 * @return {number|null}  null when the value is not in [0, max]
 */
/*
 * ⛔ IT WAS A LINEAR SCAN WITH NO CHECK ON `max`: an absent max returned
 *    null at once (indistinguishable from "not found"), and a large one ran
 *    for as long as it took. Now baby-step giant-step — O(√max) — with max a
 *    required integer in [0, 2^32].
 */
export var RECOVER_MAX = 4294967296;

export function recover_number(G, point, max) {
    if (typeof max === 'bigint') { max = Number(max); }
    if (!(Number.isInteger(max) && max >= 0 && max <= RECOVER_MAX)) {
        throw new RangeError('recover_number: max must be an integer in [0, 2^32]');
    }
    if (!point) { return null; }
    if (G.equals(point, G.IDENTITY)) { return 0; }
    var m = Math.ceil(Math.sqrt(max + 1));
    /* baby steps: j*G for 1 <= j < m */
    var table = new Map();
    var acc = G.GENERATOR;
    for (var j = 1; j < m; j++) {
        table.set(key_of(G, acc), j);
        acc = G.add(acc, G.GENERATOR);
    }
    /* giant steps: point - i*m*G */
    var step = G.neg(G.mul(BigInt(m), G.GENERATOR));
    var cur = point;
    for (var i = 0; i * m <= max; i++) {
        if (G.equals(cur, G.IDENTITY)) { return i * m <= max ? i * m : null; }
        var hit = table.get(key_of(G, cur));
        if (hit !== undefined) {
            var v = i * m + hit;
            return v <= max ? v : null;
        }
        cur = G.add(cur, step);
    }
    return null;
}

function key_of(G, P) {
    var e = G.encode(P), h = '';
    for (var k = 0; k < e.length; k++) { h += (e[k] < 16 ? '0' : '') + e[k].toString(16); }
    return h;
}

/* ==================== proving the plaintext is in range ==================== */

/**
 * Prove that a ciphertext encrypts a number between 0 and `max`.
 *
 * ==================== WHY A TALLY NEEDS THIS ====================
 *
 * `add_encrypted` sums ciphertexts without opening them, and that is the
 * whole appeal - no single vote is ever decrypted, by anyone. It is also the
 * hole: a voter who controls their own client encrypts 1000 instead of 1, the
 * tally absorbs it, and the talliers cannot see because BY DESIGN they never
 * open a single ciphertext.
 *
 * The property that hides the vote is the same property that hides the fraud.
 * So every ciphertext entering a sum has to arrive with a proof that what it
 * holds is a legal value, and this is that proof.
 *
 * ==================== IT IS A DISJUNCTION, NOT A RANGE PROOF ====================
 *
 * The size is linear in `max`, because it literally proves "the plaintext is
 * 0, OR it is 1, OR ... OR it is max" - one simulated Chaum-Pedersen branch
 * per candidate, in the Cramer-Damgard-Schoenmakers composition.
 *
 * That is the right shape when max is SMALL: 1 for a yes/no vote, perhaps 10
 * for quadratic voting. It is the wrong shape past a few dozen, where a real
 * range proof - bulletproofs.js - costs logarithmically instead. The crossover
 * is not sharp; if max runs to thousands, use the other file.
 *
 * ==================== HOW ====================
 *
 * C1 = r*G and C2 = m*G + r*PK, so if m = v then C2 - v*G = r*PK. The claim
 * "the plaintext is v" is therefore the claim that (C1, C2 - v*G) share the
 * discrete log r over the bases (G, PK) - which is dleq's statement, one per
 * candidate, OR-composed.
 *
 * For the true branch the prover runs the protocol forwards; for every other
 * it picks the challenge and response first and computes the commitments
 * backwards, which is indistinguishable. The challenges must sum to the hash
 * of everything, so only one branch can be honest and the prover cannot
 * choose which after seeing the hash.
 *
 * @param {bigint}     m       the plaintext, in [0, max]
 * @param {bigint}     r       the randomness that produced the ciphertext
 * @param {number}     max     inclusive upper bound
 * @param {Uint8Array} domain  application separator
 */
export function prove_in_range(G, publicKey, ct, m, r, max, rng, domain) {
    rng = require_rng('prove_in_range', rng);
    var mv = Number(m);
    if (!(mv >= 0 && mv <= max)) {
        throw new Error('elgamal: plaintext is outside the claimed range');
    }
    var dom = domain || new Uint8Array(0);
    var n = max + 1;
    var i;

    var A = new Array(n), B = new Array(n);
    var e = new Array(n), z = new Array(n);

    /* every branch but the true one is simulated: challenge and response
       first, commitments derived to match */
    var esum = 0n;
    for (i = 0; i < n; i++) {
        if (i === mv) { continue; }
        e[i] = random_scalar(G, rng);
        z[i] = random_scalar(G, rng);
        esum = mod(esum + e[i], G.ORDER);
        var Yi = G.add(ct.C2, G.neg(G.base_mul(BigInt(i))));
        A[i] = G.add(G.base_mul(z[i]), G.neg(G.mul(e[i], ct.C1)));
        B[i] = G.add(G.mul(z[i], publicKey), G.neg(G.mul(e[i], Yi)));
    }

    /* the true branch runs forwards */
    var w = random_scalar(G, rng);
    A[mv] = G.base_mul(w);
    B[mv] = G.mul(w, publicKey);

    var c = range_challenge(G, dom, publicKey, ct, A, B, n);
    e[mv] = mod(c - esum, G.ORDER);
    z[mv] = mod(w + e[mv] * mod(r, G.ORDER), G.ORDER);

    var out = { e: [], z: [], A: [], B: [] };
    for (i = 0; i < n; i++) {
        out.e.push(e[i]); out.z.push(z[i]);
        out.A.push(G.encode(A[i])); out.B.push(G.encode(B[i]));
    }
    return out;
}

/** @return {boolean} */
export function verify_in_range(G, publicKey, ct, proof, max, domain) {
    var dom = domain || new Uint8Array(0);
    var n = max + 1;
    var i;

    try {
        if (!proof || !proof.e || proof.e.length !== n || proof.z.length !== n ||
            proof.A.length !== n || proof.B.length !== n) { return false; }

        var A = new Array(n), B = new Array(n);
        for (i = 0; i < n; i++) {
            if (typeof proof.e[i] !== 'bigint' || typeof proof.z[i] !== 'bigint') {
                return false;
            }
            if (proof.e[i] < 0n || proof.e[i] >= G.ORDER) { return false; }
            if (proof.z[i] < 0n || proof.z[i] >= G.ORDER) { return false; }
            /* decode is the prime-order contract - see commons/group.js */
            A[i] = G.decode(proof.A[i]);
            B[i] = G.decode(proof.B[i]);
            if (!A[i] || !B[i]) { return false; }
        }

        /*
         * THE CHALLENGES MUST SUM TO THE HASH. This is what makes it a
         * disjunction rather than n independent claims: the prover chooses
         * all but one challenge freely, and the last is forced, so exactly
         * one branch can be honest and the hash decides which before the
         * prover sees it.
         */
        var c = range_challenge(G, dom, publicKey, ct, A, B, n);
        var esum = 0n;
        for (i = 0; i < n; i++) { esum = mod(esum + proof.e[i], G.ORDER); }
        if (esum !== mod(c, G.ORDER)) { return false; }

        for (i = 0; i < n; i++) {
            /* z_i*G == A_i + e_i*C1 */
            /* verification: e_i, z_i and every point are published */
            if (!G.equals(G.base_mul(proof.z[i]),
                          G.add(A[i], G.mul_vartime(proof.e[i], ct.C1)))) { return false; }
            /* z_i*PK == B_i + e_i*(C2 - i*G) */
            var Yi = G.add(ct.C2, G.neg(G.base_mul(BigInt(i))));
            if (!G.equals(G.mul_vartime(proof.z[i], publicKey),
                          G.add(B[i], G.mul_vartime(proof.e[i], Yi)))) { return false; }
        }
        return true;
    } catch (err) {
        return false;
    }
}

/** Every public value, and every commitment from every branch. */
function range_challenge(G, dom, publicKey, ct, A, B, n) {
    var parts = [ascii('cryptographic-primitives/elgamal/range/v1'),
                 be16(dom.length), dom, be16(n)];
    var pts = [publicKey, ct.C1, ct.C2];
    var i;
    for (i = 0; i < pts.length; i++) {
        var p = G.encode(pts[i]);
        parts.push(be16(p.length), p);
    }
    for (i = 0; i < n; i++) {
        var a = G.encode(A[i]), b = G.encode(B[i]);
        parts.push(be16(a.length), a, be16(b.length), b);
    }
    return G.hash_to_scalar(concat(parts));
}
