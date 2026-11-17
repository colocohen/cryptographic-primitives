/**
 * Chaum-Pedersen  -  proving two discrete logarithms are equal
 *
 * Given four points, prove that
 *
 *     B = k*A   and   D = k*C
 *
 * for the SAME secret k, without revealing k. Also called a DLEQ proof.
 *
 * WHAT IT IS FOR. On its own "I know the discrete log of B in base A" is a
 * Schnorr proof and this library already has one. The extra thing here is
 * that the SAME exponent was used in two places, and that turns out to be the
 * exact shape of several questions:
 *
 *   - "Did the server use its published key?" A verifiable OPRF is precisely
 *     this: the client checks that the key applied to its blinded input is
 *     the one that produced the advertised public key. Without it a malicious
 *     server uses a different key per client and deanonymises them by the
 *     output.
 *   - "Was this ciphertext re-encrypted honestly?" A mix network shuffles and
 *     re-randomises ciphertexts; the DLEQ proves the same randomiser was
 *     applied consistently, so nothing was substituted.
 *   - "Is this decryption share correct?" In threshold decryption each party
 *     publishes a partial decryption, and this proves it used its real key
 *     share rather than a value that would corrupt the result.
 *   - "Is this VRF output the right one?" ECVRF's proof is a DLEQ.
 *
 * IT WAS ALREADY IN THIS LIBRARY, inside oprf.js, tangled up with that
 * protocol's transcript format and its three modes. This is the same
 * mechanism with nothing protocol-specific attached, and oprf.js keeps its
 * own copy because RFC 9497 fixes the exact byte layout of the challenge -
 * a shared version that let the transcript vary would not be interoperable
 * with anything.
 *
 * THE PROOF IS FIAT-SHAMIR, so it is non-interactive and its soundness rests
 * entirely on what goes into the challenge hash. Every point the verifier
 * uses is absorbed below; a transcript that omits one lets a prover choose
 * the challenge after the fact and forge.
 */


var EMPTY_DOMAIN = new Uint8Array(0);
import { concat, ascii, be16 } from './commons/bytes.js';
import { mod, require_rng } from './commons/primes.js';

/*
 * ==================== THE GROUP IS A PARAMETER ====================
 *
 * `G` is a prime-order group (see commons/group.js) and defaults to
 * ristretto255, which is what every existing caller gets and what every
 * existing test exercises.
 *
 * IT IS HERE BECAUSE THRESHOLD DECRYPTION NEEDS IT ON A DIFFERENT CURVE. A
 * party returning a wrong decryption share breaks the result and nobody knows
 * who; the fix is exactly this proof - "the same x with V = x*G also has
 * D = x*C1" - and elgamal.js runs it over whichever group the caller chose.
 * Locked to ristretto, the identifiable half simply does not exist on
 * secp256k1.
 *
 * THE SCALAR HELPERS ARE PLAIN MODULAR ARITHMETIC, which is why one code path
 * suffices. ristretto255's scalar_mod, scalar_mul and scalar_from_uniform_
 * bytes were checked against `mod(x, ORDER)` and a little-endian reduction of
 * the same bytes, and agree exactly - so the generic versions below produce
 * byte-identical proofs on the default group. A second code path for the
 * default would have been two things to keep in step.
 */
/*
 * THE GROUP IS THE FIRST ARGUMENT AND IS REQUIRED.
 *
 * It used to be last with a ristretto255 default, which was a concession to
 * callers that no longer exists - nothing has shipped. A default group is the
 * kind of convenience that decides something important on the caller's
 * behalf: a proof produced over the wrong curve is not a proof, and an
 * omitted argument is a poor way to find that out.
 *
 * First, because it is the context every other argument is interpreted in -
 * the same position it holds in zk_cmp and elgamal.
 */

/*
 * ⭐ SCALARS ARE THE GROUP'S OWN: G.scalar_bytes, G.scalar_from_bytes and
 *   G.scalar_from_uniform_bytes. This file used to write and read
 *   LITTLE-endian on every curve (zk_bytes.scalar_bytes, at the order's
 *   width), which matched ristretto255 and nobody else - schnorr.js did the
 *   opposite. Proofs over ristretto255 are byte-identical to before; over the
 *   SEC 1 curves the scalars are now big-endian, and on ed448 57 bytes, as
 *   those curves carry scalars everywhere else. No standard fixes this
 *   format; it is the library's own.
 */


/**
 * The challenge, over the whole statement plus the prover's nonce points.
 *
 * FIVE FILES HAVE A FUNCTION WITH THIS NAME - dleq, frost, pedersen, ring and
 * ecvrf - and they are deliberately not shared. Each hashes a different
 * transcript because each is pinned by something: RFC 9591 fixes FROST's byte
 * layout, RFC 9381 fixes ECVRF's down to the 0x02 and 0x00 separators, ring
 * signatures absorb a variable-length ring and a key image, and this one
 * carries its own domain tag.
 *
 * A shared version parameterised by the transcript would be longer than any
 * of them and would let a caller produce a challenge that no other
 * implementation of that protocol computes - which is a correctness failure
 * that looks like nothing until interoperation is attempted.
 *
 * The four statement points and both commitments are all included and
 * length-prefixed. A DOMAIN STRING is mixed in as well, so a proof produced
 * for one application cannot be replayed as a proof in another - the same
 * separation that cSHAKE and HKDF's `info` provide.
 */
function challenge(G, domain, A, B, C, D, t1, t2) {
    var parts = [ascii('cryptographic-primitives/dleq/v1'), be16(domain.length), domain];
    var pts = [A, B, C, D, t1, t2];
    for (var i = 0; i < pts.length; i++) {
        var e = G.encode(pts[i]);
        parts.push(be16(e.length), e);
    }
    return G.hash_to_scalar(concat(parts));
}

/**
 * Prove that B = k*A and D = k*C.
 *
 * @param {bigint}     k       the secret exponent
 * @param {object}     A, C    the two bases
 * @param {function}   rng
 * @param {Uint8Array} [domain]  application separator
 * @return {{c: Uint8Array, s: Uint8Array}} 64 bytes when encoded
 */
export function prove(G, k, A, C, rng, domain) {
    rng = require_rng('prove', rng);
    var dom = domain || EMPTY_DOMAIN;
    var kk = mod(k, G.ORDER);

    var B = G.mul(kk, A);
    var D = G.mul(kk, C);

    /*
     * One nonce, used against BOTH bases. That is what ties the two
     * statements together: a prover with different exponents could satisfy
     * either equation alone but not both against a single r.
     */
    var r = G.random_scalar(rng);   /* not rng(64): too short for P-521 */
    var t1 = G.mul(r, A);
    var t2 = G.mul(r, C);

    var c = challenge(G, dom, A, B, C, D, t1, t2);
    var s = mod(r - mod(c * kk, G.ORDER), G.ORDER);

    return { c: G.scalar_bytes(c), s: G.scalar_bytes(s) };
}

/**
 * @return {boolean}
 *
 * Recomputes the nonce points from the response and the challenge - if the
 * proof is honest, s*A + c*B reconstructs t1 exactly - then checks that
 * hashing them reproduces the challenge that was sent.
 */
export function verify(G, A, B, C, D, proof, domain) {
    if (!proof || !(proof.c instanceof Uint8Array) || !(proof.s instanceof Uint8Array)) { return false; }
    var dom = domain || EMPTY_DOMAIN;

    /*
     * ⛔ CANONICAL SCALARS ONLY. The bytes were reduced mod the order before
     *    the `>= ORDER` check, so the check could never fire: c + q, and any
     *    length of bytes, decoded to the same c — a second, different-looking
     *    proof of the same statement for anyone holding one. Exactly the
     *    scalar width, in the group's byte order, below the order, or
     *    refused - which is GROUP.scalar_from_bytes.
     */
    var c = G.scalar_from_bytes(proof.c), s = G.scalar_from_bytes(proof.s);
    if (c === null || s === null) { return false; }

    /* verification: every scalar and point here is public */
    var t1 = G.add(G.mul_vartime(s, A), G.mul_vartime(c, B));
    var t2 = G.add(G.mul_vartime(s, C), G.mul_vartime(c, D));

    return challenge(G, dom, A, B, C, D, t1, t2) === c;
}

/** The 64-byte wire form. *
 * @return {object|null} A proof, or null if the bytes are not a valid encoding.
 */
export function encode(proof) { return concat([proof.c, proof.s]); }

export function decode(bytes, G) {
    /* the width is the group's scalar width; ristretto255 when unspecified */
    var w = G ? G.SCALAR_BYTES : 32;
    if (!(bytes instanceof Uint8Array) || bytes.length !== 2 * w) { return null; }
    return { c: bytes.subarray(0, w), s: bytes.subarray(w) };
}


/**
 * The common special case: prove that a public key and a second point share
 * an exponent, where the first base is the group generator.
 *
 * `PK = k*G` is the published key and `D = k*C` is the operation being
 * justified - a decryption share, an OPRF evaluation, a VRF output.
 */
/*
 * ⚠ EVERYTHING HERE IS FOR PRIME-ORDER GROUPS, and that is not a limitation
 *   that can be lifted by passing a different G.
 *
 *   The Schnorr response reduces the challenge modulo the group order. In
 *   Z*_n the order is phi(n)/4 and is SECRET - a verifier who knew it could
 *   factor n - so the same proof cannot be written. The unknown-order
 *   version draws the mask from a range wide enough to statistically hide
 *   c*x over the INTEGERS, and its soundness is statistical rather than
 *   perfect.
 *
 *   That is a different protocol, not a parameter. Threshold RSA in the
 *   style of Shoup needs it, to make an abort attributable - the signature
 *   itself combines without it, and only the question "who sent a bad
 *   share" goes unanswered.
 *
 *   ring_pedersen.prove_params is the nearest thing here: a discrete-log
 *   proof in an unknown-order group by cut-and-choose. Shoup needs EQUALITY
 *   of two logs under two bases, which is a different statement.
 */
export function prove_with_generator(G, k, C, rng, domain) {
    rng = require_rng('prove_with_generator', rng);
    return prove(G, k, G.GENERATOR, C, rng, domain);
}

/** @return {boolean} */
export function verify_with_generator(G, PK, C, D, proof, domain) {
    return verify(G, G.GENERATOR, PK, C, D, proof, domain);
}
