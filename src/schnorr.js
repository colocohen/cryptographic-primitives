/**
 * Schnorr signatures over any prime-order group
 *
 * The textbook scheme, for protocols that need "this party, holding the
 * secret behind V, signed this" over whatever group they already work in -
 * a threshold share's verification key, say - rather than over a fixed curve
 * with a fixed encoding (ed25519.js, BIP-340 in secp256k1.js).
 *
 *     sign:    k <- nonce, R = k*G, e = H(domain, R, V, msg), z = k + e*x
 *     verify:  z*G == R + e*V
 *
 * The signature is lp16(R) || z, z at the fixed scalar width. The challenge is
 * SHA-512 over length-prefixed domain, R, V and msg, reduced mod the order.
 * For orders up to 256 bits the reduction bias is negligible (2^-256); for
 * larger orders (P-384, P-521) the challenge space is still at least 2^384,
 * far beyond what Schnorr's security needs.
 *
 * WHY V IS IN THE CHALLENGE. Binding the public key stops a signature under
 * one key being re-presented as valid for a related key - the standard
 * "key-prefixed" Schnorr, as in EdDSA and BIP-340.
 *
 * THE NONCE IS HEDGED: H(secret, msg, V, fresh randomness). A broken or
 * repeated RNG then cannot repeat a nonce across different messages - which
 * would hand over the secret from two signatures - and a fault on the
 * randomness alone is not enough either. Deterministic-plus-random, the
 * recommendation of RFC 8032 / BIP-340 / draft-irtf-cfrg-det-sigs-with-noise.
 *
 * `domain` separates uses: two protocols signing with the same key never
 * produce interchangeable signatures.
 */

import { concat, lp16, utf8, secure_random } from './commons/bytes.js';
import { batch_all, batch_find, batch_items, group_batch_holds } from './commons/batch.js';
import { require_rng, mod } from './commons/primes.js';

function bytes_of(domain) {
    if (domain instanceof Uint8Array) { return domain; }
    if (typeof domain === 'string') { return utf8(domain); }
    throw new TypeError('schnorr: domain must be a string or bytes');
}

/*
 * ⭐ SCALARS ARE THE GROUP'S OWN, in and out: G.scalar_bytes to write z and
 *   the secret, G.scalar_from_bytes to read z back, G.scalar_from_uniform_bytes
 *   to reduce a digest. This file used to read and write big-endian on EVERY
 *   curve, while dleq.js did little-endian on every curve and elgamal.js
 *   big-endian at a different width - three conventions for one job. On the
 *   SEC 1 curves nothing changes; on ristretto255, ed25519 and ed448 z is now
 *   little-endian (and 57 bytes on ed448), as everywhere else those curves
 *   carry a scalar. No standard fixes this format; it is the library's own.
 */
function challenge(G, domain, R, V, msg) {
    return G.hash_to_scalar(concat([lp16(domain), lp16(G.encode(R)), lp16(G.encode(V)), lp16(msg)]));
}

/**
 * @param {object}     G       prime-order group (ORDER, base_mul, mul, add, encode, decode, equals)
 * @param {bigint}     x       the secret, V = x*G
 * @param {Uint8Array} msg
 * @param {function}   rng     (n) -> Uint8Array
 * @param {string|Uint8Array} domain
 * @param {object}     [V]     the public key, if the caller has it (saves a multiplication)
 * @return {Uint8Array} lp16(R) || z
 */
export function sign(G, x, msg, rng, domain, V) {
    rng = require_rng('schnorr.sign', rng);
    var q = G.ORDER, d = bytes_of(domain);
    var s = mod(x, q);
    if (s === 0n) { throw new Error('schnorr: zero secret'); }
    var P = V || G.base_mul(s);
    /* ⛔ G.hash_to_scalar: the order's width + 128 bits. sha512 reduced mod
       a 521-bit order left the top 9 bits of every P-521 nonce zero */
    var k = G.hash_to_scalar(concat([lp16(d), lp16(utf8('nonce')), lp16(G.scalar_bytes(s)),
        lp16(G.encode(P)), lp16(msg), lp16(rng(32))]));
    if (k === 0n) { k = 1n; }
    var R = G.base_mul(k);
    var z = (k + challenge(G, d, R, P, msg) * s) % q;
    return concat([lp16(G.encode(R)), G.scalar_bytes(z)]);
}

/**
 * @return {boolean}
 */
export function verify(G, V, msg, sig, domain) {
    var v = verify_input(G, V, msg, sig, domain);
    /* every scalar here is public - z and R from the signature, e from a hash
       of published values - so the variable-time multiply is the right one */
    return v !== null && G.equals(G.base_mul(v.s), G.add(v.R, G.mul_vartime(v.c, V)));
}

/*
 * Everything verify checks before the equation: { R, P, s, c, key }, or
 * null. ⭐ ONE FUNCTION for verify and both batch checks.
 */
function verify_input(G, V, msg, sig, domain) {
    if (!(sig instanceof Uint8Array) || sig.length < 3 || V == null) { return null; }
    var l = (sig[0] << 8) | sig[1];
    if (2 + l >= sig.length) { return null; }
    var R = G.decode(sig.subarray(2, 2 + l));
    if (!R) { return null; }
    /* exactly the scalar width, below the order - see GROUP.scalar_from_bytes */
    var z = G.scalar_from_bytes(sig.subarray(2 + l));
    if (z === null) { return null; }
    if (G.equals(V, G.IDENTITY)) { return null; }
    return { R: R, P: V, s: z, c: challenge(G, bytes_of(domain), R, V, msg), key: null };
}

/*
 * ⭐ BATCH VERIFICATION (commons/batch.js): verify_batch is true when every
 *    { pk, msg, sig, domain } verifies under G (pk: the public key, a group
 *    element, as verify takes it); verify_batch_find gives the indices of
 *    those verify rejects. The same answers as verify: the same checks, and
 *    a prime-order group's equation summed with random weights.
 */
var BATCH_MIN = 8;
export function verify_batch(G, items, opts) {
    var c = batch_checks(G, items, opts, 'schnorr.verify_batch');
    return batch_all(items, c.holds, c.one, BATCH_MIN);
}
export function verify_batch_find(G, items, opts) {
    var c = batch_checks(G, items, opts, 'schnorr.verify_batch_find');
    return batch_find(items, c.holds, c.one, BATCH_MIN);
}
function batch_checks(G, items, opts, who) {
    batch_items(items, who);
    var rng = (opts && opts.rng) || secure_random;
    return {
        holds: function (sub) {
            var entries = [];
            for (var i = 0; i < sub.length; i++) {
                var v = verify_input(G, sub[i].pk, sub[i].msg, sub[i].sig, sub[i].domain);
                if (v === null) { return false; }
                entries.push(v);
            }
            return group_batch_holds(G, entries, rng, who);
        },
        one: function (it) { return verify(G, it.pk, it.msg, it.sig, it.domain); }
    };
}
