/**
 * X25519  -  RFC 7748
 *
 * Diffie-Hellman on Curve25519. The most widely deployed key agreement in
 * existence: TLS 1.3 prefers it, so does SSH, and it is what WireGuard,
 * Signal and Noise are built on.
 *
 * Keys and shared secrets are 32 bytes. Both directions are one function.
 *
 * THE SHARED SECRET IS NOT A KEY. It is the x coordinate of a curve point,
 * which is not uniformly distributed over 32-byte strings. Run it through a
 * KDF - hkdf in kdf.js - before using it for anything. Every protocol that
 * uses X25519 does this, and it is the one step callers skip.
 *
 * ON REJECTING ALL-ZERO OUTPUT: a peer can send a low-order point, which
 * forces the shared secret to zero regardless of the private key. RFC 7748
 * makes the check optional because the resulting secret is useless rather
 * than dangerous in most protocols - but in any protocol where agreement
 * itself proves something, accepting it means accepting a "shared" secret the
 * attacker also knows. This implementation returns it and flags it; see
 * x25519_checked below.
 */

import { field } from './commons/modp.js';
import { secure_random } from './commons/bytes.js';
import { key_from_seed } from './commons/group.js';
import { montgomery , reject_zero, agreement_context } from './commons/montgomery.js';

var P = (1n << 255n) - 19n;
var F = field(P);
var M = montgomery(F, 121665n, 255);

export var BYTES = 32;

/**
 * Clamping, RFC 7748 section 5.
 *
 * The low three bits are cleared so the scalar is a multiple of the cofactor
 * 8, which makes any small-subgroup component of the peer's point vanish.
 * Bit 254 is set and bit 255 cleared so every scalar has the same length.
 * Together these are why X25519 needs no public-key validation at all.
 */
function clamp(k) {
    var s = new Uint8Array(k);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    return F.from_bytes_le(s);
}

/**
 * @param  {Uint8Array} secret  32 bytes - any 32 bytes
 * @param  {Uint8Array} u       32 bytes, the peer's public key or the base
 * @return {Uint8Array} 32 bytes
 */
export function x25519(secret, u) {
    if (secret.length !== 32) { throw new Error('x25519: secret must be 32 bytes'); }
    if (u.length !== 32) { throw new Error('x25519: u must be 32 bytes'); }

    /*
     * The top bit of u is MASKED OFF, not rejected. RFC 7748 requires this:
     * u is a field element in 255 bits and the spare bit is ignored, so two
     * encodings of the same point must behave identically.
     */
    var ub = new Uint8Array(u);
    ub[31] &= 0x7f;

    return F.to_bytes_le(M.ladder(clamp(secret), F.from_bytes_le(ub)));
}

/** The public key: the scalar applied to the base point u = 9. */
/*
 * x448.js has the same three lines with 56 and 5 in place of 32 and 9. They
 * are not shared: a common version would take the length and the base byte as
 * parameters, which is longer than either, and it would put the two curves'
 * base points behind one call where a wrong argument silently produces a key
 * on the other curve's convention.
 */
export function get_public_key(secret) {
    var base = new Uint8Array(32);
    base[0] = 9;
    return x25519(secret, base);
}

/**
 * A key pair: { sk, pk } as x25519 and get_public_key take them. Any 32
 * bytes are a secret key (clamping makes them a scalar), so sk IS the seed -
 * a copy of it.
 *
 * @param {Uint8Array} [seed]  32 bytes; omitted or null draws a fresh one
 *                             from the platform
 */
export function keygen(seed) {
    var sk = key_from_seed('x25519.keygen', seed, function () { return secure_random(32); });
    return { sk: sk, pk: get_public_key(sk) };
}

/**
 * Key agreement that refuses an all-zero result.
 *
 * @return {Uint8Array|null} null when the peer supplied a low-order point
 */
export function x25519_checked(secret, peer) {
    return reject_zero(x25519(secret, peer));
}

/**
 * One secret for many key agreements, held in a context:
 *
 *     var me = x25519_create();             // a fresh secret; or x25519_create(secret)
 *     send(me.pk);
 *     var shared = me.x25519_checked(peer); // null for a small-order peer
 *     me.wipe();                            // zeroes the secret; calls then throw
 *
 * What it saves is the engine's: node:crypto imports a raw secret on every
 * call, at about the cost of the agreement itself, and a context imports it
 * once (engines/node.js). The pure context holds a copy of the secret
 * (commons/montgomery.js).
 *
 * @param {Uint8Array} [secret]  32 bytes; omitted or null draws a fresh one
 */
export function x25519_create(secret) {
    return agreement_context('x25519', 32, x25519, x25519_checked, get_public_key, secret);
}
