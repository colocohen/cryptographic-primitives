/**
 * X448  -  RFC 7748
 *
 * Diffie-Hellman on Curve448, at roughly the 224-bit security level. Present
 * in TLS 1.3 and in profiles that require a higher level on paper; X25519 is
 * the default nearly everywhere else and is already beyond any foreseeable
 * classical attack.
 *
 * Keys and shared secrets are 56 bytes - note that Ed448 uses 57, because it
 * needs a bit for the sign of x and X448 has no y coordinate at all.
 *
 * The same caveat as X25519: the output is a curve coordinate, not a key.
 * Run it through a KDF.
 */

import { field } from './commons/modp.js';
import { secure_random } from './commons/bytes.js';
import { key_from_seed } from './commons/group.js';
import { montgomery , reject_zero, agreement_context } from './commons/montgomery.js';

var P = (1n << 448n) - (1n << 224n) - 1n;
var F = field(P);
var M = montgomery(F, 39081n, 448);

export var BYTES = 56;

/**
 * Clamping. The low TWO bits are cleared here - Curve448's cofactor is 4,
 * not 8 - and bit 447 is set. There is no spare high bit to clear: 448 bits
 * fill 56 bytes exactly.
 */
function clamp(k) {
    var s = new Uint8Array(k);
    s[0] &= 252;
    s[55] |= 128;
    return F.from_bytes_le(s);
}

export function x448(secret, u) {
    if (secret.length !== 56) { throw new Error('x448: secret must be 56 bytes'); }
    if (u.length !== 56) { throw new Error('x448: u must be 56 bytes'); }
    /* no masking here: 448 bits use every bit of the 56 bytes */
    return F.to_bytes_le(M.ladder(clamp(secret), F.from_bytes_le(u))).subarray(0, 56);
}

/** The public key: the scalar applied to the base point u = 5. */
export function get_public_key(secret) {
    var base = new Uint8Array(56);
    base[0] = 5;
    return x448(secret, base);
}

/**
 * A key pair: { sk, pk } as x448 and get_public_key take them. Any 56
 * bytes are a secret key (clamping makes them a scalar), so sk IS the seed -
 * a copy of it.
 *
 * @param {Uint8Array} [seed]  56 bytes; omitted or null draws a fresh one
 *                             from the platform
 */
export function keygen(seed) {
    var sk = key_from_seed('x448.keygen', seed, function () { return secure_random(56); });
    return { sk: sk, pk: get_public_key(sk) };
}

/** @return {Uint8Array|null} null on an all-zero result */
export function x448_checked(secret, peer) {
    return reject_zero(x448(secret, peer));
}

/**
 * One secret for many key agreements, held in a context:
 *
 *     var me = x448_create();             // a fresh secret; or x448_create(secret)
 *     send(me.pk);
 *     var shared = me.x448_checked(peer); // null for a small-order peer
 *     me.wipe();                            // zeroes the secret; calls then throw
 *
 * What it saves is the engine's: node:crypto imports a raw secret on every
 * call, at about the cost of the agreement itself, and a context imports it
 * once (engines/node.js). The pure context holds a copy of the secret
 * (commons/montgomery.js).
 *
 * @param {Uint8Array} [secret]  56 bytes; omitted or null draws a fresh one
 */
export function x448_create(secret) {
    return agreement_context('x448', 56, x448, x448_checked, get_public_key, secret);
}
