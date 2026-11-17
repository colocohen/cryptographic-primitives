/**
 * NaCl's crypto_box shared key: X25519, THEN HSalsa20 over the result with a
 * zero nonce.
 *
 * compat/nacl.js (box.before) and compat/sodium.js (crypto_box_beforenm)
 * each wrote this. The second step is not optional and not decoration - it
 * is what NaCl specifies, and skipping it produces a key that works
 * consistently with itself and with nobody else.
 *
 * Kept out of _common.js so that a shim with no box (bcrypt.js) does not load
 * X25519 and Salsa20 to get at platform_random.
 */
import { hsalsa20 } from '../salsa.js';
import { x25519 } from '../x25519.js';

export function box_shared_key(their_pk, my_sk) {
    return hsalsa20(x25519(my_sk, their_pk), new Uint8Array(16));
}
