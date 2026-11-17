/**
 * Shared helpers for the compatibility shims.
 *
 * The shims wrap libraries whose APIs generate their own randomness -
 * nacl.box.keyPair() and bcrypt.genSaltSync() take no rng - so unlike the
 * rest of this library, which takes one as a parameter, they have to reach
 * for the platform's.
 *
 * That is a property of the APIs being mirrored rather than a choice made
 * here, and it is the one place a shim cannot be a faithful copy AND follow
 * this library's convention.
 */

/* the shared implementation lives in commons/bytes.js - re-exported here so
   the shims read naturally */
export { secure_random as platform_random } from '../commons/bytes.js';

/**
 * A string as UTF-8 bytes; anything else is returned as it is.
 *
 * The libraries mirrored here all take "a string or bytes" for passwords and
 * messages, and every shim wrote this one line as its own `to_bytes`
 * (cryptojs, eccrypto, scrypt-js, and twice inline in sodium). UTF-8 rather
 * than commons/bytes.js's ascii(): these are user strings, not protocol
 * constants, and the mirrored libraries encode them as UTF-8.
 *
 * Shims that also accept a plain array convert after calling this - see
 * scrypt-js.js and eccrypto.js.
 */
export { text_or_bytes } from '../commons/bytes.js';
