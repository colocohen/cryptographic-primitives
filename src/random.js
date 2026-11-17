/**
 * Random bytes from the platform, in place of crypto.randomBytes.
 *
 *     random_bytes(n)    n bytes from crypto.getRandomValues
 *
 * The same source as every randomness parameter of the library left out
 * (commons/bytes.js, secure_random): never Math.random - where
 * getRandomValues is missing, this throws.
 *
 * Any n: getRandomValues fills at most 65,536 bytes a call, so a larger
 * request is filled in pieces. n = 0 gives an empty array, as
 * crypto.randomBytes(0) does.
 */

import { secure_random } from './commons/bytes.js';

export function random_bytes(n) {
    if (typeof n !== 'number' || n < 0 || n % 1 !== 0 || n > 0x7fffffff) {
        throw new TypeError('random.random_bytes: n must be a whole number of bytes, 0 or more');
    }
    return n === 0 ? new Uint8Array(0) : secure_random(n);
}
