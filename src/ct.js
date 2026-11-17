/**
 * Comparing secrets in constant time - a MAC tag, a token, a ticket's key
 * name - in place of crypto.timingSafeEqual.
 *
 *     equal(a, b)    true when a and b hold the same bytes
 *
 * A comparison that stops at the first differing byte tells whoever can
 * time it how many leading bytes were right, and a tag can then be forged
 * a byte at a time. This one reads every byte whatever it finds
 * (commons/ct.js, which every comparison in the library goes through).
 *
 * ⭐ A LENGTH MISMATCH IS false, NOT AN ERROR. Node's timingSafeEqual
 *   throws there; a token or a tag arrives at whatever length the other
 *   side chose, and an exception would make every check a try/catch and a
 *   path to crash. The time it takes shows only whether the lengths
 *   differ, and lengths are public.
 *
 * ⚠ TWO EMPTY ARRAYS ARE EQUAL, as they are in timingSafeEqual. A caller
 *   comparing a tag it sliced to a computed length checks that length is
 *   not zero.
 *
 * ⚠ CONSTANT TIME IN JAVASCRIPT IS BEST EFFORT: the source never branches
 *   on the bytes, and the engine's compiler could in principle bring a
 *   difference back.
 */

import { equal as ct_equal } from './commons/ct.js';

export function equal(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
        throw new TypeError('ct.equal: both arguments must be Uint8Arrays');
    }
    return ct_equal(a, b) === 1;
}
