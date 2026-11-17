/**
 * hmac_fast.js - HMAC with the two pad blocks compressed once.
 *
 * ==================== WHAT IT IS FOR ====================
 *
 * PBKDF2 computes HMAC(key, U) with the SAME key, once per iteration - a
 * hundred thousand times for a typical parameter. Each of those calls
 * ordinarily compresses two 64-byte pad blocks that depend only on the key
 * and never change.
 *
 * ⭐ COMPRESSING THEM ONCE HALVES THE BLOCK COUNT for the short messages that
 *   loop always has. Measured on pbkdf2-sha256 at 100k iterations:
 *
 *       plain hmac        731 ms
 *       hmac_init         490      (key schedule cached)
 *       this              164      - noble 170, node's C 46
 *
 * ==================== ⭐ IT OWNS NO PADDING ====================
 *
 * A first version drove the compression function directly and carried its
 * own padding and length-field code - twelve lines copied from md_hash,
 * which jscpd found immediately.
 *
 * ⛔ THAT DUPLICATION WAS THE DANGEROUS KIND. Two copies of a length field is
 *   how one gets a correction and the other does not, and a wrong length
 *   field produces a digest that is stable, well distributed, and not HMAC.
 *
 * ⭐ md_hash NOW TAKES A STARTING STATE, so this file computes the two pad
 *   states and hands them to the same padding code every other hash here
 *   uses.
 *
 * ==================== ⚠ AND WHAT IT HOLDS ====================
 *
 * The returned function closes over two chaining states derived from the
 * key. hmac() in hmac.js allocates and clears per call and remains the right
 * choice everywhere except a loop that reuses one key.
 *
 * ==================== ⭐ AND IT OWNS THE PADDED KEY ====================
 *
 * hmac_padded_key and the two pad bytes used to live in hmac.js, with this
 * file importing them back - while hmac.js imported hmac_fast from here. That
 * cycle worked only because function declarations are hoisted, and IPAD and
 * OPAD were defined twice to stay out of its way.
 *
 * ⭐ THEY LIVE HERE NOW and hmac.js re-exports hmac_padded_key under the same
 *   name, so the dependency runs one way: hmac.js -> this file ->
 *   merkle_damgard.js.
 */

import { md_prefixed } from './merkle_damgard.js';

/** The two HMAC pad bytes, RFC 2104. Shared with hmac.js. */
export var IPAD = 0x36;
export var OPAD = 0x5c;

/**
 * HMAC's padded key: hashed down if it is longer than a block, then
 * zero-extended.
 *
 * ⭐ SHARED because jscpd found it duplicated between `hmac` and
 *   `hmac_fast`. Two copies of a key-derivation step is the worst kind to
 *   duplicate: a divergence gives two functions that each produce a
 *   consistent MAC and disagree with each other, and every test that checks
 *   one against the other still passes.
 *
 *   ⚠ AND IT CAME BACK ONCE: hmac_init carried a third, inline copy of these
 *     lines after the first two had been merged. That copy is gone too; every
 *     HMAC in the library now pads its key here.
 *
 * ⚠ A KEY LONGER THAN THE BLOCK IS HASHED DOWN, so a long key and its digest
 *   produce the same MAC - key lengths above the block size buy nothing.
 *   That is HMAC's definition, not a shortcut here.
 *
 * ⚠ THE RETURNED BUFFER HOLDS KEY MATERIAL. Callers wipe it once the pads
 *   are built.
 */
export function hmac_padded_key(hash, key, block_size) {
    var k = new Uint8Array(block_size);
    var i;
    if (key.length > block_size) {
        var kh = hash(key);
        for (i = 0; i < kh.length; i++) { k[i] = kh[i]; }
        for (i = 0; i < kh.length; i++) { kh[i] = 0; }
    } else {
        for (i = 0; i < key.length; i++) { k[i] = key[i]; }
    }
    return k;
}

/**
 * @param {function} hash  must expose PARAMS - sha256 and sha512 do
 * @param {Uint8Array} key
 * @return {function(Uint8Array): Uint8Array}
 */
export function hmac_fast(hash, key) {
    var P = hash.PARAMS;
    if (!P) {
        throw new Error('hmac_fast: this hash does not expose its parameters');
    }
    var bs = P.block_size;
    var i;

    /* ⭐ the padded key, shared with hmac.js - see the note above */
    var k = hmac_padded_key(hash, key, bs);

    /*
     * ⭐ ONE COMPRESSION PER PAD BLOCK. What is kept is the chaining state
     *   after that single block - not a digest, and not anything a caller
     *   should ever see.
     */
    var pad = new Uint8Array(bs);

    for (i = 0; i < bs; i++) { pad[i] = k[i] ^ IPAD; }
    var inner = md_prefixed(hash, pad);

    for (i = 0; i < bs; i++) { pad[i] = k[i] ^ OPAD; }
    var outer = md_prefixed(hash, pad);

    for (i = 0; i < bs; i++) { k[i] = 0; pad[i] = 0; }

    /* the pad states are compressed once, by md_prefixed, which also carries
       the block already absorbed into the length field */
    return function (msg) {
        return outer(inner(msg));
    };
}
