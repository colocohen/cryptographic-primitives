/**
 * Reading an arbitrary-length stream from a fixed-output XOF
 *
 * SHAKE takes a length and returns exactly that many bytes. Rejection
 * sampling does not know in advance how many it will need - that is the point
 * of rejection - so every caller ends up writing the same loop: ask for a
 * generous amount, and if it runs out, ask for more.
 *
 * WHAT MAKES THAT CORRECT is not obvious and is worth stating once rather
 * than three times: SHAKE's output is PREFIX-STABLE. Asking for 2n bytes
 * returns the same first n bytes as asking for n. So a refill can simply
 * re-request a larger amount and carry on from the same position; nothing is
 * lost and nothing is recomputed incorrectly. A hash with a length-dependent
 * finalisation - SHA-512/256 against SHA-512, say - would NOT behave this
 * way, and this pattern would silently produce different values on either
 * side of a refill.
 *
 * Four call sites wrote this loop before it moved here: ML-KEM's matrix
 * sampling, both of ML-DSA's, and Falcon's hash-to-point.
 */

/**
 * @param {function}   xof      (input, len) -> Uint8Array, prefix-stable
 * @param {Uint8Array} input    the absorbed value
 * @param {number}     initial  first request, chosen so refills are rare
 */
export function xof_stream(xof, input, initial) {
    var need = initial;
    var buf = xof(input, need);
    var pos = 0;

    return {
        /**
         * The next n bytes, as a view into the buffer.
         *
         * The view is INVALIDATED by the next read that triggers a refill, so
         * callers must consume it immediately - which every rejection loop
         * does anyway, since it inspects the bytes and moves on.
         */
        read: function (n) {
            /* ⛔ WHILE, not if: one doubling is not enough for a read larger
               than what is left, and the subarray below then came back SHORT
               without an error (8 bytes, read 4, read 40 -> 12 bytes) */
            if (pos + n > buf.length) {
                while (pos + n > need) { need *= 2; }
                buf = xof(input, need);
            }
            var r = buf.subarray(pos, pos + n);
            pos += n;
            return r;
        }
    };
}
