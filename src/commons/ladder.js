/**
 * The Montgomery ladder, over any group
 *
 * Extracted when Edwards curves were added and reimplemented the loop that
 * Weierstrass already had, line for line. The ladder does not care what the
 * group is - it needs an identity, an addition, a doubling and a
 * constant-time swap, and both curve families supply all four.
 *
 * NOT SHARED WITH commons/montgomery.js. That file runs a different ladder on
 * x coordinates alone, where there is no group to speak of: P and -P are the
 * same element and "addition" is a differential formula that needs the
 * difference of the two operands as a third input. It looks similar on the
 * page and is a genuinely different algorithm.
 *
 * WHY A LADDER RATHER THAN DOUBLE-AND-ADD
 * The obvious loop doubles every iteration and adds only when the bit is set,
 * so its running time reads out the Hamming weight of the scalar. Measured on
 * this library's own field arithmetic, two exponents of the same length with
 * 2 and 256 bits set differed by 1.75x - enough to recover a private key one
 * bit at a time. The ladder performs one addition and one doubling every
 * iteration regardless, and the two accumulators are SWAPPED rather than
 * selected between, so nothing branches on a secret bit.
 *
 * It costs roughly twice the naive version. That is the price of the
 * property, and there is no cheaper way to buy it.
 */

/**
 * @param {object} G     the group: needs ZERO, add, dbl, cswap
 * @param {bigint} k     the scalar
 * @param {object} P     the point
 * @param {number} bits  a FIXED iteration count - using the scalar's own bit
 *                       length would leak its magnitude
 *
 * MISSING `bits` THROWS, and used not to.
 *
 * `undefined - 1` is NaN, `NaN >= 0` is false, so the loop never ran and the
 * ladder returned the identity for every input. That is the worst possible
 * failure for this function: a subgroup check written as
 * `mul(ORDER, P) == IDENTITY` reports that every point is in the subgroup,
 * including the ones that are not - a security check that fails open and
 * reads as passing.
 *
 * It cost four attempts to find while writing exactly that check. Throwing
 * makes the mistake impossible to make quietly.
 */
export function ladder(G, k, P, bits) {
    if (typeof bits !== 'number' || !(bits > 0)) {
        throw new Error('ladder: bits must be a positive number - ' +
                        'omitting it silently returns the identity');
    }
    var R0 = G.ZERO, R1 = P;
    for (var i = bits - 1; i >= 0; i--) {
        var bit = (k >> BigInt(i)) & 1n;
        var sw = G.cswap(bit, R0, R1);
        R0 = sw[0]; R1 = sw[1];
        R1 = G.add(R0, R1);
        R0 = G.dbl(R0);
        sw = G.cswap(bit, R0, R1);
        R0 = sw[0]; R1 = sw[1];
    }
    return R0;
}
