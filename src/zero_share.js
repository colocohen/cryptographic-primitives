/**
 * zero_share.js - pseudorandom zero-sharing over the integers (PRZS).
 *
 * n parties, every pair (i, j) holding a common secret seed, each derive an
 * integer share with NO communication such that the shares sum to exactly
 * zero (Cramer-Damgard-Ishai 2005; "F_Zero" in Chen et al. 2020/374):
 *
 *     x_{i,j} = PRF(seed_{i,j}, sid, min, max)  in [-B, B]
 *     share_i = sum_{j>i} x_{i,j}  -  sum_{j<i} x_{j,i}
 *
 * Every off-diagonal value appears once with each sign, so the sum is zero by
 * construction. Used as additive masks that cancel: each share alone is
 * statistically close to uniform in a range B wide, as long as one other
 * party's seed with i is unknown to the adversary.
 *
 * ⛔ B IS A SECURITY PARAMETER. To hide a value below 2^k statistically, B
 *   must be about 2^(k+s) for a statistical parameter s; a smaller B still
 *   sums to zero and simply stops hiding. Nothing fails.
 *
 * ⚠ ESTABLISHING THE SEEDS IS NOT HERE. They come from a setup the caller
 *   runs - a key exchange, a private message, a coin toss. The seed must be
 *   known to exactly the two parties of its pair.
 *
 * `tag` domain-separates one protocol's masks from another's; pass your own.
 */
import { shake256 } from './sha3.js';
import { concat, lp16, utf8 } from './commons/bytes.js';
import { random_below_biased } from './commons/primes.js';

var DEFAULT_TAG = 'cryptographic-primitives/zero-share/v1';

/**
 * The value for the unordered pair {lo, hi} (lo < hi), uniform over [-B, B]
 * up to 2^-128 statistical distance. Both members of the pair compute it;
 * `hi` negates it.
 */
export function zero_share_pair(seed, sid, lo, hi, B, tag) {
    if (!(seed instanceof Uint8Array) || seed.length < 16) {
        throw new TypeError('zero_share: a seed of at least 16 bytes is required');
    }
    if (typeof B !== 'bigint' || B <= 0n) { throw new TypeError('zero_share: B must be a positive bigint'); }
    if (!(lo < hi) || lo < 0 || hi > 0xffff) { throw new RangeError('zero_share: need 0 <= lo < hi <= 65535'); }
    var span = 2n * B + 1n;
    var input = concat([
        lp16(utf8(tag == null ? DEFAULT_TAG : String(tag))),
        lp16(seed),
        lp16(sid instanceof Uint8Array ? sid : utf8(sid == null ? '' : String(sid))),
        new Uint8Array([(lo >>> 8) & 0xff, lo & 0xff, (hi >>> 8) & 0xff, hi & 0xff])
    ]);
    /* uniform below span: primes.random_below_biased, with the PRF as its
       byte source (it asks for span's width + 16 bytes, which is what this
       computed by hand) - the same value as before */
    return random_below_biased(span, function (n) { return shake256(input, n); }) - B;
}

/**
 * Party `self`'s share (0-based), from `seeds[j]` = the seed it shares with
 * party j (`seeds[self]` is ignored). The n shares sum to zero.
 */
export function zero_share(self, n, seeds, sid, B, tag) {
    if (!Array.isArray(seeds) || seeds.length !== n) {
        throw new TypeError('zero_share: need one seed per party, including a placeholder for self (got ' +
                            (seeds && seeds.length) + ' for ' + n + ' parties)');
    }
    if (!Number.isInteger(self) || self < 0 || self >= n) { throw new RangeError('zero_share: self out of range'); }
    var total = 0n;
    for (var j = 0; j < n; j++) {
        if (j === self) { continue; }
        var x = zero_share_pair(seeds[j], sid, self < j ? self : j, self < j ? j : self, B, tag);
        total += self < j ? x : -x;
    }
    return total;
}
