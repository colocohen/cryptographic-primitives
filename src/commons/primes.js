import { bytes_to_bigint, secure_random } from './bytes.js';
import { finish_task } from './task.js';
/**
 * Primality testing and prime generation
 *
 * Needed only by RSA, and by nothing else in this library - every elliptic
 * curve here has its prime baked into a published standard. RSA is the one
 * scheme where the user generates primes at runtime, which is most of why its
 * key generation is slow and most of why it goes wrong.
 *
 * THE TEST IS BAILLIE-PSW: one Miller-Rabin round to base 2, then a strong
 * Lucas test. That combination has no known counterexample despite a standing
 * cash prize, and it is what FIPS 186-4 requires for RSA primes for exactly
 * that reason.
 *
 * Why not Miller-Rabin alone with many rounds? Because Miller-Rabin has
 * composites that survive ANY fixed set of bases - a caller who hardcodes
 * bases rather than choosing them randomly can be fed a number that passes.
 * The Lucas test fails on a structurally different set of composites, so a
 * number would have to fool two unrelated tests at once. No such number is
 * known.
 *
 * RANDOMNESS IS THE CALLER'S. Every function here takes an rng argument
 * returning random bytes. This library does not generate randomness - see the
 * note in rsa.js - and a prime generated from a predictable source is not a
 * secret no matter how carefully it was tested.
 */

/** Small primes, for cheap trial division before the expensive tests. */
var SMALL = /* @__PURE__ */ primes_up_to(999);

/**
 * Every prime p <= limit, as bigints, ascending (sieve of Eratosthenes).
 * `limit` is a Number; this allocates limit+1 bytes.
 */
export function primes_up_to(limit) {
    if (!Number.isInteger(limit) || limit < 0) { throw new TypeError('primes: limit must be a non-negative integer'); }
    var out = [], sieve = new Uint8Array(limit + 1);
    for (var i = 2; i <= limit; i++) {
        if (sieve[i]) { continue; }
        out.push(BigInt(i));
        for (var j = i * i; j <= limit; j += i) { sieve[j] = 1; }
    }
    return out;
}

/**
 * Chinese remaindering: the unique y in [0, prod m) with y = x[j] mod m[j].
 *
 * ⚠ THE MODULI MUST BE PAIRWISE COPRIME, and that is checked, not assumed:
 *   with a shared factor the inverse below does not exist and the result
 *   would be meaningless, so this throws naming the modulus.
 *
 * Runs on public or secret residues alike, but NOT in constant time - the
 *   inversions are on the moduli (public), the residues only multiply and
 *   reduce. A caller with secret moduli needs something else.
 */
export function crt(x, m) {
    var l = m.length;
    if (x.length !== l) { throw new TypeError('crt: ' + x.length + ' residues for ' + l + ' moduli'); }
    var M = 1n, j;
    for (j = 0; j < l; j++) { M *= m[j]; }
    var y = 0n;
    for (j = 0; j < l; j++) {
        var a = M / m[j];
        var b = mod_inverse(a % m[j], m[j]);
        if (b === null) { throw new Error('crt: modulus ' + m[j] + ' is not coprime to the others'); }
        y = mod(y + a * b * mod(x[j], m[j]), M);
    }
    return y;
}

/**
 * Modular exponentiation with a SECRET exponent, through a Montgomery ladder.
 *
 * ==================== ⛔ WHY THIS EXISTS ====================
 *
 * `powmod` below is square-and-multiply: it multiplies only when a bit is
 * set, so its running time is proportional to the exponent's Hamming weight.
 * That is fine for a public exponent and it is a KEY-RECOVERY CHANNEL for a
 * private one.
 *
 *   MEASURED on a 1024-bit modulus with two 1024-bit exponents, one with two
 *   bits set and one with all 1024:
 *
 *       powmod      1.70 ms  and  3.37 ms      ⛔ a factor of 2
 *       this        3.50 ms  and  3.50 ms      ⭐ ratio 1.000
 *
 *   And the cost of the flat version is 6% over the slower branch.
 *
 * ⭐ THE LADDER KEEPS TWO ACCUMULATORS and performs a multiply and a square
 *   every iteration whatever the bit is; the bit only decides which of the
 *   two each result lands in, through a mask rather than a branch.
 *
 * ⚠ `bits` DEFAULTS TO THE MODULUS's WIDTH, which is the right answer for
 *   every private exponent - d, dp, dq, lambda and a DH secret are all
 *   bounded by their modulus, and the modulus is public.
 *
 * ⛔ PASSING THE EXPONENT'S OWN BIT LENGTH DEFEATS THE POINT. The loop would
 *   then run for as many iterations as the secret has bits, which is the
 *   leak this function exists to close. The parameter is here for callers
 *   who know a tighter PUBLIC bound, not for shortening the loop.
 *
 * ⛔ IT DOES NOT FLATTEN EVERYTHING. A tiny exponent still runs faster,
 *   because the accumulator stays near 1n and BigInt operations cost less on
 *   small values - see the note on cselect in commons/modp.js. That does not
 *   matter here: an attacker does not choose the victim's d, and across many
 *   operations with the SAME full-width secret the timing is flat.
 */
export function powmod_ct(b, e, m, bits) {
    var w = bits === undefined ? m.toString(2).length : bits;
    /*
     * ⛔ THE LADDER WALKS EXACTLY w BITS, SO AN EXPONENT WIDER THAN w IS
     *   SILENTLY TRUNCATED and the result is quietly wrong - it still looks
     *   like a modular exponentiation, and a proof built on it simply fails
     *   to verify with nothing pointing at the cause. This cost a debugging
     *   session: the default width is the MODULUS's, which is right for RSA
     *   and DH where the exponent is reduced mod phi, and wrong for the
     *   CGGMP21 blinders, which are drawn from ranges deliberately much
     *   WIDER than the modulus so that the opening statistically hides the
     *   witness.
     *
     * ⭐ THE THROW IS NOT A TIMING LEAK. It fires only when a caller declared
     *   a width smaller than the range it samples from, which is a fixed
     *   property of that call site, not of the secret.
     */
    if ((e >> BigInt(w)) !== 0n && (e >> BigInt(w)) !== -1n) {
        throw new Error('primes: powmod_ct exponent exceeds the declared width of ' +
                        w + ' bits - pass the width of the PUBLIC bound it was ' +
                        'sampled from, not the modulus width');
    }
    /*
     * ⭐ A FIXED 4-BIT WINDOW, not the Montgomery ladder (measured: 4096-bit
     *   exponent mod 8192 bits, 497 ms → 321 ms). The ladder costs two
     *   multiplications per bit; this costs one squaring per bit plus one
     *   multiplication per four bits, and keeps the ladder's two properties:
     *
     *   - THE SAME OPERATIONS FOR EVERY EXPONENT of the declared width - w
     *     squarings and ⌈w/4⌉ multiplications, always; a zero window still
     *     multiplies (by the table's 1n).
     *   - NO BRANCH OR INDEX ON THE SECRET. The table entry is selected by
     *     scanning all sixteen and masking, as the ladder swapped by mask.
     *     An array index on the window would be a secret-dependent memory
     *     access.
     *
     *   The caveat about tiny values below applies unchanged: BigInt itself
     *   is not constant-time in its operands' sizes.
     */
    var bm = ((b % m) + m) % m;
    var tab = [1n % m, bm];
    for (var k = 2; k < 16; k++) { tab.push((tab[k - 1] * bm) % m); }
    var top = Math.ceil(w / 4) * 4;
    var r = 1n % m;
    for (var i = top - 4; i >= 0; i -= 4) {
        r = (r * r) % m; r = (r * r) % m; r = (r * r) % m; r = (r * r) % m;
        var win = (e >> BigInt(i)) & 15n;
        var sel = 0n;
        for (var j = 0; j < 16; j++) {
            var eq = -BigInt(1 - Math.min(1, Number(win ^ BigInt(j))));   /* -1n iff j === win, no branch */
            sel |= tab[j] & eq;
        }
        r = (r * sel) % m;
    }
    return r;
}

/**
 * Modular exponentiation. Variable time - the exponent here is public.
 *
 * ⭐ A 5-BIT SLIDING-FREE FIXED WINDOW (measured: 4096-bit exponent mod 8192
 *   bits, 355 ms → 280 ms): one squaring per bit and one multiplication per
 *   five bits, instead of one per set bit (half of them, on average). The
 *   31-entry table costs 30 multiplications, so short exponents keep the
 *   plain loop.
 */
function powmod(b, e, m) {
    b %= m;
    /* short or negative exponents and negative bases: the plain loop, whose
       results (including their sign for a negative base) callers already see */
    if (e < (1n << 160n) || b < 0n) {
        var r = 1n;
        while (e > 0n) {
            if (e & 1n) { r = (r * b) % m; }
            b = (b * b) % m;
            e >>= 1n;
        }
        return r;
    }
    var tab = [1n, b];
    for (var k = 2; k < 32; k++) { tab.push((tab[k - 1] * b) % m); }
    var bits = e.toString(2).length;
    var acc = 1n;
    for (var i = Math.ceil(bits / 5) * 5 - 5; i >= 0; i -= 5) {
        acc = (acc * acc) % m; acc = (acc * acc) % m; acc = (acc * acc) % m;
        acc = (acc * acc) % m; acc = (acc * acc) % m;
        var w = Number((e >> BigInt(i)) & 31n);
        if (w !== 0) { acc = (acc * tab[w]) % m; }
    }
    return acc % m;
}

/**
 * The Jacobi symbol (a/n), for odd n > 0.
 *
 * Needed to pick the Lucas parameters: the test requires a D whose Jacobi
 * symbol is -1, and finding one is how Selfridge's method selects them.
 */
export function jacobi(a, n) {
    a = ((a % n) + n) % n;
    var result = 1;
    while (a !== 0n) {
        while (a % 2n === 0n) {
            a /= 2n;
            var r = n % 8n;
            if (r === 3n || r === 5n) { result = -result; }
        }
        var t = a; a = n; n = t;
        if (a % 4n === 3n && n % 4n === 3n) { result = -result; }
        a %= n;
    }
    return n === 1n ? result : 0;
}

/** One Miller-Rabin round. Returns false only when n is definitely composite. */
function miller_rabin(n, a) {
    var d = n - 1n, r = 0n;
    while (d % 2n === 0n) { d /= 2n; r++; }

    var x = powmod(a, d, n);
    if (x === 1n || x === n - 1n) { return true; }
    for (var i = 1n; i < r; i++) {
        x = (x * x) % n;
        if (x === n - 1n) { return true; }
    }
    return false;
}

/**
 * The strong Lucas probable prime test with Selfridge's parameter choice.
 *
 * Where Miller-Rabin looks at the multiplicative group modulo n, this looks
 * at a Lucas sequence, which behaves differently on composites. That
 * independence is the whole point of pairing them.
 */
function strong_lucas(n) {
    /* find D = 5, -7, 9, -11, ... with jacobi(D, n) = -1 */
    var D = 5n, sign = 1n;
    for (var tries = 0; tries < 1000; tries++) {
        var d = D * sign;
        var j = jacobi(((d % n) + n) % n, n);
        if (j === -1) { break; }
        if (j === 0 && ((d % n) + n) % n !== 0n) { return false; }
        /* a perfect square never yields -1, so bail out and let the caller
           notice - squares are caught by trial division in practice */
        if (tries === 20) {
            var s = isqrt(n);
            if (s * s === n) { return false; }
        }
        D += 2n; sign = -sign;
    }
    var Dv = D * sign;
    var Q = (1n - Dv) / 4n;

    /* n + 1 = d * 2^s */
    var dd = n + 1n, s = 0n;
    while (dd % 2n === 0n) { dd /= 2n; s++; }

    var U = 1n, V = 1n, Qk = Q % n;
    var bits = dd.toString(2);

    for (var i = 1; i < bits.length; i++) {
        /* double */
        var U2 = (U * V) % n;
        var V2 = (V * V - 2n * Qk) % n;
        Qk = (Qk * Qk) % n;
        U = U2; V = V2;

        if (bits[i] === '1') {
            /* add one */
            var Un = (U + V) % n;
            var Vn = (V + Dv * U) % n;
            /* both are halved modulo n, which needs the odd correction */
            U = half_mod(Un, n);
            V = half_mod(Vn, n);
            Qk = (Qk * Q) % n;
        }
    }

    if (U % n === 0n || V % n === 0n) { return true; }
    for (var r2 = 1n; r2 < s; r2++) {
        V = (V * V - 2n * Qk) % n;
        V = ((V % n) + n) % n;
        if (V === 0n) { return true; }
        Qk = (Qk * Qk) % n;
    }
    return false;
}

/** Divide by two modulo an odd n, adding n first when the value is odd. */
function half_mod(x, n) {
    x = ((x % n) + n) % n;
    if (x % 2n === 1n) { x += n; }
    return (x / 2n) % n;
}

/*
 * ⭐ sqrt_int USED TO LIVE HERE - a second Newton's-method integer square root,
 *   private to the Lucas test, beside the exported isqrt further down. The two
 *   agreed on every input tried (0..5000 and two hundred values up to 2,600
 *   bits), started from different guesses and stopped on different
 *   conditions, which is how two copies of "the same" loop drift. The Lucas
 *   test's perfect-square check now calls isqrt.
 */

/**
 * Baillie-PSW: trial division, one Miller-Rabin round to base 2, then a
 * strong Lucas test.
 *
 * @param {bigint} n
 * @param {number} [extra_rounds]  additional random-base Miller-Rabin rounds
 * @param {function} [rng]         used when extra_rounds > 0; left out, the platform's
 */
/**
 * The rng a function was given, or the platform's when it was given none.
 *
 * The library's rule for randomness: a parameter left out, or null, means
 * fresh randomness from the platform (secure_random - crypto.getRandomValues,
 * which throws rather than fall back to Math.random). A function passed
 * here is used as it is, so a test can still supply a deterministic one.
 *
 * Every caller assigns the result - `rng = require_rng(who, rng)` - so the
 * rest of its body never sees a missing rng.
 */
export function require_rng(who, rng) {
    if (rng == null) { return secure_random; }
    if (typeof rng !== 'function') {
        throw new TypeError(who + ': rng must be a function returning n random bytes, ' +
                            'or left out (or null) for the platform\'s');
    }
    return rng;
}

export function is_probable_prime(n, extra_rounds, rng) {
    /*
     * THE RNG IS CHECKED UP FRONT, and it used not to be - so
     * is_probable_prime(7n, 8) returned a boolean while
     * is_probable_prime(someLargeNumber, 8) threw, because the small-number
     * path returns before the random rounds are reached.
     *
     * Behaviour that depends on the VALUE rather than the arguments is the
     * worst kind to debug: it works in the test and fails in production, on
     * exactly the inputs that matter.
     */
    if (extra_rounds) { rng = require_rng('is_probable_prime', rng); }
    if (n < 2n) { return false; }
    var i;
    for (i = 0; i < SMALL.length; i++) {
        if (n === SMALL[i]) { return true; }
        if (n % SMALL[i] === 0n) { return false; }
    }

    /*
     * ⚠ REMOVING THIS ROUND IS NOT DETECTABLE BY ANY TEST, including
     *   Wycheproof's 317 primality vectors - verified by deleting it and
     *   running everything.
     *
     *   That is not a gap in the tests; it is what Baillie-PSW IS. The
     *   strength comes from the COMBINATION of a base-2 Miller-Rabin round
     *   with a strong Lucas test, and no composite is known that passes both.
     *   Either half alone rejects almost everything, so removing one leaves
     *   behaviour that looks identical on every input anyone has found.
     *
     *   Which means this line cannot be defended by a test. It is defended by
     *   the fact that it is written down here and why.
     */
    if (!miller_rabin(n, 2n)) { return false; }
    if (!strong_lucas(n)) { return false; }

    /*
     * Baillie-PSW alone has no known counterexample. Extra random rounds are
     * offered because FIPS 186-4 mandates a round count for key generation,
     * and because "no known counterexample" is not "proven none exists".
     */
    var rounds = extra_rounds || 0;
    for (i = 0; i < rounds; i++) {
        var a = random_below(n - 3n, rng) + 2n;
        if (!miller_rabin(n, a)) { return false; }
    }
    return true;
}

/** A uniform random value in [0, limit), by rejection. */
function random_below(limit, rng) {
    var bits = limit.toString(2).length;
    var bytes = (bits + 7) >> 3;
    for (var tries = 0; tries < 1000; tries++) {
        var v = bytes_to_bigint(rng(bytes)) >> BigInt(bytes * 8 - bits);
        /* rejection rather than modulo - a modulo here would skew the low
           values, and biased primes are a real weakness */
        if (v < limit) { return v; }
    }
    throw new Error('primes: rejection sampling failed');
}

/**
 * Generate a random prime of exactly `bits` bits.
 *
 * The top TWO bits are set, not just one. That is deliberate and comes from
 * the RSA standards: with both set, the product of two such primes always has
 * exactly 2*bits bits, so a 2048-bit key is never accidentally 2047. Setting
 * only the top bit would leave that to chance.
 *
 * `mod4` CONSTRAINS THE RESIDUE, for Blum integers.
 *
 * A Paillier-Blum modulus needs p = q = 3 (mod 4), which is what makes -1 a
 * non-residue and every square have exactly one square root that is itself a
 * square. CGGMP21's modulus proof is a statement about precisely that, so a
 * key generated without the constraint cannot satisfy the proof its own
 * protocol requires - and there was no way to ask for one.
 *
 * Costs nothing: half of all odd primes satisfy it, so the search runs twice
 * as many candidates through a filter that is one modulo.
 *
 * @param {number}   bits
 * @param {function} rng    (n) -> Uint8Array of n random bytes
 * @param {number}   [rounds=8]  extra Miller-Rabin rounds
 * @param {number}   [mod4]  require v % 4 === mod4; 3 for Blum
 */
/**
 * One odd candidate of EXACTLY `bits` bits with the top TWO bits set, so the
 * product of two such values has exactly 2*bits bits - what an RSA or
 * Paillier modulus of the requested width needs.
 *
 * Shared by every prime search here. A one-attempt copy for the old callback
 * keygens (since replaced by random_prime_task) used to build its own: it kept
 * the excess bits of the last byte (a 257-bit request returned 264-bit primes)
 * and set only the top bit (two 256-bit primes multiplied to 511 bits four
 * times in six).
 */
export function prime_candidate(bits, rng) {
    rng = require_rng('primes.prime_candidate', rng);
    var bytes = (bits + 7) >> 3;
    var v = bytes_to_bigint(rng(bytes)) >> BigInt(bytes * 8 - bits);
    return v | (1n << BigInt(bits - 1)) | (1n << BigInt(bits - 2)) | 1n;
}

export function random_prime(bits, rng, rounds, mod4) {
    return finish_task(random_prime_task(bits, rng, rounds, mod4));
}

/**
 * random_prime as a task (commons/task.js): one candidate a step - a few
 * milliseconds at 1024 bits when it reaches Miller-Rabin, far less when
 * trial division rejects it - so a key generation can run in slices.
 * onCandidate(attempt), when given, is called before each candidate.
 */
export function random_prime_task(bits, rng, rounds, mod4, onCandidate) {
    rng = require_rng('random_prime', rng);
    if (bits < 16) { throw new Error('primes: bits must be at least 16'); }
    var extra = (rounds === undefined) ? 8 : rounds;
    var attempt = 0, found = null;
    return {
        step: function () {
            if (found !== null) { return true; }
            if (attempt++ >= 100000) { throw new Error('primes: failed to find a prime'); }
            if (onCandidate) { onCandidate(attempt); }
            var v = prime_candidate(bits, rng);

            /* cheaper to test the residue than to run Miller-Rabin and discard */
            if (mod4 !== undefined && Number(v & 3n) !== mod4) { return false; }

            if (is_probable_prime(v, extra, rng)) { found = v; }
            return found !== null;
        },
        result: function () { return found; }
    };
}

/**
 * A safe prime: p = 2q + 1 with q also prime.
 *
 * Moved here from ring_pedersen.js, which had it privately - CGGMP21 needs
 * the same primes for each party's Paillier modulus, and a second copy of a
 * search this delicate is how the two drift apart.
 *
 * SLOW, AND UNAVOIDABLY SO. Safe primes are rare - roughly one in
 * (ln p)^2 / 2 odd numbers - so most candidates fail. Measured here: 0.2s at
 * 384 bits, 10s at 512, and 37 seconds at 1024 over 116 candidates. That is
 * the number that shapes a protocol's setup phase, so it is worth stating
 * rather than discovering.
 *
 * `onCandidate` is called once per attempt, which is what makes a progress
 * bar or a yield to the event loop possible. Without it a 1024-bit search
 * blocks a browser tab for most of a minute with nothing to show.
 *
 * @param {number}   bits
 * @param {function} rng
 * @param {function} [onCandidate]  (attempt) -> void
 */
export function safe_prime(bits, rng, onCandidate) {
    return finish_task(safe_prime_task(bits, rng, onCandidate));
}

/**
 * safe_prime as a task (commons/task.js). An attempt is q's search, a
 * candidate a step, then the test of p = 2q + 1. A step is one Miller-Rabin
 * test at most, where an attempt used to be the whole of it (233 ms at 1024
 * bits).
 *
 * ⚠ p GETS THE 8 RANDOM MILLER-RABIN ROUNDS random_prime gives every prime
 *   (FIPS 186-5 B.3 asks for random rounds on top of the fixed test for
 *   key-generation primes). An older copy gave p Baillie-PSW alone - the same
 *   primes, but different rng consumption, so two keygens drew different
 *   second primes from one rng. There is one copy now.
 */
export function safe_prime_task(bits, rng, onCandidate) {
    rng = require_rng('safe_prime', rng);
    var attempt = 0, q_search = null, found = null;
    return {
        step: function () {
            if (found !== null) { return true; }
            if (!q_search) {
                if (++attempt > 200000) { throw new Error('primes: safe prime generation failed'); }
                if (onCandidate) { onCandidate(attempt); }
                q_search = random_prime_task(bits - 1, rng, 4);
            }
            if (!q_search.step()) { return false; }
            var q = q_search.result();
            q_search = null;
            var p = 2n * q + 1n;
            /* a cheap filter before the expensive test */
            if (p % 3n === 0n || p % 5n === 0n || p % 7n === 0n) { return false; }
            if (is_probable_prime(p, 8, rng)) { found = { p: p, q: q }; }
            return found !== null;
        },
        result: function () { return found; }
    };
}


/**
 * A key from two primes, as a task (commons/task.js): search(0) finds the
 * first prime, search(1) the second - each a prime search task - and
 * build(p, q) makes the key, or returns null to reject the pair. A rejected
 * pair discards BOTH primes and starts again, at most `attempts` times;
 * then `failure` is thrown. RSA and Paillier key generation are this, with
 * their own searches and checks.
 *
 * ⚠ BOTH PRIMES, NEVER ONE. Each rejection is a condition on the pair (too
 *   close, n a bit short, gcd(n, phi) != 1); keeping one prime and finding
 *   it a new partner would bias the distribution - and would look like it
 *   worked.
 */
export function prime_pair_task(search, build, attempts, failure) {
    var attempt = 0, first = null, current = null, key = null;
    return {
        step: function () {
            if (key !== null) { return true; }
            if (!current) {
                if (attempt >= attempts) { throw new Error(failure); }
                current = search(first === null ? 0 : 1);
            }
            if (!current.step()) { return false; }
            var prime = current.result();
            current = null;
            if (first === null) { first = prime; return false; }
            attempt++;
            key = build(first, prime);
            first = null;
            return key !== null;
        },
        result: function () { return key; }
    };
}

/** Greatest common divisor. */
export function gcd(a, b) {
    while (b !== 0n) { var t = a % b; a = b; b = t; }
    return a < 0n ? -a : a;
}

/**
 * Is v a CANONICAL unit mod m: a bigint in [1, m) with gcd(v, m) = 1?
 *
 * The membership test a ZK verifier owes every group element it receives.
 * gcd alone accepts v + m and -v as well — other encodings of the same
 * residue, and therefore other proofs of the same statement.
 */
export function unit_in(v, m) {
    return typeof v === 'bigint' && v > 0n && v < m && gcd(v, m) === 1n;
}

/**
 * Modular inverse by the extended Euclidean algorithm.
 *
 * Variable time, and correctly so: RSA key generation inverts public values
 * (e modulo phi), and Fermat's method would need a modulus that is prime,
 * which phi is not.
 */
/**
 * The extended Euclidean algorithm: g, x, y with a*x + b*y = g.
 *
 * EXPORTED BECAUSE THE SECOND COEFFICIENT IS SOMETIMES THE POINT.
 * mod_inverse below is this with y discarded, which covers most callers - but
 * an RSA accumulator's non-membership proof IS the Bezout pair, and
 * recomputing it there meant the same eight lines twice.
 */
export function bezout(a, b) {
    var old_r = a, r = b;
    var old_x = 1n, x = 0n;
    var old_y = 0n, y = 1n;
    while (r !== 0n) {
        var q = old_r / r;
        var t = old_r - q * r; old_r = r; r = t;
        t = old_x - q * x; old_x = x; x = t;
        t = old_y - q * y; old_y = y; y = t;
    }
    return { g: old_r, x: old_x, y: old_y };
}

/**
 * The multiplicative inverse of a modulo m.
 *
 * @return {bigint|null} null when gcd(a, m) != 1 - which for an RSA modulus
 *         means a SHARES A FACTOR WITH m, so a caller who ignores the null
 *         has just been handed the factorisation and thrown it away. Every
 *         caller here treats it as an error for that reason.
 */
export function mod_inverse(a, m) {
    /*
     * ⭐ bezout's first coefficient. This was the same extended Euclid loop
     *   with the second coefficient left out - a second copy kept for speed.
     *   Measured on a 2048-bit RSA-like modulus: 533 us against 665 through
     *   bezout, and on the path that calls it most (powmod_signed_ct, one
     *   inversion of the base per call) that is 0.2% of a 63 ms
     *   exponentiation. Not worth a second copy of the algorithm.
     */
    var r = bezout(((a % m) + m) % m, m);
    if (r.g !== 1n) { return null; }
    return ((r.x % m) + m) % m;
}

export { powmod };

/**
 * A modulus with a generator of the quadratic residues, AND ITS FACTORS.
 *
 * FOR TESTING ONLY, and the name says so. Three files in this library need a
 * group of unknown order - vdf.js, accumulator.js and vector_commit.js - and
 * every one of them is broken outright by an evaluator who knows the
 * factorisation: the VDF's delay evaporates, and the other two can open any
 * position or prove any membership.
 *
 * Returning p, q and phi rather than discarding them makes that impossible to
 * use by accident. Real deployments take the modulus from a multi-party
 * ceremony, from the RSA-2048 challenge, or from a class group with no setup
 * at all.
 *
 * g is a random SQUARE, so it generates the quadratic residues - a subgroup
 * with no element of order 2, which is what stops a small-order element from
 * satisfying these schemes' equations trivially.
 */
export function unknown_order_group_unsafe(bits, rng) {
    var half = bits >> 1;
    for (var i = 0; i < 100; i++) {
        var p = random_prime(half, rng);
        var q = random_prime(half, rng);
        if (p === q) { continue; }
        var N = p * q;
        /* g: random_quadratic_residue, the one "random square mod N" */
        return { N: N, g: random_quadratic_residue(N, rng), p: p, q: q,
                 phi: (p - 1n) * (q - 1n) };
    }
    throw new Error('primes: unknown-order group generation failed');
}

/**
 * A prime of exactly `bits` bits, drawn from a DETERMINISTIC byte source.
 *
 * Three files need a prime that the verifier can recompute from public data -
 * vdf.js from (g, y), accumulator.js from an element, vector_commit.js from a
 * position - and reach this through commons/zk_bytes.fs_prime, which feeds it
 * the Fiat-Shamir stream. `read` is that stream: (n) -> n bytes, the same
 * shape as an rng, and the same bytes for the same transcript.
 *
 * ⚠ IT USED TO BE hash_to_prime(domain, parts, bits, hash, be16, concat),
 *   which built its own counter-mode sha256 expansion - one of seven
 *   Fiat-Shamir expanders in this library. The derivation now lives in one
 *   place, so every derived prime changed, and the three callers' domain tags
 *   moved to a new version with it.
 *
 * Each candidate is a fresh read, top bit and low bit set. The primality test
 * uses its FIXED BASES only, with no random rounds: a randomised test could
 * accept a candidate the verifier rejects, and the two would derive different
 * primes from identical inputs.
 *
 * @param {number}   bits
 * @param {function} read  (n) -> Uint8Array, deterministic
 */
export function prime_from_stream(bits, read) {
    var bytes = (bits + 7) >> 3;
    for (var counter = 0; counter < 1000000; counter++) {
        var cand = bytes_to_bigint(read(bytes)) >> BigInt(bytes * 8 - bits);
        /* full width and odd, so the search space is the right size */
        cand |= (1n << BigInt(bits - 1)) | 1n;
        if (is_probable_prime(cand)) { return cand; }
    }
    throw new Error('primes: could not derive a prime');
}

/**
 * Least non-negative residue, for a possibly negative input.
 *
 * JavaScript's `%` keeps the sign of the dividend, so `-3n % 7n` is `-3n` and
 * not `4n`. Every proof in this library that draws SIGNED masks - and they
 * all do, because the masks have to be centred on zero to hide the sign of
 * what they cover - needs the mathematician's version.
 */
export function mod(a, m) { return ((a % m) + m) % m; }

/**
 * g^x mod m, for a possibly negative exponent.
 *
 * Was private in paillier_range.js and needed again by the factor proof; a
 * second copy of an inversion this easy to get subtly wrong is how two files
 * end up disagreeing about what a negative exponent means.
 */
/**
 * powmod_signed with a SECRET exponent.
 *
 * ==================== ⛔ TWO LEAKS, NOT ONE ====================
 *
 *   1. powmod's time tracks the exponent's Hamming weight - see powmod_ct.
 *
 *   2. ⭐ AND `if (x >= 0n)` BRANCHES ON THE EXPONENT'S SIGN. The negative
 *      path does an extra inversion, so the two differ by far more than a
 *      predictable branch: the sign of every blinder is visible in the
 *      timing.
 *
 *   Both matter here. The CGGMP21 proofs call this with secret prime factors
 *   and with signed blinders drawn from symmetric ranges, so the sign is a
 *   real bit of secret.
 *
 * ⭐ THE BASE IS PUBLIC in every caller - it is the ring-Pedersen parameter s
 *   or t, or a published ciphertext. So the inverse can be computed
 *   unconditionally and selected by mask, which costs one inversion of a
 *   public value and removes the branch entirely.
 *
 * ⚠ THE MAGNITUDE IS TAKEN BRANCHLESSLY. `x < 0n ? -x : x` reads as harmless
 *   and is a branch on the secret's sign - the same one this function exists
 *   to remove.
 *
 * ⛔ IF THE BASE IS NOT INVERTIBLE this throws, as the variable-time version
 *   does. That is a property of the base, which is public, so the throw
 *   leaks nothing about x.
 */
export function powmod_signed_ct(g, x, m, bits) {
    var neg = x < 0n ? 1n : 0n;
    var mag = (x ^ -neg) + neg;          /* |x|, without a branch on the sign */

    var gm = ((g % m) + m) % m;
    var inv = mod_inverse(gm, m);
    if (inv === null) { throw new Error('primes: non-invertible base'); }

    /* select the base by mask rather than by branch */
    var mask = -neg;                     /* 0n or -1n */
    var t = (gm ^ inv) & mask;
    var base = gm ^ t;

    /*
     * ⚠ bits MUST be the width of the PUBLIC bound this exponent was sampled
     *   from, whenever that bound is wider than the modulus. Leaving it to
     *   default to the modulus width truncates - see powmod_ct. The bound is
     *   public, so declaring it leaks nothing.
     */
    return powmod_ct(base, mag, m, bits);
}

export function powmod_signed(g, x, m) {
    if (x >= 0n) { return powmod(g, x, m); }
    var inv = mod_inverse(powmod(g, -x, m), m);
    if (inv === null) { throw new Error('primes: non-invertible base'); }
    return inv;
}

/**
 * g^x mod m for a SECRET base g and a PUBLIC signed exponent x.
 *
 * The Sigma-protocol responses w = r * rho^e: e is the public challenge, but
 * rho is the encryption randomiser and opens the ciphertext. For e < 0 that
 * needs rho^-1, and mod_inverse is the extended Euclid - its running time
 * follows the value it inverts. So the inverse is BLINDED: for a fresh unit
 * u, g^-1 = u * (g*u)^-1, and g*u is uniform whatever g is.
 *
 * The exponentiation itself stays variable-time: its timing follows the
 * exponent, which is public.
 */
export function powmod_signed_blind(g, x, m, rng) {
    rng = require_rng('primes.powmod_signed_blind', rng);
    if (x >= 0n) { return powmod(g, x, m); }
    var u = random_unit(m, rng);
    var t = mod_inverse(mod(g * u, m), m);
    if (t === null) { throw new Error('primes: non-invertible base'); }
    return powmod(mod(u * t, m), -x, m);
}

/**
 * Integer square root, by Newton's method.
 *
 * The factor proof bounds its masks at 2^(ell+eps) * sqrt(N0), and that
 * square root is the whole substance of the statement: a mask that size can
 * absorb `e*p` when p is around sqrt(N0) and cannot when p is small. Getting
 * it wrong by one in either direction weakens or breaks the proof, so it is
 * exact rather than floating point - N0 has thousands of bits and a double
 * has 53.
 */
export function isqrt(n) {
    if (n < 0n) { throw new RangeError('primes: isqrt of a negative number'); }
    if (n < 2n) { return n; }
    var x = 1n << BigInt(((n.toString(2).length) + 1) >> 1);
    for (;;) {
        var y = (x + n / x) >> 1n;
        if (y >= x) { return x; }
        x = y;
    }
}

/**
 * n = a^2 + b^2 + c^2, for n = 1 (mod 4) - the decomposition the
 * three-square range proof needs (Groth 2005; Couteau, Peters, Pointcheval,
 * eprint 2016/128 section 7.2), where n = 4(x - a)(b - x) + 1.
 *
 * Every n = 1 (mod 4) is a sum of three squares (Legendre: only
 * 4^k (8m + 7) is not). Las Vegas, after Rabin-Shallit:
 *
 *   1. draw an EVEN x1 <= sqrt(n), so p = n - x1^2 = 1 (mod 4);
 *   2. if p is a square, or a prime (then p = 1 mod 4, a sum of two squares
 *      by Fermat), finish; otherwise draw again;
 *   3. for a prime p: s = c^((p-1)/4) for a non-residue c gives s^2 = -1,
 *      and Euclid on (p, s) stopped below sqrt(p) gives p = y^2 + z^2
 *      (Hermite-Serret / Cornacchia).
 *
 * About ln(n)/2 draws: hundreds of primality tests for a 2048-bit n.
 *
 * ⚠ NOT CONSTANT TIME. The number of draws depends on n, which the range
 *   proof derives from its secret witness. It is the same kind of exposure
 *   as random_prime's search time, and the result is only ever committed.
 *
 * @param {bigint} n  n >= 1, n = 1 (mod 4)
 * @param {function} rng
 * @return {Array<bigint>} [a, b, c] with a^2 + b^2 + c^2 = n
 */
export function sum_of_three_squares(n, rng) {
    if (typeof n !== 'bigint' || n < 1n || (n & 3n) !== 1n) {
        throw new RangeError('primes: sum_of_three_squares needs n >= 1 with n = 1 (mod 4)');
    }
    rng = require_rng('sum_of_three_squares', rng);
    var root = isqrt(n);
    if (root * root === n) { return [root, 0n, 0n]; }
    var half = root >> 1n;                   /* x1 = 2k, 0 <= k <= half */
    for (var tries = 0; tries < 1000000; tries++) {
        var x1 = 2n * random_below_biased(half + 1n, rng);
        var p = n - x1 * x1;
        var sp = isqrt(p);
        if (sp * sp === p) { return [x1, sp, 0n]; }
        if (!is_probable_prime(p, 0)) { continue; }
        var two = two_squares_prime(p, rng);
        if (two) { return [x1, two[0], two[1]]; }
    }
    throw new Error('primes: sum_of_three_squares did not finish');
}

/* p = y^2 + z^2 for a prime p = 1 (mod 4), or null if p is not one after all */
function two_squares_prime(p, rng) {
    var e = (p - 1n) >> 2n, s = null;
    for (var i = 0; i < 128 && s === null; i++) {
        var c = 2n + random_below_biased(p - 3n, rng);
        var t = powmod(c, e, p);
        if (mod(t * t, p) === p - 1n) { s = t; }
    }
    if (s === null) { return null; }
    var a = p, b = s, lim = isqrt(p);
    while (b > lim) { var r = a % b; a = b; b = r; }
    var z2 = p - b * b, z = isqrt(z2);
    return z * z === z2 ? [b, z] : null;
}

/**
 * |v| <= bound, for a signed value.
 *
 * ⭐ THE LIBRARY'S ONE CONVENTION FOR "v in +-2^k": INCLUSIVE, |v| <= 2^k.
 *   Every range check in the proofs goes through this (and
 *   zk_bytes.require_in_range on the prover's side). They used to split
 *   down the middle: Pi^enc, Pi^log* and Pi^aff-g refused |z| = 2^k, the
 *   eprint 2024/1950 proofs and Pi^fac accepted it.
 *
 *   Inclusive because eprint 2024/1950 writes its bounds as |z| <= 2^(...)
 *   (Protocols 4, 7, 8). CGGMP21 does not settle it: its "+-m" is the set of m
 *   consecutive integers around zero (section 2), an interval of SIZE m rather
 *   than of half-width m, so its +-2^(ell+eps) is about half the width this
 *   library's ell and eps describe - those follow the CGGMP24/LFDT
 *   specification's half-width reading, under which the endpoint is a single
 *   value either way. An honest response is a uniform mask plus e*x, so it
 *   hits that one value with probability about 2^-(ell+eps): the choice
 *   changes no honest outcome, and making it once removes the question.
 */
export function in_range(v, bound) {
    return v <= bound && v >= -bound;
}

/**
 * Uniform in [0, bound), by oversampling and reducing.
 *
 * NOT THE SAME AS the rejection sampler above, and both are here on purpose.
 * Rejection is exactly unbiased and loops; this draws 128 bits more than it
 * needs and reduces once, which leaves a bias of about 2^-128 and never
 * loops. Three files reached the same conclusion independently and wrote the
 * same six lines - paillier_range, mta and zk_cmp - which is the point at
 * which it stops being a local detail.
 *
 * Use this where the bound is a mask width rather than a group order: the
 * values are already being hidden by something far larger, and a bounded
 * running time matters more than the last 2^-128 of uniformity.
 */
export function random_below_biased(bound, rng) {
    rng = require_rng('primes.random_below_biased', rng);
    var width = ((bound.toString(2).length + 7) >> 3) + 16;
    return bytes_to_bigint(rng(width)) % bound;
}

/** Uniform in +-bound. */
export function random_signed_below(bound, rng) {
    rng = require_rng('primes.random_signed_below', rng);
    var v = random_below_biased(bound, rng);
    return (rng(1)[0] & 1) ? -v : v;
}

/**
 * A unit mod n - an element with an inverse.
 *
 * Paillier's encryption randomness has to be invertible, or the ciphertext
 * cannot be opened and the range proof over it cannot be built. Both
 * paillier_range and mta drew one and wrote the same loop; with a modulus
 * that is a product of two large primes a random draw is a unit with
 * overwhelming probability, so the loop almost never runs twice and the bound
 * is there to fail loudly rather than spin.
 */
export function random_unit(n, rng) {
    rng = require_rng('primes.random_unit', rng);
    for (var i = 0; i < 200; i++) {
        var r = random_below_biased(n, rng);
        if (r > 1n && gcd(r, n) === 1n) { return r; }
    }
    throw new Error('primes: could not draw a unit');
}

/**
 * Is `a` a quadratic residue modulo n = p*q, given the factors?
 *
 * ⚠ THE JACOBI SYMBOL IS NOT ENOUGH. jacobi(a, n) = 1 holds both when a is a
 *   residue modulo BOTH primes and when it is a non-residue modulo BOTH -
 *   the two minus signs cancel. Half the elements with symbol 1 are not
 *   squares, and telling them apart is exactly the quadratic residuosity
 *   problem, which is believed hard without the factorisation.
 *
 *   So this needs p and q. A verifier that only has n cannot run it, and a
 *   protocol that needs the check on the verifier's side has to carry a
 *   proof instead.
 */
export function is_quadratic_residue(a, p, q) {
    return jacobi(a, p) === 1 && jacobi(a, q) === 1;
}

/**
 * A uniform element of QR_n, the subgroup of squares, other than 1.
 *
 * Squaring a uniform element of Z*_n lands uniformly in QR_n, which is why
 * this needs no rejection loop beyond the unit test - and why it is the
 * standard way to get a generator for schemes like Shoup's threshold RSA, the
 * ring-Pedersen parameters, an RSA accumulator or a VDF, all of which work in
 * QR_n rather than in all of Z*_n.
 *
 * ⭐ THE ONE "RANDOM SQUARE MOD N". There were five: this one (no extra
 *   bytes, so the reduction was biased by up to a factor of two),
 *   unknown_order_group_unsafe, two loops in ring_pedersen and vdf's
 *   hash_to_group (whose x < 2 became 2 rather than being redrawn). This is
 *   the strictest of them: random_below_biased (16 extra bytes), the draw
 *   must be a unit, and a square of 1 - from +-1 or, with negligible
 *   probability, another square root of 1 - is drawn again.
 *
 * `rng` may be a deterministic stream (zk_bytes.fs_stream) when the element
 * must be recomputable, as vdf's is.
 */
export function random_quadratic_residue(n, rng) {
    rng = require_rng('random_quadratic_residue', rng);
    for (var i = 0; i < 1000; i++) {
        var v = random_below_biased(n, rng);
        if (gcd(v, n) !== 1n) { continue; }
        var sq = (v * v) % n;
        if (sq > 1n) { return sq; }
    }
    throw new Error('primes: could not sample a quadratic residue');
}
