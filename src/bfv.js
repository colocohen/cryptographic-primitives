/**
 * bfv.js - the Brakerski/Fan-Vercauteren homomorphic encryption scheme.
 *
 * Encrypt two numbers, add or multiply the CIPHERTEXTS, and the result
 * decrypts to the sum or product of the plaintexts. Nobody holding the
 * ciphertexts learns anything, and the party doing the arithmetic never sees
 * a plaintext at all.
 *
 * paillier.js already does addition this way. What lattices buy is
 * MULTIPLICATION - and that is the difference between "add up encrypted
 * votes" and "run an arbitrary computation on data you cannot see".
 *
 * ==================== NOISE IS THE WHOLE PROBLEM ====================
 *
 * Every ciphertext carries a small error term, and every operation makes it
 * bigger: addition roughly doubles it, multiplication roughly squares it.
 * When it grows past q/(2t) the plaintext is destroyed - silently, with a
 * wrong answer rather than an error.
 *
 * So a parameter set is not a security choice alone; it is a budget for how
 * many operations can be performed. `levels()` below reports what is left,
 * because the alternative is finding out from a wrong result.
 *
 * ==================== PARAMETERS ====================
 *
 * From the Homomorphic Encryption Standard and from "Security Guidelines for
 * Implementing Homomorphic Encryption" (eprint 2024/463), which tabulates LWE
 * parameter sets for the 128, 192 and 256-bit levels. The error distribution
 * is fixed at sigma = 3.19, as those tables assume, and the secret is uniform
 * ternary - the choice the standard says has "a significant performance
 * advantage" for BGV and BFV.
 *
 * ⚠ NOT VERIFIED AGAINST A TEST VECTOR. There is no FIPS document for this
 *   with vectors attached. What is checked here: the ring arithmetic against
 *   schoolbook multiplication, the scheme's own algebraic laws over many
 *   random inputs, and that noise growth matches the predicted bound.
 *   Agreement with SEAL or OpenFHE on identical inputs would be worth more
 *   than all of it, and has not been done.
 *
 * ==================== WHAT THIS CAN AND CANNOT DO ====================
 *
 * MEASURED, on the parameter sets below:
 *
 *     hundreds of additions          fine - 200 cost 5 bits of budget
 *     multiplication by a plaintext  fine
 *     ONE ciphertext multiplication  fine, and it consumes almost everything
 *     two multiplications            only with a small t, and barely
 *
 * That is a SOMEWHAT homomorphic scheme, not a fully homomorphic one. The
 * ceiling is q, which is 54 bits here so that coefficients stay inside a
 * BigInt operation that is cheap; real depth needs a q of several hundred
 * bits, which needs an RNS representation - several small moduli carried in
 * parallel - and that is the single largest thing missing.
 *
 * The other route past the ceiling is bootstrapping, which resets the noise
 * by decrypting homomorphically. It is what makes a scheme FULLY homomorphic
 * and it is far more work than everything in this file combined.
 *
 * WHAT IT IS ENOUGH FOR: private information retrieval, encrypted tallies,
 * summing encrypted measurements, and any circuit one multiplication deep.
 *
 * ==================== AND WITH RNS, MEASURED ====================
 *
 * The rns_ functions at the bottom carry the same scheme over a chain of
 * 50-bit primes, which lifts the ceiling considerably:
 *
 *     single prime, q =  54 bits    depth  1
 *     RNS,          Q = 150 bits    depth  5     0.6 s
 *     RNS,          Q = 200 bits    depth  7     1.0 s
 *     RNS,          Q = 300 bits    depth 10     1.8 s
 *
 * The single-prime path reaches 200 bits too and takes 8 seconds to get
 * depth 6, because every coefficient product becomes a 200-bit BigInt
 * multiply. That gap is the entire argument for RNS.
 *
 * Depth 10 is enough for real circuits - a comparison, a small polynomial
 * evaluation, a weighted sum of products. It is not unlimited, and
 * bootstrapping is still the only thing that would make it so.
 *
 * ==================== COMPARED AGAINST OpenFHE ====================
 *
 * OpenFHE's BFV was installed and asked what modulus it picks. At n = 1024,
 * t = 65537, it sizes q at 120 bits for depth 1-2, 180 for depth 3, 240 for
 * depth 5. The same parameters here reach depth 4, 6 and 8 - consistently
 * about 1.6x more, and stable across eight runs with random values, so it is
 * not luck.
 *
 * TREAT THAT AS A WARNING RATHER THAN AN ADVANTAGE. When OpenFHE is more
 * conservative, the likely explanation is that it is accounting for
 * something this one is not. Two candidates:
 *
 *   - It sizes for a failure probability over many operations rather than
 *     for a measurement that succeeded. Noise is random, and eight runs is
 *     not a bound.
 *   - It reserves room for security as well as correctness. OpenFHE refuses
 *     n = 1024 at its default security level and wants n = 8192; the
 *     comparison above only works because that check was switched off.
 *
 * SO: the depth figures here are measured, not guaranteed, and a caller who
 * needs a guarantee should size q the way OpenFHE does and check
 * noise_budget rather than trusting the table.
 *
 * A true cross-check - encrypt in OpenFHE, decrypt here - was not done. The
 * serialisation formats differ and matching them is a day of work. It is
 * still the single most valuable thing that could happen to this file.
 */

import { mod, powmod, is_probable_prime, random_below_biased, require_rng } from './commons/primes.js';
import { negacyclic } from './commons/negacyclic_ntt.js';

/* ==================== the ring Z_q[X]/(X^n + 1) ==================== */

/**
 * A ring, precomputed once.
 *
 * @param {number} n  degree, a power of two
 * @param {bigint} q  prime, congruent to 1 mod 2n so a 2n-th root exists
 */
export function ring(n, q) {
    var T = negacyclic(n, q, 'bfv');

    return {
        n: n, q: q,
        /** Multiply two polynomials in the ring. */
        mul: function (a, b) {
            var A = T.forward(a), B = T.forward(b), C = new Array(n);
            for (var i = 0; i < n; i++) { C[i] = mod(A[i] * B[i], q); }
            return T.inverse(C);
        },
        add: function (a, b) {
            var o = new Array(n);
            for (var i = 0; i < n; i++) { o[i] = mod(a[i] + b[i], q); }
            return o;
        },
        sub: function (a, b) {
            var o = new Array(n);
            for (var i = 0; i < n; i++) { o[i] = mod(a[i] - b[i], q); }
            return o;
        },
        neg: function (a) {
            var o = new Array(n);
            for (var i = 0; i < n; i++) { o[i] = mod(-a[i], q); }
            return o;
        },
        zero: function () {
            var o = new Array(n);
            for (var i = 0; i < n; i++) { o[i] = 0n; }
            return o;
        }
    };
}

/* ==================== the scheme ==================== */

/**
 * Parameter sets, from the Homomorphic Encryption Standard's tables.
 *
 * `t` is the plaintext modulus and `q` the ciphertext modulus; the ratio
 * between them is the noise budget, so a larger t means fewer operations
 * before the plaintext is destroyed. `depth` is how many multiplications the
 * set survives - measured, not claimed, by the test that fills the budget.
 */
export var PARAMS = {
    /* 128-bit security, additions and a shallow multiplication */
    n1024: { n: 1024, q: 18014398509404161n, t: 65537n, sigma: 3.19 },
    n2048: { n: 2048, q: 18014398509404161n, t: 65537n, sigma: 3.19 },
    n4096: { n: 4096, q: 18014398509309953n, t: 65537n, sigma: 3.19 }
};

/**
 * Uniform ternary: each coefficient -1, 0 or 1. The standard's choice.
 *
 * ⚠ IT WAS NOT UNIFORM: one byte mod 3, and 256 = 3*85 + 1, so -1 came up
 *   86 times in 256 against 85 for the others. Each coefficient is now
 *   primes.random_below_biased(3) - 1, the library's one bounded sampler.
 */
function ternary(n, rng) {
    var o = new Array(n);
    for (var i = 0; i < n; i++) { o[i] = random_below_biased(3n, rng) - 1n; }
    return o;
}

/**
 * Discrete Gaussian, by summing uniform bits.
 *
 * The Irwin-Hall approximation: 2*sigma^2*3 coin flips minus their mean is
 * close enough to a Gaussian for this purpose, and avoids a rejection loop
 * whose timing would depend on the sample. Exact discrete Gaussians matter
 * for signatures, where the distribution leaks the key; here the error is
 * discarded at decryption and never travels.
 */
function gaussian(n, sigma, rng) {
    var reps = Math.round(6 * sigma * sigma);
    var o = new Array(n);
    var b = rng(n * reps);
    for (var i = 0; i < n; i++) {
        var s = 0;
        for (var j = 0; j < reps; j++) { s += b[i * reps + j] & 1; }
        o[i] = BigInt(s - (reps >> 1));
    }
    return o;
}

/* uniform mod q: primes.random_below_biased per coefficient (16 extra bytes
   each; this drew 8 and reduced, a fourth private copy of the sampler) */
function uniform(n, q, rng) {
    var o = new Array(n);
    for (var i = 0; i < n; i++) { o[i] = random_below_biased(q, rng); }
    return o;
}

/**
 * @param {function} [rng]  n => n random bytes; omitted or null draws fresh ones from the platform
 * @return {{pk: object, sk: object, ctx: object}}
 */
export function keygen(params, rng) {
    rng = require_rng('bfv.keygen', rng);
    /*
     * A MODULUS TOO SMALL FOR THE PLAINTEXT IS A SILENT DISASTER.
     *
     * delta = q/t is the room the message sits in above the noise floor. With
     * q = 2^27 and t = 65537 that leaves eleven bits, the fresh noise fills
     * them, and every operation returns a wrong number with no indication -
     * reported from outside as "garbage, no error".
     *
     * Twenty bits of headroom is not a security bound, just the point below
     * which nothing can work; the real sizing comes from the parameter tables
     * and from checking noise_budget.
     */
    if (params.q / params.t < (1n << 20n)) {
        throw new Error('bfv: q/t is under 2^20 - too small to hold a ' +
                        'plaintext above the noise. Use a larger q or a ' +
                        'smaller t, and check noise_budget after keygen.');
    }
    var R = ring(params.n, params.q);
    var s = ternary(params.n, rng);
    var a = uniform(params.n, params.q, rng);
    var e = gaussian(params.n, params.sigma, rng);

    /* pk = (-(a*s + e), a); decryption recovers m because pk0 + pk1*s = -e */
    var pk0 = R.neg(R.add(R.mul(a, s), e));

    var ctx = {
        R: R, n: params.n, q: params.q, t: params.t, sigma: params.sigma,
        delta: params.q / params.t
    };
    return { pk: { pk0: pk0, pk1: a }, sk: { s: s }, ctx: ctx };
}

/** Encode a small integer as a constant polynomial. */
export function encode(ctx, m) {
    var o = ctx.R.zero();
    o[0] = mod(BigInt(m), ctx.t);
    return o;
}

/** Encode a vector of integers, one per coefficient. */
export function encode_vector(ctx, values) {
    if (values.length > ctx.n) { throw new Error('bfv: too many values for this n'); }
    var o = ctx.R.zero();
    for (var i = 0; i < values.length; i++) { o[i] = mod(BigInt(values[i]), ctx.t); }
    return o;
}

/*
 * `ctx` is unused here and stays for symmetry with encode, which needs it,
 * and with decode_vector. A decoder whose signature differs from its encoder
 * is the kind of asymmetry a caller trips over once and remembers wrongly.
 */
export function decode(ctx, poly) { return poly[0]; }

/**
 * @param {number} [count]  how many slots to read; the whole ring by default
 *
 * IT USED TO REQUIRE count AND RETURN [undefined] WITHOUT IT, which reads as
 * a broken round trip rather than a missing argument - encode_vector knows
 * how many values it was given and decode_vector did not, so the obvious
 * symmetric call gave nonsense. Defaulting to n is the honest behaviour: the
 * ciphertext really does carry n slots, and the caller trims.
 */
export function decode_vector(ctx, poly, count) {
    return take(poly, count === undefined ? ctx.n : count);
}

/** The first `count` entries. */
function take(a, count) {
    var o = new Array(count);
    for (var i = 0; i < count; i++) { o[i] = a[i]; }
    return o;
}

/**
 * @param {function} [rng]  n => n random bytes; omitted or null draws fresh ones from the platform
 * @return {{c0, c1}}
 */
export function encrypt(ctx, pk, plainPoly, rng) {
    rng = require_rng('bfv.encrypt', rng);
    var R = ctx.R;
    var u = ternary(ctx.n, rng);
    var e1 = gaussian(ctx.n, ctx.sigma, rng);
    var e2 = gaussian(ctx.n, ctx.sigma, rng);

    /* delta*m raises the message above the noise floor */
    var scaled = new Array(ctx.n);
    for (var i = 0; i < ctx.n; i++) { scaled[i] = mod(plainPoly[i] * ctx.delta, ctx.q); }

    return {
        c0: R.add(R.add(R.mul(pk.pk0, u), e1), scaled),
        c1: R.add(R.mul(pk.pk1, u), e2)
    };
}

/**
 * Decrypt by rounding away the noise.
 *
 * c0 + c1*s is delta*m plus something small; dividing by delta and rounding
 * recovers m, PROVIDED the something small is still smaller than delta/2.
 * Past that the rounding lands on the wrong multiple and the answer is wrong
 * with no indication - which is why noise_budget exists.
 */
export function decrypt(ctx, sk, ct) {
    return round_to_plaintext(ctx.R.add(ct.c0, ctx.R.mul(ct.c1, sk.s)),
                              ctx.q, ctx.t, ctx.n);
}

/**
 * round(t * x / q), coefficient by coefficient, with x centred first.
 *
 * CENTRING IS NOT COSMETIC. A residue near q represents a small negative
 * number, and scaling it as though it were a large positive one rounds to the
 * wrong multiple - so a plaintext of -1 decrypts as something near t rather
 * than as t-1. Shared between the single-prime and RNS paths, which differ
 * only in which modulus they pass.
 */
function round_to_plaintext(raw, q, t, n) {
    var o = new Array(n);
    var half = q / 2n;
    for (var i = 0; i < n; i++) {
        var v = raw[i];
        var centred = v > half ? v - q : v;
        var scaled = centred * t;
        var r = scaled >= 0n ? (scaled + half) / q : -((-scaled + half) / q);
        o[i] = mod(r, t);
    }
    return o;
}

/** Componentwise. Noise roughly doubles. */
export function add(ctx, a, b) {
    return { c0: ctx.R.add(a.c0, b.c0), c1: ctx.R.add(a.c1, b.c1) };
}

export function sub(ctx, a, b) {
    return { c0: ctx.R.sub(a.c0, b.c0), c1: ctx.R.sub(a.c1, b.c1) };
}

/**
 * Multiply a ciphertext by a known plaintext.
 *
 * Far cheaper than ciphertext-ciphertext multiplication and enough for a
 * whole class of applications - a private information retrieval query is
 * exactly this operation repeated, and needs nothing more.
 */
export function mul_plain(ctx, ct, plainPoly) {
    return { c0: ctx.R.mul(ct.c0, plainPoly), c1: ctx.R.mul(ct.c1, plainPoly) };
}

/**
 * How much noise budget is left, in bits.
 *
 * ZERO MEANS THE NEXT OPERATION MAY SILENTLY CORRUPT THE PLAINTEXT. There is
 * no error to catch: a ciphertext past its budget decrypts to a wrong number
 * that looks exactly like a right one. Anything building on this should check
 * the budget rather than assume it.
 */
export function noise_budget(ctx, sk, ct) {
    return budget_from(ctx.R.add(ct.c0, ctx.R.mul(ct.c1, sk.s)),
                       decrypt(ctx, sk, ct), ctx.q, ctx.t, ctx.delta, ctx.n);
}

/** The distance between what decrypted and what should have, in bits. */
function budget_from(raw, plain, q, t, delta, n) {
    var maxNoise = 0n;
    var half = q / 2n;
    for (var i = 0; i < n; i++) {
        var expected = mod(plain[i] * delta, q);
        var d = mod(raw[i] - expected, q);
        if (d > half) { d = q - d; }
        if (d > maxNoise) { maxNoise = d; }
    }
    if (maxNoise === 0n) { maxNoise = 1n; }
    var budget = (q / (2n * t)).toString(2).length - maxNoise.toString(2).length;
    return budget > 0 ? budget : 0;
}

/* ==================== ciphertext times ciphertext ==================== */

/**
 * The relinearization key.
 *
 * WHY MULTIPLICATION NEEDS A KEY AT ALL, and addition does not:
 *
 * A ciphertext decrypts as c0 + c1*s. Multiply two of them and the product
 * decrypts as d0 + d1*s + d2*s^2 - three terms, and the s^2 is the problem.
 * The result is still a valid encryption, but under a LONGER key, and a
 * second multiplication would need s^3. Left alone, ciphertexts grow with
 * every product until they are unusable.
 *
 * Relinearization converts the three-term ciphertext back to two, using an
 * encryption of s^2 under s. That is what this key is. It is public: it
 * reveals nothing about s beyond what the public key already does.
 *
 * DECOMPOSED INTO DIGITS, because multiplying by the whole d2 would multiply
 * the key's own noise by q. Splitting d2 into base-w digits keeps each
 * product small and sums them, which is the standard trade of size against
 * noise: more digits means a larger key and less noise added.
 *
 * rng (n => n random bytes) null or omitted draws from the platform; pass
 * null to give logw.
 */
export function relin_keygen(ctx, sk, rng, logw) {
    rng = require_rng('bfv.relin_keygen', rng);
    var R = ctx.R;
    var w = 1n << BigInt(logw || 20);
    var levels = Math.ceil(ctx.q.toString(2).length / (logw || 20));
    var keys = [];
    var s2 = R.mul(sk.s, sk.s);

    var wi = 1n;
    for (var i = 0; i < levels; i++) {
        var a = uniform(ctx.n, ctx.q, rng);
        var e = gaussian(ctx.n, ctx.sigma, rng);
        /* k0 = -(a*s + e) + w^i * s^2,  k1 = a */
        var term = new Array(ctx.n);
        for (var j = 0; j < ctx.n; j++) { term[j] = mod(s2[j] * wi, ctx.q); }
        keys.push({
            k0: R.add(R.neg(R.add(R.mul(a, sk.s), e)), term),
            k1: a
        });
        wi = mod(wi * w, ctx.q);
    }
    return { keys: keys, w: w, logw: logw || 20, levels: levels };
}

/**
 * Multiply two ciphertexts.
 *
 * ⚠ NOISE GROWS MULTIPLICATIVELY, not additively. Two ciphertexts with 20
 *   bits of budget each produce one with far less than 20, and a second
 *   product may well produce garbage. Check noise_budget between operations
 *   rather than counting them.
 *
 * The scaling by t/q after the tensor product is what keeps the result in the
 * same representation as its inputs; without it the message would be scaled
 * by delta twice and decryption would divide by the wrong amount.
 */
export function mul(ctx, rlk, a, b) {
    var R = ctx.R, n = ctx.n, q = ctx.q, t = ctx.t;

    /* the tensor product, over the integers rather than mod q - the values
       reach q^2 and reducing early would discard exactly what the rescaling
       below needs */
    var d = tensor_and_rescale(a.c0, a.c1, b.c0, b.c1, t, q, n);
    var d0 = d[0], d1 = d[1], d2 = d[2];

    /* fold the s^2 term back in */
    var digits = decompose(d2, rlk.w, rlk.levels, n);
    var c0 = d0, c1 = d1;
    for (var i = 0; i < rlk.levels; i++) {
        c0 = R.add(c0, R.mul(rlk.keys[i].k0, digits[i]));
        c1 = R.add(c1, R.mul(rlk.keys[i].k1, digits[i]));
    }
    return { c0: c0, c1: c1 };
}

/**
 * The three-term product, scaled back by t/q.
 *
 * Shared by the single-prime and RNS multiplications, which differ only in
 * which modulus they hand in. The scaling has to happen on all three terms
 * with the same rounding, and separating them was how the RNS version first
 * drifted from the one it is supposed to be checked against.
 */
function tensor_and_rescale(a0, a1, b0, b1, t, q, n) {
    return [
        rescale(poly_mul_big(a0, b0, n), t, q, n),
        rescale(poly_add_big(poly_mul_big(a0, b1, n),
                             poly_mul_big(a1, b0, n), n), t, q, n),
        rescale(poly_mul_big(a1, b1, n), t, q, n)
    ];
}

/** Schoolbook over the integers, no modulus - see mul on why. */
function poly_mul_big(a, b, n) {
    var acc = new Array(2 * n);
    var i;
    for (i = 0; i < 2 * n; i++) { acc[i] = 0n; }
    for (i = 0; i < n; i++) {
        if (a[i] === 0n) { continue; }
        for (var j = 0; j < n; j++) { acc[i + j] += a[i] * b[j]; }
    }
    var o = new Array(n);
    for (i = 0; i < n; i++) { o[i] = acc[i] - acc[i + n]; }   /* X^n = -1 */
    return o;
}

function poly_add_big(a, b, n) {
    var o = new Array(n);
    for (var i = 0; i < n; i++) { o[i] = a[i] + b[i]; }
    return o;
}

/** round(t*x/q), for a signed x. */
function rescale(a, t, q, n) {
    var o = new Array(n);
    var half = q / 2n;
    for (var i = 0; i < n; i++) {
        var v = a[i] * t;
        var r = v >= 0n ? (v + half) / q : -((-v + half) / q);
        o[i] = mod(r, q);
    }
    return o;
}

/** Split each coefficient into base-w digits. */
function decompose(a, w, levels, n) {
    var out = [];
    var work = a.slice();
    for (var L = 0; L < levels; L++) {
        var d = new Array(n);
        for (var i = 0; i < n; i++) {
            d[i] = work[i] % w;
            work[i] = work[i] / w;
        }
        out.push(d);
    }
    return out;
}

/* ==================== CRT batching ==================== */

/**
 * Pack many independent values into one ciphertext, so that ONE homomorphic
 * operation performs the same arithmetic on all of them at once.
 *
 * encode_vector above already puts one value per coefficient, and that works
 * for addition: coefficients add independently. It does NOT work for
 * multiplication, because polynomial multiplication convolves the
 * coefficients - slot i of the product depends on every pair summing to i,
 * which is not what "multiply these two vectors elementwise" means.
 *
 * The Chinese Remainder Theorem gives the encoding where it does work. When
 * t = 1 mod 2n, the polynomial X^n + 1 factors completely modulo t, and the
 * ring splits into n independent copies of Z_t. Evaluating a polynomial at
 * the n roots reads out n slots; interpolating back writes them. In that
 * representation BOTH addition and multiplication are elementwise, and one
 * ciphertext operation does n of them.
 *
 * THE MODULUS HAS TO COOPERATE. t = 1 mod 2n is not a convenience: without
 * it the roots do not exist in Z_t and there is nothing to evaluate at.
 * `batching_params` finds a suitable t, and `batch_context` throws rather
 * than silently falling back to the coefficient encoding, because a caller
 * who thinks they are batching and is not gets wrong products.
 */

/**
 * Find a prime t congruent to 1 mod 2n, so the ring splits into n slots.
 *
 * `minBits` IS A BUDGET DECISION, not a convenience. t is the plaintext
 * modulus and the noise budget is roughly log2(q/t), so every bit of t is a
 * bit less room to compute in. Measured at n = 1024, q = 54 bits, one
 * ciphertext multiplication over 1024 filled slots:
 *
 *     t = 12289    (14 bits)   budget 31   works, 10 runs out of 10
 *     t = 18433    (15 bits)   budget 30   FAILS
 *     t = 1054721  (21 bits)   budget 24   FAILS
 *
 * ONE BIT SEPARATES THE FIRST TWO. And the failure is the silent kind:
 * additions stay correct, the encoding still round-trips, and only the
 * product comes out wrong - which reads as a broken implementation rather
 * than a parameter that is one bit too large.
 *
 * So ask for the smallest t the application can live with, and check
 * noise_budget after a trial multiplication rather than assuming.
 */
export function batching_modulus(n, minBits) {
    var twoN = BigInt(2 * n);
    var t = (1n << BigInt(minBits || 20)) / twoN * twoN + 1n;
    for (var i = 0; i < 100000; i++) {
        if (is_prime_small(t)) { return t; }
        t += twoN;
    }
    throw new Error('bfv: no batching modulus found');
}

/*
 * ⭐ is_prime_small WAS A HAND-WRITTEN MILLER-RABIN to the first twelve prime
 *   bases, beside commons/primes.is_probable_prime (trial division, then
 *   Baillie-PSW). Twelve fixed bases are deterministic only below
 *   318665857834031151167461 (about 2^78), the smallest number that is a
 *   strong pseudoprime to all of them - which this test accepted. Baillie-PSW
 *   has no known counterexample at any size, needs no rng with no extra
 *   rounds, and agrees with the old test on every prime this file has ever
 *   searched for: the 20 to 60-bit NTT primes are far below that bound.
 */
function is_prime_small(n) { return is_probable_prime(n); }

/**
 * Precompute the evaluation points and the interpolation.
 *
 * The slots are the odd powers of a 2n-th root of unity mod t - the roots of
 * X^n + 1. Evaluating and interpolating are an NTT and its inverse in Z_t,
 * the same transform the ciphertext ring uses, over a different modulus.
 */
export function batch_context(ctx) {
    var n = ctx.n, t = ctx.t;
    if ((t - 1n) % BigInt(2 * n) !== 0n) {
        throw new Error('bfv: t must be 1 mod 2n to batch - use batching_modulus');
    }
    /* the n roots of X^n + 1: odd powers of psi, in bit-reversed order - the
       same transform as the ciphertext ring's, over t */
    return { n: n, t: t, ntt: negacyclic(n, t, 'bfv'), slots: n };
}

/**
 * Values to a plaintext polynomial. One value per slot.
 *
 * After this, a single ciphertext multiplication multiplies every slot by its
 * counterpart - n multiplications for the price of one.
 */
export function batch_encode(bctx, values) {
    if (values.length > bctx.slots) {
        throw new Error('bfv: more values than slots');
    }
    var a = new Array(bctx.n), i;
    for (i = 0; i < bctx.n; i++) {
        a[i] = i < values.length ? mod(BigInt(values[i]), bctx.t) : 0n;
    }
    /* interpolate: the inverse transform takes slot values to coefficients */
    return bctx.ntt.inverse(a);
}

/** The inverse: coefficients back to slot values. */
export function batch_decode(bctx, poly, count) {
    return take(bctx.ntt.forward(poly),
                count === undefined ? bctx.slots : count);
}

/* ==================== RNS - the residue number system ==================== */

/**
 * Carry q as several small primes instead of one large integer.
 *
 * ==================== WHY, IN ONE MEASUREMENT ====================
 *
 *     q =  54 bits (one prime)      multiplicative depth 1
 *     q = 400 bits (eight primes)   multiplicative depth ~14
 *
 * Depth is bounded by log2(q/t), so more depth needs a bigger q - and a
 * 400-bit q held as one number makes every coefficient product a 400-bit
 * BigInt multiply, several hundred times slower than the 54-bit one that
 * fits comfortably. Holding the same q as eight 50-bit primes keeps every
 * individual operation cheap and does eight of them, which is a far better
 * trade.
 *
 * The Chinese Remainder Theorem says the two representations carry the same
 * information: a number below q is determined by its remainders modulo each
 * prime, and can be reconstructed from them.
 *
 * ==================== WHY THIS IS THE DANGEROUS PART ====================
 *
 * An incorrect NTT announces itself: 1 * x stops equalling x. An incorrect
 * RNS does not. Every operation still returns a number, the algebra still
 * looks consistent, and the error appears only for certain inputs - which is
 * the failure mode that this whole library has been finding all day.
 *
 * So the single-prime implementation above is kept, and is the ORACLE: the
 * same computation run both ways must agree exactly. That comparison is what
 * the tests do, and it is the reason the slow path was not deleted.
 */

/**
 * A chain of NTT-friendly primes whose PRODUCT exceeds 2^total_bits.
 *
 * @param {number} n           ring degree
 * @param {number} total_bits  the size of the combined modulus Q
 * @param {number} [prime_bits=50]  the size of EACH prime
 *
 * THE SECOND ARGUMENT IS THE TOTAL, NOT THE PRIME SIZE. Reading it the other
 * way round - rns_primes(1024, 50, 2) meaning "50-bit primes, two of them" -
 * asks for a Q of 50 bits built from 2-bit primes and fails with a message
 * about not finding a chain. The names say so now; they used to be `bits`
 * and `size`, which did not.
 *
 * Each prime is congruent to 1 mod 2n so the transform exists in every
 * channel, and near 2^50 so products stay where BigInt is cheap.
 */
export function rns_primes(n, total_bits, prime_bits) {
    var twoN = BigInt(2 * n);
    var each = BigInt(prime_bits || 50);
    var p = (1n << each) / twoN * twoN + 1n;
    var out = [], product = 1n;
    for (var guard = 0; guard < 200000 && product.toString(2).length < total_bits; guard++) {
        if (is_prime_small(p)) { out.push(p); product *= p; }
        p -= twoN;
    }
    if (product.toString(2).length < total_bits) {
        throw new Error('bfv: could not build a chain of ' + prime_bits +
                        '-bit primes reaching ' + total_bits + ' bits - ' +
                        'note the second argument is the TOTAL size of Q');
    }
    return out;
}

/**
 * The RNS context: one ring per prime, plus the data to reconstruct.
 */
export function rns_context(n, primes) {
    var rings = primes.map(function (p) { return ring(n, p); });
    var Q = 1n;
    var i;
    for (i = 0; i < primes.length; i++) { Q *= primes[i]; }

    /* CRT reconstruction: sum of (Q/qi) * inverse(Q/qi mod qi) * residue */
    var factors = [], inverses = [];
    for (i = 0; i < primes.length; i++) {
        var Qi = Q / primes[i];
        factors.push(Qi);
        inverses.push(powmod(mod(Qi, primes[i]), primes[i] - 2n, primes[i]));
    }
    return { n: n, primes: primes, rings: rings, Q: Q,
             factors: factors, inverses: inverses };
}

/** One polynomial mod Q into one residue polynomial per prime. */
export function rns_split(rctx, poly) {
    return rctx.primes.map(function (p) {
        var o = new Array(rctx.n);
        for (var i = 0; i < rctx.n; i++) { o[i] = mod(poly[i], p); }
        return o;
    });
}

/**
 * Residues back to a single polynomial mod Q.
 *
 * The reconstruction is exact, which is what makes the oracle comparison
 * meaningful: if the RNS path and the single-prime path disagree anywhere,
 * one of them is wrong, and there is no rounding to blame it on.
 */
export function rns_join(rctx, residues) {
    var o = new Array(rctx.n);
    for (var i = 0; i < rctx.n; i++) {
        var acc = 0n;
        for (var j = 0; j < rctx.primes.length; j++) {
            var term = mod(residues[j][i] * rctx.inverses[j], rctx.primes[j]);
            acc += term * rctx.factors[j];
        }
        o[i] = acc % rctx.Q;
    }
    return o;
}

/** Add, channel by channel. */
export function rns_add(rctx, a, b) {
    return rctx.rings.map(function (R, i) { return R.add(a[i], b[i]); });
}

export function rns_sub(rctx, a, b) {
    return rctx.rings.map(function (R, i) { return R.sub(a[i], b[i]); });
}

/**
 * Multiply, channel by channel.
 *
 * Each channel is an independent NTT over a 50-bit prime, so the cost is
 * `primes.length` cheap transforms rather than one expensive one - and the
 * transforms do not interact, which is the whole point.
 */
export function rns_mul(rctx, a, b) {
    return rctx.rings.map(function (R, i) { return R.mul(a[i], b[i]); });
}

/* ==================== BFV over RNS ==================== */

/**
 * The scheme again, with q carried as a prime chain.
 *
 * Everything above works and is limited by q being a single 54-bit prime,
 * which buys one multiplication. This path carries the same scheme over
 * several primes, so q can be hundreds of bits without any individual
 * operation leaving the range where BigInt is cheap.
 *
 * ==================== THE PART THAT IS NOT MECHANICAL ====================
 *
 * Addition and multiplication go channel by channel and need no thought:
 * the channels never interact. Two things do:
 *
 *   DECRYPTION needs the value mod Q, not per channel, because the rounding
 *   by t/Q is a statement about the whole number. So the residues are
 *   reconstructed first.
 *
 *   THE RESCALE INSIDE MULTIPLICATION is the same problem. Scaling by t/Q
 *   and rounding cannot be done independently per prime - the rounding
 *   depends on the reconstructed value. Production implementations use a
 *   fast base conversion to avoid reconstructing; this one reconstructs,
 *   which is slower and obviously correct, and the fast version can replace
 *   it later with this as its oracle.
 *
 * That is the same trade made throughout: the slow path is kept because it
 * is the only thing that can tell a fast one it is wrong.
 */

/**
 * @param {number} n
 * @param {number} qbits  total size of the ciphertext modulus
 * @param {bigint} t      plaintext modulus
 * @param {function} [rng]  n => n random bytes; omitted or null draws fresh ones from the platform
 */
export function rns_keygen(n, qbits, t, sigma, rng) {
    rng = require_rng('bfv.rns_keygen', rng);
    var primes = rns_primes(n, qbits, 50);
    var rctx = rns_context(n, primes);
    var Q = rctx.Q;

    /* the secret is one polynomial; each channel holds it reduced */
    var s = ternary(n, rng);
    var sR = rns_split(rctx, s);

    var aR = primes.map(function (p) { return uniform(n, p, rng); });
    var e = gaussian(n, sigma, rng);
    var eR = rns_split(rctx, e);

    var pk0 = rctx.rings.map(function (R, i) {
        return R.neg(R.add(R.mul(aR[i], sR[i]), eR[i]));
    });

    return {
        pk: { pk0: pk0, pk1: aR },
        sk: { s: s, sR: sR },
        ctx: { rctx: rctx, n: n, Q: Q, t: t, sigma: sigma, delta: Q / t,
               primes: primes }
    };
}

/** rng (n => n random bytes) omitted or null draws from the platform */
export function rns_encrypt(ctx, pk, plainPoly, rng) {
    rng = require_rng('bfv.rns_encrypt', rng);
    var rctx = ctx.rctx, n = ctx.n;
    var u = ternary(n, rng);
    var uR = rns_split(rctx, u);
    var e1R = rns_split(rctx, gaussian(n, ctx.sigma, rng));
    var e2R = rns_split(rctx, gaussian(n, ctx.sigma, rng));

    /* delta*m, computed mod Q then split - delta is a whole-Q quantity */
    var scaled = new Array(n);
    for (var i = 0; i < n; i++) { scaled[i] = mod(plainPoly[i] * ctx.delta, ctx.Q); }
    var scaledR = rns_split(rctx, scaled);

    return {
        c0: rctx.rings.map(function (R, j) {
            return R.add(R.add(R.mul(pk.pk0[j], uR[j]), e1R[j]), scaledR[j]);
        }),
        c1: rctx.rings.map(function (R, j) {
            return R.add(R.mul(pk.pk1[j], uR[j]), e2R[j]);
        })
    };
}

/**
 * Reconstruct, then round - see the header on why this cannot be per channel.
 */
export function rns_decrypt(ctx, sk, ct) {
    return round_to_plaintext(rns_raw(ctx, sk, ct), ctx.Q, ctx.t, ctx.n);
}

/**
 * c0 + c1*s, reconstructed mod Q.
 *
 * Both decryption and the noise measurement need this, and they must agree
 * exactly - a budget computed from a differently-reconstructed value would
 * report a number that has nothing to do with the decryption it is supposed
 * to describe.
 */
function rns_raw(ctx, sk, ct) {
    var rctx = ctx.rctx;
    return rns_join(rctx, rctx.rings.map(function (R, i) {
        return R.add(ct.c0[i], R.mul(ct.c1[i], sk.sR[i]));
    }));
}

export function rns_ct_add(ctx, a, b) {
    return {
        c0: rns_add(ctx.rctx, a.c0, b.c0),
        c1: rns_add(ctx.rctx, a.c1, b.c1)
    };
}

export function rns_ct_sub(ctx, a, b) {
    return {
        c0: rns_sub(ctx.rctx, a.c0, b.c0),
        c1: rns_sub(ctx.rctx, a.c1, b.c1)
    };
}

export function rns_mul_plain(ctx, ct, plainPoly) {
    var pR = rns_split(ctx.rctx, plainPoly);
    return {
        c0: rns_mul(ctx.rctx, ct.c0, pR),
        c1: rns_mul(ctx.rctx, ct.c1, pR)
    };
}

/** How much budget is left, in bits. See noise_budget above. */
export function rns_noise_budget(ctx, sk, ct) {
    return budget_from(rns_raw(ctx, sk, ct), rns_decrypt(ctx, sk, ct),
                       ctx.Q, ctx.t, ctx.delta, ctx.n);
}

/**
 * The relinearization key, over RNS.
 *
 * Same construction as relin_keygen: an encryption of s^2 under s, split
 * into digits so the key's own noise is not multiplied by Q. The digits are
 * base-w on the RECONSTRUCTED value rather than per channel, for the same
 * reason decryption reconstructs - a digit decomposition is a statement about
 * the whole number, and doing it per prime would decompose four unrelated
 * things.
 *
 * rng (n => n random bytes) null or omitted draws from the platform; pass
 * null to give logw.
 */
export function rns_relin_keygen(ctx, sk, rng, logw) {
    rng = require_rng('bfv.rns_relin_keygen', rng);
    var rctx = ctx.rctx;
    var lw = logw || 50;
    var w = 1n << BigInt(lw);
    var levels = Math.ceil(ctx.Q.toString(2).length / lw);

    /* s^2 mod Q, computed in RNS and reconstructed once */
    var s2R = rns_mul(rctx, sk.sR, sk.sR);
    var s2 = rns_join(rctx, s2R);

    var keys = [], wi = 1n;
    for (var i = 0; i < levels; i++) {
        var aR = ctx.primes.map(function (p) { return uniform(ctx.n, p, rng); });
        var eR = rns_split(rctx, gaussian(ctx.n, ctx.sigma, rng));

        var term = new Array(ctx.n);
        for (var j = 0; j < ctx.n; j++) { term[j] = mod(s2[j] * wi, ctx.Q); }
        var termR = rns_split(rctx, term);

        keys.push({
            k0: rctx.rings.map(function (R, c) {
                return R.add(R.neg(R.add(R.mul(aR[c], sk.sR[c]), eR[c])), termR[c]);
            }),
            k1: aR
        });
        wi = mod(wi * w, ctx.Q);
    }
    return { keys: keys, w: w, logw: lw, levels: levels };
}

/**
 * Ciphertext times ciphertext, over RNS.
 *
 * ⚠ THE TENSOR PRODUCT LEAVES RNS, and has to.
 *
 * The three-term product needs values up to Q^2 before the rescale by t/Q,
 * and the rescale is a rounding on the reconstructed number - it cannot be
 * done channel by channel, because the rounding of a sum is not the sum of
 * the roundings. Production implementations extend to an auxiliary prime
 * base and convert, which avoids ever holding Q^2; this reconstructs, which
 * is slower and obviously correct.
 *
 * That is the same choice as everywhere else in this file: the version that
 * can be checked comes first, and the fast one can replace it later with
 * this as the thing it is checked against.
 */
export function rns_mul_ct(ctx, rlk, a, b) {
    var rctx = ctx.rctx, n = ctx.n, Q = ctx.Q, t = ctx.t;

    /* out of RNS, because the tensor product exceeds any single channel */
    var a0 = rns_join(rctx, a.c0), a1 = rns_join(rctx, a.c1);
    var b0 = rns_join(rctx, b.c0), b1 = rns_join(rctx, b.c1);

    /* centre before multiplying: these are signed quantities, and treating
       them as unsigned squares the wrong number */
    a0 = centre(a0, Q, n); a1 = centre(a1, Q, n);
    b0 = centre(b0, Q, n); b1 = centre(b1, Q, n);

    var d = tensor_and_rescale(a0, a1, b0, b1, t, Q, n);
    var d0 = d[0], d1 = d[1], d2 = d[2];

    /* fold s^2 back in, digit by digit, and return to RNS */
    var digits = decompose(d2, rlk.w, rlk.levels, n);
    var c0 = rns_split(rctx, d0), c1 = rns_split(rctx, d1);
    for (var i = 0; i < rlk.levels; i++) {
        var dR = rns_split(rctx, digits[i]);
        c0 = rns_add(rctx, c0, rns_mul(rctx, rlk.keys[i].k0, dR));
        c1 = rns_add(rctx, c1, rns_mul(rctx, rlk.keys[i].k1, dR));
    }
    return { c0: c0, c1: c1 };
}

/** Map [0,Q) onto (-Q/2, Q/2]. */
function centre(a, Q, n) {
    var half = Q / 2n, o = new Array(n);
    for (var i = 0; i < n; i++) { o[i] = a[i] > half ? a[i] - Q : a[i]; }
    return o;
}
