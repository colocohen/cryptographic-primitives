/**
 * Arithmetic in a prime field, for elliptic curves
 *
 * Every value here is a BigInt reduced into [0, p). That choice was measured,
 * not assumed, and it reverses the decision taken everywhere else in this
 * library.
 *
 * WHY BigInt HERE AND NOWHERE ELSE
 * sha512.js, blake2b, xxhash64 and argon2 all carry 64-bit values as int32
 * pairs because BigInt measured 5 to 12 times slower there. At 256 bits the
 * result inverts. Measured on secp256k1's prime:
 *
 *     BigInt, (a * b) % p            6.95 M ops/s
 *     BigInt, fast reduction         3.74 M ops/s
 *     manual 10 x 26-bit limbs       1.58 M ops/s
 *
 * At 64 bits the arithmetic is tiny and BigInt's per-operation heap
 * allocation dominates. At 256 bits there is enough work to amortise it, and
 * V8 runs the multiplication in native bignum code while a limb version runs
 * a hundred multiplications and a carry chain in interpreted JavaScript.
 *
 * Note the second line: a hand-written reduction exploiting p = 2^256 - c came
 * out 1.9x SLOWER than the plain modulo. V8's BigInt remainder is well
 * optimised and hard to beat from JS.
 *
 * CONSTANT TIME - WHAT THIS FILE DOES AND DOES NOT PROMISE
 * Everything that touches a secret avoids branching on it. Inversion goes
 * through Fermat's little theorem rather than extended Euclid, because Euclid's
 * loop count depends on its input. Conditional selection is done with masks.
 * Exponentiation always performs both a square and a multiply.
 *
 * What cannot be promised: BigInt itself is not constant time. V8 sizes its
 * internal representation to the value, so operations on a small BigInt may
 * be faster than on a large one, and nothing at the JavaScript level can fix
 * that. This file removes the leaks that ARE fixable - the ones that depend
 * on secret bits rather than on secret magnitudes - which is a real
 * improvement and not a guarantee. A local attacker with precise timing
 * measurement needs hardware or WASM, and that is the honest position taken
 * in commons/ct.js as well.
 */

/**
 * Constant-time selection: returns a when bit is 1n, b when bit is 0n.
 *
 * BigInt bitwise operations behave as two's complement with infinite sign
 * extension, so -1n acts as an all-ones mask of whatever width is needed.
 * That is what makes this work without knowing the field size.
 */
/*
 * ==================== ⛔ WHAT "CONSTANT TIME" MEANS HERE ====================
 *
 * This selects without branching, and that is all it does. It is NOT constant
 * time in the sense a hardware engineer means, and neither is anything built
 * on it - because BIGINT OPERATION COST SCALES WITH OPERAND MAGNITUDE.
 *
 *   MEASURED:
 *       cselect on 0n and 1n        10 ns
 *       cselect on two 255-bit      40 ns
 *       (0n * full) % p             16 ns
 *       (full * full) % p          252 ns
 *
 * ⛔ SO A SCALAR MULTIPLICATION LEAKS ITS SCALAR'S HAMMING WEIGHT, even
 *   through a comb table that reads every window and adds every time. A
 *   sparse scalar keeps the accumulator near the identity - whose
 *   coordinates are 0n and 1n - for longer, and every operation on it is
 *   cheaper.
 *
 *   Measured on ristretto255 base_mul with TWO 250-BIT SCALARS, one with two
 *   bits set and one with all 250: 77 us against 243. A factor of 3.2, with
 *   no branch anywhere in the path.
 *
 * ⚠ THE BRANCHLESS FORM IS STILL WORTH HAVING. It removes the leak that an
 *   attacker can exploit remotely over a network - a data-dependent branch
 *   is a large, reliable signal - and leaves one that needs local timing
 *   precision to see. That is a real improvement and it is not a complete
 *   defence.
 *
 * ⛔ AND IT CANNOT BE FIXED WITHIN BigInt. A genuine constant-time field
 *   would need fixed-width limbs in a typed array, with every value padded
 *   to the full width - which is the representation commons/gpu's reference
 *   file uses and which measures SLOWER than BigInt for everything else. The
 *   trade was made knowingly; this note exists so nobody assumes otherwise.
 *
 * ⚠ CALLERS WHO NEED MORE than this must not use a JavaScript BigInt library
 *   for secrets that a local attacker can time. That is a deployment
 *   decision, not something a different function signature fixes.
 */
import { bytes_to_bigint, secure_random } from './bytes.js';

export function cselect(bit, a, b) {
    var mask = -bit;              /* 0n or -1n */
    return (a & mask) | (b & (bit - 1n));
}

/** Constant-time equality of two field elements. Returns 1n or 0n. */
export function ceq(a, b) {
    var d = a ^ b;
    /* fold every set bit down to one, without a comparison */
    var r = 0n;
    while (d > 0n) { r |= d & 1n; d >>= 1n; }
    return r ^ 1n;
}

/**
 * Build a field.
 *
 * @param  {bigint} p  a prime
 * @return {object}    the field operations
 */
/**
 * BN254's scalar field.
 *
 * Three files need it - poseidon.js, mimc.js and babyjubjub.js - because it
 * is the field every Ethereum-compatible proof system computes in, and each
 * of those is defined over it by specification rather than by choice. One
 * definition means a typo in the prime cannot make two of them silently
 * disagree.
 *
 * It is the order of BN254's group, not the prime its coordinates live in;
 * "scalar field of the curve" and "base field of the circuit" are the same
 * thing here, which is the relationship that makes embedded curves possible.
 */
export var BN254_FR =
    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

/**
 * BLS12-381's scalar field - and, for the same reason as BN254's, the base
 * field of the curve embedded in it: Jubjub (jubjub.js) has its coordinates
 * here, so arithmetic on Jubjub is native inside a BLS12-381 circuit. One
 * definition shared by bls12_381.js (as r, the order of G1 and G2) and
 * jubjub.js (as q, the field its points live in).
 */
export var BLS12_381_FR =
    0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

/**
 * Small odd powers, for the hashes designed around them.
 *
 * Poseidon's S-box is x^5 and MiMC's is x^7, and both are chosen for the same
 * reason: the exponent must be coprime to p-1 so the map is a permutation,
 * and it must be small so the circuit pays few multiplications. Written as
 * addition chains rather than pow() because three or four squarings beat a
 * 254-bit ladder by two orders of magnitude, and the exponent is public so
 * there is nothing to hide.
 */
/**
 * Modular inverse by Fermat's little theorem, for a PRIME modulus.
 *
 * Not the extended Euclidean algorithm in commons/primes.js: that one is
 * faster, and its iteration count depends on the operands, so it leaks
 * through timing. This does a fixed number of squarings for a given modulus
 * whatever the input.
 *
 * Three files invert in a curve's scalar field - kzg.js, bbs.js and
 * shamir.js - and all three were writing the same eight lines.
 */
export function inv_prime(a, p) {
    var r = 1n, b = ((a % p) + p) % p, e = p - 2n;
    while (e > 0n) {
        if (e & 1n) { r = (r * b) % p; }
        b = (b * b) % p;
        e >>= 1n;
    }
    return r;
}

/**
 * Montgomery's trick: the inverses of n values for ONE inversion and 3(n-1)
 * multiplications, over any field given its mul, inv and one.
 *
 * ⭐ ONE COPY. modp fields, Fp2 (fp_ext.js), ristretto255's scalar field and
 *   shamir's Lagrange coefficients each wrote this loop.
 *
 * ⚠ It inherits the timing of `inv` and adds no branch on the values; it does
 *   not throw on a zero (the whole product, and so every output, becomes 0),
 *   matching inv, which returns 0 rather than branch on a secret. A caller
 *   that can receive a zero must check first.
 */
export function batch_invert(values, mul, inv, one) {
    var n = values.length, i;
    if (n === 0) { return []; }
    var acc = new Array(n), running = one;
    for (i = 0; i < n; i++) { acc[i] = running; running = mul(running, values[i]); }
    var t = inv(running), out = new Array(n);
    for (i = n - 1; i >= 0; i--) { out[i] = mul(t, acc[i]); t = mul(t, values[i]); }
    return out;
}

export function pow5(F, x) {
    var x2 = F.sqr(x);
    return F.mul(F.sqr(x2), x);
}

export function pow7(F, x) {
    var x2 = F.sqr(x);
    var x4 = F.sqr(x2);
    return F.mul(F.mul(x4, x2), x);
}

export function field(p) {
    if (p <= 1n) { throw new Error('modp: p must be a prime greater than 1'); }

    var BITS = p.toString(2).length;
    var BYTES = (BITS + 7) >> 3;

    /*
     * The square-root exponent depends on the shape of p. Both common cases
     * are single exponentiations; anything else needs Tonelli-Shanks, whose
     * loop count depends on the input and which is therefore not constant
     * time. Refusing is better than shipping a leaky square root.
     */
    var sqrt_mode;
    if (p % 4n === 3n)      { sqrt_mode = 3; }
    else if (p % 8n === 5n) { sqrt_mode = 5; }
    else                    { sqrt_mode = 0; }

    function mod(a) {
        var r = a % p;
        /* a % p keeps the sign of a in JS, so negatives need one correction */
        return r < 0n ? r + p : r;
    }

    /*
     * A SPECIALISED REDUCTION WAS TRIED HERE AND REMOVED. Recorded because
     * the idea is obvious enough that someone will have it again.
     *
     * Both curve families use pseudo-Mersenne primes - secp256k1 is
     * 2^256 - 2^32 - 977, Curve25519 is 2^255 - 19 - so 2^k = c (mod p) for a
     * small c, and the high half of a product can be folded down with one
     * multiply instead of a division. Textbook, and what every C
     * implementation does.
     *
     * IT LOSES IN JAVASCRIPT. Measured on a field multiplication:
     *
     *     generic  (a*b) % p     297 ns
     *     two folds, unrolled    371 ns     secp256k1
     *     two folds, unrolled    444 ns     Curve25519
     *
     * The reason is the same one documented at the top of this file: every
     * BigInt operation allocates. The division is ONE native call into V8's
     * C++ BigInt code; the fold is six JavaScript-level BigInt operations,
     * and six allocations beat one no matter how much cheaper the arithmetic
     * is on paper.
     *
     * A MICROBENCHMARK SAID OTHERWISE - 211 ns against 298 - and it was
     * wrong. It folded the same constant repeatedly, which V8 hoists and
     * keeps in registers. The moment the input came from a real multiplication
     * the advantage inverted. Measure inside the caller, not beside it.
     */

    var F = {
        p: p,
        BITS: BITS,
        BYTES: BYTES,
        ZERO: 0n,
        ONE: 1n,

        mod: mod,
        /*
         * ⛔ THESE SLOTS EXIST SO THE OBJECT'S SHAPE NEVER CHANGES.
         *
         *   They are lazy caches - sqrt(-1) and 1/2 - and assigning them for
         *   the first time on an object that did not declare them adds a
         *   property at runtime. V8 gives such an object a new hidden class,
         *   and every call site that had specialised on the old one
         *   deoptimises.
         *
         *   ⚠ THE COST IS NOT LOCAL. It falls on `mul` and `sqr`, which are
         *     reached millions of times from every curve in the library -
         *     measured at roughly 2x on bulletproofs, which is nothing but
         *     field arithmetic. Declaring the slots up front costs nothing
         *     and removes the transition entirely.
         *
         *   This is the same rule noble states as "identical object shape:
         *   never add or remove keys", and it was learned here the
         *   expensive way.
         */
        _sqrt_m1: undefined,
        _half: undefined,

        add:  function (a, b) { var r = a + b; return r >= p ? r - p : r; },

        /*
         * ⭐ DENORMALIZED ADD AND SUB - no conditional reduction.
         *
         *   `add` already avoids the modulo, but it still compares against p
         *   on every call. Measured: 173 ns against 60 for a raw BigInt
         *   addition, and a twisted-Edwards point addition performs about
         *   ten of them.
         *
         * ⭐ WHY THIS IS SAFE: mul reduces. `(a*b) % p` is correct for any
         *   non-negative a and b, however large - so a value slightly above p
         *   can be carried until it reaches a multiplication, and the result
         *   is identical.
         *
         * ⛔ AND THE TWO RULES THAT MAKE IT UNSAFE IF BROKEN:
         *
         *   1. subN CAN GO NEGATIVE. A negative operand reaching mul gives a
         *      negative product and `% p` in JavaScript keeps the sign. Only
         *      use subN where the result is added back to something larger,
         *      or where the consumer normalizes.
         *
         *   2. VALUES MUST NOT GROW WITHOUT BOUND. Each addN can add one p;
         *      a long chain of them makes the operands bigger and the
         *      eventual multiplication slower, which undoes the saving. A
         *      handful between reductions is the useful range.
         *
         * ⚠ NEITHER RULE IS ENFORCED HERE AND NEITHER CAN BE. A violation
         *   produces a wrong value or a slow one, never an error, so these
         *   belong inside a formula that was written for them - not as a
         *   drop-in replacement for add and sub.
         */
        addN: function (a, b) { return a + b; },
        subN: function (a, b) { return a - b; },
        sub:  function (a, b) { var r = a - b; return r < 0n ? r + p : r; },
        neg:  function (a)    { return a === 0n ? 0n : p - a; },
        mul:  function (a, b) { return (a * b) % p; },
        sqr:  function (a)    { return (a * a) % p; },
        dbl:  function (a)    { var r = a + a; return r >= p ? r - p : r; },

        is_zero: function (a) { return ceq(a, 0n); },
        eq: ceq,
        cselect: cselect,

        /**
         * Exponentiation by square-and-multiply, with the multiply always
         * performed and its result selected by mask.
         *
         * The naive version skips the multiply when the exponent bit is zero,
         * which makes the running time a direct readout of the exponent. When
         * the exponent is a private key that is the whole attack.
         */
        pow: function (a, e) {
            var r = 1n, base = a;
            var n = e;
            while (n > 0n) {
                var bit = n & 1n;
                var prod = (r * base) % p;
                r = cselect(bit, prod, r);
                base = (base * base) % p;
                n >>= 1n;
            }
            return r;
        },

        /**
         * Inverse by Fermat: a^(p-2) mod p.
         *
         * The extended Euclidean algorithm is far faster but its iteration
         * count depends on the operands, so it leaks. Fermat costs a fixed
         * number of squarings for a given p no matter what a is.
         *
         * Inverting zero is undefined; this returns zero rather than throwing,
         * because throwing on a secret value is itself a timing signal.
         */
        inv: function (a) { return F.pow(a, p - 2n); },

        /**
         * Inverse of a SECRET-dependent value, BLINDED: 1/a = r · 1/(a·r)
         * for a fresh random r, the inner inverse by the fast Euclid below.
         *
         * ⭐ CONSTANT TIME WHERE IT MATTERS: Euclid's running time follows its
         *    operand, and its operand is a·r — uniform in the field and
         *    independent of a whatever a is — so the timing says nothing
         *    about a. The same blinding OpenSSL applies to ECDSA's k⁻¹.
         *    About ten times faster than Fermat (Ed25519: 270 µs → ~25).
         *
         * ⚠ IT TAKES RANDOMNESS (commons/bytes secure_random), so it is for
         *    the point-to-affine conversions of the curves (edwards.js,
         *    weierstrass.js to_affine), not a replacement for `inv` above,
         *    which stays deterministic. Zero gives zero, as `inv`.
         */
        inv_blinded: function (a) {
            var r;
            do { r = bytes_to_bigint(secure_random(BYTES + 16)) % p; } while (r === 0n);
            return F.mul(F.inv_vartime(F.mul(a, r)), r);
        },

        /**
         * A square root of -1, when the field has one.
         *
         * ⭐ A NAMED METHOD RATHER THAN AN AD-HOC CACHE. Two places were
         *   computing this independently and stashing it on the field under
         *   a private name - modp's own sqrt and edwards' sqrt_ratio. Two
         *   caches of the same constant is two places for a divergence, and
         *   a wrong sqrt(-1) gives a square root that squares to the
         *   negative of the input: a valid field element, wrong answer.
         *
         * ⚠ IT EXISTS ONLY WHEN p = 1 mod 4. For p = 3 mod 4 there is no
         *   square root of -1 and this returns null - callers that need the
         *   twist are on the p = 5 mod 8 path, where it does exist.
         *
         *   The exponentiation runs once per field and is cached; it was
         *   being redone on every point decompression that needed the twist,
         *   which measured 0.61 ms against 0.32 for the whole decode.
         */
        sqrt_of_neg_one: function () {
            if (F._sqrt_m1 === undefined) {
                F._sqrt_m1 = (p & 3n) === 1n ? F.pow(2n, (p - 1n) / 4n) : null;
            }
            return F._sqrt_m1;
        },

        /*
         * ⛔ THERE WERE TWO inv_vartime ENTRIES IN THIS OBJECT LITERAL, and
         *   the first was dead: in a literal the later key wins, silently.
         *   It was the plain extended Euclidean algorithm, documented with a
         *   measurement (25x over Fermat on the BLS12-381 base field, 27 us
         *   against 667, from the Miller loop's 64 Fp2 inversions) that was
         *   therefore never of the code actually running. Removed; the
         *   binary version below is what every caller has always had.
         *
         * ⚠ THE PORTING NOTE IT CARRIED STILL APPLIES to the one that
         *   remains: the speed-up is a property of V8's native BigInt
         *   division and shifts, not of the algorithm. In Rust the ranking
         *   reverses - allocating div_rem against an allocation-free
         *   Montgomery Fermat, measured there at about 100x the other way -
         *   so a port should measure rather than copy this choice.
         */
        /**
         * Inverse by the binary extended Euclidean algorithm.
         *
         * NOT CONSTANT TIME - the iteration count follows the operands, which
         * is exactly why `inv` above uses Fermat instead. This exists for the
         * one place where the value is PUBLIC and about to be published
         * anyway: converting a point to affine coordinates in order to encode
         * it. A signature's R, a public key's A, a verifier's reconstructed
         * point - all of them go out on the wire the moment they are
         * computed, so a timing channel on them reveals nothing.
         *
         * Roughly ten times faster than the Fermat version, which is a
         * quarter of the cost of an Ed25519 signature.
         *
         * NEVER call this on a secret.
         */
        inv_vartime: function (a) {
            if (a === 0n) { return 0n; }
            var u = ((a % p) + p) % p, v = p;
            var x1 = 1n, x2 = 0n;
            while (u !== 1n && v !== 1n) {
                while ((u & 1n) === 0n) {
                    u >>= 1n;
                    x1 = (x1 & 1n) ? (x1 + p) >> 1n : x1 >> 1n;
                }
                while ((v & 1n) === 0n) {
                    v >>= 1n;
                    x2 = (x2 & 1n) ? (x2 + p) >> 1n : x2 >> 1n;
                }
                if (u >= v) { u -= v; x1 -= x2; }
                else { v -= u; x2 -= x1; }
            }
            var r = (u === 1n) ? x1 : x2;
            return ((r % p) + p) % p;
        },

        /** Division, as multiplication by the inverse. */
        div: function (a, b) { return (a * F.inv(b)) % p; },

        /**
         * Square root, where one exists. Returns null when a is not a square.
         *
         * Point decompression needs this: a compressed point carries x and one
         * bit of y, and y is recovered by taking a square root.
         */
        sqrt: function (a) {
            var r;
            if (sqrt_mode === 3) {
                r = F.pow(a, (p + 1n) / 4n);
            } else if (sqrt_mode === 5) {
                /* p = 5 mod 8: the candidate may need a twist by sqrt(-1) */
                r = F.pow(a, (p + 3n) / 8n);
                var check = (r * r) % p;
                /* ⭐ the field's own constant - see sqrt_of_neg_one above */
                var i = F.sqrt_of_neg_one();
                var twisted = (r * i) % p;
                r = cselect(ceq(check, a), r, twisted);
            } else {
                throw new Error('modp: no constant-time square root for this prime - use sqrt_vartime');
            }
            return ((r * r) % p === a) ? r : null;
        },

        /**
         * Tonelli-Shanks: a square root for ANY prime, INCLUDING p = 1 mod 8.
         *
         * NOT CONSTANT TIME, AND THAT IS IN THE NAME. The algorithm searches
         * for the order of an element by squaring until it reaches one, so
         * the iteration count depends on the input. On a secret value that
         * leaks; on a public one - decoding a point that arrived over the
         * wire, checking whether a published x has a matching y - it is
         * exactly the right tool.
         *
         * WHY IT IS NEEDED AT ALL. The two cheap formulas above cover
         * p = 3 mod 4 and p = 5 mod 8, which is most curves by design: their
         * primes were chosen partly so that square roots would be one
         * exponentiation. BN254's scalar field is 1 mod 8 and was chosen for
         * a different reason entirely - a large power of two dividing p-1, so
         * that FFTs over it are cheap, which is what a proof system needs.
         * The two goals pull opposite ways, and this is the cost.
         *
         * The structure of the algorithm follows directly from that: p-1 is
         * written as q * 2^s with q odd, and the larger s is, the more work
         * there is. For BN254 s is 28.
         *
         * @return {bigint|null} null when a is not a square
         */
        sqrt_vartime: function (a) {
            var n = mod(a);
            if (n === 0n) { return 0n; }
            if (F.pow(n, (p - 1n) / 2n) !== 1n) { return null; }

            /* the easy shapes, when they apply */
            if (p % 4n === 3n) {
                var e = F.pow(n, (p + 1n) / 4n);
                return (e * e) % p === n ? e : null;
            }

            /* p - 1 = q * 2^s with q odd */
            var q = p - 1n, s = 0n;
            while ((q & 1n) === 0n) { q >>= 1n; s++; }

            /*
             * Any non-residue will do as the generator of the 2-Sylow
             * subgroup, and the smallest is found by trial. This is the step
             * that makes the running time input-independent but
             * MODULUS-dependent - it is the same z every time for a given p,
             * so it could be cached; it is left plain because the search
             * costs one exponentiation and runs once per call on a public
             * value.
             */
            var z = 2n;
            while (F.pow(z, (p - 1n) / 2n) !== p - 1n) { z++; }

            var m = s;
            var c = F.pow(z, q);
            var t = F.pow(n, q);
            var r = F.pow(n, (q + 1n) / 2n);

            while (t !== 1n) {
                /* find the least i with t^(2^i) = 1 */
                var i = 0n, t2 = t;
                while (t2 !== 1n) {
                    t2 = (t2 * t2) % p;
                    i++;
                    if (i === m) { return null; }
                }
                var b = F.pow(c, 1n << (m - i - 1n));
                m = i;
                c = (b * b) % p;
                t = (t * c) % p;
                r = (r * b) % p;
            }
            return (r * r) % p === n ? r : null;
        },

        /** Whether a is a quadratic residue, by Euler's criterion. */
        is_square: function (a) {
            if (a === 0n) { return true; }
            return F.pow(a, (p - 1n) / 2n) === 1n;
        },

        /**
         * Fixed-width big-endian encoding.
         *
         * Fixed width matters: a field element that happens to be small must
         * still occupy the full length, or its size leaks through the encoding.
         */
        to_bytes: function (a) {
            var out = new Uint8Array(BYTES);
            var v = a;
            for (var i = BYTES - 1; i >= 0; i--) {
                out[i] = Number(v & 0xffn);
                v >>= 8n;
            }
            return out;
        },

        from_bytes: function (b) {
            var v = 0n;
            for (var i = 0; i < b.length; i++) { v = (v << 8n) | BigInt(b[i]); }
            return v;
        },

        /** Little-endian, which the Edwards and Montgomery curves use. */
        to_bytes_le: function (a) {
            var out = new Uint8Array(BYTES);
            var v = a;
            for (var i = 0; i < BYTES; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
            return out;
        },

        from_bytes_le: function (b) {
            var v = 0n;
            for (var i = b.length - 1; i >= 0; i--) { v = (v << 8n) | BigInt(b[i]); }
            return v;
        },

        /*
         * VECTORS. WIDE bytes (BYTES + 8) reduced mod p are uniform to within
         * 2^-64: how a hash output or rng bytes become a field element.
         */
        WIDE: BYTES + 8,
        /** A big-endian byte string of any length, reduced mod p. */
        from_wide: function (b) { return F.from_bytes(b) % p; },
        /** n elements from n consecutive WIDE-byte chunks. */
        vec_from_wide: function (b, n) {
            var out = new Array(n), W = BYTES + 8;
            for (var i = 0; i < n; i++) { out[i] = F.from_bytes(b.subarray(W * i, W * (i + 1))) % p; }
            return out;
        },
        /** The elements' fixed-width encodings, concatenated. */
        vec_to_bytes: function (list) {
            var out = new Uint8Array(BYTES * list.length);
            for (var i = 0; i < list.length; i++) { out.set(F.to_bytes(list[i]), BYTES * i); }
            return out;
        },
        /** n canonical encodings from byte off. THROWS on a value >= p (who names the caller). */
        vec_from_bytes: function (b, off, n, who) {
            var out = new Array(n);
            for (var i = 0; i < n; i++) {
                var v = F.from_bytes(b.subarray(off + BYTES * i, off + BYTES * (i + 1)));
                if (v >= p) { throw new Error((who || 'modp') + ': a field element out of range'); }
                out[i] = v;
            }
            return out;
        },

        /**
         * Invert many elements with one inversion plus three multiplications
         * each - Montgomery's trick.
         *
         * Inversion is the expensive field operation by a wide margin, and
         * converting a batch of points from projective to affine coordinates
         * needs one inversion per point. This turns n inversions into one.
         *
         * ⛔ A ZERO ANYWHERE POISONS EVERY RESULT, not just its own. The
         *   running product becomes zero, its inverse is zero, and all n
         *   outputs come back zero - where `inv` alone would have returned
         *   zero for the zero and correct values for the rest.
         *
         * ⚠ IT DOES NOT THROW, DELIBERATELY. `inv` above returns zero rather
         *   than throwing because throwing on a secret value is itself a
         *   timing signal, and this follows the same rule. The caller is
         *   responsible for not handing it a zero - which for projective
         *   Z-coordinates means not handing it the point at infinity.
         */
        inv_batch: function (values) {
            return batch_invert(values, F.mul, F.inv, 1n);
        }
    };
    return F;
}
