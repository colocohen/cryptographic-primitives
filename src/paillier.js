/**
 * Paillier  -  additively homomorphic public-key encryption (1999)
 *
 * Ciphertexts can be ADDED without decrypting them:
 *
 *     E(a) * E(b) = E(a + b)
 *     E(a)^k      = E(a * k)
 *
 * Multiplying two ciphertexts produces an encryption of the SUM. Nobody
 * holding the public key learns a, b or the total; the holder of the private
 * key decrypts the result and sees only a+b.
 *
 * HOW THIS DIFFERS FROM PEDERSEN, which this library already has. A Pedersen
 * commitment is also additively homomorphic, but it CANNOT BE OPENED without
 * knowing the value and the blinding factor - it commits, it does not
 * encrypt. Paillier decrypts: the private key recovers the plaintext from the
 * ciphertext alone. That is the difference between "prove the totals match"
 * and "compute the total and read it".
 *
 * WHAT IT MAKES POSSIBLE:
 *
 *   - VOTING THAT COUNTS ITSELF. Each voter encrypts 0 or 1; the server
 *     multiplies every ciphertext together and decrypts once. It learns the
 *     tally and nothing else - not one individual vote, ever.
 *   - STATISTICS OVER ENCRYPTED DATA. Sum salaries, count matches, average a
 *     column, with the data never in the clear on the server.
 *   - THE MULTIPLICATIVE-TO-ADDITIVE CONVERSION at the heart of threshold
 *     ECDSA. GG18 and its successors need two parties holding a and b to end
 *     up holding x and y with x+y = a*b, and Paillier is how that is done.
 *
 * ============================= THE SECURITY MODEL =============================
 *
 * SEMANTIC SECURITY ONLY. Paillier is IND-CPA: an eavesdropper learns nothing
 * from a ciphertext. It is NOT IND-CCA2, and it CANNOT BE - the homomorphism
 * is a malleability, and malleability is exactly what CCA2 forbids. Anyone
 * can take E(a) and produce E(a+5) without the key.
 *
 * That is a feature here and a hazard everywhere else. A protocol using
 * Paillier must assume ciphertexts can be transformed in flight and defend
 * against it separately - with signatures, with zero-knowledge proofs that
 * the transformation was the agreed one, or by not letting an adversary see
 * the decryption. THE ATTACKS ON GG18 IN 2021 WERE EXACTLY THIS: not a break
 * of Paillier, but missing range proofs around it.
 *
 * A DECRYPTION ORACLE BREAKS IT COMPLETELY. If an adversary can submit
 * ciphertexts and observe whether decryption succeeded or what it produced,
 * they recover the key. Never decrypt attacker-chosen ciphertexts and reveal
 * anything about the outcome.
 * =============================================================================
 *
 * PERFORMANCE. Everything happens modulo n^2, so a 2048-bit key does 4096-bit
 * arithmetic. Encryption is two exponentiations and decryption one; expect
 * this to be roughly an order of magnitude slower than RSA at the same
 * security level. That is the price of the homomorphism.
 */

import { random_prime_task, safe_prime_task, prime_pair_task, mod_inverse, powmod_ct, powmod, mod, gcd,
         random_unit, require_rng } from './commons/primes.js';
import { finish_task, map_task, done_task } from './commons/task.js';

/**
 * Generate a key pair.
 *
 * THE TWO PRIMES MUST BE THE SAME LENGTH, and the implementation checks it.
 * With p and q of different sizes the modulus can be factored more easily,
 * and the simplified decryption below additionally requires
 * gcd(pq, (p-1)(q-1)) = 1, which equal-length distinct primes give.
 *
 * @param  {number}   bits  of the modulus n; 2048 is the practical minimum,
 *                          3072 for anything long-lived
 * @param  {function} [rng]  omitted or null draws fresh ones from the platform
 * @return {{pk: object, sk: object}}
 */
/**
 * @param {number}   bits
 * @param {function} [rng]  omitted or null draws fresh ones from the platform
 * @param {object}   [opts]
 *   blum {boolean}  require p = q = 3 (mod 4) - a Paillier-BLUM modulus
 *
 * ON `blum`. CGGMP21 needs it, and needs it specifically: its modulus proof
 * is a statement that N is a product of two primes congruent to 3 mod 4, and
 * a key generated without the constraint cannot satisfy the proof the
 * protocol requires of it. There was no way to ask for such a key, which made
 * ring_pedersen's prove_modulus unusable against anything paillier.keygen
 * produced.
 *
 * It is not the default because ordinary Paillier does not need it and the
 * search runs about twice as many candidates - half of all odd primes are
 * 1 mod 4 and get discarded.
 *
 * ON `safe`, AND WHY CGGMP21 NEEDS IT RATHER THAN JUST `blum`.
 *
 * The paper's auxiliary-data generation requires SAFE primes for each
 * signer's Paillier modulus, not only for the Ring-Pedersen parameters -
 * every implementation of the paper says so in as many words, and the reason is
 * that the Ring-Pedersen proofs are made against the same modulus.
 *
 * A safe prime is automatically Blum: p = 2q + 1 with q an odd prime makes
 * p = 3 (mod 4). So `safe` implies `blum` and the reverse does not hold.
 *
 * IT COSTS ABOUT A THOUSAND TIMES MORE. Measured at 512 bits: 15 ms for a
 * Blum prime, 685 ms for a safe one; at 1024 bits a safe prime takes around
 * 37 seconds. Setup for one party is minutes, and almost all of it is this
 * search - which is why `onCandidate` exists and why the search is worth
 * running ahead of time rather than inside key generation.
 */
/**
 * Build the key pair from two primes, or null if they are unusable.
 *
 * Lifted out of the search loop so a caller who found the primes elsewhere -
 * yielding between candidates, which the loop below cannot do - gets the
 * same construction rather than a second copy of it.
 */
function assemble(p, q, bits) {
    if (p === q) { return null; }
    var n = p * q;
    var lambda = (p - 1n) * (q - 1n) / gcd(p - 1n, q - 1n);   /* lcm */
    /*
     * The requirement that makes decryption work. It holds for almost all
     * equal-length prime pairs, and checking is cheaper than reasoning about
     * when it does not.
     */
    if (gcd(n, (p - 1n) * (q - 1n)) !== 1n) { return null; }

    var n2 = n * n;
    /*
     * g = n + 1 is the standard choice. It makes (1+n)^m = 1 + m*n (mod n^2)
     * by the binomial theorem - every higher term carries n^2 - so the L
     * function recovers m directly and no discrete log is needed.
     */
    var g = n + 1n;
    /* mu = (L(g^lambda mod n^2))^-1 mod n, precomputed for decryption */
    /* ⛔ secret exponent - see powmod_ct in commons/primes.js */
    /* lambda = lcm(p-1, q-1) is Paillier's trapdoor; leaking it factors n */
    var x = powmod_ct(g, lambda, n2);
    var lx = (x - 1n) / n;
    var mu = mod_inverse(lx % n, n);
    if (mu === null) { return null; }

    return {
        pk: { n: n, n2: n2, g: g, bits: bits },
        sk: { n: n, n2: n2, lambda: lambda, mu: mu, p: p, q: q }
    };
}

export function keygen(bits, rng, opts) {
    return finish_task(keygen_task(bits, rng, opts));
}

/**
 * keygen as a task (commons/task.js): a step is one prime candidate, so the
 * callback form runs it in slices - keygen(2048) holds the thread about
 * 860 ms in one piece, and with safe primes, seconds to minutes.
 */
export function keygen_task(bits, rng, opts) {
    if (bits < 512) { throw new Error('paillier: modulus must be at least 512 bits'); }
    rng = require_rng('paillier.keygen', rng);
    var half = bits >> 1;
    var wantSafe = !!(opts && opts.safe);
    var mod4 = (opts && (opts.blum || opts.safe)) ? 3 : undefined;
    var onCandidate = opts && opts.onCandidate;

    /*
     * `opts.primes` LETS A CALLER SUPPLY THE PRIMES.
     *
     * The search is the whole cost - eighteen seconds at 1024 bits with safe
     * primes, minutes at 2048 - and it is a blocking loop. A caller that
     * needs the event loop back does the search elsewhere, yielding between
     * candidates, and hands the result in. See material.js.
     *
     * They are checked rather than trusted: two equal primes make n a
     * perfect square whose factorisation is a square root.
     */
    if (opts && opts.primes) {
        var sp = opts.primes;
        if (sp.length !== 2 || sp[0] === sp[1]) {
            throw new Error('paillier: primes must be two distinct values');
        }
        var built = assemble(sp[0], sp[1], bits);
        if (built === null) { throw new Error('paillier: supplied primes are unusable'); }
        return done_task(built);
    }

    /*
     * ⭐ assemble, not a copy of it. This loop used to hold the whole
     *   construction a second time - lambda, the gcd condition, g, mu -
     *   line for line the same as assemble() above. A refusal (equal primes,
     *   gcd(n, phi) != 1, no mu) means a fresh pair (prime_pair_task).
     */
    return prime_pair_task(
        function () {
            return wantSafe ? map_task(safe_prime_task(half, rng, onCandidate), function (r) { return r.p; })
                            : random_prime_task(half, rng, undefined, mod4);
        },
        function (p, q) { return assemble(p, q, bits); },
        100, 'paillier: key generation failed');
}

/** The public half of a private key, for handing out. */
export function public_key(sk) {
    return { n: sk.n, n2: sk.n2, g: sk.n + 1n, bits: sk.n.toString(2).length };
}

/*
 * THE ENCRYPTION RANDOMISER r MUST BE COPRIME TO n AND FRESH FOR EVERY
 * ENCRYPTION. Reusing r makes the scheme deterministic, so identical
 * plaintexts become identical ciphertexts and semantic security is gone.
 *
 * ⭐ It comes from commons/primes.random_unit. This file had its own copy -
 *   the same 16 extra bytes, the same reduction, the same r > 1 and gcd test,
 *   so the same r from the same rng - which mta.js and the range proofs had
 *   already stopped using. The only difference was the retry bound (100
 *   against 200), which a modulus with two large factors never reaches.
 */

/**
 * Encrypt a value in [0, n).
 *
 * c = g^m * r^n  (mod n^2)
 *
 * @param {bigint} m
 * @param {function} [rng]  omitted or null draws fresh ones from the platform
 * @return {bigint} the ciphertext
 */
export function encrypt(pk, m, rng) {
    rng = require_rng('paillier.encrypt', rng);
    /* ⭐ enc_raw below, which is the formula - this was a seventh copy of it,
       in the same file as the one the other six were merged into */
    return enc_raw(pk.n, pk.n2, m, random_unit(pk.n, rng));
}

/**
 * The raw Paillier encryption formula, (1 + m*n) * r^n mod n^2.
 *
 * ⭐ IT IS HERE BECAUSE SIX PLACES COMPUTED IT: this file, paillier_affg's
 *   local enc(), and four inline copies across paillier_range and
 *   paillier_log. Each copy is an opportunity for the reduction of m to
 *   drift, and m is SIGNED in the ZK callers - a blinder or a witness that
 *   can be negative - so getting `mod` wrong there is a silent soundness
 *   bug rather than a crash.
 *
 *   The merge left three stragglers, since removed: encrypt() in this file
 *   still computed the formula inline, and paillier_affg's enc() and
 *   zk_bytes.paillier_enc_raw survived as wrappers that only renamed it.
 *
 * ⚠ m MAY BE NEGATIVE and is reduced with mod(), not %. The exponent r^n
 *   uses the PUBLIC modulus n, so it stays variable-time on purpose.
 */
export function enc_raw(n, n2, m, r) {
    /*
     * ⭐ r = 1 IS THE TRIVIAL ENCRYPTION, (1 + m·n) mod n², and it is common:
     *   every public linear map of a ciphertext adds its constant this way.
     *   1^n by a 4096-bit exponent still walked the whole loop - measured at
     *   16% of an RSA key-generation candidate. r is public when it is 1.
     */
    if (r === 1n) { return mod(1n + mod(m, n) * n, n2); }
    return mod(mod(1n + mod(m, n) * n, n2) * powmod(r, n, n2), n2);
}

/**
 * The raw formula again, BY THE KEY'S OWNER: r^n by CRT over p² and q².
 *
 * ⭐ THE SAME CIPHERTEXT as enc_raw(n, n2, m, r) - a party encrypting under
 *   its OWN key (a commitment, a mask it will later prove things about) knows
 *   p and q, and r^n mod n² splits into r^(n mod p(p−1)) mod p² and the same
 *   mod q²: two exponentiations a quarter of the size. Measured at 2048 bits
 *   about 1.5× - 2× faster.
 *
 * ⛔ THE EXPONENTS n mod p(p−1) AND n mod q(q−1) ARE DERIVED FROM THE
 *   FACTORS, so they take the constant-time ladder, with a public width (the
 *   modulus's). r is secret anyway: it opens the ciphertext.
 *
 * Falls back to enc_raw when the key carries no factors.
 */
export function enc_raw_sk(sk, m, r) {
    if (sk.p == null || sk.q == null) { return enc_raw(sk.n, sk.n2, m, r); }
    var k = crt_of(sk), p = sk.p, q = sk.q;
    if (k.ep == null) {
        k.ep = sk.n % (p * (p - 1n));
        k.eq = sk.n % (q * (q - 1n));
        k.q2inv = mod_inverse(k.q2, k.p2);
        k.wn = sk.n.toString(2).length;
    }
    var xp = powmod_ct(r % k.p2, k.ep, k.p2, k.wn);
    var xq = powmod_ct(r % k.q2, k.eq, k.q2, k.wn);
    var rn = xq + k.q2 * mod((xp - xq) * k.q2inv, k.p2);
    return mod(mod(1n + mod(m, sk.n) * sk.n, sk.n2) * rn, sk.n2);
}

/**
 * Encrypt with a caller-supplied randomiser.
 *
 * Needed by protocols that must PROVE something about the encryption later -
 * a zero-knowledge proof of correct encryption has to know r. Ordinary
 * callers should use encrypt() and let it draw its own.
 */
export function encrypt_with_randomness(pk, m, r) {
    return enc_raw(pk.n, pk.n2, m, r);
}

/**
 * Decrypt.
 *
 * m = L(c^lambda mod n^2) * mu  (mod n)   where L(x) = (x-1)/n
 *
 * @return {bigint}
 */
export function decrypt(sk, c) {
    /*
     * ⭐ BY CRT, when the key carries p and q (Paillier 1999 §7): one
     *   exponentiation mod p² by p−1 and one mod q² by q−1, each a quarter of
     *   the multiplication size and half the exponent length of c^λ mod n².
     *   Measured at 2048 bits: 85 ms → 29 ms. The result is the same m.
     *
     *   With g = n+1, Paillier's h_p = L_p(g^(p−1) mod p²)^−1 is simply
     *   (−q)^−1 mod p: (1+n)^(p−1) = 1 + (p−1)·n (mod p²), and
     *   L_p of that is (p−1)·q ≡ −q (mod p).
     */
    if (sk.p != null && sk.q != null) { return decrypt_crt(sk, c); }
    /* λ is the private key: the ladder must not depend on its bits, as in
       keygen. The variable-time powmod here undid that. */
    var x = powmod_ct(c % sk.n2, sk.lambda, sk.n2, sk.n.toString(2).length);
    var lx = (x - 1n) / sk.n;
    return (lx * sk.mu) % sk.n;
}

/*
 * The per-key constants of the CRT path, computed once per key object.
 * ⚠ A WeakMap, not fields on sk: keys are serialised and compared elsewhere,
 *   and a key object that grew fields would no longer round-trip unchanged.
 */
var CRT = new WeakMap();
function crt_of(sk) {
    var k = CRT.get(sk);
    if (k) { return k; }
    var p = sk.p, q = sk.q;
    k = {
        p2: p * p, q2: q * q,
        hp: mod_inverse(mod(-q, p), p), hq: mod_inverse(mod(-p, q), q),
        qinv: mod_inverse(q, p),                     /* q⁻¹ mod p, for recombining */
        /* ⛔ a PUBLIC width for the secret exponents p−1 and q−1: half the modulus, plus one */
        w: (sk.n.toString(2).length + 1 >> 1) + 1
    };
    CRT.set(sk, k);
    return k;
}
function decrypt_crt(sk, c) {
    var k = crt_of(sk), p = sk.p, q = sk.q;
    var cc = mod(c, sk.n2);
    /* ⛔ the exponents p−1, q−1 are the secret: the constant-time ladder, as before */
    var xp = powmod_ct(cc % k.p2, p - 1n, k.p2, k.w);
    var xq = powmod_ct(cc % k.q2, q - 1n, k.q2, k.w);
    var mp = mod((xp - 1n) / p * k.hp, p);
    var mq = mod((xq - 1n) / q * k.hq, q);
    return mq + q * mod((mp - mq) * k.qinv, p);
}

/* ---------------- the homomorphism ---------------- */

/**
 * E(a) * E(b) = E(a + b)
 *
 * The whole point of the scheme, and one modular multiplication.
 */
export function add(pk, c1, c2) {
    return (c1 * c2) % pk.n2;
}

/**
 * Add a known plaintext to a ciphertext: E(a) * g^b = E(a + b).
 *
 * Note this does NOT re-randomise. Two ciphertexts differing by a known
 * constant are linkable, so a protocol that cares should follow with
 * rerandomise().
 */
export function add_plain(pk, c, m) {
    var mm = ((m % pk.n) + pk.n) % pk.n;
    return (c * ((1n + mm * pk.n) % pk.n2)) % pk.n2;
}

/**
 * E(a)^k = E(a * k) - multiply an encrypted value by a KNOWN scalar.
 *
 * MULTIPLYING TWO CIPHERTEXTS IS NOT POSSIBLE. Paillier is additively
 * homomorphic only; getting E(a*b) from E(a) and E(b) needs fully homomorphic
 * encryption, which is a different and far more expensive construction. This
 * limit is what makes the MtA protocol in threshold ECDSA necessary rather
 * than trivial.
 */
export function mul_plain(pk, c, k) {
    var kk = ((k % pk.n) + pk.n) % pk.n;
    return powmod(c, kk, pk.n2);
}

/**
 * Change a ciphertext's appearance without changing what it encrypts.
 *
 * Multiplying by an encryption of zero - r^n mod n^2 - yields a ciphertext
 * that decrypts identically and is unlinkable to the original. This is the
 * operation a mix network is built from, and it is also what stops the output
 * of add_plain from betraying its input.
 *
 * rng omitted or null draws fresh ones from the platform.
 */
export function rerandomise(pk, c, rng) {
    rng = require_rng('paillier.rerandomise', rng);
    var r = random_unit(pk.n, rng);
    return (c * powmod(r, pk.n, pk.n2)) % pk.n2;
}

/**
 * Sum a whole list of ciphertexts.
 *
 * The tally operation: multiply every encrypted vote together, decrypt once,
 * and the result is the count.
 */
export function sum(pk, ciphertexts) {
    var acc = 1n;
    for (var i = 0; i < ciphertexts.length; i++) {
        acc = (acc * ciphertexts[i]) % pk.n2;
    }
    return acc;
}

/**
 * Decrypt a value that may be NEGATIVE.
 *
 * The plaintext space is [0, n), so subtraction wraps: -1 comes back as n-1.
 * Values in the upper half are interpreted as negative, which is the
 * convention every protocol using Paillier for signed arithmetic adopts. The
 * caller has to know that its values stay well inside +-n/2, because there is
 * no way to tell a genuine large positive from a wrapped negative.
 */
export function decrypt_signed(sk, c) {
    var m = decrypt(sk, c);
    return m > sk.n / 2n ? m - sk.n : m;
}

/**
 * Decrypt AND recover the randomiser: c = (1+n)^m * r^n mod n^2 gives (m, r).
 *
 * A proof of correct decryption (CGGMP21 Pi^dec, Fig. 9 "calculate the
 * randomizer rho_i of K_i^gamma_i * D_i") needs r for a ciphertext the prover
 * did not encrypt itself - here, a product of other parties' ciphertexts.
 *
 *     c * (1+n)^-m = r^n  (mod n^2),  and (1+n)^-m = 1 - m*n  (mod n^2)
 *     r = (r^n mod n)^(n^-1 mod phi)  (mod n)
 *
 * since gcd(n, phi) = 1 for a Paillier modulus. r is secret (it opens c), so
 * the exponentiation is the constant-time ladder, as in decrypt().
 *
 * @return {{m: bigint, r: bigint}}  m in [0, n), r in Z*_n
 */
export function decrypt_with_randomness(sk, c) {
    var m = decrypt(sk, c);
    var u = mod(mod(c, sk.n2) * mod(1n - m * sk.n, sk.n2), sk.n2);
    /*
     * ⭐ r by CRT too: r ≡ (u mod p)^(n⁻¹ mod (p−1)) (mod p), and likewise mod
     *   q — two half-size exponentiations instead of one full one. Same r.
     */
    var k = crt_of(sk), p = sk.p, q = sk.q;
    var up = u % p, uq = u % q;
    var rp = powmod_ct(up, mod_inverse(sk.n % (p - 1n), p - 1n), p, k.w);
    var rq = powmod_ct(uq, mod_inverse(sk.n % (q - 1n), q - 1n), q, k.w);
    var r = rq + q * mod((rp - rq) * k.qinv, p);
    return { m: m, r: r };
}

