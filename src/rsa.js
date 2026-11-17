/**
 * RSA  -  PKCS#1 v2.2 (RFC 8017)
 *
 * The oldest public-key scheme still in wide use, and the only one in this
 * library that is not built on an elliptic curve. It is here because it is
 * unavoidable: X.509 certificates, TLS, JWT's RS256 and PS256, SSH host keys,
 * code signing and PGP all still carry RSA keys, and a library that cannot
 * read them cannot read the existing world.
 *
 * @noble/curves does not implement RSA at all.
 *
 * WHERE RSA STANDS
 * A 2048-bit key is roughly a 112-bit security level, against 128 for a
 * 256-bit curve - and it is 256 bytes on the wire against 32. Signing is
 * expensive, verification is cheap, key generation is very expensive. None of
 * that is a weakness; it is why new protocols choose curves. RSA's real
 * problem is that its safe use depends on padding schemes that took twenty
 * years and several disasters to get right.
 *
 * FOUR SCHEMES, AND ONLY TWO SHOULD BE CHOSEN
 *
 *   OAEP        encryption. Use this.
 *   PSS         signing. Use this.
 *   PKCS1 v1.5  encryption. BROKEN in the sense that matters - Bleichenbacher
 *               1998 recovers plaintext from a server that reveals whether
 *               padding was valid, and the attack has been rediscovered
 *               against real deployments roughly every five years since
 *               (ROBOT, 2017). Provided for reading old data only.
 *   PKCS1 v1.5  signing. Not broken, but its security proof is far weaker
 *               than PSS's and implementations have repeatedly accepted
 *               forged signatures through sloppy parsing. Present because
 *               JWT's RS256 and most certificates use it.
 *
 * RANDOMNESS IS THE CALLER'S. Every function needing it takes an rng
 * argument. This library deliberately generates none - see the note in
 * commons/primes.js - and OAEP and PSS are both insecure with predictable
 * randomness.
 */

import { random_prime_task, prime_pair_task, mod_inverse, powmod_ct, powmod, gcd, random_unit, require_rng } from './commons/primes.js';
import { equal } from './commons/ct.js';
import { finish_task } from './commons/task.js';
import { concat, bytes_to_bigint, bigint_to_bytes, be32, xor_bytes, to_base64url } from './commons/bytes.js';
import { mgf1 } from './commons/mgf1.js';
import * as der from './commons/der.js';
import { sha256, sha384, sha512 } from './sha2.js';

/* ---------------- keys ---------------- */

/**
 * Generate a key pair.
 *
 * @param {number}   bits   modulus size - 2048 minimum for anything real
 * @param {function} rng    (n) -> Uint8Array
 * @param {bigint}   [e=65537]
 *
 * e = 65537 is the universal choice: it is prime, it has only two set bits so
 * exponentiation is cheap, and it is large enough to avoid the small-exponent
 * attacks that broke e = 3 when messages were not padded.
 */
/**
 * Fill in `bits` and `size` when a caller passes a bare {n, e}.
 *
 * ⚠ THEY USED TO BE REQUIRED AND THEIR ABSENCE WAS SILENT.
 *
 * keygen returns them, so every internal round trip worked. A public
 * key reconstructed from a certificate, a JWK, or a test vector - which is
 * {n, e} and nothing else - made `key.size` undefined, `i2osp(x, undefined)`
 * an empty array, and verify return FALSE. A correct signature reported as
 * invalid, with no indication that anything was missing.
 *
 * Both values are derivable from n, so there is no reason to demand them.
 */
function with_sizes(key) {
    if (typeof key.size === 'number' && typeof key.bits === 'number') {
        return key;
    }
    if (typeof key.n !== 'bigint') {
        throw new TypeError('rsa: key needs a modulus n');
    }
    var bits = key.n.toString(2).length;
    var out = { bits: bits, size: (bits + 7) >> 3 };
    for (var k in key) { if (out[k] === undefined) { out[k] = key[k]; } }
    return out;
}

export function keygen(bits, rng, e) {
    return finish_task(keygen_task(bits, rng, e));
}

/**
 * keygen as a task (commons/task.js): each step is one prime candidate,
 * so the callback form runs it in slices - keygen(2048) holds the
 * thread 400-800 ms in one piece, nearly all of it the two prime searches.
 *
 * A rejected pair (key_from_primes, below) discards both primes:
 * commons/primes.js prime_pair_task.
 */
export function keygen_task(bits, rng, e) {
    rng = require_rng('rsa.keygen', rng);
    if (bits < 512) { throw new Error('rsa: modulus must be at least 512 bits'); }
    var E = e === undefined ? 65537n : e;
    var half = bits >> 1;
    return prime_pair_task(
        function (i) { return random_prime_task(i === 0 ? half : bits - half, rng); },
        function (p, q) {
            var key = key_from_primes(p, q, bits, E);
            if (key !== null) { key.bits = bits; key.size = (bits + 7) >> 3; }
            return key;
        },
        100, 'rsa: key generation failed');
}

/**
 * The key from a candidate pair, or null if the PAIR must be discarded.
 *
 * Every rejection discards BOTH primes, because each constraint is on the
 * pair - see keygen_task. (The synchronous and the callback forms
 * once held this list twice, and now run the one task.)
 *
 * ⭐ d = e^-1 mod lambda, lambda = lcm(p-1, q-1) - FIPS 186-5 appendix
 *   A.1.1 asks for exactly that, and it is the smallest valid d. The old
 *   callback form inverted modulo phi = (p-1)(q-1): also a working private
 *   exponent for the same n, but a different number for the same primes,
 *   and not the one the standard specifies.
 */
function key_from_primes(p, q, bits, E) {
    if (p === q) { return null; }
    if (p < q) { var t = p; p = q; q = t; }

    /*
     * Primes that are too close together are factorable by Fermat's method in
     * almost no time. The standards require |p - q| to exceed
     * 2^(bits/2 - 100); this is the check that would have caught the
     * ROCA-adjacent generation bugs.
     */
    if (p - q < (1n << BigInt((bits >> 1) - 100))) { return null; }

    var n = p * q;
    if (n.toString(2).length !== bits) { return null; }

    var order = lcm(p - 1n, q - 1n);
    if (gcd(E, order) !== 1n) { return null; }

    var d = mod_inverse(E, order);
    if (d === null) { return null; }
    /* FIPS 186-5 A.1.1: d > 2^(nlen/2), or reject the pair - a small private
       exponent falls to Wiener / Boneh-Durfee. Never true by accident at real
       sizes (probability ~2^-(nlen/2)), so this is a check, not a loop. */
    if (d <= (1n << BigInt(bits >> 1))) { return null; }

    return {
        n: n, e: E, d: d, p: p, q: q,
        /* the CRT parameters, which make private operations ~4x faster */
        dp: d % (p - 1n),
        dq: d % (q - 1n),
        qinv: mod_inverse(q, p)
    };
}

function lcm(a, b) { return a / gcd(a, b) * b; }

/**
 * The primes of n from (n, e, d) — NIST SP 800-56B rev. 2, Appendix C.2 —
 * and the whole private key in this file's form, d normalised to
 * e⁻¹ mod λ(n) (FIPS 186-5).
 *
 * k = e·d − 1 is a multiple of λ(n); write it 2^t·r with r odd. For a random
 * g, the sequence g^r, g^2r, … reaches 1, and the step before it is a square
 * root of 1 — a non-trivial one (not ±1) with probability ≥ 1/2, and then
 * gcd(x − 1, n) is a prime. Deterministic bases (2, 3, 5, …): every value
 * here is the key's own, so no randomness is needed to be correct, only to be
 * fast, and the small primes find it within a few tries in practice.
 *
 * ⭐ ANY d WITH e·d ≡ 1 (mod λ(n)) — not only the reduced one: a larger d,
 *    or a negative one (what a Bézout combination of shares gives), is a
 *    multiple of λ away from it, and |e·d − 1| is then a multiple of λ too.
 *
 * ⭐ OR (mod λ(n)/2) (11-12): Shoup's threshold RSA shares d mod p′q′ =
 *    λ/2, which is all the squares need, and a d combined from such shares
 *    may be off by λ/2. k = 2·(e·d − 1) is a multiple of λ either way; the
 *    key returned has the reduced d = e⁻¹ mod λ.
 *
 * @return {{ n, e, d, p, q, dp, dq, qinv }} or null when (e, d) is not a
 *         valid pair for n
 */
export function private_key_from_d(n, e, d) {
    var k = 2n * (e * d - 1n);
    if (k < 0n) { k = -k; }
    if (k === 0n || n <= 3n || (n & 1n) === 0n) { return null; }
    var t = 0n, r = k;
    while ((r & 1n) === 0n) { r >>= 1n; t++; }
    var width = k.toString(2).length;
    var bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n];
    for (var bi = 0; bi < bases.length; bi++) {
        var x = powmod_ct(bases[bi], r, n, width);   /* r comes from d: constant time, over k's width */
        if (x === 1n || x === n - 1n) { continue; }
        for (var i = 0n; i < t; i++) {
            var y = x * x % n;
            if (y === 1n) {
                var p = gcd(x - 1n, n);
                if (p === 1n || p === n) { return null; }
                var q = n / p;
                if (p < q) { var tmp = p; p = q; q = tmp; }   /* p > q, as PKCS #1 lists them */
                var lam = lcm(p - 1n, q - 1n);
                var dd = mod_inverse(e, lam);
                if (dd === null || (e * d - 1n) % (lam / 2n) !== 0n) { return null; }
                return { n: n, e: e, d: dd, p: p, q: q, dp: dd % (p - 1n), dq: dd % (q - 1n), qinv: mod_inverse(q, p) };
            }
            if (y === n - 1n) { break; }
            x = y;
        }
    }
    return null;
}

/** A private key ({ n, e, d, p, q, dp, dq, qinv }) as an RFC 7517 / 7518 JWK — what node:crypto, WebCrypto and OpenSSL import. */
export function private_key_to_jwk(key) {
    var b = function (v) { return to_base64url(bigint_to_bytes(v, Math.max(1, (v.toString(16).length + 1) >> 1))); };
    return { kty: 'RSA', n: b(key.n), e: b(key.e), d: b(key.d), p: b(key.p), q: b(key.q), dp: b(key.dp), dq: b(key.dq), qi: b(key.qinv) };
}

/** Just the public half, for handing out. */
export function public_key(key) {
    return { n: key.n, e: key.e, bits: key.bits, size: key.size };
}

/* ---------------- DER (RFC 8017 appendix A.1) ---------------- */

/** RSAPublicKey: SEQUENCE { n, e }. */
export function public_key_to_der(key) { return der.seq([der.int(key.n), der.int(key.e)]); }

/** An RSAPublicKey's {n, e, bits, size}, or null for anything that is not one in strict DER. */
export function public_key_from_der(b) {
    var c = der.read_seq(b);
    if (!c || c.length !== 2) { return null; }
    var n = der.int_value(c[0]), e = der.int_value(c[1]);
    if (n === null || e === null || n < 3n || (n & 1n) === 0n || e < 3n || (e & 1n) === 0n) { return null; }
    return with_sizes({ n: n, e: e });
}

/**
 * RSAPrivateKey: SEQUENCE { 0, n, e, d, p, q, d mod (p−1), d mod (q−1),
 * q⁻¹ mod p } - version 0, two primes, no otherPrimeInfos.
 */
export function private_key_to_der(key) {
    return der.seq([der.int(0n), der.int(key.n), der.int(key.e), der.int(key.d), der.int(key.p), der.int(key.q),
                    der.int(key.dp), der.int(key.dq), der.int(key.qinv)]);
}

/**
 * The private key of an RSAPrivateKey, or null - for a malformed encoding,
 * and for values that are not one key: n = p·q, the CRT values of d, and
 * e·d ≡ 1 are all checked, so a key whose parts disagree (the fault-attack
 * shape) is refused rather than used.
 */
export function private_key_from_der(b) {
    var c = der.read_seq(b);
    if (!c || c.length !== 9 || der.int_value(c[0]) !== 0n) { return null; }
    var v = [];
    for (var i = 1; i < 9; i++) { var x = der.int_value(c[i]); if (x === null) { return null; } v.push(x); }
    var k = { n: v[0], e: v[1], d: v[2], p: v[3], q: v[4], dp: v[5], dq: v[6], qinv: v[7] };
    if (k.p < 3n || k.q < 3n || k.p * k.q !== k.n) { return null; }
    if (k.dp !== k.d % (k.p - 1n) || k.dq !== k.d % (k.q - 1n) || (k.q * k.qinv) % k.p !== 1n) { return null; }
    if ((k.e * k.dp) % (k.p - 1n) !== 1n || (k.e * k.dq) % (k.q - 1n) !== 1n) { return null; }
    return with_sizes(k);
}

/* ---------------- the raw primitive ---------------- */

/*
 * PKCS#1's names for fixed-width big-endian conversion. commons/bytes.js has
 * wr_be32 for 32-bit words; these take arbitrary widths and arbitrary
 * BigInts, which is a different job despite the family resemblance. The RFC's
 * names are kept because every line of RFC 8017 refers to them.
 */
/* RFC 8017's names for the conversions in commons/bytes.js. Every line of the
   spec refers to them this way, so the aliases stay. */
var i2osp = bigint_to_bytes;
var os2ip = bytes_to_bigint;

/**
 * The private operation, with CRT and BLINDING.
 *
 * CRT computes modulo p and q separately and recombines, which is about four
 * times faster because the exponents are half the size.
 *
 * The blinding is not optional. Without it the running time and any fault in
 * the CRT path leak information about d - and a single faulty CRT computation
 * reveals the factorisation outright, which is the Bellcore attack. Blinding
 * with a fresh random r means an attacker who induces a fault or measures a
 * timing sees a randomised value rather than one tied to the key.
 */
function private_op(key, c, rng) {
    var n = key.n;
    if (c < 0n || c >= n) {
        throw new RangeError('rsa: value is not reduced modulo n');
    }

    /*
     * r: primes.random_unit, the one "random unit mod n". This was its own
     * loop - key.size bytes reduced mod n with no slack, so biased towards
     * the bottom of [0, n) - and a unit always has an inverse.
     */
    var r = random_unit(n, rng);
    var rinv = mod_inverse(r, n);

    var blinded = (c * powmod(r, key.e, n)) % n;

    /*
     * THE CRT PATH IS AN OPTIMISATION, NOT A REQUIREMENT.
     *
     * A private key is {n, e, d} in PKCS#1; p, q and the CRT exponents are
     * optional extras that make the operation about four times faster. This
     * used to reach for key.p unconditionally, so a key that carried only d -
     * from a JWK, a test vector, or anywhere the primes were not kept -
     * failed with "Cannot mix BigInt and other types" from deep inside
     * powmod, which reads as a type bug rather than a missing field.
     *
     * The slow path is one modular exponentiation and is used when the extras
     * are absent.
     */
    if (typeof key.p !== 'bigint' || typeof key.q !== 'bigint') {
        if (typeof key.d !== 'bigint') {
            throw new TypeError('rsa: private key needs d, or p and q');
        }
        /* ⛔ the non-CRT path, same reasoning - see the note below */
        var plain = powmod_ct(blinded, key.d, n);
        return (plain * rinv) % n;
    }

/*
     * ⛔ SECRET EXPONENT - see powmod_ct in commons/primes.js for why the
     *   variable-time powmod leaks it, and what the flat path does and does
     *   not guarantee.
     */
    var m1 = powmod_ct(blinded % key.p, key.dp, key.p);
    var m2 = powmod_ct(blinded % key.q, key.dq, key.q);
    var h = (key.qinv * (((m1 - m2) % key.p) + key.p)) % key.p;
    var m = (m2 + h * key.q) % n;

    /*
     * Verify the CRT result against the public exponent before returning it.
     * A single bit flip during the CRT computation lets an attacker factor n
     * from the bad output - the check costs one cheap public operation and
     * removes the entire fault-attack surface.
     */
    if (powmod(m, key.e, n) !== blinded) {
        throw new Error('rsa: private operation failed its consistency check');
    }

    return (m * rinv) % n;
}

/**
 * m^e mod n, with m REQUIRED to be in [0, n-1].
 *
 * ⚠ THE RANGE CHECK IS NOT PEDANTRY - it is what stops malleability.
 *
 * s and s+n raise to the same value mod n, so without this both verify as
 * the same signature. A system that treats a signature as an identifier -
 * a transaction hash, a replay cache, an audit log key - then sees one
 * signature as two, which is how Bitcoin got transaction malleability by a
 * different route. PKCS#1 section 5.2 requires the check; Wycheproof marks
 * these cases SignatureMalleability.
 *
 * The same applies to a ciphertext: c and c+n decrypt identically.
 */
function public_op(key, m) {
    if (m < 0n || m >= key.n) {
        throw new RangeError('rsa: value is not reduced modulo n');
    }
    return powmod(m, key.e, key.n);
}

/* ---------------- OAEP ---------------- */
/*
 * RFC 8017 section 7.1. The encryption padding to use.
 *
 * The message is combined with a random seed through a two-way mask
 * generation function, so the same plaintext encrypts differently every time
 * and no partial information about the plaintext survives. Its security is
 * provable, which PKCS#1 v1.5's is not.
 */

/* MGF1, the mask generation function: commons/mgf1.js */

/*
 * a XOR b into a fresh array of `len` bytes. OAEP and PSS mask and unmask six
 * times between them, and each was its own allocate-and-loop; the loop is
 * commons/bytes.xor_bytes.
 */
function xor_new(a, b, len) {
    var out = new Uint8Array(len);
    xor_bytes(out, a, b, len);
    return out;
}

/**
 * @param {object}     key
 * @param {Uint8Array} msg
 * @param {function}   hash   sha256 is the usual choice; sha1 for legacy
 * @param {function}   rng
 * @param {Uint8Array} [label]
 */
export function encrypt_oaep(key, msg, hash, rng, label) {
    rng = require_rng('rsa.encrypt_oaep', rng);
    key = with_sizes(key);
    var k = key.size;
    var hlen = hash.DIGEST_SIZE;
    if (msg.length > k - 2 * hlen - 2) {
        throw new Error('rsa: message too long for this key and hash');
    }

    var lhash = hash(label || new Uint8Array(0));
    var ps = new Uint8Array(k - msg.length - 2 * hlen - 2);
    var db = concat([lhash, ps, new Uint8Array([1]), msg]);

    var seed = rng(hlen);
    var db_mask = mgf1(seed, k - hlen - 1, hash);
    var masked_db = xor_new(db, db_mask, db.length);

    var seed_mask = mgf1(masked_db, hlen, hash);
    var masked_seed = xor_new(seed, seed_mask, hlen);

    var em = concat([new Uint8Array(1), masked_seed, masked_db]);
    return i2osp(public_op(key, os2ip(em)), k);
}

/**
 * @return {Uint8Array|null} null on any failure
 *
 * Every failure path returns the same null with the same work done. OAEP has
 * three distinguishable ways to be malformed, and an implementation that
 * reports which one is a decryption oracle - the same shape of mistake that
 * makes PKCS#1 v1.5 dangerous.
 */
export function decrypt_oaep(key, ct, hash, rng, label) {
    rng = require_rng('rsa.decrypt_oaep', rng);
    key = with_sizes(key);
    var k = key.size;
    var hlen = hash.DIGEST_SIZE;
    if (ct.length !== k || k < 2 * hlen + 2) { return null; }

    var em = i2osp(private_op(key, os2ip(ct), rng), k);

    var lhash = hash(label || new Uint8Array(0));
    var y = em[0];
    var masked_seed = em.subarray(1, 1 + hlen);
    var masked_db = em.subarray(1 + hlen);

    var seed_mask = mgf1(masked_db, hlen, hash);
    var seed = xor_new(masked_seed, seed_mask, hlen);

    var db_mask = mgf1(seed, k - hlen - 1, hash);
    var db = xor_new(masked_db, db_mask, masked_db.length);
    var i;

    /* accumulate every failure into one flag rather than returning early */
    var bad = y !== 0 ? 1 : 0;
    if (equal(db.subarray(0, hlen), lhash) !== 1) { bad = 1; }

    var idx = -1;
    for (i = hlen; i < db.length; i++) {
        if (db[i] === 1 && idx === -1) { idx = i; }
        else if (db[i] !== 0 && idx === -1) { bad = 1; }
    }
    if (idx === -1) { bad = 1; }
    if (bad) { return null; }
    return db.subarray(idx + 1);
}

/* ---------------- PSS ---------------- */
/*
 * RFC 8017 section 8.1. The signature padding to use.
 *
 * Randomised, so the same message signs differently each time, and with a
 * tight security proof. PKCS#1 v1.5 signing has neither property.
 */

export function sign_pss(key, msg_hash, hash, rng, salt_len, mgf_hash) {
    return signer_create(key).sign_pss(msg_hash, hash, rng, salt_len, mgf_hash);
}

/**
 * EMSA-PSS-ENCODE (RFC 8017 section 9.1.1) with the salt GIVEN: the encoded
 * message, emLen = ceil((modBits - 1) / 8) bytes.
 *
 * ⭐ SEPARATE FROM SIGNING for a key that is never in one place: in threshold
 *   RSA every signer encodes the message itself, from the same salt, and
 *   signs the result with its share. The salt need not be secret - only fresh
 *   and unpredictable to whoever chose the message - so the requester picks
 *   it and sends it along.
 *
 * @param {object}     key       { n } (or a full key)
 * @param {Uint8Array} msg_hash  Hash(M)
 * @param {function}   hash      the hash, with DIGEST_SIZE
 * @param {Uint8Array} salt
 * @param {function}   [mgf_hash]  MGF1's hash, when it is not the message
 *                                 hash: RFC 4055's RSASSA-PSS-params let a
 *                                 key or a certificate fix the two apart
 * @return {Uint8Array}
 */
export function encode_pss(key, msg_hash, hash, salt, mgf_hash) {
    key = with_sizes(key);
    var hlen = hash.DIGEST_SIZE;
    if (!(msg_hash instanceof Uint8Array) || msg_hash.length !== hlen) { throw new Error('rsa: msg_hash must be the hash output'); }
    if (!(salt instanceof Uint8Array)) { throw new Error('rsa: salt must be bytes'); }
    var slen = salt.length;
    var embits = key.bits - 1;
    var emlen = (embits + 7) >> 3;

    if (emlen < hlen + slen + 2) { throw new Error('rsa: key too small for this salt length'); }

    var m1 = concat([new Uint8Array(8), msg_hash, salt]);
    var h = hash(m1);

    var ps = new Uint8Array(emlen - slen - hlen - 2);
    var db = concat([ps, new Uint8Array([1]), salt]);
    var db_mask = mgf1(h, emlen - hlen - 1, mgf_hash || hash);
    var masked = xor_new(db, db_mask, db.length);

    /* clear the leading bits that do not fit in emBits */
    masked[0] &= 0xff >> (8 * emlen - embits);

    return concat([masked, h, new Uint8Array([0xbc])]);
}

/** @return {boolean} */
export function verify_pss(key, msg_hash, sig, hash, salt_len, mgf_hash) {
    key = with_sizes(key);

    /*
     * A VERIFIER MUST NOT THROW ON ATTACKER-CONTROLLED INPUT.
     *
     * The range check in public_op raises on a signature at or above n, which
     * is correct - such a signature is malleable and must be refused. But
     * raising propagates to the caller, and a caller verifying signatures
     * from the network now has an unhandled exception per malformed message,
     * which is a denial of service dressed as a correctness fix.
     *
     * Everything from here is wrapped: an invalid signature is `false`, never
     * an exception. Callers that want the distinction can check the range
     * themselves.
     */
    try {
    var hlen = hash.DIGEST_SIZE;
    var slen = salt_len === undefined ? hlen : salt_len;
    var embits = key.bits - 1;
    var emlen = (embits + 7) >> 3;

    if (sig.length !== key.size) { return false; }
    if (emlen < hlen + slen + 2) { return false; }

    var em = i2osp(public_op(key, os2ip(sig)), emlen);
    if (em[emlen - 1] !== 0xbc) { return false; }

    var masked = em.subarray(0, emlen - hlen - 1);
    var h = em.subarray(emlen - hlen - 1, emlen - 1);

    if ((masked[0] & (0xff << (8 - (8 * emlen - embits)) & 0xff)) !== 0) { return false; }

    var db_mask = mgf1(h, emlen - hlen - 1, mgf_hash || hash);
    var db = xor_new(masked, db_mask, masked.length);
    var i;
    db[0] &= 0xff >> (8 * emlen - embits);

    for (i = 0; i < emlen - hlen - slen - 2; i++) { if (db[i] !== 0) { return false; } }
    if (db[emlen - hlen - slen - 2] !== 1) { return false; }

    var salt = db.subarray(db.length - slen);
    var m1 = concat([new Uint8Array(8), msg_hash, salt]);
    return equal(hash(m1), h) === 1;
    } catch (e) { return false; }
}

/* ---------------- PKCS#1 v1.5 ---------------- */
/*
 * Legacy. Read the warning at the top of this file before using either of
 * these for anything new.
 */

export function encrypt_pkcs1(key, msg, rng) {
    rng = require_rng('rsa.encrypt_pkcs1', rng);
    key = with_sizes(key);
    var k = key.size;
    if (msg.length > k - 11) { throw new Error('rsa: message too long'); }

    /* the padding must contain no zero bytes, so rejected bytes are redrawn */
    var pslen = k - msg.length - 3;
    var ps = new Uint8Array(pslen);
    var filled = 0;
    while (filled < pslen) {
        var chunk = rng(pslen - filled + 8);
        for (var i = 0; i < chunk.length && filled < pslen; i++) {
            if (chunk[i] !== 0) { ps[filled++] = chunk[i]; }
        }
    }

    var em = concat([new Uint8Array([0, 2]), ps, new Uint8Array([0]), msg]);
    return i2osp(public_op(key, os2ip(em)), k);
}

/**
 * @return {Uint8Array|null}
 *
 * Returning null rather than distinguishing failure modes is the minimum
 * defence against Bleichenbacher's attack. It is NOT a complete one: the
 * attack works on any oracle that reveals validity at all, including through
 * timing or through what the surrounding protocol does next. The only real
 * fix is not to use this scheme.
 */
export function decrypt_pkcs1(key, ct, rng) {
    rng = require_rng('rsa.decrypt_pkcs1', rng);
    key = with_sizes(key);
    var k = key.size;
    if (ct.length !== k) { return null; }
    var em = i2osp(private_op(key, os2ip(ct), rng), k);

    var bad = 0;
    if (em[0] !== 0 || em[1] !== 2) { bad = 1; }
    var idx = -1;
    for (var i = 2; i < k; i++) {
        if (em[i] === 0 && idx === -1) { idx = i; }
    }
    if (idx === -1 || idx < 10) { bad = 1; }
    if (bad) { return null; }
    return em.subarray(idx + 1);
}

/*
 * DigestInfo prefixes for PKCS#1 v1.5 signatures - the DER encoding of the
 * hash algorithm identifier that precedes the digest. These are fixed byte
 * strings by definition, and hardcoding them is what the RFC prescribes:
 * parsing DER here is how implementations have historically accepted forged
 * signatures.
 */
var DIGEST_INFO = {
    'sha1':   [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14],
    'sha224': [0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04,0x05,0x00,0x04,0x1c],
    'sha256': [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20],
    'sha384': [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30],
    'sha512': [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40],

    /*
     * The truncated SHA-512 variants and the SHA-3 family, added when
     * Wycheproof's rsa_signature files turned out to cover them and this
     * table did not - so a caller asking for PKCS#1 with SHA3-256 got
     * "unsupported hash", which is honest but leaves a standard combination
     * unavailable for no reason.
     *
     * The OIDs are 2.16.840.1.101.3.4.2.x, the same arc as SHA-2: x is 5 and
     * 6 for the truncated SHA-512s, and 7 through 10 for SHA3-224 up to
     * SHA3-512. The lengths in the second and last bytes follow from the
     * digest size and are what an implementation gets wrong if it copies a
     * neighbouring line without recounting.
     */
    'sha512_224': [0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x05,0x05,0x00,0x04,0x1c],
    'sha512_256': [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x06,0x05,0x00,0x04,0x20],
    'sha3_224':   [0x30,0x2d,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x07,0x05,0x00,0x04,0x1c],
    'sha3_256':   [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x08,0x05,0x00,0x04,0x20],
    'sha3_384':   [0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x09,0x05,0x00,0x04,0x30],
    'sha3_512':   [0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0a,0x05,0x00,0x04,0x40]
};

/**
 * The PKCS#1 v1.5 encoded message block, WITHOUT the private operation.
 *
 * ⭐ EXPORTED FOR THRESHOLD SIGNING. When the private exponent is shared
 *   rather than held, the padding still has to be built once and agreed on -
 *   every party raises the SAME EM to their own share. sign_pkcs1 does both
 *   halves and gives no way to stop in between.
 *
 * ⚠ AND THE ENCODING IS FIXED BYTES BY DESIGN. RFC 8017 prescribes
 *   hardcoding the DigestInfo prefix rather than building it from an ASN.1
 *   encoder, because parsing it at verification time is how implementations
 *   have historically accepted forged signatures. The same reasoning applies
 *   here: a threshold signer that constructs EM differently from the verifier
 *   produces signatures nothing accepts, with no error anywhere.
 *
 * @param {object} key        needs `size`, or `n` to derive it from
 * @param {Uint8Array} msg_hash
 * @param {string} hash_name  'sha256', 'sha3_256', ...
 * @return {Uint8Array} exactly key.size bytes
 */
export function encode_pkcs1(key, msg_hash, hash_name) {
    return pkcs1_em(with_sizes(key), msg_hash, hash_name);
}

function pkcs1_em(key, msg_hash, hash_name) {
    var prefix = DIGEST_INFO[hash_name];
    if (!prefix) { throw new Error('rsa: unsupported hash for PKCS#1 v1.5: ' + hash_name); }
    var t = concat([new Uint8Array(prefix), msg_hash]);
    var k = key.size;
    if (k < t.length + 11) { throw new Error('rsa: key too small'); }
    var ps = new Uint8Array(k - t.length - 3).fill(0xff);
    return concat([new Uint8Array([0, 1]), ps, new Uint8Array([0]), t]);
}

/** @param {string} hash_name  'sha256', 'sha384', 'sha512', 'sha224' or 'sha1' */
export function sign_pkcs1(key, msg_hash, hash_name, rng) {
    return signer_create(key).sign_pkcs1(msg_hash, hash_name, rng);
}

/**
 * Verification compares the WHOLE re-encoded block, byte for byte.
 *
 * The alternative - parsing the block and pulling out the digest - is how
 * Bleichenbacher's 2006 signature forgery worked against e = 3: a parser that
 * ignored trailing bytes accepted a value that was not a valid signature at
 * all. Re-encoding and comparing has no parser to fool.
 */
export function verify_pkcs1(key, msg_hash, sig, hash_name) {
    key = with_sizes(key);

    /*
     * A VERIFIER MUST NOT THROW ON ATTACKER-CONTROLLED INPUT.
     *
     * The range check in public_op raises on a signature at or above n, which
     * is correct - such a signature is malleable and must be refused. But
     * raising propagates to the caller, and a caller verifying signatures
     * from the network now has an unhandled exception per malformed message,
     * which is a denial of service dressed as a correctness fix.
     *
     * Everything from here is wrapped: an invalid signature is `false`, never
     * an exception. Callers that want the distinction can check the range
     * themselves.
     */
    try {
    if (sig.length !== key.size) { return false; }
    var expected;
    try { expected = pkcs1_em(key, msg_hash, hash_name); }
    catch (e) { return false; }
    var em = i2osp(public_op(key, os2ip(sig)), key.size);
    return equal(em, expected) === 1;
    } catch (e) { return false; }
}

/* ---------------- RSA-FDH-VRF (RFC 9381 §4) ---------------- */
/*
 * A VERIFIABLE RANDOM FUNCTION FROM AN RSA KEY. The proof is a deterministic
 * RSA signature of a full-domain hash of the input, the value is a hash of
 * the proof. One input, one proof: e is invertible mod φ(n), so x ↦ xᵉ is a
 * permutation and the e-th root is unique ("trusted uniqueness", §3 — trusted
 * because a modulus with gcd(e, φ) ≠ 1 would break it; RFC 8017 §3 keys
 * cannot have one).
 *
 *   suite_string   0x01 SHA-256, 0x02 SHA-384, 0x03 SHA-512   (§4.4)
 *   MGF_salt       I2OSP(k, 4) ‖ I2OSP(n, k)                  (all three)
 *   EM             MGF1(suite ‖ 0x01 ‖ MGF_salt ‖ alpha, k − 1)
 *   pi             I2OSP(EM^d mod n, k)
 *   beta           Hash(suite ‖ 0x02 ‖ pi)
 *
 * Split so a threshold key can sign EM itself: the encoding and
 * the value here, the e-th root wherever the key lives.
 */
var FDH_VRF = {
    sha256: { suite: 1, hash: sha256 },
    sha384: { suite: 2, hash: sha384 },
    sha512: { suite: 3, hash: sha512 }
};

function fdh_vrf_suite(hash_name) {
    var s = FDH_VRF[hash_name === undefined ? 'sha256' : hash_name];
    if (!s) { throw new TypeError('rsa: the RSA-FDH-VRF hash is sha256, sha384 or sha512'); }
    return s;
}

/**
 * EM, the k−1 octets RSASP1 is applied to (§4.1 steps 1–2).
 * @param {object}     key        { n } (or a full key)
 * @param {Uint8Array} alpha      the VRF input
 * @param {string}     [hash_name] 'sha256' (default), 'sha384', 'sha512'
 * @return {Uint8Array}
 */
export function encode_fdh_vrf(key, alpha, hash_name) {
    key = with_sizes(key);
    if (!(alpha instanceof Uint8Array)) { throw new TypeError('rsa: the VRF input must be bytes'); }
    var s = fdh_vrf_suite(hash_name);
    if (key.size >= 4294967296) { throw new RangeError('rsa: k must be below 2^32'); }
    var salt = concat([be32(key.size), i2osp(key.n, key.size)]);
    return mgf1(concat([new Uint8Array([s.suite, 0x01]), salt, alpha]), key.size - 1, s.hash);
}

/**
 * beta from pi (§4.2). ⚠️ Only for a pi that fdh_vrf_prove made or that
 * fdh_vrf_verify accepted: on anything else the "value" means nothing.
 */
export function fdh_vrf_proof_to_hash(pi, hash_name) {
    var s = fdh_vrf_suite(hash_name);
    if (!(pi instanceof Uint8Array)) { throw new TypeError('rsa: the VRF proof must be bytes'); }
    return s.hash(concat([new Uint8Array([s.suite, 0x02]), pi]));
}

/** pi for alpha, with a whole private key (§4.1). */
export function fdh_vrf_prove(key, alpha, hash_name, rng) {
    rng = require_rng('rsa.fdh_vrf_prove', rng);
    key = with_sizes(key);
    return i2osp(private_op(key, os2ip(encode_fdh_vrf(key, alpha, hash_name)), rng), key.size);
}

/**
 * §4.3: beta when pi is the proof for alpha under (n, e), else null. Never
 * throws on the proof: a verifier reads it off the network.
 */
export function fdh_vrf_verify(key, alpha, pi, hash_name) {
    key = with_sizes(key);
    var EM = encode_fdh_vrf(key, alpha, hash_name);     /* throws only on the caller's own arguments */
    try {
        if (!(pi instanceof Uint8Array) || pi.length !== key.size) { return null; }
        var s = os2ip(pi);
        if (s >= key.n) { return null; }                 /* "signature representative out of range" */
        var em = i2osp(public_op(key, s), key.size);
        /* m = m′ as integers: EM is k−1 octets, so the k-octet form has a zero first octet */
        if (em[0] !== 0 || equal(em.subarray(1), EM) !== 1) { return null; }
        return fdh_vrf_proof_to_hash(pi, hash_name);
    } catch (e) { return null; }
}

/* ---------------- Over a whole message ---------------- */
/*
 * The signature functions above take the message's hash, which the caller
 * computes - incrementally, or in another step. These take the message and
 * hash it here, with the hash given as a function (sha256, sha3_256, ...),
 * the same way for PSS and for PKCS#1 v1.5. Otherwise their arguments are
 * those of the function each wraps.
 */
export function sign_pss_message(key, msg, hash, rng, salt_len, mgf_hash) {
    return signer_create(key).sign_pss_message(msg, hash, rng, salt_len, mgf_hash);
}

export function verify_pss_message(key, msg, sig, hash, salt_len, mgf_hash) {
    return verify_pss(key, hash(msg), sig, hash, salt_len, mgf_hash);
}

/* PKCS#1 v1.5 names the hash in the signature; hash.NAME is that name. */
function digest_name(hash) {
    if (typeof hash !== 'function' || !DIGEST_INFO[hash.NAME]) {
        throw new Error('rsa: PKCS#1 v1.5 needs one of the SHA-1, SHA-2 or SHA-3 hash functions');
    }
    return hash.NAME;
}

export function sign_pkcs1_message(key, msg, hash, rng) {
    return signer_create(key).sign_pkcs1_message(msg, hash, rng);
}

/**
 * One private key for many signatures, held in a context: the four signing
 * operations with the key taken out of their arguments.
 *
 *     var signer = rsa.signer_create(key);
 *     signer.sign_pss_message(msg, sha256);          // salt: the digest's length
 *     signer.sign_pss_message(msg, sha384, rng, 48);
 *     signer.sign_pkcs1_message(msg, sha512);
 *     signer.sign_pss(msg_hash, hash, rng, salt_len, mgf_hash) and sign_pkcs1(msg_hash, hash_name, rng)
 *     signer.wipe();                                 // drops the key; calls then throw
 *
 * The hash and the salt are arguments of each signature, so one signer
 * serves every scheme a protocol negotiates. Each signature is EMSA-PSS or
 * EMSA-PKCS1-v1_5 here, then RSASP1 (the private operation, blinded);
 * signer_with builds the same four over another RSASP1 - an engine's,
 * which keeps the key it imported once (engines/node.js). The output is
 * the one-shot functions' bytes for the same rng.
 *
 * ⚠ wipe() drops the key: its numbers are BigInts, which JavaScript cannot
 *   overwrite, so they stay in memory until collected.
 */
export function signer_create(key) {
    var k = private_copy(key);
    return signer_with(k, function (em, rng) { return i2osp(private_op(k, os2ip(em), rng), k.size); });
}

/**
 * The four signing operations over an RSASP1 of the caller's: rsasp1(em,
 * rng) -> the signature, key.size bytes, of the encoded message em.
 */
export function signer_with(key, rsasp1) {
    var k = with_sizes(key);
    function live() { if (k === null) { throw new Error('rsa: the signer was wiped'); } }
    function pss(msg_hash, hash, rng, salt_len, mgf_hash) {
        live();
        rng = require_rng('rsa.sign_pss', rng);
        var slen = salt_len === undefined ? hash.DIGEST_SIZE : salt_len;
        return rsasp1(encode_pss(k, msg_hash, hash, slen > 0 ? rng(slen) : new Uint8Array(0), mgf_hash), rng);
    }
    function pkcs1(msg_hash, hash_name, rng) {
        live();
        rng = require_rng('rsa.sign_pkcs1', rng);
        return rsasp1(pkcs1_em(k, msg_hash, hash_name), rng);
    }
    return {
        sign_pss: pss,
        sign_pkcs1: pkcs1,
        sign_pss_message: function (msg, hash, rng, salt_len, mgf_hash) { return pss(hash(msg), hash, rng, salt_len, mgf_hash); },
        sign_pkcs1_message: function (msg, hash, rng) { return pkcs1(hash(msg), digest_name(hash), rng); },
        wipe: function () { k = null; }
    };
}

/* every key context's first check: a modulus and an exponent */
function need_public(key) {
    if (!key || typeof key.n !== 'bigint' || typeof key.e !== 'bigint') { throw new TypeError('rsa: key needs a modulus n and an exponent e'); }
}

/*
 * A private key as an object of its own, with what private_op can use: d,
 * or the primes and the CRT values, or both (the CRT path when it can).
 */
function private_copy(key) {
    need_public(key);
    if (typeof key.d !== 'bigint' && (typeof key.p !== 'bigint' || typeof key.q !== 'bigint')) {
        throw new TypeError('rsa: private key needs d, or p and q');
    }
    var out = {}, names = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qinv'];
    for (var i = 0; i < names.length; i++) { if (typeof key[names[i]] === 'bigint') { out[names[i]] = key[names[i]]; } }
    return with_sizes(out);
}

export function verify_pkcs1_message(key, msg, sig, hash) {
    /* a wrong hash function throws: it is the caller's mistake, not the signature's */
    return verify_pkcs1(key, hash(msg), sig, digest_name(hash));
}

/**
 * One public key for many verifications, held in a context: the four
 * verifying operations with the key taken out of their arguments.
 *
 *     var verifier = rsa.verifier_create({ n, e });
 *     verifier.verify_pss_message(msg, sig, sha256);          // salt: the digest's length
 *     verifier.verify_pss_message(msg, sig, sha256, 20, sha1); // a certificate's own parameters
 *     verifier.verify_pkcs1_message(msg, sig, sha384);
 *     verifier.verify_pss(msg_hash, sig, hash, salt_len, mgf_hash) and verify_pkcs1(msg_hash, sig, hash_name)
 *
 * The same answers as the one-shot functions. The engine imports the key
 * once (engines/node.js). A public key needs no wipe().
 */
export function verifier_create(key) {
    need_public(key);
    var k = with_sizes({ n: key.n, e: key.e });
    return {
        verify_pss: function (msg_hash, sig, hash, salt_len, mgf_hash) { return verify_pss(k, msg_hash, sig, hash, salt_len, mgf_hash); },
        verify_pkcs1: function (msg_hash, sig, hash_name) { return verify_pkcs1(k, msg_hash, sig, hash_name); },
        verify_pss_message: function (msg, sig, hash, salt_len, mgf_hash) { return verify_pss_message(k, msg, sig, hash, salt_len, mgf_hash); },
        verify_pkcs1_message: function (msg, sig, hash) { return verify_pkcs1_message(k, msg, sig, hash); }
    };
}
