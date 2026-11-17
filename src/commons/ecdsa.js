/**
 * ECDSA over a short Weierstrass curve
 *
 * Everything here is generic: key generation, SEC 1 point encoding, RFC 6979
 * nonce derivation, signing, verification, public-key recovery, ECDH, and the
 * two signature encodings. Only the curve parameters and the hash differ
 * between secp256k1 and the NIST P-curves, so only those are arguments.
 *
 * Extracted before the second curve was written rather than after. The first
 * version of secp256k1.js held all of this inline, and P-256 would have
 * duplicated roughly three hundred of its three hundred and forty-eight
 * lines - with P-384, P-521 and Brainpool behind it.
 *
 * What does NOT belong here: Schnorr/BIP-340. It shares the curve but not the
 * signature scheme, has its own key format, its own tagged hashes and its own
 * x-only points, and generalising it would be inventing a scheme nobody uses.
 * It stays in secp256k1.js.
 */

import { field } from './modp.js';
import { weierstrass } from './weierstrass.js';
import { hmac_drbg } from '../drbg.js';
import { bytes_to_bigint, bigint_to_bytes, concat, secure_random } from './bytes.js';
import { random_secret_below, key_from_seed } from './group.js';
import { held } from './ct.js';
import { window_mul, fixed_base, double_mul, double_mul_base, base_table, wnaf_mul } from './fixed_window.js';
import { glv_double_mul, glv_base_table } from './glv.js';
import { read_seq as der_read_seq, read_whole as der_read_whole, int_value as der_int_value, oid_value as der_oid_value,
         seq as der_seq, int as der_int, octets as der_octets, oid as der_oid, tlv as der_tlv } from './der.js';

/**
 * @param {object} params
 *   p, n, a, b, Gx, Gy   the curve, as bigints
 *   hash                 the hash for RFC 6979, e.g. sha256
 *   name                 used in error messages
 */
/**
 * bits2int, per RFC 6979 section 2.3.2, for an order of `qbits` bits: the
 * LEFTMOST min(qbits, 8*len) bits of `b` as a big-endian integer.
 *
 * ⚠ NOT REDUCED. A caller that needs a scalar takes it mod q itself; the
 *   ECDSA message hash is bits2int(H) mod q. Exported because a threshold
 *   ECDSA signer outside this file must derive the exact same z, and a
 *   private copy that reduced instead of truncating disagreed on P-521.
 */
export function bits2int_q(b, qbits) {
    var v = bytes_to_bigint(b);
    var delta = b.length * 8 - qbits;
    return delta > 0 ? v >> BigInt(delta) : v;
}

export function ecdsa(params) {
    var P = params.p, N = params.n, HALF_N = N / 2n;
    var Fp = field(P);
    var Fn = field(N);
    var C = weierstrass(Fp, params.a, params.b);
    var G = C.of(params.Gx, params.Gy);


    var H = params.hash;
    var HLEN = H.DIGEST_SIZE;
    var name = params.name || 'ecdsa';

    /* Field elements and scalars can differ in width - P-521 is 66 bytes */
    var FBYTES = Fp.BYTES;
    var NBITS = N.toString(2).length;

    /*
     * SCALAR MULTIPLICATION, THREE WAYS.
     *
     * base_mul   the generator is fixed, so its table is built once and the
     *            doublings vanish entirely - measured 9x faster than the
     *            ladder on secp256k1. Used for key generation, for the nonce
     *            point in signing, and for one half of verification.
     * var_mul    an arbitrary point, so the table is built per call. A 5-bit
     *            window still beats the ladder by about 1.7x because it does
     *            one addition per five bits instead of one per bit.
     *
     * BOTH REMAIN CONSTANT TIME. The table lookup scans every entry and
     * selects with masks rather than indexing, so the memory access pattern
     * does not depend on the scalar. See commons/fixed_window.js.
     */
    var base_mul = fixed_base(C, G, NBITS, 4);
    function var_mul(k, P) { return window_mul(C, k, P, NBITS, 5); }

    /*
     * THE GLV ENDOMORPHISM, WHERE THE CURVE HAS ONE. Only a few curves do -
     * secp256k1 among the ones here, none of the NIST or Brainpool primes -
     * so it is a parameter rather than a property of this file. When present
     * it splits each 256-bit scalar into two 128-bit halves and halves the
     * doublings; measured 1.2x on a verification-shaped double
     * multiplication and 2.1x on a single one.
     *
     * Used ONLY on public scalars, for the reason set out in commons/glv.js.
     */
    var GLV = params.endomorphism || null;

    /*
     * ⭐ THE GENERATOR'S TABLE IS KEPT (11-11): odd multiples at w = 8 (and
     *    their endomorphism images under GLV), built on first use. Every
     *    verification has the generator on one side; its table was rebuilt
     *    each time, at a narrow window.
     */
    var G_TABLE = GLV ? glv_base_table(C, Fp, GLV.beta, G, 8) : base_table(C, G, 8);

    function pub_double_mul(a, P1, b, P2) {
        if (P2 === G && P1 !== G) { return pub_double_mul(b, P2, a, P1); }
        var table = P1 === G ? G_TABLE : null;
        if (GLV) {
            return glv_double_mul(C, Fp, GLV.beta, N, GLV.basis, a, P1, b, P2, 5, table);
        }
        return table ? double_mul_base(C, a, table, b, P2, 5) : double_mul(C, a, P1, b, P2, 5);
    }

    var NBYTES = (NBITS + 7) >> 3;

    function fb(x) { return Fp.to_bytes(x); }
    function fn(b) { return Fp.from_bytes(b); }

    /**
     * bits2int, per RFC 6979 section 2.3.2.
     *
     * Takes the LEFTMOST min(bitlen(n), 8*len) bits, which for a hash wider
     * than the order means shifting right rather than reducing. P-521 with
     * SHA-512 is the case where hash and order genuinely differ in width, and
     * reducing instead of truncating there gives a different - and wrong -
     * answer.
     */
    function bits2int(b) { return bits2int_q(b, NBITS); }

    function int2octets(x) { return bigint_to_bytes(x, NBYTES); }
    /* public bytes only: a recovered key against the signer's */
    function same_bytes(a, b) {
        if (a.length !== b.length) { return false; }
        for (var i = 0; i < a.length; i++) { if (a[i] !== b[i]) { return false; } }
        return true;
    }

    /** bits2octets: bits2int reduced into the scalar field, then re-encoded. */
    function bits2octets(b) {
        var z = bits2int(b);
        return int2octets(z >= N ? z - N : z);
    }

    /*
     * RFC 6979 - deterministic nonces.
     *
     * THIS IS HMAC_DRBG, seeded with the private key and the message hash,
     * and it now IS drbg.js's hmac_drbg rather than a copy of it. RFC 6979
     * section 3.3 says so itself: the K/V pair, the two-round update with
     * 0x00 and 0x01 separators and the generate loop are SP 800-90A 10.1.2,
     * instantiated with entropy = int2octets(x) || bits2octets(h1) [|| extra].
     *
     * ⚠ THE RE-KEY ON REJECTION IS THE DRBG'S OWN. This used to be written
     *   out here on the stated grounds that a retry must re-key rather than
     *   draw again - but SP 800-90A's generate ends with update() on empty
     *   input, which is K = HMAC(K, V || 0x00), V = HMAC(K, V): precisely
     *   RFC 6979 step h.3. Calling generate again IS the re-key. The two were
     *   checked byte for byte over signatures where a quarter to a half of
     *   the candidates were rejected.
     *
     * k is derived from the private key and the message alone, so it is
     * unpredictable without the key, unique per message, and reproducible.
     * That removes ECDSA's single most dangerous input: a repeated k gives up
     * the private key in two subtractions, and a merely BIASED k gives it up
     * to lattice attacks over a few hundred signatures.
     *
     * The retry loop matters. When a candidate falls outside [1, n) it
     * re-keys rather than reducing, because reducing would skew the
     * distribution - and a skewed nonce is the same attack.
     */
    function rfc6979_k(secret_bytes, msg_hash, extra) {
        var seed = [int2octets(fn(secret_bytes)), bits2octets(msg_hash)];
        if (extra) { seed.push(extra); }
        var drbg = hmac_drbg(H, concat(seed));

        for (var i = 0; i < 1000; i++) {
            /* NBYTES may exceed one digest (P-521 with SHA-512 is 66 > 64);
               generate concatenates as many blocks as it takes */
            var cand = bits2int(drbg.generate(NBYTES));
            if (cand > 0n && cand < N) { return cand; }
        }
        throw new Error(name + ': RFC 6979 failed to produce a nonce');
    }

    /*
     * ECDSA verification past its checks: r and s in [1, n), and Qp the
     * public key, decoded and on the curve, in the curve's own coordinates.
     */
    function verify_point(msg_hash, r, s, Qp) {
        var z = bits2int(msg_hash);
        if (z >= N) { z -= N; }
        /*
         * ⭐ VARIABLE-TIME INVERSE, and it is safe HERE and nowhere else
         *   in this file: s is half of a SIGNATURE. It is transmitted in
         *   the clear, so its value is already known to anyone who can
         *   time this.
         *
         *   Measured: 293 us for Fermat against 52 for Euclid on the
         *   scalar field, and verify spent 0.44 ms outside its double
         *   multiplication - most of it here.
         *
         * ⛔ THE SIGNING PATH (API.sign) MUST NOT DO THIS. There Fn.inv(k)
         *   inverts the NONCE, and a timing signal on k recovers the
         *   private key from a single signature. The two lines look
         *   identical and one of them is a key-recovery bug.
         */
        var w = Fn.inv_vartime ? Fn.inv_vartime(s) : Fn.inv(s);
        var u1 = Fn.mul(z, w), u2 = Fn.mul(r, w);

        /*
         * u1*G + u2*Q in one interleaved pass. Both scalars are derived
         * from public values - the message hash and the signature - so
         * the variable-time path is correct here and twice as fast.
         */
        var A = C.to_affine_public(pub_double_mul(u1, G, u2, Qp));
        if (A === null) { return false; }
        return (A.x % N) === r;
    }

    var API = {
        CURVE: params,
        FIELD: Fp,
        SCALAR: Fn,
        POINT: C,
        G: G,
        BYTES: FBYTES,

        /**
         * k * G, through the precomputed table this module already builds.
         *
         * ⭐ THE TABLE EXISTED AND WAS UNREACHABLE. sign and get_public_key
         *   used it; nothing outside could. A caller wanting k*G for anything
         *   else - a commitment, a nonce, a share - had to call POINT.mul and
         *   pay for a generic variable-base multiplication.
         *
         *   Measured on secp256k1: 1.25 ms through the table against 4.50 ms
         *   without it, a factor of 3.6 thrown away by an export that was
         *   never written.
         *
         * ⚠ ristretto255 and babyjubjub had the same gap for a different
         *   reason - they had no table at all - and were fixed the same day.
         *   This one is a missing line, not a missing algorithm.
         */
        /**
         * Scalar multiplication of an ARBITRARY point, in variable time.
         *
         * ⛔ THE NAME IS THE WARNING. Its addition pattern depends on the
         *   scalar's bits, so a secret scalar must go through `C.mul` - the
         *   two return the same point and differ only in timing, which means
         *   a wrong choice gives correct answers and a side channel.
         *
         * ⭐ WHERE IT IS SAFE: verification, where every scalar is either
         *   published in the signature or derived by hashing published
         *   values. wNAF at width 5 measured roughly twice the ladder's
         *   speed on these curves.
         *
         * ⚠ SEE commons/modp.js on cselect for what "constant time" does and
         *   does not mean under BigInt - the ladder is branchless, not
         *   timing-flat.
         */
        mul_vartime: function (k, P) { return wnaf_mul(C, k, P, 5); },

        /** a·P1 + b·P2 for PUBLIC scalars — the endomorphism where the curve has one (verification). */
        double_mul_vartime: pub_double_mul,

        /*
         * ⛔ AFFINE THROUGH THE CONSTANT-TIME INVERSE whenever the scalar is
         *   secret - a key, a nonce. The point itself gets published, but
         *   its projective Z does not, and Z depends on the scalar: timing a
         *   variable-time inversion of it leaks scalar bits (Naccache, Smart
         *   and Stern, PKC 2004). BIP-340, SM2 and BLS here already converted
         *   that way; ECDSA and EdDSA did not. to_affine_public stays for
         *   points computed from public data only (verification).
         */
        base_mul: function (k) {
            var x = (k instanceof Uint8Array) ? fn(k) : k;
            return C.to_affine(base_mul(x));
        },

        /**
         * k * G through the same table, left PROJECTIVE.
         *
         * base_mul above converts to affine (constant time); this returns the
         * table's output untouched, projective, for a caller that keeps
         * computing. It is what commons/group.js hands to every GROUP built
         * on this file.
         *
         * @param {bigint} k  already reduced into [0, n)
         */
        base_mul_point: function (k) { return base_mul(k); },

        is_valid_secret: function (k) {
            var x = (k instanceof Uint8Array) ? fn(k) : k;
            return x > 0n && x < N;
        },

        get_public_key: function (secret, compressed) {
            var d = fn(secret);
            if (!(d > 0n && d < N)) { throw new Error(name + ': invalid secret key'); }
            var A = C.to_affine(base_mul(d));
            return API.encode_point(A.x, A.y, compressed !== false);
        },

        /**
         * SEC 1 encoding. Compressed carries x plus one bit of y; the receiver
         * recovers y by a square root.
         */
        encode_point: function (x, y, compressed) {
            if (compressed === false) {
                var out = new Uint8Array(1 + FBYTES * 2);
                out[0] = 0x04;
                out.set(fb(x), 1);
                out.set(fb(y), 1 + FBYTES);
                return out;
            }
            var c = new Uint8Array(1 + FBYTES);
            c[0] = (y & 1n) === 1n ? 0x03 : 0x02;
            c.set(fb(x), 1);
            return c;
        },

        /**
         * Decode, rejecting anything not on the curve.
         *
         * Not defensive politeness: a point from a different, weaker curve fed
         * into a scalar multiplication leaks the scalar. Rejecting it before
         * it reaches the ladder is the only defence.
         */
        decode_point: function (b) {
            var x, y;
            if (b.length === 1 + FBYTES && (b[0] === 0x02 || b[0] === 0x03)) {
                x = fn(b.subarray(1));
                if (x >= P) { return null; }
                y = C.decompress(x, b[0] === 0x03);
                if (y === null) { return null; }
            } else if (b.length === 1 + FBYTES * 2 && b[0] === 0x04) {
                x = fn(b.subarray(1, 1 + FBYTES));
                y = fn(b.subarray(1 + FBYTES));
                if (x >= P || y >= P) { return null; }
            } else {
                return null;
            }
            if (!C.is_on_curve(x, y)) { return null; }
            return { x: x, y: y };
        },

        /**
         * A key pair: { sk, pk } as sign, verify, get_public_key and ecdh
         * take them - sk the scalar's NBYTES big-endian bytes, pk the
         * compressed SEC 1 point.
         *
         * @param {Uint8Array} [seed]  the secret key itself, checked as
         *   get_public_key checks it; omitted or null draws a fresh one from
         *   the platform (a uniform scalar in [1, n), by rejection)
         */
        keygen: function (seed) {
            var sk = key_from_seed(name + '.keygen', seed, function () {
                return int2octets(random_secret_below(N, name + '.keygen'));
            });
            return { sk: sk, pk: API.get_public_key(sk) };
        },

        /**
         * Sign a message hash. THE CALLER HASHES.
         *
         * Bitcoin hashes twice, some protocols prefix a domain string, and
         * @noble/curves v2 hashes inside its own sign - a signature made under
         * one convention will not verify under another. Keeping the hash out
         * here makes the choice the caller's and visible.
         *
         * @param {Uint8Array} [extra]  RFC 6979 section 3.6's additional data
         *   k', fed to the nonce derivation after the key and the hash.
         *   Omitted or null draws fresh ones from the platform (32 bytes): a
         *   HEDGED signature, never a bare random k - the nonce still
         *   depends on the key and the message, so a weak platform rng
         *   cannot repeat it across messages, and a fault or a side channel
         *   on one deterministic derivation is not replayed on every
         *   signature. Bytes given are used as k' (deterministic given them);
         *   an EMPTY Uint8Array is classic RFC 6979, the signature its test
         *   vectors and every other deterministic signer produce.
         */
        sign: function (msg_hash, secret, extra) {
            var d = fn(secret);
            if (!(d > 0n && d < N)) { throw new Error(name + ': invalid secret key'); }
            if (extra == null) { extra = secure_random(32); }
            if (!(extra instanceof Uint8Array)) {
                throw new TypeError(name + ': extra must be a Uint8Array, or left out (or null) for fresh randomness');
            }

            var z = bits2int(msg_hash);
            if (z >= N) { z -= N; }
            /* on the vanishing chance of r or s zero, k' grows by a counter
               byte - with an empty extra exactly the retry this always did */
            var more = extra;

            for (var tries = 0; tries < 64; tries++) {
                var k = rfc6979_k(secret, msg_hash, more.length ? more : null);
                var R = C.to_affine(base_mul(k));   /* k secret: see base_mul */
                var r = R.x % N;
                if (r === 0n) { more = concat([extra, new Uint8Array([tries])]); continue; }

                var s = Fn.mul(Fn.inv(k), (z + r * d) % N);
                if (s === 0n) { more = concat([extra, new Uint8Array([tries])]); continue; }

                var norm = API.normalize_s(r, s, API.recovery_id(R, N));
                return norm;
            }
            throw new Error(name + ': signing failed');
        },

        /**
         * sign and verify over a whole message: the same operations with the
         * hashing done here - hash(msg) is what sign and verify take. For a
         * caller who holds the message rather than its digest; one who
         * hashes elsewhere (incrementally, or in another step) keeps using
         * sign and verify.
         *
         * @param {function} hash  sha256, sha384, ... from this library
         * @param {Uint8Array} [extra]  as sign's: omitted or null draws fresh
         *   ones from the platform, an empty Uint8Array is classic RFC 6979
         */
        sign_message: function (hash, msg, secret, extra) {
            return API.sign(hash(msg), secret, extra);
        },

        verify_message: function (hash, msg, sig, public_key) {
            return API.verify(hash(msg), sig, public_key);
        },

        /**
         * A signature computed elsewhere (node:crypto, a hardware key), in
         * the shape sign returns: s made low, as sign makes it, and
         * `recovery` found the first time it is read.
         *
         * ⚠ READING recovery COSTS A PUBLIC-KEY RECOVERY - about as much as
         *   signing in JavaScript - so it is not computed up front: most
         *   callers write the signature as r and s and never read it.
         *
         * The message hash and the public key may each be a function that
         * returns it, called only when recovery is read: an engine that
         * signed with a key it holds need not export the public key for a
         * value nobody asked for.
         *
         * @param {Uint8Array|function} msg_hash
         * @param {bigint} r
         * @param {bigint} s
         * @param {Uint8Array|function} public_key  the signer's, SEC 1, either form
         * @return {{r: bigint, s: bigint, recovery: number}}
         */
        signature_from_rs: function (msg_hash, r, s, public_key) {
            if (s > HALF_N) { s = N - s; }
            var rec = null;
            /* the getter in the literal: one object of a fixed shape, made once per signature */
            var sig = {
                r: r, s: s,
                get recovery() {
                    if (typeof msg_hash === 'function') { msg_hash = msg_hash(); }
                    if (typeof public_key === 'function') { public_key = public_key(); }
                    for (var i = 0; rec === null && i < 4; i++) {
                        var q = API.recover(msg_hash, sig, i, public_key.length === 1 + FBYTES);
                        if (q !== null && same_bytes(q, public_key)) { rec = i; }
                    }
                    return rec;
                }
            };
            return sig;
        },

        /**
         * Which of the two possible R points was used, so a verifier can
         * rebuild the public key from the signature alone.
         *
         * @param {object} R  the affine nonce point
         * @param {bigint} n  the group order
         * @return {number}   0..3
         */
        recovery_id: function (R, n) {
            var rec = (R.y & 1n) === 1n ? 1 : 0;
            if (R.x >= n) { rec |= 2; }
            return rec;
        },

        /**
         * Low-s normalisation.
         *
         * Both s and n-s verify, so a signature can be altered without the
         * key - transaction malleability, which cost Bitcoin years of
         * workarounds and which Bitcoin now rejects outright.
         *
         * EXPOSED SEPARATELY BECAUSE THRESHOLD SIGNERS NEVER CALL sign().
         * A threshold protocol assembles r and s from shares; the signing
         * loop above does not run, so the normalisation buried inside it does
         * not either. A caller who forgets it produces signatures that this
         * library's own verify accepts and that Bitcoin rejects - passing
         * every local test and failing in the field, which is the worst place
         * to find out.
         *
         * @return {{r: bigint, s: bigint, recovery: number}}
         */
        normalize_s: function (r, s, recovery) {
            if (s > N / 2n) { return { r: r, s: N - s, recovery: recovery ^ 1 }; }
            return { r: r, s: s, recovery: recovery };
        },

        verify: function (msg_hash, sig, public_key) {
            var r = sig.r, s = sig.s;
            if (!(r > 0n && r < N) || !(s > 0n && s < N)) { return false; }
            var Q = API.decode_point(public_key);
            return Q !== null && verify_point(msg_hash, r, s, C.of(Q.x, Q.y));
        },

        /**
         * One public key for many signatures, held in a context: verify and
         * verify_message with the key taken out of their arguments.
         *
         *     var verifier = p256.verifier_create(public_key);
         *     verifier.verify_message(sha256, msg, sig);   // true or false
         *     verifier.verify(msg_hash, sig);
         *
         * The key is decoded (in compressed form, a square root) once; the
         * engine imports it once (engines/node.js). Same answers as verify:
         * a key that does not decode gives a verifier that accepts nothing.
         * A public key needs no wipe().
         */
        verifier_create: function (public_key) {
            var Q = public_key instanceof Uint8Array ? API.decode_point(public_key) : null;
            var point = Q === null ? null : C.of(Q.x, Q.y);
            function verify(msg_hash, sig) {
                var r = sig.r, s = sig.s;
                if (!(r > 0n && r < N) || !(s > 0n && s < N)) { return false; }
                return point !== null && verify_point(msg_hash, r, s, point);
            }
            return {
                verify: verify,
                verify_message: function (hash, msg, sig) { return verify(hash(msg), sig); }
            };
        },

        /**
         * Rebuild the public key from a signature.
         *
         * Ethereum stores no public keys - every transaction carries only a
         * signature, and the sender's identity is recovered from it.
         */
        recover: function (msg_hash, sig, recovery, compressed) {
            var r = sig.r, s = sig.s;
            if (!(r > 0n && r < N) || !(s > 0n && s < N)) { return null; }
            if (recovery < 0 || recovery > 3) { return null; }

            var x = (recovery & 2) ? r + N : r;
            if (x >= P) { return null; }
            var y = C.decompress(x, (recovery & 1) === 1);
            if (y === null) { return null; }

            var R = C.of(x, y);
            var z = bits2int(msg_hash);
            if (z >= N) { z -= N; }

            var Q = pub_double_mul(s, R, N - z, G);
            Q = var_mul(Fn.inv(r), Q);

            var A = C.to_affine(Q);
            if (A === null) { return null; }
            return API.encode_point(A.x, A.y, compressed !== false);
        },

        /**
         * The shared secret is the X COORDINATE ONLY of the shared point.
         *
         * Every standard from SEC 1 onward defines it that way - y carries one
         * bit both parties can already compute. It still needs a KDF before
         * use; raw x is not uniformly distributed.
         */
        /**
         * One secret for many signatures, held in a context: sign and
         * sign_message with the secret taken out of their arguments.
         *
         *     var signer = p256.signer_create(sk);
         *     signer.sign_message(sha384, msg);        // { r, s, recovery }
         *     signer.sign(msg_hash, extra);            // a digest, RFC 6979's extra
         *     signer.wipe();                           // zeroes the secret; calls then throw
         *
         * The hash is an argument of each signature, not of the signer, so
         * one signer serves every hash a protocol negotiates. The engine
         * imports the secret once (engines/node.js); the pure context holds
         * a copy of it.
         */
        signer_create: function (secret) {
            if (!API.is_valid_secret(secret)) { throw new Error(name + ': invalid secret key'); }
            var key = held(name, new Uint8Array(secret));
            return {
                sign: function (msg_hash, extra) { return API.sign(msg_hash, key.use(), extra); },
                sign_message: function (hash, msg, extra) { return API.sign_message(hash, msg, key.use(), extra); },
                wipe: key.wipe
            };
        },

        /**
         * One secret for many agreements, held in a context:
         *
         *     var me = p256.ecdh_create();      // a fresh secret; or ecdh_create(sk)
         *     send(me.pk_uncompressed);         // or me.pk, compressed
         *     var shared = me.ecdh(peer);
         *     me.wipe();                        // zeroes the secret; calls then throw
         *
         * The engine imports the secret once instead of on every call
         * (engines/node.js); the pure context holds a copy of it.
         */
        ecdh_create: function (secret) {
            var sk = key_from_seed(name + '.ecdh_create', secret, function () {
                return int2octets(random_secret_below(N, name + '.ecdh_create'));
            });
            if (!API.is_valid_secret(sk)) { throw new Error(name + ': invalid secret key'); }
            var key = held(name, sk);
            return {
                pk: API.get_public_key(sk),
                pk_uncompressed: API.get_public_key(sk, false),
                ecdh: function (peer_public_key) { return API.ecdh(key.use(), peer_public_key); },
                wipe: key.wipe
            };
        },

        ecdh: function (secret, peer_public_key) {
            var d = fn(secret);
            if (!(d > 0n && d < N)) { throw new Error(name + ': invalid secret key'); }
            var Q = API.decode_point(peer_public_key);
            if (Q === null) { throw new Error(name + ': invalid peer public key'); }
            var S = C.to_affine(var_mul(d, C.of(Q.x, Q.y)));
            if (S === null) { throw new Error(name + ': degenerate shared point'); }
            return fb(S.x);
        },

        /**
         * DER, as X.509 and Bitcoin carry it: {r, s} from a SEQUENCE of two
         * INTEGERs, or null. Strict - every non-canonical encoding, every
         * trailing byte refused (commons/der.js, which holds why); that is
         * what Wycheproof's DER files test, and what BIP 66 requires.
         *
         * @return {{r: bigint, s: bigint}|null}
         */
        sig_from_der: function (der) {
            /* through commons/der.js, the library's one strict DER parser: a
               SEQUENCE of exactly two minimal, positive INTEGERs and nothing
               after it (an r or s of zero is no signature either) */
            var c = der_read_seq(der);
            if (!c || c.length !== 2) { return null; }
            var r = der_int_value(c[0]), sv = der_int_value(c[1]);
            if (r === null || sv === null || r === 0n || sv === 0n) { return null; }
            return { r: r, s: sv };
        },

        sig_to_der: function (sig) { return der_seq([der_int(sig.r), der_int(sig.s)]); },

        /**
         * ECPrivateKey (RFC 5915): SEQUENCE { 1, OCTET STRING d, [0] curve OID },
         * without the optional public key - the form composite signatures
         * (RFC 10073) and PKCS #8 carry.
         */
        private_key_to_der: function (secret) {
            var d = fn(secret);
            if (!(d > 0n && d < N)) { throw new Error(name + ': invalid secret key'); }
            if (!params.oid) { throw new Error(name + ': this curve has no OID to name'); }
            return der_seq([der_int(1n), der_octets(int2octets(d)),
                            der_tlv(0xa0, der_oid(params.oid))]);
        },

        /**
         * The secret key of an ECPrivateKey, or null. The curve OID, when
         * present, must be this curve's; an included public key must be the
         * secret's own.
         */
        private_key_from_der: function (der) {
            var c = der_read_seq(der);
            if (!c || c.length < 2 || c.length > 4 || der_int_value(c[0]) !== 1n) { return null; }
            if (c[1].tag !== 0x04 || c[1].content.length !== NBYTES) { return null; }
            var sk = new Uint8Array(c[1].content), d = bytes_to_bigint(sk);
            if (!(d > 0n && d < N)) { return null; }
            var next = 2;
            if (c[next] && c[next].tag === 0xa0) {
                var o = der_read_whole(c[next].content, 0x06);
                if (!o || der_oid_value(o) !== params.oid) { return null; }
                next++;
            }
            if (c[next] && c[next].tag === 0xa1) {
                var bs = der_read_whole(c[next].content, 0x03);
                if (!bs || bs.content[0] !== 0) { return null; }
                var pub = bs.content.subarray(1), mine = API.get_public_key(sk, pub.length === 1 + FBYTES);
                if (pub.length !== mine.length || !mine.every(function (v, i) { return v === pub[i]; })) { return null; }
                next++;
            }
            return next === c.length ? sk : null;
        },

        /** Fixed-width r || s, as most modern protocols use. */
        sig_to_compact: function (sig) {
            var out = new Uint8Array(NBYTES * 2);
            out.set(int2octets(sig.r), 0);
            out.set(int2octets(sig.s), NBYTES);
            return out;
        },

        /**
         * Decode r || s.
         *
         * PLAIN big-endian, not bits2int. Those two differ whenever the order
         * is not a whole number of bytes: for P-521, NBYTES*8 is 528 and the
         * order is 521 bits, so bits2int shifts right by seven. That is
         * correct for a message hash - it is how RFC 6979 truncates to the
         * order's width - and completely wrong for a signature component,
         * which is an integer already in range.
         *
         * The bug was invisible on P-256 and P-384, where the shift is zero,
         * and showed up only as P-521 failing to verify its own bytes after a
         * round trip.
         */
        sig_from_compact: function (b) {
            if (b.length !== NBYTES * 2) { return null; }
            return {
                r: bytes_to_bigint(b.subarray(0, NBYTES)),
                s: bytes_to_bigint(b.subarray(NBYTES))
            };
        }
    };
    return API;
}
