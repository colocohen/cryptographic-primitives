import { bigint_to_bytes, bigint_to_bytes_le,
         bytes_to_bigint, bytes_to_bigint_le, secure_random } from './bytes.js';
import { mod, require_rng } from './primes.js';
import { shake256 } from '../sha3.js';
/**
 * The prime-order group interface
 *
 * Eight files here need an abelian group of prime order and nothing else:
 * frost, musig2, ecvrf, oprf, dleq, adaptor, ring, pedersen. Each is pinned
 * today to whichever curve its author reached for, and none of them contains
 * a line that genuinely depends on the curve - they depend on there being
 * one.
 *
 * Four curve modules already provide the operations, under three different
 * vocabularies. The order of the group is `ORDER`, `CURVE.L` and `CURVE.n`;
 * the generator is `BASE`, `B` and `G`. Same mathematics, three spellings.
 *
 * ==================== decode IS A CONTRACT ====================
 *
 * That is the reason this file exists, and it is not tidiness.
 *
 * The four curves need genuinely different work to answer the same question -
 * "is this byte string a point I may safely use?"
 *
 *   ristretto255   free; the encoding is canonical and there is no cofactor
 *   ed25519        on curve, not the identity, AND [L]P == identity
 *   secp256k1/p256 on curve, in range, not infinity - cofactor is 1
 *
 * The middle row is the one that bites. edwards25519 has cofactor 8, so a
 * point of order 8 decodes cleanly and passes every check RFC 8032 asks for -
 * which is correct for verifying a signature and NOT sufficient for anything
 * that treats the point as a group element. RFC 9591 section 6.1 requires the
 * subgroup test in DeserializeElement and spells it out.
 *
 * Without a shared contract each of the eight callers has to remember this
 * independently. frost.js does not, and is safe today only because it is
 * hardcoded to the one curve where the check is unnecessary. Generalising it
 * without this file would introduce the bug.
 *
 * ==================== AND IT HIDES bits ====================
 *
 * The underlying ladder needs a fixed iteration count. It now throws when one
 * is missing, but it used to return the identity - so a subgroup check written
 * as `mul(ORDER, P) == IDENTITY` reported that every point was in the
 * subgroup, including the ones that were not. A security check that fails
 * open and reads as passing.
 *
 * `mul(k, P)` here supplies the count internally, which makes that mistake
 * unavailable to all eight callers at once.
 *
 * ==================== WHAT IS NOT HERE ====================
 *
 * SCALAR ARITHMETIC. Every operation is `(a op b) % ORDER` on a bigint, so a
 * consumer holding ORDER already has all of it. Including it would mean four
 * implementations of arithmetic that has one.
 *
 * SERIALIZED SIZES. `Ne` and `Ns` look like they belong here and do not: they
 * are ciphersuite choices, not properties of the group. p256 and secp256k1
 * encode Elements in 33 bytes and ristretto255 and ed25519 in 32, but so does
 * every other framing decision in RFC 9591, and those live with the suite.
 *
 * `scalar_from_uniform_bytes`. Ed25519 and ristretto255 reduce a 64-byte
 * digest little-endian; the SEC1 pair use hash_to_field with
 * expand_message_xmd. Same group, DIFFERENT ANSWER depending on the protocol,
 * because interoperating protocols specify the endianness - so it belongs to
 * the protocol, not the group.
 *
 * ==================== WHAT WAS WRONGLY NOT HERE ====================
 *
 * `hash_to_group` was excluded on the same reasoning and should not have
 * been. The two are not alike: a scalar reduction has to match whatever the
 * far side does, byte for byte, while hashing to a point takes its domain
 * separator FROM THE CALLER - so the contract is uniform even though the
 * suite underneath is not.
 *
 *     Map bytes to a group element, deterministically, with no known
 *     discrete log relative to the generator.
 *
 * Which is the same shape as `decode`: one sentence every curve satisfies its
 * own way. Leaving it out meant a caller working over several curves needed a
 * switch - ristretto255 spells it `hash_to_group(msg)`, the others
 * `<curve>_h2c.hash_to_curve(msg, dst)` - which is the divergence this file
 * exists to remove.
 */

/**
 * Build the interface from a curve module's own vocabulary.
 *
 * @param {object} spec
 *   name       {string}    matches the ciphersuite table
 *   ORDER      {bigint}    the prime order
 *   bits       {number}    fixed ladder width for this scalar size
 *   IDENTITY   {object}    the neutral element
 *   GENERATOR  {object}    the fixed base point
 *   add        {function}  (P, Q) -> Element
 *   neg        {function}  (P) -> Element
 *   mul_raw    {function}  (k, P, bits) -> Element, constant time
 *   base_mul   {function}  (k) -> Element, or omitted to use mul_raw
 *   equals     {function}  (P, Q) -> boolean
 *   encode_raw {function}  (P) -> Uint8Array
 *   decode_raw {function}  (bytes) -> Element | null, the curve's own checks
 *   in_subgroup{function}  (P) -> boolean, or omitted when the cofactor is 1
 *   hash       {function}  (msg, dst) -> Element
 */
export function make_group(spec) {
    var ORDER = spec.ORDER;
    var BITS = spec.bits;
    var IDENTITY = spec.IDENTITY;
    var SCALAR_WIDTH = spec.scalar_bytes_length || ((ORDER.toString(2).length + 7) >> 3);
    var UNIFORM_BYTES = (ORDER.toString(2).length + 128 + 7) >> 3;
    function from_uniform(b) {
        if (!(b instanceof Uint8Array) || b.length < UNIFORM_BYTES) {
            throw new RangeError(spec.name + ': a uniform scalar needs at least ' + UNIFORM_BYTES +
                                 ' bytes (the order plus 128 bits), got ' + (b && b.length));
        }
        var v = spec.little_endian ? bytes_to_bigint_le(b) : bytes_to_bigint(b);
        return v % spec.ORDER;
    }

    /*
     * ⛔ A SCALAR OUTSIDE [0, ORDER) WAS TRUNCATED to BITS bits, silently: 2^bits+5
     *    multiplied as 5, a negative scalar as garbage. Every element of this
     *    group has prime order, so k·P = (k mod ORDER)·P exactly — reducing is
     *    the correct answer, not an approximation, and it is what callers meant.
     */
    function reduce(k) {
        if (typeof k !== 'bigint') { throw new TypeError(spec.name + ': scalar must be a bigint'); }
        return (k >= 0n && k < ORDER) ? k : mod(k, ORDER);
    }

    function mul(k, P) {
        return spec.mul_raw(reduce(k), P, BITS);
    }

    return {
        name: spec.name,
        ORDER: ORDER,
        IDENTITY: IDENTITY,
        GENERATOR: spec.GENERATOR,

        add: spec.add,
        neg: spec.neg,
        equals: spec.equals,
        mul: mul,

        /*
         * ⛔⛔ mul_vartime IS NOT A FASTER mul. Its running time depends on
         *   the SCALAR, so calling it on anything secret - a signing key, a
         *   share, a nonce, a blinder - publishes that secret in the timing.
         *   It belongs ONLY in verification, where every scalar arrived on
         *   the wire and is already public.
         *
         * ⭐ IT IS ON THE INTERFACE because without it the group abstraction
         *   had no variable-time multiply at all, so ring, oprf, musig2 and
         *   the zk_* verifiers - everything that works through G.mul - paid
         *   full constant-time cost on public inputs with no way to opt out.
         *   That is roughly a 2x tax on those verify paths.
         *
         * ⚠ IT FALLS BACK TO mul when a curve does not supply one, so a
         *   caller never breaks by reaching for it - which is exactly why
         *   the rule above has to be read rather than discovered.
         */
        mul_vartime: spec.mul_vartime
            ? function (k, P) { return spec.mul_vartime(reduce(k), P); }
            : mul,

        base_mul: spec.base_mul
            ? function (k) { return spec.base_mul(reduce(k)); }
            : function (k) { return mul(k, spec.GENERATOR); },

        /**
         * Map bytes to a group element, deterministically.
         *
         * `dst` separates applications: the same message under two different
         * tags must give two different points, or two protocols sharing a
         * curve share their hashed generators as well.
         */
        /*
         * ⭐ THE EMPTY-DST REFUSAL LIVES HERE, ONCE. RFC 9380 section 3.1
         *   requires a non-empty tag, and every curve's GROUP.hash used to
         *   restate the check with its own wording - 'nist:' for three
         *   different curves, a different sentence for ristretto255. An
         *   empty tag separates nothing, so a caller that omitted it would
         *   believe it had separation it did not have.
         *
         * Absent when the curve has no hash-to-curve suite (pasta), so a
         * caller gets a clear failure at the call site rather than a point
         * that agrees with nothing.
         */
        hash: spec.hash ? function (msg, dst) {
            if (!dst || dst.length === 0) {
                throw new Error(spec.name + ': hash needs a non-empty domain separator');
            }
            return spec.hash(msg, dst);
        } : undefined,

        /* ==================== scalars ====================
         *
         * FROST needs three scalar operations that the point interface does
         * not cover, and they are the only reason frost.js imported one
         * curve directly instead of taking a GROUP.
         *
         * All three derive from ORDER and one fact the curve knows and a
         * generic layer cannot: WHICH END THE BYTES START AT. Edwards curves
         * serialise scalars little-endian, inherited from Ed25519; the
         * Weierstrass ones use big-endian, inherited from the integer
         * conventions of SEC 1 and FIPS 186. Getting it backwards produces
         * signatures that verify against nothing and look like a protocol
         * bug rather than an encoding one.
         */

        /** Reduce into [0, ORDER), accepting negatives. */
        scalar_mod: function (x) { return mod(x, ORDER); },

        /** A scalar as fixed-width bytes, in this curve's byte order. */
        scalar_bytes: function (k) {
            var v = mod(k, ORDER);
            return spec.little_endian
                ? bigint_to_bytes_le(v, SCALAR_WIDTH)
                : bigint_to_bytes(v, SCALAR_WIDTH);
        },

        /**
         * The inverse of scalar_bytes, CANONICAL ONLY: exactly the scalar
         * width, in this curve's byte order, below the order - or null.
         *
         * ⭐ ONE DECODER FOR EVERY PROOF FORMAT. schnorr.js read its response
         *   big-endian on every curve, dleq.js little-endian on every curve,
         *   elgamal.js big-endian at the ORDER's width (56 bytes on ed448,
         *   where scalar_bytes writes 57). Three conventions for one job, and
         *   each canonicality check written separately - the oprf copy was
         *   the one that lacked it.
         */
        scalar_from_bytes: function (b) {
            if (!(b instanceof Uint8Array) || b.length !== SCALAR_WIDTH) { return null; }
            var v = spec.little_endian ? bytes_to_bigint_le(b) : bytes_to_bigint(b);
            return v < ORDER ? v : null;
        },

        /** The width scalar_bytes writes and scalar_from_bytes reads. */
        SCALAR_BYTES: SCALAR_WIDTH,

        /**
         * A WIDE input reduced into the scalar field.
         *
         * The input is deliberately longer than the order - 64 bytes for a
         * 32-byte field - so that reducing it leaves a distribution
         * statistically indistinguishable from uniform. Hashing to exactly
         * the field width and reducing does not: the top values wrap and are
         * twice as likely, which is a bias an adversary can accumulate over
         * many signatures.
         *
         * ⛔ AND "LONGER" IS NOW CHECKED: at least the order's bits + 128
         *   (UNIFORM_BYTES). "64 bytes" was written into callers as a constant,
         *   which is right for a 256-bit order and wrong for P-521 (every
         *   reduced value below 2^512: the top 9 bits of every nonce ZERO) and
         *   brainpoolP512r1 (small values twice as likely). schnorr.js and
         *   dleq.js drew nonces that way - and threshold signing runs
         *   through schnorr.js on P-521 too. A biased nonce is a lattice
         *   attack on the key; refusing the short input closes the class.
         */
        scalar_from_uniform_bytes: from_uniform,

        /** The input width scalar_from_uniform_bytes requires. */
        UNIFORM_BYTES: UNIFORM_BYTES,

        /**
         * A uniform secret scalar in [1, ORDER) - nonces, masks, keys.
         * rng omitted or null draws fresh bytes from the platform.
         */
        random_scalar: function (rng) {
            rng = require_rng(spec.name + '.random_scalar', rng);
            for (var i = 0; i < 64; i++) {
                var k = from_uniform(rng(UNIFORM_BYTES));
                if (k !== 0n) { return k; }
            }
            throw new Error(spec.name + ': rng returned zero scalars');
        },

        /**
         * A scalar derived from bytes - this library's OWN challenges and
         * deterministic nonces (schnorr, dleq, elgamal, pedersen): SHAKE256 to
         * UNIFORM_BYTES, reduced. Not for RFC-fixed derivations, which keep
         * their specified hash in their own files.
         */
        hash_to_scalar: function (msg) {
            return from_uniform(shake256(msg, UNIFORM_BYTES));
        },

        /**
         * RFC 9591 section 3.1: this raises an error on the identity.
         *
         * Serializing the identity is always a bug in the caller - a
         * commitment or a public key that came out as the neutral element
         * means an earlier step went wrong - so this is the one place where
         * throwing is right. Returning some agreed encoding would let the
         * mistake travel.
         */
        encode: function (P) {
            if (spec.equals(P, IDENTITY)) {
                throw new Error(spec.name + ': cannot serialize the identity element');
            }
            return spec.encode_raw(P);
        },


        /**
         * The contract, stated once so eight callers need not each restate it:
         *
         *   Returns a point that is on the curve, is not the identity, and
         *   lies in the prime-order subgroup - or null.
         *
         * NULL RATHER THAN THROWING, deliberately. A malformed element is
         * something a PEER did. In FROST it becomes an identifiable abort
         * naming that peer; an exception would surface as a generic parse
         * failure with nobody named, losing exactly the information the
         * protocol went to trouble to produce.
         */
        decode: function (b) {
            if (!b || b.length !== spec.encoded_length) { return null; }
            var P = spec.decode_raw(b);
            if (P === null || P === undefined) { return null; }
            if (spec.equals(P, IDENTITY)) { return null; }
            if (spec.in_subgroup && !spec.in_subgroup(P)) { return null; }
            return P;
        }
    };
}

/**
 * The same group under another base point.
 *
 * Some protocols fix their own generator rather than the curve's: Zcash's
 * spend authorization signatures multiply by a base found by hashing
 * (reddsa.js), and a FROST ciphersuite over them must commit, sign and verify
 * against that base or its signatures verify against nothing. Every operation
 * on points stays the curve's; only GENERATOR, base_mul and the name change.
 *
 * ⚠ THE NAME MUST CHANGE TOO. Callers check a GROUP against its ciphersuite
 *   by name; a rebased group still called after its curve would pass that
 *   check under a suite expecting the original base.
 *
 * @param {object}   G         a make_group() group
 * @param {string}   name      the new group's name
 * @param {object}   B         the new base point, in G
 * @param {function} [table]   (k) -> k·B, constant time, for k in [0, ORDER)
 *                             - a fixed_base table; G.mul(k, B) when omitted
 */
export function rebased(G, name, B, table) {
    var base_mul = table
        ? function (k) { return table(G.scalar_mod(k)); }
        : function (k) { return G.mul(k, B); };
    return Object.assign({}, G, { name: name, GENERATOR: B, base_mul: base_mul });
}

/**
 * The same interface for a short Weierstrass curve.
 *
 * Three adaptations that Edwards does not need, and that were identical in
 * secp256k1.js and nist.js before this existed:
 *
 *   equals      Weierstrass points carry `is_zero` but no `eq` - the
 *               projective form is not a unique representation, so equality
 *               means subtracting and testing for the neutral element.
 *   encode      encode_point takes affine COORDINATES, not a point.
 *   decode      decode_point returns affine coordinates while the arithmetic
 *               runs projectively.
 *
 * None of it is deep, and all of it is exactly the kind of thing that drifts
 * when it lives in two files: fix the conversion in one and the other keeps
 * the old behaviour, silently.
 *
 * @param {object} spec
 *   name         {string}
 *   ORDER        {bigint}   the group order
 *   bits         {number}   fixed ladder width
 *   POINT        {object}   ZERO, of, is_zero, neg, add, mul, to_affine_public
 *   GENERATOR    {object}
 *   encode_point {function} (x, y, compressed) -> Uint8Array
 *   decode_point {function} (bytes) -> {x, y} | null
 *   encoded_length {number}
 */
export function make_weierstrass_group(spec) {
    var P = spec.POINT;
    return make_group({
        name: spec.name,
        ORDER: spec.ORDER,
        bits: spec.bits,
        IDENTITY: P.ZERO,
        GENERATOR: spec.GENERATOR,
        encoded_length: spec.encoded_length,
        add: P.add,
        neg: P.neg,
        mul_raw: P.mul,
        /*
         * ⭐ k*G THROUGH THE CURVE'S COMB TABLE, when the curve hands one over.
         *   Without it make_group fell back to the ladder on the generator -
         *   measured 3.6 ms against 1.4 ms on secp256k1, for every FROST
         *   commitment, Schnorr nonce and ElGamal ciphertext over these
         *   curves. It must be PROJECTIVE and CONSTANT TIME: ecdsa.js's
         *   base_mul_point, not its affine base_mul, which inverts with the
         *   variable-time Euclid meant for published points.
         */
        base_mul: spec.base_mul,
        /* ⚠ the wNAF multiply lives on the CURVE object, not on POINT -
           spec.mul_vartime is how a Weierstrass curve hands it over. Reading
           it off P silently yields undefined and falls back to the
           constant-time ladder, which looks like it works and simply is not
           faster. */
        mul_vartime: spec.mul_vartime || P.mul_vartime,
        /*
         * `!!` IS LOAD-BEARING. is_zero returns the output of a constant-time
         * comparison, which on these curves is a bigint 1n or 0n rather than
         * a boolean - so equals returned a different TYPE depending on which
         * curve the caller had.
         *
         * `if (equals(a, b))` works either way, which is why it went
         * unnoticed. `equals(a, b) !== false` does not: 0n !== false is true,
         * so a check written that way passes for every pair of points,
         * including unequal ones. Same failure mode as a ladder with no bit
         * count - open, and reading as healthy.
         */
        equals: function (A, B) { return !!P.is_zero(P.add(A, P.neg(B))); },
        /* constant-time affine: most encoded points come from secrets (see
           commons/eddsa.js encode_point) */
        encode_raw: function (Q) {
            var A = P.to_affine(Q);
            return spec.encode_point(A.x, A.y, true);
        },
        decode_raw: function (b) {
            var A = spec.decode_point(b);
            return A === null ? null : P.of(A.x, A.y);
        },
        hash: spec.hash
        /* no in_subgroup: both SEC1 curves here have cofactor 1 */
    });
}

/**
 * The GROUP for a curve built by commons/ecdsa.js.
 *
 * secp256k1.js, nist.js and brainpool.js all need the same binding - the
 * curve's POINT, generator, SEC 1 codec, comb-table base_mul and wNAF
 * mul_vartime - and nist.js had its own constructor for its three while
 * secp256k1.js spelled the same fields out again. nist's version also forgot
 * mul_vartime, so P-256's GROUP verified at constant-time cost.
 *
 * @param {object}   E     an ecdsa() instance
 * @param {function} [hash] (msg, dst) -> projective point, when the curve
 *                          has an RFC 9380 suite
 */
export function ecdsa_group(name, E, hash) {
    return make_weierstrass_group({
        name: name,
        ORDER: E.CURVE.n,
        bits: E.CURVE.n.toString(2).length,
        POINT: E.POINT,
        GENERATOR: E.G,
        /* the field width in bytes, plus the SEC1 prefix (P-521: 66 + 1) */
        encoded_length: E.BYTES + 1,
        encode_point: E.encode_point,
        decode_point: E.decode_point,
        base_mul: E.base_mul_point,
        mul_vartime: E.mul_vartime,
        hash: hash
    });
}


/* ==================== keygen ====================
 *
 * Every curve module's keygen(seed) is built from the three below, so the
 * rule is stated once: a seed given IS the secret key, in the module's own
 * encoding, and is checked exactly as the module's get_public_key checks
 * it; a seed omitted or null is fresh randomness from the platform.
 */

/**
 * A uniform secret scalar in [1, limit), from the platform's randomness.
 *
 * REJECTION SAMPLING, NOT REDUCTION: limit's byte length is drawn, the bits
 * above limit's width are masked off, and a value outside [1, limit) is
 * drawn again. Reducing a wider draw would do too, but only with the 128
 * extra bits random_scalar spends; this needs none, and every draw is kept
 * with probability above one half.
 *
 * @param {bigint} limit  the exclusive bound - the order, or n - 1 for SM2
 */
export function random_secret_below(limit, who) {
    var bits = (limit - 1n).toString(2).length;
    var width = (bits + 7) >> 3;
    var top = 0xff >> (width * 8 - bits);
    for (var i = 0; i < 256; i++) {
        var b = secure_random(width);
        b[0] &= top;
        var v = bytes_to_bigint(b);
        b.fill(0);
        if (v > 0n && v < limit) { return v; }
    }
    throw new Error(who + ': the platform rng gave no usable scalar in 256 draws');
}

/**
 * keygen's secret key: a COPY of the caller's seed (so zeroing one leaves
 * the other), or `fresh()` when the seed is omitted or null.
 */
export function key_from_seed(who, seed, fresh) {
    if (seed == null) { return fresh(); }
    if (!(seed instanceof Uint8Array)) {
        throw new TypeError(who + ': seed must be a Uint8Array, or left out (or null) for a fresh key');
    }
    return new Uint8Array(seed);
}

/**
 * keygen(seed) for a GROUP whose secret key is a bare scalar (ristretto255,
 * decaf448, jubjub, Pallas, Vesta): { sk: scalar_bytes(k), pk: encode(k·G) }.
 * A seed given is that scalar's encoding - canonical, nonzero, or refused.
 *
 * @param {Uint8Array} [seed]  G.SCALAR_BYTES bytes; omitted or null draws a fresh key
 */
export function group_keygen(G, seed) {
    var who = G.name + '.keygen';
    var sk = key_from_seed(who, seed, function () {
        return G.scalar_bytes(random_secret_below(G.ORDER, who));
    });
    var k = G.scalar_from_bytes(sk);
    if (k === null || k === 0n) {
        throw new Error(who + ': the seed must be a canonical nonzero scalar of ' + G.SCALAR_BYTES + ' bytes');
    }
    return { sk: sk, pk: G.encode(G.base_mul(k)) };
}
