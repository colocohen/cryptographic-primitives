/**
 * EdDSA  -  RFC 8032
 *
 * Generic over Ed25519 and Ed448. Only the curve, the hash and a few
 * encoding widths differ, so only those are arguments - the same split as
 * commons/ecdsa.js, made for the same reason.
 *
 * HOW IT DIFFERS FROM ECDSA, AND WHY THAT MATTERS
 *
 *   - The nonce is a HASH of the private key and the message, not a random
 *     value and not an HMAC construction bolted on afterwards. RFC 6979 had
 *     to be invented to retrofit that onto ECDSA; EdDSA has had it since
 *     2011. There is no nonce for a caller to supply and none to get wrong.
 *
 *   - No modular inversion anywhere in signing. ECDSA computes k^-1, which is
 *     both slow and the thing that makes multi-party ECDSA hard.
 *
 *   - The private key is a SEED, not a scalar. The scalar is derived by
 *     hashing the seed and clamping the result, so every valid 32-byte string
 *     is a valid key - there is no range check to forget and no invalid key
 *     to handle.
 *
 * CLAMPING. Three bits at the bottom of the scalar are cleared and one near
 * the top is set. Clearing the low bits forces the scalar to be a multiple of
 * the cofactor, which neutralises small-subgroup attacks; setting the high
 * bit fixes the scalar's length so a variable-time ladder cannot leak it. It
 * is a small, ugly, extremely effective piece of engineering.
 */

import { field } from './modp.js';
import { edwards, sqrt_ratio } from './edwards.js';
import { concat, bytes_to_bigint_le, bigint_to_bytes_le, secure_random } from './bytes.js';
import { fixed_base, base_table, double_mul_base, msm, msm_group } from './fixed_window.js';
import { batch_weight, batch_all, batch_find, batch_items } from './batch.js';
import { key_from_seed } from './group.js';

/*
 * Below this many signatures a batch is checked one by one: the msm's
 * buckets cost more than they save (measured, Ed25519: a batch of 1 is 1.7x
 * slower than verify, 8 is about even, 64 is 2.4x faster). The answer is the
 * same either way.
 */
var BATCH_MIN = 8;

/**
 * @param {object} params
 *   p, a, d, L        the curve and the group order
 *   cofactor          8 for Ed25519, 4 for Ed448
 *   Gx, Gy            the base point
 *   hash              the hash, taking (Uint8Array) -> Uint8Array
 *   bytes             encoded point / signature-half width
 *   clamp             function mutating the hashed seed in place
 *   sqrt_mode         8 for p = 5 mod 8, 4 for p = 3 mod 4
 *   scalar_bits       fixed ladder width
 *   pure_uses_dom     true if the PURE variant already carries a domain
 *                     prefix - Ed448 does, Ed25519 does not
 *   dom_prefix        the domain string, needed by the ctx and ph variants
 *                     even where the pure variant has none
 *   prehash           the function the ph variants apply to the message
 */
export function eddsa(params) {
    var F = field(params.p);
    var C = edwards(F, params.a, params.d);
    var B = C.of(params.Gx, params.Gy);
    var L = params.L;
    var BYTES = params.bytes;
    var HASH = params.hash;
    var SQRT = params.sqrt_mode;
    var BITS = params.scalar_bits;

    /*
     * See commons/ecdsa.js. The generator's table is built on first use, so a
     * caller who only verifies never pays to construct it.
     */
    var base_mul = fixed_base(C, B, BITS, 4);
    /* the generator's verification table: odd multiples at w = 8, cached form, built once */
    var B_TABLE = base_table(C, B, 8);
    var MSM_G = msm_group(C);

    /**
     * Point encoding: y little-endian, with the low bit of x in the TOP bit.
     *
     * Edwards curves compress for free - every y has at most two x values and
     * one bit distinguishes them, exactly as in SEC 1, but with no 0x02/0x03
     * prefix byte because the spare bit already exists in y's encoding.
     */
    /*
     * ⛔ THROUGH THE CONSTANT-TIME INVERSE, always. Most points encoded here
     *   come from a secret scalar - the public key, R in every signature -
     *   and their projective Z depends on it; timing a variable-time
     *   inversion of Z leaks scalar bits (Naccache, Smart and Stern, PKC
     *   2004). One rule for every encoder in the library. Since 11-11 the
     *   constant-time inverse is the BLINDED one (modp inv_blinded, through
     *   C.to_affine): the same protection at about a tenth of Fermat's cost.
     */
    function encode_point(P) {
        var A = C.to_affine(P);
        var out = new Uint8Array(BYTES);
        var yb = F.to_bytes_le(A.y);
        out.set(yb.subarray(0, BYTES), 0);
        out[BYTES - 1] |= (A.x & 1n) === 1n ? 0x80 : 0x00;
        return out;
    }

    /**
     * @return {object|null} null when the bytes are not a valid point
     */
    function decode_point(b) {
        if (b.length !== BYTES) { return null; }
        var buf = new Uint8Array(b);
        var x_odd = (buf[BYTES - 1] & 0x80) !== 0;
        buf[BYTES - 1] &= 0x7f;
        var y = F.from_bytes_le(buf);
        if (y >= F.p) { return null; }

        /* x^2 = (y^2 - 1) / (d*y^2 - a) */
        var y2 = F.sqr(y);
        var u = F.sub(y2, 1n);
        var v = F.sub(F.mul(params.d, y2), params.a);
        var x = sqrt_ratio(F, u, v, SQRT);
        if (x === null) { return null; }

        /* x = 0 with the sign bit set is not a canonical encoding */
        if (x === 0n && x_odd) { return null; }
        if (((x & 1n) === 1n) !== x_odd) { x = F.neg(x); }
        return C.of(x, y);
    }

    /** The hashed, clamped seed: the scalar and the nonce prefix. */
    function expand(seed) {
        if (seed.length !== BYTES) {
            throw new Error(params.name + ': secret key must be ' + BYTES + ' bytes');
        }
        var h = HASH(seed);
        var half = h.length >> 1;
        var s = new Uint8Array(h.subarray(0, half));
        params.clamp(s);
        return { scalar: F.from_bytes_le(s), prefix: h.subarray(half) };
    }

    function mod_L(b) { return bytes_to_bigint_le(b) % L; }

    /*
     * Little-endian encoding at an EXPLICIT width. F.to_bytes_le in
     * commons/modp.js is always at the FIELD's width, and EdDSA needs the
     * SCALAR's - Ed448's field is 56 bytes while its encoded values are 57 -
     * which is why F.to_bytes_le cannot be used here. commons/bytes.js's
     * bigint_to_bytes_le takes the width as an argument, which is exactly
     * this; the local copy written for that reason went.
     */
    var le_bytes = bigint_to_bytes_le;

    /**
     * The domain prefix.
     *
     * RFC 8032 defines three variants per curve and they differ ONLY here:
     *
     *   pure       Ed25519: no prefix at all.  Ed448: dom4(0, ctx).
     *   ctx        dom(0, ctx)  - binds a context string
     *   ph         dom(1, ctx)  - the message arrives already hashed
     *
     * Pure Ed25519 having no prefix while every other variant does is the
     * single most confusing thing in RFC 8032, and it is not an oversight:
     * pure Ed25519 was deployed years before the context variants existed, so
     * adding a prefix would have broken every existing signature.
     *
     * The phflag byte is what keeps a prehashed signature from verifying as a
     * plain one over the digest. Without it the two would be the same
     * computation, and a signature over H(m) could be replayed as a signature
     * over the 64-byte string H(m).
     */
    function dom(ctx, phflag, force) {
        if (!force && !params.pure_uses_dom) { return new Uint8Array(0); }
        var c = ctx || new Uint8Array(0);
        if (c.length > 255) { throw new Error(params.name + ': context too long'); }
        var tag = params.dom_prefix;
        var out = new Uint8Array(tag.length + 2 + c.length);
        out.set(tag, 0);
        out[tag.length] = phflag ? 1 : 0;
        out[tag.length + 1] = c.length;
        out.set(c, tag.length + 2);
        return out;
    }

    var API = {
        CURVE: params,
        FIELD: F,
        POINT: C,
        B: B,
        BYTES: BYTES,
        SIG_BYTES: BYTES * 2,

        encode_point: encode_point,
        decode_point: decode_point,

        /*
         * The hashed, clamped seed: {scalar, prefix}. EXPOSED because ecvrf.js
         * and key_blind.js need exactly RFC 8032's key derivation - RFC 9381
         * and the key-blinding draft both specify it so an Ed25519 key can be
         * reused - and each had written the hash, the split and the clamp
         * out again by hand.
         */
        expand: expand,

        /**
         * @param  {Uint8Array} seed  the private key
         * @return {Uint8Array} the encoded public point
         */
        /**
         * k * B, through the precomputed table this module already builds.
         *
         * ⭐ THE TABLE EXISTED AND WAS UNREACHABLE. sign and get_public_key
         *   used it; nothing outside could, so a caller wanting k*B for a
         *   commitment or a share paid for a generic variable-base multiply.
         *
         *   Measured on the equivalent secp256k1 path: 0.57 ms through the
         *   table against 4.42 ms without - a factor of 7.8 lost to a
         *   missing export.
         *
         * ⚠ THE SCALAR IS NOT CLAMPED HERE. sign and get_public_key clamp
         *   because RFC 8032 requires it for key derivation; a caller doing
         *   arbitrary group arithmetic does not want that, and clamping
         *   silently would give an answer that is wrong for every use except
         *   the one it was copied from.
         */
        base_mul: function (k) {
            return base_mul(k);
        },

        get_public_key: function (seed) {
            var e = expand(seed);
            return encode_point(base_mul(e.scalar));
        },

        /**
         * A key pair: { sk, pk } as sign, verify and get_public_key take
         * them. The secret key IS the seed, so sk is a copy of it.
         *
         * @param {Uint8Array} [seed]  BYTES bytes (32 for Ed25519, 57 for
         *   Ed448); omitted or null draws a fresh one from the platform
         */
        keygen: function (seed) {
            var sk = key_from_seed(params.name + '.keygen', seed, function () { return secure_random(BYTES); });
            return { sk: sk, pk: API.get_public_key(sk) };
        },

        /**
         * @param {Uint8Array} msg
         * @param {Uint8Array} seed
         * @param {Uint8Array} [ctx]  context string, Ed448 only
         *
         * ⛔ NO public_key ARGUMENT. It used to accept the signer's public key
         *   "to save a scalar multiplication", documented as untrusted - and
         *   it was not harmless: r = H(prefix || M) does not depend on A, so
         *   two signatures of one message under two different A share r and
         *   give the secret scalar as (S1 - S2) / (k1 - k2). That is the
         *   double-public-key oracle that hit several Ed25519 libraries in
         *   2022. A is derived from the secret, always.
         */
        sign: function (msg, seed, ctx) {
            return API.sign_variant(msg, seed, ctx, 0);
        },

        /**
         * @param {number} variant  0 = pure, 1 = ctx, 2 = ph
         */
        sign_variant: function (msg, seed, ctx, variant) {
            return API.sign_expanded(msg, expand(seed), ctx, variant);
        },

        /**
         * RFC 8032 signing from an ALREADY-EXPANDED key: {scalar, prefix}.
         *
         * ⭐ THE ONE COPY OF STEPS 2-6. key_blind.js signs under a blinded
         *   scalar s1*s2 with the two prefixes concatenated - not a key any
         *   seed expands to - and used to restate r, R, k and S here line for
         *   line to do it. Everything after the expansion is identical, so it
         *   is one function and sign_variant is expand-then-this.
         *
         * A is computed from e.scalar here, never taken from the caller (see
         *   sign above).
         */
        sign_expanded: function (msg, e, ctx, variant) {
            return sign_with(msg, e, encode_point(base_mul(e.scalar)), ctx, variant);
        },

        /**
         * ⭐ A SIGNER FOR ONE KEY: the seed expanded, and A computed from it,
         *    ONCE — then each message costs one base multiplication, not two
         *    (measured, Ed25519 in JS: 1.2 ms → 0.6 ms a signature). Same
         *    bytes as sign(), always.
         *
         *    ⛔ A IS STILL DERIVED FROM THE SECRET, never taken from a caller
         *       (see sign above): this is the same computation, kept rather
         *       than repeated.
         *
         * @param {Uint8Array} seed
         * @param {Uint8Array} [ctx]       with variant 1 or 2
         * @param {number}     [variant]   0 = pure (default), 1 = ctx, 2 = ph
         * @return {{ sign: function(Uint8Array): Uint8Array, wipe: function() }}
         *
         * wipe() zeroes the prefix and drops the scalar (a BigInt, which
         * cannot be overwritten); sign() then throws.
         */
        signer_create: function (seed, ctx, variant) {
            var e = expand(seed);
            var A = encode_point(base_mul(e.scalar));
            var v = variant === undefined ? 0 : variant;
            return {
                sign: function (msg) {
                    if (e === null) { throw new Error(params.name + ': the signer was wiped'); }
                    return sign_with(msg, e, A, ctx, v);
                },
                wipe: function () { if (e !== null) { e.prefix.fill(0); e = null; } }
            };
        },

        /**
         * ⭐ A VERIFIER FOR ONE PUBLIC KEY: the key decoded (a square root)
         *    once, not per signature. Same answers as verify(), never throws;
         *    a key that does not decode gives a verifier that accepts nothing.
         */
        verifier_create: function (public_key, ctx, variant, mode) {
            var v = variant === undefined ? 0 : variant;
            var holds = equation(mode);
            var A = public_key instanceof Uint8Array && public_key.length === BYTES ? decode_point(public_key) : null;
            return {
                verify: function (msg, sig) {
                    if (A === null) { return false; }
                    var x = verify_input(msg, sig, public_key, A, ctx, v);
                    return x !== null && holds(x);
                }
            };
        },

        /**
         * @return {boolean}
         *
         * Uses the cofactored equation, [h]S*B == [h]R + [h]k*A, where h is
         * the curve's cofactor - 8 for Ed25519 and 4 for Ed448. RFC 8032
         * permits either form; the cofactored one accepts a strictly larger
         * set of signatures and is what makes different implementations agree
         * on edge cases involving small-order points. The alternative is
         * stricter and has caused real interoperability failures between
         * libraries that chose differently.
         */
        verify: function (msg, sig, public_key, ctx, mode) {
            return API.verify_variant(msg, sig, public_key, ctx, 0, mode);
        },

        /**
         * @param {string} [mode]  which of RFC 8032's two verifications:
         *
         *   'cofactored' (the default)  [h]S*B == [h]R + [h]k*A, as above.
         *   'strict'                    S*B == R + k*A without the cofactor,
         *                               and R and A rejected when they are
         *                               of small order - libsodium's rule.
         *
         * Honest signatures verify under both. They part only on crafted
         * ones - small-order components in R or A - and a caller that must
         * give the same answer as libsodium chooses 'strict'. Checked against
         * the twelve cases of ed25519-speccheck: 'strict' agrees with
         * libsodium on all twelve. (OpenSSL's rule is a third one;
         * engines/node.js asks it only where its answer is this one.)
         */
        verify_variant: function (msg, sig, public_key, ctx, variant, mode) {
            var holds = equation(mode);
            var v = verify_input(msg, sig, public_key, null, ctx, variant);
            return v !== null && holds(v);
        },

        /**
         * ⭐ BATCH VERIFICATION: true when every item verifies, checked as one
         *    equation over random 128-bit weights z_i,
         *
         *        h·( Σ z_i·R_i + Σ (z_i·k_i)·A_i − (Σ z_i·S_i)·B ) == O
         *
         *    in one msm (commons/fixed_window.js). h is the cofactor, as in
         *    verify: the batch is the cofactored equation summed.
         *
         * ⭐ THE SAME ANSWERS AS verify, BY CONSTRUCTION. Every item goes
         *    through verify_input - verify's own length, decoding, S < L and
         *    challenge - so no input passes one and fails the other there.
         *    Then:
         *      - every item verifies ⇒ each h·(S_i·B − R_i − k_i·A_i) = O, and
         *        so does the weighted sum: the batch accepts, always. (The
         *        scalars are reduced mod L; what that changes on a point with
         *        a small-order part is killed by the final h, since every
         *        point's order divides h·L.)
         *      - an item fails ⇒ h·(S_i·B − R_i − k_i·A_i) is a point of
         *        order L, and the sum hits O only if z_i lands on one value
         *        mod L: probability 2^-128, over randomness drawn after the
         *        signatures are fixed. This is the one way a batch can
         *        differ from verify, and no batch check can do without it.
         *
         * @param items  [{ msg, sig, pk, ctx? }]  (ctx: the context, Ed448)
         * @param opts   { rng } — 16 bytes per item; the CSPRNG by default
         */
        verify_batch: function (items, opts) {
            var c = batch_checks(items, opts, 'verify_batch');
            return batch_all(items, c.holds, c.one, BATCH_MIN);
        },

        /**
         * Which items do NOT verify: their indices, ascending ([] when all
         * do) - exactly the ones verify rejects (commons/batch.js).
         */
        verify_batch_find: function (items, opts) {
            var c = batch_checks(items, opts, 'verify_batch_find');
            return batch_find(items, c.holds, c.one, BATCH_MIN);
        }
    };

    function batch_checks(items, opts, who) {
        batch_items(items, params.name + ' ' + who);
        var o = opts || {}, rng = o.rng || secure_random, variant = o.variant === undefined ? 0 : o.variant;
        return {
            holds: function (sub) { return batch_holds(sub, rng, variant); },
            one: function (it) { return API.verify_variant(it.msg, it.sig, it.pk, it.ctx, variant); }
        };
    }

    /*
     * The batch equation, for items that are all past verify_input. Items
     * that share an encoded public key share its decoding (a square root)
     * and one msm term: their A is the same point, so the weights add (a
     * node checks many transactions from one sender).
     */
    function batch_holds(items, rng, variant) {
        var scalars = [], points = [], by_key = new Map(), sB = 0n;
        for (var i = 0; i < items.length; i++) {
            var it = items[i];
            var key = it.pk instanceof Uint8Array && it.pk.length === BYTES ? String.fromCharCode.apply(null, it.pk) : null;
            var at = key === null ? undefined : by_key.get(key);
            var v = verify_input(it.msg, it.sig, it.pk, at === undefined ? null : points[at], it.ctx, variant);
            if (v === null) { return false; }
            var z = batch_weight(rng, params.name + ' verify_batch');
            sB = (sB + z * v.S) % L;
            scalars.push(z);
            points.push(v.R);
            var zk = (z * v.k) % L;
            if (at === undefined) {
                if (key === null) { scalars.push(zk); points.push(v.A); continue; }
                by_key.set(key, scalars.length);
                scalars.push(zk);
                points.push(v.A);
            } else {
                scalars[at] = (scalars[at] + zk) % L;
            }
        }
        scalars.push((L - sB) % L);
        points.push(B);
        /* every scalar is public - a weight drawn here or a value from a signature - so the variable-time msm is right */
        var sum = msm(MSM_G, scalars, points);
        for (var d = 1n; d < params.cofactor; d <<= 1n) { sum = C.dbl(sum); }
        return C.eq(sum, C.ZERO);
    }

    /* RFC 8032 §5.1.6 steps 2-6, from the expanded key and its encoded A */
    function sign_with(msg, e, A, ctx, variant) {
        if (variant === 2) { msg = params.prehash(msg); }
        var pre = dom(ctx, variant === 2, variant !== 0);

        var r = mod_L(HASH(concat([pre, e.prefix, msg])));
        var R = encode_point(base_mul(r));
        var k = mod_L(HASH(concat([pre, R, A, msg])));
        var S = (r + k * e.scalar) % L;

        var sig = new Uint8Array(BYTES * 2);
        sig.set(R, 0);
        sig.set(le_bytes(S, BYTES), BYTES);
        return sig;
    }

    /*
     * RFC 8032 §5.1.7 steps 1 and 2: everything verify checks before the
     * equation, giving { A, R, S, k }, or null. ⭐ ONE FUNCTION for verify,
     * verifier and both batch checks, so they cannot disagree on an input
     * (decoding, S < L, the challenge). A: already decoded (verifier), or
     * null to decode public_key here.
     */
    function verify_input(msg, sig, public_key, A, ctx, variant) {
        if (A === null) {
            if (public_key.length !== BYTES) { return null; }
            A = decode_point(public_key);
            if (A === null) { return null; }
        }
        if (!(sig instanceof Uint8Array) || sig.length !== BYTES * 2) { return null; }
        if (variant === 2) { msg = params.prehash(msg); }

        var R = decode_point(sig.subarray(0, BYTES));
        if (R === null) { return null; }

        var S = bytes_to_bigint_le(sig.subarray(BYTES, 2 * BYTES));
        /* a non-canonical S is a malleability hole - reject it */
        if (S >= L) { return null; }

        var pre = dom(ctx, variant === 2, variant !== 0);
        var k = mod_L(HASH(concat([pre, sig.subarray(0, BYTES), public_key, msg])));
        return { A: A, R: R, S: S, k: k };
    }

    function equation(mode) {
        if (mode === undefined || mode === 'cofactored') { return cofactored_holds; }
        if (mode === 'strict') { return strict_holds; }
        throw new Error(params.name + ": verify mode must be 'cofactored' or 'strict'");
    }

    /* [h]P is the identity: P lies entirely in the small torsion subgroup. */
    function small_order(P) {
        var Q = P;
        for (var d = 1n; d < params.cofactor; d <<= 1n) { Q = C.dbl(Q); }
        return C.eq(Q, C.ZERO);
    }

    /*
     * RFC 8032 §5.1.7 step 3 without the cofactor, S*B == R + k*A, checked
     * as S*B - k*A == R in the same interleaved pass as the cofactored form;
     * a small-order R or A is refused first, and so is a non-canonical one:
     * libsodium's rule, on all twelve ed25519-speccheck cases.
     */
    function strict_holds(v) {
        if (small_order(v.A) || small_order(v.R)) { return false; }
        var lhs = double_mul_base(C, v.S, B_TABLE, v.k, C.neg(v.A), 5);
        return C.eq(lhs, v.R);
    }

    /* RFC 8032 §5.1.7 step 3, cofactored: [h]S*B == [h]R + [h]k*A */
    function cofactored_holds(v) {
        var A = v.A, R = v.R, S = v.S, k = v.k;
        var h = params.cofactor;

        /*
         * The equation is (S*h)*B == h*R + (k*h)*A, and it is checked as
         *
         *     (S*h)*B - (k*h)*A == h*R
         *
         * so the two expensive multiplications share their doublings in
         * one interleaved pass. Negating A turns the subtraction into an
         * addition, which on an Edwards curve is negating one coordinate.
         *
         * h*R is a cofactor multiplication - three doublings for h = 8 -
         * so it is not worth a window.
         *
         * Every scalar here comes from the signature or the public key,
         * so the variable-time path is correct.
         */
        var kh = (k * h) % (L * h);
        var lhs = double_mul_base(C, S * h, B_TABLE, kh, C.neg(A), 5);

        var rhs = R;
        for (var d = 1n; d < h; d <<= 1n) { rhs = C.dbl(rhs); }

        return C.eq(lhs, rhs);
    }

    return API;
}
