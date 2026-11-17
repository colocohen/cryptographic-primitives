/**
 * Shared plumbing for the sigma protocols.
 *
 * Three files - paillier_range, paillier_log (since removed: CGGMP21's
 * current revision has no Pi^log*) and zk_cmp - grew the same two
 * pieces independently, which is the point at which they stop being local
 * detail. Both are the kind of thing that is easy to write slightly
 * differently in two places and hard to notice: a proof produced by one and
 * verified by the other would simply fail, with no error to read.
 */

import { concat, be16, be32, ascii, utf8, bytes_to_bigint, bigint_to_bytes,
         bigint_to_bytes_le } from './bytes.js';
import { mod, powmod_signed, powmod_signed_ct, random_signed_below, in_range,
         random_below_biased, random_unit, random_quadratic_residue,
         prime_from_stream, require_rng } from './primes.js';
import { xof_stream } from './xof_stream.js';
import { shake256 } from '../sha3.js';

/**
 * The byte width of a bigint's magnitude.
 *
 * bigint_to_bytes takes a WIDTH and pads to it; passing 0 returns an empty
 * array, silently. These values have no natural width - a challenge response
 * is whatever size it came out - so the width is computed and carried. That
 * mistake was made once here and only the encode/decode round-trip test
 * caught it, because verification never calls the encoder.
 */
export function byte_width(v) {
    var bits = (v < 0n ? -v : v).toString(2).length;
    return (bits + 7) >> 3;
}

/**
 * A signed bigint as sign byte, length, magnitude.
 *
 * The sign travels because these are INTEGERS, not residues: reducing z1 into
 * a range would destroy the bound the proofs rest on, so it can genuinely be
 * negative and the encoding has to say so.
 */
export function int_bytes(v) {
    var neg = v < 0n;
    var a = neg ? -v : v;
    var b = bigint_to_bytes(a, byte_width(a));
    return concat([new Uint8Array([neg ? 1 : 0]), be16(b.length), b]);
}

/**
 * The inverse of int_bytes - CANONICAL ONLY: sign byte 0 or 1, at least one
 * magnitude byte, no leading zero byte (zero is the single byte 0x00), no -0.
 * Anything else would let several byte strings carry one proof, which breaks
 * whatever compares or hashes proofs by their bytes (an echo broadcast).
 *
 * @return {{value: bigint, next: number}|null}  null if short or non-canonical
 */
export function read_int(bytes, off) {
    if (off + 3 > bytes.length) { return null; }
    var sign = bytes[off];
    var len = (bytes[off + 1] << 8) | bytes[off + 2];
    if (sign > 1 || len === 0 || off + 3 + len > bytes.length) { return null; }
    if (bytes[off + 3] === 0 && (len > 1 || sign === 1)) { return null; }
    var v = bytes_to_bigint(bytes.subarray(off + 3, off + 3 + len));
    return { value: sign === 1 ? -v : v, next: off + 3 + len };
}

/* ==================== Fiat-Shamir: one expander ==================== */

/*
 * EVERY NON-STANDARD PROOF IN THIS LIBRARY DERIVES ITS CHALLENGE HERE.
 *
 * There were seven expanders: expand_challenge (sha256 in counter mode, 16
 * bytes of slack), ring_pedersen's challenge_bits, challenge_values and
 * large_challenge, the single-digest digest_challenge of Pi_dlenc and Pi_sig,
 * zk_fac_sp's sha512 challenge, and two in primes/vdf for primes and group
 * elements. Each framed its input differently, each reduced differently, and
 * two of them had quirks nobody chose: digest_challenge's sign bit WAS the
 * magnitude's low bit at ell = 256, and it silently capped ell at the digest
 * width. They are one construction now:
 *
 *     fs_stream(tag, sid, parts)  ->  read(n), a SHAKE256 stream over
 *         "cryptographic-primitives/fs/v1" | tag | sid | count | part_1 | ... | part_k
 *
 * with every field length-prefixed and every part TYPE-tagged (bytes, an
 * integer, a string), so no two transcripts frame to the same input - a
 * bigint and its own byte encoding hash differently, and moving a boundary
 * between two parts changes a length. Everything a proof needs is a thin
 * reading of that stream:
 *
 *     fs_bits     count bits                   Pi_prm, Pi_df
 *     fs_uint     uniform in [0, 2^bits)       Pi_sch, Pi_df*
 *     fs_signed   uniform in +-(2^bits - 1), the sign from its OWN byte
 *     fs_below    below a bound, 16 extra bytes (primes.random_below_biased)
 *     fs_unit     a unit mod N (primes.random_unit)                  Pi_mod
 *     fs_qr       a square mod N (primes.random_quadratic_residue)   vdf
 *     fs_prime    a prime of a given width (primes.prime_from_stream)
 *
 * The samplers are the SAME functions the provers use with a real rng; the
 * stream simply takes the rng's place. So "uniform below N" means one thing
 * whether the bytes are random or derived.
 *
 * ⚠ EVERY TAG THAT MOVED HERE WAS BUMPED A VERSION, so a transcript built the
 *   old way and one built this way can never be mistaken for each other.
 *
 * ⛔ NOT FOR STANDARD CHALLENGES. RFC 9591, RFC 9497, RFC 9381 and BIP-340
 *   fix their challenge bytes; those stay exactly as their specifications
 *   say, in their own files.
 */

var FS_CORE = /* @__PURE__ */ ascii('cryptographic-primitives/fs/v1');

function fs_part(v) {
    if (v instanceof Uint8Array) { return concat([new Uint8Array([0]), be32(v.length), v]); }
    if (typeof v === 'bigint')   { return concat([new Uint8Array([1]), int_bytes(v)]); }
    if (typeof v === 'string')   { var u = utf8(v); return concat([new Uint8Array([2]), be32(u.length), u]); }
    throw new TypeError('fs: a transcript part must be bytes, a bigint or a string');
}

/**
 * The transcript stream.
 *
 * @param {string}     tag    the proof's domain tag, versioned
 * @param {Uint8Array} sid    the session binding (may be empty, never absent)
 * @param {Array}      parts  Uint8Array | bigint | string, in a fixed order
 * @return {function}  read(n) -> n fresh bytes, the next n of the stream
 */
export function fs_stream(tag, sid, parts) {
    if (!(sid instanceof Uint8Array)) { throw new TypeError('fs: sid must be a Uint8Array'); }
    var tb = ascii(tag);
    var enc = [FS_CORE, be16(tb.length), tb, be32(sid.length), sid, be32(parts.length)];
    for (var i = 0; i < parts.length; i++) { enc.push(fs_part(parts[i])); }
    var x = xof_stream(shake256, concat(enc), 256);
    /* a copy: xof_stream's views are invalidated by its next refill */
    return function read(n) { return x.read(n).slice(); };
}

/** `count` bits, least significant first within each byte. */
export function fs_bits(read, count) {
    var b = read((count + 7) >> 3), out = [];
    for (var i = 0; i < count; i++) { out.push((b[i >> 3] >> (i & 7)) & 1); }
    return out;
}

/** Uniform in [0, 2^bits) - exactly, by masking, so no slack is needed. */
export function fs_uint(read, bits) {
    var bytes = (bits + 7) >> 3;
    return bytes_to_bigint(read(bytes)) >> BigInt(bytes * 8 - bits);
}

/**
 * Uniform magnitude below 2^bits with a sign from a SEPARATE byte, so the
 * value lies in +-(2^bits - 1) and the sign is independent of the magnitude.
 */
export function fs_signed(read, bits) {
    var v = fs_uint(read, bits);
    return (read(1)[0] & 1) ? -v : v;
}

export function fs_below(read, bound) { return random_below_biased(bound, read); }
export function fs_unit(read, N)      { return random_unit(N, read); }
export function fs_qr(read, N)        { return random_quadratic_residue(N, read); }
export function fs_prime(read, bits)  { return prime_from_stream(bits, read); }


/**
 * The session identifier, checked rather than defaulted.
 *
 * Five proof files repeat this, and the repetition is the point: an unbound
 * proof verifies in every run with the same statement, so a default of
 * "empty" would make replayability the behaviour a caller reaches by
 * forgetting. Passing an empty array is still allowed - it just has to appear
 * in the caller's own source rather than in its absence.
 *
 * @param {string}     who  the module name, for the message
 * @param {Uint8Array} sid
 */
export function require_sid(who, sid) {
    if (sid === undefined || sid === null) {
        throw new Error(who + ': sid is required - pass an empty Uint8Array ' +
                        'to opt out deliberately');
    }
    return sid;
}

/**
 * A fixed-width little-endian scalar.
 *
 * Little-endian to match ristretto255's own scalar_bytes, which inherits it
 * from Ed25519. Using the big-endian helper produced proofs whose challenge
 * decoded byte-reversed, so every honest proof failed - and only against the
 * existing suite, because both halves of a fresh proof were consistently
 * wrong together.
 */
export function scalar_bytes(v, order) {
    return bigint_to_bytes_le(mod(v, order), (order.toString(2).length + 7) >> 3);
}

/**
 * Concatenate a fixed list of named bigint fields, and read them back.
 *
 * Three proofs serialise the same way - a declared field order, each value
 * sign-tagged and length-prefixed - and the ORDER is the part that must not
 * drift: encode and decode agreeing on a different list than each other
 * produces a proof that round-trips to nonsense and still verifies against
 * nothing.
 */
export function encode_fields(proof, order) {
    var out = [];
    for (var i = 0; i < order.length; i++) { out.push(int_bytes(proof[order[i]])); }
    return concat(out);
}

/** @return {object|null} null on any malformed input */
export function decode_fields(bytes, order) {
    if (!bytes) { return null; }
    var out = {}, off = 0;
    for (var i = 0; i < order.length; i++) {
        if (off + 3 > bytes.length) { return null; }
        var r = read_int(bytes, off);
        if (!r) { return null; }
        out[order[i]] = r.value;
        off = r.next;
    }
    return { fields: out, next: off };
}

/**
 * A proof as bytes, for proofs that carry group elements and repetitions.
 *
 * `ints` name the bigint fields (encode_fields: sign, length, magnitude) and
 * `blobs` the byte-string fields (a group element's encoding: two-byte
 * length, then the bytes). A field holding an ARRAY - one entry per
 * repetition, as in the kappa-fold binary-challenge proofs - is written as a
 * two-byte count followed by its entries, so a repeated proof and a single
 * one share one codec. Field order is the order of the two lists, ints
 * first; decode_proof refuses truncation and trailing bytes.
 *
 * @param {object} proof
 * @param {Array<string>} ints
 * @param {Array<string>} blobs
 */
export function encode_proof(proof, ints, blobs) {
    var out = [], i, j;
    function one_int(v) { out.push(int_bytes(v)); }
    function one_blob(b) { out.push(be16(b.length)); out.push(b); }
    for (i = 0; i < ints.length; i++) {
        var v = proof[ints[i]];
        if (Array.isArray(v)) { out.push(be16(v.length)); for (j = 0; j < v.length; j++) { one_int(v[j]); } }
        else { one_int(v); }
    }
    for (i = 0; i < blobs.length; i++) {
        var b = proof[blobs[i]];
        if (Array.isArray(b)) { out.push(be16(b.length)); for (j = 0; j < b.length; j++) { one_blob(b[j]); } }
        else { one_blob(b); }
    }
    return concat(out);
}

/**
 * The inverse of encode_proof. `repeated` lists the fields that are arrays.
 *
 * @return {object|null} null on any malformed input
 */
export function decode_proof(bytes, ints, blobs, repeated) {
    if (!(bytes instanceof Uint8Array)) { return null; }
    var rep = {}, i, j, off = 0, out = {};
    for (i = 0; i < (repeated || []).length; i++) { rep[repeated[i]] = true; }
    function u16() {
        if (off + 2 > bytes.length) { throw new RangeError('short'); }
        var n = (bytes[off] << 8) | bytes[off + 1]; off += 2; return n;
    }
    function one_int() {
        if (off + 3 > bytes.length) { throw new RangeError('short'); }
        var r = read_int(bytes, off);
        if (!r) { throw new RangeError('short or non-canonical integer'); }
        off = r.next; return r.value;
    }
    function one_blob() {
        var n = u16();
        if (off + n > bytes.length) { throw new RangeError('short'); }
        var b = bytes.slice(off, off + n); off += n; return b;
    }
    try {
        for (i = 0; i < ints.length; i++) {
            if (rep[ints[i]]) { var n = u16(), a = []; for (j = 0; j < n; j++) { a.push(one_int()); } out[ints[i]] = a; }
            else { out[ints[i]] = one_int(); }
        }
        for (i = 0; i < blobs.length; i++) {
            if (rep[blobs[i]]) { var m = u16(), c = []; for (j = 0; j < m; j++) { c.push(one_blob()); } out[blobs[i]] = c; }
            else { out[blobs[i]] = one_blob(); }
        }
    } catch (e) { return null; }
    return off === bytes.length ? out : null;
}

/**
 * The masking parameters, read once with their defaults.
 *
 * Four files repeated this, and `ell` and `eps` are not tuning knobs - they
 * are what the simulator argument needs - so reading them in one place makes
 * the defaults one thing rather than four.
 */
export function masks(opts, dflt) {
    return {
        ell:  (opts && opts.ell)  || dflt.ell,
        ell2: (opts && opts.ell2) || dflt.ell2,
        eps:  (opts && opts.eps)  || dflt.eps
    };
}

/**
 * `value` must lie in +-2^bits, or the proof is about something else.
 *
 * Four proofs open with this same guard, and it is not defensive politeness:
 * the whole substance of a range proof is the bound, so a prover handed a
 * value outside it would produce a proof of a claim that is false. Failing at
 * the door is the only place it can be said clearly - a verifier rejecting it
 * later looks like a broken relation.
 */
export function require_in_range(who, name, value, bits) {
    /* |value| <= 2^bits - the library's one convention; see primes.in_range */
    if (!in_range(value, 1n << BigInt(bits))) {
        throw new Error(who + ': ' + name + ' is outside the claimed range');
    }
    return value;
}

/* ==================== the paper's +-m (CGGMP21 section 2.7) ==================== */

/*
 * "+-m denotes the set {-(m-1)/2, ..., (m-1)/2} if m is odd and
 *  {-m/2-1, ..., m/2} if m is even" - CGGMP21 (eprint 2021/060) section 2.7.
 *
 * +-m IS A SET OF m INTEGERS, so its half-width is about m/2 - NOT m. The
 * library used to read "+-2^b" as |x| <= 2^b, twice the paper's interval, in
 * every mask, witness check and response bound of Pi^enc, Pi^log*, Pi^aff-g
 * and Pi^fac. These helpers are now the only way those four proofs turn a
 * paper bound into a number, so the sampler, the witness guard, the response
 * check and the exponentiation ladder all come from the same half-width and
 * cannot drift apart again (the ladder and the guard did once: an edge
 * witness passed the guard and threw in the ladder).
 *
 * ⚠ THE EVEN CASE, CHOSEN: the paper's even-m set is evidently a typo for
 *   {-m/2+1, ..., m/2} (m elements, one more on the positive side). This
 *   library takes the CLOSED SYMMETRIC interval |x| <= m/2 instead - m + 1
 *   elements, the asymmetry dropped. The one extra value, -m/2, changes no
 *   bound by more than one and no statistical argument at all, and a
 *   symmetric set keeps "x in +-m" and "-x in +-m" the same statement.
 *   For odd m (the group order q) the set is exactly the paper's.
 */

/** The half-width of the paper's +-m: (m-1)/2 for odd m, m/2 for even. */
export function pm_half(m) {
    if (typeof m !== 'bigint' || m < 1n) { throw new RangeError('pm: m must be a positive bigint'); }
    return (m & 1n) ? (m - 1n) >> 1n : m >> 1n;
}

/** Is v in the paper's +-m, i.e. |v| <= pm_half(m)? */
export function pm_in(v, m) { return typeof v === 'bigint' && in_range(v, pm_half(m)); }

/**
 * Uniform in +-m: random_below_biased(2h + 1) - h for h = pm_half(m).
 *
 * Uniform over the closed interval, zero included once - not
 * random_signed_below's magnitude-and-sign draw, which weights zero twice.
 * rng omitted or null draws fresh bytes from the platform.
 */
export function pm_sample(m, rng) {
    rng = require_rng('zk_bytes.pm_sample', rng);
    var h = pm_half(m);
    return random_below_biased(2n * h + 1n, rng) - h;
}

/**
 * The ladder width for an exponent in +-m: the bit length of its largest
 * magnitude. powmod_signed_ct walks exactly this many bits, so a value the
 * guard admits always fits the ladder.
 */
export function pm_bits(m) { return pm_half(m).toString(2).length; }

/** The prover's witness guard: v must lie in +-m, or the statement is false. */
export function require_pm(who, name, v, m) {
    if (!pm_in(v, m)) { throw new Error(who + ': ' + name + ' is outside the claimed range'); }
    return v;
}

/** A Fiat-Shamir challenge uniform in +-m (+-q for the group order q). */
export function fs_pm(read, m) {
    var h = pm_half(m);
    return fs_below(read, 2n * h + 1n) - h;
}

/**
 * CGGMP21's parameters, defaulted from the group order and checked against
 * appendix C.1:
 *
 *     kappa = log q;  ell >= kappa;  eps >= ell + kappa;
 *     ell' >= ell + eps + 2 ell;  log N >= ell' + eps  (+ 2 here, below)
 *
 * with the paper's concrete choice (ell, eps, ell') = (kappa, 2 kappa,
 * 5 kappa) as the default. `moduli` are the Paillier moduli the proof is
 * about; log N is taken as each one's bit length.
 *
 * ⛔ log N >= ell' + eps + 2, TWO BITS ABOVE THE PAPER. A response in
 *   J_eps = +-2^(ell'+eps) has half-width 2^(ell'+eps-1), and the extracted
 *   witness - a difference of two responses - reaches +-2^(ell'+eps). At
 *   log N = ell' + eps exactly that passes N/2, so the extracted value can
 *   wrap mod N: a prover in the setup-less proofs (aff-g*, dec) put p + N in
 *   one ciphertext and p in another, and both verified (demonstrated). Two
 *   bits keep the whole extraction range strictly inside +-N/2.
 *
 * ⚠ REFUSED, NOT WARNED, in prover and verifier alike. The old default
 *   ell' = 512 at ell = 256 was below 3 ell + eps = 1280, and nothing said so.
 *
 * @param {string} who
 * @param {bigint} order   the group order q
 * @param {object} [opts]  ell, eps, ell2 (= ell')
 * @param {Array<bigint>} moduli
 * @return {{kappa, ell, eps, ell2}}
 */
export function cggmp_params(who, order, opts, moduli) {
    if (typeof order !== 'bigint' || order < 3n) {
        throw new TypeError(who + ': the group order q is required (a bigint) - ' +
                            'the challenge is drawn from +-q');
    }
    var kappa = order.toString(2).length;
    var ell  = (opts && opts.ell)  || kappa;
    var eps  = (opts && opts.eps)  || 2 * kappa;
    var ell2 = (opts && opts.ell2) || 5 * kappa;
    function no(why) { throw new Error(who + ': parameters violate CGGMP21 appendix C.1 - ' + why); }
    if (ell < kappa) { no('ell (' + ell + ') < kappa = log q (' + kappa + ')'); }
    if (eps < ell + kappa) { no('eps (' + eps + ') < ell + kappa (' + (ell + kappa) + ')'); }
    if (ell2 < 3 * ell + eps) { no("ell' (" + ell2 + ') < ell + eps + 2 ell (' + (3 * ell + eps) + ')'); }
    for (var i = 0; i < moduli.length; i++) {
        var nb = moduli[i].toString(2).length;
        if (nb < ell2 + eps + 2) { no('log N (' + nb + " bits) < ell' + eps + 2 (" + (ell2 + eps + 2) + ')'); }
    }
    return { kappa: kappa, ell: ell, eps: eps, ell2: ell2 };
}

/**
 * The challenge width of the Paillier-only Sigma proofs (Pi^zero, Pi^mul,
 * Pi^aff-p, the exact range proof), which have no group and so no q to draw
 * the challenge from.
 *
 * The challenge is e in [0, 2^kappa). Special soundness divides by e - e',
 * so every |e - e'| < 2^kappa must be a unit mod the modulus THE PROVER
 * CHOSE: below its smallest prime factor.
 *
 * ⛔ THE SIZE OF N SAYS NOTHING ABOUT ITS FACTORS. A cheating prover picks
 *   N = 65537 * q, grinds Fiat-Shamir until e = 0 mod 65537, and proves a
 *   false statement (demonstrated in review: a forged Pi^zero for a nonzero
 *   plaintext, in about 10^5 hashes). So the bound on the factors is a
 *   REQUIRED input, `opts.factor_bits`: the guarantee the verifier holds for
 *   that key - from Pi^fac (CGGMP21 Figure 26: no factor below about
 *   2^ell, i.e. 256 bits at the paper's parameters) - and kappa must stay
 *   below it. There is no default, because the only honest default would be
 *   "trust the prover".
 *
 * ⛔ kappa >= 128. The soundness error is 2^-kappa per hash query: at 32 bits
 *   a forger needs about 2^32 SHAKE calls, a few core-days in this code and
 *   much less natively.
 *
 * ⚠ THE DEFAULT IS 128, not 256: Pi^fac at the paper's parameters vouches
 *   for factors of about 256 bits, and kappa must stay strictly below that.
 *   A caller holding a stronger guarantee may raise it.
 *
 * @param {string} who
 * @param {object} opts    { factor_bits (REQUIRED), kappa (default 128) }
 * @param {Array<bigint>} provers  the moduli chosen by the prover
 * @return {number} kappa
 */
export function paillier_kappa(who, opts, provers) {
    var kappa = (opts && opts.kappa) || 128;
    var fb = opts && opts.factor_bits;
    if (!Number.isInteger(kappa) || kappa < 128) {
        throw new Error(who + ': kappa (the challenge width) must be an integer >= 128');
    }
    if (!Number.isInteger(fb)) {
        throw new Error(who + ": opts.factor_bits is required - the verified lower bound on the prime " +
                        "factors of the prover's modulus (from Pi^fac); its bit length is not a substitute");
    }
    if (kappa >= fb) {
        throw new Error(who + ': kappa (' + kappa + ') must be below factor_bits (' + fb + ')');
    }
    for (var i = 0; i < provers.length; i++) {
        var nb = provers[i].toString(2).length;
        if (2 * fb > nb + 1) {
            throw new Error(who + ': factor_bits (' + fb + ') cannot hold for a ' + nb + '-bit modulus');
        }
    }
    return kappa;
}

/* ==================== shared by the Sigma proofs over Z*_N ==================== */

/**
 * Exponentiation with a possibly NEGATIVE exponent.
 *
 * ⚠ THE RESPONSES IN THESE PROOFS ARE SIGNED. They are mask + e*value over
 *   the INTEGERS, with e drawn from +/-2^ell, and nothing reduces them.
 *   powmod is undefined for a negative exponent, so the sign is handled
 *   here rather than left to produce a wrong value quietly.
 *
 * @return {bigint|null} null when the base is not invertible
 */
export function signed_pow(base, exp, m) {
    /* primes.powmod_signed, with null instead of a throw for a non-unit */
    try { return powmod_signed(base, exp, m); } catch (e) { return null; }
}

/**
 * A uniform integer in +/-bound, for masking.
 *
 * ⚠ A MASK SIZED TOO SMALL STILL VERIFIES. Every equation holds for an
 *   honest prover and the only thing lost is the hiding, which no positive
 *   test can see. The caller must size the bound at eps bits beyond the
 *   value being hidden - see the proofs that use this.
 *
 * rng omitted or null draws fresh bytes from the platform.
 */
export function signed_mask(bound, rng) {
    rng = require_rng('zk_bytes.signed_mask', rng);
    /* one sampler: primes.random_signed_below (+16 bytes, one reduction, a sign bit) */
    return random_signed_below(bound, rng);
}

/**
 * (1 + (m mod N)·N) · R mod N², for a randomiser R that is ALREADY an N-th
 * residue - the small-exponent Paillier of eprint 2024/1950 (section 2.3.4:
 * "E = enc_N(x, r^beta) = (1 + xN) * r0^beta mod N^2"), where R = rho^lambda and
 * rho = rho0^(2N). Raising R to the N again, as paillier.enc_raw does, gives a
 * consistent but different scheme and costs a full |N|-bit exponentiation
 * mod N^2 per ciphertext - the very cost the small exponents remove.
 */
export function paillier_enc_nth(N, m, R) {
    var N2 = N * N;
    var mm = ((m % N) + N) % N;
    return ((1n + mm * N) % N2) * (((R % N2) + N2) % N2) % N2;
}

/*
 * ⭐ paillier_enc_raw USED TO BE HERE: a one-line pass-through to
 *   paillier.enc_raw with nothing calling it, and the reason this commons
 *   file imported a scheme file at all. Removed; use paillier.enc_raw.
 */

/* ==================== shared by Pi_dlenc and Pi_sig ==================== */

/*
 * zk_dlenc.js and zk_sig.js are two Sigma protocols from the same paper
 * (eprint 2024/1950, Protocols 6 and 7), written one after the other, and
 * they carried identical pieces: the prover's exponentiation, the tag that
 * binds the declared sizes, and the reduction of the transcript digest to a
 * challenge (digest_challenge, since replaced by fs_signed - see the
 * Fiat-Shamir section above). They live here and both files import them.
 */

/**
 * Constant-time signed exponentiation for a PROVER, whose exponents are
 * secret masks.
 *
 * signed_pow branches on the sign and uses a variable-time ladder - fine for
 * a verifier, whose inputs are public, but not here. `bits` is the width of
 * the PUBLIC bound the mask was drawn from.
 *
 * A non-unit base is a PUBLIC property of the parameters (and never happens
 * with honest ones), so that case falls back to signed_pow and its null.
 * ⛔ ONLY that case: an exponent wider than its declared width is a bug in the
 *   caller, and falling back would turn it into a timing leak.
 */
export function prover_pow(base, exp, m, bits) {
    try { return powmod_signed_ct(base, exp, m, bits); }
    catch (e) {
        if (/non-invertible/.test(String(e && e.message))) { return signed_pow(base, exp, m); }
        throw e;
    }
}

/**
 * The declared sizes, as transcript bytes.
 *
 * ⭐ EVERY PUBLIC INPUT GOES INTO THE CHALLENGE (v2 of both transcripts),
 *   including the declared ranges: a Fiat-Shamir challenge that skips part of
 *   the statement lets that part be chosen after the challenge is known. The
 *   field list is the UNION of what both proofs declare, so a size one of
 *   them does not use is written as '-' rather than left out.
 *
 * @param {object} sizes
 * @param {number} nu_default  the proof's nu when sizes.nu is absent
 */
export function sizes_tag(sizes, nu_default) {
    return ascii([sizes.ell, sizes.nu || nu_default, sizes.n_x, sizes.n_lambda, sizes.n_a, sizes.n_b,
                  sizes.n_lambda0, sizes.n_trho].map(function (x) { return x == null ? '-' : String(x); }).join(','));
}

