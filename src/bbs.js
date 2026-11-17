/**
 * BBS  -  one signature over many messages, revealing only what you choose
 *
 * A signer signs a LIST of messages and produces a single constant-size
 * signature. The holder can then generate a proof that discloses any subset of
 * those messages while revealing nothing about the rest - and the proof still
 * establishes that the disclosed ones were genuinely signed.
 *
 *     sign(sk, pk, header, [name, id, dob, address])  ->  80 bytes
 *     prove(pk, sig, header, ph, messages, [2])       ->  "dob is 1990-01-01,
 *                                                          signed by them,
 *                                                          and nothing else"
 *
 * ==================== WHAT IT GIVES THAT NOTHING ELSE HERE DOES ====================
 *
 * SELECTIVE DISCLOSURE. Every other signature in this library signs one blob:
 * to reveal part of it you have to reveal all of it, or split it into several
 * signatures and leak which parts exist. BBS signs a vector and lets the
 * holder choose per presentation.
 *
 * UNLINKABLE PROOFS. Two presentations derived from the same signature cannot
 * be recognised as related. This is what makes BBS the basis for digital
 * credentials - a driving licence presented twice does not become a tracking
 * identifier. Presenting an ordinary signature twice does exactly that,
 * because the signature bytes are the same both times.
 *
 * The proof is a zero-knowledge proof of knowledge of a signature; the
 * verifier never sees the signature itself.
 *
 * ======================== HOW IT WORKS ========================
 *
 * The signature is a pair (A, e) where
 *
 *     B = P1 + Q_1*domain + H_1*msg_1 + ... + H_L*msg_L
 *     A = B * (1 / (sk + e))
 *
 * and verification is one pairing check:
 *
 *     e(A, W + BP2*e) * e(B, -BP2) == 1
 *
 * Each message has its OWN generator H_i, which is what makes selective
 * disclosure possible: the verifier can rebuild the part of B corresponding to
 * the disclosed messages and the prover proves knowledge of the rest.
 *
 * THE GENERATORS ARE DERIVED BY HASHING, so nobody knows a discrete-log
 * relation between them. If anyone did, they could move value between message
 * positions - claim msg_3 was signed when msg_5 was. The derivation is a
 * chain: each generator seeds the next, so the whole vector follows from the
 * ciphersuite identifier alone.
 *
 * SIGNING IS DETERMINISTIC, unlike the academic scheme. The value e is a hash
 * of the secret key and the messages rather than a random draw, which removes
 * an entire failure mode - a bad entropy source at signing time no longer
 * leaks the key. The draft made this change deliberately.
 *
 * ============================ CAVEATS ============================
 *
 * THE SPECIFICATION IS A DRAFT. draft-irtf-cfrg-bbs-signatures is not yet an
 * RFC, and the byte layout has changed between versions. This implements the
 * -08 layout with the BLS12-381-SHA-256 ciphersuite, and interoperating with
 * another implementation means checking which draft it targets.
 *
 * MESSAGE ORDER IS PART OF THE STATEMENT. Generator H_i is bound to position
 * i, so passing the same messages in a different order produces a different
 * signature and a verification failure - not a silent mismatch, but not an
 * obvious error message either.
 */

import { CURVE, POINT1, POINT2, BASE2, PAIRING, FIELD12, hash_to_g1,
         decompress_point_g1, compress_point_g1, compress_point_g2,
         decompress_point_g2 } from './bls12_381.js';
import { msm, msm_ct, msm_group } from './commons/fixed_window.js';
import { inv_prime } from './commons/modp.js';
import { sha256 } from './sha2.js';
import { expand_message_xmd, hash_to_field } from './commons/h2c.js';
import { concat, ascii, bytes_to_bigint, bigint_to_bytes, from_hex } from './commons/bytes.js';
import { require_rng, mod } from './commons/primes.js';

var R = CURVE.r;
var G1 = /* @__PURE__ */ msm_group(POINT1);

/** The BLS12-381-SHA-256 ciphersuite identifier. */
export var API_ID = /* @__PURE__ */ ascii('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_');

/**
 * P1, a fixed point of G1 distinct from the base point.
 *
 * It appears in B so that a signature over zero messages is still bound to
 * something; the draft fixes its value rather than deriving it, so it is
 * transcribed and checked against the vectors.
 */
var P1_HEX = 'a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d1' +
             '61b4e28c9';

var EXPAND_LEN = 48;


function i2osp(v, len) { return bigint_to_bytes(BigInt(v), len); }

/**
 * Hash to a scalar in [0, r).
 *
 * expand_message produces 48 bytes rather than 32 - the extra 16 make the
 * reduction modulo r statistically uniform. Hashing to 32 and reducing would
 * bias the result towards the low end, which matters because these scalars
 * become the challenge in a proof.
 */
function hash_to_scalar(msg, dst) {
    /* RFC 9380 hash_to_field with one element, m = 1, L = 48 - commons/h2c.js's,
       which this was written out as by hand */
    return hash_to_field(msg, 1, dst, R, 1, EXPAND_LEN, xmd_sha256)[0];
}

function xmd_sha256(m, d, l) { return expand_message_xmd(m, d, l, sha256); }

/**
 * Derive the generator vector.
 *
 * A chain: the seed is hashed to produce v, and each generator comes from
 * hashing v together with its index while v is advanced each round. Nobody can
 * know a discrete-log relation between them, which is what stops a holder from
 * moving a signed message from one position to another.
 */
export function create_generators(count, api_id) {
    var aid = api_id || API_ID;
    var seed_dst = concat([aid, ascii('SIG_GENERATOR_SEED_')]);
    var gen_dst = concat([aid, ascii('SIG_GENERATOR_DST_')]);
    var gen_seed = concat([aid, ascii('MESSAGE_GENERATOR_SEED')]);

    var v = expand_message_xmd(gen_seed, seed_dst, EXPAND_LEN, sha256);
    var out = [];
    for (var i = 1; i <= count; i++) {
        v = expand_message_xmd(concat([v, i2osp(i, 8)]), seed_dst, EXPAND_LEN, sha256);
        out.push(hash_to_g1(v, gen_dst));
    }
    return out;
}

/** Map an octet string to a scalar, for use as a signed message. */
export function message_to_scalar(msg, api_id) {
    var aid = api_id || API_ID;
    return hash_to_scalar(msg, concat([aid, ascii('MAP_MSG_TO_SCALAR_AS_HASH_')]));
}

export function messages_to_scalars(msgs, api_id) {
    return msgs.map(function (m) { return message_to_scalar(m, api_id); });
}

/* ---------------- keys ---------------- */

/** @return {bigint} the secret scalar */
export function keygen(key_material, key_info, api_id) {
    var aid = api_id || API_ID;
    var info = key_info || new Uint8Array(0);
    var dst = concat([aid, ascii('KEYGEN_DST_')]);
    var derive = concat([key_material, i2osp(info.length, 2), info]);
    var sk = hash_to_scalar(derive, dst);
    if (sk === 0n) { throw new Error('bbs: derived a zero secret key'); }
    return sk;
}

/**
 * The public key: a point of G2, 96 bytes compressed.
 *
 * bls12_381.js has get_public_key_short, which is the same three lines. They
 * are not shared because the INPUT differs in a way that matters: that one
 * takes raw key bytes and reduces them, this one takes a scalar that
 * keygen() already derived through BBS's own KEYGEN_DST_ hash. Routing a BBS
 * key through the BLS entry point would skip that derivation and produce a
 * key that no BBS implementation agrees with.
 */
export function sk_to_pk(sk) {
    var W = POINT2.to_affine(POINT2.mul_ct(mod(sk, CURVE.r), BASE2, 255));   /* the key: constant time */
    return compress_point_g2(W.x, W.y);
}

/* ---------------- the core operations ---------------- */

function serialize_points(pts) {
    var parts = [];
    for (var i = 0; i < pts.length; i++) {
        var A = POINT1.to_affine(pts[i]);
        parts.push(point_bytes(A));
    }
    return concat(parts);
}

/**
 * 48 bytes, compressed G1, as the draft's serialize expects.
 *
 * It is the ZCash encoding, which bls12_381.js exports and this file already
 * used for G2. The G1 half was written out here a second time, with the
 * larger-root test spelled y*2 > p against the curve file's 2y/p >= 1 - the
 * same test for an odd p, and a second place to get it wrong.
 */
export function point_bytes(A) { return compress_point_g1(A.x, A.y); }

/**
 * The domain: everything contextual, distilled to one scalar.
 *
 * It binds the public key, the generator vector, the message count and the
 * header. All three parties must compute the same value, so a header the
 * verifier does not know about makes verification fail rather than succeed
 * with a different meaning.
 */
export function calculate_domain(pk_bytes, Q1, H_points, header, api_id) {
    var aid = api_id || API_ID;
    var hdr = header || new Uint8Array(0);
    var dom = concat([
        i2osp(H_points.length, 8),
        serialize_points([Q1].concat(H_points)),
        aid
    ]);
    var input = concat([pk_bytes, dom, i2osp(hdr.length, 8), hdr]);
    return hash_to_scalar(input, concat([aid, ascii('H2S_')]));
}

/**
 * Compute B = P1 + Q_1*domain + sum(H_i * msg_i).
 *
 * The multi-scalar multiplication is over PUBLIC values when verifying and
 * over the holder's own messages when signing; in both cases the caller
 * already knows them, so Pippenger's data-dependent bucketing costs nothing.
 */
/*
 * ⚠ ct SELECTS THE CONSTANT-TIME MSM, and core_proof_gen must pass it.
 *   Pippenger skips zero digits, so its running time counts the non-zero
 *   digits of the scalar vector - and in proof_gen that vector contains the
 *   UNDISCLOSED messages, which are exactly what the proof exists to keep
 *   from the verifier.
 *
 * ⛔ core_verify PASSES FALSE and should: there the messages are the
 *   disclosed ones, already on the wire.
 *
 * ⚠ core_sign ALSO PASSES FALSE. The usual argument is that the signer
 *   already knows the messages, which is true and is not quite the point -
 *   an attacker co-located with a signer that signs for many parties still
 *   reads them out. It is left variable-time because signing throughput is
 *   the reason this scheme is used; treat it as a deliberate trade, not as
 *   an established safe case.
 */
function compute_B(P1, Q1, domain, H_points, msg_scalars, ct) {
    var scalars = [domain], points = [Q1];
    for (var i = 0; i < msg_scalars.length; i++) {
        scalars.push(msg_scalars[i]);
        points.push(H_points[i]);
    }
    return POINT1.add(P1, ct ? msm_ct(G1, scalars, points, 255)
                             : msm(G1, scalars, points, 255));
}

/**
 * Sign a vector of message scalars.
 *
 * @param  {bigint}     sk         the secret scalar
 * @param  {Uint8Array} pk_bytes   the signer's public key, 96 bytes
 * @param  {Array<bigint>} msgs    message scalars, from messages_to_scalars
 * @return {{A: object, e: bigint}}
 */
export function core_sign(sk, pk_bytes, msgs, header, api_id) {
    var aid = api_id || API_ID;
    var gens = create_generators(msgs.length + 1, aid);
    var Q1 = gens[0], H = gens.slice(1);

    var domain = calculate_domain(pk_bytes, Q1, H, header, aid);

    /*
     * e is DERIVED, not drawn. A random e from a broken entropy source would
     * leak the key; hashing the key and the messages makes that impossible
     * and makes signing reproducible.
     */
    var parts = [bigint_to_bytes(mod(sk, CURVE.r), 32)];
    for (var i = 0; i < msgs.length; i++) { parts.push(bigint_to_bytes(mod(msgs[i], CURVE.r), 32)); }
    parts.push(bigint_to_bytes(domain, 32));
    var e = hash_to_scalar(concat(parts), concat([aid, ascii('H2S_')]));

    var P1 = P1_POINT();
    if (P1 === null) { throw new Error('bbs: P1 could not be decompressed'); }

    var B = compute_B(P1, Q1, domain, H, msgs);

    /* A = B / (sk + e) */
    var denom = mod(sk + e, CURVE.r);
    if (denom === 0n) { throw new Error('bbs: sk + e is zero'); }
    var A = POINT1.mul(inv_r(denom), B, 255);

    return { A: A, e: e };
}

/**
 * Verify a signature.
 *
 *     e(A, W + BP2*e) * e(B, -BP2) == 1
 *
 * One pairing product rather than two pairings, for the same reason BLS
 * verification does it - a single final exponentiation instead of two.
 *
 * @return {boolean}
 */
export function core_verify(pk_bytes, sig, msgs, header, api_id) {
    try {
        var aid = api_id || API_ID;
        var Wd = decompress_point_g2(pk_bytes);
        if (Wd === null) { return false; }
        var W = POINT2.of(Wd.x, Wd.y);

        var gens = create_generators(msgs.length + 1, aid);
        var Q1 = gens[0], H = gens.slice(1);
        var domain = calculate_domain(pk_bytes, Q1, H, header, aid);

        var P1 = P1_POINT();
        if (P1 === null) { return false; }
        var B = compute_B(P1, Q1, domain, H, msgs);

        var acc = PAIRING.pair_product([
            [POINT1.to_affine(sig.A),
             POINT2.to_affine(POINT2.add(W, POINT2.mul(sig.e, BASE2)))],
            [POINT1.to_affine(B), POINT2.to_affine(POINT2.neg(BASE2))]
        ]);
        return FIELD12.eq(acc, FIELD12.ONE);
    } catch (err) {
        return false;
    }
}

/* ---------------- helpers ---------------- */

/* P1 is a fixed suite constant, so it is decompressed once and cached */
var P1_CACHE = null;
function P1_POINT() {
    if (P1_CACHE === null) { P1_CACHE = point_from_hex(P1_HEX); }
    return P1_CACHE;
}

function point_from_hex(h) {
    var d = decompress_point_g1(from_hex(h));
    return d === null ? null : POINT1.of(d.x, d.y);
}

/* modular inverse in the scalar field - shared, see commons/modp.js */
function inv_r(a) { return inv_prime(a, R); }

/** The 80-byte wire form: 48-byte point then 32-byte scalar. *
 * @return {object|null} A signature, or null if the encoding is malformed or a component is out of range.
 */
export function signature_to_octets(sig) {
    return concat([point_bytes(POINT1.to_affine(sig.A)), bigint_to_bytes(sig.e, 32)]);
}

export function octets_to_signature(bytes) {
    if (bytes.length !== 80) { return null; }
    var d = decompress_point_g1(bytes.subarray(0, 48));
    if (d === null) { return null; }
    var e = bytes_to_bigint(bytes.subarray(48));
    if (e === 0n || e >= R) { return null; }
    return { A: POINT1.of(d.x, d.y), e: e };
}

/* ==================== PROOFS: THE SELECTIVE DISCLOSURE ====================
 *
 * This is what BBS exists for. The holder takes a signature over L messages
 * and produces a proof that discloses any subset, revealing nothing about the
 * rest - and the verifier never sees the signature itself.
 *
 * TWO PROPERTIES, AND THE SECOND IS THE SUBTLE ONE:
 *
 *   The disclosed messages were genuinely signed by the holder of PK.
 *   Two proofs from the SAME signature cannot be recognised as related.
 *
 * The second is why a credential presented twice does not become a tracking
 * identifier. Presenting an ordinary signature twice does exactly that,
 * because the bytes are identical both times.
 *
 * HOW THE UNLINKABILITY WORKS. The signature (A, e) is randomised into
 * (Abar, Bbar, D) using fresh scalars r1, r2 on every presentation, and the
 * verifier checks a pairing equation on the randomised form. The equation
 * holds only for a genuine signature, and the randomised triple carries no
 * information linking it to any other presentation.
 *
 * THE UNDISCLOSED MESSAGES ARE PROVED IN ZERO KNOWLEDGE. For each hidden
 * message the prover sends a masked response m^_j = m~_j + msg_j * c; the
 * verifier can check the aggregate without learning any individual value.
 *
 * ============================== THE RANDOMNESS ==============================
 *
 * PROOF GENERATION NEEDS FRESH RANDOMNESS, unlike signing which is
 * deterministic. That asymmetry is deliberate: a deterministic proof would be
 * identical every time and unlinkability would be lost - the very property
 * the proof exists to provide.
 *
 * And the randomness must be good. Repeating the scalars across two proofs
 * from the same signature leaks the undisclosed messages by subtracting the
 * two responses, in the same way a repeated Schnorr nonce leaks a key.
 */

/** Serialise a mixed array of points and scalars, as the draft's serialize. */
function serialize_mixed(items) {
    var parts = [];
    for (var i = 0; i < items.length; i++) {
        var it = items[i];
        if (typeof it === 'bigint') {
            parts.push(bigint_to_bytes(mod(it, CURVE.r), 32));
        } else if (typeof it === 'number') {
            parts.push(i2osp(it, 8));
        } else {
            parts.push(point_bytes(POINT1.to_affine(it)));
        }
    }
    return concat(parts);
}

/**
 * The Fiat-Shamir challenge.
 *
 * EVERYTHING THE VERIFIER USES IS ABSORBED: the disclosed indexes and their
 * messages, the three randomised signature components, both commitment
 * values, the domain, and the presentation header. A challenge over less than
 * that would let a prover choose the remaining values after seeing it.
 *
 * The presentation header is what binds a proof to one occasion - a nonce
 * from the verifier, a timestamp, a session identifier. Without it, a proof
 * can be replayed.
 */
function proof_challenge(init, disclosed_indexes, disclosed_msgs, ph, api_id) {
    var aid = api_id || API_ID;
    var arr = [disclosed_indexes.length];
    for (var i = 0; i < disclosed_indexes.length; i++) {
        arr.push(disclosed_indexes[i]);
        arr.push(disclosed_msgs[i]);
    }
    arr.push(init.Abar, init.Bbar, init.D, init.T1, init.T2, init.domain);
    var octs = concat([serialize_mixed(arr),
                       i2osp((ph || new Uint8Array(0)).length, 8),
                       ph || new Uint8Array(0)]);
    return hash_to_scalar(octs, concat([aid, ascii('H2S_')]));
}

/**
 * Generate a proof disclosing the messages at `disclosed_indexes`.
 *
 * @param {Uint8Array}     pk_bytes
 * @param {object}         sig       from core_sign or octets_to_signature
 * @param {Array<bigint>}  msgs      ALL the signed message scalars, in order
 * @param {Array<number>}  disclosed_indexes  ascending, zero-based
 * @param {function}       rng
 * @param {Uint8Array}     [ph]      presentation header
 * @return {Uint8Array}
 */
export function core_proof_gen(pk_bytes, sig, msgs, disclosed_indexes,
                               rng, header, ph, api_id) {
    rng = require_rng('core_proof_gen', rng);
    var aid = api_id || API_ID;
    var L = msgs.length;

    /* the undisclosed set is the complement, and must stay in ascending order
       because the generators are bound to positions */
    var disclosed = {}, i;
    for (i = 0; i < disclosed_indexes.length; i++) { disclosed[disclosed_indexes[i]] = true; }
    var undisclosed = [];
    for (i = 0; i < L; i++) { if (!disclosed[i]) { undisclosed.push(i); } }
    var U = undisclosed.length;

    var gens = create_generators(L + 1, aid);
    var Q1 = gens[0], H = gens.slice(1);
    var domain = calculate_domain(pk_bytes, Q1, H, header, aid);

    /* 5 + U fresh scalars: r1, r2, e~, r1~, r3~ and one mask per hidden message */
    var rs = [];
    for (i = 0; i < 5 + U; i++) { rs.push(random_scalar(rng)); }
    var r1 = rs[0], r2 = rs[1], e_t = rs[2], r1_t = rs[3], r3_t = rs[4];
    var m_t = rs.slice(5);

    var P1 = P1_POINT();
    var B = compute_B(P1, Q1, domain, H, msgs, true);

    /* the randomised signature */
    var D = POINT1.mul(r2, B, 255);
    var Abar = POINT1.mul(mod(r1 * r2, CURVE.r), sig.A, 255);
    var Bbar = POINT1.add(POINT1.mul(r1, D, 255),
                          POINT1.neg(POINT1.mul(sig.e, Abar, 255)));

    /* the two commitments */
    var T1 = POINT1.add(POINT1.mul(e_t, Abar, 255), POINT1.mul(r1_t, D, 255));

    var t2_scalars = [r3_t], t2_points = [D];
    for (i = 0; i < U; i++) {
        t2_scalars.push(m_t[i]);
        t2_points.push(H[undisclosed[i]]);
    }
    /* ⛔ every scalar here is a blinder masking an undisclosed message in the
       responses - see compute_B above */
    var T2 = msm_ct(G1, t2_scalars, t2_points, 255);

    var init = { Abar: Abar, Bbar: Bbar, D: D, T1: T1, T2: T2, domain: domain };
    var disclosed_msgs = disclosed_indexes.map(function (j) { return msgs[j]; });
    var c = proof_challenge(init, disclosed_indexes, disclosed_msgs, ph, aid);

    /* the responses */
    var r3 = inv_r(r2);
    var e_hat = mod(e_t + sig.e * c, CURVE.r);
    var r1_hat = mod(r1_t - r1 * c, CURVE.r);
    var r3_hat = mod(r3_t - r3 * c, CURVE.r);
    var m_hat = [];
    for (i = 0; i < U; i++) {
        m_hat.push(mod(m_t[i] + msgs[undisclosed[i]] * c, CURVE.r));
    }

    return proof_to_octets({ Abar: Abar, Bbar: Bbar, D: D, e_hat: e_hat,
                             r1_hat: r1_hat, r3_hat: r3_hat, m_hat: m_hat, c: c });
}

/**
 * Verify a proof against the disclosed messages.
 *
 * The verifier reconstructs T1 and T2 from the responses - they come out
 * equal to the prover's commitments exactly when the responses were honest -
 * recomputes the challenge, and checks one pairing equation on the randomised
 * signature.
 *
 * @return {boolean}
 */
export function core_proof_verify(pk_bytes, proof_bytes, msgs, disclosed_indexes,
                                  header, ph, api_id, L) {
    try {
        var aid = api_id || API_ID;
        var proof = octets_to_proof(proof_bytes);
        if (proof === null) { return false; }

        var Wd = decompress_point_g2(pk_bytes);
        if (Wd === null) { return false; }
        var W = POINT2.of(Wd.x, Wd.y);

        var U = proof.m_hat.length;
        var R = disclosed_indexes.length;
        var total = L === undefined ? U + R : L;
        if (msgs.length !== R) { return false; }

        var disclosed = {}, i;
        for (i = 0; i < R; i++) {
            if (disclosed_indexes[i] >= total) { return false; }
            disclosed[disclosed_indexes[i]] = true;
        }
        var undisclosed = [];
        for (i = 0; i < total; i++) { if (!disclosed[i]) { undisclosed.push(i); } }
        if (undisclosed.length !== U) { return false; }

        var gens = create_generators(total + 1, aid);
        var Q1 = gens[0], H = gens.slice(1);
        var domain = calculate_domain(pk_bytes, Q1, H, header, aid);

        /* T1 = Bbar*c + Abar*e^ + D*r1^ */
        var T1 = msm(G1, [proof.c, proof.e_hat, proof.r1_hat],
                     [proof.Bbar, proof.Abar, proof.D], 255);

        /* Bv is the disclosed part of B, which the verifier can rebuild */
        var P1 = P1_POINT();
        var bv_scalars = [domain], bv_points = [Q1];
        for (i = 0; i < R; i++) {
            bv_scalars.push(msgs[i]);
            bv_points.push(H[disclosed_indexes[i]]);
        }
        var Bv = POINT1.add(P1, msm(G1, bv_scalars, bv_points, 255));

        /* T2 = Bv*c + D*r3^ + sum(H_j * m^_j) */
        var t2_scalars = [proof.c, proof.r3_hat], t2_points = [Bv, proof.D];
        for (i = 0; i < U; i++) {
            t2_scalars.push(proof.m_hat[i]);
            t2_points.push(H[undisclosed[i]]);
        }
        var T2 = msm(G1, t2_scalars, t2_points, 255);

        var init = { Abar: proof.Abar, Bbar: proof.Bbar, D: proof.D,
                     T1: T1, T2: T2, domain: domain };
        var c = proof_challenge(init, disclosed_indexes, msgs, ph, aid);
        if (c !== proof.c) { return false; }

        /* and the signature itself: e(Abar, W) * e(Bbar, -BP2) == 1 */
        var acc = PAIRING.pair_product([
            [POINT1.to_affine(proof.Abar), POINT2.to_affine(W)],
            [POINT1.to_affine(proof.Bbar), POINT2.to_affine(POINT2.neg(BASE2))]
        ]);
        return FIELD12.eq(acc, FIELD12.ONE);
    } catch (err) {
        return false;
    }
}

/**
 * A uniform scalar.
 *
 * Drawn from 48 bytes rather than 32 so that reducing modulo r is unbiased -
 * the same reason hash_to_scalar expands to 48. A biased masking scalar would
 * leak information about the message it hides.
 */
function random_scalar(rng) {
    var v = mod(bytes_to_bigint(rng(EXPAND_LEN)), CURVE.r);
    return v === 0n ? 1n : v;
}

/** 3 points, then 3 scalars, then U scalars, then the challenge. *
 * @return {object|null} A proof, or null if the encoding is malformed.
 */
export function proof_to_octets(p) {
    var parts = [point_bytes(POINT1.to_affine(p.Abar)),
                 point_bytes(POINT1.to_affine(p.Bbar)),
                 point_bytes(POINT1.to_affine(p.D)),
                 bigint_to_bytes(p.e_hat, 32),
                 bigint_to_bytes(p.r1_hat, 32),
                 bigint_to_bytes(p.r3_hat, 32)];
    for (var i = 0; i < p.m_hat.length; i++) {
        parts.push(bigint_to_bytes(p.m_hat[i], 32));
    }
    parts.push(bigint_to_bytes(p.c, 32));
    return concat(parts);
}

export function octets_to_proof(bytes) {
    if (bytes.length < 3 * 48 + 4 * 32) { return null; }
    if ((bytes.length - 3 * 48 - 4 * 32) % 32 !== 0) { return null; }

    var pts = [];
    for (var i = 0; i < 3; i++) {
        var d = decompress_point_g1(bytes.subarray(i * 48, (i + 1) * 48));
        if (d === null) { return null; }
        pts.push(POINT1.of(d.x, d.y));
    }
    var off = 144;
    function scalar() {
        var v = bytes_to_bigint(bytes.subarray(off, off + 32));
        off += 32;
        return v;
    }
    var e_hat = scalar(), r1_hat = scalar(), r3_hat = scalar();
    var m_hat = [];
    var remaining = (bytes.length - off) / 32 - 1;
    for (var j = 0; j < remaining; j++) { m_hat.push(scalar()); }
    var c = scalar();

    /* every scalar must be canonical - a value at or above r is a
       malleability hole, as it is in every other signature format here */
    var all = [e_hat, r1_hat, r3_hat, c].concat(m_hat);
    for (var k = 0; k < all.length; k++) {
        if (all[k] >= R) { return null; }
    }
    return { Abar: pts[0], Bbar: pts[1], D: pts[2], e_hat: e_hat,
             r1_hat: r1_hat, r3_hat: r3_hat, m_hat: m_hat, c: c };
}
