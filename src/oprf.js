/**
 * OPRF, VOPRF and POPRF  -  RFC 9497
 *
 * An oblivious pseudorandom function: two parties jointly compute F(k, x)
 * where the SERVER holds k and never learns x, and the CLIENT holds x and
 * never learns k.
 *
 *     client   Blind(x)              -> a blinded element
 *     server   BlindEvaluate(k, .)   -> applies its key to something it
 *                                       cannot read
 *     client   Finalize(.)           -> removes the blind, gets F(k, x)
 *
 * The mechanism is small: the client hashes x to a curve point and multiplies
 * by a random scalar r; the server multiplies by k; the client multiplies by
 * r^-1 and is left with k*H(x). The server saw only r*H(x), which is a
 * uniformly random point.
 *
 * WHAT IT MAKES POSSIBLE, none of which can be built without it:
 *
 *   - PRIVATE SET INTERSECTION. Two parties learn what their lists have in
 *     common and nothing about the rest. This is how "has your password been
 *     breached" services avoid learning your password.
 *   - OPAQUE, the asymmetric PAKE. The server authenticates a password while
 *     holding NOTHING that can be attacked offline after a breach - which
 *     replaces "hash the password and store it", where a stolen database
 *     gives the attacker something to run Argon2 against.
 *   - PRIVACY PASS. Anonymous tokens: solve one CAPTCHA, receive tokens that
 *     cannot be linked to the solve or to each other.
 *
 * THREE MODES, AND THE DIFFERENCE MATTERS:
 *
 *   OPRF   the base protocol. The client CANNOT TELL whether the server used
 *          the right key - so a malicious server can use a different key per
 *          client and deanonymise them by the output.
 *   VOPRF  adds a zero-knowledge proof that the key matches a published
 *          public key. Without this there is no real anonymity, which is why
 *          Privacy Pass uses it.
 *   POPRF  adds a PUBLIC input mixed into the evaluation - an expiry date, a
 *          rate-limit bucket - that both parties see and agree on.
 *
 * THE STATIC DIFFIE-HELLMAN LIMIT is the security consideration to know. An
 * adversary who can query the server many times reduces the effort to recover
 * k below the group's nominal strength: RFC 9497 section 7.2.3 gives roughly
 * 2^(n/2) queries buying a 2^(n/2) attack. For ristretto255 that means the
 * effective security is around 128 bits only if a single key is not used for
 * more than about 2^64 evaluations. Rotate keys.
 *
 * ALL FIVE CIPHERSUITES of section 4, each a call to `oprf_suite`:
 *
 *   ristretto255-SHA512   decaf448-SHAKE256   P256-SHA256   P384-SHA384
 *   P521-SHA512
 *
 * They differ only in the group, the hash and how bytes become a scalar or a
 * group element; the protocol below is written once over commons/group.js.
 * The module-level functions are the ristretto255-SHA512 suite, as they were
 * when it was the only one.
 */

import * as r255 from './ristretto255.js';
import { GROUP as DECAF448 } from './decaf448.js';
import { P256_GROUP, P384_GROUP, P521_GROUP } from './nist.js';
import { sha256, sha384, sha512 } from './sha2.js';
import { shake256 } from './sha3.js';
import { expand_message_xmd, expand_message_xof, hash_to_field } from './commons/h2c.js';
import { concat, ascii, be16, lp16, bytes_to_bigint, bytes_to_bigint_le } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';

export var MODE_OPRF = 0x00;
export var MODE_VOPRF = 0x01;
export var MODE_POPRF = 0x02;


/*
 * The per-suite pieces (section 4): the group, the hash, HashToGroup, and
 * HashToScalar - expand to 64 bytes and reduce little-endian for the two
 * Edwards-based groups, RFC 9380 hash_to_field for the NIST ones.
 * RandomScalar draws `uniform` bytes and reduces them the same way
 * (`scalar`), the 64 bytes RFC 9496 section 4.4 names for ristretto255 and
 * decaf448 and hash_to_field's L for the NIST curves.
 */
function edwards(G, hash, expand, to_group) {
    function scalar(b) { return bytes_to_bigint_le(b) % G.ORDER; }
    return {
        G: G, hash: hash, uniform: 64, scalar: scalar, to_group: to_group,
        to_scalar: function (m, dst) { return scalar(expand(m, dst, 64)); }
    };
}
function nist(G, hash, L) {
    function expand(m, dst, len) { return expand_message_xmd(m, dst, len, hash); }
    return {
        G: G, hash: hash, uniform: L, to_group: G.hash,
        scalar: function (b) { return bytes_to_bigint(b) % G.ORDER; },
        to_scalar: function (m, dst) { return hash_to_field(m, 1, dst, G.ORDER, 1, L, expand)[0]; }
    };
}

var SPECS = {
    'ristretto255-SHA512': /* @__PURE__ */ Object.assign(edwards(r255.GROUP, sha512,
        function (m, dst, len) { return expand_message_xmd(m, dst, len, sha512); },
        /* hash_to_ristretto255: expand_message_xmd to 64 bytes, then element derivation */
        function (m, dst) { return r255.from_uniform_bytes(expand_message_xmd(m, dst, 64, sha512)); }), {
        /* ⭐ one interleaved walk for a·P + b·Q, about 1.55x over two multiplications */
        double_mul: r255.double_mul_vartime
    }),
    'decaf448-SHAKE256': /* @__PURE__ */ edwards(DECAF448, function (m) { return shake256(m, 64); },
        function (m, dst, len) { return expand_message_xof(m, dst, len, shake256); }, DECAF448.hash),
    'P256-SHA256': /* @__PURE__ */ nist(P256_GROUP, sha256, 48),
    'P384-SHA384': /* @__PURE__ */ nist(P384_GROUP, sha384, 72),
    'P521-SHA512': /* @__PURE__ */ nist(P521_GROUP, sha512, 98)
};

/**
 * One ciphersuite of RFC 9497.
 *
 * @param {string} id  'ristretto255-SHA512', 'decaf448-SHAKE256',
 *                     'P256-SHA256', 'P384-SHA384' or 'P521-SHA512'
 */
export function oprf_suite(id) {
    var S = SPECS[id];
    if (!S) { throw new Error('oprf: unknown ciphersuite ' + id); }
    var G = S.G, ORDER = G.ORDER, NS = G.SCALAR_BYTES;
    function smod(x) { return G.scalar_mod(x); }
    function inv(x) {
        /* Fermat: x^(ORDER-2), branch-free on x, which is a secret blind */
        var r = 1n, b = smod(x), e = ORDER - 2n;
        while (e > 0n) { if (e & 1n) { r = (r * b) % ORDER; } b = (b * b) % ORDER; e >>= 1n; }
        return r;
    }
    var double_mul = S.double_mul || function (a, P, b, Q) { return G.add(G.mul_vartime(a, P), G.mul_vartime(b, Q)); };

    function context_string(mode) {
        return ascii('OPRFV1-' + String.fromCharCode(mode) + '-' + id);
    }

    /*
     * HashToGroup with a mode-specific domain tag: a blinded element from an
     * OPRF session can never be replayed into a VOPRF one.
     */
    function hash_to_group(input, mode) {
        return S.to_group(input, concat([ascii('HashToGroup-'), context_string(mode)]));
    }

    var hash_to_scalar_dst = S.to_scalar;

    function hash_to_scalar(input, mode) {
        return hash_to_scalar_dst(input, concat([ascii('HashToScalar-'), context_string(mode)]));
    }

    /* RandomScalar: uniform bytes reduced as the suite reduces them, never
       zero; rng omitted or null draws fresh ones from the platform */
    function random_scalar(rng) {
        rng = require_rng('oprf.random_scalar', rng);
        for (var i = 0; i < 64; i++) {
            var r = S.scalar(rng(S.uniform));
            if (r !== 0n) { return r; }
        }
        throw new Error('oprf: rng returned zero scalars');
    }

    function check_identity(P, what) {
        if (G.equals(P, G.IDENTITY)) { throw new Error('oprf: ' + what + ' maps to the identity'); }
        return P;
    }

    /* ---------------- keys ---------------- */

    /**
     * Derive a key pair from a seed, section 3.2.
     *
     * The rejection loop is not decoration: DeriveKeyPair must not produce
     * zero, and reducing a biased value instead of retrying would skew the
     * key distribution.
     */
    function derive_keypair(seed, key_info, mode) {
        var m = mode === undefined ? MODE_OPRF : mode;
        var dst = concat([ascii('DeriveKeyPair'), context_string(m)]);
        var info = key_info || new Uint8Array(0);
        for (var counter = 0; counter < 256; counter++) {
            var sk = hash_to_scalar_dst(concat([seed, lp16(info), new Uint8Array([counter])]), dst);
            if (sk !== 0n) { return { sk: sk, pk: G.encode(G.base_mul(sk)) }; }
        }
        throw new Error('oprf: key derivation failed');
    }

    /* ---------------- client: blind ---------------- */

    /**
     * @return {{blind: bigint, blinded: Uint8Array}}
     *
     * THE BLIND MUST BE FRESH PER EVALUATION AND MUST BE KEPT. Reusing it
     * across two inputs lets the server link them; losing it makes the
     * response unusable.
     */
    function blind(input, rng, mode) {
        rng = require_rng('blind', rng);
        var m = mode === undefined ? MODE_OPRF : mode;
        var r = random_scalar(rng);
        var P = check_identity(hash_to_group(input, m), 'input');
        return { blind: r, blinded: G.encode(G.mul(r, P)) };
    }

    /* ---------------- server: evaluate ---------------- */

    /*
     * GROUP.decode refuses the identity, as section 3.3 requires of every
     * deserialised element: an identity evaluation would give the same
     * output for every input.
     */
    function decode_all(list) {
        var out = [];
        for (var i = 0; i < list.length; i++) {
            var P = G.decode(list[i]);
            if (!P) { return null; }
            out.push(P);
        }
        return out;
    }

    /** The base OPRF evaluation: one scalar multiplication, no proof. @return {Uint8Array|null} */
    function blind_evaluate(sk, blinded) {
        var B = G.decode(blinded);
        if (!B) { return null; }
        return G.encode(G.mul(smod(sk), B));
    }

    /**
     * VOPRF evaluation of a BATCH, with ONE DLEQ proof that every element was
     * evaluated under the key behind the published public key.
     *
     * @return {{evaluated: Uint8Array[], proof: Uint8Array}|null}
     */
    function blind_evaluate_verifiable_batch(sk, pk, blinded, rng) {
        rng = require_rng('blind_evaluate_verifiable', rng);
        var B = decode_all(blinded), PK = G.decode(pk);
        if (!B || !PK) { return null; }
        var k = smod(sk), E = B.map(function (b) { return G.mul(k, b); });
        var proof = generate_proof(k, G.GENERATOR, PK, B, E, rng, MODE_VOPRF);
        return { evaluated: E.map(G.encode), proof: proof };
    }

    /** VOPRF evaluation of one element. @return {{evaluated, proof}|null} */
    function blind_evaluate_verifiable(sk, pk, blinded, rng) {
        var r = blind_evaluate_verifiable_batch(sk, pk, [blinded], rng);
        return r && { evaluated: r.evaluated[0], proof: r.proof };
    }

    function tweak_scalar(info) {
        return hash_to_scalar(concat([ascii('Info'), lp16(info)]), MODE_POPRF);
    }

    /**
     * POPRF evaluation of a batch. The public input is folded into the KEY
     * rather than the message: the server evaluates with sk + H(info), and
     * the client divides it back out. That is what lets both sides agree on
     * the info without the client learning sk.
     *
     * @return {{evaluated: Uint8Array[], proof, tweaked_key}|null}
     */
    function blind_evaluate_partial_batch(sk, blinded, info, rng) {
        rng = require_rng('blind_evaluate_partial', rng);
        var B = decode_all(blinded);
        if (!B) { return null; }
        var t = smod(sk + tweak_scalar(info));
        /*
         * t = 0 means the public info hashed to the NEGATIVE of the private
         * key. A client that triggers this has to know the key, so RFC 9497
         * treats it as a signal to rotate rather than as a routine error.
         */
        if (t === 0n) { return null; }
        /*
         * THE SERVER MULTIPLIES BY t^-1, NOT t. That inversion is what makes
         * the DLEQ direction work out: blinded = t * evaluated, so the proof
         * over (evaluated, blinded) has the same exponent as (G, tweakedKey).
         */
        var ti = inv(t), E = B.map(function (b) { return G.mul(ti, b); });
        var tweaked = G.base_mul(t);
        var proof = generate_proof(t, G.GENERATOR, tweaked, E, B, rng, MODE_POPRF);
        return { evaluated: E.map(G.encode), proof: proof, tweaked_key: G.encode(tweaked) };
    }

    function blind_evaluate_partial(sk, blinded, info, rng) {
        var r = blind_evaluate_partial_batch(sk, [blinded], info, rng);
        return r && { evaluated: r.evaluated[0], proof: r.proof, tweaked_key: r.tweaked_key };
    }

    /* ---------------- client: finalize ---------------- */

    function finalize_hash(input, unblinded, info) {
        var parts = [lp16(input)];
        if (info !== undefined) { parts.push(lp16(info)); }
        parts.push(lp16(unblinded), ascii('Finalize'));
        return S.hash(concat(parts));
    }

    function unblind(input, r, E, info) {
        return finalize_hash(input, G.encode(G.mul(inv(r), E)), info);
    }

    /** @return {Uint8Array|null} the PRF output */
    function finalize(input, blind_scalar, evaluated) {
        var E = G.decode(evaluated);
        if (!E) { return null; }
        return unblind(input, blind_scalar, E);
    }

    /**
     * VOPRF finalize of a batch - CHECKS THE PROOF FIRST and returns null if
     * it fails. Skipping the check turns VOPRF back into OPRF while looking
     * like it did not, which is the failure mode worth guarding against.
     *
     * @return {Uint8Array[]|null}
     */
    function finalize_verifiable_batch(inputs, blinds, evaluated, blinded, pk, proof) {
        var E = decode_all(evaluated), B = decode_all(blinded), PK = G.decode(pk);
        if (!E || !B || !PK || E.length !== B.length || E.length !== inputs.length) { return null; }
        if (!verify_proof(G.GENERATOR, PK, B, E, proof, MODE_VOPRF)) { return null; }
        return E.map(function (e, i) { return unblind(inputs[i], blinds[i], e); });
    }

    function finalize_verifiable(input, blind_scalar, evaluated, blinded, pk, proof) {
        var r = finalize_verifiable_batch([input], [blind_scalar], [evaluated], [blinded], pk, proof);
        return r && r[0];
    }

    /** POPRF finalize of a batch: the client derives the tweaked key itself. @return {Uint8Array[]|null} */
    function finalize_partial_batch(inputs, blinds, evaluated, blinded, pk, proof, info) {
        var E = decode_all(evaluated), B = decode_all(blinded), PK = G.decode(pk);
        if (!E || !B || !PK || E.length !== B.length || E.length !== inputs.length) { return null; }
        var tweaked = G.add(PK, G.base_mul(tweak_scalar(info)));
        if (G.equals(tweaked, G.IDENTITY)) { return null; }
        if (!verify_proof(G.GENERATOR, tweaked, E, B, proof, MODE_POPRF)) { return null; }
        return E.map(function (e, i) { return unblind(inputs[i], blinds[i], e, info); });
    }

    function finalize_partial(input, blind_scalar, evaluated, blinded, pk, proof, info) {
        var r = finalize_partial_batch([input], [blind_scalar], [evaluated], [blinded], pk, proof, info);
        return r && r[0];
    }

    /* ---------------- the DLEQ proof (section 2.2) ---------------- */

    /**
     * ComputeComposites: fold a batch of (C, D) pairs into a single pair with
     * random weights derived from the transcript.
     *
     * THE BATCHING IS WHAT MAKES VOPRF PRACTICAL. One proof covers a whole
     * batch, and the weights come from a hash so the server cannot choose
     * them to hide a bad evaluation.
     */
    function compute_composites(B, C, D, mode, k) {
        var seed_dst = concat([ascii('Seed-'), context_string(mode)]);
        var seed = S.hash(concat([lp16(G.encode(B)), lp16(seed_dst)]));
        var M = G.IDENTITY, Z = G.IDENTITY;
        for (var i = 0; i < C.length; i++) {
            var di = hash_to_scalar(concat([lp16(seed), be16(i), lp16(G.encode(C[i])), lp16(G.encode(D[i])),
                                            ascii('Composite')]), mode);
            M = G.add(G.mul_vartime(di, C[i]), M);
            if (k === undefined) { Z = G.add(G.mul_vartime(di, D[i]), Z); }
        }
        /* the server knows k and can compute Z as k*M in one multiplication */
        if (k !== undefined) { Z = G.mul(k, M); }
        return { M: M, Z: Z };
    }

    function proof_challenge(B, M, Z, t2, t3, mode) {
        return hash_to_scalar(concat([lp16(G.encode(B)), lp16(G.encode(M)), lp16(G.encode(Z)),
                                      lp16(G.encode(t2)), lp16(G.encode(t3)), ascii('Challenge')]), mode);
    }

    function generate_proof(k, A, B, C, D, rng, mode) {
        var comp = compute_composites(B, C, D, mode, k);
        var r = random_scalar(rng);
        var t2 = G.mul(r, A), t3 = G.mul(r, comp.M);
        var c = proof_challenge(B, comp.M, comp.Z, t2, t3, mode);
        var s = smod(r - smod(c * k));
        return concat([G.scalar_bytes(c), G.scalar_bytes(s)]);
    }

    function verify_proof(A, B, C, D, proof, mode) {
        if (!(proof instanceof Uint8Array) || proof.length !== 2 * NS) { return false; }
        /* ⛔ canonical scalars only (DeserializeScalar): a reduced s + ORDER
           would give every proof a second encoding */
        var c = G.scalar_from_bytes(proof.subarray(0, NS));
        var s = G.scalar_from_bytes(proof.subarray(NS));
        if (c === null || s === null) { return false; }
        var comp = compute_composites(B, C, D, mode);
        var t2 = double_mul(s, A, c, B);
        var t3 = double_mul(s, comp.M, c, comp.Z);
        return proof_challenge(B, comp.M, comp.Z, t2, t3, mode) === c;
    }

    /* ---------------- the server-side shortcut ---------------- */

    /**
     * Evaluate directly, for a party that holds both the key and the input:
     * checking a client's result server-side, or a PSI server evaluating its
     * own set.
     */
    function evaluate(sk, input, mode, info) {
        var m = mode === undefined ? MODE_OPRF : mode;
        var P = check_identity(hash_to_group(input, m), 'input');
        if (m !== MODE_POPRF) { return finalize_hash(input, G.encode(G.mul(smod(sk), P))); }
        var t = smod(sk + tweak_scalar(info));
        if (t === 0n) { throw new Error('oprf: the info cancels the key'); }
        /* POPRF inverts, the other two do not - see blind_evaluate_partial */
        return finalize_hash(input, G.encode(G.mul(inv(t), P)), info);
    }

    return {
        identifier: id, GROUP: G,
        /* Ne, Ns, Nh of section 4 */
        Ne: G.encode(G.GENERATOR).length, Ns: NS, Nh: S.hash(new Uint8Array(0)).length,
        MODE_OPRF: MODE_OPRF, MODE_VOPRF: MODE_VOPRF, MODE_POPRF: MODE_POPRF,
        derive_keypair: derive_keypair,
        blind: blind,
        blind_evaluate: blind_evaluate,
        blind_evaluate_verifiable: blind_evaluate_verifiable,
        blind_evaluate_verifiable_batch: blind_evaluate_verifiable_batch,
        blind_evaluate_partial: blind_evaluate_partial,
        blind_evaluate_partial_batch: blind_evaluate_partial_batch,
        finalize: finalize,
        finalize_verifiable: finalize_verifiable,
        finalize_verifiable_batch: finalize_verifiable_batch,
        finalize_partial: finalize_partial,
        finalize_partial_batch: finalize_partial_batch,
        evaluate: evaluate,
        hash_to_group: hash_to_group,
        hash_to_scalar: hash_to_scalar,
        random_scalar: random_scalar
    };
}

/* the five suites, built on first use - a P-521 table nobody asked for is not built at load */
var CACHE = {};
function lazy(id) { return function () { return CACHE[id] || (CACHE[id] = oprf_suite(id)); }; }
export var SUITE_IDS = Object.keys(SPECS);
export function suite(id) {
    if (!SPECS[id]) { throw new Error('oprf: unknown ciphersuite ' + id); }
    return lazy(id)();
}

/* ---------------- the module-level API: ristretto255-SHA512 ---------------- */

var R = lazy('ristretto255-SHA512');
export function derive_keypair(seed, key_info, mode) { return R().derive_keypair(seed, key_info, mode); }
export function blind(input, rng, mode) { return R().blind(input, rng, mode); }
export function blind_evaluate(sk, blinded) { return R().blind_evaluate(sk, blinded); }
export function blind_evaluate_verifiable(sk, pk, blinded, rng) { return R().blind_evaluate_verifiable(sk, pk, blinded, rng); }
export function blind_evaluate_partial(sk, blinded, info, rng) { return R().blind_evaluate_partial(sk, blinded, info, rng); }
export function finalize(input, blind_scalar, evaluated) { return R().finalize(input, blind_scalar, evaluated); }
export function finalize_verifiable(input, blind_scalar, evaluated, blinded, pk, proof) {
    return R().finalize_verifiable(input, blind_scalar, evaluated, blinded, pk, proof);
}
export function finalize_partial(input, blind_scalar, evaluated, blinded, pk, proof, info) {
    return R().finalize_partial(input, blind_scalar, evaluated, blinded, pk, proof, info);
}
export function evaluate(sk, input, mode, info) { return R().evaluate(sk, input, mode, info); }
