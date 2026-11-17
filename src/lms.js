/**
 * LMS and HSS  -  RFC 8554, approved in NIST SP 800-208
 *
 * Hash-based signatures, standardised YEARS BEFORE ML-DSA and SLH-DSA - RFC
 * 8554 is from 2019 and SP 800-208 from 2020. They were the first
 * quantum-resistant signatures NIST approved, and they are already in
 * firmware-signing deployments that could not wait for the competition.
 *
 * THE DEFINING PROPERTY IS THAT THEY ARE STATEFUL, and it is a serious
 * operational constraint rather than a detail. Each private key can sign a
 * FIXED number of messages - 2^h, where h is the tree height - and each
 * signature must use a DIFFERENT leaf. Reusing a leaf reveals enough of the
 * one-time key to forge, exactly as it would for any Winternitz scheme.
 *
 * That means the signer must persist a counter and must never roll back.
 * A restored VM snapshot, a database replica promoted after a failover, or a
 * process that crashed after signing but before committing the counter can
 * all reuse a leaf and destroy the key. SP 800-208 spends most of its length
 * on this, and it is why SLH-DSA - which is stateless and needs no counter -
 * exists despite being larger and slower.
 *
 * USE THESE where the signer is a controlled, single-instance system that
 * signs rarely and can guarantee its state: firmware images, secure boot
 * roots, code-signing appliances. Do NOT use them for anything replicated.
 *
 * HSS is LMS stacked: a top tree signs the public key of a lower tree, which
 * signs the messages. That multiplies the capacity - two levels of h=20 give
 * 2^40 signatures - without the top tree's key generation becoming
 * impossible, since building a height-25 tree means computing 2^25 one-time
 * keys.
 */

import { sha256 } from './sha2.js';
import { concat, be32, be16, be8, rd_be32u, secure_random } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';
import { equal } from './commons/ct.js';

/* Domain separators, RFC 8554 section 3.1.3. They exist so that a hash
   computed for one purpose can never be reinterpreted as another. */
var D_PBLC = 0x8080, D_MESG = 0x8181, D_LEAF = 0x8282, D_INTR = 0x8383;

/** LM-OTS parameter sets. p is the number of chains, ls the checksum shift. */
export var OTS_TYPES = {
    0x00000001: { n: 32, w: 1, p: 265, ls: 7, hash: sha256 },
    0x00000002: { n: 32, w: 2, p: 133, ls: 6, hash: sha256 },
    0x00000003: { n: 32, w: 4, p: 67,  ls: 4, hash: sha256 },
    0x00000004: { n: 32, w: 8, p: 34,  ls: 0, hash: sha256 }
};

/** LMS parameter sets: tree heights from 5 to 25. */
export var LMS_TYPES = {
    0x00000005: { m: 32, h: 5,  hash: sha256 },
    0x00000006: { m: 32, h: 10, hash: sha256 },
    0x00000007: { m: 32, h: 15, hash: sha256 },
    0x00000008: { m: 32, h: 20, hash: sha256 },
    0x00000009: { m: 32, h: 25, hash: sha256 }
};



/**
 * The i-th w-bit coefficient of a byte string, most significant first.
 *
 * w divides 8 in every parameter set, so this never straddles a byte.
 */
function coef(s, i, w) {
    var per_byte = 8 / w;
    var byte = s[Math.floor(i / per_byte)];
    var shift = 8 - w * ((i % per_byte) + 1);
    return (byte >> shift) & ((1 << w) - 1);
}

/**
 * The Winternitz checksum.
 *
 * Without it an attacker could advance any chain - moving forward is free -
 * and forge. Advancing a message digit DECREASES the checksum, and the
 * checksum's own chains would have to move backwards, which a hash chain
 * forbids. It is the same argument as in SLH-DSA's WOTS+, and it is the only
 * thing that makes a hash chain into a signature.
 */
function checksum(q, ots) {
    var sum = 0;
    var u = Math.floor((8 * ots.n) / ots.w);
    for (var i = 0; i < u; i++) { sum += (1 << ots.w) - 1 - coef(q, i, ots.w); }
    return be16((sum << ots.ls) & 0xffff);
}

/**
 * One hash chain step range, from `from` to `to`.
 *
 * Every step is bound to the key identifier I, the leaf number q, the chain
 * index i and the step number j, so a chain value from one position can never
 * be reused at another.
 */
function chain(x, i, from, to, I, q, ots) {
    var t = x;
    for (var j = from; j < to; j++) {
        t = ots.hash(concat([I, be32(q), be16(i), be8(j), t]));
    }
    return t;
}

/**
 * The one-time private key for leaf q, chain i.
 *
 * SP 800-208 appendix A: a pseudorandom derivation from a single seed, so
 * that a private key is a seed rather than 2^h * p hash values. RFC 8554
 * leaves this open; deriving it is what makes the scheme storable.
 */
function ots_sk(seed, I, q, i, ots) {
    return ots.hash(concat([I, be32(q), be16(i), be8(0xff), seed]));
}

/** The one-time public key: hash all p chains run to the end. */
function ots_pk(seed, I, q, ots) {
    var parts = [I, be32(q), be16(D_PBLC)];
    for (var i = 0; i < ots.p; i++) {
        var x = ots_sk(seed, I, q, i, ots);
        parts.push(chain(x, i, 0, (1 << ots.w) - 1, I, q, ots));
    }
    return ots.hash(concat(parts));
}

/**
 * Q || Cksm(Q): the message hash and its checksum, whose w-bit digits say how
 * far along each chain the signature sits. Signing and verification each
 * computed it.
 */
function digest_digits(msg, I, q, C, ots) {
    var Q = ots.hash(concat([I, be32(q), be16(D_MESG), C, msg]));
    return concat([Q, checksum(Q, ots)]);
}

function ots_sign(msg, seed, I, q, C, ots) {
    var V = digest_digits(msg, I, q, C, ots);
    var parts = [C];
    for (var i = 0; i < ots.p; i++) {
        var a = coef(V, i, ots.w);
        var x = ots_sk(seed, I, q, i, ots);
        parts.push(chain(x, i, 0, a, I, q, ots));
    }
    return concat(parts);
}

/** Recover the one-time public key from a signature - this is verification. */
function ots_pk_from_sig(msg, sig, I, q, ots) {
    var C = sig.subarray(0, ots.n);
    var V = digest_digits(msg, I, q, C, ots);
    var parts = [I, be32(q), be16(D_PBLC)];
    for (var i = 0; i < ots.p; i++) {
        var a = coef(V, i, ots.w);
        var y = sig.subarray(ots.n * (i + 1), ots.n * (i + 2));
        parts.push(chain(y, i, a, (1 << ots.w) - 1, I, q, ots));
    }
    return ots.hash(concat(parts));
}

/* ---------------- the Merkle tree ---------------- */

/**
 * Node r of the tree, computed recursively.
 *
 * Leaves are numbered 2^h + q, so a node's index encodes its position and is
 * hashed in - the same binding that stops one subtree's node from being
 * replayed in another.
 */
function tree_node(r, seed, I, lms, ots) {
    if (r >= (1 << lms.h)) {
        return leaf_hash(lms, I, r, ots_pk(seed, I, r - (1 << lms.h), ots));
    }
    var l = tree_node(2 * r, seed, I, lms, ots);
    var rr = tree_node(2 * r + 1, seed, I, lms, ots);
    return interior_hash(lms, I, r, l, rr);
}

/* the two node hashes, shared by building the tree and walking a path up it
   in verify() - which wrote both out again, the interior one twice */
function leaf_hash(lms, I, r, ots_pub) {
    return lms.hash(concat([I, be32(r), be16(D_LEAF), ots_pub]));
}
function interior_hash(lms, I, r, left, right) {
    return lms.hash(concat([I, be32(r), be16(D_INTR), left, right]));
}

function build_lms(lms_type, ots_type) {
    var lms = LMS_TYPES[lms_type], ots = OTS_TYPES[ots_type];
    if (!lms || !ots) { throw new Error('lms: unknown parameter set'); }

    var OTS_SIG_BYTES = 4 + ots.n * (ots.p + 1);
    var SIG_BYTES = 4 + OTS_SIG_BYTES + 4 + lms.m * lms.h;
    var PK_BYTES = 8 + 16 + lms.m;

    var API = {
        LMS_TYPE: lms_type,
        OTS_TYPE: ots_type,
        HEIGHT: lms.h,
        MAX_SIGNATURES: 1 << lms.h,
        PK_BYTES: PK_BYTES,
        SIG_BYTES: SIG_BYTES,

        /**
         * @param {Uint8Array} [seed]  n bytes
         * @param {Uint8Array} [I]     16-byte key identifier, unique per key
         *
         * Each omitted or null draws fresh ones from the platform: RFC 8554
         * makes SEED a secret random value and I a random identifier (5.2),
         * and a random I is what keeps it unique.
         *
         * Building the tree computes 2^h one-time keys, so key generation for
         * h=20 is minutes of work. That is inherent, not an implementation
         * shortcoming, and it is why HSS exists.
         */
        keygen: function (seed, I) {
            if (seed == null) { seed = secure_random(ots.n); }
            if (I == null) { I = secure_random(16); }
            if (!(seed instanceof Uint8Array) || seed.length !== ots.n) { throw new Error('lms: seed must be ' + ots.n + ' bytes'); }
            if (!(I instanceof Uint8Array) || I.length !== 16) { throw new Error('lms: I must be 16 bytes'); }
            var root = tree_node(1, seed, I, lms, ots);
            return {
                pk: concat([be32(lms_type), be32(ots_type), I, root]),
                sk: { seed: seed, I: I, q: 0, root: root }
            };
        },

        /**
         * Sign, ADVANCING THE STATE.
         *
         * The returned object carries the next counter value; the caller must
         * persist it before releasing the signature. This API returns the new
         * state rather than mutating in place so that "I signed but did not
         * save the counter" is a visible mistake rather than an invisible one.
         *
         * @param {Uint8Array} [C]  n bytes of randomness (RFC 8554 4.5's
         *                          per-signature randomizer); omitted or
         *                          null draws fresh ones from the platform.
         *                          The state advances the same either way.
         */
        sign: function (sk, msg, C) {
            if (C == null) { C = secure_random(ots.n); }
            if (!(C instanceof Uint8Array) || C.length !== ots.n) { throw new Error('lms: C must be ' + ots.n + ' bytes'); }
            if (sk.q >= (1 << lms.h)) {
                throw new Error('lms: key exhausted - all 2^h signatures used');
            }
            var q = sk.q;
            var ots_sig = ots_sign(msg, sk.seed, sk.I, q, C, ots);

            var path = [];
            var r = (1 << lms.h) + q;
            for (var i = 0; i < lms.h; i++) {
                path.push(tree_node((r >> i) ^ 1, sk.seed, sk.I, lms, ots));
            }

            var sig = concat([be32(q), be32(ots_type), ots_sig, be32(lms_type)].concat(path));
            return {
                sig: sig,
                sk: { seed: sk.seed, I: sk.I, q: q + 1, root: sk.root },
                remaining: (1 << lms.h) - q - 1
            };
        },

        verify: function (pk, msg, sig) {
            if (pk.length !== PK_BYTES) { return false; }
            if (rd_be32u(pk, 0) !== lms_type || rd_be32u(pk, 4) !== ots_type) { return false; }
            var I = pk.subarray(8, 24), root = pk.subarray(24);

            if (sig.length !== SIG_BYTES) { return false; }
            var q = rd_be32u(sig, 0);
            if (q >= (1 << lms.h)) { return false; }
            if (rd_be32u(sig, 4) !== ots_type) { return false; }

            var ots_sig = sig.subarray(8, 8 + ots.n * (ots.p + 1));
            var off = 8 + ots.n * (ots.p + 1);
            if (rd_be32u(sig, off) !== lms_type) { return false; }
            off += 4;

            var kc = ots_pk_from_sig(msg, ots_sig, I, q, ots);

            /* walk the authentication path back to the root */
            var node = (1 << lms.h) + q;
            var t = leaf_hash(lms, I, node, kc);
            for (var i = 0; i < lms.h; i++) {
                var auth = sig.subarray(off + i * lms.m, off + (i + 1) * lms.m);
                /* an odd node is a right child: the sibling goes first */
                t = (node & 1) ? interior_hash(lms, I, node >> 1, auth, t)
                               : interior_hash(lms, I, node >> 1, t, auth);
                node = node >> 1;
            }
            return equal(t, root) === 1;
        }
    };
    return API;
}

/* The parameter sets, named as RFC 8554 names them. w=8 gives the smallest
   signatures and the slowest operations; w=1 the reverse. */
export var lms_sha256_h5_w8   = /* @__PURE__ */ build_lms(0x00000005, 0x00000004);
export var lms_sha256_h5_w4   = /* @__PURE__ */ build_lms(0x00000005, 0x00000003);
export var lms_sha256_h5_w2   = /* @__PURE__ */ build_lms(0x00000005, 0x00000002);
export var lms_sha256_h5_w1   = /* @__PURE__ */ build_lms(0x00000005, 0x00000001);
export var lms_sha256_h10_w8  = /* @__PURE__ */ build_lms(0x00000006, 0x00000004);
export var lms_sha256_h10_w4  = /* @__PURE__ */ build_lms(0x00000006, 0x00000003);
export var lms_sha256_h15_w8  = /* @__PURE__ */ build_lms(0x00000007, 0x00000004);
export var lms_sha256_h20_w8  = /* @__PURE__ */ build_lms(0x00000008, 0x00000004);

export { build_lms as lms };

/* ---------------- HSS ---------------- */
/**
 * Hierarchical Signature System: LMS trees stacked, RFC 8554 section 6.
 *
 * WHY IT EXISTS. Key generation for an LMS tree of height h computes 2^h
 * one-time keys - for h=25 that is 33 million, which is hours. HSS gets the
 * same capacity from two trees of height 20: the top tree signs the PUBLIC
 * KEY of a lower tree, and the lower tree signs messages. Capacity multiplies
 * while generation cost only adds.
 *
 * The cost is signature size: every level's signature and public key travel
 * with the message, so a two-level HSS signature is roughly twice an LMS one.
 *
 * THE STATE PROBLEM GETS WORSE, not better. Each level has its own counter,
 * and when a lower tree exhausts, a NEW lower tree must be generated and
 * signed by the level above - which advances the upper counter. A signer that
 * loses state now has several counters to get wrong rather than one. The same
 * warning as for LMS applies with more force.
 */

/**
 * @param {Array} levels  one entry per level, top first, each
 *                        { lms_type, ots_type }
 */
export function hss(levels) {
    if (levels.length < 1 || levels.length > 8) {
        throw new Error('hss: between one and eight levels');
    }
    var L = levels.length;
    var trees = levels.map(function (x) { return build_lms(x.lms_type, x.ots_type); });

    var API = {
        LEVELS: L,
        PK_BYTES: 4 + trees[0].PK_BYTES,

        /**
         * @param {function} [rng]  (n) -> Uint8Array, for seeds and identifiers;
         *                          omitted or null draws from the platform
         */
        keygen: function (rng) {
            rng = require_rng('hss.keygen', rng);
            var keys = [], sigs = [];
            var i;
            for (i = 0; i < L; i++) {
                keys.push(trees[i].keygen(rng(32), rng(16)));
            }
            /* each level signs the public key of the one below */
            for (i = 0; i < L - 1; i++) {
                var r = trees[i].sign(keys[i].sk, keys[i + 1].pk, rng(32));
                keys[i].sk = r.sk;
                sigs.push(r.sig);
            }
            return {
                pk: concat([be32(L), keys[0].pk]),
                sk: { keys: keys, sigs: sigs }
            };
        },

        /**
         * Sign with the BOTTOM tree, regenerating exhausted levels upward.
         *
         * The returned state must be persisted before the signature is
         * released - see the note above, which matters more here than for a
         * single tree. rng omitted or null draws from the platform.
         */
        sign: function (sk, msg, rng) {
            rng = require_rng('hss.sign', rng);
            var keys = sk.keys.slice(), sigs = sk.sigs.slice();

            /* find the deepest level with capacity left */
            var d = L - 1;
            while (d >= 0 && keys[d].sk.q >= trees[d].MAX_SIGNATURES) { d--; }
            if (d < 0) { throw new Error('hss: every level exhausted'); }

            /* regenerate every level below it and re-sign the chain */
            for (var i = d + 1; i < L; i++) {
                keys[i] = trees[i].keygen(rng(32), rng(16));
            }
            for (var j = d; j < L - 1; j++) {
                var r = trees[j].sign(keys[j].sk, keys[j + 1].pk, rng(32));
                keys[j] = { pk: keys[j].pk, sk: r.sk };
                sigs[j] = r.sig;
            }

            var bottom = trees[L - 1].sign(keys[L - 1].sk, msg, rng(32));
            keys[L - 1] = { pk: keys[L - 1].pk, sk: bottom.sk };

            var parts = [be32(L - 1)];
            for (var k = 0; k < L - 1; k++) { parts.push(sigs[k], keys[k + 1].pk); }
            parts.push(bottom.sig);

            return { sig: concat(parts), sk: { keys: keys, sigs: sigs } };
        },

        /**
         * Verify the whole chain: each level's public key must be signed by
         * the level above, and the top must be the one in the public key.
         *
         * A signature that verifies at every level but whose LEVEL COUNT does
         * not match the public key is rejected - otherwise an attacker could
         * present a shorter chain ending at an intermediate key they control.
         */
        verify: function (pk, msg, sig) {
            if (pk.length !== API.PK_BYTES) { return false; }
            if (rd_be32u(pk, 0) !== L) { return false; }
            if (sig.length < 4) { return false; }
            if (rd_be32u(sig, 0) !== L - 1) { return false; }

            var key = pk.subarray(4);
            var off = 4;
            for (var i = 0; i < L - 1; i++) {
                var slen = trees[i].SIG_BYTES;
                var plen = trees[i + 1].PK_BYTES;
                if (off + slen + plen > sig.length) { return false; }
                var s = sig.subarray(off, off + slen);
                var next = sig.subarray(off + slen, off + slen + plen);
                if (!trees[i].verify(key, next, s)) { return false; }
                key = next;
                off += slen + plen;
            }
            if (off + trees[L - 1].SIG_BYTES !== sig.length) { return false; }
            return trees[L - 1].verify(key, msg, sig.subarray(off));
        }
    };
    return API;
}
