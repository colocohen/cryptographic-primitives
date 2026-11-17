/**
 * XMSS and XMSS^MT  -  RFC 8391, with the parameter sets of NIST SP 800-208
 *
 * The other stateful hash-based signature next to LMS/HSS (lms.js), and the
 * older of the two designs. Same idea: Winternitz one-time keys at the leaves
 * of a Merkle tree, the root is the public key, and every signature consumes
 * one leaf. Same security basis: nothing but the hash function.
 *
 * WHAT IS DIFFERENT FROM LMS. Every hash call is keyed and masked. The key
 * and two bitmasks are derived from PUB_SEED and the call's 32-byte address,
 * and the inputs are XORed with the masks before hashing. That gives a proof
 * from second-preimage resistance rather than collision resistance, which is
 * why XMSS gets by with the same n. The price is three to four hash calls
 * where LMS makes one.
 *
 * STATEFUL, WITH EVERYTHING lms.js SAYS ABOUT IT. The index in the private
 * key must advance with every signature and must never roll back: a reused
 * index signs two different digests with the same one-time key, and that is
 * enough to forge. sign() therefore RETURNS the advanced key instead of
 * changing the one it was given, and the caller must persist that key before
 * releasing the signature.
 *
 * XMSS^MT is XMSS stacked into d layers, as HSS is LMS stacked, except that
 * the whole hypertree is fixed by one seed. The lower trees are not
 * generated and signed on the fly; they are recomputed from the seed. Capacity
 * is 2^h with h up to 60, while key generation builds only the top tree of
 * height h/d.
 *
 * COST. Building a tree of height t computes 2^t one-time public keys, each
 * about 1000 keyed hashes. This module signs as the reference implementation's
 * plain variant does: each signature rebuilds the subtree its auth path lies
 * in. That is seconds for t = 10, minutes for t = 16 and hours for t = 20 in
 * JavaScript, for key generation and for every signature alike. Verification
 * is d one-time keys plus d·t hashes, a few milliseconds.
 *
 * THE PARAMETER SETS. Every set RFC 8391 and SP 800-208 define (21 XMSS and
 * 56 XMSS^MT), named and numbered as the reference implementation and the
 * IANA registry name them. SP 800-208 approves the SHA2_*_256, SHA2_*_192,
 * SHAKE256_*_256 and SHAKE256_*_192 sets. RFC 8391 adds SHA2_*_512 and
 * SHAKE_*_256 (SHAKE128) and SHAKE_*_512 (SHAKE256).
 *
 * KEY FORMAT (the reference implementation's, and the one liboqs uses for
 * its test vectors):
 *   pk = OID(4) ‖ root ‖ PUB_SEED
 *   sk = OID(4) ‖ idx ‖ SK_SEED ‖ SK_PRF ‖ root ‖ PUB_SEED
 * idx is 4 bytes for XMSS and ceil(h/8) bytes for XMSS^MT. The signature is
 * idx ‖ R ‖ (WOTS+ signature ‖ auth path) for each layer, bottom layer first.
 */

import { sha256, sha512 } from './sha2.js';
import { shake128, shake256 } from './sha3.js';
import { md_prefixed } from './commons/merkle_damgard.js';
import { concat, be32, rd_be32u, bytes_to_bigint, bigint_to_bytes } from './commons/bytes.js';
import { equal } from './commons/ct.js';
import { require_rng } from './commons/primes.js';

/* ---------------- parameter sets ---------------- */

/* the hash functions, by name: [RFC name, function, n, the name's width] */
var FAMILIES = [
    ['SHA2', 'sha2', 32, 256],
    ['SHA2', 'sha2', 64, 512],
    ['SHAKE', 'shake128', 32, 256],
    ['SHAKE', 'shake256', 64, 512],
    ['SHA2', 'sha2', 24, 192],
    ['SHAKE256', 'shake256', 32, 256],
    ['SHAKE256', 'shake256', 24, 192]
];
var XMSS_HEIGHTS = [10, 16, 20];
var XMSSMT_SHAPES = [[20, 2], [20, 4], [40, 2], [40, 4], [40, 8], [60, 3], [60, 6], [60, 12]];

/*
 * The OIDs run through the families above in order: three heights each for
 * XMSS (OID 1 is SHA2_10_256, 0x15 is SHAKE256_20_192), eight shapes each for
 * XMSS^MT (1 is SHA2_20/2_256, 0x38 is SHAKE256_60/12_192).
 */
function params(mt, oid) {
    var per = mt ? XMSSMT_SHAPES.length : XMSS_HEIGHTS.length;
    var fam = FAMILIES[((oid - 1) / per) | 0];
    if (!fam || oid < 1 || (oid | 0) !== oid) { throw new Error('xmss: unknown parameter set ' + oid); }
    var shape = mt ? XMSSMT_SHAPES[(oid - 1) % per] : [XMSS_HEIGHTS[(oid - 1) % per], 1];
    var n = fam[2], h = shape[0], d = shape[1];
    var name = mt ? 'XMSSMT-' + fam[0] + '_' + h + '/' + d + '_' + fam[3] : 'XMSS-' + fam[0] + '_' + h + '_' + fam[3];
    var len1 = 2 * n, len = len1 + 3;     /* w = 16: two digits a byte, three for the checksum */
    return {
        name: name, oid: oid, func: fam[1], n: n, h: h, d: d, tree_height: h / d,
        /* toByte(X, 32) in the RFC; the SP 800-208 n = 24 sets cut it to 4 bytes */
        pad_len: n === 24 ? 4 : n,
        len1: len1, len: len,
        index_bytes: mt ? Math.ceil(h / 8) : 4
    };
}

/* ---------------- hashing ---------------- */

/* The domain separators that open every hash input (RFC 8391 5.1). */
var PAD_F = 0, PAD_H = 1, PAD_HASH = 2, PAD_PRF = 3, PAD_PRF_KEYGEN = 4;
/* X-VRF's output hash, past the RFC's five */
var PAD_VRF = 5;
var TYPE_OTS = 0, TYPE_LTREE = 1, TYPE_TREE = 2;

function core_hash(P) {
    var n = P.n;
    if (P.func === 'sha2') {
        if (n === 64) { return sha512; }
        if (n === 32) { return sha256; }
        return function (x) { return sha256(x).subarray(0, 24); };
    }
    var xof = P.func === 'shake128' ? shake128 : shake256;
    return function (x) { return xof(x, n); };
}

/*
 * H(toByte(pad) ‖ key ‖ rest) for a fixed pad and key: PRF, PRF_keygen and
 * the message's R all have this shape. With SHA-256 at n = 32 and SHA-512 at
 * n = 64, toByte(pad) ‖ key is exactly one block, so it is compressed once
 * per key and every call compresses only the rest.
 */
function keyed(P, core, pad, key) {
    var pre = new Uint8Array(P.pad_len + P.n);
    pre[P.pad_len - 1] = pad;
    pre.set(key, P.pad_len);
    if (P.func === 'sha2' && P.n !== 24) { return md_prefixed(core, pre); }
    return function (rest) { return core(concat([pre, rest])); };
}

/*
 * The hash functions bound to one key: F and H (keyed and masked through
 * PUB_SEED), the WOTS+ secret derivation (through SK_SEED, when signing or
 * generating) and the tree hashing built on them.
 */
function hasher(P, pub_seed, sk_seed) {
    var n = P.n, pl = P.pad_len, core = core_hash(P);
    var prf = keyed(P, core, PAD_PRF, pub_seed);
    var prf_keygen = sk_seed ? keyed(P, core, PAD_PRF_KEYGEN, sk_seed) : null;
    var ab = new Uint8Array(32);

    /* the address as 32 bytes, with its key-and-mask word set */
    function adrs(a, km) {
        a[7] = km;
        for (var i = 0; i < 8; i++) {
            ab[4 * i] = a[i] >>> 24; ab[4 * i + 1] = a[i] >>> 16; ab[4 * i + 2] = a[i] >>> 8; ab[4 * i + 3] = a[i];
        }
        return ab;
    }

    /*
     * The F and H inputs are built in buffers kept for the key's lifetime:
     * at 96 bytes and up, V8 gives a fresh typed array its own backing
     * store, and allocating one per call cost more than the hashing. Neither
     * function reenters itself, and the core hash copies what it reads.
     */
    var fbuf = new Uint8Array(pl + 2 * n), hbuf = new Uint8Array(pl + 3 * n);
    fbuf[pl - 1] = PAD_F; hbuf[pl - 1] = PAD_H;

    function f(x, a) {
        var buf = fbuf;
        buf.set(prf(adrs(a, 0)), pl);
        var m = prf(adrs(a, 1));
        for (var i = 0; i < n; i++) { buf[pl + n + i] = x[i] ^ m[i]; }
        return core(buf);
    }

    function h(left, right, a) {
        var buf = hbuf;
        buf.set(prf(adrs(a, 0)), pl);
        var m1 = prf(adrs(a, 1)), m2 = prf(adrs(a, 2));
        for (var i = 0; i < n; i++) {
            buf[pl + n + i] = left[i] ^ m1[i];
            buf[pl + 2 * n + i] = right[i] ^ m2[i];
        }
        return core(buf);
    }

    /* steps of chain a[5], from position `from` */
    function chain(x, from, steps, a) {
        for (var j = from; j < from + steps && j < 16; j++) { a[6] = j; x = f(x, a); }
        return x;
    }

    /* the message digits and the checksum's three: lengths along each chain */
    function digits(msg) {
        var out = new Array(P.len), csum = 0;
        for (var i = 0; i < n; i++) { out[2 * i] = msg[i] >> 4; out[2 * i + 1] = msg[i] & 15; }
        for (var k = 0; k < P.len1; k++) { csum += 15 - out[k]; }
        out[P.len1] = (csum >> 8) & 15; out[P.len1 + 1] = (csum >> 4) & 15; out[P.len1 + 2] = csum & 15;
        return out;
    }

    /* the WOTS+ secret for chain i of the key at address a */
    function wots_secret(a, i) {
        a[5] = i; a[6] = 0;
        return prf_keygen(concat([pub_seed, adrs(a, 0)]));
    }

    function wots_pk(a) {
        var pk = new Array(P.len);
        for (var i = 0; i < P.len; i++) { pk[i] = chain(wots_secret(a, i), 0, 15, a); }
        return pk;
    }

    function wots_sign(msg, a) {
        var dg = digits(msg), sig = new Array(P.len);
        for (var i = 0; i < P.len; i++) { sig[i] = chain(wots_secret(a, i), 0, dg[i], a); }
        return sig;
    }

    function wots_pk_from_sig(sig, off, msg, a) {
        var dg = digits(msg), pk = new Array(P.len);
        for (var i = 0; i < P.len; i++) {
            a[5] = i;
            pk[i] = chain(sig.subarray(off + i * n, off + (i + 1) * n), dg[i], 15 - dg[i], a);
        }
        return pk;
    }

    /* the L-tree: a WOTS+ public key compressed to one node, an odd node
       carried up unhashed */
    function l_tree(pk, a) {
        var l = pk.length, height = 0;
        a[5] = 0;
        while (l > 1) {
            for (var i = 0; i < (l >> 1); i++) { a[6] = i; pk[i] = h(pk[2 * i], pk[2 * i + 1], a); }
            if (l & 1) { pk[l >> 1] = pk[l - 1]; l = (l >> 1) + 1; } else { l = l >> 1; }
            a[5] = ++height;
        }
        return pk[0];
    }

    function address(layer, tree, type) {
        var a = new Uint32Array(8);
        a[0] = layer; a[1] = Number(tree >> 32n); a[2] = Number(tree & 0xffffffffn); a[3] = type;
        return a;
    }

    function leaf(layer, tree, i) {
        var ots = address(layer, tree, TYPE_OTS), lt = address(layer, tree, TYPE_LTREE);
        ots[4] = i; lt[4] = i;
        return l_tree(wots_pk(ots), lt);
    }

    /*
     * The root of tree `tree` on `layer`, and the auth path of leaf `at`:
     * the leaves left to right with a stack, merging equal heights.
     */
    function treehash(layer, tree, at) {
        var t = P.tree_height, node = address(layer, tree, TYPE_TREE);
        var stack = [], heights = [], auth = new Array(t);
        for (var i = 0; i < (1 << t); i++) {
            stack.push(leaf(layer, tree, i)); heights.push(0);
            if ((at ^ 1) === i) { auth[0] = stack[stack.length - 1]; }
            while (stack.length >= 2 && heights[heights.length - 1] === heights[heights.length - 2]) {
                var ht = heights[heights.length - 1], idx = i >> (ht + 1);
                node[5] = ht; node[6] = idx;
                var right = stack.pop(); heights.pop();
                stack[stack.length - 1] = h(stack[stack.length - 1], right, node);
                heights[heights.length - 1] = ht + 1;
                if (((at >> (ht + 1)) ^ 1) === idx) { auth[ht + 1] = stack[stack.length - 1]; }
            }
        }
        return { root: stack[0], auth: auth };
    }

    function compute_root(lf, at, sig, off, layer, tree) {
        var a = address(layer, tree, TYPE_TREE), x = lf;
        for (var i = 0; i < P.tree_height; i++) {
            var sib = sig.subarray(off + i * n, off + (i + 1) * n);
            a[5] = i; a[6] = at >>> (i + 1);
            x = ((at >>> i) & 1) ? h(sib, x, a) : h(x, sib, a);
        }
        return x;
    }

    return {
        wots_sign: wots_sign, wots_pk_from_sig: wots_pk_from_sig, l_tree: l_tree,
        address: address, treehash: treehash, compute_root: compute_root
    };
}

/* ---------------- the scheme ---------------- */

function build(mt, oid) {
    var P = params(mt, oid), n = P.n, ib = P.index_bytes, t = P.tree_height;
    var core = core_hash(P);
    var OID = be32(oid);
    var PK_BYTES = 4 + 2 * n, SK_BYTES = 4 + ib + 4 * n;
    var SIG_BYTES = ib + n + P.d * (P.len + t) * n;
    /*
     * 2^h - 1 signatures, indices 0 to 2^h - 2, as in the reference
     * implementation: the all-ones index 2^h - 1 marks a used-up key. That
     * marker always fits in the index field, where 2^h itself would not when
     * 8 divides h - an index that wrapped to 0 would sign with leaf 0 again.
     */
    var MAX = (1n << BigInt(P.h)) - 1n;
    var LEAF_MASK = (1n << BigInt(t)) - 1n;

    function check_oid(b, what) {
        if (rd_be32u(b, 0) !== oid) { throw new Error('xmss: the ' + what + ' is for another parameter set'); }
    }

    /* H_msg(R ‖ root ‖ toByte(idx, n), M) */
    function h_msg(R, root, idx, msg) {
        var pre = new Uint8Array(P.pad_len);
        pre[P.pad_len - 1] = PAD_HASH;
        return core(concat([pre, R, root, bigint_to_bytes(idx, n), msg]));
    }

    function parse_sk(sk) {
        if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES) { throw new Error('xmss: the private key is ' + SK_BYTES + ' bytes'); }
        check_oid(sk, 'private key');
        var o = 4 + ib;
        return {
            idx: bytes_to_bigint(sk.subarray(4, o)),
            sk_seed: sk.subarray(o, o + n), sk_prf: sk.subarray(o + n, o + 2 * n),
            root: sk.subarray(o + 2 * n, o + 3 * n), pub_seed: sk.subarray(o + 3 * n, o + 4 * n)
        };
    }
    /* idx || R || (WOTS+ signature || auth path) per layer, at leaf idx */
    function sign_at(k, idx, R, msg) {
        var H = hasher(P, k.pub_seed, k.sk_seed), node = h_msg(R, k.root, idx, msg);
        var parts = [bigint_to_bytes(idx, ib), R], rest = idx;
        for (var layer = 0; layer < P.d; layer++) {
            var at = Number(rest & LEAF_MASK);
            rest >>= BigInt(t);
            var ots = H.address(layer, rest, TYPE_OTS);
            ots[4] = at;
            parts = parts.concat(H.wots_sign(node, ots));
            var tr = H.treehash(layer, rest, at);
            parts = parts.concat(tr.auth);
            node = tr.root;
        }
        return concat(parts);
    }
    function vrf_counter(ctr) {
        var c = typeof ctr === 'bigint' ? ctr : BigInt(ctr);
        if (c < 0n || c >= (1n << BigInt(P.h))) { throw new Error('xmss: the VRF counter is a leaf index, 0 to 2^h - 1'); }
        return c;
    }
    function vrf_output(proof, x) {
        var pre = new Uint8Array(P.pad_len);
        pre[P.pad_len - 1] = PAD_VRF;
        return core(concat([pre, proof, x]));
    }

    var API = {
        NAME: P.name,
        OID: oid,
        N: n,
        HEIGHT: P.h,
        LAYERS: P.d,
        PK_BYTES: PK_BYTES,
        SK_BYTES: SK_BYTES,
        SIG_BYTES: SIG_BYTES,
        /** 2^h - 1, as a BigInt: XMSS^MT goes up to 2^60 - 1. */
        MAX_SIGNATURES: MAX,

        /**
         * Key generation from 3n seed bytes: SK_SEED ‖ SK_PRF ‖ PUB_SEED.
         * Builds the top tree, 2^(h/d) one-time keys (see COST above).
         */
        keygen_derand: function (seed) {
            if (!(seed instanceof Uint8Array) || seed.length !== 3 * n) { throw new Error('xmss: the seed is ' + 3 * n + ' bytes'); }
            var sk_seed = seed.slice(0, n), sk_prf = seed.slice(n, 2 * n), pub_seed = seed.slice(2 * n);
            var root = hasher(P, pub_seed, sk_seed).treehash(P.d - 1, 0n, 0).root;
            return {
                pk: concat([OID, root, pub_seed]),
                sk: concat([OID, new Uint8Array(ib), sk_seed, sk_prf, root, pub_seed])
            };
        },

        /** @param {function(number): Uint8Array} [rng]  omitted or null draws fresh bytes from the platform */
        keygen: function (rng) {
            rng = require_rng('xmss.keygen', rng);
            return API.keygen_derand(rng(3 * n));
        },

        /**
         * Sign, ADVANCING THE STATE. Deterministic: R is PRF(SK_PRF, idx).
         *
         * Returns { sig, sk, remaining }: sk is the key with the next index,
         * to be persisted before sig is released, and remaining (a BigInt) is
         * how many signatures it has left. The key passed in is not changed.
         * After the last signature, sk has the all-ones index and its
         * SK_SEED and SK_PRF are zero.
         */
        sign: function (sk, msg) {
            var k = parse_sk(sk), idx = k.idx;
            if (idx >= MAX) { throw new Error('xmss: key exhausted - all 2^h - 1 signatures used'); }
            var R = keyed(P, core, PAD_PRF, k.sk_prf)(bigint_to_bytes(idx, 32));
            var sig = sign_at(k, idx, R, msg);
            var next = sk.slice();
            next.set(bigint_to_bytes(idx + 1n, ib), 4);
            /* the used-up key keeps nothing to sign with */
            if (idx + 1n === MAX) { next.fill(0, 4 + ib, 4 + ib + 2 * n); }
            return { sig: sig, sk: next, remaining: MAX - idx - 1n };
        },

        /**
         * X-VRF (Buser et al., ePrint 2021/302): a VRF from deterministic
         * XMSS. The leaf is the public counter ctr (a block number mod 2^h,
         * say) and the randomizer R is zero, so for one key, input and ctr
         * there is one valid proof - a WOTS+ signature is unique for its
         * one-time key - and the output is its hash:
         *
         *     proof = the XMSS signature of x at leaf ctr, R = 0^n
         *     y     = H(toByte(5, pad) || proof || x), n bytes
         *
         * STATELESS, BUT ONE INPUT PER COUNTER: a second input at the same
         * ctr is a second signature by that one-time key. The key's idx is
         * not read or advanced; the counter is the state.
         * @return {{y: Uint8Array, proof: Uint8Array}}
         */
        vrf_eval: function (sk, x, ctr) {
            var k = parse_sk(sk), c = vrf_counter(ctr);
            var proof = sign_at(k, c, new Uint8Array(n), x);
            return { y: vrf_output(proof, x), proof: proof };
        },
        /** @return {Uint8Array|null} y, when proof is the one proof for (pk, x, ctr) */
        vrf_verify: function (pk, x, ctr, proof) {
            var c = vrf_counter(ctr);
            if (!(proof instanceof Uint8Array) || proof.length !== SIG_BYTES) { return null; }
            if (bytes_to_bigint(proof.subarray(0, ib)) !== c) { return null; }
            for (var i = 0; i < n; i++) { if (proof[ib + i] !== 0) { return null; } }
            return API.verify(pk, x, proof) ? vrf_output(proof, x) : null;
        },

        verify: function (pk, msg, sig) {
            if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES || rd_be32u(pk, 0) !== oid) { return false; }
            if (!(sig instanceof Uint8Array) || sig.length !== SIG_BYTES) { return false; }
            var idx = bytes_to_bigint(sig.subarray(0, ib));
            /* any index below 2^h is a leaf: another signer may use the last */
            if (idx > MAX) { return false; }
            var root = pk.subarray(4, 4 + n), H = hasher(P, pk.subarray(4 + n), null);
            var node = h_msg(sig.subarray(ib, ib + n), root, idx, msg);
            var off = ib + n, rest = idx;
            for (var layer = 0; layer < P.d; layer++) {
                var at = Number(rest & LEAF_MASK);
                rest >>= BigInt(t);
                var ots = H.address(layer, rest, TYPE_OTS), lt = H.address(layer, rest, TYPE_LTREE);
                ots[4] = at; lt[4] = at;
                var lf = H.l_tree(H.wots_pk_from_sig(sig, off, node, ots), lt);
                off += P.len * n;
                node = H.compute_root(lf, at, sig, off, layer, rest);
                off += t * n;
            }
            return equal(node, root) === 1;
        }
    };
    return API;
}

/** An XMSS parameter set by OID (1 to 0x15). */
export function xmss(oid) { return build(false, oid); }
/** An XMSS^MT parameter set by OID (1 to 0x38). */
export function xmssmt(oid) { return build(true, oid); }

/* XMSS, RFC 8391 and SP 800-208. SHAKE is SHAKE128 at n = 32 and SHAKE256 at n = 64. */
export var xmss_sha2_10_256 = /* @__PURE__ */ xmss(0x01);
export var xmss_sha2_16_256 = /* @__PURE__ */ xmss(0x02);
export var xmss_sha2_20_256 = /* @__PURE__ */ xmss(0x03);
export var xmss_sha2_10_512 = /* @__PURE__ */ xmss(0x04);
export var xmss_sha2_16_512 = /* @__PURE__ */ xmss(0x05);
export var xmss_sha2_20_512 = /* @__PURE__ */ xmss(0x06);
export var xmss_shake_10_256 = /* @__PURE__ */ xmss(0x07);
export var xmss_shake_16_256 = /* @__PURE__ */ xmss(0x08);
export var xmss_shake_20_256 = /* @__PURE__ */ xmss(0x09);
export var xmss_shake_10_512 = /* @__PURE__ */ xmss(0x0a);
export var xmss_shake_16_512 = /* @__PURE__ */ xmss(0x0b);
export var xmss_shake_20_512 = /* @__PURE__ */ xmss(0x0c);
export var xmss_sha2_10_192 = /* @__PURE__ */ xmss(0x0d);
export var xmss_sha2_16_192 = /* @__PURE__ */ xmss(0x0e);
export var xmss_sha2_20_192 = /* @__PURE__ */ xmss(0x0f);
export var xmss_shake256_10_256 = /* @__PURE__ */ xmss(0x10);
export var xmss_shake256_16_256 = /* @__PURE__ */ xmss(0x11);
export var xmss_shake256_20_256 = /* @__PURE__ */ xmss(0x12);
export var xmss_shake256_10_192 = /* @__PURE__ */ xmss(0x13);
export var xmss_shake256_16_192 = /* @__PURE__ */ xmss(0x14);
export var xmss_shake256_20_192 = /* @__PURE__ */ xmss(0x15);

/* XMSS^MT: xmssmt_<family>_<h>_<d>_<width> is XMSSMT-<family>_<h>/<d>_<width>. */
export var xmssmt_sha2_20_2_256 = /* @__PURE__ */ xmssmt(0x01);
export var xmssmt_sha2_20_4_256 = /* @__PURE__ */ xmssmt(0x02);
export var xmssmt_sha2_40_2_256 = /* @__PURE__ */ xmssmt(0x03);
export var xmssmt_sha2_40_4_256 = /* @__PURE__ */ xmssmt(0x04);
export var xmssmt_sha2_40_8_256 = /* @__PURE__ */ xmssmt(0x05);
export var xmssmt_sha2_60_3_256 = /* @__PURE__ */ xmssmt(0x06);
export var xmssmt_sha2_60_6_256 = /* @__PURE__ */ xmssmt(0x07);
export var xmssmt_sha2_60_12_256 = /* @__PURE__ */ xmssmt(0x08);
export var xmssmt_sha2_20_2_512 = /* @__PURE__ */ xmssmt(0x09);
export var xmssmt_sha2_20_4_512 = /* @__PURE__ */ xmssmt(0x0a);
export var xmssmt_sha2_40_2_512 = /* @__PURE__ */ xmssmt(0x0b);
export var xmssmt_sha2_40_4_512 = /* @__PURE__ */ xmssmt(0x0c);
export var xmssmt_sha2_40_8_512 = /* @__PURE__ */ xmssmt(0x0d);
export var xmssmt_sha2_60_3_512 = /* @__PURE__ */ xmssmt(0x0e);
export var xmssmt_sha2_60_6_512 = /* @__PURE__ */ xmssmt(0x0f);
export var xmssmt_sha2_60_12_512 = /* @__PURE__ */ xmssmt(0x10);
export var xmssmt_shake_20_2_256 = /* @__PURE__ */ xmssmt(0x11);
export var xmssmt_shake_20_4_256 = /* @__PURE__ */ xmssmt(0x12);
export var xmssmt_shake_40_2_256 = /* @__PURE__ */ xmssmt(0x13);
export var xmssmt_shake_40_4_256 = /* @__PURE__ */ xmssmt(0x14);
export var xmssmt_shake_40_8_256 = /* @__PURE__ */ xmssmt(0x15);
export var xmssmt_shake_60_3_256 = /* @__PURE__ */ xmssmt(0x16);
export var xmssmt_shake_60_6_256 = /* @__PURE__ */ xmssmt(0x17);
export var xmssmt_shake_60_12_256 = /* @__PURE__ */ xmssmt(0x18);
export var xmssmt_shake_20_2_512 = /* @__PURE__ */ xmssmt(0x19);
export var xmssmt_shake_20_4_512 = /* @__PURE__ */ xmssmt(0x1a);
export var xmssmt_shake_40_2_512 = /* @__PURE__ */ xmssmt(0x1b);
export var xmssmt_shake_40_4_512 = /* @__PURE__ */ xmssmt(0x1c);
export var xmssmt_shake_40_8_512 = /* @__PURE__ */ xmssmt(0x1d);
export var xmssmt_shake_60_3_512 = /* @__PURE__ */ xmssmt(0x1e);
export var xmssmt_shake_60_6_512 = /* @__PURE__ */ xmssmt(0x1f);
export var xmssmt_shake_60_12_512 = /* @__PURE__ */ xmssmt(0x20);
export var xmssmt_sha2_20_2_192 = /* @__PURE__ */ xmssmt(0x21);
export var xmssmt_sha2_20_4_192 = /* @__PURE__ */ xmssmt(0x22);
export var xmssmt_sha2_40_2_192 = /* @__PURE__ */ xmssmt(0x23);
export var xmssmt_sha2_40_4_192 = /* @__PURE__ */ xmssmt(0x24);
export var xmssmt_sha2_40_8_192 = /* @__PURE__ */ xmssmt(0x25);
export var xmssmt_sha2_60_3_192 = /* @__PURE__ */ xmssmt(0x26);
export var xmssmt_sha2_60_6_192 = /* @__PURE__ */ xmssmt(0x27);
export var xmssmt_sha2_60_12_192 = /* @__PURE__ */ xmssmt(0x28);
export var xmssmt_shake256_20_2_256 = /* @__PURE__ */ xmssmt(0x29);
export var xmssmt_shake256_20_4_256 = /* @__PURE__ */ xmssmt(0x2a);
export var xmssmt_shake256_40_2_256 = /* @__PURE__ */ xmssmt(0x2b);
export var xmssmt_shake256_40_4_256 = /* @__PURE__ */ xmssmt(0x2c);
export var xmssmt_shake256_40_8_256 = /* @__PURE__ */ xmssmt(0x2d);
export var xmssmt_shake256_60_3_256 = /* @__PURE__ */ xmssmt(0x2e);
export var xmssmt_shake256_60_6_256 = /* @__PURE__ */ xmssmt(0x2f);
export var xmssmt_shake256_60_12_256 = /* @__PURE__ */ xmssmt(0x30);
export var xmssmt_shake256_20_2_192 = /* @__PURE__ */ xmssmt(0x31);
export var xmssmt_shake256_20_4_192 = /* @__PURE__ */ xmssmt(0x32);
export var xmssmt_shake256_40_2_192 = /* @__PURE__ */ xmssmt(0x33);
export var xmssmt_shake256_40_4_192 = /* @__PURE__ */ xmssmt(0x34);
export var xmssmt_shake256_40_8_192 = /* @__PURE__ */ xmssmt(0x35);
export var xmssmt_shake256_60_3_192 = /* @__PURE__ */ xmssmt(0x36);
export var xmssmt_shake256_60_6_192 = /* @__PURE__ */ xmssmt(0x37);
export var xmssmt_shake256_60_12_192 = /* @__PURE__ */ xmssmt(0x38);
