/**
 * SLH-DSA  -  FIPS 205, formerly SPHINCS+
 *
 * The third post-quantum standard NIST published in August 2024, and the odd
 * one out: it rests on NOTHING but the security of a hash function.
 *
 * WHY THAT MATTERS. ML-KEM and ML-DSA are lattice schemes, and lattice
 * cryptanalysis is twenty years old. If Module-LWE turns out to be weaker
 * than believed, both fall together. SLH-DSA needs only that SHA-2 or SHAKE
 * behave like hash functions - an assumption the field has stress-tested for
 * decades and that no quantum algorithm meaningfully threatens beyond
 * Grover's square root. It is the hedge, and NIST standardised it explicitly
 * as one.
 *
 * THE PRICE IS EXTREME. An SLH-DSA-128s signature is 7856 bytes and takes
 * hundreds of milliseconds to produce; the 128f variant signs faster and
 * costs 17088 bytes. Against Ed25519's 64 bytes and ML-DSA-65's 3309, this is
 * a different order of thing. It is for firmware signing, certificate roots,
 * and long-lived signatures where verification is rare and the assumption
 * matters more than the size.
 *
 * HOW IT WORKS, in one paragraph. A one-time signature scheme (WOTS+) signs a
 * value by revealing hash-chain positions. One-time is a real limit, so
 * thousands of WOTS+ keys are collected into Merkle trees (XMSS), and trees
 * are stacked into a hypertree so that only the top root is the public key. A
 * separate few-time scheme (FORS) signs the message digest, and the hypertree
 * signs the FORS key. The message digest also selects WHICH leaf is used, at
 * random, which is why a few-time scheme suffices.
 *
 * THE s AND f VARIANTS trade signature size against signing speed: s has
 * fewer, taller trees (small signatures, slow signing), f has more, shorter
 * ones. Verification is fast in both.
 *
 * ALL TWELVE PARAMETER SETS: slh_dsa_shake_* and slh_dsa_sha2_*, the same
 * sizes and structure over either hash family (below).
 */

import { shake256 } from './sha3.js';
import { sha256, sha512 } from './sha2.js';
import { hmac } from './hmac.js';
import { md_prefixed } from './commons/merkle_damgard.js';
import { mgf1 } from './commons/mgf1.js';
import { concat, wr_be32, rd_be32u, bytes_to_bigint, secure_random } from './commons/bytes.js';
import { equal } from './commons/ct.js';
import { fips_interfaces } from './commons/fips_context.js';

/*
 * FIPS 205 table 2. n is the hash output width and drives everything;
 * h is the total hypertree height, d the number of layers, a and k the FORS
 * parameters, m the message digest length.
 */
export var PARAMS = {
    '128s': { n: 16, h: 63, d: 7,  hp: 9, a: 12, k: 14, lg_w: 4, m: 30 },
    '128f': { n: 16, h: 66, d: 22, hp: 3, a: 6,  k: 33, lg_w: 4, m: 34 },
    '192s': { n: 24, h: 63, d: 7,  hp: 9, a: 14, k: 17, lg_w: 4, m: 39 },
    '192f': { n: 24, h: 66, d: 22, hp: 3, a: 8,  k: 33, lg_w: 4, m: 42 },
    '256s': { n: 32, h: 64, d: 8,  hp: 8, a: 14, k: 22, lg_w: 4, m: 47 },
    '256f': { n: 32, h: 68, d: 17, hp: 4, a: 9,  k: 35, lg_w: 4, m: 49 }
};

/* ---------------- addresses ---------------- */
/*
 * Every hash call is bound to a 32-byte ADDRESS naming exactly where in the
 * structure it sits: which layer, which tree, which type of node, which
 * index. That is what stops a hash computed in one part of the hypertree from
 * being replayed in another - the whole security argument depends on it, and
 * an address field written to the wrong offset produces a scheme that is
 * self-consistent and broken.
 */

var ADRS_WOTS_HASH = 0, ADRS_WOTS_PK = 1, ADRS_TREE = 2,
    ADRS_FORS_TREE = 3, ADRS_FORS_ROOTS = 4, ADRS_WOTS_PRF = 5, ADRS_FORS_PRF = 6;

function adrs_new() { return new Uint8Array(32); }

function adrs_layer(a, v) { wr_be32(a, 0, v); }

/* a fresh address naming one XMSS tree of the hypertree: built five times,
   once through an inline function, in ht_sign and ht_verify */
function adrs_at(layer, tree) {
    var a = adrs_new();
    adrs_layer(a, layer);
    adrs_tree(a, tree);
    return a;
}

/**
 * The tree address is 12 bytes, and the value is a BIGINT.
 *
 * The hypertree index is h - h' bits wide, which is 63 for the 128f and 192f
 * parameter sets. Converting it to a Number silently loses the low bits above
 * 2^53 - and the failure is invisible in isolation, because a signer and
 * verifier that make the same mistake still agree with each other. Only a
 * second implementation catches it.
 */
function adrs_tree(a, v) {
    for (var i = 0; i < 12; i++) { a[4 + i] = 0; }
    var x = typeof v === 'bigint' ? v : BigInt(v);
    for (var j = 11; j >= 4; j--) { a[4 + j] = Number(x & 0xffn); x >>= 8n; }
}

function adrs_type(a, t) {
    wr_be32(a, 16, t);
    /* changing the type ZEROES the three fields after it - FIPS 205 requires
       this, and forgetting it leaks state between address types */
    for (var i = 20; i < 32; i++) { a[i] = 0; }
}

function adrs_keypair(a, v) { wr_be32(a, 20, v); }
function adrs_chain(a, v)   { wr_be32(a, 24, v); }
function adrs_hash(a, v)    { wr_be32(a, 28, v); }
function adrs_tree_height(a, v) { wr_be32(a, 24, v); }
function adrs_tree_index(a, v)  { wr_be32(a, 28, v); }
function adrs_get_keypair(a) { return rd_be32u(a, 20); }

/**
 * A copy of `a` retyped to `type`, keeping its key-pair address.
 *
 * FIPS 205 does this every time a WOTS+ or FORS key derives its secret
 * values (WOTS_PRF, FORS_PRF) or compresses its public key (WOTS_PK,
 * FORS_ROOTS), and the three lines were written out six times. The ORDER is
 * what matters: setting the type zeroes the key-pair field, so it has to be
 * written back afterwards.
 */
function adrs_retyped(a, type) {
    var c = Uint8Array.from(a);
    adrs_type(c, type);
    adrs_keypair(c, adrs_get_keypair(a));
    return c;
}

/* ---------------- the two hash families ---------------- */
/*
 * FIPS 205 defines two, with the same parameters and the same structure
 * above them: only these six functions differ (section 11).
 *
 * SHAKE (11.1): every function is SHAKE256 over the public seed, the address
 * and the input.
 *
 * SHA-2 (11.2), for hardware with SHA-2 acceleration and no Keccak: the
 * address is compressed to 22 bytes, PK.seed is padded to a full block (so
 * its compression is done once per key - md_prefixed), the message digest is
 * MGF1 and the message PRF is HMAC. At security category 1 everything is
 * SHA-256; at 3 and 5, H_msg, PRF_msg, H and T are SHA-512 while PRF and F
 * stay SHA-256 (11.2.2).
 */
function shake_hashes(n, m) {
    function th(pk_seed, adrs, x) { return shake256(concat([pk_seed, adrs, x]), n); }
    return {
        /** Message digest, and the tree and leaf indices derived from it. */
        h_msg: function (r, pk_seed, pk_root, msg) {
            return shake256(concat([r, pk_seed, pk_root, msg]), m);
        },
        prf: function (pk_seed, sk_seed, adrs) { return th(pk_seed, adrs, sk_seed); },
        prf_msg: function (sk_prf, opt_rand, msg) {
            return shake256(concat([sk_prf, opt_rand, msg]), n);
        },
        f: th, h: th, t: th
    };
}

/* ADRSc (FIPS 205 11.2): layer's low byte, the tree address's low 8 bytes,
   type's low byte, then the last 12 bytes as they are - 22 in all */
function adrs_compressed(a) {
    var c = new Uint8Array(22);
    c[0] = a[3];
    c.set(a.subarray(8, 16), 1);
    c[9] = a[19];
    c.set(a.subarray(20, 32), 10);
    return c;
}

function sha2_hashes(n, m) {
    var wide = n > 16, Hx = wide ? sha512 : sha256;
    /*
     * PK.seed ‖ 0^(64−n) (and 0^(128−n) for SHA-512) is one whole block,
     * compressed once per key. Bound to the pk_seed array itself: every call
     * of keygen, sign and verify slices a fresh one, so a state never outlives
     * the call that made it.
     */
    var bound = null, s256, sX;
    function states(pk_seed) {
        if (pk_seed !== bound) {
            var b = new Uint8Array(64); b.set(pk_seed);
            s256 = md_prefixed(sha256, b);
            if (wide) { var c = new Uint8Array(128); c.set(pk_seed); sX = md_prefixed(sha512, c); } else { sX = s256; }
            bound = pk_seed;
        }
    }
    function t256(pk_seed, adrs, x) { states(pk_seed); return s256(concat([adrs_compressed(adrs), x])).subarray(0, n); }
    function tX(pk_seed, adrs, x) { states(pk_seed); return sX(concat([adrs_compressed(adrs), x])).subarray(0, n); }
    return {
        h_msg: function (r, pk_seed, pk_root, msg) {
            return mgf1(concat([r, pk_seed, Hx(concat([r, pk_seed, pk_root, msg]))]), m, Hx);
        },
        prf: function (pk_seed, sk_seed, adrs) { return t256(pk_seed, adrs, sk_seed); },
        prf_msg: function (sk_prf, opt_rand, msg) {
            return hmac(Hx, sk_prf, concat([opt_rand, msg])).subarray(0, n);
        },
        f: t256, h: tX, t: tX
    };
}

var FAMILIES = { shake: shake_hashes, sha2: sha2_hashes };

/* ---------------- the scheme ---------------- */

function build(family, name) {
    var p = PARAMS[name];
    var n = p.n, w = 1 << p.lg_w;
    var len1 = Math.ceil((8 * n) / p.lg_w);
    var len2 = Math.floor(Math.log2(len1 * (w - 1)) / p.lg_w) + 1;
    var len = len1 + len2;
    var H = FAMILIES[family](n, p.m);

    var PK_BYTES = 2 * n;
    var SK_BYTES = 4 * n;
    var SIG_BYTES = (1 + p.k * (1 + p.a) + p.h + p.d * len) * n;

    /**
     * A hash chain: apply F repeatedly from position i for s steps.
     *
     * This is the whole of WOTS+. A signature reveals an intermediate point
     * in each chain; a verifier walks the rest of the way. The chain can only
     * go forward, which is why revealing a point commits to everything after
     * it and why the key is ONE-TIME - a second signature under the same key
     * reveals earlier points and lets an attacker forge.
     */
    function chain(x, i, s, pk_seed, adrs) {
        var t = x;
        for (var j = i; j < i + s; j++) {
            adrs_hash(adrs, j);
            t = H.f(pk_seed, adrs, t);
        }
        return t;
    }

    /** Split a byte string into base-w digits. */
    function base_w(bytes, out_len) {
        var out = new Uint8Array(out_len);
        var inp = 0, bits = 0, total = 0;
        for (var i = 0; i < out_len; i++) {
            if (bits === 0) { total = bytes[inp++]; bits = 8; }
            bits -= p.lg_w;
            out[i] = (total >> bits) & (w - 1);
        }
        return out;
    }

    /**
     * The message digits plus a CHECKSUM of them.
     *
     * The checksum is what makes WOTS+ a signature rather than a commitment:
     * without it an attacker could increase any digit - moving forward along
     * a chain is free - and forge. Increasing a digit decreases the checksum,
     * and the checksum's own chains would have to move backwards, which is
     * exactly what a hash chain forbids.
     */
    function wots_digits(msg) {
        var d = base_w(msg, len1);
        var csum = 0;
        for (var i = 0; i < len1; i++) { csum += w - 1 - d[i]; }
        csum <<= (8 - ((len2 * p.lg_w) % 8)) % 8;
        var csum_bytes = new Uint8Array(Math.ceil((len2 * p.lg_w) / 8));
        for (var j = csum_bytes.length - 1; j >= 0; j--) {
            csum_bytes[j] = csum & 0xff; csum = csum >>> 8;
        }
        var c = base_w(csum_bytes, len2);
        var out = new Uint8Array(len);
        out.set(d, 0); out.set(c, len1);
        return out;
    }

    function wots_pk_gen(sk_seed, pk_seed, adrs) {
        var wots_adrs = Uint8Array.from(adrs);
        var sk_adrs = adrs_retyped(adrs, ADRS_WOTS_PRF);

        var tmp = [];
        for (var i = 0; i < len; i++) {
            adrs_chain(sk_adrs, i);
            var sk = H.prf(pk_seed, sk_seed, sk_adrs);
            adrs_chain(wots_adrs, i);
            tmp.push(chain(sk, 0, w - 1, pk_seed, wots_adrs));
        }
        return H.t(pk_seed, adrs_retyped(adrs, ADRS_WOTS_PK), concat(tmp));
    }

    function wots_sign(msg, sk_seed, pk_seed, adrs) {
        var digits = wots_digits(msg);
        var sk_adrs = adrs_retyped(adrs, ADRS_WOTS_PRF);

        var out = new Uint8Array(len * n);
        for (var i = 0; i < len; i++) {
            adrs_chain(sk_adrs, i);
            var sk = H.prf(pk_seed, sk_seed, sk_adrs);
            adrs_chain(adrs, i);
            out.set(chain(sk, 0, digits[i], pk_seed, adrs), i * n);
        }
        return out;
    }

    function wots_pk_from_sig(sig, msg, pk_seed, adrs) {
        var digits = wots_digits(msg);
        var tmp = [];
        for (var i = 0; i < len; i++) {
            adrs_chain(adrs, i);
            tmp.push(chain(sig.subarray(i * n, (i + 1) * n), digits[i],
                           w - 1 - digits[i], pk_seed, adrs));
        }
        return H.t(pk_seed, adrs_retyped(adrs, ADRS_WOTS_PK), concat(tmp));
    }

    /** A Merkle node, computed recursively. */
    function xmss_node(sk_seed, i, z, pk_seed, adrs) {
        if (z === 0) {
            adrs_type(adrs, ADRS_WOTS_HASH);
            adrs_keypair(adrs, i);
            return wots_pk_gen(sk_seed, pk_seed, adrs);
        }
        var l = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
        var r = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
        adrs_type(adrs, ADRS_TREE);
        adrs_tree_height(adrs, z);
        adrs_tree_index(adrs, i);
        return H.h(pk_seed, adrs, concat([l, r]));
    }

    function xmss_sign(msg, sk_seed, idx, pk_seed, adrs) {
        var auth = [];
        for (var j = 0; j < p.hp; j++) {
            var kk = (idx >> j) ^ 1;
            auth.push(xmss_node(sk_seed, kk, j, pk_seed, Uint8Array.from(adrs)));
        }
        adrs_type(adrs, ADRS_WOTS_HASH);
        adrs_keypair(adrs, idx);
        var sig = wots_sign(msg, sk_seed, pk_seed, adrs);
        return concat([sig].concat(auth));
    }

    /*
     * One step of a Merkle authentication walk: the bit decides whether the
     * running node is the LEFT or the RIGHT input to the parent hash.
     *
     * ⭐ BOTH xmss_pk_from_sig AND fors_pk_from_sig WALK A TREE THIS WAY and
     *   each spelled the swap out as its own if/else. Getting the order
     *   backwards in one of them does not throw - it yields a wrong root, so
     *   the signature simply fails to verify, with the two branches looking
     *   equally plausible on inspection.
     */
    function hash_auth_step(bit, node, auth, pk_seed, adrs) {
        return bit === 0 ? H.h(pk_seed, adrs, concat([node, auth]))
                         : H.h(pk_seed, adrs, concat([auth, node]));
    }

    function xmss_pk_from_sig(idx, sig, msg, pk_seed, adrs) {
        adrs_type(adrs, ADRS_WOTS_HASH);
        adrs_keypair(adrs, idx);
        var node = wots_pk_from_sig(sig.subarray(0, len * n), msg, pk_seed, adrs);

        adrs_type(adrs, ADRS_TREE);
        adrs_tree_index(adrs, idx);
        for (var k2 = 0; k2 < p.hp; k2++) {
            adrs_tree_height(adrs, k2 + 1);
            var auth = sig.subarray(len * n + k2 * n, len * n + (k2 + 1) * n);
            var ti = (idx >> (k2 + 1));
            adrs_tree_index(adrs, ti);
            node = hash_auth_step((idx >> k2) & 1, node, auth, pk_seed, adrs);
        }
        return node;
    }

    var XMSS_SIG_BYTES = (len + p.hp) * n;

    function ht_sign(msg, sk_seed, pk_seed, tree, leaf) {
        var sig = [xmss_sign(msg, sk_seed, leaf, pk_seed, adrs_at(0, tree))];
        var root = xmss_pk_from_sig(leaf, sig[0], msg, pk_seed, adrs_at(0, tree));

        var t = typeof tree === 'bigint' ? tree : BigInt(tree);
        var mask = (1n << BigInt(p.hp)) - 1n;
        for (var j = 1; j < p.d; j++) {
            var lf = Number(t & mask);
            t = t >> BigInt(p.hp);
            var s = xmss_sign(root, sk_seed, lf, pk_seed, adrs_at(j, t));
            sig.push(s);
            if (j < p.d - 1) {
                root = xmss_pk_from_sig(lf, s, root, pk_seed, adrs_at(j, t));
            }
        }
        return concat(sig);
    }

    function ht_verify(msg, sig, pk_seed, tree, leaf, pk_root) {
        var node = xmss_pk_from_sig(leaf, sig.subarray(0, XMSS_SIG_BYTES), msg, pk_seed, adrs_at(0, tree));

        var t = typeof tree === 'bigint' ? tree : BigInt(tree);
        var mask = (1n << BigInt(p.hp)) - 1n;
        for (var j = 1; j < p.d; j++) {
            var lf = Number(t & mask);
            t = t >> BigInt(p.hp);
            node = xmss_pk_from_sig(lf, sig.subarray(j * XMSS_SIG_BYTES, (j + 1) * XMSS_SIG_BYTES),
                                    node, pk_seed, adrs_at(j, t));
        }
        return equal(node, pk_root) === 1;
    }

    /* ---------------- FORS ---------------- */

    function fors_sk(sk_seed, pk_seed, adrs, idx) {
        var sk_adrs = adrs_retyped(adrs, ADRS_FORS_PRF);
        adrs_tree_index(sk_adrs, idx);
        return H.prf(pk_seed, sk_seed, sk_adrs);
    }

    function fors_node(sk_seed, i, z, pk_seed, adrs) {
        if (z === 0) {
            var sk = fors_sk(sk_seed, pk_seed, adrs, i);
            adrs_tree_height(adrs, 0);
            adrs_tree_index(adrs, i);
            return H.f(pk_seed, adrs, sk);
        }
        var l = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
        var r = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
        adrs_tree_height(adrs, z);
        adrs_tree_index(adrs, i);
        return H.h(pk_seed, adrs, concat([l, r]));
    }

    /** Read k indices of a bits each from the digest. */
    function fors_indices(digest) {
        var out = new Array(p.k);
        var bit = 0;
        for (var i = 0; i < p.k; i++) {
            var v = 0;
            for (var b = 0; b < p.a; b++) {
                v = (v << 1) | ((digest[bit >> 3] >> (7 - (bit & 7))) & 1);
                bit++;
            }
            out[i] = v;
        }
        return out;
    }

    function fors_sign(digest, sk_seed, pk_seed, adrs) {
        var idx = fors_indices(digest);
        var parts = [];
        for (var i = 0; i < p.k; i++) {
            parts.push(fors_sk(sk_seed, pk_seed, adrs, (i << p.a) + idx[i]));
            for (var j = 0; j < p.a; j++) {
                var s = (idx[i] >> j) ^ 1;
                parts.push(fors_node(sk_seed, (i << (p.a - j)) + s, j, pk_seed, Uint8Array.from(adrs)));
            }
        }
        return concat(parts);
    }

    function fors_pk_from_sig(sig, digest, pk_seed, adrs) {
        var idx = fors_indices(digest);
        var roots = [];
        var stride = (1 + p.a) * n;
        for (var i = 0; i < p.k; i++) {
            var base = i * stride;
            var sk = sig.subarray(base, base + n);
            adrs_tree_height(adrs, 0);
            adrs_tree_index(adrs, (i << p.a) + idx[i]);
            var node = H.f(pk_seed, adrs, sk);
            var ti = (i << p.a) + idx[i];
            for (var j = 0; j < p.a; j++) {
                var auth = sig.subarray(base + (j + 1) * n, base + (j + 2) * n);
                adrs_tree_height(adrs, j + 1);
                ti = ti >> 1;
                adrs_tree_index(adrs, ti);
                node = hash_auth_step((idx[i] >> j) & 1, node, auth, pk_seed, adrs);
            }
            roots.push(node);
        }
        return H.t(pk_seed, adrs_retyped(adrs, ADRS_FORS_ROOTS), concat(roots));
    }

    /* ---------------- the top level ---------------- */

    var FORS_SIG_BYTES = p.k * (1 + p.a) * n;

    /** Split the message digest into the FORS input and the tree/leaf indices. */
    function split_digest(digest) {
        var md_len = Math.ceil((p.k * p.a) / 8);
        var tree_len = Math.ceil((p.h - p.hp) / 8);
        var leaf_len = Math.ceil(p.hp / 8);
        var md = digest.subarray(0, md_len);
        var tb = digest.subarray(md_len, md_len + tree_len);
        var lb = digest.subarray(md_len + tree_len, md_len + tree_len + leaf_len);
        var tree = bytes_to_bigint(tb) & ((1n << BigInt(p.h - p.hp)) - 1n);
        var leaf = 0;
        for (var j = 0; j < lb.length; j++) { leaf = (leaf << 8) | lb[j]; }
        leaf &= (1 << p.hp) - 1;
        /* the tree index stays a BigInt - see the note on adrs_tree */
        return { md: md, tree: tree, leaf: leaf };
    }

    /* the FORS key the digest selects: layer 0, its tree, its leaf - the same
       five lines opened sign() and verify() */
    function fors_adrs(sp) {
        var a = adrs_at(0, sp.tree);
        adrs_type(a, ADRS_FORS_TREE);
        adrs_keypair(a, sp.leaf);
        return a;
    }

    var API = {
        PARAMS: p,
        PK_BYTES: PK_BYTES,
        SK_BYTES: SK_BYTES,
        SIG_BYTES: SIG_BYTES,

        /**
         * @param {Uint8Array} [seed]  3n bytes: sk_seed || sk_prf || pk_seed;
         *                             omitted or null draws them from the
         *                             platform (secure_random)
         */
        keygen: function (seed) {
            if (seed == null) { seed = secure_random(3 * n); }
            if (seed.length !== 3 * n) { throw new Error('slh_dsa: seed must be 3n bytes'); }
            var sk_seed = seed.subarray(0, n);
            var sk_prf = seed.subarray(n, 2 * n);
            var pk_seed = seed.subarray(2 * n);

            var adrs = adrs_new();
            adrs_layer(adrs, p.d - 1);
            var root = xmss_node(sk_seed, 0, p.hp, pk_seed, adrs);

            var pk = concat([pk_seed, root]);
            var sk = concat([sk_seed, sk_prf, pk_seed, root]);
            return { pk: pk, sk: sk };
        },

        /**
         * slh_sign_internal (FIPS 205 Alg 19): the signature of a formatted
         * message M'. sign() and hash_sign() (fips_interfaces, below) form M'
         * and call this.
         *
         * @param {Uint8Array} mp          M'
         * @param {Uint8Array} [opt_rand]  n bytes. Omitted or null draws fresh
         *                                 ones from the platform: randomised
         *                                 signing, FIPS 205's default, more
         *                                 robust against fault attacks. The
         *                                 key's pk_seed - sk.subarray(2n, 3n) -
         *                                 gives the DETERMINISTIC variant.
         */
        sign_internal: function (sk, mp, opt_rand) {
            if (sk.length !== SK_BYTES) { throw new Error('slh_dsa: sk must be 4n bytes'); }
            if (opt_rand == null) { opt_rand = secure_random(n); }
            if (!(opt_rand instanceof Uint8Array) || opt_rand.length !== n) {
                throw new Error('slh_dsa: opt_rand must be n bytes');
            }
            var sk_seed = sk.subarray(0, n);
            var sk_prf = sk.subarray(n, 2 * n);
            var pk_seed = sk.subarray(2 * n, 3 * n);
            var pk_root = sk.subarray(3 * n);

            var r = H.prf_msg(sk_prf, opt_rand, mp);
            var digest = H.h_msg(r, pk_seed, pk_root, mp);
            var sp = split_digest(digest);

            var adrs = fors_adrs(sp);

            var fs = fors_sign(sp.md, sk_seed, pk_seed, adrs);
            var fpk = fors_pk_from_sig(fs, sp.md, pk_seed, Uint8Array.from(adrs));
            var hs = ht_sign(fpk, sk_seed, pk_seed, sp.tree, sp.leaf);

            return concat([r, fs, hs]);
        },

        /**
         * slh_verify_internal (FIPS 205 Alg 20), over M'. The context's
         * length limit is checked where M' is formed (fips_interfaces), here
         * as in signing: without it a 256-byte context encoded as length 0.
         */
        verify_internal: function (pk, mp, sig) {
            if (pk.length !== PK_BYTES || sig.length !== SIG_BYTES) { return false; }
            var pk_seed = pk.subarray(0, n), pk_root = pk.subarray(n);

            var r = sig.subarray(0, n);
            var fs = sig.subarray(n, n + FORS_SIG_BYTES);
            var hs = sig.subarray(n + FORS_SIG_BYTES);

            var digest = H.h_msg(r, pk_seed, pk_root, mp);
            var sp = split_digest(digest);

            var adrs = fors_adrs(sp);

            var fpk = fors_pk_from_sig(fs, sp.md, pk_seed, adrs);
            return ht_verify(fpk, hs, pk_seed, sp.tree, sp.leaf, pk_root);
        }
    };
    /* sign / verify (pure), hash_sign / hash_verify and their _digest forms (pre-hash, HashSLH-DSA) */
    var I = fips_interfaces('slh_dsa', API.sign_internal, API.verify_internal);
    for (var key in I) { API[key] = I[key]; }
    return API;
}

export var slh_dsa_shake_128s = /* @__PURE__ */ build('shake', '128s');
export var slh_dsa_shake_128f = /* @__PURE__ */ build('shake', '128f');
export var slh_dsa_shake_192s = /* @__PURE__ */ build('shake', '192s');
export var slh_dsa_shake_192f = /* @__PURE__ */ build('shake', '192f');
export var slh_dsa_shake_256s = /* @__PURE__ */ build('shake', '256s');
export var slh_dsa_shake_256f = /* @__PURE__ */ build('shake', '256f');

export var slh_dsa_sha2_128s = /* @__PURE__ */ build('sha2', '128s');
export var slh_dsa_sha2_128f = /* @__PURE__ */ build('sha2', '128f');
export var slh_dsa_sha2_192s = /* @__PURE__ */ build('sha2', '192s');
export var slh_dsa_sha2_192f = /* @__PURE__ */ build('sha2', '192f');
export var slh_dsa_sha2_256s = /* @__PURE__ */ build('sha2', '256s');
export var slh_dsa_sha2_256f = /* @__PURE__ */ build('sha2', '256f');
