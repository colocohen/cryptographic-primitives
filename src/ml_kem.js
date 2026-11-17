/**
 * ML-KEM  -  FIPS 203, formerly CRYSTALS-Kyber
 *
 * The post-quantum key encapsulation mechanism NIST standardised in August
 * 2024. It replaces the key-agreement half of what elliptic curves do: where
 * X25519 has both sides compute a shared point, ML-KEM has one side ENCAPSULATE
 * a secret to the other's public key.
 *
 * WHY IT EXISTS. Shor's algorithm breaks every scheme in this library that
 * rests on discrete logarithms or factoring - X25519, ECDSA, EdDSA, BLS, RSA,
 * all of them - on a quantum computer large enough to run it. No such machine
 * exists and none may for decades, but the threat is retroactive: traffic
 * captured today can be decrypted later. That is why deployment has already
 * happened, years ahead of any actual quantum computer.
 *
 * ITS HARDNESS IS LATTICE-BASED: Module-LWE, the difficulty of recovering a
 * short secret from noisy linear equations over a polynomial ring. That has
 * no known quantum speedup beyond Grover's square root, which is why the
 * parameters are sized the way they are.
 *
 * THE PRICE IS SIZE. An X25519 public key is 32 bytes; an ML-KEM-768 key is
 * 1184, and its ciphertext is 1088. That is why every real deployment is
 * HYBRID - X25519 alongside ML-KEM, with both secrets fed into the KDF - so
 * that breaking the result needs both a quantum computer and a break of the
 * lattice assumption. Chrome and Cloudflare shipped X25519MLKEM768 in 2024
 * for exactly that reason.
 *
 * A KEM IS NOT A DIFFIE-HELLMAN. It is not interactive and it is not
 * symmetric: the encapsulator generates the secret and the decapsulator
 * recovers it. Protocols that assumed contributory key agreement need
 * rethinking, not just substitution.
 */

import { sha3_256, sha3_512, shake256 } from './sha3.js';
import { concat, secure_random } from './commons/bytes.js';
import { equal, select_bytes, held } from './commons/ct.js';
import { pack_bits, unpack_bits } from './commons/bitpack.js';
import * as RING from './commons/kyber_ring.js';
import { Q, N, ntt, ntt_inverse, poly_add, poly_sub, poly_reduce, poly_new, to_positive } from './commons/kyber_ring.js';
import { module_lattice } from './commons/module_lattice.js';

var LAT = /* @__PURE__ */ module_lattice(RING);

/*
 * The three parameter sets. k is the module rank - the number of polynomials
 * in a vector - and everything else scales with it. eta controls the noise
 * magnitude; du and dv are how many bits each ciphertext coefficient keeps
 * after compression, which is where most of the size saving comes from.
 */
export var PARAMS = {
    512:  { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 },
    768:  { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 },
    1024: { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 }
};

/* ---------------- sampling ---------------- */

/**
 * SampleNTT: a uniformly random polynomial in the NTT domain from
 * SHAKE128(seed ‖ i ‖ j), by rejection sampling (commons/module_lattice.js).
 * Exported for ot_kem.js, which samples t̂ the same way.
 */
export function sample_ntt(seed, i, j) { return LAT.uniform(seed, i, j); }

/**
 * SamplePolyCBD: noise from a centred binomial distribution.
 *
 * Each coefficient is the difference of two counts of set bits, which gives a
 * small value centred on zero. A Gaussian would be closer to the theory but
 * needs either a table or floating point, and both leak through timing - the
 * binomial is chosen because it can be computed with bit operations alone.
 */
function sample_cbd(bytes, eta) {
    var a = poly_new();
    if (eta === 2) {
        for (var i = 0; i < N / 8; i++) {
            var t = bytes[4 * i] | (bytes[4 * i + 1] << 8) |
                    (bytes[4 * i + 2] << 16) | (bytes[4 * i + 3] << 24);
            var d = t & 0x55555555;
            d += (t >>> 1) & 0x55555555;
            for (var j = 0; j < 8; j++) {
                var x = (d >>> (4 * j)) & 0x3;
                var y = (d >>> (4 * j + 2)) & 0x3;
                a[8 * i + j] = x - y;
            }
        }
    } else {
        /* eta = 3 packs three bits per half, so the stride is 3 bytes per 4 */
        for (var i2 = 0; i2 < N / 4; i2++) {
            var t2 = bytes[3 * i2] | (bytes[3 * i2 + 1] << 8) | (bytes[3 * i2 + 2] << 16);
            var d2 = t2 & 0x00249249;
            d2 += (t2 >>> 1) & 0x00249249;
            d2 += (t2 >>> 2) & 0x00249249;
            for (var j2 = 0; j2 < 4; j2++) {
                var x2 = (d2 >>> (6 * j2)) & 0x7;
                var y2 = (d2 >>> (6 * j2 + 3)) & 0x7;
                a[4 * i2 + j2] = x2 - y2;
            }
        }
    }
    return a;
}

function prf(eta, seed, nonce) {
    return shake256(concat([seed, new Uint8Array([nonce])]), 64 * eta);
}

/* ---------------- compression and encoding ---------------- */

/**
 * Compress a coefficient to d bits.
 *
 * This is LOSSY and deliberately so: it is where the ciphertext gets small
 * enough to ship. The scheme tolerates the error because the decryption
 * already has to survive the noise that makes the problem hard - compression
 * noise just adds to a budget that exists anyway.
 *
 * Exported with decompress for kemeleon.js, whose ciphertext encoding
 * inverts this step.
 */
export function compress(x, d) {
    var v = to_positive(x);
    return Math.floor((v * (1 << d) + (Q >> 1)) / Q) & ((1 << d) - 1);
}

export function decompress(y, d) {
    return Math.floor((y * Q + (1 << (d - 1))) / (1 << d));
}

/**
 * Pack 256 d-bit values into 32d bytes, little-endian bit order.
 *
 * The loops are commons/bitpack.js, shared with ml_dsa.js, which had the
 * same two under other names. Decoding writes into poly_new() - an
 * Int16Array, the representation commons/kyber_ring.js measured as fastest -
 * which is why the shared reader takes its output array from the caller.
 */
function byte_encode(a, d) {
    var out = new Uint8Array(32 * d);
    pack_bits(a, d, out, 0);
    return out;
}

function byte_decode(bytes, d) {
    return unpack_bits(bytes, 0, N, d, poly_new());
}

function poly_compress(a, d) {
    var t = poly_new();
    for (var i = 0; i < N; i++) { t[i] = compress(a[i], d); }
    return byte_encode(t, d);
}

function poly_decompress(bytes, d) {
    var t = byte_decode(bytes, d);
    var a = poly_new();
    for (var i = 0; i < N; i++) { a[i] = decompress(t[i], d); }
    return a;
}

/* ---------------- K-PKE, the public-key encryption underneath ---------------- */



function pke_keygen(d, p) {
    var k = p.k;
    var g = sha3_512(concat([d, new Uint8Array([k])]));
    var rho = g.subarray(0, 32), sigma = g.subarray(32);

    var A = LAT.matrix(rho, k, k, false);

    var s = pke_secret(sigma, p), e = [], i;
    for (i = 0; i < k; i++) { e.push(sample_cbd(prf(p.eta1, sigma, k + i), p.eta1)); }
    for (i = 0; i < k; i++) { ntt(e[i]); }

    var t = [];
    for (i = 0; i < k; i++) {
        var acc = LAT.row_dot(A[i], s);
        poly_add(acc, acc, e[i]);
        poly_reduce(acc);
        t.push(acc);
    }

    var ek = new Uint8Array(384 * k + 32);
    for (i = 0; i < k; i++) { ek.set(encode12(t[i]), 384 * i); }
    ek.set(rho, 384 * k);

    return { ek: ek, dk: pke_dk(s, k) };
}

/*
 * K-PKE's secret s, in the NTT domain: the first k samples from sigma
 * (nonces 0 to k - 1; e takes the next k). With no A, it is the cheap part
 * of a key pair - and all of dk_PKE.
 */
function pke_secret(sigma, p) {
    var s = [];
    for (var i = 0; i < p.k; i++) { s.push(sample_cbd(prf(p.eta1, sigma, i), p.eta1)); ntt(s[i]); }
    return s;
}
/* dk = dk_PKE || ek || H(ek) || z (FIPS 203 Algorithm 16) */
function kem_dk(dk_pke, ek, z) {
    var n = dk_pke.length, dk = new Uint8Array(2 * n + 96);
    dk.set(dk_pke, 0);
    dk.set(ek, n);
    dk.set(sha3_256(ek), 2 * n + 32);
    dk.set(z, 2 * n + 64);
    return dk;
}
function pke_dk(s, k) {
    var dk = new Uint8Array(384 * k);
    for (var i = 0; i < k; i++) { dk.set(encode12(s[i]), 384 * i); }
    return dk;
}

function encode12(a) {
    var t = poly_new();
    for (var i = 0; i < N; i++) { t[i] = to_positive(a[i]); }
    return byte_encode(t, 12);
}

function pke_encrypt(ek, m, r, p) {
    var k = p.k, i;
    var t = [];
    for (i = 0; i < k; i++) { t.push(byte_decode(ek.subarray(384 * i, 384 * (i + 1)), 12)); }
    var rho = ek.subarray(384 * k, 384 * k + 32);

    var A = LAT.matrix(rho, k, k, true);

    var y = [], e1 = [], nonce = 0;
    for (i = 0; i < k; i++) { y.push(sample_cbd(prf(p.eta1, r, nonce++), p.eta1)); }
    for (i = 0; i < k; i++) { e1.push(sample_cbd(prf(p.eta2, r, nonce++), p.eta2)); }
    var e2 = sample_cbd(prf(p.eta2, r, nonce), p.eta2);

    for (i = 0; i < k; i++) { ntt(y[i]); }

    var u = [];
    for (i = 0; i < k; i++) {
        var acc = LAT.row_dot(A[i], y);
        ntt_inverse(acc);
        poly_add(acc, acc, e1[i]);
        poly_reduce(acc);
        u.push(acc);
    }

    var v = LAT.row_dot(t, y);
    ntt_inverse(v);
    poly_add(v, v, e2);

    /* the message bit becomes a coefficient at q/2, the furthest point from
       zero - which is what gives decryption its error tolerance */
    var mu = poly_decompress(m, 1);
    poly_add(v, v, mu);
    poly_reduce(v);

    var c1len = 32 * p.du * k;
    var c = new Uint8Array(c1len + 32 * p.dv);
    for (i = 0; i < k; i++) { c.set(poly_compress(u[i], p.du), 32 * p.du * i); }
    c.set(poly_compress(v, p.dv), c1len);
    return c;
}

function pke_decrypt(dk, c, p) {
    var k = p.k, i;
    var c1len = 32 * p.du * k;

    var u = [];
    for (i = 0; i < k; i++) {
        u.push(poly_decompress(c.subarray(32 * p.du * i, 32 * p.du * (i + 1)), p.du));
    }
    var v = poly_decompress(c.subarray(c1len), p.dv);

    var s = [];
    for (i = 0; i < k; i++) { s.push(byte_decode(dk.subarray(384 * i, 384 * (i + 1)), 12)); }

    for (i = 0; i < k; i++) { ntt(u[i]); }
    var w = LAT.row_dot(s, u);
    ntt_inverse(w);
    poly_sub(w, v, w);
    poly_reduce(w);

    return poly_compress(w, 1);
}

/* ---------------- ML-KEM ---------------- */

function build(bits) {
    var p = PARAMS[bits];
    var k = p.k;
    SETS['ml_kem' + bits] = p;

    var EK_BYTES = 384 * k + 32;
    var DK_BYTES = 768 * k + 96;
    var CT_BYTES = 32 * (p.du * k + p.dv);

    /*
     * ⛔ FIPS 203 section 7.2 REQUIRES TWO CHECKS ON ek BEFORE ENCAPSULATING
     *    and they were missing: the length (type check), and that every
     *    12-bit coefficient is below q (modulus check - ByteEncode12 of
     *    ByteDecode12 must give back the same bytes). A coefficient >= q is
     *    reduced silently by the arithmetic, so a malformed key still
     *    "works" - against a key nobody holds the matching secret for.
     */
    function check_ek(ek) {
        if (!(ek instanceof Uint8Array) || ek.length !== EK_BYTES) {
            throw new Error('ml_kem: wrong public key length');
        }
        for (var i = 0; i < k; i++) {
            var a = byte_decode(ek.subarray(384 * i, 384 * (i + 1)), 12);
            for (var j = 0; j < N; j++) {
                if (a[j] >= Q) { throw new Error('ml_kem: public key fails the FIPS 203 modulus check'); }
            }
        }
    }

    /*
     * ek as numbers: its k polynomials t (12-bit coefficients, each below q
     * - the modulus check) and rho. For constructions that treat t as an
     * element of Z_q^(256k): Kemeleon's encoding, KEM-based OT.
     */
    function split_ek(ek) {
        if (!(ek instanceof Uint8Array) || ek.length !== EK_BYTES) { throw new Error('ml_kem: wrong public key length'); }
        var t = new Int32Array(k * N);
        for (var i = 0; i < k; i++) {
            unpack_bits(ek, 384 * i, N, 12, t.subarray(N * i));
            for (var j = 0; j < N; j++) {
                if (t[N * i + j] >= Q) { throw new Error('ml_kem: public key fails the FIPS 203 modulus check'); }
            }
        }
        return { t: t, rho: ek.subarray(384 * k) };
    }
    function join_ek(t, rho) {
        var ek = new Uint8Array(EK_BYTES);
        for (var i = 0; i < k; i++) { pack_bits(t.subarray(N * i, N * (i + 1)), 12, ek, 384 * i); }
        ek.set(rho, 384 * k);
        return ek;
    }

    var API = {
        PARAMS: p,
        split_ek: split_ek,
        join_ek: join_ek,
        EK_BYTES: EK_BYTES,
        DK_BYTES: DK_BYTES,
        CT_BYTES: CT_BYTES,
        SS_BYTES: 32,

        /**
         * @param {Uint8Array} [seed]  64 bytes: d || z; omitted or null draws
         *                             them from the platform (secure_random)
         *
         * The seed is the whole secret. FIPS 203 keeps d and z separate for a
         * reason - d generates the key pair, z is the implicit-rejection
         * secret used when decapsulation fails - and they must be independent.
         */
        keygen: function (seed) {
            if (seed == null) { seed = secure_random(64); }
            if (seed.length !== 64) { throw new Error('ml_kem: seed must be 64 bytes'); }
            var kp = pke_keygen(seed.subarray(0, 32), p);
            return { ek: kp.ek, dk: kem_dk(kp.dk, kp.ek, seed.subarray(32)) };
        },

        /**
         * @param  {Uint8Array} [m]  32 bytes of fresh randomness; omitted or
         *                          null draws them from the platform
         * @return {{ct: Uint8Array, ss: Uint8Array}}
         *
         * The shared secret is derived from m and a hash of the public key,
         * so it is bound to the exact key it was encapsulated to.
         */
        encaps: function (ek, m) {
            check_ek(ek);
            if (m == null) { m = secure_random(32); }
            if (m.length !== 32) { throw new Error('ml_kem: randomness must be 32 bytes'); }
            var g = sha3_512(concat([m, sha3_256(ek)]));
            var K = g.subarray(0, 32), r = g.subarray(32);
            return { ct: pke_encrypt(ek, m, r, p), ss: new Uint8Array(K) };
        },

        /**
         * FIPS 203 section 7.2 encapsulation-key check, exposed so a protocol
         * can refuse a bad key when it is RECEIVED rather than at first use.
         * @return {boolean}
         */
        check_ek: function (ek) {
            try { check_ek(ek); return true; } catch (e) { return false; }
        },

        /**
         * Decapsulation ALWAYS SUCCEEDS - and that is the design, not a bug.
         *
         * On a malformed ciphertext it returns a secret derived from the
         * key's private z value instead of failing. That is IMPLICIT
         * REJECTION, and it exists because a KEM that reports failure gives
         * an attacker an oracle: submit modified ciphertexts, watch which are
         * accepted, and recover the key. Every chosen-ciphertext attack on
         * lattice KEMs works that way, and returning a wrong-but-plausible
         * secret closes it.
         *
         * The caller learns of the failure when the derived key does not work.
         */
        /**
         * One decapsulation key for many ciphertexts, held in a context:
         *
         *     var me = ml_kem768.decaps_create();   // a fresh key pair; or decaps_create(dk)
         *     send(me.ek);
         *     var ss = me.decaps(ct);
         *     me.wipe();                            // zeroes dk; calls then throw
         *
         * dk is checked once (FIPS 203 section 7.3), and an engine imports it
         * once instead of on every call (engines/node.js). The pure context
         * holds a copy of dk.
         */
        decaps_create: function (dk) {
            var own;
            if (dk == null) { own = API.keygen().dk; }
            else {
                if (!(dk instanceof Uint8Array) || dk.length !== DK_BYTES) { throw new Error('ml_kem: wrong secret key length'); }
                if (!equal(sha3_256(dk.subarray(384 * k, 768 * k + 32)), dk.subarray(768 * k + 32, 768 * k + 64))) {
                    throw new Error('ml_kem: decapsulation key fails the FIPS 203 hash check');
                }
                own = new Uint8Array(dk);
            }
            var key = held('ml_kem', own);
            return {
                ek: own.slice(384 * k, 768 * k + 32),
                decaps: function (ct) { return API.decaps(key.use(), ct); },
                wipe: key.wipe
            };
        },

        decaps: function (dk, ct) {
            if (dk.length !== DK_BYTES) { throw new Error('ml_kem: wrong secret key length'); }
            if (ct.length !== CT_BYTES) { throw new Error('ml_kem: wrong ciphertext length'); }

            var dk_pke = dk.subarray(0, 384 * k);
            var ek = dk.subarray(384 * k, 768 * k + 32);
            var h = dk.subarray(768 * k + 32, 768 * k + 64);
            var z = dk.subarray(768 * k + 64);
            /* FIPS 203 section 7.3: the hash stored in dk must be H(ek) */
            if (!equal(sha3_256(ek), h)) {
                throw new Error('ml_kem: decapsulation key fails the FIPS 203 hash check');
            }

            var m = pke_decrypt(dk_pke, ct, p);
            var g = sha3_512(concat([m, h]));
            var K = g.subarray(0, 32), r = g.subarray(32);

            /* re-encrypt and compare: the Fujisaki-Okamoto transform */
            var ct2 = pke_encrypt(ek, m, r, p);
            var K_reject = shake256(concat([z, ct]), 32);

            /* select without branching on whether the ciphertext was valid -
               commons/ct.js's select_bytes, which this loop used to spell out */
            return select_bytes(equal(ct, ct2), K, K_reject);
        }
    };
    return API;
}

/*
 * The expanded decapsulation key of keygen(seed), given ek: s from d (no
 * A - the expensive half of key generation), then ek, H(ek) and z. For an
 * engine whose key generation hands back the seed and ek but not this form
 * (engines/node.js); ek must be the one this seed generates.
 */
export function decapsulation_key(name, seed, ek) {
    var p = SETS[name];
    if (!p || !(seed instanceof Uint8Array) || seed.length !== 64) { throw new Error('ml_kem: decapsulation_key needs a set name and a 64-byte seed'); }
    if (!(ek instanceof Uint8Array) || ek.length !== 384 * p.k + 32) { throw new Error('ml_kem: ek has the wrong length for ' + name); }
    var g = sha3_512(concat([seed.subarray(0, 32), new Uint8Array([p.k])]));
    return kem_dk(pke_dk(pke_secret(g.subarray(32), p), p.k), ek, seed.subarray(32));
}
var SETS = {};

export var ml_kem512  = /* @__PURE__ */ build(512);
export var ml_kem768  = /* @__PURE__ */ build(768);
export var ml_kem1024 = /* @__PURE__ */ build(1024);
