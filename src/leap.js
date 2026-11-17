/**
 * Leap  -  oblivious evaluation of the Spring PRF (ePrint 2025/333)
 *
 * An OBLIVIOUS PRF: the client learns F_K(x) for an x the server never
 * sees, and nothing else about K. The PRF is Spring in its BCH mode, a
 * rounded Naor-Reingold product in R_q = Z_q[X]/(X^128 + 1), q = 257:
 *
 *     Spring_K(c_1..c_128) = BCH( S( k_0 * prod_(c_i = 1) k_i ) )
 *     F_K(x) = H2(x, Spring_K(H1(x)))                     (section 3.5)
 *
 * with S rounding each coefficient to a bit (1 on [q/4, 3q/4]) and BCH the
 * 128 -> 64 bit map of the extended [128, 64, 22] BCH code, which takes the
 * rounding bias of 1/q down to 2^-145. The key k_0..k_128 lives in NTT form
 * as discrete logarithms base 3 (section 5.1): a product of units is a sum of
 * bytes mod 256, and a coefficient 3^s is never zero.
 *
 * THE PROTOCOL (Fig. 4), every OT one the client receives:
 *   subset sum  per input bit i, a 1-of-2 OT of (r_i, r_i + k_i): the client
 *               sums its 128 strings, the server holds k_0 - sum r_i; lifted,
 *               b = 3^(client sum) and a = 3^(server sum) multiply to the
 *               PRF's product, in NTT form (section 3.1, 5.3)
 *   OLE         per coefficient, Gilboa's product sharing over nine 1-of-2
 *               OTs: the client gets y_j = a_j b_j + e_j, the server keeps e_j
 *               (section 3.2, 5.4)
 *   rounding    both apply the inverse NTT; per coefficient a 1-of-257 OT of
 *               S(z - e_j) xor d_j for every z: the client takes z = y_j
 *               (section 3.3, 5.5)
 *   BCH         the server sends BCH(d); BCH is linear, so the client's
 *               BCH(y') xor BCH(d) is Spring_K(x) (section 3.4)
 * The paper proves this UC-secure in the OT- and OLE-hybrid model, against
 * malicious clients and servers (Theorem 1).
 *
 * THE OTs. Random OTs are inputs, as in pool.js: ot_kem.js (post-quantum base
 * OTs) with ot_extend.js makes them; each is spent once. The client sends a
 * correction bit per OT (choice xor its random choice), 304 bytes in all.
 * A string the receiver may take expands from its OT key by SHAKE256: the
 * subset-sum blinders r_i, the Gilboa masks e_j,t (96 bits reduced mod q).
 * The 1-of-257 OT is the Naor-Pinkas OT of commons/random_ot.js over nine
 * 1-of-2 OTs: entry z under the string at z xor (the client's correction).
 *
 * MESSAGES. Six, after the OTs:
 *     client -> server  C1  16 bytes     subset-sum corrections
 *     server -> client  S1  16384 bytes  128 blinded key polynomials
 *     client -> server  C2  144 bytes    OLE corrections
 *     server -> client  S2  1296 bytes   Gilboa ciphertexts (9 bits each)
 *     client -> server  C3  144 bytes    rounding corrections
 *     server -> client  S3  4120 bytes   rounding tables (257 bits each), BCH(d)
 *
 * ENCODING (this library's; the paper publishes no vectors): the key is the
 * 129 polynomials' discrete logarithms, 128 bytes each; H1 and H2 are
 * SHAKE256 with domain bytes; the NTT is commons/negacyclic_ntt.js's (the
 * roots of X^128 + 1 in bit-reversed order); Spring's output is 8 bytes,
 * little endian.
 */

import { shake256 } from './sha3.js';
import { ascii, be32, bytes_to_bigint_le, bigint_to_bytes_le } from './commons/bytes.js';
import { domain_xof } from './commons/domain_xof.js';
import { bit_le, bits_le, pack_bits, unpack_bits } from './commons/bitpack.js';
import { require_rng } from './commons/primes.js';
import { negacyclic } from './commons/negacyclic_ntt.js';
import { check_sender_ots, check_receiver_ots, one_of_n_send, one_of_n_receive } from './commons/random_ot.js';

var Q = 257, N = 128, KAPPA = 128, LQ = 9;
var DST = /* @__PURE__ */ ascii('cryptographic-primitives/leap/v1');
var DOM_H1 = 0, DOM_H2 = 1, DOM_SUB = 2, DOM_OLE = 3;
var KEY_BYTES = (KAPPA + 1) * N;
var OT_SUB = 0, OT_OLE = KAPPA, OT_RND = KAPPA + N * LQ, OTS = KAPPA + 2 * N * LQ;
var C1_BYTES = KAPPA / 8, C2_BYTES = N * LQ / 8, C3_BYTES = N * LQ / 8;
var S1_BYTES = KAPPA * N, S2_BYTES = N * LQ * LQ / 8, TABLE_BYTES = Math.ceil(N * Q / 8), S3_BYTES = TABLE_BYTES + 8;

var expand = /* @__PURE__ */ domain_xof(shake256, DST);

/* 3^i mod q; the ring's NTT */
var POW = /* @__PURE__ */ (function () { var t = new Int32Array(256); t[0] = 1; for (var i = 1; i < 256; i++) { t[i] = t[i - 1] * 3 % Q; } return t; }());
var RING = /* @__PURE__ */ negacyclic(N, BigInt(Q), 'leap');

/** The NTT of a polynomial mod q (coefficients low first): its values at the roots of X^128 + 1. */
export function ntt(a) { return Int32Array.from(RING.forward(Array.from(a, BigInt)), Number); }
/** The inverse NTT: the polynomial with these values. */
export function intt(v) { return Int32Array.from(RING.inverse(Array.from(v, BigInt)), Number); }

/* S: a coefficient to its rounding round(2z / q) mod 2 */
function round_bit(z) { return z >= 65 && z <= 192 ? 1 : 0; }

/*
 * BCH: 128 bits (two little-endian words) to their 64-bit image under the
 * extended BCH code's matrix, as the SPRING reference computes it - rows
 * that are shifts of one row, so a product of shifts.
 */
var BCH_LO = [2, 7, 8, 10, 12, 14, 15, 16, 23, 25, 27, 28, 30, 31, 32, 33, 37, 38, 39, 40, 41, 42, 44, 45, 48, 58, 61, 63];
var BCH_HI = [62, 57, 56, 54, 52, 50, 49, 48, 41, 39, 37, 36, 34, 33, 32, 31, 27, 26, 25, 24, 23, 22, 20, 19, 16, 6, 3, 1];
var M64 = (1n << 64n) - 1n;
/** The BCH map of Spring-BCH: 16 bytes (bit i = coefficient i) to 8. Linear over GF(2). */
export function bch(bits) {
    if (!(bits instanceof Uint8Array) || bits.length !== 16) { throw new Error('leap: BCH takes 16 bytes'); }
    var b1 = bytes_to_bigint_le(bits.subarray(0, 8)), b2 = bytes_to_bigint_le(bits.subarray(8)), r = b1, i;
    for (i = 0; i < BCH_LO.length; i++) { r ^= (b1 << BigInt(BCH_LO[i])) & M64; }
    for (i = 0; i < BCH_HI.length; i++) { r ^= b2 >> BigInt(BCH_HI[i]); }
    if (b2 & 1n) { r ^= M64; }
    return bigint_to_bytes_le(r, 8);
}

function check_key(key) { if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) { throw new Error('leap: a key is ' + KEY_BYTES + ' bytes'); } }
function check_bytes(b, len, what) { if (!(b instanceof Uint8Array) || b.length !== len) { throw new Error('leap: ' + what + ' is ' + len + ' bytes'); } }
function step(st, want, name) {
    if (st.step !== want) { throw new Error('leap: ' + name + ' out of order (this state is past it or not yet there)'); }
    st.step++;
}

/** A server key: 129 polynomials, uniform in discrete-log NTT form. */
export function keygen(rng) { rng = require_rng('leap.keygen', rng); return rng(KEY_BYTES); }

/** H1: any input to the PRF's 128 input bits. */
function H1(x) { return expand(DOM_H1, [x], KAPPA / 8); }
function H2(x, f) { return expand(DOM_H2, [x, f], 32); }

/* the subset product's discrete logarithms, lifted: the polynomial in NTT form */
function lift(s) { var v = new Int32Array(N); for (var j = 0; j < N; j++) { v[j] = POW[s[j]]; } return v; }
function round_poly(coef) { var o = new Uint8Array(16); for (var j = 0; j < N; j++) { o[j >> 3] |= round_bit(coef[j]) << (j & 7); } return o; }

/** Spring-BCH on 128 input bits (16 bytes, bit i = c_(i+1)): 8 bytes. */
export function spring(key, c) {
    check_key(key);
    check_bytes(c, KAPPA / 8, 'a Spring input');
    var s = key.slice(0, N);
    for (var i = 0; i < KAPPA; i++) {
        if (bit_le(c, i)) { var off = (i + 1) * N; for (var j = 0; j < N; j++) { s[j] = (s[j] + key[off + j]) & 255; } }
    }
    return bch(round_poly(intt(lift(s))));
}
/** The OPRF, with the key: F_K(x) = H2(x, Spring_K(H1(x))), 32 bytes. */
export function evaluate(key, x) { return H2(x, spring(key, H1(x))); }

/* strings from OT keys: a blinder (128 bytes), a Gilboa mask in Z_q */
function blinder(k, i) { return expand(DOM_SUB, [k, be32(i)], N); }
function mask(k, i) { var b = expand(DOM_OLE, [k, be32(i)], 12), v = 0; for (var m = 0; m < 12; m++) { v = (v * 256 + b[m]) % Q; } return v; }
/* coefficient j's nine rounding OTs */
function round_ots(list, j) { return list.slice(OT_RND + j * LQ, OT_RND + (j + 1) * LQ); }
function packed(values, bits) { var o = new Uint8Array(Math.ceil(values.length * bits / 8)); pack_bits(values, bits, o, 0); return o; }

/* ---------------- server ---------------- */

/** The server's state for one evaluation; pairs: OTS entries [k0, k1] (it sends every OT). */
export function server_start(key, pairs) {
    check_key(key);
    check_sender_ots(pairs, OTS, 'leap');
    return { step: 0, key: key, pairs: pairs };
}
/** C1 -> S1: the blinded key polynomials; the server keeps a = 3^(k_0 - sum r_i). */
export function server_subset(st, c1) {
    check_bytes(c1, C1_BYTES, 'C1');
    step(st, 0, 'server_subset');
    var a = st.key.slice(0, N), out = new Uint8Array(S1_BYTES), i, j;
    for (i = 0; i < KAPPA; i++) {
        var beta = bit_le(c1, i), pr = st.pairs[OT_SUB + i];
        var rb = blinder(pr[beta], i), rp = blinder(pr[1 - beta], i), off = (i + 1) * N;
        for (j = 0; j < N; j++) {
            a[j] = (a[j] - rb[j]) & 255;
            out[i * N + j] = rp[j] ^ ((rb[j] + st.key[off + j]) & 255);
        }
    }
    st.a = lift(a);
    return out;
}
/** C2 -> S2: Gilboa's ciphertexts e + a_j 2^t, one per coefficient and bit; the server keeps E = iNTT(e). */
export function server_ole(st, c2) {
    check_bytes(c2, C2_BYTES, 'C2');
    step(st, 1, 'server_ole');
    var e = new Int32Array(N), ct = new Int32Array(N * LQ);
    for (var j = 0; j < N; j++) {
        for (var t = 0; t < LQ; t++) {
            var idx = j * LQ + t, beta = bit_le(c2, idx), pr = st.pairs[OT_OLE + idx];
            var ej = mask(pr[beta], idx);
            e[j] = (e[j] + ej) % Q;
            ct[idx] = (ej + st.a[j] * (1 << t) + mask(pr[1 - beta], idx)) % Q;
        }
    }
    st.E = intt(e);
    var out = new Uint8Array(S2_BYTES);
    pack_bits(ct, LQ, out, 0);
    return out;
}
/** C3 -> S3: per coefficient, S(z - E_j) xor d_j for z in Z_q under the Naor-Pinkas pads; then BCH(d). */
export function server_round(st, c3, rng) {
    check_bytes(c3, C3_BYTES, 'C3');
    rng = require_rng('leap.server_round', rng);
    step(st, 2, 'server_round');
    var d = rng(16), out = new Uint8Array(S3_BYTES);
    for (var j = 0; j < N; j++) {
        var pads = one_of_n_send(round_ots(st.pairs, j), 1, be32(j)), beta = bits_le(c3, j * LQ, LQ), dj = bit_le(d, j), Ej = st.E[j];
        for (var z = 0; z < Q; z++) {
            var pos = j * Q + z;
            out[pos >> 3] |= (round_bit((z - Ej + Q) % Q) ^ dj ^ pads[z ^ beta]) << (pos & 7);
        }
    }
    out.set(bch(d), TABLE_BYTES);
    return out;
}

/* ---------------- client ---------------- */

/** The client's state and C1; recv: OTS entries {choice, key} (it receives every OT). */
export function client_start(x, recv) {
    if (!(x instanceof Uint8Array)) { throw new Error('leap: the input is bytes'); }
    check_receiver_ots(recv, OTS, 'leap');
    var c = H1(x), corr = new Int32Array(KAPPA);
    for (var i = 0; i < KAPPA; i++) { corr[i] = bit_le(c, i) ^ recv[OT_SUB + i].choice; }
    return { state: { step: 0, x: x, c: c, recv: recv }, msg: packed(corr, 1) };
}
/** S1 -> C2: the subset sum, lifted to b; the corrections for b's bits. */
export function client_ole(st, s1) {
    check_bytes(s1, S1_BYTES, 'S1');
    step(st, 0, 'client_ole');
    var s = new Uint8Array(N), corr = new Int32Array(N), i, j, t;
    for (i = 0; i < KAPPA; i++) {
        var r = blinder(st.recv[OT_SUB + i].key, i), ci = bit_le(st.c, i);
        for (j = 0; j < N; j++) { s[j] = (s[j] + (ci ? r[j] ^ s1[i * N + j] : r[j])) & 255; }
    }
    st.b = lift(s);
    for (j = 0; j < N; j++) { for (t = 0; t < LQ; t++) { corr[j] |= (((st.b[j] >> t) & 1) ^ st.recv[OT_OLE + j * LQ + t].choice) << t; } }
    return packed(corr, LQ);
}
/** S2 -> C3: y = a b + e from Gilboa's ciphertexts, Y = iNTT(y); the corrections for Y's coefficients. */
export function client_round(st, s2) {
    check_bytes(s2, S2_BYTES, 'S2');
    var ct = unpack_bits(s2, 0, N * LQ, LQ), y = new Int32Array(N), corr = new Int32Array(N), j, t;
    if (ct.some(function (v) { return v >= Q; })) { throw new Error('leap: an OLE ciphertext is out of range'); }
    step(st, 1, 'client_round');
    for (j = 0; j < N; j++) {
        for (t = 0; t < LQ; t++) {
            var idx = j * LQ + t;
            var m = mask(st.recv[OT_OLE + idx].key, idx);
            y[j] = (y[j] + ((st.b[j] >> t) & 1 ? ct[idx] - m + Q : m)) % Q;
        }
    }
    st.Y = intt(y);
    st.pads = [];
    for (j = 0; j < N; j++) { var o = one_of_n_receive(round_ots(st.recv, j), 1, be32(j)); st.pads.push(o.string); corr[j] = st.Y[j] ^ o.choice; }
    return packed(corr, LQ);
}
/** S3 -> the output: the rounded bits opened at Y, BCH, then H2. */
export function client_finish(st, s3) {
    check_bytes(s3, S3_BYTES, 'S3');
    step(st, 2, 'client_finish');
    var yb = new Uint8Array(16);
    for (var j = 0; j < N; j++) {
        yb[j >> 3] |= (bit_le(s3, j * Q + st.Y[j]) ^ st.pads[j]) << (j & 7);
    }
    var f = bch(yb), d = s3.subarray(TABLE_BYTES);
    for (var i = 0; i < 8; i++) { f[i] ^= d[i]; }
    return H2(st.x, f);
}

export var SIZES = {
    KEY_BYTES: KEY_BYTES, OUTPUT_BYTES: 32, OTS: OTS,
    C1_BYTES: C1_BYTES, S1_BYTES: S1_BYTES, C2_BYTES: C2_BYTES, S2_BYTES: S2_BYTES, C3_BYTES: C3_BYTES, S3_BYTES: S3_BYTES
};
