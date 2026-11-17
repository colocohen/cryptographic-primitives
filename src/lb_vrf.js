/**
 * LB-VRF  -  a lattice-based one-time VRF (Esgin, Kuchta, Sakzad, Steinfeld,
 * Zhang, Sun, Chu; ePrint 2020/1222, FC 2021), parameter Set I
 *
 * A VERIFIABLE RANDOM FUNCTION: the key holder computes v = F_sk(mu) and a
 * proof that anyone can check against pk; v is unique for (pk, mu) and looks
 * random to everyone else. Here, under Module-SIS and Module-LWE:
 *
 *     pk  t = A s                    s ternary in R^9, A uniform in Rq^(4x9)
 *     v   = <b, s> over R_p-bar       b = G(A, t, mu), a fresh basis per input
 *     pi  a Fiat-Shamir-with-aborts proof that one s gives both t and v:
 *         y <- [-beta, beta]^(9x256); w1 = A y, w2 = <b, y>
 *         c = H(A, t, mu, w1, w2, v)  (39 coefficients +-1)
 *         z = y + c s, restarted unless |z|_inf <= beta - kappa
 *     verify  |z|_inf <= beta - kappa and c = H(A, t, mu, A z - c t, <b, z> - c v, v)
 *
 * R = Z[x]/(x^256 + 1); A and t live mod q = 100679681, the VRF value in
 * R_p-bar = Z_p[x]/(x^32 + 852368) with p = 2097169 (a factor of x^256 + 1
 * mod p, so v is 32 coefficients, 84 bytes). Uniqueness is computational
 * (two valid values for one input give an MSIS solution, the paper's
 * Theorem 3.1) and holds for honestly generated A.
 *
 * ONE OUTPUT PER KEY. Each value v = <b, s> is a noiseless linear equation in
 * s; Set I keeps s hidden for k = 1 evaluation (the paper's Theorem B.1), so
 * a key pair yields ONE VRF output - the paper's blockchain use, a fresh key
 * per round. The paper's Sets II and III (k = 3, 5) leave q, p and f
 * unspecified and are not offered.
 *
 * ENCODING (this library's; the paper publishes no vectors): the public
 * parameter A expands from a 32-byte seed by SHAKE128; G, H and the
 * challenge by SHAKE256 with domain bytes; pk is t (27-bit coefficients),
 * the value v (21-bit), the proof c~ (32 bytes, the seed of c) || z
 * (18-bit, offset by beta - kappa) || v. evaluate is hedged: y is drawn from SHAKE256(sk,
 * mu, rnd).
 *
 * API (lb_vrf):
 *   params(seed32) -> pp                    A from its seed; one pp per system
 *   keygen(pp, seed32) -> {pk, sk}
 *   evaluate(pp, sk, mu, rnd32) -> {value, output, proof}   the proof carries the value
 * seed32 and rnd32 omitted or null draw fresh ones from the platform.
 *   verify(pp, pk, mu, proof) -> {value, output} | null
 * output = SHAKE256("LB-VRF output" || value, 32) for applications that want bits.
 */

import { shake128, shake256 } from './sha3.js';
import { concat, ascii, secure_random } from './commons/bytes.js';
import { pack_bits, unpack_bits } from './commons/bitpack.js';
import { equal } from './commons/ct.js';

var N = 256, Q = 100679681, P = 2097169, RF = 852368, NR = 4, NS = 9, KAPPA = 39, BETA = 89856, BOUND = BETA - KAPPA;
var QB = 27, PB = 21, ZB = 18, D = 32;
var T_BYTES = NR * N * QB / 8, V_BYTES = D * PB / 8, Z_BYTES = NS * N * ZB / 8, C_BYTES = 32;
var PK_BYTES = 32 + T_BYTES, SK_BYTES = 32 + NS * N, PROOF_BYTES = C_BYTES + Z_BYTES;
var DOM = { A: 0, S: 1, B: 2, Y: 3, C: 4, OUT: 5 };
var LABEL = /* @__PURE__ */ ascii('LB-VRF set I v1');

/* (-R)^j mod p, j = 0..7: x^(32 j + i) = (-R)^j x^i in R_p-bar */
var RPOW = /* @__PURE__ */ (function () { var o = [1]; for (var j = 1; j < 8; j++) { o.push(Number(BigInt(o[j - 1]) * BigInt(P - RF) % BigInt(P))); } return o; }());

function mod(a, m) { a %= m; return a < 0 ? a + m : a; }
function mulmod(a, b, m) { return Number(BigInt(a) * BigInt(b) % BigInt(m)); }

/* a stream reader over SHAKE */
function stream(xof, input, chunk) {
    var buf = xof(input, chunk), pos = 0, len = chunk;
    return function (n) {
        if (pos + n > buf.length) { len *= 2; buf = xof(input, len); }
        var out = buf.subarray(pos, pos + n); pos += n; return out;
    };
}
function dom(d, parts) { return concat([LABEL, new Uint8Array([d])].concat(parts)); }

/* uniform coefficients below m from `bits`-bit little-endian chunks of 4 bytes */
function uniform(read, count, m, bits) {
    var out = new Int32Array(count), mask = bits === 32 ? 0xffffffff : (1 << bits) - 1;
    for (var i = 0; i < count;) {
        var b = read(4), v = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) & mask;
        if (v >>> 0 < m) { out[i++] = v; }
    }
    return out;
}

/* negacyclic products in R, both inputs as Int32Array(256); the result mod q in [0, q) */
function mul_q(a, small) {
    var acc = new Float64Array(N), i, j;
    for (i = 0; i < N; i++) {
        var ai = a[i];
        if (!ai) { continue; }
        for (j = 0; j < N; j++) {
            var s = small[j];
            if (!s) { continue; }
            var k = i + j;
            if (k < N) { acc[k] += ai * s; } else { acc[k - N] -= ai * s; }
        }
        if ((i & 15) === 15) { for (j = 0; j < N; j++) { acc[j] %= Q; } }
    }
    var out = new Int32Array(N);
    for (i = 0; i < N; i++) { out[i] = mod(acc[i], Q); }
    return out;
}
/* R -> R_p-bar */
function reduce_p(a) {
    var out = new Int32Array(D);
    for (var i = 0; i < D; i++) {
        var acc = 0;
        for (var j = 0; j < 8; j++) { acc = (acc + mulmod(mod(a[32 * j + i], P), RPOW[j], P)) % P; }
        out[i] = acc;
    }
    return out;
}
/* products in R_p-bar */
function mul_p(a, b) {
    var t = new Array(2 * D - 1).fill(0), i, j;
    for (i = 0; i < D; i++) { if (!a[i]) { continue; } for (j = 0; j < D; j++) { t[i + j] = (t[i + j] + mulmod(a[i], b[j], P)) % P; } }
    for (i = 2 * D - 2; i >= D; i--) { t[i - D] = mod(t[i - D] - mulmod(t[i], RF, P), P); }
    return Int32Array.from(t.slice(0, D));
}
function inner_p(b, x) {
    var acc = new Int32Array(D);
    for (var k = 0; k < NS; k++) { var m = mul_p(b[k], reduce_p(x[k])); for (var i = 0; i < D; i++) { acc[i] = (acc[i] + m[i]) % P; } }
    return acc;
}
function mat_vec(A, x) {
    var out = [];
    for (var r = 0; r < NR; r++) {
        var acc = new Int32Array(N);
        for (var k = 0; k < NS; k++) { var m = mul_q(A[r][k], x[k]); for (var i = 0; i < N; i++) { acc[i] = (acc[i] + m[i]) % Q; } }
        out.push(acc);
    }
    return out;
}

/* encodings */
function enc(polys, bits, offset) {
    var len = polys.length * polys[0].length, out = new Uint8Array(len * bits / 8), v = new Int32Array(len), o = 0;
    for (var p = 0; p < polys.length; p++) { for (var i = 0; i < polys[p].length; i++) { v[o++] = polys[p][i] + offset; } }
    pack_bits(v, bits, out, 0);
    return out;
}
function dec(bytes, count, len, bits, offset) {
    var v = unpack_bits(bytes, 0, count * len, bits, new Int32Array(count * len)), out = [];
    for (var p = 0; p < count; p++) { out.push(v.subarray(p * len, (p + 1) * len).map(function (x) { return x - offset; })); }
    return out;
}

/* the challenge: kappa coefficients +-1 from a seed (SampleInBall) */
function challenge(seed) {
    var read = stream(shake256, dom(DOM.C, [seed]), 136), c = new Int32Array(N), signs = read(8), k = 0;
    for (var i = N - KAPPA; i < N; i++, k++) {
        var j;
        do { j = read(1)[0]; } while (j > i);
        c[i] = c[j];
        c[j] = ((signs[k >> 3] >> (k & 7)) & 1) ? -1 : 1;
    }
    return c;
}
function mul_c(c, a, m) {
    /* c ternary, a mod m: the product mod m */
    var out = new Float64Array(N);
    for (var i = 0; i < N; i++) {
        if (!c[i]) { continue; }
        for (var j = 0; j < N; j++) {
            var k = i + j, v = c[i] * a[j];
            if (k < N) { out[k] += v; } else { out[k - N] -= v; }
        }
    }
    return Int32Array.from(out, function (x) { return mod(x, m); });
}

export function params(seed) {
    if (!(seed instanceof Uint8Array) || seed.length !== 32) { throw new Error('lb_vrf: the parameter seed is 32 bytes'); }
    var read = stream(shake128, dom(DOM.A, [seed]), 168 * 64), A = [];
    for (var r = 0; r < NR; r++) { var row = []; for (var k = 0; k < NS; k++) { row.push(uniform(read, N, Q, QB)); } A.push(row); }
    return { seed: seed.slice(), A: A };
}

function basis(pp, pk, mu) {
    var read = stream(shake256, dom(DOM.B, [pp.seed, pk, mu]), 136 * 16), b = [];
    for (var k = 0; k < NS; k++) { b.push(uniform(read, D, P, PB)); }
    return b;
}
function hash_c(pp, pk, mu, w1, w2, v) {
    return shake256(dom(DOM.C, [pp.seed, pk, mu, enc(w1, QB, 0), enc([w2], PB, 0), v]), C_BYTES);
}
function output_of(v) { return shake256(concat([ascii('LB-VRF output'), v]), 32); }

export function keygen(pp, seed) {
    if (seed == null) { seed = secure_random(32); }
    if (!(seed instanceof Uint8Array) || seed.length !== 32) { throw new Error('lb_vrf: the key seed is 32 bytes'); }
    var read = stream(shake256, dom(DOM.S, [pp.seed, seed]), 136 * 24), s = [];
    for (var k = 0; k < NS; k++) {
        var p = new Int32Array(N);
        for (var i = 0; i < N;) { var x = read(1)[0]; if (x < 255) { p[i++] = (x % 3) - 1; } }
        s.push(p);
    }
    var pk = concat([pp.seed, enc(mat_vec(pp.A, s), QB, 0)]);
    return { pk: pk, sk: concat([pk.subarray(0, 32), enc(s, 8, 1)]) };
}

function parse_pk(pp, pk) {
    if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES || !equal(pk.subarray(0, 32), pp.seed)) { return null; }
    var t = dec(pk.subarray(32), NR, N, QB, 0);
    for (var r = 0; r < NR; r++) { for (var i = 0; i < N; i++) { if (t[r][i] >= Q) { return null; } } }
    return t;
}

export function evaluate(pp, sk, mu, rnd) {
    if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES || !equal(sk.subarray(0, 32), pp.seed)) { throw new Error('lb_vrf: the secret key is ' + SK_BYTES + ' bytes, for these parameters'); }
    if (rnd == null) { rnd = secure_random(32); }
    if (!(rnd instanceof Uint8Array) || rnd.length !== 32) { throw new Error('lb_vrf: eval takes 32 bytes of randomness'); }
    var s = dec(sk.subarray(32), NS, N, 8, 1), k, i;
    var pk = concat([pp.seed, enc(mat_vec(pp.A, s), QB, 0)]), b = basis(pp, pk, mu), v = inner_p(b, s), venc = enc([v], PB, 0);
    var read = stream(shake256, dom(DOM.Y, [sk, mu, rnd]), 136 * 64);
    for (;;) {
        var y = [];
        for (k = 0; k < NS; k++) { y.push(Int32Array.from(uniform(read, N, 2 * BETA + 1, ZB), function (x) { return x - BETA; })); }
        var ct = hash_c(pp, pk, mu, mat_vec(pp.A, y), inner_p(b, y), venc), c = challenge(ct), z = [], ok = true;
        for (k = 0; k < NS && ok; k++) {
            var cs = mul_c(c, s[k].map(function (x) { return mod(x, Q); }), Q), zk = new Int32Array(N);
            for (i = 0; i < N; i++) {
                var csi = cs[i] > Q / 2 ? cs[i] - Q : cs[i];
                zk[i] = y[k][i] + csi;
                if (zk[i] > BOUND || zk[i] < -BOUND) { ok = false; break; }
            }
            z.push(zk);
        }
        if (ok) { return { value: venc, output: output_of(venc), proof: concat([ct, enc(z, ZB, BOUND), venc]) }; }
    }
}

export function verify(pp, pk, mu, proof) {
    var t = parse_pk(pp, pk);
    if (!t || !(proof instanceof Uint8Array) || proof.length !== PROOF_BYTES + V_BYTES) { return null; }
    var venc = proof.subarray(PROOF_BYTES), ct = proof.subarray(0, C_BYTES);
    var z = dec(proof.subarray(C_BYTES, PROOF_BYTES), NS, N, ZB, BOUND), v = dec(venc, 1, D, PB, 0)[0], k, i;
    for (i = 0; i < D; i++) { if (v[i] >= P) { return null; } }
    for (k = 0; k < NS; k++) { for (i = 0; i < N; i++) { if (z[k][i] > BOUND || z[k][i] < -BOUND) { return null; } } }
    var c = challenge(ct), b = basis(pp, pk, mu), Az = mat_vec(pp.A, z), w1 = [];
    for (var r = 0; r < NR; r++) {
        var ctr = mul_c(c, t[r], Q), w = new Int32Array(N);
        for (i = 0; i < N; i++) { w[i] = mod(Az[r][i] - ctr[i], Q); }
        w1.push(w);
    }
    var bz = inner_p(b, z), cv = mul_p(reduce_p(c), v), w2 = new Int32Array(D);
    for (i = 0; i < D; i++) { w2[i] = mod(bz[i] - cv[i], P); }
    return equal(hash_c(pp, pk, mu, w1, w2, venc), ct) ? { value: venc.slice(), output: output_of(venc) } : null;
}

export var SIZES = { PK_BYTES: PK_BYTES, SK_BYTES: SK_BYTES, PROOF_BYTES: PROOF_BYTES + V_BYTES, VALUE_BYTES: V_BYTES };
