/**
 * HQC - Hamming Quasi-Cyclic, the code-based KEM NIST selected in March 2025
 * as the backup to ML-KEM (HQC v5.1.0, gitlab.com/pqc-hqc/hqc, the version
 * going into NIST's standard; byte-compatible with its KATs).
 *
 * WHY A SECOND KEM. ML-KEM is a lattice scheme; if lattices fall, it falls.
 * HQC rests on something else entirely: decoding a random quasi-cyclic code
 * - the syndrome decoding problem, studied since McEliece in 1978. Larger
 * (an HQC-1 public key is 2,241 bytes, ML-KEM-512's 800) and slower, it is the
 * hedge.
 *
 *     hqc1   NIST category 1   pk 2,241   ct 4,433   sk 32   ss 32
 *     hqc3   NIST category 3   pk 4,514   ct 8,978
 *     hqc5   NIST category 5   pk 7,237   ct 14,421
 *
 * HOW IT WORKS. Everything lives in GF(2)[x]/(x^n − 1), n prime. The secret
 * key is two sparse vectors x, y (weight ω); the public key is h (random,
 * from a seed) and s = x + y·h. Encryption hides the message m, encoded with a
 * concatenated code (Reed-Solomon outer, duplicated Reed-Muller inner), under
 * s·r2 + e; decryption removes y·u and lets the code correct what is left.
 * The KEM is a Fujisaki-Okamoto transform over that with implicit
 * rejection: a bad ciphertext gives a key derived from a secret σ, never an
 * error.
 *
 * ⭐ THE SECRET KEY IS A 32-BYTE SEED (v5's "compressed dk"): every part is
 *   re-derived from it on each decapsulation.
 *
 * CONSTANT TIME, as far as JavaScript allows. Every product here has one
 * sparse operand whose support is secret, so it is computed as a sum of
 * rotations of the dense one - each rotation a barrel shifter over public
 * shift amounts with the secret bits choosing through masks, so no position
 * decides an index or a branch. GF(2^8) multiplication is carry-less
 * arithmetic, not log/exp tables indexed by secrets; the Reed-Solomon
 * decoder and the Reed-Muller peak search keep the reference's mask-based
 * structure.
 */
import { sha3_256, sha3_512, shake256 } from './sha3.js';
import { concat, xor_into } from './commons/bytes.js';
import { xof_stream } from './commons/xof_stream.js';
import { require_rng } from './commons/primes.js';

var PARAMS = {
    1: { N: 17669, N1: 46, N2: 384, W: 67,  WE: 76,  WR: 76,  K: 16, T: 15, threshold: 16767881 },
    3: { N: 35851, N1: 56, N2: 640, W: 101, WE: 114, WR: 114, K: 24, T: 16, threshold: 16742417 },
    5: { N: 57637, N1: 90, N2: 640, W: 132, WE: 150, WR: 150, K: 32, T: 29, threshold: 16772367 }
};
var SEED = 32, SALT = 16;

/* ---------------- GF(2^8), x^8 + x^4 + x^3 + x + 1 (0x11B), α = 3 ---------------- */

/* carry-less a·b reduced, with no table and no branch on a or b */
function gf_mul(a, b) {
    var r = 0;
    for (var i = 0; i < 8; i++) {
        r ^= a & -((b >> i) & 1);
        a = (a << 1) ^ (0x11b & -((a >> 7) & 1));
    }
    return r & 0xff;
}
function gf_inverse(a) {                   /* a^254, the reference's addition chain; 0 -> 0 */
    var a2 = gf_mul(a, a), a3 = gf_mul(a2, a), a4 = gf_mul(a2, a2), a7 = gf_mul(a4, a3), a11 = gf_mul(a4, a7);
    var x = gf_mul(a11, a4);               /* a^15 */
    x = gf_mul(x, x); x = gf_mul(x, x); x = gf_mul(x, x);   /* a^120 */
    x = gf_mul(x, a7);                     /* a^127 */
    return gf_mul(x, x);
}
/* α^e for a public e: the powers are public, so a table is fine here */
var GF_EXP = (function () { var t = new Uint8Array(255), v = 1; for (var i = 0; i < 255; i++) { t[i] = v; v = gf_mul(v, 3); } return t; }());
function alpha_pow(e) { return GF_EXP[((e % 255) + 255) % 255]; }

/* masks on 16-bit quantities, as the reference's */
function nz_mask(x) { x &= 0xffff; return -(((x | -x) >>> 31) & 1) & 0xffff; }   /* 0xffff if x != 0 */

function build(level) {
    var p = PARAMS[level], N = p.N, N1 = p.N1, N2 = p.N2, K = p.K, T = p.T, N1N2 = N1 * N2;
    var MULT = N2 / 128;
    var NB = (N + 7) >> 3, N1N2B = N1N2 >> 3, NW = (N + 31) >> 5;
    var PK_BYTES = SEED + NB, CT_BYTES = NB + N1N2B + SALT;
    var name = 'hqc' + level;

    /* ---------------- bit vectors: Uint32Array, little-endian, N bits ---------------- */
    function from_bytes(b, nbits) {
        var w = new Uint32Array(NW);
        for (var i = 0; i < b.length; i++) { w[i >> 2] |= b[i] << ((i & 3) * 8); }
        mask_to(w, nbits);
        return w;
    }
    function to_bytes(w, nbytes) {
        var b = new Uint8Array(nbytes);
        for (var i = 0; i < nbytes; i++) { b[i] = (w[i >> 2] >>> ((i & 3) * 8)) & 0xff; }
        return b;
    }
    function mask_to(w, nbits) {
        var full = nbits >> 5, rem = nbits & 31;
        if (full < w.length) { w[full] &= rem ? (1 << rem) - 1 : 0; for (var i = full + 1; i < w.length; i++) { w[i] = 0; } }
    }

    /*
     * rot(v, s) = v · x^s mod (x^N − 1) for a PUBLIC s in [0, N): the bits
     * shifted left by s, and the s top ones wrapped round to the bottom.
     */
    function shl_bits(v, s, out) {             /* out = (v << s) truncated to N bits */
        var ws = s >> 5, bs = s & 31;
        for (var i = NW - 1; i >= 0; i--) {
            var j = i - ws, hi = j >= 0 ? v[j] : 0, lo = j - 1 >= 0 ? v[j - 1] : 0;
            out[i] = bs ? (hi << bs) | (lo >>> (32 - bs)) : hi;
        }
        mask_to(out, N);
    }
    function shr_bits_xor(v, s, out) {         /* out ^= v >> s */
        var ws = s >> 5, bs = s & 31;
        for (var i = 0; i < NW; i++) {
            var j = i + ws, lo = j < NW ? v[j] : 0, hi = j + 1 < NW ? v[j + 1] : 0;
            out[i] ^= bs ? (lo >>> bs) | (hi << (32 - bs)) : lo;
        }
    }
    function rot_public(v, s, out) { shl_bits(v, s, out); if (s) { shr_bits_xor(v, N - s, out); } }

    /* the stages of a barrel shifter: rotations by 2^b mod N */
    var STAGES = [];
    for (var b = 0; (1 << b) < N; b++) { STAGES.push((1 << b) % N); }

    /*
     * dense · (sparse with support `sup`), mod x^N − 1. Each support element
     * rotates the dense vector through every stage, each stage's result
     * kept or discarded by a mask from that bit of the (secret) position.
     */
    function mul_sparse(dense, sup) {
        var acc = new Uint32Array(NW), cur = new Uint32Array(NW), tmp = new Uint32Array(NW);
        for (var k = 0; k < sup.length; k++) {
            var pos = sup[k];
            cur.set(dense);
            for (var st = 0; st < STAGES.length; st++) {
                rot_public(cur, STAGES[st], tmp);
                var m = -((pos >>> st) & 1) | 0;
                for (var i = 0; i < NW; i++) { cur[i] = (tmp[i] & m) | (cur[i] & ~m); }
            }
            xor_into(acc, cur);
        }
        cur.fill(0); tmp.fill(0);
        return acc;
    }
    function vector_of(sup) {
        var v = new Uint32Array(NW);
        /* every word visited for every element: the index written never depends on a branch */
        for (var i = 0; i < NW; i++) {
            var val = 0;
            for (var k = 0; k < sup.length; k++) {
                var d = i ^ (sup[k] >>> 5), eq = ((d | -d) >>> 31) ^ 1;
                val |= (1 << (sup[k] & 31)) & -eq;
            }
            v[i] = val;
        }
        return v;
    }

    /* ---------------- sampling (vector.c) ---------------- */
    function xof(seed, dom) { return xof_stream(shake256, dom === undefined ? seed : concat([seed, new Uint8Array([dom])]), 4096); }

    function set_random(x) { return from_bytes(x.read(NB), N); }

    /* rejection sampling, for the key: 24-bit candidates below the threshold, mod N, distinct */
    function support1(x, weight) {
        var sup = new Uint32Array(weight);
        for (var i = 0; i < weight;) {
            var r = x.read(3), c = r[0] | (r[1] << 8) | (r[2] << 16);
            var accept = ((c - p.threshold) >>> 31) & 1;
            c = c % N;
            var found = 0;
            for (var j = 0; j < i; j++) { var d = sup[j] ^ c; found |= ((d | -d) >>> 31) ^ 1; }
            accept &= found ^ 1;
            sup[i] = c;
            i += accept;
        }
        return sup;
    }
    /* for encryption: i + ⌊u·(N − i)/2^32⌋, duplicates replaced by i (vect_generate_random_support2) */
    function support2(x, weight) {
        var b = x.read(4 * weight), sup = new Uint32Array(weight);
        for (var i = 0; i < weight; i++) {
            var u = (b[4 * i] | (b[4 * i + 1] << 8) | (b[4 * i + 2] << 16) | (b[4 * i + 3] << 24)) >>> 0;
            sup[i] = i + Math.floor(u * (N - i) / 4294967296);
        }
        for (var k = weight - 2; k >= 0; k--) {
            var found = 0;
            for (var j = k + 1; j < weight; j++) { var d = sup[j] ^ sup[k]; found |= ((d | -d) >>> 31) ^ 1; }
            var m = -found;
            sup[k] = (m & k) | (~m & sup[k]);
        }
        return sup;
    }

    /* ---------------- Reed-Solomon over GF(2^8), systematic (reed_solomon.c) ---------------- */
    var G = (function () {                     /* g(x) = Π_{i=1}^{2t} (x − α^i) */
        var g = [1];
        for (var i = 1; i <= 2 * T; i++) {
            var a = alpha_pow(i), ng = new Array(g.length + 1).fill(0);
            for (var j = 0; j < g.length; j++) { ng[j + 1] ^= g[j]; ng[j] ^= gf_mul(g[j], a); }
            g = ng;
        }
        return g;
    }());
    function rs_encode(m) {
        var c = new Uint8Array(N1), R = N1 - K;
        for (var i = 0; i < K; i++) {
            var gate = m[K - 1 - i] ^ c[R - 1];
            for (var k = R - 1; k; k--) { c[k] = c[k - 1] ^ gf_mul(gate, G[k]); }
            c[0] = gf_mul(gate, G[0]);
        }
        c.set(m, R);
        return c;
    }
    /* β^j for the message positions, β = α^(−pos), pos = N1 − K + i (public) */
    var EVAL = [];
    for (var ii = 0; ii < K; ii++) { var row = []; for (var jj = 1; jj <= T; jj++) { row.push(alpha_pow(-(N1 - K + ii) * jj)); } EVAL.push(row); }
    function eval_at(poly, i) { var out = poly[0]; for (var j = 1; j <= T; j++) { out ^= gf_mul(poly[j], EVAL[i][j - 1]); } return out; }

    function rs_decode(c) {
        /* syndromes S_i = Σ_j c_j α^((i+1)j) */
        var S = new Array(2 * T).fill(0);
        for (var i = 0; i < 2 * T; i++) {
            for (var j = 1; j < N1; j++) { S[i] ^= gf_mul(c[j], alpha_pow((i + 1) * j)); }
            S[i] ^= c[0];
        }
        /* Berlekamp-Massey, with the reference's masks in place of branches */
        var sigma = new Array(T + 1).fill(0), sigma_mu = new Array(T + 1).fill(0), xsr = new Array(T + 1).fill(0);
        sigma[0] = 1; xsr[1] = 1;
        var deg_sigma = 0, deg_sigma_rho = 0, rho = 0xffff, d_rho = 1, d_mu = S[0];
        for (var mu = 0; mu < 2 * T; mu++) {
            var d_nonzero = nz_mask(d_mu);
            for (var a = 0; a <= T; a++) { sigma_mu[a] = sigma[a]; }
            var deg_sigma_mu = deg_sigma;
            var q = gf_mul(d_mu, gf_inverse(d_rho));
            for (var k = 1; k <= mu + 1 && k <= T; k++) { sigma[k] ^= gf_mul(q, xsr[k]); }
            var deg_xsr = ((mu - rho) + deg_sigma_rho) & 0xffff;
            var grow = -(((deg_sigma_mu - deg_xsr) & 0xffff) >> 15) & 0xffff;
            var pm = d_nonzero & grow;
            deg_sigma ^= pm & (deg_xsr ^ deg_sigma);
            for (var t = T; t; t--) { xsr[t] = (pm & sigma_mu[t - 1]) ^ (~pm & xsr[t - 1] & 0xffff); }
            deg_sigma_rho ^= pm & (deg_sigma_mu ^ deg_sigma_rho);
            rho ^= pm & (mu ^ rho);
            d_rho ^= pm & (d_mu ^ d_rho);
            if (mu + 1 < 2 * T) {
                d_mu = S[mu + 1];
                for (var u = 1; u <= mu + 1 && u <= T; u++) { d_mu ^= gf_mul(sigma[u], S[mu + 1 - u]); }
            }
        }
        /* error positions among the message symbols, then Forney's values */
        var z = new Array(T + 1).fill(0);
        z[0] = 1;
        for (var zi = 0; zi < T; zi++) {
            z[zi + 1] = S[zi];
            for (var zj = 0; zj < zi; zj++) { z[zi + 1] ^= gf_mul(sigma[zj + 1], S[zi - 1 - zj]); }
            z[zi + 1] ^= sigma[zi + 1];
        }
        var sodd = new Array(T + 1).fill(0);
        for (var o = 1; o <= T; o += 2) { sodd[o] = sigma[o]; }
        var m = new Uint8Array(K);
        for (var e = 0; e < K; e++) {
            var at_err = eval_at(sigma, e) & 0xff;
            var is_err = ((at_err | -at_err) >>> 31) ^ 1;              /* sigma(β) = 0 */
            var num = eval_at(z, e) & 0xff, den = eval_at(sodd, e) & 0xff;
            var mag = gf_mul(num, gf_inverse(den));
            var valid = -is_err & nz_mask(den) & 0xff;
            m[e] = c[e + N1 - K] ^ (mag & valid);
        }
        return m;
    }

    /* ---------------- duplicated Reed-Muller RM(1,7) (reed_muller.c) ---------------- */
    function rm_word(msg) {                    /* the four 32-bit words of one RM(1,7) codeword */
        function bm(x) { return -(x & 1) | 0; }
        var w = new Int32Array(4), f = bm(msg >> 7);
        f ^= bm(msg) & 0x55555555; f ^= bm(msg >> 1) & 0x33333333; f ^= bm(msg >> 2) & 0x0f0f0f0f;
        f ^= bm(msg >> 3) & (0xff00ff00 | 0); f ^= bm(msg >> 4) & (0xffff0000 | 0);
        w[0] = f; f ^= bm(msg >> 5); w[1] = f; f ^= bm(msg >> 6); w[3] = f; f ^= bm(msg >> 5); w[2] = f;
        return w;
    }
    function rm_encode(c) {                    /* N1 bytes -> N1·N2 bits, as bytes */
        var out = new Uint8Array(N1N2B), cw = 16;
        for (var i = 0; i < N1; i++) {
            var w = rm_word(c[i]);
            for (var cp = 0; cp < MULT; cp++) {
                var base = (i * MULT + cp) * cw;
                for (var part = 0; part < 4; part++) { for (var by = 0; by < 4; by++) { out[base + 4 * part + by] = (w[part] >>> (8 * by)) & 0xff; } }
            }
        }
        return out;
    }
    function rm_decode(bytes) {
        var out = new Uint8Array(N1), ex = new Int32Array(128), tr = new Int32Array(128);
        for (var i = 0; i < N1; i++) {
            ex.fill(0);
            for (var cp = 0; cp < MULT; cp++) {
                var base = (i * MULT + cp) * 16;
                for (var part = 0; part < 4; part++) {
                    var w = (bytes[base + 4 * part] | (bytes[base + 4 * part + 1] << 8) | (bytes[base + 4 * part + 2] << 16) | (bytes[base + 4 * part + 3] << 24)) >>> 0;
                    for (var bit = 0; bit < 32; bit++) { ex[part * 32 + bit] += (w >>> (bit ^ 7)) & 1; }
                }
            }
            /* the fast Hadamard transform, seven passes */
            var src = ex, dst = tr;
            for (var pass = 0; pass < 7; pass++) {
                for (var k = 0; k < 64; k++) { dst[k] = src[2 * k] + src[2 * k + 1]; dst[k + 64] = src[2 * k] - src[2 * k + 1]; }
                var sw = src; src = dst; dst = sw;
            }
            var t = src;                        /* after seven passes the result is in tr */
            t[0] -= 64 * MULT;
            /* the peak, first one on a tie, with no branch */
            var pabs = 0, pval = 0, ppos = 0;
            for (var j = 0; j < 128; j++) {
                var v = t[j], neg = v >> 31, ab = (v ^ neg) - neg;
                var gt = ((pabs - ab) >>> 31) & 1, m = -gt;
                pval = (v & m) | (pval & ~m); ppos = (j & m) | (ppos & ~m); pabs = (ab & m) | (pabs & ~m);
            }
            ppos |= 128 * (((-pval) >>> 31) & 1);
            out[i] = ppos;
        }
        return out;
    }

    /* ---------------- hashes (symmetric.c), each with its domain byte ---------------- */
    function hash_h(ek) { return sha3_256(concat([ek, new Uint8Array([1])])); }
    function hash_g(hek, m, salt) { return sha3_512(concat([hek, m, salt, new Uint8Array([0])])); }
    function hash_i(seed) { return sha3_512(concat([seed, new Uint8Array([2])])); }
    function hash_j(hek, sigma, u, v, salt) { return sha3_256(concat([hek, sigma, u, v, salt, new Uint8Array([3])])); }

    /* ---------------- HQC-PKE (hqc.c) ---------------- */
    function pke_keygen(seed) {
        var ks = hash_i(seed), seed_dk = ks.slice(0, SEED), seed_ek = ks.slice(SEED);
        var dx = xof(seed_dk), ysup = support1(dx, p.W), xsup = support1(dx, p.W);
        var h = set_random(xof(seed_ek));
        var s = mul_sparse(h, ysup);
        xor_into(s, vector_of(xsup));
        ks.fill(0);
        return { ek: concat([seed_ek, to_bytes(s, NB)]), seed_dk: seed_dk, ysup: ysup };
    }
    function pke_encrypt(ek, m, theta) {
        var x = xof(theta);
        var r2 = support2(x, p.WR), e = support2(x, p.WE), r1 = support2(x, p.WR);
        var h = set_random(xof(ek.subarray(0, SEED))), s = from_bytes(ek.subarray(SEED), N);
        var u = mul_sparse(h, r2);
        xor_into(u, vector_of(r1));
        var t = mul_sparse(s, r2);
        xor_into(t, vector_of(e));
        mask_to(t, N1N2);
        var v = from_bytes(rm_encode(rs_encode(m)), N1N2);
        xor_into(v, t);
        r1.fill(0); r2.fill(0); e.fill(0); t.fill(0);
        return { u: to_bytes(u, NB), v: to_bytes(v, N1N2B) };
    }
    function pke_decrypt(ysup, u, v) {
        var t = mul_sparse(from_bytes(u, N), ysup);
        mask_to(t, N1N2);
        xor_into(t, from_bytes(v, N1N2));
        var m = rs_decode(rm_decode(to_bytes(t, N1N2B)));
        t.fill(0);
        return m;
    }

    /* ---------------- HQC-KEM (hqc-kem.c) ---------------- */
    /* seed_pke ‖ σ from the KEM seed, under the domain byte K (the reference's xof_init_dom_sep) */
    function kem_seeds(seed_kem) { var x = xof(seed_kem, K); return { seed_pke: new Uint8Array(x.read(SEED)), sigma: new Uint8Array(x.read(K)) }; }

    function keygen_derand(seed_kem) {
        if (!(seed_kem instanceof Uint8Array) || seed_kem.length !== SEED) { throw new Error(name + ': the key seed is 32 bytes'); }
        var ks = kem_seeds(seed_kem), kp = pke_keygen(ks.seed_pke);
        ks.seed_pke.fill(0); ks.sigma.fill(0); kp.seed_dk.fill(0); kp.ysup.fill(0);
        return { pk: kp.ek, sk: new Uint8Array(seed_kem) };
    }
    function encaps_derand(pk, m, salt) {
        if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { throw new Error(name + ': a public key is ' + PK_BYTES + ' bytes'); }
        if (!(m instanceof Uint8Array) || m.length !== K || !(salt instanceof Uint8Array) || salt.length !== SALT) {
            throw new Error(name + ': encapsulation takes a ' + K + '-byte message and a 16-byte salt');
        }
        var kt = hash_g(hash_h(pk), m, salt), c = pke_encrypt(pk, m, kt.subarray(32));
        var ss = kt.slice(0, 32);
        kt.fill(0);
        return { ct: concat([c.u, c.v, salt]), ss: ss };
    }
    function decaps(sk, ct) {
        if (!(sk instanceof Uint8Array) || sk.length !== SEED) { throw new Error(name + ': a secret key is 32 bytes'); }
        if (!(ct instanceof Uint8Array) || ct.length !== CT_BYTES) { throw new Error(name + ': a ciphertext is ' + CT_BYTES + ' bytes'); }
        var ks = kem_seeds(sk), kp = pke_keygen(ks.seed_pke);
        var u = ct.subarray(0, NB), v = ct.subarray(NB, NB + N1N2B), salt = ct.subarray(NB + N1N2B);
        var m = pke_decrypt(kp.ysup, u, v);
        var hek = hash_h(kp.ek), kt = hash_g(hek, m, salt), c = pke_encrypt(kp.ek, m, kt.subarray(32));
        var kbar = hash_j(hek, ks.sigma, u, v, salt);
        /* c' == c, folded to one bit with no branch (the salt is the ciphertext's own) */
        var diff = 0;
        for (var i = 0; i < NB; i++) { diff |= c.u[i] ^ u[i]; }
        for (var j = 0; j < N1N2B; j++) { diff |= c.v[j] ^ v[j]; }
        var mk = -(((diff | -diff) >>> 31) ^ 1) & 0xff, out = new Uint8Array(32);
        for (var k = 0; k < 32; k++) { out[k] = (kt[k] & mk) | (kbar[k] & ~mk); }
        ks.seed_pke.fill(0); ks.sigma.fill(0); kp.seed_dk.fill(0); kp.ysup.fill(0); m.fill(0); kt.fill(0); kbar.fill(0);
        return out;
    }

    return {
        NAME: name, PK_BYTES: PK_BYTES, SK_BYTES: SEED, CT_BYTES: CT_BYTES, SS_BYTES: 32, MESSAGE_BYTES: K,
        keygen_derand: keygen_derand,
        /** rng(32) once - the KEM seed, which is the secret key */
        keygen: function (rng) { rng = require_rng(name + '.keygen', rng); var s = rng(SEED); try { return keygen_derand(s); } finally { s.fill(0); } },
        encaps_derand: encaps_derand,
        /** rng(K) for the message, then rng(16) for the salt - in that order, as the KATs draw them */
        encaps: function (pk, rng) {
            rng = require_rng(name + '.encaps', rng);
            var m = rng(K), salt = rng(SALT);
            try { return encaps_derand(pk, m, salt); } finally { m.fill(0); }
        },
        /** Never fails: a bad ciphertext gives SHA3-256(H(ek) ‖ σ ‖ c ‖ 3) (implicit rejection). */
        decaps: decaps,
        /** ⚠ HAZMAT: the generator of the Reed-Solomon code, for checking against the specification. */
        rs_generator: function () { return G.slice(); }
    };
}

export var hqc1 = /* @__PURE__ */ build(1);
export var hqc3 = /* @__PURE__ */ build(3);
export var hqc5 = /* @__PURE__ */ build(5);
