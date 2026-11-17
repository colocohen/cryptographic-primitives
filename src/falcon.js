/**
 * Falcon  -  round 3 of the NIST competition (v1.2, October 2020): key
 * generation, signing and verification
 *
 * The fourth NIST post-quantum signature, and the one with the SMALLEST
 * signatures by a wide margin:
 *
 *     Falcon-512      pk  897   sig ~656
 *     ML-DSA-44       pk 1312   sig 2420
 *     SLH-DSA-128s    pk   32   sig 7856
 *
 * That is why it exists alongside ML-DSA: a signature four times smaller
 * matters for certificates, DNSSEC records and anything with a size budget.
 * NIST is standardising it as FN-DSA (FIPS 206); this file is the round-3
 * specification that every Falcon deployment so far implements, and it is
 * pinned to that submission's test vectors: key generation and signing
 * reproduce them byte for byte from the vectors' DRBG seeds.
 *
 * WHAT MAKES FALCON HARD, AND HOW IT IS HANDLED HERE.
 *
 *   - Signing samples a DISCRETE GAUSSIAN over a lattice, with a fast-Fourier
 *     nearest-plane algorithm in floating point (ffSampling). If the
 *     sampler's distribution is skewed, signatures leak the private key - the
 *     published "FALCON Down" attacks. The sampler here is the reference's,
 *     operation for operation: the same ChaCha20-based generator, the same
 *     base sampler table, the same rejection with exp(-x) in 63-bit fixed
 *     point. That it reproduces the reference's signatures exactly is the
 *     evidence that its distribution is the reference's.
 *
 *   - The floating point must round exactly as the reference rounds. It
 *     does: JavaScript's numbers are the reference's IEEE-754 doubles, and
 *     commons/falcon_fft.js keeps the reference's order of operations.
 *
 *   - Key generation solves the NTRU equation f G - g F = q with big
 *     integers (commons/falcon_ntru.js).
 *
 * TIMING. The sampler and the arithmetic run in time independent of secret
 * values as far as JavaScript allows - the reference's constant-time
 * structure is kept (table scans rather than lookups, no secret branches in
 * the base sampler) - but a JavaScript engine gives no guarantee, and
 * floating-point operations on subnormals can be slow on some hardware.
 * Where an attacker can time many signatures with sub-microsecond
 * precision, ML-DSA is the better choice.
 *
 * FORMATS (the reference's):
 *   pk  = 0x00 + logn ‖ h, 14 bits per coefficient
 *   sk  = 0x50 + logn ‖ f ‖ g ‖ F, each coefficient in a fixed number of bits
 *   sig = 0x30 + logn ‖ nonce (40) ‖ s2 compressed - variable length; verify
 *         also accepts it zero-padded to SIG_BYTES
 */

import { shake256 } from './sha3.js';
import { chacha20 } from './chacha.js';
import { concat, secure_random } from './commons/bytes.js';
import { xof_stream } from './commons/xof_stream.js';
import { pack_bits_be, unpack_bits_be } from './commons/bitpack.js';
import * as P from './commons/falcon_fft.js';
import { Q, keygen as ntru_keygen, ntt, ntt_inverse, mod_q, mul_div_q } from './commons/falcon_ntru.js';

/*
 * beta2 is the squared norm bound: a signature is valid when the recovered
 * (s1, s2) pair is shorter than this. Everything in Falcon comes down to
 * that one inequality. fg_bits is the width of f and g in the private key
 * (F and G take 8).
 */
export var PARAMS = {
    512:  { n: 512,  logn: 9,  beta2: 34034726, pk: 897,  sk: 1281, sig: 666,  fg_bits: 6 },
    1024: { n: 1024, logn: 10, beta2: 70265242, pk: 1793, sk: 2305, sig: 1280, fg_bits: 5 }
};

/* ---------------- hashing to a point ---------------- */

/**
 * Hash a salted message to a polynomial modulo q.
 *
 * Sixteen bits are read at a time and REJECTED at or above 5q, then reduced.
 * Rejecting rather than reducing directly is what keeps the output uniform -
 * the same reason ML-KEM's matrix sampling rejects, and the same consequence:
 * the number of bytes consumed varies, which is safe because the input is
 * public.
 */
function hash_to_point(salt, msg, n) {
    var c = new Int32Array(n);
    var s = xof_stream(shake256, concat([salt, msg]), 2 * n * 3);
    var i = 0;
    while (i < n) {
        var b = s.read(2);
        var t = (b[0] << 8) | b[1];
        if (t < 61445) { c[i++] = t % Q; }   /* 61445 = 5*q, the largest
                                                multiple of q below 2^16 */
    }
    return c;
}

/* ---------------- encodings ---------------- */

function encode_pk(h, logn) {
    var out = new Uint8Array(1 + ((14 << logn) >> 3));
    out[0] = logn;
    pack_bits_be(h, 14, out, 1);
    return out;
}

/**
 * Decode the public key: a header byte then n 14-bit coefficients.
 *
 * @return {Int32Array|null}
 */
function decode_pk(pk, p) {
    if (pk.length !== p.pk || pk[0] !== p.logn) { return null; }
    var h = unpack_bits_be(pk, 1, p.n, 14).values;
    /* a coefficient at or above q is not a valid encoding */
    for (var i = 0; i < p.n; i++) { if (h[i] >= Q) { return null; } }
    return h;
}

/* f, g, F as signed `bits`-bit fields; -2^(bits-1) is not a valid value */
function decode_small(bytes, off, n, bits) {
    var r = unpack_bits_be(bytes, off, n, bits), out = new Int8Array(n), top = 1 << (bits - 1);
    for (var i = 0; i < n; i++) {
        var w = r.values[i];
        if (w === top) { return null; }
        out[i] = w & top ? w - (top << 1) : w;
    }
    return r.rest === 0 ? out : null;
}

function encode_sk(k, p) {
    var out = new Uint8Array(p.sk), off = 1;
    out[0] = 0x50 + p.logn;
    off += pack_bits_be(k.f, p.fg_bits, out, off);
    off += pack_bits_be(k.g, p.fg_bits, out, off);
    pack_bits_be(k.F, 8, out, off);
    return out;
}

/* { f, g, F, G } from a private key, G recomputed; null for a malformed key */
function decode_sk(sk, p) {
    if (!(sk instanceof Uint8Array) || sk.length !== p.sk || sk[0] !== 0x50 + p.logn) { return null; }
    var w = (p.n * p.fg_bits) >> 3;
    var f = decode_small(sk, 1, p.n, p.fg_bits), g = decode_small(sk, 1 + w, p.n, p.fg_bits);
    var F = decode_small(sk, 1 + 2 * w, p.n, 8);
    if (!f || !g || !F) { return null; }
    /* G = g F / f mod q (complete_private), and it must be small */
    var t = mul_div_q(g, F, f, p.logn);
    if (t === null) { return null; }
    var G = new Int8Array(p.n);
    for (var i = 0; i < p.n; i++) {
        var v = t[i] > Q >> 1 ? t[i] - Q : t[i];
        if (v < -127 || v > 127) { return null; }
        G[i] = v;
    }
    return { f: f, g: g, F: F, G: G };
}

/*
 * The compressed signature half.
 *
 * Falcon compresses because its coefficients are Gaussian and therefore
 * mostly small: each is a sign bit, seven low bits, and a UNARY high part.
 * That is why signatures VARY IN LENGTH and are padded to a fixed size - the
 * padding must be zero, and a non-canonical encoding is a rejection rather
 * than something to interpret.
 */
function comp_encode(s, max) {
    var out = new Uint8Array(max), acc = 0, len = 0, v = 0;
    for (var u = 0; u < s.length; u++) {
        var t = s[u];
        if (t < -2047 || t > 2047) { return null; }
        var w = t < 0 ? -t : t;
        acc = (acc << 1) | (t < 0 ? 1 : 0);
        acc = (acc << 7) | (w & 127);
        len += 8;
        var hi = w >> 7;
        acc = (acc << (hi + 1)) | 1;
        len += hi + 1;
        while (len >= 8) {
            len -= 8;
            if (v >= max) { return null; }
            out[v++] = (acc >>> len) & 0xff;
        }
        acc &= (1 << len) - 1;
    }
    if (len > 0) {
        if (v >= max) { return null; }
        out[v++] = (acc << (8 - len)) & 0xff;
    }
    return out.subarray(0, v);
}

/** @return {Int32Array|null} */
function decode_sig(bytes, n) {
    var s = new Int32Array(n);
    var pos = 0, acc = 0, bits = 0;

    for (var i = 0; i < n; i++) {
        /* refill to at least eight bits */
        if (bits < 8) {
            if (pos >= bytes.length) { return null; }
            acc = (acc << 8) | bytes[pos++];
            bits += 8;
        }
        var sign = (acc >> (bits - 1)) & 1;
        bits -= 1;

        if (bits < 7) {
            if (pos >= bytes.length) { return null; }
            acc = (acc << 8) | bytes[pos++];
            bits += 8;
        }
        var low = (acc >> (bits - 7)) & 0x7f;
        bits -= 7;

        /* the unary high part */
        var high = 0;
        for (;;) {
            if (bits === 0) {
                if (pos >= bytes.length) { return null; }
                acc = (acc << 8) | bytes[pos++];
                bits = 8;
            }
            var b = (acc >> (bits - 1)) & 1;
            bits -= 1;
            if (b) { break; }
            high++;
            /* coefficients are bounded by 2047, so the unary part is at most
               15 - a longer run is a malformed encoding, not a large value */
            if (high > 15) { return null; }
        }

        var v = (high << 7) | low;
        /* minus zero is not a canonical encoding */
        if (sign && v === 0) { return null; }
        s[i] = sign ? -v : v;
    }

    /*
     * Every remaining bit must be zero.
     *
     * Falcon signatures are VARIABLE LENGTH - the Gaussian coefficients
     * compress to whatever they compress to - and the padded encoding fills
     * the rest with zeros to a fixed size. Accepting non-zero padding would
     * make the encoding malleable: an attacker could alter those bytes and
     * produce a second valid signature for the same message.
     */
    if ((acc & ((1 << bits) - 1)) !== 0) { return null; }
    while (pos < bytes.length) { if (bytes[pos++] !== 0) { return null; } }
    return s;
}

/* ---------------- the sampler's randomness ---------------- */

/*
 * The reference's PRNG: ChaCha20 keyed from 56 bytes of SHAKE256 output,
 * eight blocks at a time, their 32-bit words interleaved block by block in a
 * 512-byte buffer. Word 14 and 15 of each block's input carry a 64-bit
 * counter XORed into the seed's last two words. ChaCha20 here is RFC 8439's
 * with the seed's words 8 and 9 in the counter and first nonce slots, which
 * is the same function.
 */
function prng(src) {
    var d = src.read(56).slice();
    var key = d.subarray(0, 32), ctr = d[32] | (d[33] << 8) | (d[34] << 16) | (d[35] << 24);
    var w10 = d[40] | (d[41] << 8) | (d[42] << 16) | (d[43] << 24), w11 = d[44] | (d[45] << 8) | (d[46] << 16) | (d[47] << 24);
    var cc_lo = (d[48] | (d[49] << 8) | (d[50] << 16) | (d[51] << 24)) >>> 0, cc_hi = (d[52] | (d[53] << 8) | (d[54] << 16) | (d[55] << 24)) >>> 0;
    var buf = new Uint8Array(512), ptr = 0, zero = new Uint8Array(64);

    function put32(a, o, v) { a[o] = v; a[o + 1] = v >>> 8; a[o + 2] = v >>> 16; a[o + 3] = v >>> 24; }
    function refill() {
        for (var u = 0; u < 8; u++) {
            /* a fresh nonce array per block: chacha20 caches its words by the array's identity */
            var nonce = new Uint8Array(12);
            nonce.set(d.subarray(36, 40), 0);
            put32(nonce, 4, w10 ^ cc_lo); put32(nonce, 8, w11 ^ cc_hi);
            var blk = chacha20(key, nonce, zero, ctr >>> 0);
            for (var v = 0; v < 16; v++) {
                for (var b = 0; b < 4; b++) { buf[(u << 2) + (v << 5) + b] = blk[4 * v + b]; }
            }
            cc_lo = (cc_lo + 1) >>> 0;
            if (cc_lo === 0) { cc_hi = (cc_hi + 1) >>> 0; }
        }
        ptr = 0;
    }
    refill();

    return {
        /* 8 bytes, little-endian, as three 24-bit limbs (all the base sampler reads) */
        u64_limbs: function () {
            if (ptr >= 512 - 9) { refill(); }
            var o = ptr;
            ptr += 8;
            return [buf[o] | (buf[o + 1] << 8) | (buf[o + 2] << 16), buf[o + 3] | (buf[o + 4] << 8) | (buf[o + 5] << 16), buf[o + 6] | (buf[o + 7] << 8)];
        },
        u8: function () {
            var v = buf[ptr++];
            if (ptr === 512) { refill(); }
            return v;
        }
    };
}

/* ---------------- the sampler ---------------- */

/*
 * The base sampler: a half-Gaussian of standard deviation 1.8205, as a
 * reverse cumulative table of 72-bit values in three 24-bit limbs. The
 * result is how many entries the random value is below, counted with a
 * borrow chain over every entry so the time is independent of the result.
 */
var DIST = [
    10745844, 3068844, 3741698, 5559083, 1580863, 8248194, 2260429, 13669192, 2736639,
    708981, 4421575, 10046180, 169348, 7122675, 4136815, 30538, 13063405, 7650655,
    4132, 14505003, 7826148, 417, 16768101, 11363290, 31, 8444042, 8086568,
    1, 12844466, 265321, 0, 1232676, 13644283, 0, 38047, 9111839,
    0, 870, 6138264, 0, 14, 12545723, 0, 0, 3104126,
    0, 0, 28824, 0, 0, 198, 0, 0, 1
];

function gaussian0(p) {
    var l = p.u64_limbs(), v0 = l[0], v1 = l[1], v2 = l[2] | (p.u8() << 16), z = 0;
    for (var u = 0; u < DIST.length; u += 3) {
        var cc = (v0 - DIST[u + 2]) >>> 31;
        cc = (v1 - DIST[u + 1] - cc) >>> 31;
        cc = (v2 - DIST[u] - cc) >>> 31;
        z += cc;
    }
    return z;
}

/* exp(-x) * ccs * 2^63 for 0 <= x < log 2, in 64-bit fixed point (fpr_expm_p63) */
var EXPM = [
    0x00000004741183A3n, 0x00000036548CFC06n, 0x0000024FDCBF140An, 0x0000171D939DE045n,
    0x0000D00CF58F6F84n, 0x000680681CF796E3n, 0x002D82D8305B0FEAn, 0x011111110E066FD0n,
    0x0555555555070F00n, 0x155555555581FF00n, 0x400000000002B400n, 0x7FFFFFFFFFFF4800n,
    0x8000000000000000n
];
var M64 = (1n << 64n) - 1n, TWO63 = 9223372036854775808;

function expm_p63(x, ccs) {
    var y = EXPM[0], z = (BigInt(P.trunc(x * TWO63)) << 1n) & M64;
    for (var u = 1; u < EXPM.length; u++) { y = (EXPM[u] - ((z * y) >> 64n)) & M64; }
    z = (BigInt(P.trunc(ccs * TWO63)) << 1n) & M64;
    return (z * y) >> 64n;
}

var LOG2 = 0.69314718055994530941723212146, INV_LOG2 = 1.4426950408889634073599246810;

/* a Bernoulli trial with probability ccs * exp(-x), against random bytes */
function ber_exp(p, x, ccs) {
    var s = P.trunc(x * INV_LOG2), r = x - s * LOG2;
    if (s > 63) { s = 63; }
    var z = (((expm_p63(r, ccs) << 1n) - 1n) & M64) >> BigInt(s), w, i = 64;
    do {
        i -= 8;
        w = p.u8() - Number((z >> BigInt(i)) & 0xffn);
    } while (w === 0 && i > 0);
    return w < 0;
}

var INV_2SQRSIGMA0 = .150865048875372721532312163019;
var SIGMA_MIN = [0, 1.1165085072329102588881898380334015, 1.1321247692325272405718031785357108,
    1.1475285353733668684571123112513188, 1.1702540788534828939713084716509250, 1.1925466358390344011122170489094133,
    1.2144300507766139921088487776957699, 1.2359260567719808790104525941706723, 1.2570545284063214162779743112075080,
    1.2778336969128335860256340575729042, 1.2982803343442918539708792538826807];
var INV_SIGMA = [0, 0.0069054793295940891952143765991630516, 0.0068102267767177975961393730687908629,
    0.0067188101910722710707826117910434131, 0.0065883354370073665545865037227681924, 0.0064651781207602900738053897763485516,
    0.0063486788828078995327741182928037856, 0.0062382586529084374473367528433697537, 0.0061334065020930261548984001431770281,
    0.0060336696681577241031668062510953022, 0.0059386453095331159950250124336477482];

/* an integer from the discrete Gaussian of centre mu and standard deviation 1/isigma */
function sampler(p, sigma_min, mu, isigma) {
    var s = P.floor(mu), r = mu - s, dss = (isigma * isigma) * 0.5, ccs = isigma * sigma_min;
    for (;;) {
        var z0 = gaussian0(p), b = p.u8() & 1, z = b + ((b << 1) - 1) * z0;
        var x = ((z - r) * (z - r)) * dss;
        x = x - (z0 * z0) * INV_2SQRSIGMA0;
        if (ber_exp(p, x, ccs)) { return s + z; }
    }
}

/* ---------------- fast Fourier sampling ---------------- */

/*
 * ffSampling over the LDL tree of the Gram matrix, computed level by level
 * as it is walked (the reference's ffSampling_fft_dyntree). t0, t1 are the
 * target, overwritten with the sample; g00, g01, g11 the Gram matrix,
 * destroyed; tmp scratch of 4n.
 */
function ff_sampling(samp, t0, t1, g00, g01, g11, orig_logn, logn, tmp) {
    if (logn === 0) {
        var leaf = Math.sqrt(g00[0]) * INV_SIGMA[orig_logn];
        t0[0] = samp(t0[0], leaf);
        t1[0] = samp(t1[0], leaf);
        return;
    }
    var n = 1 << logn, hn = n >> 1;
    P.poly_ldl(g00, g01, g11, logn);
    P.poly_split(tmp, tmp.subarray(hn), g00, logn); g00.set(tmp.subarray(0, n));
    P.poly_split(tmp, tmp.subarray(hn), g11, logn); g11.set(tmp.subarray(0, n));
    tmp.set(g01.subarray(0, n));
    g01.set(g00.subarray(0, hn));
    g01.set(g11.subarray(0, hn), hn);

    var z1 = tmp.subarray(n), w = tmp.subarray(2 * n);
    P.poly_split(z1, z1.subarray(hn), t1, logn);
    ff_sampling(samp, z1, z1.subarray(hn), g11, g11.subarray(hn), g01.subarray(hn), orig_logn, logn - 1, z1.subarray(n));
    P.poly_merge(w, z1, z1.subarray(hn), logn);
    z1.set(t1.subarray(0, n));
    P.poly_sub(z1, w, logn);
    t1.set(w.subarray(0, n));
    P.poly_mul(tmp, z1, logn);
    P.poly_add(t0, tmp, logn);

    var z0 = tmp;
    P.poly_split(z0, z0.subarray(hn), t0, logn);
    ff_sampling(samp, z0, z0.subarray(hn), g00, g00.subarray(hn), g01, orig_logn, logn - 1, z0.subarray(n));
    P.poly_merge(t0, z0, z0.subarray(hn), logn);
}

/* the basis [[g, -f], [G, -F]] in FFT form, into b00, b01, b10, b11 */
function basis(k, logn, b00, b01, b10, b11) {
    for (var i = 0, n = 1 << logn; i < n; i++) { b01[i] = k.f[i]; b00[i] = k.g[i]; b11[i] = k.F[i]; b10[i] = k.G[i]; }
    P.fft(b01, logn); P.fft(b00, logn); P.fft(b11, logn); P.fft(b10, logn);
    P.poly_neg(b01, logn); P.poly_neg(b11, logn);
}

/*
 * One signing attempt (do_sign_dyn), with the reference's buffer layout so
 * that every operation reads what the reference's reads. Returns s2, or null
 * when the sampled pair is too long and a new attempt is needed.
 */
function sign_attempt(samp, k, hm, p) {
    var logn = p.logn, n = p.n, T = new Float64Array(12 * n);
    var V = function (i) { return T.subarray(i * n); };
    var b00 = V(0), b01 = V(1), b10 = V(2), b11 = V(3), t0 = V(4), t1 = V(5);
    basis(k, logn, b00, b01, b10, b11);

    /* the Gram matrix B B*, into b00 (g00), b01 (g01), b10 (g11) */
    t0.set(b01.subarray(0, n)); P.poly_mulselfadj(t0, logn);
    t1.set(b00.subarray(0, n)); P.poly_muladj(t1, b10, logn);
    P.poly_mulselfadj(b00, logn); P.poly_add(b00, t0, logn);
    t0.set(b01.subarray(0, n));
    P.poly_muladj(b01, b11, logn); P.poly_add(b01, t1, logn);
    P.poly_mulselfadj(b10, logn);
    t1.set(b11.subarray(0, n)); P.poly_mulselfadj(t1, logn); P.poly_add(b10, t1, logn);
    var g00 = b00, g01 = b01, g11 = b10;
    b01 = t0; t0 = V(5); t1 = V(6);

    /* the target (hm, 0) B^-1 */
    for (var u = 0; u < n; u++) { t0[u] = hm[u]; }
    P.fft(t0, logn);
    var ni = 1 / 12289;
    t1.set(t0.subarray(0, n));
    P.poly_mul(t1, b01, logn); P.poly_mulconst(t1, -ni, logn);
    P.poly_mul(t0, b11, logn); P.poly_mulconst(t0, ni, logn);
    b11.set(T.subarray(5 * n, 7 * n));
    t0 = V(3); t1 = V(4);
    ff_sampling(samp, t0, t1, g00, g01, g11, logn, logn, V(5));

    /* back through B: the lattice point closest to the target */
    T.copyWithin(4 * n, 3 * n, 5 * n);
    t0 = V(4); t1 = V(5);
    b00 = V(0); b01 = V(1); b10 = V(2); b11 = V(3);
    basis(k, logn, b00, b01, b10, b11);
    var tx = V(6), ty = V(7);
    tx.set(t0.subarray(0, n)); ty.set(t1.subarray(0, n));
    P.poly_mul(tx, b00, logn); P.poly_mul(ty, b10, logn); P.poly_add(tx, ty, logn);
    ty.set(t0.subarray(0, n)); P.poly_mul(ty, b01, logn);
    t0.set(tx.subarray(0, n));
    P.poly_mul(t1, b11, logn); P.poly_add(t1, ty, logn);
    P.ifft(t0, logn); P.ifft(t1, logn);

    /* s1 = hm - t0, s2 = -t1, and the pair must be short (is_short_half) */
    var sqn = 0, s2 = new Int16Array(n);
    for (var v = 0; v < n; v++) { var z = hm[v] - P.rint(t0[v]); sqn += z * z; }
    for (var w = 0; w < n; w++) { s2[w] = -P.rint(t1[w]); sqn += s2[w] * s2[w]; }
    return sqn <= p.beta2 ? s2 : null;
}

/* ---------------- verification arithmetic ---------------- */

/* s1 = c - s2 h mod q, centred, and whether |(s1, s2)|^2 <= beta2 */
function is_short_verify(c, s2, h, p) {
    var t = mod_q(s2), H = Int32Array.from(h), logn = p.logn;
    ntt(t, logn); ntt(H, logn);
    for (var i = 0; i < p.n; i++) { t[i] = (t[i] * H[i]) % Q; }
    ntt_inverse(t, logn);
    var norm = 0;
    for (var j = 0; j < p.n; j++) {
        var v = (c[j] - t[j]) % Q;
        if (v < 0) { v += Q; }
        /* the centred representative is what the norm is measured on */
        if (v > Q >> 1) { v -= Q; }
        norm += v * v + s2[j] * s2[j];
    }
    return norm <= p.beta2;
}

/* ---------------- the scheme ---------------- */

function build(size) {
    var p = PARAMS[size], n = p.n;
    var SIG_MAX = p.sig - 41;    /* the compressed s2 must fit the padded format */

    var API = {
        PARAMS: p,
        PK_BYTES: p.pk,
        SK_BYTES: p.sk,
        SIG_BYTES: p.sig,

        /**
         * Key generation from a 48-byte seed (the reference draws exactly
         * that many from its RNG). Hundreds of milliseconds: the NTRU
         * equation is solved with big integers.
         *
         * @param {Uint8Array} [seed]  48 bytes; omitted or null draws fresh
         *                             ones from the platform
         */
        keygen: function (seed) {
            if (seed == null) { seed = secure_random(48); }
            if (!(seed instanceof Uint8Array) || seed.length !== 48) { throw new Error('falcon: the seed is 48 bytes'); }
            var k = ntru_keygen(seed, p.logn);
            return { pk: encode_pk(k.h, p.logn), sk: encode_sk(k, p) };
        },

        /**
         * @param {Uint8Array} rnd  88 bytes: the 40-byte nonce, then the
         *                          48-byte seed of the sampler's randomness,
         *                          in the order the reference draws them;
         *                          omitted or null draws fresh ones from
         *                          the platform
         * @return {Uint8Array} the signature, variable length, at most SIG_BYTES
         */
        sign: function (sk, msg, rnd) {
            var k = decode_sk(sk, p);
            if (k === null) { throw new Error('falcon: malformed private key'); }
            if (rnd == null) { rnd = secure_random(88); }
            if (!(rnd instanceof Uint8Array) || rnd.length !== 88) { throw new Error('falcon: rnd is 88 bytes'); }
            var nonce = rnd.subarray(0, 40), hm = hash_to_point(nonce, msg, n);
            var src = xof_stream(shake256, rnd.subarray(40), 56 * 4);
            for (;;) {
                var pr = prng(src), smin = SIGMA_MIN[p.logn];
                var s2 = sign_attempt(function (mu, isigma) { return sampler(pr, smin, mu, isigma); }, k, hm, p);
                if (s2 === null) { continue; }
                /*
                 * Rarely, a short s2 still compresses past the padded size;
                 * the reference's API (falcon.c) samples again, from the same
                 * stream, and so does this.
                 */
                var c = comp_encode(s2, SIG_MAX);
                if (c === null) { continue; }
                var sig = new Uint8Array(41 + c.length);
                sig[0] = 0x30 + p.logn; sig.set(nonce, 1); sig.set(c, 41);
                return sig;
            }
        },

        /**
         * Accepts BOTH encodings: the padded form at exactly SIG_BYTES, and
         * the variable-length form the reference produces by default. They
         * differ only in trailing zeros, and rejecting one of them would make
         * this unable to read half the Falcon signatures in the world.
         *
         * @param {Uint8Array} sig  header byte, 40-byte salt, then the
         *                          compressed s2
         * @return {boolean}
         */
        verify: function (pk, msg, sig) {
            if (sig.length < 42 || sig.length > p.sig) { return false; }
            /* the header byte: 0x30 for the compressed encoding, plus logn */
            if ((sig[0] & 0x0f) !== p.logn) { return false; }
            if ((sig[0] & 0xf0) !== 0x30) { return false; }

            var h = decode_pk(pk, p);
            if (h === null) { return false; }

            var salt = sig.subarray(1, 41);
            var s2 = decode_sig(sig.subarray(41), n);
            if (s2 === null) { return false; }

            /*
             * NO CONTEXT PREFIX. Round-3 Falcon hashes the salt and the raw
             * message; the domain-separation prefix that ML-DSA and SLH-DSA
             * carry is a FIPS 206 draft addition that no deployed
             * implementation applies yet - @noble/post-quantum refuses a
             * context argument outright. Adding it here would make this
             * unable to verify any Falcon signature in existence.
             */
            return is_short_verify(hash_to_point(salt, msg, n), s2, h, p);
        }
    };
    return API;
}

export var falcon512  = /* @__PURE__ */ build(512);
export var falcon1024 = /* @__PURE__ */ build(1024);
