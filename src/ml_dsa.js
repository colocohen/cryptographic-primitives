/**
 * ML-DSA  -  FIPS 204, formerly CRYSTALS-Dilithium
 *
 * The post-quantum signature scheme NIST standardised in August 2024,
 * alongside ML-KEM. Where ML-KEM replaces key agreement, this replaces
 * ECDSA, EdDSA and RSA signatures.
 *
 * IT IS "FIAT-SHAMIR WITH ABORTS", and the aborts are the whole design. A
 * signature is a proof of knowledge of a short secret; the natural way to
 * build one leaks information about that secret through the proof's
 * distribution. Dilithium's answer is to compute a candidate signature and
 * THROW IT AWAY if it falls outside a safe range, retrying with fresh
 * randomness. A signing call therefore loops - typically four to seven times
 * for ML-DSA-65 - and the number of iterations depends on the secret.
 *
 * THAT LOOP IS A TIMING CHANNEL AND IT IS ACCEPTED. The rejection condition
 * depends on secret data, so signing time varies with the key. The scheme's
 * security analysis accounts for this: what leaks is the number of rejections,
 * which is information about the discarded candidates rather than the key
 * itself. It is called out here because it looks exactly like the kind of
 * leak this library removes everywhere else, and the difference is
 * deliberate rather than an oversight.
 *
 * SIZES ARE THE REAL COST. An Ed25519 signature is 64 bytes; ML-DSA-65's is
 * 3309, with a 1952-byte public key. That is not a implementation detail - it
 * changes what fits in a certificate, a DNS record or a blockchain
 * transaction, and it is why hybrid deployment is the norm.
 */

import { shake256 } from './sha3.js';
import { concat, secure_random } from './commons/bytes.js';
import { xof_stream } from './commons/xof_stream.js';
import { equal } from './commons/ct.js';
import { fips_message, fips_interfaces } from './commons/fips_context.js';
import { pack_bits, unpack_bits } from './commons/bitpack.js';
import * as RING from './commons/dilithium_ring.js';
import { Q, N, D, ntt, ntt_inverse, poly_mul, poly_add, poly_sub,
         poly_new, to_positive, smod, poly_chknorm, poly_shift_left,
         ntt_copy, vec_ntt } from './commons/dilithium_ring.js';
import { module_lattice } from './commons/module_lattice.js';

var LAT = /* @__PURE__ */ module_lattice(RING);

export var PARAMS = {
    44: { k: 4, l: 4, eta: 2, tau: 39, beta: 78,  gamma1: 1 << 17, gamma2: (Q - 1) / 88, omega: 80, ctilde: 32 },
    65: { k: 6, l: 5, eta: 4, tau: 49, beta: 196, gamma1: 1 << 19, gamma2: (Q - 1) / 32, omega: 55, ctilde: 48 },
    87: { k: 8, l: 7, eta: 2, tau: 60, beta: 120, gamma1: 1 << 19, gamma2: (Q - 1) / 32, omega: 75, ctilde: 64 }
};

function bitlen(x) { var n = 0; while (x > 0) { n++; x >>>= 1; } return n; }

/* ---------------- rounding and hints ---------------- */

/**
 * Split a coefficient into its top bits and a signed remainder.
 *
 * The public key carries only the top bits of t, which is what keeps it from
 * being twice the size. The dropped low bits become part of the secret key
 * and are compensated for by the hint vector at verification time - that
 * exchange is most of what makes Dilithium's signatures as small as they are.
 */
function power2round(a) {
    var a1 = (a + (1 << (D - 1)) - 1) >> D;
    return [a1, a - (a1 << D)];
}

/** Split into high and low parts relative to 2*gamma2. */
function decompose(a, gamma2) {
    var a1 = (a + 127) >> 7;
    if (gamma2 === (Q - 1) / 32) {
        a1 = ((a1 * 1025 + (1 << 21)) >> 22) & 15;
    } else {
        a1 = ((a1 * 11275 + (1 << 23)) >> 24);
        a1 ^= ((43 - a1) >> 31) & a1;
    }
    var a0 = a - a1 * 2 * gamma2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    return [a1, a0];
}

function high_bits(a, gamma2) { return decompose(a, gamma2)[0]; }

function use_hint(h, a, gamma2) {
    var d = decompose(a, gamma2);
    var a1 = d[0], a0 = d[1];
    if (h === 0) { return a1; }
    if (gamma2 === (Q - 1) / 32) {
        return a0 > 0 ? (a1 + 1) & 15 : (a1 - 1) & 15;
    }
    if (a0 > 0) { return a1 === 43 ? 0 : a1 + 1; }
    return a1 === 0 ? 43 : a1 - 1;
}

/* ---------------- sampling ---------------- */


/** Secret polynomials with coefficients in [-eta, eta]. */
function rej_bounded_poly(rho, nonce, eta) {
    var a = poly_new();
    var st = xof_stream(shake256, concat([rho, new Uint8Array([nonce & 0xff, (nonce >> 8) & 0xff])]), 136 * 5);
    var j = 0;
    while (j < N) {
        var b = st.read(1)[0];
        var t0 = b & 0x0f, t1 = b >> 4;
        if (eta === 2) {
            if (t0 < 15 && j < N) { a[j++] = to_positive(2 - (t0 - (((205 * t0) >> 10) * 5))); }
            if (t1 < 15 && j < N) { a[j++] = to_positive(2 - (t1 - (((205 * t1) >> 10) * 5))); }
        } else {
            if (t0 < 9 && j < N) { a[j++] = to_positive(4 - t0); }
            if (t1 < 9 && j < N) { a[j++] = to_positive(4 - t1); }
        }
    }
    return a;
}

/**
 * The challenge: a polynomial with exactly tau coefficients equal to +/-1 and
 * the rest zero.
 *
 * Its sparsity is what keeps c*s1 short enough for the rejection bound to be
 * satisfiable, and its low weight is why multiplying by it is cheap.
 */
function sample_in_ball(seed, tau) {
    var c = poly_new();
    var buf = shake256(seed, 136 * 2);
    var signs = 0n;
    for (var i = 0; i < 8; i++) { signs |= BigInt(buf[i]) << BigInt(8 * i); }
    var pos = 8;
    for (var i2 = N - tau; i2 < N; i2++) {
        var b;
        do {
            if (pos >= buf.length) { buf = shake256(seed, buf.length * 2); }
            b = buf[pos++];
        } while (b > i2);
        c[i2] = c[b];
        c[b] = to_positive(1 - 2 * Number(signs & 1n));
        signs >>= 1n;
    }
    return c;
}

/** The masking vector y, uniform in (-gamma1, gamma1]. */
function expand_mask(rho, nonce, gamma1) {
    var bits = bitlen(gamma1 - 1) + 1;
    var buf = shake256(concat([rho, new Uint8Array([nonce & 0xff, (nonce >> 8) & 0xff])]), 32 * bits);
    /* the bit reader used to be written out here a third time, beside
       pack_bits/unpack_bits and ml_kem's copies; all are commons/bitpack.js */
    var a = unpack_bits(buf, 0, N, bits);
    for (var i = 0; i < N; i++) { a[i] = to_positive(gamma1 - a[i]); }
    return a;
}

/*
 * ---------------- bit packing ----------------
 *
 * pack_bits / unpack_bits are commons/bitpack.js, shared with ml_kem.js's
 * ByteEncode/ByteDecode: FIPS 203 and 204 define the same little-endian
 * order, and the two files had the same loop.
 */

/* ---------------- the scheme ---------------- */

function build(level) {
    var p = PARAMS[level];
    var k = p.k, l = p.l;

    var ETA_BITS = bitlen(2 * p.eta);
    var T1_BITS = bitlen(Q - 1) - D;              /* 10 */
    var GAMMA1_BITS = bitlen(p.gamma1 - 1) + 1;
    var W1_BITS = p.gamma2 === (Q - 1) / 32 ? 4 : 6;

    var PK_BYTES = 32 + 32 * k * T1_BITS;
    var SK_BYTES = 128 + 32 * ((l + k) * ETA_BITS + k * D);
    var SIG_BYTES = p.ctilde + 32 * l * GAMMA1_BITS + p.omega + k;

    /* ExpandA: entry (i, j) from RejNTTPoly(rho ‖ j ‖ i) (commons/module_lattice.js) */
    function expand_a(rho) { return LAT.matrix(rho, k, l, false); }
    var row_dot = LAT.row_dot;

    function pk_encode(rho, t1) {
        var out = new Uint8Array(PK_BYTES);
        out.set(rho, 0);
        for (var i = 0; i < k; i++) { pack_bits(t1[i], T1_BITS, out, 32 + 32 * T1_BITS * i); }
        return out;
    }

    function pk_decode(pk) {
        var rho = pk.subarray(0, 32);
        var t1 = [];
        for (var i = 0; i < k; i++) {
            t1.push(unpack_bits(pk, 32 + 32 * T1_BITS * i, N, T1_BITS));
        }
        return { rho: rho, t1: t1 };
    }

    function sk_encode(rho, K, tr, s1, s2, t0) {
        var out = new Uint8Array(SK_BYTES);
        out.set(rho, 0); out.set(K, 32); out.set(tr, 64);
        var off = 128, i;
        for (i = 0; i < l; i++) {
            pack_bits(centred(s1[i], p.eta), ETA_BITS, out, off); off += 32 * ETA_BITS;
        }
        for (i = 0; i < k; i++) {
            pack_bits(centred(s2[i], p.eta), ETA_BITS, out, off); off += 32 * ETA_BITS;
        }
        for (i = 0; i < k; i++) {
            pack_bits(shifted(t0[i]), D, out, off); off += 32 * D;
        }
        return out;
    }

    /* eta - x, so the packed values are unsigned */
    function centred(poly, eta) {
        var out = new Int32Array(N);
        for (var i = 0; i < N; i++) { out[i] = eta - smod(poly[i]); }
        return out;
    }
    function shifted(poly) {
        var out = new Int32Array(N);
        for (var i = 0; i < N; i++) { out[i] = (1 << (D - 1)) - poly[i]; }
        return out;
    }

    function sk_decode(sk) {
        var rho = sk.subarray(0, 32), K = sk.subarray(32, 64), tr = sk.subarray(64, 128);
        var off = 128, i, j;
        var s1 = [], s2 = [], t0 = [];
        /* s1 and s2 are the same encoding, and were two copies of this loop */
        function eta_poly() {
            var v = unpack_bits(sk, off, N, ETA_BITS); off += 32 * ETA_BITS;
            for (var c = 0; c < N; c++) { v[c] = to_positive(p.eta - v[c]); }
            return v;
        }
        for (i = 0; i < l; i++) { s1.push(eta_poly()); }
        for (i = 0; i < k; i++) { s2.push(eta_poly()); }
        for (i = 0; i < k; i++) {
            var v3 = unpack_bits(sk, off, N, D); off += 32 * D;
            var q3 = new Int32Array(N);
            for (j = 0; j < N; j++) { q3[j] = (1 << (D - 1)) - v3[j]; }
            t0.push(q3);
        }
        return { rho: rho, K: K, tr: tr, s1: s1, s2: s2, t0: t0 };
    }

    function w1_encode(w1) {
        var out = new Uint8Array(32 * W1_BITS * k);
        for (var i = 0; i < k; i++) { pack_bits(w1[i], W1_BITS, out, 32 * W1_BITS * i); }
        return out;
    }

    /** sigEncode (FIPS 204 Alg 26): ctilde, z (l polys, any representative), hint (k bit-polys). */
    function sig_encode(ctilde, z, hint) {
        var sig = new Uint8Array(SIG_BYTES), i, j;
        sig.set(ctilde, 0);
        var off = p.ctilde;
        for (i = 0; i < l; i++) {
            var packed = new Int32Array(N);
            for (j = 0; j < N; j++) { packed[j] = p.gamma1 - smod(z[i][j]); }
            pack_bits(packed, GAMMA1_BITS, sig, off);
            off += 32 * GAMMA1_BITS;
        }
        var idx = 0;
        for (i = 0; i < k; i++) {
            for (j = 0; j < N; j++) { if (hint[i][j]) { sig[off + idx++] = j; } }
            sig[off + p.omega + i] = idx;
        }
        return sig;
    }

    /** mu = H(tr || M'), M' the formatted message (FIPS 204 Alg 7 line 6, Alg 8 line 7). */
    function mu_of(tr, mp) { return shake256(concat([tr, mp]), 64); }

    /** mu = H(tr || 0 || |ctx| || ctx || msg), pure ML-DSA (FIPS 204 Alg 2/7). */
    function message_mu(tr, msg, ctx) {
        var mp = fips_message(ctx, msg);
        if (!mp) { throw new Error('ml_dsa: context too long'); }
        return mu_of(tr, mp);
    }

    /*
     * The helpers below were HAZMAT-ONLY: written for ml_dsa_threshold.js
     * while keygen, sign and verify kept their own inline copies - so the
     * threshold signer and the ordinary one computed the same values through
     * different code, and only the final verify() tied them together. sign()
     * and verify() now call them too.
     */

    /** tr = H(pk), 64 bytes. */
    function tr_of(pk) { return shake256(pk, 64); }

    /** ctilde = H(mu || w1Encode(w1)). */
    function challenge(mu, w1) { return shake256(concat([mu, w1_encode(w1)]), p.ctilde); }

    /** MakeHint(z, r): 1 when adding z changes the high bits of r. */
    function make_hint(z, r) {
        return high_bits(r, p.gamma2) !== high_bits(to_positive(r + z), p.gamma2) ? 1 : 0;
    }

    /** HighBits of every coefficient of every polynomial: w -> w1. */
    function high_bits_vec(w) {
        var out = [];
        for (var i = 0; i < w.length; i++) {
            var h = new Int32Array(N);
            for (var j = 0; j < N; j++) { h[j] = high_bits(to_positive(w[i][j]), p.gamma2); }
            out.push(h);
        }
        return out;
    }

    /** t1 * 2^d, in the NTT domain, from the decoded public key's t1. */
    function t1_hat(t1) {
        var out = [];
        for (var i = 0; i < k; i++) {
            var t = Int32Array.from(t1[i]);
            poly_shift_left(t);          /* already < q: no reduction needed */
            ntt(t);
            out.push(t);
        }
        return out;
    }

    /**
     * A*z - c*t, row by row, back in the coefficient domain: what verify()
     * rounds into w1', and what ml_dsa_threshold.js builds both combine()
     * (t = t1*2^d) and its per-signer residual (t = a signer's public part)
     * on. It lived in ml_dsa_threshold.js as a second copy of verify's loop.
     *
     * @param c      the challenge polynomial, coefficient domain
     * @param z      l polynomials, any representative (signed is fine)
     * @param t_hat  k polynomials in the NTT domain
     */
    function az_minus_ct(A, c, z, t_hat) {
        var ch = ntt_copy(c), zh = vec_ntt(z), out = [];
        for (var i = 0; i < k; i++) {
            var az = row_dot(A[i], zh);
            var ct = poly_new(); poly_mul(ct, ch, t_hat[i]);
            var rr = poly_new(); poly_sub(rr, az, ct); ntt_inverse(rr);
            out.push(rr);
        }
        return out;
    }

    /*
     * What every signature with one key needs and none changes: sk decoded,
     * A expanded from rho, and s1, s2, t0 in the NTT domain. sign_internal
     * builds it per call; a signer (signer_create) builds it once - A alone
     * is a fifth of a signature. wipe() zeroes the secret parts.
     */
    function signing_state(sk_bytes) {
        if (!(sk_bytes instanceof Uint8Array) || sk_bytes.length !== SK_BYTES) { throw new Error('ml_dsa: sk must be ' + SK_BYTES + ' bytes'); }
        var s = sk_decode(sk_bytes);
        return {
            s: s, A: expand_a(s.rho),
            s1_hat: vec_ntt(s.s1), s2_hat: vec_ntt(s.s2),
            t0_hat: vec_ntt(s.t0),          /* t0 is signed; vec_ntt reduces */
            wipe: function () {
                var parts = [s.s1, s.s2, s.t0, this.s1_hat, this.s2_hat, this.t0_hat];
                for (var a = 0; a < parts.length; a++) { for (var b = 0; b < parts[a].length; b++) { parts[a][b].fill(0); } }
                s.K.fill(0);
            }
        };
    }

    /* ML-DSA.Sign_internal over a signing state (FIPS 204 Algorithm 7) */
    function sign_with(st, mp, rnd) {
        if (rnd == null) { rnd = secure_random(32); }
        if (!(rnd instanceof Uint8Array) || rnd.length !== 32) {
            throw new Error('ml_dsa: rnd must be 32 bytes');
        }
        var s = st.s, A = st.A, s1_hat = st.s1_hat, s2_hat = st.s2_hat, t0_hat = st.t0_hat;
        var i, j;

        var mu = mu_of(s.tr, mp);
        var rho2 = shake256(concat([s.K, rnd, mu]), 64);

        for (var kappa = 0; kappa < 1000; kappa += l) {
            var y = [];
            for (i = 0; i < l; i++) { y.push(expand_mask(rho2, kappa + i, p.gamma1)); }
            var y_hat = vec_ntt(y);

            var w = [];
            for (i = 0; i < k; i++) {
                var wi = row_dot(A[i], y_hat);
                ntt_inverse(wi);
                w.push(wi);
            }

            var ctilde = challenge(mu, high_bits_vec(w));
            var cc = sample_in_ball(ctilde, p.tau);
            var c_hat = ntt_copy(cc);

            /* z = y + c*s1 */
            var z = [], bad = false;
            for (i = 0; i < l; i++) {
                var cs = poly_new();
                poly_mul(cs, c_hat, s1_hat[i]);
                ntt_inverse(cs);
                poly_add(cs, cs, y[i]);
                z.push(cs);
                if (poly_chknorm(cs, p.gamma1 - p.beta)) { bad = true; }
            }
            if (bad) { continue; }

            /* r0 = LowBits(w - c*s2) */
            var r0_ok = true, ct0 = [], hint = [];
            var wcs = [];
            for (i = 0; i < k; i++) {
                var cs2 = poly_new();
                poly_mul(cs2, c_hat, s2_hat[i]);
                ntt_inverse(cs2);
                var d = poly_new();
                poly_sub(d, w[i], cs2);
                wcs.push(d);
                for (j = 0; j < N; j++) {
                    var lo = decompose(to_positive(d[j]), p.gamma2)[1];
                    if (Math.abs(lo) >= p.gamma2 - p.beta) { r0_ok = false; break; }
                }
                if (!r0_ok) { break; }
            }
            if (!r0_ok) { continue; }

            /* the hint, and its two bounds */
            var hint_weight = 0, ct0_ok = true;
            for (i = 0; i < k; i++) {
                var c0 = poly_new();
                poly_mul(c0, c_hat, t0_hat[i]);
                ntt_inverse(c0);
                ct0.push(c0);
                if (poly_chknorm(c0, p.gamma2)) { ct0_ok = false; break; }
            }
            if (!ct0_ok) { continue; }

            for (i = 0; i < k; i++) {
                var hi2 = new Uint8Array(N);
                for (j = 0; j < N; j++) {
                    /*
                     * The hint is one bit per coefficient: does adding the
                     * dropped low part of t change the high part? The
                     * verifier has only t1, so without this bit it would
                     * compute a different w1 and the challenge would not
                     * match.
                     */
                    hi2[j] = make_hint(ct0[i][j], wcs[i][j]);
                    hint_weight += hi2[j];
                }
                hint.push(hi2);
            }
            if (hint_weight > p.omega) { continue; }

            return sig_encode(ctilde, z, hint);
        }
        throw new Error('ml_dsa: signing exceeded the rejection limit');
    }

    var API = {
        PARAMS: p,
        PK_BYTES: PK_BYTES,
        SK_BYTES: SK_BYTES,
        SIG_BYTES: SIG_BYTES,

        /**
         * @param {Uint8Array} [seed]  32 bytes; omitted or null draws them
         *                             from the platform (secure_random)
         */
        keygen: function (seed) {
            if (seed == null) { seed = secure_random(32); }
            if (seed.length !== 32) { throw new Error('ml_dsa: seed must be 32 bytes'); }
            var h = shake256(concat([seed, new Uint8Array([k, l])]), 128);
            var rho = h.subarray(0, 32), rhop = h.subarray(32, 96), K = h.subarray(96, 128);

            var A = expand_a(rho);
            var s1 = [], s2 = [], i, j;
            for (i = 0; i < l; i++) { s1.push(rej_bounded_poly(rhop, i, p.eta)); }
            for (i = 0; i < k; i++) { s2.push(rej_bounded_poly(rhop, l + i, p.eta)); }

            var s1_hat = vec_ntt(s1);

            var t1 = [], t0 = [];
            for (i = 0; i < k; i++) {
                var t = row_dot(A[i], s1_hat);
                ntt_inverse(t);
                poly_add(t, t, s2[i]);
                var hi = new Int32Array(N), lo = new Int32Array(N);
                for (j = 0; j < N; j++) {
                    var pr = power2round(to_positive(t[j]));
                    hi[j] = pr[0]; lo[j] = pr[1];
                }
                t1.push(hi); t0.push(lo);
            }

            var pk = pk_encode(rho, t1);
            var tr = tr_of(pk);
            return { pk: pk, sk: sk_encode(rho, K, tr, s1, s2, t0) };
        },

        /**
         * ML-DSA.Sign_internal (FIPS 204 Alg 7): the signature of a formatted
         * message M'. sign() and hash_sign() (fips_interfaces, below) form M'
         * and call this.
         *
         * @param {Uint8Array} mp     M'
         * @param {Uint8Array} [rnd]  32 bytes. Omitted or null draws fresh ones
         *                            from the platform: the HEDGED variant,
         *                            FIPS 204's default, which is more robust
         *                            against fault and side-channel attacks on
         *                            the signer. 32 zero bytes give the
         *                            DETERMINISTIC variant (FIPS 204 3.4),
         *                            reproducible from the key and message.
         */
        sign_internal: function (sk_bytes, mp, rnd) {
            return sign_with(signing_state(sk_bytes), mp, rnd);
        },

        /**
         * ⚠ HAZMAT: the building blocks of ML-DSA, for constructions that
         *   produce standard ML-DSA signatures some other way — a threshold
         *   protocol, say. Nothing here checks that what is built from them
         *   is secure; the signature verify() accepts is all they guarantee.
         *   Polynomials are Int32Array(256) with coefficients in [0, q) unless
         *   stated; NTT and ring arithmetic are in commons/dilithium_ring.js.
         */
        hazmat: {
            PARAMS: p, Q: Q, N: N, D: D,
            expand_a: expand_a,
            row_dot: row_dot,
            pk_encode: pk_encode,
            pk_decode: pk_decode,
            sk_decode: sk_decode,
            power2round: power2round,
            decompose: function (a) { return decompose(a, p.gamma2); },
            high_bits: function (a) { return high_bits(a, p.gamma2); },
            use_hint: function (h, a) { return use_hint(h, a, p.gamma2); },
            make_hint: make_hint,
            sample_in_ball: function (ctilde) { return sample_in_ball(ctilde, p.tau); },
            w1_encode: w1_encode,
            sig_encode: sig_encode,
            tr: tr_of,
            mu: message_mu,
            challenge: challenge,
            high_bits_vec: high_bits_vec,
            t1_hat: t1_hat,
            az_minus_ct: az_minus_ct
        },

        /**
         * ML-DSA.Verify_internal (FIPS 204 Alg 8), over M'.
         *
         * THE CONTEXT LENGTH IS CHECKED WHERE M' IS FORMED (fips_interfaces),
         * in verification as in signing, and used not to be: a 256-byte
         * context was encoded with its length byte truncated to 0x00, and the
         * signature verified against a DIFFERENT message than the one
         * presented. Found by Wycheproof's InvalidContext cases; FIPS 204
         * section 5.3 requires the verifier to reject.
         */
        verify_internal: function (pk_bytes, mp, sig) {
            if (pk_bytes.length !== PK_BYTES || sig.length !== SIG_BYTES) { return false; }
            var pd = pk_decode(pk_bytes);
            var i, j;

            var ctilde = sig.subarray(0, p.ctilde);
            var off = p.ctilde;
            var z = [];
            for (i = 0; i < l; i++) {
                var v = unpack_bits(sig, off, N, GAMMA1_BITS);
                off += 32 * GAMMA1_BITS;
                var q = poly_new();
                for (j = 0; j < N; j++) { q[j] = to_positive(p.gamma1 - v[j]); }
                if (poly_chknorm(q, p.gamma1 - p.beta)) { return false; }
                z.push(q);
            }

            /* the hint, with its encoding validated - a malformed hint is a
               rejection, not something to interpret generously */
            var hint = [], idx = 0;
            for (i = 0; i < k; i++) {
                var end = sig[off + p.omega + i];
                if (end < idx || end > p.omega) { return false; }
                var h = new Uint8Array(N);
                for (j = idx; j < end; j++) {
                    if (j > idx && sig[off + j] <= sig[off + j - 1]) { return false; }
                    h[sig[off + j]] = 1;
                }
                idx = end;
                hint.push(h);
            }
            for (j = idx; j < p.omega; j++) { if (sig[off + j] !== 0) { return false; } }

            var A = expand_a(pd.rho);
            var mu = mu_of(tr_of(pk_bytes), mp);
            var cc = sample_in_ball(ctilde, p.tau);

            /* w1' = UseHint(h, A*z - c*t1*2^d) */
            var rows = az_minus_ct(A, cc, z, t1_hat(pd.t1));
            var w1 = [];
            for (i = 0; i < k; i++) {
                var h1 = new Int32Array(N);
                for (j = 0; j < N; j++) {
                    h1[j] = use_hint(hint[i][j], to_positive(rows[i][j]), p.gamma2);
                }
                w1.push(h1);
            }

            return equal(challenge(mu, w1), ctilde) === 1;
        }
    };
    /* sign / verify (pure), hash_sign / hash_verify and their _digest forms (pre-hash, HashML-DSA) */
    /*
     * signer_create(key): key is the expanded sk, or the 32-byte seed it
     * comes from (what a PKCS #8 ML-DSA key often carries) - two lengths that
     * cannot be confused. The signing state is built once.
     */
    var I = fips_interfaces('ml_dsa', API.sign_internal, API.verify_internal, function (key) {
        if (!(key instanceof Uint8Array) || (key.length !== 32 && key.length !== SK_BYTES)) {
            throw new Error('ml_dsa: a signer needs the ' + SK_BYTES + '-byte sk or its 32-byte seed');
        }
        var own = key.length === 32 ? API.keygen(key).sk : new Uint8Array(key);
        var st = signing_state(own);
        return {
            sign: function (mp, rnd) { return sign_with(st, mp, rnd); },
            wipe: function () { st.wipe(); own.fill(0); }
        };
    });
    for (var key in I) { API[key] = I[key]; }
    return API;
}

export var ml_dsa44 = /* @__PURE__ */ build(44);
export var ml_dsa65 = /* @__PURE__ */ build(65);
export var ml_dsa87 = /* @__PURE__ */ build(87);
