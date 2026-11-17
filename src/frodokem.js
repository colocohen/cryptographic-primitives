/**
 * FrodoKEM - Learning With Errors key encapsulation, "plain" LWE
 * (the FrodoKEM team's 2023 standardization proposal, the version in the ISO
 * process; github.com/microsoft/PQCrypto-LWEKE)
 *
 * The conservative lattice KEM. ML-KEM's lattice has algebraic structure - a
 * polynomial ring - that makes it small and fast and is also the one thing
 * an attacker might someday use; FrodoKEM's has none: its public matrix A is
 * an unstructured n × n matrix of integers, regenerated from a 16-byte seed.
 * The price is size and time: a FrodoKEM-976 public key is 15,632 bytes
 * against ML-KEM-768's 1,184. Germany's BSI, France's ANSSI and the
 * Netherlands' NLNCSA recommend it for exactly that trade.
 *
 *     frodokem{640,976,1344}_{aes,shake}     the standard variants
 *     efrodokem{640,976,1344}_{aes,shake}    the ephemeral ones
 *
 * STANDARD OR EPHEMERAL. The standard variant adds a salt to every
 * ciphertext and doubles the seed for its noise; that is what keeps it secure
 * when one key receives very many ciphertexts (the multi-ciphertext attacks
 * the salt was added against). eFrodoKEM drops both, for keys that receive
 * few - one per key, as in a TLS-style exchange.
 *
 * AES OR SHAKE generates A: AES-128 where the hardware accelerates it,
 * SHAKE128 elsewhere. The choice changes only how A is expanded.
 *
 * A IS NEVER HELD WHOLE. At n = 1344 it is 1.8 million entries; each row is
 * generated, used in A·S (key generation) or S'·A (encapsulation), and
 * dropped.
 *
 * Decapsulation's re-encryption check and the choice between the real key
 * and the fallback s run without a secret-dependent branch (Guo, Johansson
 * and Nilsson, CRYPTO 2020, broke FrodoKEM's reference code through exactly
 * that branch).
 */
import { shake128, shake256 } from './sha3.js';
import { aes_block_fn } from './aes.js';
import { concat } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';

/* the specification's Tables 3 and 4: the error distribution (in units of
   2^-16, as given) and the sizes in BYTES */
var PARAMS = {
    640:  { n: 640,  D: 15, B: 2, chi: [9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1],
            seedA: 16, z: 16, mu: 16, seedSE: 32, salt: 32, s: 16, k: 16, pkh: 16, ss: 16, shake: shake128 },
    976:  { n: 976,  D: 16, B: 3, chi: [11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1],
            seedA: 16, z: 16, mu: 24, seedSE: 48, salt: 48, s: 24, k: 24, pkh: 24, ss: 24, shake: shake256 },
    1344: { n: 1344, D: 16, B: 4, chi: [18286, 14320, 6876, 2023, 364, 40, 2],
            seedA: 16, z: 16, mu: 32, seedSE: 64, salt: 64, s: 32, k: 32, pkh: 32, ss: 32, shake: shake256 }
};
var NBAR = 8;

function build(level, gen_kind, ephemeral) {
    var base = PARAMS[level];
    var n = base.n, D = base.D, Bb = base.B, q = 1 << D, QM = q - 1, H = base.shake;
    /* eFrodoKEM: half the noise seed, no salt */
    var seedSE_len = ephemeral ? base.seedSE / 2 : base.seedSE, salt_len = ephemeral ? 0 : base.salt;
    var name = (ephemeral ? 'efrodokem' : 'frodokem') + level + '_' + gen_kind;

    /* T_chi, the zero-centred CDF of §2.2.4 */
    var T = [base.chi[0] / 2 - 1];
    for (var z = 1; z < base.chi.length; z++) { T.push(T[z - 1] + base.chi[z]); }

    var B_BYTES = D * n * NBAR / 8, C1_BYTES = D * NBAR * n / 8, C2_BYTES = D * NBAR * NBAR / 8;
    var PK_BYTES = base.seedA + B_BYTES;
    var SK_BYTES = base.s + PK_BYTES + 2 * n * NBAR + base.pkh;
    var CT_BYTES = C1_BYTES + C2_BYTES + salt_len;

    /* ---------------- A, a row at a time (Algorithms 7, 8) ---------------- */
    function row_gen(seedA) {
        if (gen_kind === 'aes') {
            var enc = aes_block_fn(seedA), blk = new Uint8Array(16), out = new Uint8Array(16);
            return function (i, row) {
                for (var j = 0; j < n; j += 8) {
                    blk.fill(0);
                    blk[0] = i & 0xff; blk[1] = i >> 8; blk[2] = j & 0xff; blk[3] = j >> 8;
                    enc(blk, 0, out, 0);
                    for (var k = 0; k < 8; k++) { row[j + k] = (out[2 * k] | (out[2 * k + 1] << 8)) & QM; }
                }
            };
        }
        var inp = new Uint8Array(2 + seedA.length);
        inp.set(seedA, 2);
        return function (i, row) {
            inp[0] = i & 0xff; inp[1] = i >> 8;
            var c = shake128(inp, 2 * n);
            for (var j = 0; j < n; j++) { row[j] = (c[2 * j] | (c[2 * j + 1] << 8)) & QM; }
        };
    }

    /* ---------------- sampling (Algorithms 5, 6) ---------------- */
    /* count of t > T[z], with no branch on t */
    function sample(r) {
        var t = r >>> 1, e = 0;
        for (var z = 0; z < T.length - 1; z++) { e += (T[z] - t) >>> 31; }
        var sgn = -(r & 1);                     /* 0 or -1 */
        return (e ^ sgn) - sgn;                 /* e, or -e */
    }
    /* `count` samples from 16-bit little-endian words of `bytes`, from word `from` */
    function samples(bytes, from, count) {
        var out = new Int32Array(count);
        for (var i = 0; i < count; i++) { var w = from + i; out[i] = sample(bytes[2 * w] | (bytes[2 * w + 1] << 8)); }
        return out;
    }

    /* ---------------- packing (Algorithms 3, 4) ---------------- */
    function pack(vals) {
        var out = new Uint8Array(vals.length * D / 8), acc = 0, bits = 0, o = 0;
        for (var i = 0; i < vals.length; i++) {
            acc = (acc * q) + (vals[i] & QM); bits += D;          /* MSB first */
            while (bits >= 8) { bits -= 8; out[o++] = Math.floor(acc / Math.pow(2, bits)) & 0xff; acc %= Math.pow(2, bits); }
        }
        return out;
    }
    function unpack(b, count) {
        var out = new Int32Array(count), acc = 0, bits = 0, o = 0, i = 0;
        while (o < count) {
            while (bits < D) { acc = acc * 256 + b[i++]; bits += 8; }
            bits -= D;
            var p = Math.pow(2, bits);
            out[o++] = Math.floor(acc / p) & QM; acc %= p;
        }
        return out;
    }

    /* ---------------- encode / decode (Algorithms 1, 2): B bits per entry ---------------- */
    function encode(m) {
        var out = new Int32Array(NBAR * NBAR), bit = 0;
        for (var i = 0; i < out.length; i++) {
            var v = 0;
            for (var l = 0; l < Bb; l++, bit++) { v |= ((m[bit >> 3] >> (bit & 7)) & 1) << l; }
            out[i] = v << (D - Bb);
        }
        return out;
    }
    function decode(M) {
        var out = new Uint8Array(NBAR * NBAR * Bb / 8), bit = 0;
        for (var i = 0; i < M.length; i++) {
            var v = (((M[i] & QM) + (1 << (D - Bb - 1))) >>> (D - Bb)) & ((1 << Bb) - 1);
            for (var l = 0; l < Bb; l++, bit++) { out[bit >> 3] |= ((v >> l) & 1) << (bit & 7); }
        }
        return out;
    }

    /* ---------------- the matrix products ---------------- */
    /* B = A·S + E, S given as S^T (nbar × n, row-major), E n × nbar: one row of A at a time */
    function as_plus_e(seedA, St, E) {
        var gen = row_gen(seedA), row = new Int32Array(n), B = new Int32Array(n * NBAR);
        for (var i = 0; i < n; i++) {
            gen(i, row);
            for (var k = 0; k < NBAR; k++) {
                var acc = E[i * NBAR + k], s = k * n;
                for (var j = 0; j < n; j++) { acc += row[j] * St[s + j]; }
                B[i * NBAR + k] = acc & QM;
            }
        }
        return B;
    }
    /* B' = S'·A + E', S' and E' mbar × n: S' column i scales row i of A */
    function sa_plus_e(seedA, Sp, Ep) {
        var gen = row_gen(seedA), row = new Int32Array(n), acc = new Int32Array(Ep);
        for (var i = 0; i < n; i++) {
            gen(i, row);
            /* every entry of S', zero or not: S' is secret, and skipping its
               zeros would put its sparsity into the running time */
            for (var k = 0; k < NBAR; k++) {
                var s = Sp[k * n + i], o = k * n;
                for (var j = 0; j < n; j++) { acc[o + j] += s * row[j]; }
            }
        }
        for (var t = 0; t < acc.length; t++) { acc[t] &= QM; }
        return acc;
    }
    /* X (mbar × n) times Y (n × nbar) plus E (mbar × nbar) */
    function mul_add(X, Y, E) {
        var out = new Int32Array(NBAR * NBAR);
        for (var i = 0; i < NBAR; i++) {
            for (var k = 0; k < NBAR; k++) {
                var acc = E ? E[i * NBAR + k] : 0;
                for (var j = 0; j < n; j++) { acc += X[i * n + j] * Y[j * NBAR + k]; }
                out[i * NBAR + k] = acc & QM;
            }
        }
        return out;
    }

    /* ---------------- the KEM (Algorithms 12-14) ---------------- */
    var RAND_KEYGEN = base.s + seedSE_len + base.z, RAND_ENCAPS = base.mu + salt_len;

    function keygen_derand(r) {
        if (!(r instanceof Uint8Array) || r.length !== RAND_KEYGEN) { throw new Error(name + ': key generation takes ' + RAND_KEYGEN + ' bytes'); }
        var s = r.subarray(0, base.s), seedSE = r.subarray(base.s, base.s + seedSE_len), z = r.subarray(base.s + seedSE_len);
        var seedA = H(z, base.seedA);
        var rb = H(concat([new Uint8Array([0x5f]), seedSE]), 4 * n * NBAR);
        var St = samples(rb, 0, n * NBAR), E = samples(rb, n * NBAR, n * NBAR);
        var b = pack(as_plus_e(seedA, St, E));
        var pk = concat([seedA, b]), pkh = H(pk, base.pkh);
        var st = new Uint8Array(2 * n * NBAR);
        for (var i = 0; i < St.length; i++) { st[2 * i] = St[i] & 0xff; st[2 * i + 1] = (St[i] >> 8) & 0xff; }
        var sk = concat([s, pk, st, pkh]);
        St.fill(0); E.fill(0); st.fill(0); rb.fill(0);
        return { pk: pk, sk: sk };
    }

    /* everything encapsulation and the re-encryption share: (S', E', E'') from seedSE */
    function noise(seedSE) {
        var rb = H(concat([new Uint8Array([0x96]), seedSE]), 2 * (2 * NBAR * n + NBAR * NBAR));
        var out = { Sp: samples(rb, 0, NBAR * n), Ep: samples(rb, NBAR * n, NBAR * n), Epp: samples(rb, 2 * NBAR * n, NBAR * NBAR) };
        rb.fill(0);
        return out;
    }
    function encrypt(pk, mu, seedSE) {
        var seedA = pk.subarray(0, base.seedA), b = pk.subarray(base.seedA);
        var N = noise(seedSE);
        var Bp = sa_plus_e(seedA, N.Sp, N.Ep);
        var V = mul_add(N.Sp, unpack(b, n * NBAR), N.Epp), M = encode(mu);
        for (var i = 0; i < V.length; i++) { V[i] = (V[i] + M[i]) & QM; }
        N.Sp.fill(0);
        return { Bp: Bp, C: V };
    }
    function encaps_derand(pk, r) {
        if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { throw new Error(name + ': a public key is ' + PK_BYTES + ' bytes'); }
        if (!(r instanceof Uint8Array) || r.length !== RAND_ENCAPS) { throw new Error(name + ': encapsulation takes ' + RAND_ENCAPS + ' bytes'); }
        var mu = r.subarray(0, base.mu), salt = r.subarray(base.mu);
        var pkh = H(pk, base.pkh);
        var sk_ = H(concat([pkh, mu, salt]), seedSE_len + base.k);
        var e = encrypt(pk, mu, sk_.subarray(0, seedSE_len));
        var c1 = pack(e.Bp), c2 = pack(e.C);
        var ss = H(concat([c1, c2, salt, sk_.subarray(seedSE_len)]), base.ss);
        sk_.fill(0);
        return { ct: concat([c1, c2, salt]), ss: ss };
    }
    function decaps(sk, ct) {
        if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES) { throw new Error(name + ': a secret key is ' + SK_BYTES + ' bytes'); }
        if (!(ct instanceof Uint8Array) || ct.length !== CT_BYTES) { throw new Error(name + ': a ciphertext is ' + CT_BYTES + ' bytes'); }
        var c1 = ct.subarray(0, C1_BYTES), c2 = ct.subarray(C1_BYTES, C1_BYTES + C2_BYTES), salt = ct.subarray(C1_BYTES + C2_BYTES);
        var s = sk.subarray(0, base.s), pk = sk.subarray(base.s, base.s + PK_BYTES);
        var stb = sk.subarray(base.s + PK_BYTES, base.s + PK_BYTES + 2 * n * NBAR), pkh = sk.subarray(SK_BYTES - base.pkh);
        /* S (n × nbar) from S^T as stored, signed 16-bit little-endian */
        var S = new Int32Array(n * NBAR);
        for (var k = 0; k < NBAR; k++) { for (var j = 0; j < n; j++) { var w = k * n + j; S[j * NBAR + k] = (stb[2 * w] | (stb[2 * w + 1] << 8)) << 16 >> 16; } }
        var Bp = unpack(c1, NBAR * n), C = unpack(c2, NBAR * NBAR);
        var BS = mul_add(Bp, S, null), M = new Int32Array(NBAR * NBAR);
        for (var i = 0; i < M.length; i++) { M[i] = (C[i] - BS[i]) & QM; }
        var mu = decode(M);
        var sk_ = H(concat([pkh, mu, salt]), seedSE_len + base.k);
        var e = encrypt(pk, mu, sk_.subarray(0, seedSE_len));
        /* B' ‖ C == B'' ‖ C', folded to one bit with no branch */
        var diff = 0;
        for (var t = 0; t < Bp.length; t++) { diff |= Bp[t] ^ e.Bp[t]; }
        for (var u = 0; u < C.length; u++) { diff |= C[u] ^ e.C[u]; }
        var ok = ((diff | -diff) >>> 31) ^ 1, m = -ok & 0xff, kp = sk_.subarray(seedSE_len), kbar = new Uint8Array(base.k);
        for (var v = 0; v < kbar.length; v++) { kbar[v] = (kp[v] & m) | (s[v] & ~m); }
        var ss = H(concat([c1, c2, salt, kbar]), base.ss);
        S.fill(0); sk_.fill(0); kbar.fill(0); mu.fill(0);
        return ss;
    }

    return {
        NAME: name, PK_BYTES: PK_BYTES, SK_BYTES: SK_BYTES, CT_BYTES: CT_BYTES, SS_BYTES: base.ss,
        KEYGEN_RANDOM_BYTES: RAND_KEYGEN, ENCAPS_RANDOM_BYTES: RAND_ENCAPS,
        keygen_derand: keygen_derand,
        keygen: function (rng) { rng = require_rng(name + '.keygen', rng); var r = rng(RAND_KEYGEN); try { return keygen_derand(r); } finally { r.fill(0); } },
        encaps_derand: encaps_derand,
        encaps: function (pk, rng) { rng = require_rng(name + '.encaps', rng); var r = rng(RAND_ENCAPS); try { return encaps_derand(pk, r); } finally { r.fill(0); } },
        /** Never fails: a bad ciphertext gives a pseudorandom secret (implicit rejection). */
        decaps: decaps
    };
}

export var frodokem640_aes = /* @__PURE__ */ build(640, 'aes', false);
export var frodokem640_shake = /* @__PURE__ */ build(640, 'shake', false);
export var frodokem976_aes = /* @__PURE__ */ build(976, 'aes', false);
export var frodokem976_shake = /* @__PURE__ */ build(976, 'shake', false);
export var frodokem1344_aes = /* @__PURE__ */ build(1344, 'aes', false);
export var frodokem1344_shake = /* @__PURE__ */ build(1344, 'shake', false);
export var efrodokem640_aes = /* @__PURE__ */ build(640, 'aes', true);
export var efrodokem640_shake = /* @__PURE__ */ build(640, 'shake', true);
export var efrodokem976_aes = /* @__PURE__ */ build(976, 'aes', true);
export var efrodokem976_shake = /* @__PURE__ */ build(976, 'shake', true);
export var efrodokem1344_aes = /* @__PURE__ */ build(1344, 'aes', true);
export var efrodokem1344_shake = /* @__PURE__ */ build(1344, 'shake', true);
