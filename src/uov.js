/**
 * UOV  -  Unbalanced Oil and Vinegar, the round-3 submission to NIST's
 * additional signatures (August 2026)
 *
 * The oldest multivariate signature still standing (Kipnis, Patarin and
 * Goubin, 1999), and the base that MAYO and SNOVA build on. A public key is
 * m quadratic polynomials in n variables; a signature is a point where all
 * of them take the hash of the message. Finding one is hard in general and
 * easy with the trapdoor: the polynomials vanish on a secret "oil" subspace
 * of dimension m, so fixing the other v = n - m "vinegar" variables leaves a
 * LINEAR system in the oil variables.
 *
 * SIGNATURES ARE TINY AND KEYS ARE NOT: 96 to 275 bytes of signature against
 * 66 KB to 3 MB of public key. That fits a verifier that holds one key and
 * checks many signatures, and little else.
 *
 * THE PARAMETER SETS (n, m, q) and their variants. ip (119, 45, 256),
 * is (160, 64, 16), iii (193, 72, 256), v (259, 96, 256): the round-3 sets,
 * ip, iii and v enlarged from round 2 against the newer attacks. Each comes in
 * three key formats with the same keys underneath and the same signatures:
 *   classic   pk expanded (P1, P2, P3), sk expanded (seed, O, P1, F2)
 *   pkc       pk compressed (pk_seed, P3), sk expanded
 *   pkc_skc   pk compressed, sk = its 32-byte seed
 *
 * HOW IT WORKS. SHAKE256(sk_seed) gives pk_seed and the oil matrix O; AES-128
 * in counter mode under pk_seed gives P1 (upper triangular, v x v) and P2
 * (v x m) for each of the m polynomials, and P3 = Upper(O^T P1 O + O^T P2)
 * completes them. Signing hashes (msg, salt) to the target, derives vinegar
 * values from (msg, salt, sk_seed, counter), and solves the linear system
 * for the oil values; a singular system is retried with the next counter.
 *
 * The arithmetic is commons/gf2k.js and commons/ov_map.js, on the
 * reference's packed layout.
 */

import { shake256 } from './sha3.js';
import { aes_ctr } from './aes.js';
import { concat, secure_random } from './commons/bytes.js';
import { equal } from './commons/ct.js';
import { GF16, GF256 } from './commons/gf2k.js';
import { ov_map } from './commons/ov_map.js';

var SETS = {
    ip:  { q: 256, n: 119, m: 45 },
    is:  { q: 16,  n: 160, m: 64 },
    iii: { q: 256, n: 193, m: 72 },
    v:   { q: 256, n: 259, m: 96 }
};

function tri(k) { return k * (k + 1) / 2; }

function build(set, variant) {
    var S = SETS[set], F = S.q === 16 ? GF16 : GF256;
    var n = S.n, m = S.m, v = n - m;
    var OB = F.len(m), VB = F.len(v), NB = F.len(n);
    var P1_BYTES = OB * tri(v), P2_BYTES = OB * v * m, P3_BYTES = OB * tri(m);
    var O_BYTES = VB * m, SIG_BYTES = NB + 16;
    var EPK = P1_BYTES + P2_BYTES + P3_BYTES, CPK = 16 + P3_BYTES;
    var ESK = 32 + O_BYTES + P1_BYTES + P2_BYTES;
    var PK_BYTES = variant === 'classic' ? EPK : CPK;
    var SK_BYTES = variant === 'pkc_skc' ? 32 : ESK;

    var Q = ov_map(F, v, m, OB);

    /* (pk_seed, O) from sk_seed; (P1, P2) from pk_seed */
    function expand_seed(sk_seed) {
        var b = shake256(sk_seed, 16 + O_BYTES);
        return { pk_seed: b.slice(0, 16), O: b.slice(16) };
    }
    function expand_p(pk_seed) {
        var s = aes_ctr(pk_seed, new Uint8Array(16), new Uint8Array(P1_BYTES + P2_BYTES));
        return { P1: s.subarray(0, P1_BYTES), P2: s.subarray(P1_BYTES) };
    }
    /* UOV stores O column by column: m columns of v packed elements */
    function unpack_o(O) {
        var Ou = new Uint8Array(v * m);
        for (var j = 0; j < m; j++) { for (var k = 0; k < v; k++) { Ou[k * m + j] = F.get(O.subarray(j * VB), k); } }
        return Ou;
    }

    function keypair(sk_seed) {
        var e = expand_seed(sk_seed), p = expand_p(e.pk_seed), r = Q.l_p3(p.P1, p.P2, unpack_o(e.O), true);
        return { sk_seed: sk_seed, pk_seed: e.pk_seed, O: e.O, P1: p.P1, P2: p.P2, P3: r.P3, F2: r.L };
    }

    /* the expanded secret key's parts, from either format */
    function secret(sk) {
        if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES) { throw new Error('uov: the private key is ' + SK_BYTES + ' bytes'); }
        if (variant === 'pkc_skc') {
            var e = expand_seed(sk), p = expand_p(e.pk_seed);
            return { sk_seed: sk, O: e.O, P1: p.P1, F2: Q.l_p3(p.P1, p.P2, unpack_o(e.O), false).L };
        }
        var o = 32;
        return {
            sk_seed: sk.subarray(0, 32), O: sk.subarray(o, o += O_BYTES),
            P1: sk.subarray(o, o += P1_BYTES), F2: sk.subarray(o, o + P2_BYTES)
        };
    }

    var NAME = 'OV(' + S.q + ',' + n + ',' + m + ')-' + variant.replace('_', '-');

    return {
        NAME: NAME,
        PK_BYTES: PK_BYTES,
        SK_BYTES: SK_BYTES,
        SIG_BYTES: SIG_BYTES,

        /** @param {Uint8Array} [seed]  the 32-byte sk_seed; omitted or null draws fresh ones from the platform */
        keygen: function (seed) {
            if (seed == null) { seed = secure_random(32); }
            if (!(seed instanceof Uint8Array) || seed.length !== 32) { throw new Error('uov: the seed is 32 bytes'); }
            var k = keypair(seed.slice());
            var pk = variant === 'classic' ? concat([k.P1, k.P2, k.P3]) : concat([k.pk_seed, k.P3]);
            var sk = variant === 'pkc_skc' ? k.sk_seed : concat([k.sk_seed, k.O, k.P1, k.F2]);
            return { pk: pk, sk: sk };
        },

        /** @param {Uint8Array} [salt]  16 random bytes; omitted or null draws fresh ones from the platform */
        sign: function (sk, msg, salt) {
            if (salt == null) { salt = secure_random(16); }
            if (!(salt instanceof Uint8Array) || salt.length !== 16) { throw new Error('uov: the salt is 16 bytes'); }
            var K = secret(sk);
            var y = shake256(concat([msg, salt]), OB);
            for (var ctr = 0; ctr < 256; ctr++) {
                var vin = shake256(concat([msg, salt, K.sk_seed, new Uint8Array([ctr])]), VB);
                /* the linear system: column j is sum_i vin_i F2(i, j), the right side y - P1(vin) */
                var L = Q.x_mat(K.F2, 0, vin, v, m), r = Q.dot(y.slice(), Q.x_ut(K.P1, 0, vin, v), vin, v);
                var x = F.solve(L, r, m);
                if (x === null) { continue; }
                /* w = (vin + O x, x) */
                var w = new Uint8Array(NB), wv = vin.slice();
                for (var c = 0; c < m; c++) { F.madd(wv, 0, K.O, c * VB, F.get(x, c), VB); }
                for (var e = 0; e < v; e++) { F.set(w, e, F.get(wv, e)); }
                for (var f = 0; f < m; f++) { F.set(w, v + f, F.get(x, f)); }
                return concat([w, salt]);
            }
            throw new Error('uov: no solvable system in 256 attempts');
        },

        verify: function (pk, msg, sig) {
            if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { return false; }
            if (!(sig instanceof Uint8Array) || sig.length !== SIG_BYTES) { return false; }
            var P1, P2, P3;
            if (variant === 'classic') {
                P1 = pk.subarray(0, P1_BYTES); P2 = pk.subarray(P1_BYTES, P1_BYTES + P2_BYTES); P3 = pk.subarray(P1_BYTES + P2_BYTES);
            } else {
                var p = expand_p(pk.subarray(0, 16));
                P1 = p.P1; P2 = p.P2; P3 = pk.subarray(16);
            }
            var w = sig.subarray(0, NB), z = Q.dot(new Uint8Array(OB), Q.s_p(P1, P2, P3, w), w, n);
            return equal(z, shake256(concat([msg, sig.subarray(NB)]), OB)) === 1;
        }
    };
}

export var uov_ip = /* @__PURE__ */ build('ip', 'classic');
export var uov_ip_pkc = /* @__PURE__ */ build('ip', 'pkc');
export var uov_ip_pkc_skc = /* @__PURE__ */ build('ip', 'pkc_skc');
export var uov_is = /* @__PURE__ */ build('is', 'classic');
export var uov_is_pkc = /* @__PURE__ */ build('is', 'pkc');
export var uov_is_pkc_skc = /* @__PURE__ */ build('is', 'pkc_skc');
export var uov_iii = /* @__PURE__ */ build('iii', 'classic');
export var uov_iii_pkc = /* @__PURE__ */ build('iii', 'pkc');
export var uov_iii_pkc_skc = /* @__PURE__ */ build('iii', 'pkc_skc');
export var uov_v = /* @__PURE__ */ build('v', 'classic');
export var uov_v_pkc = /* @__PURE__ */ build('v', 'pkc');
export var uov_v_pkc_skc = /* @__PURE__ */ build('v', 'pkc_skc');
