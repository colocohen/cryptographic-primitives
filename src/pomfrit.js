/**
 * PoMFRIT  -  post-quantum blind signatures from the MAYO trapdoor and
 * VOLE-in-the-head (Baum, Beckmann, Beullens, Mukherjee, Rechberger, USENIX
 * Security 2026; ePrint 2026/109), the One-More-MAYO construction
 *
 * A BLIND SIGNATURE: the signer signs a message it never sees, and cannot
 * later link the signature to the session that produced it; still, each
 * session yields at most one valid signature.
 *
 *   user    request(pk, msg)  -> t       starts a VOLE-in-the-head proof, whose
 *                                        commitment fixes a random r in F16^m;
 *                                        t = H(msg, commitment) + r
 *   signer  issue(sk, t)      -> s       a MAYO preimage: P*(s) = t
 *   user    finish(state, s)  -> sig     completes the proof: "I know s and the
 *                                        committed r with P*(s) = H(msg, .) + r"
 *   anyone  verify(pk, msg, sig)
 *
 * The signer sees only t, which r makes uniform; the signature reveals
 * neither r nor s. Forging one more signature than the signer issued means
 * finding a preimage of a fresh random-oracle target: the "one-more
 * preimage resistance" of the MAYO trapdoor (the paper's Definition 3.1),
 * a strengthening of the assumption MAYO itself rests on.
 *
 * WHAT IS PROVEN, AND HOW. The witness is r (4m bits, taken from the VOLE's
 * random string without a correction - the first stage of the proof commits
 * to it before the message is signed) and s (4kn bits). F16 sits inside
 * GF(2^lambda) through a root beta of MAYO's x^4 + x + 1. The m equations
 * P*(s) + r + h = 0 are folded into one by random weights ell drawn after the
 * witness commitment (chall2), as the paper does; with E_ij the whipping
 * matrices the folded constraint is
 *
 *     sum_{i <= j} s_i^T M_ij s_j  +  <ell, r>  +  <ell, h>,
 *     M_ij = sum_e (E_ij^T ell)_e P_e
 *
 * one quadratic constraint, evaluated in bulk on the VOLE tags.
 *
 * THE SHAKE256+MAYO CONSTRUCTION (the paper's conservative one,
 * pomfrit_shake_*) rests on MAYO's plain assumption and SHAKE256 alone:
 *
 *   user    com = SHAKE256(SHAKE256(msg) || r)   (r random, lambda bits)
 *           t   = SHAKE256(com, m/2 bytes)       the request; it hides msg
 *   signer  s with P*(s) = t
 *   user    proves "I know r, s with P*(s) = SHAKE256(SHAKE256(SHAKE256(msg)
 *           || r))", binding the context, not t: the signature shows neither
 *
 * Both SHAKE256 calls on secret input are one Keccak-f[1600] each; the
 * witness holds the state after every round (commons/keccak_circuit.js), so
 * each round is 1600 quadratic constraints, and the MAYO equations fold as
 * above over the last state's leading bytes. pomfrit_shake_d16_* commits
 * only every sixth state and proves each six rounds as four forward and two
 * back (chi's inverse is cubic) at degree 16: the same statement in under
 * a third of the size, for a slower proof.
 *
 * PARAMETERS: levels 1, 3 and 5 pair MAYO_1 / MAYO_3 / MAYO_5 (round 3) with
 * the VOLE trees of FAEST-128 / 192 / 256 v3, "s" (short) or "f" (fast). The
 * paper's implementation is MAYO round 2 inside FAEST round 2's framework;
 * this one follows its construction on the round-3 schemes of this library,
 * so the bytes are this library's own.
 */

import { voleith } from './commons/voleith.js';
import { keccak_round_states, keccak_block_constraints } from './commons/keccak_circuit.js';
import { mayo1, mayo3, mayo5 } from './mayo.js';
import { shake256 } from './sha3.js';
import { GF16 } from './commons/gf2k.js';
import { concat, ascii } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';
import { lazy_scheme } from './commons/lazy_scheme.js';

/* level -> [MAYO, lambda, (tau, w, T_open) short, (tau, w, T_open) fast] - FAEST v3's trees */
var SETS = {
    '128s': [mayo1, 128, 11, 7, 102], '128f': [mayo1, 128, 17, 8, 108],
    '192s': [mayo3, 192, 16, 12, 162], '192f': [mayo3, 192, 24, 8, 163],
    '256s': [mayo5, 256, 22, 6, 225], '256f': [mayo5, 256, 33, 8, 229]
};
var LABEL = /* @__PURE__ */ ascii('PoMFRIT One-More-MAYO v1');
var LABEL_SHAKE = /* @__PURE__ */ ascii('PoMFRIT SHAKE256+MAYO v1');
var LABEL_SHAKE16 = /* @__PURE__ */ ascii('PoMFRIT SHAKE256+MAYO deg-16 v1');
var DOM_CTX = 20, DOM_H = 21, DOM_MU = 22, DOM_IV = 23, DOM_MIX = 24;

function build(name) {
    var P = SETS[name], MY = P[0], TD = MY.trapdoor, lambda = P[1];
    var m = TD.M, n = TD.N, k = TD.K, OB = m / 2, SB = TD.S_BYTES;
    var FREE = 4 * m, ELL = 4 * m + 4 * k * n;
    var E = voleith({ lambda: lambda, tau: P[2], w: P[3], T_open: P[4], ell: ELL, D: 2, em: false });
    var F = E.F, W = E.W, lb = lambda / 8;
    var SIG = E.proof_bytes(FREE);
    var G = beta_powers(F, W);

    function ctx_of(pk, msg) { return E.hsh([LABEL, pk, msg], DOM_CTX, 2 * lb); }
    function iv_of(iv_pre, ctx) { return E.hsh([iv_pre, ctx], DOM_IV, 16); }
    /* h = H(msg, pi_1): the target's public half, m GF(16) elements packed */
    function h_of(ctx, vc_h, c, c_mult, iv_pre) { return E.hsh([ctx, vc_h, c, c_mult, iv_pre], DOM_H, OB); }
    function mu_of(ctx, h) { return E.hsh([ctx, h], DOM_MU, 2 * lb); }

    function constraints(pm, h) {
        return function (Rg, emit, chall2) { emit(fold(F, W, G, pm, h, Rg.raw, E.hsh([chall2, LABEL], DOM_MIX, m * lb), 0, FREE), 2); };
    }

    var API = {
        NAME: 'PoMFRIT-' + name.toUpperCase(),
        PK_BYTES: MY.PK_BYTES, SK_BYTES: MY.SK_BYTES, SIG_BYTES: SIG,
        REQUEST_BYTES: OB, RESPONSE_BYTES: SB, RND_BYTES: MY.SK_BYTES,

        /** The signer's key pair: a MAYO key. seed omitted or null draws a fresh one from the platform. */
        keygen: function (seed) { return MY.keygen(seed); },

        /**
         * Sig1, the user. Draws the VOLE root (lambda/8 bytes) and the IV
         * (16 bytes). @return {{state, request}} - send request, keep state.
         */
        request: function (pk, msg, rng) {
            rng = require_rng('pomfrit.request', rng);
            if (!(pk instanceof Uint8Array) || pk.length !== MY.PK_BYTES) { throw new Error('pomfrit: the public key is ' + MY.PK_BYTES + ' bytes'); }
            var root = rng(lb), iv_pre = rng(16), ctx = ctx_of(pk, msg);
            var V = E.commit(root, iv_of(iv_pre, ctx));
            var h = h_of(ctx, V.vc.h, V.c, V.c_mult, iv_pre), t = new Uint8Array(OB);
            for (var q = 0; q < OB; q++) { t[q] = h[q] ^ V.u[q]; }
            return { state: { pk: pk, ctx: ctx, V: V, iv_pre: iv_pre, h: h, t: t }, request: t };
        },

        /**
         * Sig2, the signer: a preimage of the request under the trapdoor.
         * rnd (RND_BYTES) randomizes it; omitted or null draws fresh ones
         * from the platform. @return {Uint8Array} the response
         */
        issue: function (sk, request, rnd) {
            if (!(request instanceof Uint8Array) || request.length !== OB) { throw new Error('pomfrit: a request is ' + OB + ' bytes'); }
            var t = new Uint8Array(m);
            for (var e = 0; e < m; e++) { t[e] = GF16.get(request, e); }
            return TD.sample(sk, t, rnd);
        },

        /** Sig3, the user. THROWS when the response is not a preimage of the request. @return {Uint8Array} the signature */
        finish: function (st, response) {
            if (!(response instanceof Uint8Array) || response.length !== SB) { throw new Error('pomfrit: a response is ' + SB + ' bytes'); }
            var y = TD.evaluate(st.pk, response);
            for (var e = 0; e < m; e++) {
                if (y[e] !== GF16.get(st.t, e)) { throw new Error('pomfrit: the response is not a preimage of the request'); }
            }
            var wit = concat([st.V.u.subarray(0, OB), response]);
            return E.prove(st.V, mu_of(st.ctx, st.h), st.iv_pre, wit, FREE, constraints(TD.public_map(st.pk), st.h));
        },

        verify: function (pk, msg, sig) {
            if (!(pk instanceof Uint8Array) || pk.length !== MY.PK_BYTES) { return false; }
            var p = E.parse(sig, FREE);
            if (!p) { return false; }
            var ctx = ctx_of(pk, msg), h = null, pm = TD.public_map(pk);
            return E.verify(sig, function (vc_h) { h = h_of(ctx, vc_h, p.c, p.c_mult, p.iv_pre); return mu_of(ctx, h); },
                            function (iv_pre) { return iv_of(iv_pre, ctx); }, FREE,
                            function (Rg, emit, chall2) { constraints(pm, h)(Rg, emit, chall2); });
        }
    };
    return API;
}

/* ---------------- the conservative construction: SHAKE256 inside the proof ---------------- */

/*
 * Fischlin's construction as the paper's Algorithm 1 has it. The user commits
 * com = SHAKE256(SHAKE256(msg) || r) with a random r; the signer returns a
 * MAYO preimage of t = SHAKE256(com) (the bare trapdoor - the salt and the
 * round-3 linear terms are left out, as the paper leaves out the salt); the
 * signature proves knowledge of r and s with P*(s) = SHAKE256(SHAKE256(
 * SHAKE256(msg) || r)). Both Keccak-f evaluations are in the witness round
 * by round (the paper's degree-2 circuit), so the signature is far larger,
 * and the security rests on MAYO's EUF-CMA and the hash alone - no one-more
 * assumption.
 */
var RATE = 136;
/*
 * split = [nf, nb]: each block of nf + nb Keccak rounds is proven nf forward
 * from one committed state and nb back from the next (commons/
 * keccak_circuit.js) - [1, 0], every state at degree 2, or [4, 2], every
 * sixth at degree 16 and about a quarter of the size.
 */
function build_shake(name, split) {
    var P = SETS[name], MY = P[0], TD = MY.trapdoor, lambda = P[1], lb = lambda / 8;
    var m = TD.M, n = TD.N, k = TD.K, OB = m / 2, SB = TD.S_BYTES, DIG = { 128: 32, 192: 48, 256: 64 }[lambda];
    var NF = split[0], NB = split[1], RB = NF + NB, NS = 24 / RB, DEG = Math.max(1 << NF, Math.pow(3, NB));
    var LBL = RB === 1 ? LABEL_SHAKE : LABEL_SHAKE16, SUFFIX = RB === 1 ? '' : '-D' + DEG;
    var K1 = lambda, K2 = K1 + NS * 1600, S0 = K2 + NS * 1600, ELL = S0 + 4 * k * n, LAST = (NS - 1) * 1600;
    var E = voleith({ lambda: lambda, tau: P[2], w: P[3], T_open: P[4], ell: ELL, D: DEG, em: false });
    var F = E.F, W = E.W, G = beta_powers(F, W), SIG = E.proof_bytes(0);

    function ctx_of(pk, msg) { return E.hsh([LBL, pk, msg], DOM_CTX, 2 * lb); }
    function iv_of(iv_pre, ctx) { return E.hsh([iv_pre, ctx], DOM_IV, 16); }
    function first_block(prefix) {
        var st = new Uint8Array(200);
        st.set(prefix); st[prefix.length] ^= 0x1f; st[RATE - 1] ^= 0x80;
        return st;
    }
    function target(com) {
        var tb = shake256(com, OB), t = new Uint8Array(m);
        for (var e = 0; e < m; e++) { t[e] = GF16.get(tb, e); }
        return t;
    }

    /* the statement: Keccak-f twice, block by block, then the folded MAYO equation on K2's output */
    function constraints(pm, hmu) {
        return function (Rg, emit, chall2) {
            var one = Rg.cbit(1), zero = Rg.cbit(0), consts = [zero, one];
            /* K1's input: SHAKE256(msg) || r || padding */
            var in1 = first_block(new Uint8Array(2 * lb));
            in1.set(hmu);
            function k1in(i) {
                var by = i >> 3;
                if (by >= lb && by < 2 * lb) { return Rg.bit(i - 8 * lb); }
                return consts[(in1[by] >> (i & 7)) & 1];
            }
            var pad2 = first_block(new Uint8Array(DIG));
            function k2in(i) {
                var by = i >> 3;
                if (by < DIG) { return Rg.bit(K1 + LAST + i); }
                return consts[(pad2[by] >> (i & 7)) & 1];
            }
            function perm(base, input) {
                for (var b = 0; b < NS; b++) {
                    keccak_block_constraints(Rg, emit, b === 0 ? input : function (i) { return Rg.bit(base + (b - 1) * 1600 + i); },
                                             function (i) { return Rg.bit(base + b * 1600 + i); }, b * RB, NF, NB);
                }
            }
            perm(K1, k1in);
            perm(K2, k2in);
            emit(fold(F, W, G, pm, null, Rg.raw, E.hsh([chall2, LBL], DOM_MIX, m * lb), K2 + LAST, S0), 2);
        };
    }

    return {
        NAME: 'PoMFRIT-SHAKE256' + SUFFIX + '-' + name.toUpperCase(),
        PK_BYTES: MY.PK_BYTES, SK_BYTES: MY.SK_BYTES, SIG_BYTES: SIG,
        REQUEST_BYTES: DIG, RESPONSE_BYTES: SB, RND_BYTES: MY.SK_BYTES,

        /** seed omitted or null draws a fresh one from the platform */
        keygen: function (seed) { return MY.keygen(seed); },

        /** Sig1. Draws r (lambda/8 bytes), then the proof's root (lambda/8) and IV (16). @return {{state, request}} */
        request: function (pk, msg, rng) {
            rng = require_rng('pomfrit.request', rng);
            if (!(pk instanceof Uint8Array) || pk.length !== MY.PK_BYTES) { throw new Error('pomfrit: the public key is ' + MY.PK_BYTES + ' bytes'); }
            var hmu = shake256(msg, lb), r = rng(lb), com = shake256(concat([hmu, r]), DIG);
            return { state: { pk: pk, ctx: ctx_of(pk, msg), hmu: hmu, r: r, com: com, root: rng(lb), iv_pre: rng(16) }, request: com };
        },

        /** Sig2: a preimage of SHAKE256(request); rnd (RND_BYTES) omitted or null draws fresh ones from the platform. */
        issue: function (sk, request, rnd) {
            if (!(request instanceof Uint8Array) || request.length !== DIG) { throw new Error('pomfrit: a request is ' + DIG + ' bytes'); }
            return TD.sample(sk, target(request), rnd);
        },

        /** Sig3. THROWS when the response is not a preimage. */
        finish: function (st, response) {
            if (!(response instanceof Uint8Array) || response.length !== SB) { throw new Error('pomfrit: a response is ' + SB + ' bytes'); }
            var t = target(st.com), y = TD.evaluate(st.pk, response);
            for (var e = 0; e < m; e++) { if (y[e] !== t[e]) { throw new Error('pomfrit: the response is not a preimage of the request'); } }
            var s1 = keccak_round_states(first_block(concat([st.hmu, st.r])));
            var s2 = keccak_round_states(first_block(s1[23].subarray(0, DIG)));
            function committed(q, i) { return i % RB === RB - 1; }
            var wit = concat([st.r].concat(s1.filter(committed), s2.filter(committed), [response]));
            var V = E.commit(st.root, iv_of(st.iv_pre, st.ctx));
            return E.prove(V, st.ctx, st.iv_pre, wit, 0, constraints(TD.public_map(st.pk), st.hmu));
        },

        verify: function (pk, msg, sig) {
            if (!(pk instanceof Uint8Array) || pk.length !== MY.PK_BYTES) { return false; }
            var ctx = ctx_of(pk, msg);
            return E.verify(sig, ctx, function (iv_pre) { return iv_of(iv_pre, ctx); }, 0, constraints(TD.public_map(pk), shake256(msg, lb)));
        }
    };
}

/* ---------------- GF(16) inside GF(2^lambda) ---------------- */

/*
 * beta, a root of x^4 + x + 1 (MAYO's GF(16)) in GF(2^lambda), and EMB[x] =
 * the image of each GF(16) element. GF(16)* is the subgroup of order 15, so
 * g^((2^lambda - 1) / 15) for a g of full order is a primitive 15th root of
 * unity; one of its powers coprime to 15 is a root of x^4 + x + 1.
 */
function beta_powers(F, W) {
    var N = (BigInt(1) << BigInt(F.BITS)) - BigInt(1), g = new Uint32Array(W), z = new Uint32Array(W), t = new Uint32Array(W);
    function is_one(y) { var d = y[0] ^ 1; for (var u = 1; u < W; u++) { d |= y[u]; } return d === 0; }
    for (var cand = 2; cand < 64; cand++) {
        g.fill(0); g[0] = cand;
        F.pow(z, 0, g, 0, N / BigInt(15));
        F.pow(t, 0, z, 0, 5);
        if (is_one(t)) { continue; }
        F.pow(t, 0, z, 0, 3);
        if (is_one(t)) { continue; }
        /* z has order 15; find the power of it that is a root of x^4 + x + 1 */
        for (var j = 1; j < 15; j++) {
            if (j % 3 === 0 || j % 5 === 0) { continue; }
            var b = new Uint32Array(W), b4 = new Uint32Array(W);
            F.pow(b, 0, z, 0, j); F.pow(b4, 0, b, 0, 4);
            F.add(b4, 0, b4, 0, b, 0);
            if (is_one(b4)) {
                var EMB = new Uint32Array(16 * W), pw = new Uint32Array(4 * W);
                pw[0] = 1; F.copy(pw, W, b, 0); F.mul(pw, 2 * W, b, 0, b, 0); F.mul(pw, 3 * W, pw, 2 * W, b, 0);
                for (var x = 1; x < 16; x++) {
                    var low = x & -x, q = 31 - Math.clz32(low);
                    F.add(EMB, x * W, EMB, (x ^ low) * W, pw, q * W);
                }
                return { EMB: EMB, BETA: pw };
            }
        }
    }
    throw new Error('pomfrit: no embedding of GF(16) found');
}

/* ---------------- the folded constraint, in bulk ---------------- */

/*
 * The one quadratic constraint P*(s) + t + h = 0, folded by the weights in
 * mixbytes, evaluated on the prover's tags (its two low coefficients; the
 * top one vanishes for a true witness) or on the verifier's keys (its value
 * at Delta). The committed target t is the m nibbles at witness bit TB, s
 * the k*n nibbles at SBASE; h is public, or null.
 */
function fold(F, W, G, pm, h, R, mixbytes, TB, SBASE) {
    var m = pm.m, n = pm.n, k = pm.k, v = pm.v, o = pm.o, OB = pm.OB, Z = pm.Z, f = pm.f;
    var NT = n * (n + 1) / 2, i, j, a, b, e, q, x;
    var tmp = new Uint32Array(W), acc0 = new Uint32Array(W), acc1 = new Uint32Array(W);

    function xor(d, dofs, s, sofs) { for (var t = 0; t < W; t++) { d[dofs + t] ^= s[sofs + t]; } }
    /* the GF(2^lambda) image of a committed nibble: tags (or keys) of its four bits times beta^q */
    function elem(base, src, out, oofs) {
        for (var t = 0; t < W; t++) { out[oofs + t] = src[base * W + t]; }
        for (var qq = 1; qq < 4; qq++) { F.mul(tmp, 0, src, (base + qq) * W, G.BETA, qq * W); xor(out, oofs, tmp, 0); }
    }
    function nib(base) {
        var y = 0;
        for (var qq = 0; qq < 4; qq++) { y |= ((R.wbits[(base + qq) >> 3] >> ((base + qq) & 7)) & 1) << qq; }
        return y;
    }

    /* the weights ell, and E^T-powers of them: lam[z] = (Z^T)^z ell */
    var ell = F.from_bytes(mixbytes, 0, m), maxz = 0;
    for (i = 0; i < k; i++) { for (j = 0; j < k; j++) { maxz = Math.max(maxz, Z[i][j]); } }
    var lam = [ell];
    for (var zz = 1; zz <= maxz; zz++) {
        var prev = lam[zz - 1], nx = new Uint32Array(m * W);
        nx.set(prev.subarray(W));
        for (q = 0; q < 4; q++) {
            if (f[q]) { F.mul(tmp, 0, prev, q * W, G.EMB, f[q] * W); xor(nx, (m - 1) * W, tmp, 0); }
        }
        lam.push(nx);
    }

    /* the committed values: r_e and s_{i,a} as GF(2^lambda) images (tags or keys), and the s nibbles for the prover */
    var src = R.prover ? R.tags : R.keys;
    var RT = new Uint32Array(m * W), ST = new Uint32Array(k * n * W);
    for (e = 0; e < m; e++) { elem(TB + 4 * e, src, RT, e * W); }
    for (i = 0; i < k * n; i++) { elem(SBASE + 4 * i, src, ST, i * W); }

    /* the coefficient batch of position (a, b), a <= b: [array, offset] */
    function batch(aa, bb) {
        if (bb < v) { return [pm.P1, pm.ut(aa, bb, v)]; }
        if (aa < v) { return [pm.P2, (aa * o + (bb - v)) * OB]; }
        return [pm.P3, pm.ut(aa - v, bb - v, o)];
    }
    var BA = [], BO = new Int32Array(NT);
    for (a = 0, x = 0; a < n; a++) { for (b = a; b < n; b++, x++) { var bt = batch(a, b); BA.push(bt[0]); BO[x] = bt[1]; } }
    function tri(aa, bb) { return aa <= bb ? aa * n - (aa * (aa - 1) >> 1) + (bb - aa) : bb * n - (bb * (bb - 1) >> 1) + (aa - bb); }

    /* the prover's (P + P^T) sigma_i, n batches each - the F16 half of the cross terms */
    var PS = [];
    if (R.prover) {
        var sig = [];
        for (i = 0; i < k; i++) { var sv = new Uint8Array(n); for (a = 0; a < n; a++) { sv[a] = nib(SBASE + 4 * (i * n + a)); } sig.push(sv); }
        for (i = 0; i < k; i++) {
            var ps = new Uint8Array(n * OB);
            for (a = 0, x = 0; a < n; a++) {
                for (b = a; b < n; b++, x++) {
                    if (a === b) { continue; }
                    GF16.madd(ps, a * OB, BA[x], BO[x], sig[i][b], OB);
                    GF16.madd(ps, b * OB, BA[x], BO[x], sig[i][a], OB);
                }
            }
            PS.push(ps);
        }
    }

    /* <lambda, batch> through byte tables: TQ[q][byte] = EMB(lo) lambda_2q + EMB(hi) lambda_2q+1 */
    var TQ = new Uint32Array(OB * 256 * W), A = new Uint32Array(16 * W), Bt = new Uint32Array(16 * W), basis = new Uint32Array(4 * W);
    function tables(lv) {
        for (q = 0; q < OB; q++) {
            for (var half = 0; half < 2; half++) {
                var T16 = half ? Bt : A, le = 2 * q + half;
                for (var bb = 0; bb < 4; bb++) { F.mul(basis, bb * W, lv, le * W, G.BETA, bb * W); }
                for (var y = 1; y < 16; y++) {
                    var low = y & -y, bq = 31 - Math.clz32(low);
                    for (var t = 0; t < W; t++) { T16[y * W + t] = T16[(y ^ low) * W + t] ^ basis[bq * W + t]; }
                }
            }
            var base = q * 256 * W;
            for (var by = 0; by < 256; by++) {
                var lo = (by & 15) * W, hi = (by >> 4) * W, d = base + by * W;
                for (var t2 = 0; t2 < W; t2++) { TQ[d + t2] = A[lo + t2] ^ Bt[hi + t2]; }
            }
        }
    }
    function inner(out, oofs, arr, off) {
        for (var t = 0; t < W; t++) { out[oofs + t] = 0; }
        for (var qq = 0; qq < OB; qq++) { xor(out, oofs, TQ, (qq * 256 + arr[off + qq]) * W); }
    }

    var M = new Uint32Array(NT * W), w0 = new Uint32Array(W), w1 = new Uint32Array(W);
    for (i = 0; i < k; i++) {
        for (j = i; j < k; j++) {
            tables(lam[Z[i][j]]);
            for (x = 0; x < NT; x++) { inner(M, x * W, BA[x], BO[x]); }
            for (a = 0; a < n; a++) {
                w0.fill(0);
                if (i === j) {
                    /* the upper triangle: sum_{b >= a} M_ab y_b */
                    for (b = a; b < n; b++) { F.mul(tmp, 0, M, tri(a, b) * W, ST, (j * n + b) * W); xor(w0, 0, tmp, 0); }
                } else {
                    /* M + M^T, zero diagonal */
                    for (b = 0; b < n; b++) { if (b !== a) { F.mul(tmp, 0, M, tri(a, b) * W, ST, (j * n + b) * W); xor(w0, 0, tmp, 0); } }
                }
                F.mul(tmp, 0, ST, (i * n + a) * W, w0, 0); xor(acc0, 0, tmp, 0);
                if (R.prover) {
                    /* the cross coefficient: tau_i,a (Msym sigma_j)_a, and sigma_i,a w0_a when i < j */
                    inner(w1, 0, PS[j], a * OB);
                    F.mul(tmp, 0, ST, (i * n + a) * W, w1, 0); xor(acc1, 0, tmp, 0);
                    if (i !== j) { F.mul(tmp, 0, w0, 0, G.EMB, sig[i][a] * W); xor(acc1, 0, tmp, 0); }
                }
            }
        }
    }

    /* the committed r, at degree 1 (prover) or times Delta (verifier), and the public h at degree 2 */
    var lr = new Uint32Array(W), lh = new Uint32Array(W);
    for (e = 0; e < m; e++) {
        F.mul(tmp, 0, ell, e * W, RT, e * W); xor(lr, 0, tmp, 0);
        var he = h ? GF16.get(h, e) : 0;
        if (he) { F.mul(tmp, 0, ell, e * W, G.EMB, he * W); xor(lh, 0, tmp, 0); }
    }
    if (R.prover) {
        xor(acc1, 0, lr, 0);
        var c = new Uint32Array(3 * W);
        c.set(acc0, 0); c.set(acc1, W);
        return R.value(2, c);
    }
    F.mul(tmp, 0, lr, 0, R.dpow, W); xor(acc0, 0, tmp, 0);
    F.mul(tmp, 0, lh, 0, R.dpow, 2 * W); xor(acc0, 0, tmp, 0);
    return R.value(0, acc0);
}

function lazy(name, split) {
    return lazy_scheme(function () { return split ? build_shake(name, split) : build(name); },
        ['NAME', 'PK_BYTES', 'SK_BYTES', 'SIG_BYTES', 'REQUEST_BYTES', 'RESPONSE_BYTES', 'RND_BYTES'],
        ['keygen', 'request', 'issue', 'finish', 'verify']);
}

export var pomfrit_128s = /* @__PURE__ */ lazy('128s');
export var pomfrit_128f = /* @__PURE__ */ lazy('128f');
export var pomfrit_192s = /* @__PURE__ */ lazy('192s');
export var pomfrit_192f = /* @__PURE__ */ lazy('192f');
export var pomfrit_256s = /* @__PURE__ */ lazy('256s');
export var pomfrit_256f = /* @__PURE__ */ lazy('256f');
export var pomfrit_shake_128s = /* @__PURE__ */ lazy('128s', [1, 0]);
export var pomfrit_shake_128f = /* @__PURE__ */ lazy('128f', [1, 0]);
export var pomfrit_shake_192s = /* @__PURE__ */ lazy('192s', [1, 0]);
export var pomfrit_shake_192f = /* @__PURE__ */ lazy('192f', [1, 0]);
export var pomfrit_shake_256s = /* @__PURE__ */ lazy('256s', [1, 0]);
export var pomfrit_shake_256f = /* @__PURE__ */ lazy('256f', [1, 0]);
export var pomfrit_shake_d16_128s = /* @__PURE__ */ lazy('128s', [4, 2]);
export var pomfrit_shake_d16_128f = /* @__PURE__ */ lazy('128f', [4, 2]);
export var pomfrit_shake_d16_192s = /* @__PURE__ */ lazy('192s', [4, 2]);
export var pomfrit_shake_d16_192f = /* @__PURE__ */ lazy('192f', [4, 2]);
export var pomfrit_shake_d16_256s = /* @__PURE__ */ lazy('256s', [4, 2]);
export var pomfrit_shake_d16_256f = /* @__PURE__ */ lazy('256f', [4, 2]);
