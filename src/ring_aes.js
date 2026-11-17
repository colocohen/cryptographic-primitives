/**
 * Post-quantum ring, linkable ring and threshold ring signatures from AES and
 * VOLE-in-the-head (Chiang, Damgård, Duro, Engan, Kolby, Scholl, ePrint
 * 2025/113)
 *
 * A RING SIGNATURE says "one of these n keys signed", and not which. Here
 * the keys are FAEST's - pk = (x, AES_k(x)) - and a signature is a
 * VOLE-in-the-head proof (commons/voleith.js, FAEST's proof system) of
 *
 *     I know k and an index i with AES_k(x_i) = y_i
 *
 * The prover commits to i as one-hot vectors (commons/voleith.js
 * one_hot_select, the paper's section 4.1) and to the selected (x_i, y_i),
 * and proves the AES encryption of commons/aes_circuit.js between them: the
 * statement costs one AES and a selection linear in the ring, and the
 * signature grows only with the few one-hot bits.
 *
 *   ring_aes_*.sign(sk, ring, msg, rnd)    sk a FAEST secret key, ring an array
 *                                          of FAEST public keys containing its own
 *   ring_aes_*.verify(ring, msg, sig)
 *
 * LINKABLE AND THRESHOLD (section 5). Keys whose function binds the key:
 * pk = P(k) = AES_k(<1>) || ... || AES_k(<n>) with n = 2, 3, 4 blocks at
 * levels 1, 3, 5 (<i> the block 0...0 || i), and a deterministic tag
 *
 *     tau = T(k, scope) = CBC-MAC_f(k, H(scope)),  f_k(x) = trunc_127(AES_k(1 || x))
 *
 * over n blocks of 127 bits (bit 0 of a block is the "1 ||"; P's inputs have
 * it 0, so the two never share an AES input). The proof covers P and the
 * CBC chain too, so the tag is the signer's own: two signatures by one key
 * in one scope carry the same tag, and nothing else links them. The scope
 * defaults to (ring, message) - the threshold setting - and may be any bytes
 * (a poll, an epoch) to link across messages.
 *
 *   lrs_aes_*.keygen(k), sign(sk, ring, msg, rnd, scope?), verify(ring, msg, sig, scope?),
 *   tag(sig), linked(sig1, sig2)
 *   lrs_aes_*.combine(sigs), verify_threshold(ring, msg, sig, t)
 *       t signatures on (ring, msg) with t different tags: t different signers
 *
 * PARAMETERS: FAEST v3's VOLE trees ("s" short, "f" fast); the one-hot shape
 * is chosen for the fewest bits (degree at most 6, inside FAEST's 7). The
 * AES circuit is FAEST v3's, two rounds per committed state, so the
 * witness is smaller than the paper's (which commits every round).
 */

import { voleith, one_hot_shape, one_hot_witness, one_hot_select } from './commons/voleith.js';
import { aes_circuit } from './commons/aes_circuit.js';
import { binary_field } from './commons/binfield.js';
import { faest_128s, faest_128f, faest_192s, faest_192f, faest_256s, faest_256f } from './faest.js';
import { shake256 } from './sha3.js';
import { concat, ascii, be32, secure_random } from './commons/bytes.js';
import { lazy_scheme } from './commons/lazy_scheme.js';

/* level -> [lambda, tau, w, T_open] - FAEST v3's trees */
var TREES = {
    '128s': [128, 11, 7, 102], '128f': [128, 17, 8, 108],
    '192s': [192, 16, 12, 162], '192f': [192, 24, 8, 163],
    '256s': [256, 22, 6, 225], '256f': [256, 33, 8, 229]
};
var FAEST = { '128s': faest_128s, '128f': faest_128f, '192s': faest_192s, '192f': faest_192f, '256s': faest_256s, '256f': faest_256f };
var MAX_DIM = 6, D = 7, DOM_MU = 40, DOM_ROOT = 41, DOM_IV = 42, DOM_TAG = 43;
var LABEL_RING = /* @__PURE__ */ ascii('cryptographic-primitives ring_aes v1');
var LABEL_LINK = /* @__PURE__ */ ascii('cryptographic-primitives lrs_aes v1');

function pad8(n) { return (n + 7) & ~7; }
function set_bits(dst, off, src01) { for (var i = 0; i < src01.length; i++) { if (src01[i]) { dst[(off + i) >> 3] |= 1 << ((off + i) & 7); } } }
function put(dst, off, bytes) { for (var i = 0; i < bytes.length * 8; i++) { if ((bytes[i >> 3] >> (i & 7)) & 1) { dst[(off + i) >> 3] |= 1 << ((off + i) & 7); } } }

/* the proof system for each witness length, built once */
function systems(T) {
    var cache = {};
    return function (ell) {
        if (!cache[ell]) { cache[ell] = voleith({ lambda: T[0], tau: T[1], w: T[2], T_open: T[3], ell: ell, D: D, em: false }); }
        return cache[ell];
    };
}

function check_ring(ring, len) {
    if (!Array.isArray(ring) || ring.length < 2) { throw new Error('ring_aes: a ring is an array of at least two public keys'); }
    for (var i = 0; i < ring.length; i++) {
        if (!(ring[i] instanceof Uint8Array) || ring[i].length !== len) { throw new Error('ring_aes: every public key in the ring is ' + len + ' bytes'); }
    }
}
function find(ring, pk) {
    for (var i = 0; i < ring.length; i++) {
        var d = 0;
        for (var j = 0; j < pk.length; j++) { d |= ring[i][j] ^ pk[j]; }
        if (d === 0) { return i; }
    }
    throw new Error('ring_aes: the signer\'s public key is not in the ring');
}

/* ---------------- ring signatures over FAEST keys ---------------- */

function build_ring(name) {
    var T = TREES[name], lambda = T[0], lb = lambda / 8, beta = lambda === 128 ? 1 : 2, FK = FAEST[name];
    var PK = 16 + 16 * beta, system = systems(T), F = binary_field(lambda), A = aes_circuit(F, F.W, lambda, 4);

    function layout(n) {
        var shape = one_hot_shape(n, MAX_DIM), V = A.LKE + beta * A.LENC, H = V + 8 * PK;
        return { shape: shape, V: V, H: H, ell: pad8(H + shape.bits) };
    }
    function mu_of(E, ring, msg) { return E.hsh([LABEL_RING, be32(ring.length)].concat(ring, [msg]), DOM_MU, 2 * lb); }
    function statement(L, ring) {
        return function (Rg, emit) {
            emit(Rg.mul(Rg.bit(0), Rg.bit(1)), 2);
            var rk = A.key_schedule(Rg, emit, 0), input = A.wbits(Rg, L.V, 128);
            for (var b = 0; b < beta; b++) {
                var inb = input.slice();
                if (b === 1) { inb[0] = Rg.add(inb[0], Rg.cbit(1)); }
                A.block(Rg, emit, rk, inb, A.wbits(Rg, L.V + 128 * (b + 1), 128), A.LKE + b * A.LENC);
            }
            one_hot_select(Rg, emit, F, L.shape, L.H, ring, L.V, 8 * PK);
        };
    }

    return {
        NAME: 'RING-AES-' + name.toUpperCase(), PK_BYTES: PK, SK_BYTES: FK.SK_BYTES, SEED_BYTES: FK.SEED_BYTES, RND_BYTES: lb,
        /**
         * FAEST's key generation: seed = x || k (the two lowest bits of k not
         * both 1); omitted or null draws fresh ones from the platform
         */
        keygen: function (seed) { return FK.keygen(seed); },
        sig_bytes: function (n) { return system(layout(n).ell).proof_bytes(0); },

        /** rnd: RND_BYTES; omitted or null draws fresh ones from the platform */
        sign: function (sk, ring, msg, rnd) {
            check_ring(ring, PK);
            if (rnd == null) { rnd = secure_random(lb); }
            if (!(rnd instanceof Uint8Array) || rnd.length !== lb) { throw new Error('ring_aes: sign takes ' + lb + ' bytes of randomness'); }
            var me = FK.keygen(sk), i = find(ring, me.pk), L = layout(ring.length), E = system(L.ell);
            var x = sk.subarray(0, 16), key = sk.subarray(16), kk = A.round_keys(key, 4);
            var wit = new Uint8Array(L.ell / 8), parts = [A.key_witness(key)];
            for (var b = 0; b < beta; b++) { var xb = new Uint8Array(x); xb[0] ^= b; parts.push(A.block_witness(kk, xb)); }
            wit.set(concat(parts));
            put(wit, L.V, ring[i]);
            set_bits(wit, L.H, one_hot_witness(L.shape, i));
            var mu = mu_of(E, ring, msg), h = E.hsh([sk, mu, rnd], DOM_ROOT, lb + 16), iv_pre = h.slice(lb);
            var V = E.commit(h.slice(0, lb), E.hsh([iv_pre, mu], DOM_IV, 16));
            return E.prove(V, mu, iv_pre, wit, 0, statement(L, ring));
        },

        verify: function (ring, msg, sig) {
            try { check_ring(ring, PK); } catch (e) { return false; }
            var L = layout(ring.length), E = system(L.ell);
            if (!(sig instanceof Uint8Array) || sig.length !== E.proof_bytes(0)) { return false; }
            var mu = mu_of(E, ring, msg);
            return E.verify(sig, mu, function (iv_pre) { return E.hsh([iv_pre, mu], DOM_IV, 16); }, 0, statement(L, ring));
        }
    };
}

/* ---------------- linkable and threshold ring signatures ---------------- */

function build_link(name) {
    var T = TREES[name], lambda = T[0], lb = lambda / 8, NBLK = { 128: 2, 192: 3, 256: 4 }[lambda];
    var PK = 16 * NBLK, TAG = 16, system = systems(T), F = binary_field(lambda), A = aes_circuit(F, F.W, lambda, 4);

    function counter(i) { var b = new Uint8Array(16); b[15] = i; return b; }
    function check_key(k) {
        if (!(k instanceof Uint8Array) || k.length !== lb) { throw new Error('lrs_aes: a secret key is ' + lb + ' bytes'); }
        if ((k[0] & 3) === 3) { throw new Error('lrs_aes: the two lowest bits of the key must not both be 1'); }
    }
    function public_key(k) {
        var kk = A.round_keys(k, 4), parts = [];
        for (var i = 1; i <= NBLK; i++) { parts.push(A.encrypt(kk, counter(i))); }
        return concat(parts);
    }
    /* H(scope): NBLK blocks of 127 bits (bit 0 clear) */
    function hscope(scope) {
        var h = shake256(concat([LABEL_LINK, be32(scope.length), scope, new Uint8Array([DOM_TAG])]), 16 * NBLK);
        for (var i = 0; i < NBLK; i++) { h[16 * i] &= 0xfe; }
        return h;
    }
    /* the CBC chain: AES inputs and full outputs of each block; the tag is the last output, bit 0 cleared */
    function chain(kk, hx) {
        var c = new Uint8Array(16), ins = [], outs = [];
        for (var i = 0; i < NBLK; i++) {
            var x = new Uint8Array(16);
            for (var q = 0; q < 16; q++) { x[q] = c[q] ^ hx[16 * i + q]; }
            x[0] |= 1;
            var o = A.encrypt(kk, x);
            ins.push(x); outs.push(o);
            c = o.slice(); c[0] &= 0xfe;
        }
        return { ins: ins, outs: outs, tag: c };
    }
    function layout(n) {
        var shape = one_hot_shape(n, MAX_DIM), CB = A.LKE + 2 * NBLK * A.LENC, O = CB, B0 = O + 128 * (NBLK - 1), Y = B0 + 1, H = Y + 8 * PK;
        return { shape: shape, O: O, B0: B0, Y: Y, H: H, ell: pad8(H + shape.bits) };
    }
    function scope_of(ring, msg, scope) { return scope !== undefined ? scope : concat([be32(ring.length)].concat(ring, [msg])); }
    function mu_of(E, ring, msg, tag) { return E.hsh([LABEL_LINK, be32(ring.length)].concat(ring, [msg, tag]), DOM_MU, 2 * lb); }
    function statement(L, ring, hx, tag) {
        return function (Rg, emit) {
            emit(Rg.mul(Rg.bit(0), Rg.bit(1)), 2);
            var rk = A.key_schedule(Rg, emit, 0), i, q;
            /* P(k): block i of the selected public key */
            for (i = 0; i < NBLK; i++) {
                A.block(Rg, emit, rk, A.cbits(Rg, counter(i + 1), 128), A.wbits(Rg, L.Y + 128 * i, 128), A.LKE + i * A.LENC);
            }
            /* T(k, scope): the CBC chain, ending in the public tag */
            var hb = A.cbits(Rg, hx, 128 * NBLK), tb = A.cbits(Rg, tag, 128);
            for (i = 0; i < NBLK; i++) {
                var input = [];
                for (q = 0; q < 128; q++) {
                    if (q === 0) { input.push(Rg.cbit(1)); }
                    else { input.push(i === 0 ? hb[q] : Rg.add(Rg.bit(L.O + 128 * (i - 1) + q), hb[128 * i + q])); }
                }
                var output = i < NBLK - 1 ? A.wbits(Rg, L.O + 128 * i, 128) : [Rg.bit(L.B0)].concat(tb.slice(1));
                A.block(Rg, emit, rk, input, output, A.LKE + (NBLK + i) * A.LENC);
            }
            one_hot_select(Rg, emit, F, L.shape, L.H, ring, L.Y, 8 * PK);
        };
    }

    /* rnd: RND_BYTES; omitted or null draws fresh ones from the platform */
    function sign(sk, ring, msg, rnd, scope) {
        check_key(sk);
        check_ring(ring, PK);
        if (rnd == null) { rnd = secure_random(lb); }
        if (!(rnd instanceof Uint8Array) || rnd.length !== lb) { throw new Error('lrs_aes: sign takes ' + lb + ' bytes of randomness'); }
        var pk = public_key(sk), idx = find(ring, pk), L = layout(ring.length), E = system(L.ell);
        var kk = A.round_keys(sk, 4), hx = hscope(scope_of(ring, msg, scope)), ch = chain(kk, hx), i;
        var wit = new Uint8Array(L.ell / 8), parts = [A.key_witness(sk)];
        for (i = 1; i <= NBLK; i++) { parts.push(A.block_witness(kk, counter(i))); }
        for (i = 0; i < NBLK; i++) { parts.push(A.block_witness(kk, ch.ins[i])); }
        wit.set(concat(parts));
        for (i = 0; i < NBLK - 1; i++) { put(wit, L.O + 128 * i, ch.outs[i]); }
        set_bits(wit, L.B0, [ch.outs[NBLK - 1][0] & 1]);
        put(wit, L.Y, ring[idx]);
        set_bits(wit, L.H, one_hot_witness(L.shape, idx));
        var mu = mu_of(E, ring, msg, ch.tag), h = E.hsh([sk, mu, rnd], DOM_ROOT, lb + 16), iv_pre = h.slice(lb);
        var V = E.commit(h.slice(0, lb), E.hsh([iv_pre, mu], DOM_IV, 16));
        return concat([ch.tag, E.prove(V, mu, iv_pre, wit, 0, statement(L, ring, hx, ch.tag))]);
    }
    function verify(ring, msg, sig, scope) {
        try { check_ring(ring, PK); } catch (e) { return false; }
        var L = layout(ring.length), E = system(L.ell);
        if (!(sig instanceof Uint8Array) || sig.length !== TAG + E.proof_bytes(0) || (sig[0] & 1)) { return false; }
        var tag = sig.subarray(0, TAG), mu = mu_of(E, ring, msg, tag), hx = hscope(scope_of(ring, msg, scope));
        return E.verify(sig.subarray(TAG), mu, function (iv_pre) { return E.hsh([iv_pre, mu], DOM_IV, 16); }, 0, statement(L, ring, hx, tag));
    }
    function tag(sig) { return sig.slice(0, TAG); }
    function same(a, b) { var d = 0; for (var q = 0; q < TAG; q++) { d |= a[q] ^ b[q]; } return d === 0; }

    return {
        NAME: 'LRS-AES-' + name.toUpperCase(), PK_BYTES: PK, SK_BYTES: lb, RND_BYTES: lb, TAG_BYTES: TAG,
        /**
         * k: lambda/8 bytes, the two lowest bits not both 1. Omitted or null
         * draws fresh ones from the platform, again while those bits are
         * both 1. @return {{pk, sk}}
         */
        keygen: function (k) {
            if (k == null) {
                do { k = secure_random(lb); } while ((k[0] & 3) === 3);
            }
            check_key(k);
            return { pk: public_key(k), sk: k.slice() };
        },
        sig_bytes: function (n) { return TAG + system(layout(n).ell).proof_bytes(0); },
        sign: sign, verify: verify, tag: tag,
        linked: function (s1, s2) { return same(tag(s1), tag(s2)); },

        /** Threshold: t partial signatures on (ring, msg), concatenated. */
        combine: function (sigs) { return concat(sigs); },
        /** At least t different ring members signed msg: t valid partials, pairwise different tags. */
        verify_threshold: function (ring, msg, sig, t) {
            try { check_ring(ring, PK); } catch (e) { return false; }
            var one = TAG + system(layout(ring.length).ell).proof_bytes(0), tags = [];
            if (!(t >= 1) || !(sig instanceof Uint8Array) || sig.length !== t * one) { return false; }
            for (var i = 0; i < t; i++) {
                var s = sig.subarray(i * one, (i + 1) * one);
                for (var j = 0; j < tags.length; j++) { if (same(tags[j], s)) { return false; } }
                if (!verify(ring, msg, s)) { return false; }
                tags.push(s.subarray(0, TAG));
            }
            return true;
        }
    };
}

function lazy(name, link) {
    return link
        ? lazy_scheme(function () { return build_link(name); }, ['NAME', 'PK_BYTES', 'SK_BYTES', 'RND_BYTES', 'TAG_BYTES'],
            ['keygen', 'sig_bytes', 'sign', 'verify', 'tag', 'linked', 'combine', 'verify_threshold'])
        : lazy_scheme(function () { return build_ring(name); }, ['NAME', 'PK_BYTES', 'SK_BYTES', 'SEED_BYTES', 'RND_BYTES'],
            ['keygen', 'sig_bytes', 'sign', 'verify']);
}

export var ring_aes_128s = /* @__PURE__ */ lazy('128s');
export var ring_aes_128f = /* @__PURE__ */ lazy('128f');
export var ring_aes_192s = /* @__PURE__ */ lazy('192s');
export var ring_aes_192f = /* @__PURE__ */ lazy('192f');
export var ring_aes_256s = /* @__PURE__ */ lazy('256s');
export var ring_aes_256f = /* @__PURE__ */ lazy('256f');
export var lrs_aes_128s = /* @__PURE__ */ lazy('128s', true);
export var lrs_aes_128f = /* @__PURE__ */ lazy('128f', true);
export var lrs_aes_192s = /* @__PURE__ */ lazy('192s', true);
export var lrs_aes_192f = /* @__PURE__ */ lazy('192f', true);
export var lrs_aes_256s = /* @__PURE__ */ lazy('256s', true);
export var lrs_aes_256f = /* @__PURE__ */ lazy('256f', true);
