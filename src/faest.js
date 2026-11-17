/**
 * FAEST  -  the round-3 submission to NIST's additional signatures (v3,
 * August 2026)
 *
 * A signature from a proof of knowledge of an AES key: pk = (x, AES_k(x)),
 * sk = k, and a signature is a non-interactive VOLE-in-the-head proof that
 * the signer knows k. The prover commits to an extended witness (the key, the
 * key-schedule words and every other round state) with VOLE correlations from
 * tau GGM trees (all in one tree, the "BAVC"), proves the AES relations as
 * degree-7 constraints over GF(2^lambda) (each S-box checked through the
 * conjugates of its input and output byte), and opens all leaves but one per
 * tree, chosen by Fiat-Shamir with w bits of grinding.
 *
 * ROUND 3: the VOLE masks u * Delta of the ZK check are committed through
 * the CRT construction of commons/vole_mult.js (the residues modulo the tree
 * moduli come free from the trees, the rest through bit-multiplication gates
 * with 10 hashed correction bits each), and the ZK check is degree 7.
 *
 * The proof system itself - the BAVC, the VOLE commitment, the ZK check and
 * the Fiat-Shamir pipeline - is commons/voleith.js, and the AES circuit (the
 * extended witness and its constraints) commons/aes_circuit.js; this file is
 * the signature: FAEST's keys, its statement and its hashing.
 *
 * THE PARAMETER SETS: 128, 192, 256 bits, "s" (short) or "f" (fast); the
 * one-way function is AES-128/192/256 (two blocks above 128 bits), or in the
 * _em sets the Even-Mansour Rijndael x -> E_x(k) xor k with a lambda-bit block
 * (Rijndael-192 / -256 above 128), whose key schedule is public.
 *
 * KEYS: pk = x || F(x); sk = x || k, where the lowest two bits of k are not
 * both 1 (keygen rejects such a k). sign takes rho (lambda/8 bytes), mixed
 * with sk and the message into the GGM root seed.
 */

import { aes_circuit } from './commons/aes_circuit.js';
import { voleith } from './commons/voleith.js';
import { concat, secure_random } from './commons/bytes.js';
import { lazy_scheme } from './commons/lazy_scheme.js';

/* [lambda, tau, w, T_open, ell, Nst, Ske, R, Lke, Lenc, input bytes, output bytes, em] */
var SETS = {
    '128s': [128, 11, 7, 102, 960, 4, 40, 10, 448, 512, 16, 16, false],
    '128f': [128, 17, 8, 108, 960, 4, 40, 10, 448, 512, 16, 16, false],
    '192s': [192, 16, 12, 162, 1728, 4, 32, 12, 448, 640, 16, 32, false],
    '192f': [192, 24, 8, 163, 1728, 4, 32, 12, 448, 640, 16, 32, false],
    '256s': [256, 22, 6, 225, 2208, 4, 52, 14, 672, 768, 16, 32, false],
    '256f': [256, 33, 8, 229, 2208, 4, 52, 14, 672, 768, 16, 32, false],
    'em_128s': [128, 11, 7, 103, 640, 4, 0, 10, 128, 512, 16, 16, true],
    'em_128f': [128, 17, 8, 105, 640, 4, 0, 10, 128, 512, 16, 16, true],
    'em_192s': [192, 16, 8, 162, 1152, 6, 0, 12, 192, 960, 24, 24, true],
    'em_192f': [192, 25, 8, 171, 1152, 6, 0, 12, 192, 960, 24, 24, true],
    'em_256s': [256, 22, 6, 218, 1792, 8, 0, 14, 256, 1536, 32, 32, true],
    'em_256f': [256, 33, 8, 229, 1792, 8, 0, 14, 256, 1536, 32, 32, true]
};
var D_ZK = 7;

function build(name) {
    var P = SETS[name], lambda = P[0], tau = P[1], w = P[2], T_OPEN = P[3], ell = P[4], Nst = P[5], R = P[7];
    var Lke = P[8], Lenc = P[9], IN = P[10], OUT = P[11], em = P[12];
    var E = voleith({ lambda: lambda, tau: tau, w: w, T_open: T_OPEN, ell: ell, D: D_ZK, em: em });
    var lb = lambda / 8, F = E.F, W = E.W, NK = lambda / 32, hsh = E.hsh;
    var blocksize = 32 * Nst, beta = Math.ceil(lambda / blocksize);
    var SIG = E.proof_bytes(0), PK = IN + OUT, SK = IN + lb;

    /* ---- the AES statement: commons/aes_circuit.js ---- */
    var A = aes_circuit(F, W, lambda, Nst);
    function constraints(Rg, owf_in, owf_out, emit) {
        /* the key's two lowest bits are not both 1 */
        emit(Rg.mul(Rg.bit(0), Rg.bit(1)), 2);
        var rk, input, output, b;
        if (em) {
            rk = A.cbits(Rg, A.round_keys(owf_in, NK).b, (R + 1) * blocksize);
            input = A.wbits(Rg, 0, blocksize);
            var oc = A.cbits(Rg, owf_out, blocksize);
            output = A.wbits(Rg, 0, blocksize).map(function (x, q) { return Rg.add(x, oc[q]); });
        } else {
            rk = A.key_schedule(Rg, emit, 0);
            input = A.cbits(Rg, owf_in, blocksize);
            output = A.cbits(Rg, owf_out, beta * blocksize);
        }
        for (b = 0; b < beta; b++) {
            var inb = input.slice();
            if (b === 1) { inb[0] = Rg.add(inb[0], Rg.cbit(1)); }
            A.block(Rg, emit, rk, inb, output.slice(b * blocksize, (b + 1) * blocksize), Lke + b * Lenc);
        }
    }

    /* ---- the one-way function and the extended witness ---- */
    function owf(key, input) {
        if (em) {
            var o = A.encrypt(A.round_keys(input, NK), key);
            for (var q = 0; q < lb; q++) { o[q] ^= key[q]; }
            return o;
        }
        var kk = A.round_keys(key, 4), out = A.encrypt(kk, input);
        if (beta === 2) { var in2 = input.slice(); in2[0] ^= 1; out = concat([out, A.encrypt(kk, in2)]); }
        return out;
    }
    function witness(key, input) {
        if (em) { return concat([key.slice(), A.block_witness(A.round_keys(input, NK), key)]); }
        var kk = A.round_keys(key, 4), parts = [A.key_witness(key)];
        for (var b = 0; b < beta; b++) { var x = input.slice(); x[0] ^= b; parts.push(A.block_witness(kk, x)); }
        return concat(parts);
    }

    function check_key(key) { return (key[0] & 3) !== 3; }

    /*
     * seed = the OWF input || the key, SEED_BYTES. Omitted or null draws
     * fresh ones from the platform - again while the key's two lowest bits
     * are both 1, as the reference's key generation rejects them.
     */
    function keygen(seed) {
        if (seed == null) {
            do { seed = secure_random(IN + lb); } while (!check_key(seed.subarray(IN)));
        }
        if (!(seed instanceof Uint8Array) || seed.length !== IN + lb) { throw new Error('faest: keygen takes ' + (IN + lb) + ' bytes (the OWF input, then the key)'); }
        var input = seed.slice(0, IN), key = seed.slice(IN);
        if (!check_key(key)) { throw new Error('faest: the two lowest bits of the key must not both be 1'); }
        return { pk: concat([input, owf(key, input)]), sk: seed.slice() };
    }

    /* rho: RND_BYTES; omitted or null draws fresh ones from the platform */
    function sign(sk, msg, rho) {
        if (!(sk instanceof Uint8Array) || sk.length !== SK) { throw new Error('faest: secret key must be ' + SK + ' bytes'); }
        if (rho == null) { rho = secure_random(lb); }
        if (!(rho instanceof Uint8Array) || rho.length !== lb) { throw new Error('faest: sign takes ' + lb + ' bytes of randomness'); }
        var input = sk.subarray(0, IN), key = sk.subarray(IN);
        if (!check_key(key)) { throw new Error('faest: invalid secret key'); }
        var output = owf(key, input), wit = witness(key, input);
        var mu = hsh([input, output, msg], 8, 2 * lb), h3 = hsh([key, mu, rho], 3, lb + 16), root = h3.slice(0, lb), iv_pre = h3.slice(lb);
        var V = E.commit(root, hsh([iv_pre, mu], 4, 16));
        return E.prove(V, mu, iv_pre, wit, 0, function (Rg, emit) { constraints(Rg, input, output, emit); });
    }

    function verify(pk, msg, sig) {
        if (!(pk instanceof Uint8Array) || pk.length !== PK || !(sig instanceof Uint8Array) || sig.length !== SIG) { return false; }
        var input = pk.subarray(0, IN), output = pk.subarray(IN), mu = hsh([input, output, msg], 8, 2 * lb);
        return E.verify(sig, mu, function (iv_pre) { return hsh([iv_pre, mu], 4, 16); }, 0,
                        function (Rg, emit) { constraints(Rg, input, output, emit); });
    }

    return {
        NAME: 'FAEST-' + name.toUpperCase().replace('_', '-'),
        PK_BYTES: PK, SK_BYTES: SK, SIG_BYTES: SIG, SEED_BYTES: IN + lb, RND_BYTES: lb, KEY_BYTES: lb,
        keygen: keygen, sign: sign, verify: verify
    };
}

function lazy(name) {
    return lazy_scheme(function () { return build(name); },
        ['NAME', 'PK_BYTES', 'SK_BYTES', 'SIG_BYTES', 'SEED_BYTES', 'RND_BYTES', 'KEY_BYTES'],
        ['keygen', 'sign', 'verify']);
}

export var faest_128s = /* @__PURE__ */ lazy('128s');
export var faest_128f = /* @__PURE__ */ lazy('128f');
export var faest_192s = /* @__PURE__ */ lazy('192s');
export var faest_192f = /* @__PURE__ */ lazy('192f');
export var faest_256s = /* @__PURE__ */ lazy('256s');
export var faest_256f = /* @__PURE__ */ lazy('256f');
export var faest_em_128s = /* @__PURE__ */ lazy('em_128s');
export var faest_em_128f = /* @__PURE__ */ lazy('em_128f');
export var faest_em_192s = /* @__PURE__ */ lazy('em_192s');
export var faest_em_192f = /* @__PURE__ */ lazy('em_192f');
export var faest_em_256s = /* @__PURE__ */ lazy('em_256s');
export var faest_em_256f = /* @__PURE__ */ lazy('em_256f');
