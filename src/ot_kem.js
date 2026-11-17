/**
 * ot_kem.js — oblivious transfer from a KEM: post-quantum base OTs.
 *
 * ot_base.js is Chou–Orlandi, a Diffie–Hellman protocol; ot_extend.js turns
 * any 128 base transfers into millions with hashing alone, so a quantum-safe
 * base OT makes the whole stack quantum-safe. This is the one built from a
 * KEM whose public keys form a group and look uniform - Masny and Rindal's
 * "endemic OT" (CCS 2019, ePrint 2019/706), with ML-KEM, as libOTe runs it
 * with Kyber:
 *
 *     receiver   (pk, sk) <- KeyGen; R uniform in the key space
 *                r_{1-b} = R,  r_b = pk - H(R)            sends r_0, r_1
 *     sender     pk_0 = r_0 + H(r_1),  pk_1 = r_1 + H(r_0)
 *                (c_j, K_j) <- Encaps(pk_j)                sends c_0, c_1
 *                k_j = KDF(r_0, r_1, j, c_j, K_j)
 *     receiver   k_b = KDF(r_0, r_1, b, c_b, Decaps(sk, c_b))
 *
 * pk_b is the receiver's own key; pk_{1-b} = R + H(pk - H(R)) is one nobody
 * holds a secret for. r_0 and r_1 are both uniform - pk is, under MLWE - so
 * the sender learns nothing of b; and to know both secrets the receiver would
 * need two keys related through the random oracle H.
 *
 * THE KEY SPACE. An ML-KEM key is (t, rho): t in Z_q^(256k), the group, and
 * rho the seed of the public matrix, which r_0 and r_1 share. H maps to
 * uniform t (SampleNTT on a hash of the input), R is uniform t.
 *
 * The receiver's choice is selected without a branch (commons/ct.js), as in
 * ot_base.js: both r_0 and r_1 are computed either way.
 */

import { ml_kem512, ml_kem768, ml_kem1024, sample_ntt } from './ml_kem.js';
import { sha3_256 } from './sha3.js';
import { concat, ascii, be16, be32 } from './commons/bytes.js';
import { select_bytes, equal } from './commons/ct.js';
import { require_rng } from './commons/primes.js';

var Q = 3329, N = 256;
var DST_H = /* @__PURE__ */ ascii('cryptographic-primitives/ot/kem/v1/hash');
var DST_K = /* @__PURE__ */ ascii('cryptographic-primitives/ot/kem/v1/key');

function build(name, KEM) {
    var k = KEM.PARAMS.k, EK = KEM.EK_BYTES, CT = KEM.CT_BYTES;

    function check_sid(sid) {
        if (!(sid instanceof Uint8Array) || sid.length === 0) {
            throw new TypeError('ot_kem: sid must be non-empty bytes - it separates transfers');
        }
    }
    function ctx(sid, i) { return concat([be16(sid.length), sid, be32(i)]); }
    /* H: the key space -> t, uniform */
    function H(c, r) {
        var seed = sha3_256(concat([DST_H, c, r])), t = new Int32Array(k * N);
        for (var j = 0; j < k; j++) { t.set(sample_ntt(seed, j, 0xff), N * j); }
        return t;
    }
    function add(a, b) { var o = new Int32Array(a.length); for (var j = 0; j < a.length; j++) { o[j] = (a[j] + b[j]) % Q; } return o; }
    function sub(a, b) { var o = new Int32Array(a.length); for (var j = 0; j < a.length; j++) { o[j] = (a[j] - b[j] + Q) % Q; } return o; }
    function kdf(c, r0, r1, j, ct, K) { return sha3_256(concat([DST_K, c, r0, r1, new Uint8Array([j]), ct, K])); }

    /**
     * Receiver: choose. @return {{state, msg}} msg = r_0 || r_1, 2 EK bytes.
     * Draws 64 bytes (the ML-KEM key) and 32 (R).
     */
    function receiver_choose(choice, rng, sid, i) {
        rng = require_rng('ot_kem.receiver_choose', rng);
        check_sid(sid);
        if (choice !== 0 && choice !== 1) { throw new TypeError('ot_kem: choice must be 0 or 1, got ' + choice); }
        var c = ctx(sid, i), kp = KEM.keygen(rng(64)), pk = KEM.split_ek(kp.ek), rs = rng(32), R = new Int32Array(k * N);
        for (var j = 0; j < k; j++) { R.set(sample_ntt(rs, j, 0), N * j); }
        var Rb = KEM.join_ek(R, pk.rho), X = KEM.join_ek(sub(pk.t, H(c, Rb)), pk.rho);
        var r0 = select_bytes(choice, Rb, X), r1 = select_bytes(choice, X, Rb);
        return { state: { choice: choice, dk: kp.dk, c: c, r0: r0, r1: r1 }, msg: concat([r0, r1]) };
    }

    /** Sender: both keys, and the ciphertexts. Draws 2 x 32 bytes. @return {{k0, k1, msg}} msg = c_0 || c_1 */
    function sender_respond(msg, rng, sid, i) {
        rng = require_rng('ot_kem.sender_respond', rng);
        check_sid(sid);
        if (!(msg instanceof Uint8Array) || msg.length !== 2 * EK) { throw new Error('ot_kem: the receiver message is ' + 2 * EK + ' bytes'); }
        var c = ctx(sid, i), r0 = msg.subarray(0, EK), r1 = msg.subarray(EK), s0 = KEM.split_ek(r0), s1 = KEM.split_ek(r1);
        if (!equal(s0.rho, s1.rho)) { throw new Error('ot_kem: the two keys must share rho'); }
        var e0 = KEM.encaps(KEM.join_ek(add(s0.t, H(c, r1)), s0.rho), rng(32));
        var e1 = KEM.encaps(KEM.join_ek(add(s1.t, H(c, r0)), s1.rho), rng(32));
        return { k0: kdf(c, r0, r1, 0, e0.ct, e0.ss), k1: kdf(c, r0, r1, 1, e1.ct, e1.ss), msg: concat([e0.ct, e1.ct]) };
    }

    /** Receiver: its one key. */
    function receiver_key(state, msg) {
        if (!(msg instanceof Uint8Array) || msg.length !== 2 * CT) { throw new Error('ot_kem: the sender message is ' + 2 * CT + ' bytes'); }
        var ct = select_bytes(state.choice, msg.subarray(CT), msg.subarray(0, CT));
        return kdf(state.c, state.r0, state.r1, state.choice, ct, KEM.decaps(state.dk, ct));
    }

    return {
        NAME: 'OT-' + name, KEM: KEM, RECEIVER_BYTES: 2 * EK, SENDER_BYTES: 2 * CT, KEY_BYTES: 32,
        receiver_choose: receiver_choose, sender_respond: sender_respond, receiver_key: receiver_key
    };
}

export var ot_ml_kem512 = /* @__PURE__ */ build('ML-KEM-512', ml_kem512);
export var ot_ml_kem768 = /* @__PURE__ */ build('ML-KEM-768', ml_kem768);
export var ot_ml_kem1024 = /* @__PURE__ */ build('ML-KEM-1024', ml_kem1024);
