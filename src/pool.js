/**
 * Pool  -  a post-quantum OPRF from learning with rounding and oblivious
 * transfer (Davidson, Deo, Tremblay Thibault; ePrint 2025/1816)
 *
 * An OBLIVIOUS PRF: the client learns F_sk(x) for an x the server never
 * sees, and nothing else about sk. Here the PRF is binary-secret LWR,
 *
 *     F_sk(t, x) = round_{q,p}(A s_r)  for each row r,   A = RO(t, x) in Z_q^(delta x n)
 *
 * with t public metadata (partial obliviousness) and delta = 128 / log p rows,
 * so an output is 128 bits. The protocol needs only random OTs, made before
 * the input is known:
 *
 *   PREPROCESSING (per tau evaluations)
 *     n delta random 1-of-2 OTs, the CLIENT sending (r_0,i, r_1,i in Z_q^tau),
 *       the server receiving r_b,i on a random b_i; the server publishes
 *       b-bar_i = b_i xor sk_i
 *     delta tau random 1-of-Delta OTs (Delta = q/p), the SERVER sending
 *       (r'_0 .. r'_(Delta-1) in Z_p), the client receiving r'_b' on a random b'
 *   ONLINE (two messages)
 *     client  e_i = a_i + r_(b-bar_i),i + r_(1-b-bar_i),i;  b-bar' = (r_Sigma - b') mod Delta
 *     server  a~_Sigma = a . sk + r_Sigma from its OT strings and e;
 *             y_k = round(a~_Sigma - k) + r'_((k - b-bar') mod Delta), k < Delta
 *     client  z = y_(r_Sigma mod Delta) - r'_b' - floor(r_Sigma / Delta)  (mod p)
 *
 * The client's e is masked by OT strings the server never holds; the server
 * reveals only the one y the client can unmask, and that y is the rounding
 * of a . sk shifted by a multiple of Delta - exactly F + k.
 *
 * ⛔ SEMI-HONEST. The paper proves security against parties that follow the
 *    protocol (Theorems 5.2, 5.3); a malicious client or server is not in
 *    its model, and this module does not add the proofs that would put it
 *    there. Each preprocessing serves tau evaluations, once each: the
 *    states count them and refuse a reuse.
 *
 * THE OTs. The random OTs are inputs here, as in the paper's OT-hybrid
 * model; ot_kem.js (post-quantum base OTs) with ot_extend.js makes them. A
 * random 1-of-Delta OT is log2(Delta) random 1-of-2 OTs, the strings
 * r'_k the XOR over the bits of k of PRF(key_t[k_t]) (Naor-Pinkas): the client's
 * keys open exactly its b' (commons/random_ot.js). OT keys are 32-byte
 * seeds, expanded by SHAKE256.
 *
 * PARAMETER SETS (the paper's Table 3): POOL_128 (n, p, q) = (482, 2^8, 2^12),
 * POOL_128_P4 (415, 2^4, 2^8); POOL_100 (370, 2^8, 2^12), POOL_100_P4
 * (296, 2^4, 2^8).
 */

import { shake256 } from './sha3.js';
import { ascii, be32 } from './commons/bytes.js';
import { domain_xof } from './commons/domain_xof.js';
import { pack_bits, unpack_bits } from './commons/bitpack.js';
import { require_rng } from './commons/primes.js';
import { check_sender_ots, check_receiver_ots, one_of_n_send, one_of_n_receive } from './commons/random_ot.js';

var SETS = { POOL_128: [482, 8, 12], POOL_128_P4: [415, 4, 8], POOL_100: [370, 8, 12], POOL_100_P4: [296, 4, 8] };
var DST = /* @__PURE__ */ ascii('cryptographic-primitives/pool/v1');
var DOM_RO = 0, DOM_R = 1;

var expand = /* @__PURE__ */ domain_xof(shake256, DST);

export function pool(name) {
    var P = SETS[name];
    if (!P) { throw new Error('pool: unknown parameter set ' + name); }
    var n = P[0], LP = P[1], LQ = P[2], p = 1 << LP, q = 1 << LQ, DELTA = q / p, LD = LQ - LP, ROWS = 128 / LP;
    var NOT2 = ROWS * n, SK_BYTES = NOT2 / 8, OUT_BYTES = 16;
    var REQ_BYTES = (NOT2 * LQ + ROWS * LD) / 8 + 4, RESP_BYTES = ROWS * DELTA * LP / 8 + 4;

    /* the row vectors a = RO(t, x) in Z_q^(ROWS x n) */
    function ro(t, x) {
        var b = expand(DOM_RO, [t, x], 2 * NOT2), a = new Int32Array(NOT2);
        for (var i = 0; i < NOT2; i++) { a[i] = (b[2 * i] | (b[2 * i + 1] << 8)) & (q - 1); }
        return a;
    }
    function sk_bit(sk, i) { return (sk[i >> 3] >> (i & 7)) & 1; }
    function round_qp(x) { return ((x * p + (q >> 1)) >> LQ) & (p - 1); }
    /* the j-th of tau values mod q a 1-of-2 OT key expands to */
    function rq(key, j) { var b = expand(DOM_R, [key, be32(j)], 2); return (b[0] | (b[1] << 8)) & (q - 1); }
    function check_groups(list, check) { list.forEach(function (g) { check(g, LD, 'pool'); }); }

    function keygen(rng) { rng = require_rng('pool.keygen', rng); return rng(SK_BYTES); }

    /** The PRF itself: 128 bits, ROWS outputs of log p bits. */
    function evaluate(sk, t, x) {
        var a = ro(t, x), out = new Int32Array(ROWS);
        for (var r = 0; r < ROWS; r++) {
            var acc = 0;
            for (var i = 0; i < n; i++) { if (sk_bit(sk, r * n + i)) { acc += a[r * n + i]; } }
            out[r] = round_qp(acc & (q - 1));
        }
        var o = new Uint8Array(OUT_BYTES);
        pack_bits(out, LP, o, 0);
        return o;
    }

    /*
     * PREPROCESSING, from random OTs.
     *   server: recv2 - ROWS n entries {choice, key}  (it receives one of the client's two strings)
     *           send16 - ROWS tau entries, each LD pairs [k0, k1]  (it sends the 1-of-Delta strings)
     *   client: send2 - ROWS n pairs [k0, k1]
     *           recv16 - ROWS tau entries, each LD {choice, key}
     */
    function server_preprocess(sk, tau, recv2, send16) {
        if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES) { throw new Error('pool: a key is ' + SK_BYTES + ' bytes'); }
        if (!Array.isArray(recv2) || recv2.length !== NOT2 || !Array.isArray(send16) || send16.length !== ROWS * tau) { throw new Error('pool: ' + NOT2 + ' 1-of-2 and ' + ROWS * tau + ' 1-of-' + DELTA + ' OTs'); }
        check_receiver_ots(recv2, NOT2, 'pool');
        check_groups(send16, check_sender_ots);
        var bbar = new Uint8Array(SK_BYTES);
        for (var i = 0; i < NOT2; i++) { if (recv2[i].choice ^ sk_bit(sk, i)) { bbar[i >> 3] |= 1 << (i & 7); } }
        return { state: { sk: sk, tau: tau, used: new Uint8Array(tau), recv2: recv2, send16: send16 }, msg: bbar };
    }
    function client_preprocess(tau, send2, recv16, bbar) {
        if (!Array.isArray(send2) || send2.length !== NOT2 || !Array.isArray(recv16) || recv16.length !== ROWS * tau) { throw new Error('pool: ' + NOT2 + ' 1-of-2 and ' + ROWS * tau + ' 1-of-' + DELTA + ' OTs'); }
        if (!(bbar instanceof Uint8Array) || bbar.length !== SK_BYTES) { throw new Error('pool: the server\'s preprocessing message is ' + SK_BYTES + ' bytes'); }
        check_sender_ots(send2, NOT2, 'pool');
        check_groups(recv16, check_receiver_ots);
        return { tau: tau, used: new Uint8Array(tau), send2: send2, recv16: recv16, bbar: bbar.slice() };
    }

    function take(st, j) {
        if (!(j >= 0 && j < st.tau && (j | 0) === j)) { throw new Error('pool: the use index is 0 to tau - 1'); }
        if (st.used[j]) { throw new Error('pool: preprocessing use ' + j + ' was already spent'); }
        st.used[j] = 1;
    }

    /** Client, online: the request for x (metadata t) on preprocessing use j. @return {{state, msg}} */
    function request(st, j, t, x) {
        take(st, j);
        var a = ro(t, x), e = new Int32Array(NOT2), rows = [], r, i;
        for (r = 0; r < ROWS; r++) {
            var rs = 0;
            for (i = r * n; i < (r + 1) * n; i++) {
                var b = sk_bit(st.bbar, i), mine = rq(st.send2[i][b], j);
                e[i] = (a[i] + mine + rq(st.send2[i][1 - b], j)) & (q - 1);
                rs = (rs + mine) & (q - 1);
            }
            var o = one_of_n_receive(st.recv16[r * st.tau + j], LP, be32(j));
            rows.push({ rs: rs, bp: o.choice, mask: o.string });
        }
        var bb = Int32Array.from(rows, function (w) { return ((w.rs % DELTA) - w.bp + DELTA) % DELTA; });
        var msg = new Uint8Array(REQ_BYTES);
        msg.set(be32(j), 0);
        pack_bits(e, LQ, msg, 4);
        pack_bits(bb, LD, msg, 4 + NOT2 * LQ / 8);
        return { state: { j: j, rows: rows }, msg: msg };
    }

    /**
     * Server, online: the response. THROWS on a malformed or replayed
     * request. The metadata t enters through the client's a = RO(t, x): a
     * semi-honest client uses the t it was given.
     */
    function blind_evaluate(st, msg) {
        if (!(msg instanceof Uint8Array) || msg.length !== REQ_BYTES) { throw new Error('pool: a request is ' + REQ_BYTES + ' bytes'); }
        var j = (msg[0] << 24 | msg[1] << 16 | msg[2] << 8 | msg[3]) >>> 0;
        take(st, j);
        var e = unpack_bits(msg, 4, NOT2, LQ, new Int32Array(NOT2)), bb = unpack_bits(msg, 4 + NOT2 * LQ / 8, ROWS, LD, new Int32Array(ROWS));
        var y = new Int32Array(ROWS * DELTA);
        for (var r = 0; r < ROWS; r++) {
            var acc = 0;
            for (var i = r * n; i < (r + 1) * n; i++) {
                var mine = rq(st.recv2[i].key, j);
                acc += sk_bit(st.sk, i) ? e[i] - mine : mine;
            }
            acc &= q - 1;
            var strings = one_of_n_send(st.send16[r * st.tau + j], LP, be32(j));
            for (var k = 0; k < DELTA; k++) { y[r * DELTA + k] = (round_qp((acc - k) & (q - 1)) + strings[(k - bb[r] + DELTA) % DELTA]) & (p - 1); }
        }
        var out = new Uint8Array(RESP_BYTES);
        out.set(be32(j), 0);
        pack_bits(y, LP, out, 4);
        return out;
    }

    /** Client: F_sk(t, x), 16 bytes. */
    function finalize(rq_state, msg) {
        if (!(msg instanceof Uint8Array) || msg.length !== RESP_BYTES) { throw new Error('pool: a response is ' + RESP_BYTES + ' bytes'); }
        if (((msg[0] << 24 | msg[1] << 16 | msg[2] << 8 | msg[3]) >>> 0) !== rq_state.j) { throw new Error('pool: the response is for another use'); }
        var y = unpack_bits(msg, 4, ROWS * DELTA, LP, new Int32Array(ROWS * DELTA)), z = new Int32Array(ROWS);
        for (var r = 0; r < ROWS; r++) {
            var w = rq_state.rows[r], low = w.rs % DELTA;
            z[r] = (y[r * DELTA + low] - w.mask - (w.rs - low) / DELTA) & (p - 1);
        }
        var o = new Uint8Array(OUT_BYTES);
        pack_bits(z, LP, o, 0);
        return o;
    }

    return {
        NAME: name, N: n, P: p, Q: q, DELTA: DELTA, ROWS: ROWS, SK_BYTES: SK_BYTES, OUT_BYTES: OUT_BYTES,
        REQUEST_BYTES: REQ_BYTES, RESPONSE_BYTES: RESP_BYTES,
        /** random OTs one preprocessing of tau uses needs: 1-of-2 with the client sending, and 1-of-2 with the server sending */
        OTS_CLIENT_SENDS: NOT2, OTS_SERVER_SENDS: function (tau) { return ROWS * tau * LD; },
        keygen: keygen, evaluate: evaluate,
        server_preprocess: server_preprocess, client_preprocess: client_preprocess,
        request: request, blind_evaluate: blind_evaluate, finalize: finalize
    };
}

export var POOL_128 = /* @__PURE__ */ pool('POOL_128');
export var POOL_128_P4 = /* @__PURE__ */ pool('POOL_128_P4');
export var POOL_100 = /* @__PURE__ */ pool('POOL_100');
export var POOL_100_P4 = /* @__PURE__ */ pool('POOL_100_P4');
