/**
 * pve.js - publicly verifiable encryption of a discrete log.
 *
 *     public   G, X = x*G, a recipient's X-Wing key ek, a label
 *     output   a ciphertext of x to ek, and a proof - checkable by ANYONE,
 *              with no secret - that ek's holder will recover exactly the x
 *              behind X
 *
 * The use is a backup: a party encrypts its key share to a recovery key and
 * hands the result to someone who can check it but not open it. Nobody has to
 * find out on the day it is needed that the backup was empty.
 *
 * ==================== CUT AND CHOOSE ====================
 *
 * Per repetition k, the prover splits x in two and encrypts both halves:
 *
 *     r0 <- random,  r1 = x - r0
 *     ct0 = Enc(ek, r0; seed0),  ct1 = Enc(ek, r1; seed1),  R0 = r0*G
 *
 * The challenge bit b (Fiat-Shamir over everything) OPENS one half: r_b and
 * seed_b are published, so anyone re-encrypts and compares, and checks
 * r_b*G = R_b (with R1 = X - R0). The other ciphertext stays closed. One half
 * says nothing about x: r0 is uniform, and so is x - r0.
 *
 * Decryption opens a closed half r', checks r'*G = R_{1-b} - so a garbage
 * closed half is noticed, not used - and returns x = r_b + r'. A prover who
 * made the closed half wrong in repetition k had to guess that bit; to make
 * EVERY closed half wrong it has to guess all of them. 128 repetitions:
 * soundness 2^-128 per hash query, the margin an offline Fiat-Shamir proof
 * needs.
 *
 * ⭐ WHY CUT AND CHOOSE AND NOT A SIGMA PROTOCOL. A sigma proof of "this
 *   ciphertext holds the discrete log of X" needs an encryption that is
 *   homomorphic in a group the curve can talk to - ElGamal in the exponent,
 *   Paillier, Camenisch-Shoup. None of those is post-quantum. Cut and choose
 *   asks only that encryption be DETERMINISTIC GIVEN ITS RANDOMNESS, so the
 *   verifier can redo an opened one - and X-Wing (ML-KEM-768 + X25519) is,
 *   through encaps_derand. The backup stays closed to a quantum computer; the
 *   statement about X is as strong as X itself.
 *
 * ⚠ THE PRICE IS SIZE: one X-Wing ciphertext per repetition stays in the
 *   proof - 128 x 1120 bytes, about 160 KB per backup on a 32-byte curve.
 *   Creating one costs 256 encapsulations, checking it 128; opening it,
 *   usually one decapsulation.
 *
 * Each half is encrypted as X-Wing (encaps_derand) -> a key from the shared
 * secret and the piece's context -> ChaCha20-Poly1305 under a zero nonce (the
 * key is used once). The label is the session binding: the caller puts in it
 * whatever the backup must not be moved away from - the key, the party, the
 * epoch.
 */

import { concat, ascii, be16, be8 } from './commons/bytes.js';
import { bit_le as bit } from './commons/bitpack.js';
import { require_rng, mod } from './commons/primes.js';
import { fs_stream, fs_bits, require_sid } from './commons/zk_bytes.js';
import { shake256, sha3_256 } from './sha3.js';
import { chacha20poly1305_encrypt, chacha20poly1305_decrypt } from './chacha.js';
import * as xwing from './xwing.js';

var TAG = 'cryptographic-primitives/pve-dlog/v1';
var KEY_TAG = /* @__PURE__ */ ascii(TAG + '/key');
var NONCE = /* @__PURE__ */ new Uint8Array(12);
var REPS = 128;
var SEED = 64;                      /* X-Wing eseed */
var KEM_CT = 1120;
var TAG_BYTES = 16;                 /* Poly1305 */

function point_len(G) { return G.encode(G.GENERATOR).length; }
function piece_len(G) { return KEM_CT + G.SCALAR_BYTES + TAG_BYTES; }
function open_len(G) { return G.SCALAR_BYTES + SEED; }

/** The context of one half: the label's hash, the repetition and the side. */
function piece_ctx(lh, k, b) { return concat([lh, be16(k), be8(b)]); }

/** One half, encrypted deterministically from its seed. */
function piece(G, ek, seed, r, ctx) {
    var e = xwing.encaps_derand(ek, seed);
    var key = shake256(concat([KEY_TAG, e.ss, ctx]), 32);
    try {
        return concat([e.ct, chacha20poly1305_encrypt(key, NONCE, G.scalar_bytes(r), ctx)]);
    } finally { e.ss.fill(0); key.fill(0); }
}

/** The plaintext of a closed half, or null. */
function unpiece(G, dk, bytes, ctx) {
    var ss = xwing.decaps(dk, bytes.subarray(0, KEM_CT));
    var key = shake256(concat([KEY_TAG, ss, ctx]), 32);
    try {
        var pt = chacha20poly1305_decrypt(key, NONCE, bytes.subarray(KEM_CT), ctx);
        return pt ? G.scalar_from_bytes(pt) : null;
    } catch (err) { return null; }
    finally { ss.fill(0); key.fill(0); }
}

function challenge(G, X, ek, label, R, pieces) {
    var parts = [G.name, G.encode(X), sha3_256(ek), BigInt(REPS)];
    for (var k = 0; k < REPS; k++) { parts.push(R[k], pieces[k][0], pieces[k][1]); }
    return fs_bits(fs_stream(TAG, label, parts), REPS);
}

function bits_bytes(c) {
    var out = new Uint8Array(REPS >> 3);
    for (var i = 0; i < REPS; i++) { if (c[i]) { out[i >> 3] |= 1 << (i & 7); } }
    return out;
}

/**
 * Encrypt x (with X = x*G) to the X-Wing key ek, with the proof.
 *
 * @param {object}     G      prime-order group
 * @param {bigint}     x      the secret, in [1, ORDER)
 * @param {Uint8Array} ek     the recipient's X-Wing public key, 1216 bytes
 * @param {Uint8Array} label  the binding - required, as a sid is
 * @param {function}   rng
 * @return {{c: Uint8Array, R: Uint8Array[], open: Uint8Array[], kept: Uint8Array[]}}
 */
export function encrypt(G, x, ek, label, rng) {
    require_sid('pve', label);
    rng = require_rng('pve.encrypt', rng);
    if (!xwing.check_public_key(ek)) { throw new Error('pve: ek is not an X-Wing public key'); }
    x = mod(x, G.ORDER);
    if (x === 0n) { throw new RangeError('pve: x must not be zero'); }
    var X = G.base_mul(x);
    var lh = sha3_256(label);
    var R = [], halves = [], seeds = [], pieces = [];
    for (var k = 0; k < REPS; k++) {
        var r0;
        do { r0 = G.random_scalar(rng); } while (r0 === x);      /* R1 = X - R0 must not be the identity */
        var h = [r0, mod(x - r0, G.ORDER)], s = [rng(SEED), rng(SEED)];
        R.push(G.encode(G.base_mul(r0)));
        pieces.push([piece(G, ek, s[0], h[0], piece_ctx(lh, k, 0)),
                     piece(G, ek, s[1], h[1], piece_ctx(lh, k, 1))]);
        halves.push(h); seeds.push(s);
    }
    var c = challenge(G, X, ek, label, R, pieces);
    var open = [], kept = [];
    for (var j = 0; j < REPS; j++) {
        var b = c[j];
        open.push(concat([G.scalar_bytes(halves[j][b]), seeds[j][b]]));
        kept.push(pieces[j][1 - b]);
        halves[j][0] = halves[j][1] = 0n;
        seeds[j][0].fill(0); seeds[j][1].fill(0);
    }
    return { c: bits_bytes(c), R: R, open: open, kept: kept };
}

/** The halves' points, and the proof's shape - or null. */
function parse(G, X, pve) {
    if (!pve || !(pve.c instanceof Uint8Array) || pve.c.length !== REPS >> 3) { return null; }
    if (!Array.isArray(pve.R) || !Array.isArray(pve.open) || !Array.isArray(pve.kept)) { return null; }
    if (pve.R.length !== REPS || pve.open.length !== REPS || pve.kept.length !== REPS) { return null; }
    var pts = [];
    for (var k = 0; k < REPS; k++) {
        var R0 = G.decode(pve.R[k]);
        if (!R0) { return null; }
        var R1 = G.add(X, G.neg(R0));
        if (G.equals(R1, G.IDENTITY)) { return null; }
        if (!(pve.open[k] instanceof Uint8Array) || pve.open[k].length !== open_len(G)) { return null; }
        if (!(pve.kept[k] instanceof Uint8Array) || pve.kept[k].length !== piece_len(G)) { return null; }
        pts.push([R0, R1]);
    }
    return pts;
}

/**
 * Anyone's check: ek's holder will recover the x behind X from this.
 *
 * @return {boolean}
 */
export function verify(G, X, ek, label, pve) {
    require_sid('pve', label);
    try {
        if (!X || G.equals(X, G.IDENTITY) || !xwing.check_public_key(ek)) { return false; }
        var pts = parse(G, X, pve);
        if (!pts) { return false; }
        var lh = sha3_256(label), pieces = [];
        for (var k = 0; k < REPS; k++) {
            var b = bit(pve.c, k);
            var r = G.scalar_from_bytes(pve.open[k].subarray(0, G.SCALAR_BYTES));
            if (r === null) { return false; }
            /* r is public here: it was opened */
            if (!G.equals(G.mul_vartime(r, G.GENERATOR), pts[k][b])) { return false; }
            var redo = piece(G, ek, pve.open[k].slice(G.SCALAR_BYTES), r, piece_ctx(lh, k, b));
            pieces.push(b ? [pve.kept[k], redo] : [redo, pve.kept[k]]);
        }
        var c = challenge(G, X, ek, label, pve.R, pieces);
        for (var j = 0; j < REPS; j++) { if (c[j] !== bit(pve.c, j)) { return false; } }
        return true;
    } catch (err) {
        return false;
    }
}

/**
 * The recipient's side: x, checked against X.
 *
 * Verifies first - a proof that does not verify is refused rather than mined
 * for whatever half happens to open.
 *
 * @param {Uint8Array} dk  the X-Wing secret key (32-byte seed)
 * @return {bigint}
 */
export function decrypt(G, X, dk, label, pve) {
    require_sid('pve', label);
    var ek = xwing.public_key(dk);
    if (!verify(G, X, ek, label, pve)) { throw new Error('pve: the proof does not verify for this key, X and label'); }
    var pts = parse(G, X, pve), lh = sha3_256(label);
    for (var k = 0; k < REPS; k++) {
        var b = bit(pve.c, k);
        var other = unpiece(G, dk, pve.kept[k], piece_ctx(lh, k, 1 - b));
        if (other === null || !G.equals(G.base_mul(other), pts[k][1 - b])) { continue; }
        var x = mod(G.scalar_from_bytes(pve.open[k].subarray(0, G.SCALAR_BYTES)) + other, G.ORDER);
        if (G.equals(G.base_mul(x), X)) { return x; }
    }
    /* unreachable for a verified proof, except with probability 2^-128 */
    throw new Error('pve: no closed half decrypts consistently');
}

/* ---------------- serialisation: fixed widths, no framing ---------------- */

/** The encoded size on G. */
export function size(G) { return (REPS >> 3) + REPS * (point_len(G) + open_len(G) + piece_len(G)); }

export function encode(G, pve) {
    var parts = [pve.c];
    for (var k = 0; k < REPS; k++) { parts.push(pve.R[k], pve.open[k], pve.kept[k]); }
    var out = concat(parts);
    if (out.length !== size(G)) { throw new Error('pve: malformed proof'); }
    return out;
}

/** @return {object|null} null if the length is wrong */
export function decode(G, bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== size(G)) { return null; }
    var pl = point_len(G), ol = open_len(G), kl = piece_len(G), off = REPS >> 3;
    var out = { c: bytes.slice(0, off), R: [], open: [], kept: [] };
    for (var k = 0; k < REPS; k++) {
        out.R.push(bytes.slice(off, off += pl));
        out.open.push(bytes.slice(off, off += ol));
        out.kept.push(bytes.slice(off, off += kl));
    }
    return out;
}

export { REPS };
