/**
 * Merlin — transcripts for zero-knowledge proofs and signatures, on STROBE.
 *
 *     https://merlin.cool    (the Rust `merlin` crate, v1.0)
 *     https://strobe.sourceforge.io   (STROBE v1.0.2, the subset Merlin uses)
 *
 * A transcript is the Fiat–Shamir hash done as a conversation: every value
 * the protocol fixes is appended under a label, and a challenge is drawn
 * from everything appended so far. Two protocols, or two steps of one, can
 * only collide by appending the same labels with the same values in the
 * same order — the domain separation is in the structure, not in a tag the
 * caller must remember.
 *
 * sr25519 (sr25519.js) is the reason it is here: schnorrkel computes its
 * challenge, its nonce and its key derivation on Merlin transcripts.
 *
 * ⭐ ONLY WHAT MERLIN USES of STROBE-128: meta-AD, AD, PRF and KEY. The
 *    transport operations (send/receive, with the T flag) are refused, as
 *    in the Rust crate.
 *
 * ⭐ THE STATE IS COPIED, never shared. `clone()` gives a transcript that
 *    continues independently — a challenge drawn on one does not move the
 *    other — which is what a signer needs to derive its nonce from the
 *    transcript without changing the transcript the verifier rebuilds.
 */

import { keccak_f1600 } from './commons/keccak.js';
import { ascii, le32 as le32_bytes, text_or_bytes, secure_random } from './commons/bytes.js';

var STROBE_R = 166;
var FLAG_I = 1, FLAG_A = 2, FLAG_C = 4, FLAG_T = 8, FLAG_M = 16, FLAG_K = 32;

function bytes_of(x, what) {
    var b = text_or_bytes(x);
    if (!(b instanceof Uint8Array)) { throw new TypeError('merlin: ' + what + ' must be bytes or a string'); }
    return b;
}
/** Merlin's lengths are u32: refused past 2^32, not wrapped. */
function le32(n) {
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) { throw new RangeError('merlin: a length must fit in 32 bits'); }
    return le32_bytes(n);
}

/* ---------------- STROBE-128, Merlin's subset ---------------- */

function Strobe128(label) {
    this.state = new Uint8Array(200);
    this.pos = 0; this.pos_begin = 0; this.cur_flags = 0;
    if (label === undefined) { return; }       // clone(): filled in by the caller
    this.state.set([1, STROBE_R + 2, 1, 0, 1, 96], 0);
    this.state.set(ascii('STROBEv1.0.2'), 6);
    keccak_f1600(this.state);
    this.meta_ad(bytes_of(label, 'label'), false);
}
Strobe128.prototype.run_f = function () {
    this.state[this.pos] ^= this.pos_begin;
    this.state[this.pos + 1] ^= 0x04;
    this.state[STROBE_R + 1] ^= 0x80;
    keccak_f1600(this.state);
    this.pos = 0; this.pos_begin = 0;
};
Strobe128.prototype.absorb = function (d) {
    for (var i = 0; i < d.length; i++) { this.state[this.pos++] ^= d[i]; if (this.pos === STROBE_R) { this.run_f(); } }
};
Strobe128.prototype.overwrite = function (d) {
    for (var i = 0; i < d.length; i++) { this.state[this.pos++] = d[i]; if (this.pos === STROBE_R) { this.run_f(); } }
};
Strobe128.prototype.squeeze = function (n) {
    var out = new Uint8Array(n);
    for (var i = 0; i < n; i++) {
        out[i] = this.state[this.pos]; this.state[this.pos++] = 0;
        if (this.pos === STROBE_R) { this.run_f(); }
    }
    return out;
};
Strobe128.prototype.begin_op = function (flags, more) {
    if (more) {
        if (this.cur_flags !== flags) { throw new Error('strobe: a continued operation changed its flags'); }
        return;
    }
    if (flags & FLAG_T) { throw new Error('strobe: transport operations are not supported'); }
    var old = this.pos_begin;
    this.pos_begin = this.pos + 1;
    this.cur_flags = flags;
    this.absorb(new Uint8Array([old, flags]));
    if ((flags & (FLAG_C | FLAG_K)) !== 0 && this.pos !== 0) { this.run_f(); }
};
Strobe128.prototype.meta_ad = function (d, more) { this.begin_op(FLAG_M | FLAG_A, more); this.absorb(d); };
Strobe128.prototype.ad = function (d, more) { this.begin_op(FLAG_A, more); this.absorb(d); };
Strobe128.prototype.prf = function (n, more) { this.begin_op(FLAG_I | FLAG_A | FLAG_C, more); return this.squeeze(n); };
Strobe128.prototype.key = function (d, more) { this.begin_op(FLAG_A | FLAG_C, more); this.overwrite(d); };
Strobe128.prototype.clone = function () {
    var s = new Strobe128();
    s.state.set(this.state); s.pos = this.pos; s.pos_begin = this.pos_begin; s.cur_flags = this.cur_flags;
    return s;
};
Strobe128.prototype.wipe = function () { this.state.fill(0); this.pos = 0; this.pos_begin = 0; this.cur_flags = 0; };

/* ---------------- the transcript ---------------- */

/**
 * A Merlin transcript: `new Transcript('my protocol')`.
 * Labels and messages are bytes, or ASCII strings.
 */
function Transcript(label) {
    if (label === undefined) { return; }       // clone()
    this.strobe = new Strobe128('Merlin v1.0');
    this.append_message('dom-sep', label);
}
/** Append a message under a label. */
Transcript.prototype.append_message = function (label, message) {
    var m = bytes_of(message, 'message');
    this.strobe.meta_ad(bytes_of(label, 'label'), false);
    this.strobe.meta_ad(le32(m.length), true);
    this.strobe.ad(m, false);
    return this;
};
/** Append a u64, little-endian, as Merlin's append_u64. */
Transcript.prototype.append_u64 = function (label, x) {
    var v = BigInt(x), b = new Uint8Array(8);
    if (v < 0n || v >= (1n << 64n)) { throw new RangeError('merlin: a u64'); }
    for (var i = 0; i < 8; i++) { b[i] = Number((v >> BigInt(8 * i)) & 255n); }
    return this.append_message(label, b);
};
/** Draw n challenge bytes under a label; the transcript moves on. */
Transcript.prototype.challenge_bytes = function (label, n) {
    this.strobe.meta_ad(bytes_of(label, 'label'), false);
    this.strobe.meta_ad(le32(n), true);
    return this.strobe.prf(n, false);
};
/**
 * Merlin's TranscriptRng: n bytes from the transcript, the witnesses
 * (each { label, bytes }, rekey_with_witness_bytes) and 32 random bytes
 * (finalize). The transcript itself does not move.
 *
 * ⭐ THE NONCE IS BOUND TO EVERYTHING: the transcript (message, key), the
 *    secret witnesses and fresh randomness. A bad random source alone does
 *    not repeat a nonce across messages; a fixed `random` makes it
 *    deterministic, which is how the test vectors pin it. `random` omitted
 *    or null draws fresh bytes from the platform.
 */
Transcript.prototype.witness_bytes = function (n, witnesses, random) {
    var r = random == null ? secure_random(32) : random;
    if (!(r instanceof Uint8Array) || r.length !== 32) { throw new TypeError('merlin: witness_bytes needs 32 random bytes'); }
    var s = this.strobe.clone();
    try {
        for (var i = 0; i < (witnesses || []).length; i++) {
            var w = bytes_of(witnesses[i].bytes, 'witness');
            s.meta_ad(bytes_of(witnesses[i].label, 'label'), false);
            s.meta_ad(le32(w.length), true);
            s.key(w, false);
        }
        s.meta_ad(ascii('rng'), false);
        s.key(r, false);
        s.meta_ad(le32(n), false);
        return s.prf(n, false);
    } finally { s.wipe(); }
};
Transcript.prototype.clone = function () {
    var t = new Transcript();
    t.strobe = this.strobe.clone();
    return t;
};
Transcript.prototype.wipe = function () { this.strobe.wipe(); };

export { Transcript, Strobe128 };
