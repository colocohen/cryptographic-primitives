/**
 * sr25519 — Schnorr signatures over ristretto255 with Merlin transcripts.
 *
 *     schnorrkel (the Rust crate, w3f / Polkadot), its byte layouts exactly:
 *     sign / verify, the soft and hard key derivation (HDKD), the VRF and the
 *     shared secret. Checked against @scure/sr25519 (test/curves_sr25519).
 *
 * The signature is the ordinary Schnorr one,
 *
 *     R = r·G,   s = r + k·x,   checked as  R = s·G − k·A
 *
 * on ristretto255 (no cofactor), with the challenge k drawn from a Merlin
 * transcript (merlin.js) rather than from a hash of a concatenation:
 *
 *     Transcript("SigningContext")
 *       append ""            context        ← the signing context (Polkadot: "substrate")
 *       append "sign-bytes"  message
 *       append "proto-name"  "Schnorr-sig"
 *       append "sign:pk"     A
 *       append "sign:R"      R
 *       k = challenge "sign:c", 64 bytes, reduced mod ℓ
 *
 * ⭐ THE CONTEXT IS PART OF WHAT IS SIGNED. A signature under one context
 *    does not verify under another; it is the application's to choose, and
 *    nothing here assumes one.
 *
 * ⭐ THE MARKER BIT. The top bit of the last byte of s is set (s < 2^253
 *    leaves it free), so a schnorrkel signature cannot be mistaken for an
 *    Ed25519 one. Verify refuses a signature without it.
 *
 * ⭐ THE SECRET KEY FORMAT is 64 bytes, key ‖ nonce, the key half in the
 *    "Ed25519 form" (the scalar times the cofactor 8, little-endian) — the
 *    format of @scure/sr25519 and polkadot-js. The nonce half seeds the
 *    signing nonce; it is not the signing nonce.
 *
 * ⭐ FOR THRESHOLD SIGNING (FROST, frost_codec.js suite "sr25519") the
 *    message and the context travel together as one byte string,
 *    `signing_message(context, message)`, and `challenge_of` computes k from
 *    it. A party's share is the ordinary FROST share; the sum verifies here.
 */

import { Transcript } from './merlin.js';
import { GROUP as G, ORDER, BASE, from_uniform_bytes, double_mul_vartime } from './ristretto255.js';
import { sha512 } from './sha2.js';
import { concat, le32, text_or_bytes, secure_random, bytes_to_bigint_le, bigint_to_bytes_le } from './commons/bytes.js';
import { batch_all, batch_find, batch_items, group_batch_holds } from './commons/batch.js';

var L = ORDER;
var EMPTY = new Uint8Array(0);

function bytes(x, what, len) {
    x = text_or_bytes(x);
    if (!(x instanceof Uint8Array)) { throw new TypeError('sr25519: ' + what + ' must be bytes'); }
    if (len != null && x.length !== len) { throw new RangeError('sr25519: ' + what + ' must be ' + len + ' bytes'); }
    return x;
}
function scalar_wide(b) { return bytes_to_bigint_le(b) % L; }

/* ---------------- keys ---------------- */

/** The secret scalar of a 64-byte secret key (the key half divided by 8). */
function secret_scalar(secretKey) {
    return bytes_to_bigint_le(bytes(secretKey, 'secretKey', 64).subarray(0, 32)) >> 3n;
}
/** A 64-byte secret key from a scalar and a 32-byte nonce seed. */
function encode_secret(x, nonce) {
    var mask = (1n << 256n) - 1n;
    return concat([bigint_to_bytes_le(((x % L) << 3n) & mask, 32), bytes(nonce, 'nonce', 32)]);
}
/**
 * A 32-byte mini secret (seed) → a 64-byte secret key, schnorrkel's
 * ExpandMode::Ed25519 (what Substrate uses): SHA-512, clamped as Ed25519,
 * divided by the cofactor; the upper half is the nonce seed.
 */
function secret_from_seed(seed) {
    var h = sha512(bytes(seed, 'seed', 32));
    h[0] &= 248; h[31] &= 63; h[31] |= 64;
    var x = bytes_to_bigint_le(h.subarray(0, 32)) >> 3n;
    var out = encode_secret(x, h.subarray(32, 64));
    h.fill(0);
    return out;
}
function get_public_key(secretKey) {
    return G.encode(G.base_mul(secret_scalar(secretKey)));
}
/**
 * A key pair: { sk: the 64-byte secret key, pk: 32 bytes }, as sign, verify
 * and get_public_key take them. The seed is the 32-byte mini secret that
 * Substrate stores, expanded by secret_from_seed; omitted or null draws a
 * fresh one from the platform.
 */
function keygen(seed) {
    var mini = seed == null ? secure_random(32) : seed;
    var sk = secret_from_seed(mini);
    if (seed == null) { mini.fill(0); }
    return { sk: sk, pk: get_public_key(sk) };
}
/** A public key, decoded: a ristretto255 point other than the identity, or null. */
function decode_public_key(pk) {
    if (!(pk instanceof Uint8Array) || pk.length !== 32) { return null; }
    var A = G.decode(pk);
    return A == null || G.equals(A, G.IDENTITY) ? null : A;
}

/* ---------------- the transcript and the challenge ---------------- */

/** Transcript("SigningContext") with the context and the message, schnorrkel's SigningContext::bytes. */
function signing_transcript(context, message) {
    var t = new Transcript('SigningContext');
    t.append_message('', bytes(context, 'context'));
    t.append_message('sign-bytes', bytes(message, 'message'));
    return t;
}
/** k, the challenge, for a context, a message, a public key and R (both 32 bytes). */
function challenge(context, message, publicKey, R) {
    var t = signing_transcript(context, message);
    t.append_message('proto-name', 'Schnorr-sig');
    t.append_message('sign:pk', bytes(publicKey, 'publicKey', 32));
    t.append_message('sign:R', bytes(R, 'R', 32));
    return scalar_wide(t.challenge_bytes('sign:c', 64));
}

/**
 * The context and the message as one byte string — what FROST signs and
 * binds its nonces to (frost_codec suite "sr25519"): LE32(|context|) ‖
 * context ‖ message. Unambiguous: the length fixes where the message begins.
 */
function signing_message(context, message) {
    var c = bytes(context, 'context'), m = bytes(message, 'message');
    return concat([le32(c.length), c, m]);
}
/** The inverse of signing_message, or null. */
function split_signing_message(sm) {
    if (!(sm instanceof Uint8Array) || sm.length < 4) { return null; }
    var n = sm[0] | (sm[1] << 8) | (sm[2] << 16) | (sm[3] << 24);
    if (n < 0 || 4 + n > sm.length) { return null; }
    return { context: sm.subarray(4, 4 + n), message: sm.subarray(4 + n) };
}
/** k from a signing_message — the challenge FROST computes. */
function challenge_of(sm, publicKey, R) {
    var p = split_signing_message(sm);
    if (p == null) { throw new TypeError('sr25519: not a signing message (signing_message(context, message))'); }
    return challenge(p.context, p.message, publicKey, R);
}

/* ---------------- signatures ---------------- */

/** R (32 bytes) and s → the 64-byte signature, with the schnorrkel marker. */
function encode_signature(R, s) {
    var out = concat([bytes(R, 'R', 32), bigint_to_bytes_le(s % L, 32)]);
    out[63] |= 0x80;
    return out;
}
/** A 64-byte signature → { R (bytes), Rp (point), s }, or null: marker set, R a point, s canonical. */
function decode_signature(sig) {
    if (!(sig instanceof Uint8Array) || sig.length !== 64 || (sig[63] & 0x80) === 0) { return null; }
    var sb = Uint8Array.from(sig.subarray(32, 64));
    sb[31] &= 0x7f;
    var s = bytes_to_bigint_le(sb);
    if (s >= L) { return null; }
    var R = sig.subarray(0, 32), Rp = G.decode(R);
    if (Rp == null) { return null; }
    return { R: Uint8Array.from(R), Rp: Rp, s: s };
}

/**
 * Sign. `random` (32 bytes) feeds the nonce with the transcript and the
 * key's nonce seed; given, the signature is deterministic.
 */
function sign(secretKey, message, context, random) {
    if (context == null) { throw new TypeError('sr25519: sign needs a signing context (Polkadot: "substrate")'); }
    var x = secret_scalar(secretKey), nonce = bytes(secretKey, 'secretKey', 64).subarray(32, 64);
    var A = G.encode(G.base_mul(x));
    var t = signing_transcript(context, message);
    t.append_message('proto-name', 'Schnorr-sig');
    t.append_message('sign:pk', A);
    var r = scalar_wide(t.witness_bytes(64, [{ label: 'signing', bytes: nonce }], random || secure_random(32)));
    var R = G.encode(G.base_mul(r));
    t.append_message('sign:R', R);
    var k = scalar_wide(t.challenge_bytes('sign:c', 64));
    var s = (k * x + r) % L;
    t.wipe();
    return encode_signature(R, s);
}

/** Verify. Never throws on malformed input: false. */
function verify(message, signature, publicKey, context) {
    var v = verify_input(message, signature, publicKey, context);
    /* s·B − k·A in one walk: both scalars are public */
    return v !== null && G.equals(double_mul_vartime(v.s, BASE, (L - v.c) % L, v.P), v.R);
}

/*
 * Everything verify checks before the equation: { R, P, s, c, key }, or
 * null. ⭐ ONE FUNCTION for verify and both batch checks.
 */
function verify_input(message, signature, publicKey, context) {
    if (context == null) { throw new TypeError('sr25519: verify needs the signing context it was signed under'); }
    var A = decode_public_key(publicKey), d = decode_signature(signature);
    if (A == null || d == null) { return null; }
    return { R: d.Rp, P: A, s: d.s, c: challenge(context, message, publicKey, d.R), key: publicKey };
}

/*
 * ⭐ BATCH VERIFICATION (commons/batch.js; schnorrkel has verify_batch too):
 *    items [{ msg, sig, pk, ctx }]. verify_batch is true when every item
 *    verifies; verify_batch_find gives the indices of those verify rejects.
 *    The same checks (verify_input), and ristretto255 - a prime-order group -
 *    so the summed equation answers as verify does.
 */
var BATCH_MIN = 8;
function verify_batch(items, opts) {
    var c = batch_checks(items, opts, 'sr25519.verify_batch');
    return batch_all(items, c.holds, c.one, BATCH_MIN);
}
function verify_batch_find(items, opts) {
    var c = batch_checks(items, opts, 'sr25519.verify_batch_find');
    return batch_find(items, c.holds, c.one, BATCH_MIN);
}
function batch_checks(items, opts, who) {
    batch_items(items, who);
    var rng = (opts && opts.rng) || secure_random;
    return {
        holds: function (sub) {
            var entries = [];
            for (var i = 0; i < sub.length; i++) {
                var v = verify_input(sub[i].msg, sub[i].sig, sub[i].pk, sub[i].ctx);
                if (v === null) { return false; }
                entries.push(v);
            }
            return group_batch_holds(G, entries, rng, who);
        },
        one: function (it) { return verify(it.msg, it.sig, it.pk, it.ctx); }
    };
}

/* ---------------- key derivation (HDKD) ---------------- */

function hdkd_transcript(chainCode) {
    var t = new Transcript('SchnorrRistrettoHDKD');
    t.append_message('sign-bytes', EMPTY);
    t.append_message('chain-code', bytes(chainCode, 'chainCode', 32));
    return t;
}

/**
 * Soft derivation from the PUBLIC key: { tweak, chainCode, publicKey }.
 * The child key is A + tweak·G — so a threshold key derives it with the
 * tweak alone, every holder on its own (schnorrkel derived_key_simple).
 */
function derive_soft(publicKey, chainCode) {
    var A = decode_public_key(publicKey);
    if (A == null) { throw new TypeError('sr25519: publicKey is not a key'); }
    var t = hdkd_transcript(chainCode);
    t.append_message('public-key', publicKey);
    var tweak = scalar_wide(t.challenge_bytes('HDKD-scalar', 64));
    var cc = t.challenge_bytes('HDKD-chaincode', 32);
    t.wipe();
    return { tweak: tweak, chainCode: cc, publicKey: G.encode(G.add(A, G.base_mul(tweak))) };
}
/** Soft derivation of a secret key (the child's nonce seed is drawn with `random`). */
function secret_soft(secretKey, chainCode, random) {
    var x = secret_scalar(secretKey), nonce = secretKey.subarray(32, 64);
    var A = G.encode(G.base_mul(x));
    var t = hdkd_transcript(chainCode);
    t.append_message('public-key', A);
    var tweak = scalar_wide(t.challenge_bytes('HDKD-scalar', 64));
    t.challenge_bytes('HDKD-chaincode', 32);
    var seed = concat([bigint_to_bytes_le(x, 32), nonce]);
    var child_nonce = t.witness_bytes(32, [{ label: 'HDKD-nonce', bytes: nonce }, { label: 'HDKD-nonce', bytes: seed }], random || secure_random(32));
    seed.fill(0); t.wipe();
    return encode_secret((x + tweak) % L, child_nonce);
}
/**
 * Hard derivation: needs the secret key itself — a new mini secret from
 * the key and the chain code. ⚠️ Under MPC nobody holds the key, so a
 * threshold key has no hard children; give each account its own key.
 */
function secret_hard(secretKey, chainCode) {
    var t = hdkd_transcript(chainCode);
    var kb = bigint_to_bytes_le(secret_scalar(secretKey), 32);
    t.append_message('secret-key', kb);
    var msk = t.challenge_bytes('HDKD-hard', 32);
    t.challenge_bytes('HDKD-chaincode', 32);
    t.wipe(); kb.fill(0);
    var out = secret_from_seed(msk);
    msk.fill(0);
    return out;
}

/** The shared secret: x·B, encoded (schnorrkel / @scure getSharedSecret). */
function shared_secret(secretKey, publicKey) {
    var B = decode_public_key(publicKey);
    if (B == null) { throw new TypeError('sr25519: publicKey is not a key'); }
    return G.encode(G.mul(secret_scalar(secretKey), B));
}

/* ---------------- VRF ---------------- */

/*
 * The VRF's input is a Merlin transcript: (context, message) as
 * SigningContext::bytes builds it — what @scure/sr25519 takes — or any
 * transcript, as { label, items: [[label, bytes], …] } (Substrate's
 * VrfTranscript; a u64 is its 8 little-endian bytes, Merlin's append_u64).
 */
function vrf_transcript(context, message) {
    if (message != null && typeof message === 'object' && !(message instanceof Uint8Array)) {
        if (typeof message.label !== 'string' && !(message.label instanceof Uint8Array)) { throw new TypeError('sr25519: a VRF transcript is { label, items }'); }
        var t = new Transcript(message.label);
        for (var i = 0; i < (message.items || []).length; i++) { t.append_message(message.items[i][0], bytes(message.items[i][1], 'a transcript item')); }
        return t;
    }
    return signing_transcript(context || EMPTY, message);
}
/** H, the VRF's input point, for an input and a key — schnorrkel's vrf_hash. */
function vrf_input_point(context, message, publicKey) {
    var t = vrf_transcript(context, message);
    t.append_message('vrf-nm-pk', bytes(publicKey, 'publicKey', 32));
    var H = from_uniform_bytes(t.challenge_bytes('VRFHash', 64));
    t.wipe();
    return H;
}
/** The DLEQ transcript: "VRF", with the extra data when there is any. */
function dleq_transcript(extra, H) {
    var d = new Transcript('VRF');
    var e = bytes(extra || EMPTY, 'extra');
    if (e.length) { d.append_message('', e); }
    d.append_message('proto-name', 'DLEQProof');
    d.append_message('vrf:h', G.encode(H));
    return d;
}
function dleq_tail(t, R, Hr, publicKey, output) {
    t.append_message('vrf:R=g^r', G.encode(R));
    t.append_message('vrf:h^r', G.encode(Hr));
    t.append_message('vrf:pk', publicKey);
    t.append_message('vrf:h^sk', G.encode(output));
    var c = scalar_wide(t.challenge_bytes('prove', 64));
    t.wipe();
    return c;
}
/**
 * c, the DLEQ challenge, from its commitments R = r·G and Hr = r·H — what a
 * threshold signer needs (a protocol sums R and Hr over the signers, then
 * each answers s_i = r_i − c·λ_i·x_i).
 */
function vrf_challenge(extra, H, R, Hr, publicKey, output) {
    return dleq_tail(dleq_transcript(extra, H), R, Hr, publicKey, output);
}
/** output ‖ c ‖ s, 96 bytes. */
function vrf_encode(output, c, s) {
    return concat([G.encode(output), bigint_to_bytes_le(c, 32), bigint_to_bytes_le(s, 32)]);
}

/**
 * The schnorrkel VRF: output ‖ c ‖ s, 96 bytes. The output point is
 * x·H(input, key); the proof is a DLEQ that it is the key's.
 * `message` is bytes (with `context`), or a transcript { label, items }.
 */
function vrf_sign(message, secretKey, context, extra, random) {
    var x = secret_scalar(secretKey), nonce = secretKey.subarray(32, 64);
    var A = G.encode(G.base_mul(x));
    var H = vrf_input_point(context, message, A);
    var out = G.mul(x, H), t = dleq_transcript(extra, H);
    var r = scalar_wide(t.witness_bytes(64, [{ label: 'proving\u00000', bytes: nonce }], random || secure_random(32)));
    var c = dleq_tail(t, G.base_mul(r), G.mul(r, H), A, out);
    return vrf_encode(out, c, ((r - c * x) % L + L) % L);
}
/** Verify a VRF proof; false on anything malformed. */
function vrf_verify(message, proof, publicKey, context, extra) {
    var A = decode_public_key(publicKey);
    if (A == null || !(proof instanceof Uint8Array) || proof.length !== 96) { return false; }
    var out = G.decode(proof.subarray(0, 32));
    var c = bytes_to_bigint_le(proof.subarray(32, 64)), s = bytes_to_bigint_le(proof.subarray(64, 96));
    if (out == null || G.equals(out, G.IDENTITY) || c >= L || s >= L) { return false; }
    var H = vrf_input_point(context, message, publicKey);
    var R = double_mul_vartime(c, A, s, BASE);
    var Hr = double_mul_vartime(c, out, s, H);
    return vrf_challenge(extra, H, R, Hr, publicKey, out) === c;
}

export {
    keygen, secret_from_seed, secret_scalar, encode_secret, get_public_key, decode_public_key,
    signing_transcript, challenge, signing_message, split_signing_message, challenge_of,
    encode_signature, decode_signature, sign, verify, verify_batch, verify_batch_find,
    derive_soft, secret_soft, secret_hard, shared_secret,
    vrf_transcript, vrf_input_point, vrf_challenge, vrf_encode, vrf_sign, vrf_verify
};
