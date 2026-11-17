/**
 * Encrypting a long message piece by piece - a file, a network stream -
 * with each piece authenticated on its own.
 *
 *     var enc = chacha20poly1305_stream_create(key, rng);
 *     send(enc.header);
 *     send(enc.push(piece1));
 *     send(enc.push(piece2, true));          // true: the last piece
 *
 *     var dec = chacha20poly1305_stream_open_create(key, header);
 *     dec.push(sealed1);                      // piece1, or null if forged
 *     dec.push(sealed2, true);                // piece2; dec.finished() is true
 *
 * ==================== WHAT A PIECE CARRIES ====================
 *
 * Each piece is sealed by an AEAD (AES-GCM or ChaCha20-Poly1305) under a
 * nonce that holds its position and whether it is the last:
 *
 *     nonce = counter (11 bytes, big-endian) || last (1 byte: 0 or 1)
 *
 * so a piece cannot be moved, repeated, dropped or cut off without its tag
 * failing: a reordered piece is opened at the wrong counter, and a stream
 * truncated after piece k ends on a piece sealed with last = 0, which does
 * not open as the last one. This is the STREAM construction of Hoang,
 * Reyhanitabar, Rogaway and Vizár (CRYPTO 2015), laid out as age's payload
 * (age-encryption.org/v1).
 *
 * ⚠ THE RECEIVER MUST CHECK finished() AT THE END. A stream whose last
 *   piece never arrived opens every piece it has, correctly; only the
 *   missing end says it was cut short.
 *
 * ==================== ONE KEY PER STREAM ====================
 *
 * The header is 16 random bytes, and the stream's key is
 *
 *     HKDF-SHA256(key, salt = header, info = 'cryptographic-primitives stream v1 ' + cipher)
 *
 * so every stream has a key of its own and the counter can start at zero:
 * a long-lived key used for many streams never repeats a (key, nonce) pair,
 * which for both ciphers would give away the plaintexts and the
 * authentication key.
 *
 * ⭐ SYMMETRIC: both sides take (piece, last, aad) - the sender says which
 *   piece is the last, and so does the receiver, who knows it as the end of
 *   the input. The receiver's `last` is checked, not trusted: it is part of
 *   the nonce.
 *
 * The piece size is the caller's: pieces of any length, mixed, are fine;
 * 64 KiB is a common choice. Each sealed piece is 16 bytes longer.
 */

import { hkdf } from './kdf.js';
import { sha256 } from './sha2.js';
import { aes_gcm_create } from './aes.js';
import { chacha20poly1305_create, chacha20, hchacha20, poly1305 } from './chacha.js';
import { ascii } from './commons/bytes.js';
import { equal } from './commons/ct.js';
import { require_rng } from './commons/primes.js';

var HEADER_BYTES = 16;
var INFO = 'cryptographic-primitives stream v1 ';

/* counter as 11 big-endian bytes, then the last-piece flag */
function piece_nonce(counter, last) {
    var n = new Uint8Array(12);
    var c = counter;
    for (var i = 10; i >= 0 && c > 0; i--) {
        n[i] = c % 256;
        c = Math.floor(c / 256);
    }
    n[11] = last ? 1 : 0;
    return n;
}

function stream_key(key, header, name) {
    if (!(header instanceof Uint8Array) || header.length !== HEADER_BYTES) {
        throw new Error('stream: header must be ' + HEADER_BYTES + ' bytes');
    }
    return hkdf(sha256, key, key.length, header, ascii(INFO + name));
}

/*
 * The two sides, over any AEAD context maker: make(key) -> { encrypt(nonce,
 * plaintext, aad), decrypt(nonce, sealed, aad) -> plaintext or null, wipe() }.
 * api/stream.js passes its own contexts, so a piece runs natively when the
 * platform's AEAD is faster for its size (engines/select.js).
 */
export function stream_seal_with(make, name, key, rng) {
    rng = require_rng('stream', rng);
    var header = rng(HEADER_BYTES);
    var k = stream_key(key, header, name);
    var ctx = make(k);
    k.fill(0);
    var counter = 0, ended = false;
    return {
        header: header,
        /** The sealed piece. `last` ends the stream; nothing may follow it. */
        push: function (piece, last, aad) {
            if (ended) { throw new Error('stream: the last piece was already sealed'); }
            var sealed = ctx.encrypt(piece_nonce(counter, !!last), piece, aad);
            counter++;
            if (last) { ended = true; ctx.wipe(); }
            return sealed;
        },
        /** Has the last piece been sealed? */
        finished: function () { return ended; }
    };
}

export function stream_open_with(make, name, key, header) {
    var k = stream_key(key, header, name);
    var ctx = make(k);
    k.fill(0);
    var counter = 0, ended = false;
    return {
        /**
         * The piece, or null when it does not open - forged, out of order,
         * or `last` wrong. A null leaves the stream where it was, so the
         * caller decides whether to stop; it should.
         */
        push: function (sealed, last, aad) {
            if (ended) { throw new Error('stream: the last piece was already opened'); }
            var piece = ctx.decrypt(piece_nonce(counter, !!last), sealed, aad);
            if (piece === null) { return null; }
            counter++;
            if (last) { ended = true; ctx.wipe(); }
            return piece;
        },
        /** Did the last piece arrive and open? Until it does, the stream may have been cut short. */
        finished: function () { return ended; }
    };
}

/* ---------------- the ciphers ---------------- */

function aes_gcm(k) { return aes_gcm_create(k); }
function chacha20poly1305(k) { return chacha20poly1305_create(k); }

/** AES-GCM pieces; the key is 16, 24 or 32 bytes. */
export function aes_gcm_stream_create(key, rng) { return stream_seal_with(aes_gcm, 'aes_gcm', key, rng); }
export function aes_gcm_stream_open_create(key, header) { return stream_open_with(aes_gcm, 'aes_gcm', key, header); }

/** ChaCha20-Poly1305 pieces; the key is 32 bytes. */
export function chacha20poly1305_stream_create(key, rng) { return stream_seal_with(chacha20poly1305, 'chacha20poly1305', key, rng); }
export function chacha20poly1305_stream_open_create(key, header) { return stream_open_with(chacha20poly1305, 'chacha20poly1305', key, header); }

/*
 * ==================== libsodium's secretstream ====================
 *
 * The same idea in libsodium's own format,
 * crypto_secretstream_xchacha20poly1305 - so a stream sealed here opens in
 * any program built on libsodium (PHP's sodium_crypto_secretstream_*,
 * PyNaCl, libsodium.js, ...) and the other way round. It has one cipher,
 * XChaCha20-Poly1305, and its own layout:
 *
 *     header (24 bytes)   random; HChaCha20(key, header[0..16]) is the
 *                         stream's key, header[16..24] the start of its nonce
 *     a sealed piece      1 byte  - the piece's tag, encrypted
 *                         the piece, encrypted
 *                         16 bytes - Poly1305 over the associated data, the
 *                                    encrypted tag block and the piece
 *
 * The tag says what the piece is: 0 a message, 3 the last (FINAL), and 2
 * (REKEY) / 1 (PUSH) libsodium's two others. The receiver here opens any
 * of them; REKEY replaces the key as libsodium does.
 *
 * ⚠ THE PADDING IS libsodium's, NOT RFC 8439's. After the encrypted piece
 *   comes (mlen mod 16) zero bytes - (0x10 - 64 + mlen) & 0xf in its source
 *   - where the AEAD of RFC 8439 pads to a multiple of 16. It is what the
 *   format is, and a tag computed the RFC way matches nothing.
 *
 * ⭐ THE SAME SHAPE AS THE STREAMS ABOVE: push(piece, last, aad) on both
 *   sides, finished(), and the receiver's `last` checked against the tag.
 *   rekey() is libsodium's crypto_secretstream_xchacha20poly1305_rekey: a
 *   new key with no piece sent, which both sides must call at the same
 *   point.
 */
var SS_HEADER_BYTES = 24;
var TAG_MESSAGE = 0, TAG_REKEY = 2, TAG_FINAL = 3;
var ZEROS = new Uint8Array(16);

function le64(n) {
    var b = new Uint8Array(8), v = n;
    for (var i = 0; i < 8; i++) { b[i] = v % 256; v = Math.floor(v / 256); }
    return b;
}

/* the state both sides keep: k, and nonce = counter (4 bytes LE) || inonce (8 bytes) */
function ss_state(key, header) {
    if (!(key instanceof Uint8Array) || key.length !== 32) { throw new Error('secretstream: key must be 32 bytes'); }
    if (!(header instanceof Uint8Array) || header.length !== SS_HEADER_BYTES) {
        throw new Error('secretstream: header must be ' + SS_HEADER_BYTES + ' bytes');
    }
    var st = { k: hchacha20(key, header.subarray(0, 16)), nonce: new Uint8Array(12) };
    st.nonce[0] = 1;   /* counter = 1 */
    st.nonce.set(header.subarray(16, 24), 4);
    return st;
}

function ss_rekey(st) {
    var both = new Uint8Array(40);
    both.set(st.k, 0);
    both.set(st.nonce.subarray(4), 32);
    var fresh = chacha20(st.k, st.nonce, both, 0);
    st.k.fill(0);
    st.k = fresh.slice(0, 32);
    st.nonce.fill(0);
    st.nonce[0] = 1;
    st.nonce.set(fresh.subarray(32, 40), 4);
    fresh.fill(0);
}

/* after each piece: inonce ^= mac[0..8], counter + 1, and a new key on REKEY or a wrapped counter */
function ss_advance(st, mac, tag) {
    for (var i = 0; i < 8; i++) { st.nonce[4 + i] ^= mac[i]; }
    for (var c = 0; c < 4; c++) { if (++st.nonce[c] !== 0) { break; } }
    var wrapped = st.nonce[0] === 0 && st.nonce[1] === 0 && st.nonce[2] === 0 && st.nonce[3] === 0;
    if ((tag & TAG_REKEY) !== 0 || wrapped) { ss_rekey(st); }
}

/* Poly1305 over aad, its padding, the 64-byte tag block, the encrypted piece, its padding and the lengths */
function ss_mac(st, aad, block, c) {
    var poly_key = chacha20(st.k, st.nonce, new Uint8Array(64), 0).subarray(0, 32);
    var a = aad || new Uint8Array(0);
    var parts = [a, ZEROS.subarray(0, (16 - (a.length % 16)) % 16), block, c,
                 ZEROS.subarray(0, c.length % 16), le64(a.length), le64(64 + c.length)];
    var total = 0, i;
    for (i = 0; i < parts.length; i++) { total += parts[i].length; }
    var msg = new Uint8Array(total), off = 0;
    for (i = 0; i < parts.length; i++) { msg.set(parts[i], off); off += parts[i].length; }
    var mac = poly1305(poly_key, msg);
    poly_key.fill(0);
    return mac;
}

/** libsodium-compatible sealing side; the key is 32 bytes. */
export function xchacha20poly1305_secretstream_create(key, rng) {
    rng = require_rng('secretstream', rng);
    var header = rng(SS_HEADER_BYTES);
    var st = ss_state(key, header), ended = false;
    function seal(piece, tag, aad) {
        var block = new Uint8Array(64);
        block[0] = tag;
        block = chacha20(st.k, st.nonce, block, 1);
        var c = chacha20(st.k, st.nonce, piece, 2);
        var mac = ss_mac(st, aad, block, c);
        var out = new Uint8Array(1 + c.length + 16);
        out[0] = block[0];
        out.set(c, 1);
        out.set(mac, 1 + c.length);
        ss_advance(st, mac, tag);
        return out;
    }
    return {
        header: header,
        push: function (piece, last, aad) {
            if (ended) { throw new Error('secretstream: the last piece was already sealed'); }
            var out = seal(piece, last ? TAG_FINAL : TAG_MESSAGE, aad);
            if (last) { ended = true; st.k.fill(0); }
            return out;
        },
        rekey: function () { ss_rekey(st); },
        finished: function () { return ended; }
    };
}

/** libsodium-compatible opening side. */
export function xchacha20poly1305_secretstream_open_create(key, header) {
    var st = ss_state(key, header), ended = false;
    return {
        /** The piece, or null when it does not open or `last` does not match its tag. */
        push: function (sealed, last, aad) {
            if (ended) { throw new Error('secretstream: the last piece was already opened'); }
            if (!(sealed instanceof Uint8Array) || sealed.length < 17) { return null; }
            var mlen = sealed.length - 17;
            var block = new Uint8Array(64);
            block[0] = sealed[0];
            var tag = chacha20(st.k, st.nonce, block, 1)[0];
            block = chacha20(st.k, st.nonce, (function () { var b = new Uint8Array(64); b[0] = tag; return b; }()), 1);
            var c = sealed.subarray(1, 1 + mlen);
            var mac = ss_mac(st, aad, block, c);
            if (equal(mac, sealed.subarray(1 + mlen)) !== 1) { return null; }
            if ((tag === TAG_FINAL) !== !!last) { return null; }
            var piece = chacha20(st.k, st.nonce, c, 2);
            ss_advance(st, mac, tag);
            if (last) { ended = true; st.k.fill(0); }
            return piece;
        },
        rekey: function () { ss_rekey(st); },
        finished: function () { return ended; }
    };
}
