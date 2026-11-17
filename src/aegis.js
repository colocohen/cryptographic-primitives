/**
 * AEGIS  -  draft-irtf-cfrg-aegis-aead
 *
 * A family of authenticated ciphers built from the AES ROUND rather than from
 * AES itself, and the fastest AEAD available on hardware with AES-NI - roughly
 * two to four times AES-GCM, and faster than ChaCha20-Poly1305.
 *
 * WHERE THE SPEED COMES FROM. AEGIS-128L absorbs 32 bytes per state update
 * and that update is 8 AES rounds, so it spends 0.25 rounds per byte.
 * AES-GCM spends 10 rounds per 16 bytes - 0.625 per byte - and then runs
 * GHASH on top. AEGIS authenticates as a side effect of its own state
 * evolution, so there is no second pass at all.
 *
 * THE ADVANTAGE IS CONDITIONAL ON HARDWARE, and this is the honest caveat.
 * Every count above assumes `aesenc` is a single-cycle instruction. In pure
 * software the AES round is a table lookup, AEGIS inherits the cache-timing
 * exposure that comes with it, and ChaCha20-Poly1305 - which has no tables at
 * all - is both faster and safer. AEGIS is a hardware cipher.
 *
 * NONCE REUSE IS BAD BUT NOT GCM-BAD. Repeating a nonce reveals the
 * relationship between the two plaintexts, as with any stream cipher. It does
 * NOT leak an authentication subkey the way GCM does, so an attacker who sees
 * a repeat cannot then forge arbitrary messages. That is a genuine
 * improvement, not a licence to repeat nonces.
 *
 * TWO VARIANTS ARE IMPLEMENTED. AEGIS-128L has a 1024-bit state and processes
 * 32 bytes at a time; AEGIS-256 has a 768-bit state, processes 16, and takes a
 * 256-bit key and nonce. The X2 and X4 parallel modes in the draft are
 * omitted: they exist to feed 256- and 512-bit SIMD lanes, which JavaScript
 * has no way to reach.
 *
 * STATUS: an IRTF CFRG draft, not an RFC. AEGIS won the CAESAR competition's
 * high-performance category in 2019 and is deployed - it is in libsodium and
 * in Fastly's infrastructure - but a peer that does not know it will not
 * negotiate it.

 * ---------------------------------------------------------------------------
 * THE X VARIANTS ARE NOT HERE, AND THAT IS A DECISION.
 *
 * The draft also defines AEGIS-128X and AEGIS-256X, which run 2 or 4 AEGIS
 * states in parallel. They are omitted because the reason they exist does not
 * apply in JavaScript:
 *
 *     "Some CPUs... include instructions to efficiently apply the AES round
 *      function to a vector of AES blocks... designed to take advantage of
 *      these instructions."
 *
 * That is VAES. With wide vector registers the states live in separate lanes
 * and update together; without them, X2 runs two states SEQUENTIALLY while
 * absorbing twice as much per update - the same throughput, plus the cost of
 * managing more state. There is nothing to gain.
 *
 * THEY ARE ALSO NOT DROP-IN FASTER VERSIONS. AEGIS-128X2 is a different
 * cipher from AEGIS-128L: different output, different tag. Adding it would be
 * adding an algorithm nobody can decrypt with the one already here.
 *
 * AND MEASURED HERE, AEGIS IS NOT THE FAST OPTION ANYWAY:
 *
 *     aegis256           17.0 MB/s
 *     chacha20poly1305   15.2 MB/s
 *     aegis128l          11.8 MB/s
 *
 * AEGIS wins by a wide margin on hardware with AES-NI and loses without it,
 * because its whole design assumes the AES round is one instruction. In
 * software, ChaCha20-Poly1305 is both faster and free of the cache-timing
 * exposure that any table-based AES round carries.
 * ---------------------------------------------------------------------------
 */

import { aes_round } from './commons/aes_round.js';
import { equal } from './commons/ct.js';
import { xor_bytes, le64 } from './commons/bytes.js';

/*
 * C0 and C1 - Fibonacci numbers modulo 256 and the same sequence continued.
 * Nothing up anyone's sleeve, and the draft says so.
 */
var C0 = /* @__PURE__ */ new Uint8Array([
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
    0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62
]);
var C1 = /* @__PURE__ */ new Uint8Array([
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
    0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
]);

/* le64 (bit counts, past 2^32) is commons/bytes.js's */

/* ---------------- AEGIS-128L ---------------- */

function state128l() {
    var s = [];
    for (var i = 0; i < 8; i++) { s.push(new Uint8Array(16)); }
    return s;
}

/**
 * The state update: eight AES rounds in a ring, with two message blocks
 * injected at S0 and S4.
 *
 * Every round key is the PREVIOUS state word, so the whole state advances at
 * once and each word depends on two others. That is what makes one update
 * enough diffusion for 32 bytes of message.
 */
function update128l(s, m0, m1, tmp) {
    var t = tmp;
    var x = new Uint8Array(16);
    xor_bytes(x, s[0], m0, 16);
    aes_round(s[7], x, t[0]);
    aes_round(s[0], s[1], t[1]);
    aes_round(s[1], s[2], t[2]);
    aes_round(s[2], s[3], t[3]);
    xor_bytes(x, s[4], m1, 16);
    aes_round(s[3], x, t[4]);
    aes_round(s[4], s[5], t[5]);
    aes_round(s[5], s[6], t[6]);
    aes_round(s[6], s[7], t[7]);
    for (var i = 0; i < 8; i++) { s[i].set(t[i]); }
}

function init128l(key, nonce, tmp) {
    var s = state128l();
    xor_bytes(s[0], key, nonce, 16);
    s[1].set(C1);
    s[2].set(C0);
    s[3].set(C1);
    xor_bytes(s[4], key, nonce, 16);
    xor_bytes(s[5], key, C0, 16);
    xor_bytes(s[6], key, C1, 16);
    xor_bytes(s[7], key, C0, 16);
    for (var i = 0; i < 10; i++) { update128l(s, nonce, key, tmp); }
    return s;
}

/** The two keystream blocks, derived from the state without advancing it. */
function z128l(s, z0, z1) {
    for (var i = 0; i < 16; i++) {
        z0[i] = s[1][i] ^ s[6][i] ^ (s[2][i] & s[3][i]);
        z1[i] = s[2][i] ^ s[5][i] ^ (s[6][i] & s[7][i]);
    }
}

function finalize128l(s, ad_bits, msg_bits, tag_len, tmp) {
    var t = new Uint8Array(16);
    var la = le64(ad_bits), lm = le64(msg_bits);
    for (var i = 0; i < 8; i++) { t[i] = s[2][i] ^ la[i]; }
    for (var j = 0; j < 8; j++) { t[8 + j] = s[2][8 + j] ^ lm[j]; }

    for (var r = 0; r < 7; r++) { update128l(s, t, t, tmp); }

    var tag = new Uint8Array(tag_len);
    var k;
    if (tag_len === 16) {
        for (k = 0; k < 16; k++) {
            tag[k] = s[0][k] ^ s[1][k] ^ s[2][k] ^ s[3][k] ^ s[4][k] ^ s[5][k] ^ s[6][k];
        }
    } else {
        for (k = 0; k < 16; k++) {
            tag[k] = s[0][k] ^ s[1][k] ^ s[2][k] ^ s[3][k];
            tag[16 + k] = s[4][k] ^ s[5][k] ^ s[6][k] ^ s[7][k];
        }
    }
    return tag;
}

function aegis128l_core(key, nonce, data, aad, tag_len, decrypting) {
    if (key.length !== 16) { throw new Error('aegis128l: key must be 16 bytes'); }
    if (nonce.length !== 16) { throw new Error('aegis128l: nonce must be 16 bytes'); }
    if (tag_len !== 16 && tag_len !== 32) { throw new Error('aegis: tag must be 16 or 32 bytes'); }

    var tmp = state128l();
    var s = init128l(key, nonce, tmp);
    var ad = aad || new Uint8Array(0);
    var z0 = new Uint8Array(16), z1 = new Uint8Array(16);
    var blk = new Uint8Array(32);
    var i, j;

    /* absorb the associated data, zero-padded to a whole block */
    for (i = 0; i + 32 <= ad.length; i += 32) {
        update128l(s, ad.subarray(i, i + 16), ad.subarray(i + 16, i + 32), tmp);
    }
    if (i < ad.length) {
        blk.fill(0);
        blk.set(ad.subarray(i), 0);
        update128l(s, blk.subarray(0, 16), blk.subarray(16), tmp);
    }

    var out = new Uint8Array(data.length);

    for (i = 0; i + 32 <= data.length; i += 32) {
        z128l(s, z0, z1);
        for (j = 0; j < 16; j++) {
            out[i + j] = data[i + j] ^ z0[j];
            out[i + 16 + j] = data[i + 16 + j] ^ z1[j];
        }
        /* the state absorbs the PLAINTEXT in both directions */
        var p0 = decrypting ? out.subarray(i, i + 16) : data.subarray(i, i + 16);
        var p1 = decrypting ? out.subarray(i + 16, i + 32) : data.subarray(i + 16, i + 32);
        update128l(s, p0, p1, tmp);
    }

    var rem = data.length - i;
    if (rem > 0) {
        z128l(s, z0, z1);
        blk.fill(0);
        blk.set(data.subarray(i), 0);
        for (j = 0; j < 16; j++) {
            blk[j] ^= z0[j];
            blk[16 + j] ^= z1[j];
        }
        for (j = 0; j < rem; j++) { out[i + j] = blk[j]; }
        /*
         * The partial block is absorbed as the ZERO-PADDED PLAINTEXT, which
         * means the trailing bytes of the decrypted block have to be cleared
         * before absorbing - otherwise decryption absorbs keystream where
         * encryption absorbed zeros, and the tags diverge.
         */
        if (decrypting) {
            blk.fill(0);
            blk.set(out.subarray(i, i + rem), 0);
        } else {
            blk.fill(0);
            blk.set(data.subarray(i), 0);
        }
        update128l(s, blk.subarray(0, 16), blk.subarray(16), tmp);
    }

    var tag = finalize128l(s, ad.length * 8, data.length * 8, tag_len, tmp);
    return { out: out, tag: tag };
}

/**
 * @param {Uint8Array} key    16 bytes
 * @param {Uint8Array} nonce  16 bytes, and it must not repeat under one key
 * @param {number}     [tag_len]  16 or 32
 * @return {Uint8Array} ciphertext followed by the tag
 */
export function aegis128l_encrypt(key, nonce, plaintext, aad, tag_len) {
    var tl = tag_len === undefined ? 16 : tag_len;
    var r = aegis128l_core(key, nonce, plaintext, aad, tl);
    var out = new Uint8Array(r.out.length + tl);
    out.set(r.out, 0);
    out.set(r.tag, r.out.length);
    return out;
}

/** @return {Uint8Array|null} null when authentication fails */
export function aegis128l_decrypt(key, nonce, sealed, aad, tag_len) {
    var tl = tag_len === undefined ? 16 : tag_len;
    if (sealed.length < tl) { return null; }
    var ct = sealed.subarray(0, sealed.length - tl);
    var r = aegis128l_core(key, nonce, ct, aad, tl, true);
    if (equal(r.tag, sealed.subarray(sealed.length - tl)) !== 1) { return null; }
    return r.out;
}

/* ---------------- AEGIS-256 ---------------- */

function state256() {
    var s = [];
    for (var i = 0; i < 6; i++) { s.push(new Uint8Array(16)); }
    return s;
}

function update256(s, m, tmp) {
    var t = tmp;
    var x = new Uint8Array(16);
    xor_bytes(x, s[0], m, 16);
    aes_round(s[5], x, t[0]);
    aes_round(s[0], s[1], t[1]);
    aes_round(s[1], s[2], t[2]);
    aes_round(s[2], s[3], t[3]);
    aes_round(s[3], s[4], t[4]);
    aes_round(s[4], s[5], t[5]);
    for (var i = 0; i < 6; i++) { s[i].set(t[i]); }
}

function init256(key, nonce, tmp) {
    var k0 = key.subarray(0, 16), k1 = key.subarray(16);
    var n0 = nonce.subarray(0, 16), n1 = nonce.subarray(16);
    var s = state256();
    xor_bytes(s[0], k0, n0, 16);
    xor_bytes(s[1], k1, n1, 16);
    s[2].set(C1);
    s[3].set(C0);
    xor_bytes(s[4], k0, C0, 16);
    xor_bytes(s[5], k1, C1, 16);

    var kn0 = new Uint8Array(16), kn1 = new Uint8Array(16);
    xor_bytes(kn0, k0, n0, 16);
    xor_bytes(kn1, k1, n1, 16);
    for (var i = 0; i < 4; i++) {
        update256(s, k0, tmp);
        update256(s, k1, tmp);
        update256(s, kn0, tmp);
        update256(s, kn1, tmp);
    }
    return s;
}

function z256(s, z) {
    for (var i = 0; i < 16; i++) {
        z[i] = s[1][i] ^ s[4][i] ^ s[5][i] ^ (s[2][i] & s[3][i]);
    }
}

function finalize256(s, ad_bits, msg_bits, tag_len, tmp) {
    var t = new Uint8Array(16);
    var la = le64(ad_bits), lm = le64(msg_bits);
    for (var i = 0; i < 8; i++) { t[i] = s[3][i] ^ la[i]; }
    for (var j = 0; j < 8; j++) { t[8 + j] = s[3][8 + j] ^ lm[j]; }

    for (var r = 0; r < 7; r++) { update256(s, t, tmp); }

    var tag = new Uint8Array(tag_len);
    var k;
    if (tag_len === 16) {
        for (k = 0; k < 16; k++) {
            tag[k] = s[0][k] ^ s[1][k] ^ s[2][k] ^ s[3][k] ^ s[4][k] ^ s[5][k];
        }
    } else {
        for (k = 0; k < 16; k++) {
            tag[k] = s[0][k] ^ s[1][k] ^ s[2][k];
            tag[16 + k] = s[3][k] ^ s[4][k] ^ s[5][k];
        }
    }
    return tag;
}

function aegis256_core(key, nonce, data, aad, tag_len, decrypting) {
    if (key.length !== 32) { throw new Error('aegis256: key must be 32 bytes'); }
    if (nonce.length !== 32) { throw new Error('aegis256: nonce must be 32 bytes'); }
    if (tag_len !== 16 && tag_len !== 32) { throw new Error('aegis: tag must be 16 or 32 bytes'); }

    var tmp = state256();
    var s = init256(key, nonce, tmp);
    var ad = aad || new Uint8Array(0);
    var z = new Uint8Array(16);
    var blk = new Uint8Array(16);
    var i, j;

    for (i = 0; i + 16 <= ad.length; i += 16) {
        update256(s, ad.subarray(i, i + 16), tmp);
    }
    if (i < ad.length) {
        blk.fill(0);
        blk.set(ad.subarray(i), 0);
        update256(s, blk, tmp);
    }

    var out = new Uint8Array(data.length);

    for (i = 0; i + 16 <= data.length; i += 16) {
        z256(s, z);
        for (j = 0; j < 16; j++) { out[i + j] = data[i + j] ^ z[j]; }
        update256(s, decrypting ? out.subarray(i, i + 16) : data.subarray(i, i + 16), tmp);
    }

    var rem = data.length - i;
    if (rem > 0) {
        z256(s, z);
        blk.fill(0);
        blk.set(data.subarray(i), 0);
        for (j = 0; j < 16; j++) { blk[j] ^= z[j]; }
        for (j = 0; j < rem; j++) { out[i + j] = blk[j]; }
        blk.fill(0);
        blk.set(decrypting ? out.subarray(i, i + rem) : data.subarray(i), 0);
        update256(s, blk, tmp);
    }

    var tag = finalize256(s, ad.length * 8, data.length * 8, tag_len, tmp);
    return { out: out, tag: tag };
}

/**
 * @param {Uint8Array} key    32 bytes
 * @param {Uint8Array} nonce  32 bytes
 *
 * The 256-bit nonce is the reason to prefer this variant when nonces are
 * RANDOM rather than counted: 128 bits is comfortable, and AEGIS-128L's
 * 128-bit nonce is already fine, but a 256-bit one removes the question
 * entirely.
 */
export function aegis256_encrypt(key, nonce, plaintext, aad, tag_len) {
    var tl = tag_len === undefined ? 16 : tag_len;
    var r = aegis256_core(key, nonce, plaintext, aad, tl, false);
    var out = new Uint8Array(r.out.length + tl);
    out.set(r.out, 0);
    out.set(r.tag, r.out.length);
    return out;
}

/** @return {Uint8Array|null} null when authentication fails */
export function aegis256_decrypt(key, nonce, sealed, aad, tag_len) {
    var tl = tag_len === undefined ? 16 : tag_len;
    if (sealed.length < tl) { return null; }
    var ct = sealed.subarray(0, sealed.length - tl);
    var r = aegis256_core(key, nonce, ct, aad, tl, true);
    if (equal(r.tag, sealed.subarray(sealed.length - tl)) !== 1) { return null; }
    return r.out;
}
