/**
 * MD4  -  RFC 1320
 *
 * COMPLETELY BROKEN. Collisions can be produced by hand in under a second,
 * and preimage attacks are within reach. There is no security argument for
 * MD4 in any context.
 *
 * It is here because NTLM is built on it and will not go away: every Windows
 * domain, every SMB implementation, every password-audit tool needs
 * MD4(UTF-16LE(password)) to speak the protocol. Reading and testing that is
 * a legitimate need; so is auditing hashes that already exist.
 *
 * MD4 also matters historically - MD5, SHA-1, RIPEMD and the whole family
 * descend from it - and its failure is what taught the field how three-round
 * designs break.
 *
 * Three rounds of sixteen steps, 512-bit blocks, little-endian throughout.
 * MD5 added a fourth round and a per-step constant precisely because MD4's
 * three were not enough.
 */

import { md_hash, md_create } from './commons/merkle_damgard.js';
import { rotl32 } from './commons/bytes.js';

var BLOCK_SIZE  = 64;
var DIGEST_SIZE = 16;

var IV = new Int32Array([0x67452301|0, 0xefcdab89|0, 0x98badcfe|0, 0x10325476|0]);

/* The two round constants are the square roots of 2 and 3. MD5 replaced
   these with 64 distinct values - one per step - which is most of what
   separates the two designs. */
var K1 = 0x5a827999 | 0;
var K2 = 0x6ed9eba1 | 0;

/* Message word order per round, and rotation amounts */
var ORDER2 = [0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15];
var ORDER3 = [0,8,4,12, 2,10,6,14, 1,9,5,13, 3,11,7,15];
var ROT1 = [3,7,11,19];
var ROT2 = [3,5,9,13];
var ROT3 = [3,9,11,15];

function compress(H, buf, off, W) {
    var i;
    for (i = 0; i < 16; i++) {
        W[i] = ((buf[off]) | (buf[off + 1] << 8) |
                (buf[off + 2] << 16) | (buf[off + 3] << 24)) | 0;
        off += 4;
    }

    var a = H[0], b = H[1], c = H[2], d = H[3];

    /* round 1: F = (b AND c) OR (NOT b AND d), words in order */
    for (i = 0; i < 16; i++) {
        var f = (b & c) | (~b & d);
        var t = (((a + f) | 0) + W[i]) | 0;
        t = rotl32(t, ROT1[i & 3]);
        a = d; d = c; c = b; b = t;
    }

    /* round 2: G = majority, plus a constant, words strided by four */
    for (i = 0; i < 16; i++) {
        var g = (b & c) | (b & d) | (c & d);
        var t2 = ((((a + g) | 0) + W[ORDER2[i]]) | 0) + K1 | 0;
        t2 = rotl32(t2, ROT2[i & 3]);
        a = d; d = c; c = b; b = t2;
    }

    /* round 3: H = xor, a different constant, bit-reversed word order */
    for (i = 0; i < 16; i++) {
        var h = b ^ c ^ d;
        var t3 = ((((a + h) | 0) + W[ORDER3[i]]) | 0) + K2 | 0;
        t3 = rotl32(t3, ROT3[i & 3]);
        a = d; d = c; c = b; b = t3;
    }

    H[0] = (H[0] + a) | 0;
    H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0;
    H[3] = (H[3] + d) | 0;
}

var PARAMS = {
    compress:      compress,
    iv:            IV,
    w_size:        16,
    block_size:    64,
    len_field:     8,
    digest_size:   16,
    little_endian: true
};

/**
 * @param  {Uint8Array} msg
 * @return {Uint8Array} 16 bytes
 */
export var md4 = /* @__PURE__ */ (function () {
    function md4(msg) { return md_hash(PARAMS, msg); }
    md4.BLOCK_SIZE  = BLOCK_SIZE;
    md4.DIGEST_SIZE = DIGEST_SIZE;
    md4.create = md4_create;
    return md4;
}());

/**
 * The NTLM password hash: MD4 of the password encoded as UTF-16 little-endian.
 *
 * Provided explicitly because getting the encoding wrong is the single most
 * common mistake when working with NTLM, and because a caller who wants this
 * should not have to discover that MD4 is what they need.
 *
 * There is no salt and no iteration count. An NTLM hash is a fast, unsalted
 * digest of the password, which is why rainbow tables against it are trivial
 * and why the hash itself is a password equivalent - possessing it is enough
 * to authenticate.
 *
 * @param  {string} password
 * @return {Uint8Array} 16 bytes
 */
export function ntlm(password) {
    var b = new Uint8Array(password.length * 2);
    for (var i = 0; i < password.length; i++) {
        var c = password.charCodeAt(i);
        b[i * 2] = c & 0xff;
        b[i * 2 + 1] = (c >>> 8) & 0xff;
    }
    return md4(b);
}

/**
 * The same hash, fed in pieces: update() as often as needed, digest() once;
 * copy() forks the state. See md_create in commons/merkle_damgard.js.
 */
export function md4_create() { return md_create(PARAMS); }
