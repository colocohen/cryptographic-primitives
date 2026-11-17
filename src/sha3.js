/**
 * Keccak-based hashes  -  FIPS 202, plus the original pre-standard variant
 *
 * SHA3-224/256/384/512, SHAKE128/256, and Keccak-224/256/384/512.
 *
 * A sponge construction: no compression function updating a small state,
 * but one 1600-bit state that absorbs the message and is then squeezed for
 * output. The permutation itself lives in commons/keccak.js, which is also
 * where ML-KEM, ML-DSA and SLH-DSA will draw their SHAKE sampling from.
 *
 * Every function in this file is that one permutation with two numbers
 * changed - the rate, and a domain separation byte:
 *
 *     SHA-3         0x06     rate 144 / 136 / 104 / 72
 *     SHAKE         0x1f     rate 168 / 136
 *     Keccak        0x01     rate 144 / 136 / 104 / 72
 *
 * Two consequences of the sponge worth knowing:
 *   - No length extension exposure. sha3_256(key || msg) is safe as a MAC,
 *     unlike SHA-2, which is the reason HMAC exists at all.
 *   - Output length is unconstrained, which is what SHAKE exposes.
 *
 * THE 0x01 VARIANTS
 * NIST added the 01 suffix to the padding on the way to FIPS 202 in 2015.
 * Ethereum was already built on the original Keccak draft and did not
 * follow, so the whole EVM - addresses, event hashing, the Merkle Patricia
 * trie - uses Keccak-256 rather than SHA3-256. The function named sha3 in
 * Solidity is in fact Keccak-256. This is a common source of confusion.
 */

import { keccak_sponge, keccak_create, encode_string, bytepad, right_encode, left_encode } from './commons/keccak.js';
import { ascii, concat } from './commons/bytes.js';

/* ---------------- SHA-3: fixed output length, domain 0x06 ---------------- */

/** SHA3-224. */
export var sha3_224 = /* @__PURE__ */ (function () {
    function sha3_224(msg) { return keccak_sponge(msg, 144, 0x06, 28); }
    sha3_224.BLOCK_SIZE  = 144;
    sha3_224.DIGEST_SIZE = 28;
    sha3_224.create = sha3_224_create;
    sha3_224.NAME = 'sha3_224';
    return sha3_224;
}());

/** SHA3-256. */
export var sha3_256 = /* @__PURE__ */ (function () {
    function sha3_256(msg) { return keccak_sponge(msg, 136, 0x06, 32); }
    sha3_256.BLOCK_SIZE  = 136;
    sha3_256.DIGEST_SIZE = 32;
    sha3_256.create = sha3_256_create;
    sha3_256.NAME = 'sha3_256';
    return sha3_256;
}());

/** SHA3-384. */
export var sha3_384 = /* @__PURE__ */ (function () {
    function sha3_384(msg) { return keccak_sponge(msg, 104, 0x06, 48); }
    sha3_384.BLOCK_SIZE  = 104;
    sha3_384.DIGEST_SIZE = 48;
    sha3_384.create = sha3_384_create;
    sha3_384.NAME = 'sha3_384';
    return sha3_384;
}());

/** SHA3-512. */
export var sha3_512 = /* @__PURE__ */ (function () {
    function sha3_512(msg) { return keccak_sponge(msg, 72, 0x06, 64); }
    sha3_512.BLOCK_SIZE  = 72;
    sha3_512.DIGEST_SIZE = 64;
    sha3_512.create = sha3_512_create;
    sha3_512.NAME = 'sha3_512';
    return sha3_512;
}());

/* ---------------- SHAKE: free output length, domain 0x1f ---------------- */

/** SHAKE128. @param out_len output length in bytes - any positive value. */
export var shake128 = /* @__PURE__ */ (function () {
    function shake128(msg, out_len) { return keccak_sponge(msg, 168, 0x1f, out_len); }
    shake128.BLOCK_SIZE  = 168;
    return shake128;
}());

/** SHAKE256. @param out_len output length in bytes - any positive value. */
export var shake256 = /* @__PURE__ */ (function () {
    function shake256(msg, out_len) { return keccak_sponge(msg, 136, 0x1f, out_len); }
    shake256.BLOCK_SIZE  = 136;
    return shake256;
}());

/* ---------------- Original Keccak: domain 0x01 ---------------- */

/** Keccak-224. */
export var keccak224 = /* @__PURE__ */ (function () {
    function keccak224(msg) { return keccak_sponge(msg, 144, 0x01, 28); }
    keccak224.BLOCK_SIZE  = 144;
    keccak224.DIGEST_SIZE = 28;
    keccak224.create = keccak224_create;
    return keccak224;
}());

/** Keccak-256. The Ethereum hash. */
export var keccak256 = /* @__PURE__ */ (function () {
    function keccak256(msg) { return keccak_sponge(msg, 136, 0x01, 32); }
    keccak256.BLOCK_SIZE  = 136;
    keccak256.DIGEST_SIZE = 32;
    keccak256.create = keccak256_create;
    return keccak256;
}());

/** Keccak-384. */
export var keccak384 = /* @__PURE__ */ (function () {
    function keccak384(msg) { return keccak_sponge(msg, 104, 0x01, 48); }
    keccak384.BLOCK_SIZE  = 104;
    keccak384.DIGEST_SIZE = 48;
    keccak384.create = keccak384_create;
    return keccak384;
}());

/** Keccak-512. */
export var keccak512 = /* @__PURE__ */ (function () {
    function keccak512(msg) { return keccak_sponge(msg, 72, 0x01, 64); }
    keccak512.BLOCK_SIZE  = 72;
    keccak512.DIGEST_SIZE = 64;
    keccak512.create = keccak512_create;
    return keccak512;
}());

/* ---------------- cSHAKE: SHAKE with a customisation string ---------------- */
/*
 * SP 800-185. Same sponge, but a length-prefixed header is absorbed first so
 * that two different customisations of the same message can never collide.
 * The header goes through bytepad, so it is always a whole number of blocks.
 *
 * With both strings empty cSHAKE is defined to BE SHAKE - including the 0x1f
 * domain byte rather than 0x04. That special case is in the spec, not an
 * optimisation, and skipping it produces wrong output.
 *
 * @param {Uint8Array} msg
 * @param {number}     out_len
 * @param {Uint8Array} [fn_name]  N - reserved for NIST-defined functions
 * @param {Uint8Array} [custom]   S - the application's customisation string
 * @param {Uint8Array} [suffix]   absorbed after msg - the encoded output
 *                                length KMAC, TupleHash and ParallelHash end
 *                                their input with
 * @param {Uint8Array} [extra]    absorbed after the header and before msg;
 *                                must be bytepad'ed to the rate. KMAC's key.
 *
 * ⭐ KMAC, TupleHash AND ParallelHash ARE ALL THIS FUNCTION. Each used to build
 *   the bytepad(encode_string(N) || encode_string(S)) header itself and call
 *   the sponge with domain 0x04 directly - three more copies of cSHAKE, which
 *   is what SP 800-185 defines all three in terms of. The two parameters at
 *   the end are what they needed that this did not take.
 */
function cshake(msg, rate, out_len, fn_name, custom, suffix, extra) {
    var n = fn_name || EMPTY;
    var c = custom  || EMPTY;
    if (n.length === 0 && c.length === 0) {
        /* cSHAKE with both strings empty IS SHAKE - of everything it absorbs */
        return keccak_sponge(msg, rate, 0x1f, out_len, extra, 24, suffix);
    }
    var header = bytepad([encode_string(n), encode_string(c)], rate);
    if (extra) { header = concat([header, extra]); }
    return keccak_sponge(msg, rate, 0x04, out_len, header, 24, suffix);
}

var EMPTY = new Uint8Array(0);

export var cshake128 = /* @__PURE__ */ (function () {
    function cshake128(msg, out_len, fn_name, custom) {
        return cshake(msg, 168, out_len, fn_name, custom);
    }
    cshake128.BLOCK_SIZE = 168;
    return cshake128;
}());

export var cshake256 = /* @__PURE__ */ (function () {
    function cshake256(msg, out_len, fn_name, custom) {
        return cshake(msg, 136, out_len, fn_name, custom);
    }
    cshake256.BLOCK_SIZE = 136;
    return cshake256;
}());

/* ---------------- TurboSHAKE: 12 rounds instead of 24 ---------------- */
/*
 * Roughly twice as fast as SHAKE, at a security level the designers argue is
 * still ample. Keccak-p[1600,12] uses the LAST twelve round constants of the
 * 24-round schedule, not the first twelve.
 *
 * Newer post-quantum work reaches for this rather than SHAKE, which is why it
 * belongs in the library before ML-KEM and ML-DSA arrive.
 *
 * @param {number} [domain=0x1f]  separation byte, 0x01..0x7f
 */
export var turboshake128 = /* @__PURE__ */ (function () {
    function turboshake128(msg, out_len, domain) {
        return keccak_sponge(msg, 168, domain === undefined ? 0x1f : domain,
                             out_len, null, 12);
    }
    turboshake128.BLOCK_SIZE = 168;
    return turboshake128;
}());

export var turboshake256 = /* @__PURE__ */ (function () {
    function turboshake256(msg, out_len, domain) {
        return keccak_sponge(msg, 136, domain === undefined ? 0x1f : domain,
                             out_len, null, 12);
    }
    turboshake256.BLOCK_SIZE = 136;
    return turboshake256;
}());

/* ---------------- KMAC: the Keccak-native MAC ---------------- */
/*
 * SP 800-185. A MAC without HMAC's double wrap, because the sponge is not
 * length-extendable in the first place - one pass instead of two.
 *
 *     KMAC(K, X, L, S) = cSHAKE(bytepad(encode_string(K), rate)
 *                               || X || right_encode(L),
 *                               L, "KMAC", S)
 *
 * Every field carries its own length, so no two distinct (key, message,
 * output length) triples can produce the same absorbed byte stream. That
 * includes the requested output length, encoded at the very end - which is
 * why a KMAC tag truncated to 16 bytes is NOT the 16-byte KMAC of the same
 * input. Ask for the length you want.
 *
 * The XOF variants encode zero there instead, and are the ones to use when
 * the output length is not fixed in advance.
 */

var KMAC_NAME = /* @__PURE__ */ ascii('KMAC');

function kmac(msg, key, rate, out_len, custom, xof) {
    /*
     * The key block is itself bytepad'ed, so header || key_block is still a
     * whole number of blocks and the message keeps starting on a boundary.
     */
    var key_block = bytepad([encode_string(key)], rate);
    var suffix = right_encode(xof ? 0 : out_len * 8);
    return cshake(msg, rate, out_len, KMAC_NAME, custom, suffix, key_block);
}

/**
 * @param {Uint8Array} key
 * @param {Uint8Array} msg
 * @param {number}     out_len   in bytes. Encoded into the input - see above.
 * @param {Uint8Array} [custom]  S, an application customisation string
 */
export var kmac128 = /* @__PURE__ */ (function () {
    function kmac128(key, msg, out_len, custom) {
        return kmac(msg, key, 168, out_len, custom, false);
    }
    kmac128.BLOCK_SIZE = 168;
    return kmac128;
}());

export var kmac256 = /* @__PURE__ */ (function () {
    function kmac256(key, msg, out_len, custom) {
        return kmac(msg, key, 136, out_len, custom, false);
    }
    kmac256.BLOCK_SIZE = 136;
    return kmac256;
}());

/** XOF forms: the output length is not committed to, so it may vary. */
export var kmac128xof = /* @__PURE__ */ (function () {
    function kmac128xof(key, msg, out_len, custom) {
        return kmac(msg, key, 168, out_len, custom, true);
    }
    kmac128xof.BLOCK_SIZE = 168;
    return kmac128xof;
}());

export var kmac256xof = /* @__PURE__ */ (function () {
    function kmac256xof(key, msg, out_len, custom) {
        return kmac(msg, key, 136, out_len, custom, true);
    }
    kmac256xof.BLOCK_SIZE = 136;
    return kmac256xof;
}());

/* ---------------- TupleHash ---------------- */
/*
 * SP 800-185. Hashing a LIST of strings unambiguously.
 *
 * The problem it solves is real and easy to get wrong by hand: hashing
 * a || b is not a function of (a, b), because ("ab", "c") and ("a", "bc")
 * concatenate identically. Any protocol that hashes several fields together
 * and simply joins them has this bug, and it is exploitable whenever an
 * attacker controls where one field ends and the next begins.
 *
 * TupleHash length-prefixes every element, so the encoding is injective. The
 * XOF variants leave the output length uncommitted; the others encode it, so
 * a truncated TupleHash is not the TupleHash of a shorter length.
 */

function tuplehash(items, rate, out_len, custom, xof) {
    var parts = [];
    for (var i = 0; i < items.length; i++) { parts.push(encode_string(items[i])); }
    var suffix = right_encode(xof ? 0 : out_len * 8);
    return cshake(concat(parts), rate, out_len, TUPLE_NAME, custom, suffix);
}

var TUPLE_NAME = /* @__PURE__ */ ascii('TupleHash');

/**
 * @param {Uint8Array[]} items   the tuple, in order
 * @param {number}       out_len
 * @param {Uint8Array}   [custom]
 */
export function tuplehash128(items, out_len, custom) {
    return tuplehash(items, 168, out_len, custom, false);
}
export function tuplehash256(items, out_len, custom) {
    return tuplehash(items, 136, out_len, custom, false);
}
export function tuplehash128xof(items, out_len, custom) {
    return tuplehash(items, 168, out_len, custom, true);
}
export function tuplehash256xof(items, out_len, custom) {
    return tuplehash(items, 136, out_len, custom, true);
}

/* ---------------- ParallelHash ---------------- */
/*
 * SP 800-185. The message is cut into fixed-size blocks, each is hashed
 * independently, and the digests are hashed together - the same shape as
 * BLAKE3's tree, for the same reason: independent blocks can be processed on
 * separate cores.
 *
 * This implementation is single-threaded and gets nothing from that, exactly
 * as with BLAKE3. The structure is still mandatory because it defines the
 * output, and the block size is part of the parameters: the same message
 * under a different block size gives a different digest.
 */

var PARALLEL_NAME = /* @__PURE__ */ ascii('ParallelHash');

function parallelhash(msg, block_size, rate, out_len, custom, xof) {
    var n = Math.ceil(msg.length / block_size);
    var digest_len = rate === 168 ? 32 : 64;

    /* left_encode(B) || cSHAKE of each block || right_encode(n) || right_encode(L) */
    var head = left_encode(block_size);
    var body = new Uint8Array(head.length + n * digest_len);
    body.set(head, 0);

    for (var i = 0; i < n; i++) {
        var end = Math.min((i + 1) * block_size, msg.length);
        var d = cshake(msg.subarray(i * block_size, end), rate, digest_len, undefined, undefined);
        body.set(d, head.length + i * digest_len);
    }

    var suffix = concat([right_encode(n), right_encode(xof ? 0 : out_len * 8)]);
    return cshake(body, rate, out_len, PARALLEL_NAME, custom, suffix);
}

/**
 * @param {Uint8Array} msg
 * @param {number}     block_size  bytes per parallel block - part of the output
 * @param {number}     out_len
 * @param {Uint8Array} [custom]
 */
export function parallelhash128(msg, block_size, out_len, custom) {
    return parallelhash(msg, block_size, 168, out_len, custom, false);
}
export function parallelhash256(msg, block_size, out_len, custom) {
    return parallelhash(msg, block_size, 136, out_len, custom, false);
}
export function parallelhash128xof(msg, block_size, out_len, custom) {
    return parallelhash(msg, block_size, 168, out_len, custom, true);
}
export function parallelhash256xof(msg, block_size, out_len, custom) {
    return parallelhash(msg, block_size, 136, out_len, custom, true);
}

/* ---------------- KangarooTwelve ---------------- */
/*
 * The Keccak team's own answer to "SHA-3 is too slow": twelve rounds instead
 * of twenty-four, plus a tree so that long messages can be processed in
 * parallel. Roughly four times faster than SHA3-256 in optimised code.
 *
 * The tree only engages past 8192 bytes. Below that, KT12 is exactly
 * TurboSHAKE with a domain byte of 0x07 - which is why short messages get no
 * tree overhead at all, a deliberate contrast with BLAKE3 where the chunk
 * structure applies from the first byte.
 *
 * The customisation string is appended to the message rather than prefixed
 * through bytepad, with its own length encoding. That is a different
 * convention from cSHAKE and KMAC above, and mixing them up produces a hash
 * that looks right and interoperates with nothing.
 *
 * As with ParallelHash and BLAKE3, this implementation is single-threaded, so
 * the tree is structure rather than speed here.
 */

var KT_CHUNK = 8192;

/**
 * KangarooTwelve's own length encoding, which is NOT SP 800-185's
 * right_encode despite looking similar.
 *
 * right_encode(0) is 00 01 - one byte of value, then the count. K12's
 * length_encode(0) is just 00 - zero bytes of value, then a count of zero.
 * They differ only at zero, and zero is exactly the case an empty
 * customisation string hits, so the mistake produces a hash that is wrong for
 * the most common call and right for the rest.
 */
function length_encode(x) {
    /* everywhere but zero it IS right_encode - the same bytes, then the
       count - so only the zero case is written here */
    if (x === 0) { return new Uint8Array([0]); }
    return right_encode(x);
}

function kt(msg, custom, out_len, rate, cv_len) {
    var c = custom || EMPTY;

    /* the customisation string and its length ride at the end of the message */
    var enc = length_encode(c.length);
    var s = new Uint8Array(msg.length + c.length + enc.length);
    s.set(msg, 0);
    s.set(c, msg.length);
    s.set(enc, msg.length + c.length);

    if (s.length <= KT_CHUNK) {
        /* short path: no tree, plain TurboSHAKE with KT12's domain byte */
        return keccak_sponge(s, rate, 0x07, out_len, null, 12);
    }

    var n = Math.ceil((s.length - KT_CHUNK) / KT_CHUNK);

    /*
     * The final node is: first chunk || 0x03 0x00*7 || chunk CVs
     * || right_encode(n) || 0xFFFF. Each chunk after the first is hashed with
     * domain 0x0b; the node itself with 0x06.
     */
    var tail = length_encode(n);
    var total = KT_CHUNK + 8 + n * cv_len + tail.length + 2;
    var node = new Uint8Array(total);
    var o = 0;

    node.set(s.subarray(0, KT_CHUNK), 0); o = KT_CHUNK;
    node[o] = 0x03; o += 8;

    for (var i = 0; i < n; i++) {
        var start = KT_CHUNK + i * KT_CHUNK;
        var end = Math.min(start + KT_CHUNK, s.length);
        var cv = keccak_sponge(s.subarray(start, end), rate, 0x0b, cv_len, null, 12);
        node.set(cv, o); o += cv_len;
    }

    node.set(tail, o); o += tail.length;
    node[o] = 0xff; node[o + 1] = 0xff;

    return keccak_sponge(node, rate, 0x06, out_len, null, 12);
}

/**
 * @param {Uint8Array} msg
 * @param {number}     [out_len=32]
 * @param {Uint8Array} [custom]  appended, not prefixed - see the note above
 */
export function kt128(msg, out_len, custom) {
    return kt(msg, custom, out_len === undefined ? 32 : out_len, 168, 32);
}

export function kt256(msg, out_len, custom) {
    return kt(msg, custom, out_len === undefined ? 64 : out_len, 136, 64);
}

/* ---------------- Incremental ---------------- */
/*
 * The same functions fed in pieces. Each _create takes the one-shot form's
 * arguments minus the message and returns
 *
 *     { update(msg), copy(), digest() }          fixed-length hashes and KMAC
 *     { update(msg), copy(), digest(n), read(n) } extendable output (SHAKE,
 *                                                cSHAKE, TurboSHAKE, KMACXOF)
 *
 * read(n) returns the next n bytes and may be called again; digest(n) takes
 * the whole output at once and ends the instance.
 */

/* A fixed-length hash: digest() takes no length, and there is no read(). */
function fixed(inner, out_len) {
    var self = {
        update: function (msg) { inner.update(msg); return self; },
        copy: function () { return fixed(inner.copy(), out_len); },
        digest: function () { return inner.digest(out_len); }
    };
    return self;
}

function xof(inner) {
    var self = {
        update: function (msg) { inner.update(msg); return self; },
        copy: function () { return xof(inner.copy()); },
        digest: function (out_len) { return inner.digest(out_len); },
        read: function (n) { return inner.read(n); }
    };
    return self;
}

export function sha3_224_create()  { return fixed(keccak_create(144, 0x06), 28); }
export function sha3_256_create()  { return fixed(keccak_create(136, 0x06), 32); }
export function sha3_384_create()  { return fixed(keccak_create(104, 0x06), 48); }
export function sha3_512_create()  { return fixed(keccak_create(72, 0x06), 64); }
export function keccak224_create() { return fixed(keccak_create(144, 0x01), 28); }
export function keccak256_create() { return fixed(keccak_create(136, 0x01), 32); }
export function keccak384_create() { return fixed(keccak_create(104, 0x01), 48); }
export function keccak512_create() { return fixed(keccak_create(72, 0x01), 64); }

export function shake128_create() { return xof(keccak_create(168, 0x1f)); }
export function shake256_create() { return xof(keccak_create(136, 0x1f)); }

export function turboshake128_create(domain) { return xof(keccak_create(168, domain === undefined ? 0x1f : domain, null, 12)); }
export function turboshake256_create(domain) { return xof(keccak_create(136, domain === undefined ? 0x1f : domain, null, 12)); }

/* As cshake above: the same header, the same fall-back to SHAKE when both strings are empty. */
function cshake_create(rate, fn_name, custom, suffix, extra) {
    var n = fn_name || EMPTY;
    var c = custom  || EMPTY;
    if (n.length === 0 && c.length === 0) {
        return keccak_create(rate, 0x1f, extra, 24, suffix);
    }
    var header = bytepad([encode_string(n), encode_string(c)], rate);
    if (extra) { header = concat([header, extra]); }
    return keccak_create(rate, 0x04, header, 24, suffix);
}

export function cshake128_create(fn_name, custom) { return xof(cshake_create(168, fn_name, custom)); }
export function cshake256_create(fn_name, custom) { return xof(cshake_create(136, fn_name, custom)); }

/* As kmac above. The fixed-length form commits to out_len up front: it is absorbed at the end. */
function kmac_create(key, rate, out_len, custom, is_xof) {
    var key_block = bytepad([encode_string(key)], rate);
    var suffix = right_encode(is_xof ? 0 : out_len * 8);
    return cshake_create(rate, KMAC_NAME, custom, suffix, key_block);
}

export function kmac128_create(key, out_len, custom) { return fixed(kmac_create(key, 168, out_len, custom, false), out_len); }
export function kmac256_create(key, out_len, custom) { return fixed(kmac_create(key, 136, out_len, custom, false), out_len); }
export function kmac128xof_create(key, custom) { return xof(kmac_create(key, 168, 0, custom, true)); }
export function kmac256xof_create(key, custom) { return xof(kmac_create(key, 136, 0, custom, true)); }
