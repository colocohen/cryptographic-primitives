/**
 * Word operations: byte order and rotation
 *
 * Extracted after seven files had each written their own `rd32` - and, more
 * to the point, after two of those seven meant something different by it.
 *
 * aes, camellia, seed and sm4 read big-endian; chacha and salsa read
 * little-endian. Same function name, opposite byte order, no way to notice by
 * reading one file. That is the same trap documented for `add64` in argon2.js
 * and checksum.js, and this is the resolution the note there could not reach:
 * the names here say which order they mean, so the two can coexist in one
 * place without either caller having to remember.
 *
 * Nothing here is in an inner loop. These run four times per block, not once
 * per byte, and cross-module calls in this project measured free - see
 * commons/arx32.js.
 */

/** Read four bytes as a big-endian 32-bit word. */
export function rd_be32(a, o) {
    return ((a[o] << 24) | (a[o + 1] << 16) | (a[o + 2] << 8) | a[o + 3]) | 0;
}

/** Read four bytes as a little-endian 32-bit word. */
export function rd_le32(a, o) {
    return ((a[o]) | (a[o + 1] << 8) | (a[o + 2] << 16) | (a[o + 3] << 24)) | 0;
}

/** Write a 32-bit word as four big-endian bytes. */
export function wr_be32(a, o, v) {
    a[o]     = (v >>> 24) & 0xff; a[o + 1] = (v >>> 16) & 0xff;
    a[o + 2] = (v >>> 8) & 0xff;  a[o + 3] = v & 0xff;
}

/** Write a 32-bit word as four little-endian bytes. */
export function wr_le32(a, o, v) {
    a[o]     = v & 0xff;          a[o + 1] = (v >>> 8) & 0xff;
    a[o + 2] = (v >>> 16) & 0xff; a[o + 3] = (v >>> 24) & 0xff;
}

/** Write an array of words as consecutive big-endian bytes. */
export function wr_be32s(a, o, words) {
    for (var i = 0; i < words.length; i++) { wr_be32(a, o + i * 4, words[i]); }
}

/** Write an array of words as consecutive little-endian bytes. */
export function wr_le32s(a, o, words) {
    for (var i = 0; i < words.length; i++) { wr_le32(a, o + i * 4, words[i]); }
}

/**
 * Hex text to bytes and back, lowercase. For constants written into source
 * (a DST, a table) and for compat wrappers - four files had each written
 * their own copy of the decoder.
 */
export function from_hex(s) {
    var out = new Uint8Array(s.length >> 1);
    for (var i = 0; i < out.length; i++) { out[i] = parseInt(s.substr(i * 2, 2), 16); }
    return out;
}

export function to_hex(a) {
    var s = '';
    for (var i = 0; i < a.length; i++) { s += (a[i] >>> 4).toString(16) + (a[i] & 15).toString(16); }
    return s;
}

/**
 * Concatenate byte arrays.
 *
 * Trivial, and duplicated in argon2.js and kdf.js before it moved here.
 * Length-prefixed encodings live with the algorithms that define them - see
 * encode_string and bytepad in commons/keccak.js - because those carry
 * meaning. This one carries none, which is exactly why it belongs in one
 * place rather than three.
 */
export function concat(parts) {
    var total = 0, i, j, p, n;
    for (i = 0; i < parts.length; i++) { total += parts[i].length; }
    var out = new Uint8Array(total), o = 0;
    for (i = 0; i < parts.length; i++) {
        p = parts[i]; n = p.length;
        /* a short part by hand: TypedArray.set costs more than the copy below ~48 bytes (measured, 1.6x on transcript-sized parts) */
        if (n < 48) { for (j = 0; j < n; j++) { out[o + j] = p[j]; } }
        else { out.set(p, o); }
        o += n;
    }
    return out;
}

/** A 32-bit value as four big-endian bytes, allocated fresh. */
export function be32(n) {
    return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/**
 * Rotate a 32-bit word left.
 *
 * Several files defined this identically - md4, sm3 and sm4 among them - and
 * one copy carried a guard for n = 0 that the others did not. The guard is
 * unnecessary: JavaScript masks shift counts to five bits, so x >>> 32 is
 * x >>> 0, and (x << 0) | (x >>> 0) folded through | 0 returns x unchanged.
 * Verified across every rotation amount and a spread of signed and unsigned
 * inputs before the guard was dropped.
 *
 * Worth stating because "rotate by zero" is a real edge case wherever the
 * rotation amount is data-derived rather than fixed - blowfish's key schedule
 * and several stream ciphers can land on it.
 */
export function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) | 0; }

/** Rotate a 32-bit word right. */
export function rotr32(x, n) { return ((x >>> n) | (x << (32 - n))) | 0; }

/**
 * Big-endian bytes to a BigInt, and back at a fixed width.
 *
 * RFC 8017 calls these OS2IP and I2OSP, X9.62 calls them something else, and
 * commons/ecdsa.js and rsa.js had written both under two more names before
 * they landed here. The operation is the same in every case.
 *
 * FIXED WIDTH ON THE WAY OUT is the part that matters. A value that happens
 * to be small must still fill the full length, or its magnitude leaks through
 * the length of its encoding - and in RSA a short encoding also changes what
 * the modular exponentiation computes.
 */
/*
 * ⭐ THROUGH A HEX STRING, not a byte at a time. Shifting a growing BigInt
 *   by 8 once per byte copies it every time - quadratic in the length:
 *   measured 131 µs for 1024 bytes, against 10 µs this way (32 bytes:
 *   2.3 → 0.5 µs). The same value; checked against the loop for every
 *   length from 0 to 1024.
 */
var HEX = [];
for (var hx = 0; hx < 256; hx++) { HEX.push((hx < 16 ? '0' : '') + hx.toString(16)); }

export function bytes_to_bigint(b) {
    var n = b.length;
    if (n === 0) { return 0n; }
    if (n <= 6) {
        var w = 0;
        for (var j = 0; j < n; j++) { w = w * 256 + b[j]; }
        return BigInt(w);
    }
    var h = '';
    for (var i = 0; i < n; i++) { h += HEX[b[i]]; }
    return BigInt('0x' + h);
}

export function bigint_to_bytes(x, len) {
    /*
     * `len` IS REQUIRED, and omitting it used to give an empty array rather
     * than a failure - so an integer serialised without its width silently
     * became nothing, and whatever consumed it saw a valid-looking zero-byte
     * field. The whole point of this function is the fixed width.
     */
    if (typeof len !== 'number' || len < 0 || (len | 0) !== len) {
        throw new TypeError('bytes: bigint_to_bytes needs a byte width');
    }
    var out = new Uint8Array(len);
    /*
     * ⭐ LONG NON-NEGATIVE VALUES THROUGH HEX, for the same reason as
     *   bytes_to_bigint (1024 bytes: 108 → 38 µs). Short or negative ones
     *   keep the loop, which is faster below ~64 bytes and defines what a
     *   negative value becomes (its low `len` bytes, two's complement).
     *   Values wider than `len` keep their low `len` bytes either way.
     */
    if (len < 64 || x < 0n) {
        for (var i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
        return out;
    }
    var h = x.toString(16);
    if (h.length & 1) { h = '0' + h; }
    var nb = h.length >> 1, start = nb > len ? nb - len : 0;
    for (var k = start, o = len - (nb - start); k < nb; k++, o++) {
        out[o] = parseInt(h.substr(2 * k, 2), 16);
    }
    return out;
}

/**
 * Read four bytes as an UNSIGNED big-endian 32-bit value.
 *
 * rd_be32 returns a signed int32, which is what every cipher here wants -
 * its callers feed the result straight into bitwise arithmetic. Format and
 * protocol code wants the unsigned value: LMS compares 32-bit algorithm
 * identifiers, and a type code with the top bit set would compare as
 * negative.
 */
export function rd_be32u(a, o) {
    return (((a[o] << 24) | (a[o + 1] << 16) | (a[o + 2] << 8) | a[o + 3]) >>> 0);
}

/**
 * Increment a big-endian counter in place, wrapping at the array's width.
 *
 * WRITTEN THE LONG WAY ON PURPOSE. The obvious `if (++c[i] !== 0) break` is
 * WRONG on a typed array: ++ stores the wrapped value but EVALUATES to the
 * unwrapped one, so incrementing a byte of 255 yields 256 rather than 0 and
 * the carry never propagates. That bug shipped in this library's CTR_DRBG and
 * only showed up on the CAVP vectors where a counter byte actually reached
 * 255 - which made it look data-dependent and nearly hid it.
 *
 * Used by every counter mode and by CTR_DRBG.
 */
export function inc_be(c) {
    for (var i = c.length - 1; i >= 0; i--) {
        c[i] = (c[i] + 1) & 0xff;
        if (c[i] !== 0) { break; }
    }
}

/** Read bytes as a LITTLE-endian bigint. The 25519 family's convention. */
export function bytes_to_bigint_le(b) {
    var v = 0n;
    for (var i = b.length - 1; i >= 0; i--) { v = (v << 8n) | BigInt(b[i]); }
    return v;
}

/** A bigint as `len` little-endian bytes. */
export function bigint_to_bytes_le(v, len) {
    var out = new Uint8Array(len);
    var x = v;
    for (var i = 0; i < len; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
    return out;
}

/** dst = a XOR b, over `len` bytes. */
export function xor_bytes(dst, a, b, len) {
    for (var i = 0; i < len; i++) { dst[i] = a[i] ^ b[i]; }
}
/** a ^= b over a's length, in place; returns a. */
export function xor_into(a, b) { for (var i = 0; i < a.length; i++) { a[i] ^= b[i]; } return a; }
/** a XOR b, a fresh array of a's length (b at least as long). */
export function xor(a, b) { var o = new Uint8Array(a.length); for (var i = 0; i < a.length; i++) { o[i] = a[i] ^ b[i]; } return o; }

/** A single byte, as a one-element array. */
export function be8(n) { return new Uint8Array([n & 0xff]); }

/** A 16-bit value as two big-endian bytes. */
export function be16(n) {
    /*
     * ⛔ REFUSES WHAT DOES NOT FIT, as I2OSP(n, 2) does in every RFC that
     *    uses it. Thirty-odd call sites pass a LENGTH here as a transcript
     *    prefix; a silent wrap at 65536 made a 65536-byte field encode as
     *    an empty one, so two different transcripts could hash the same.
     */
    if (!(Number.isInteger(n) && n >= 0 && n <= 0xffff)) {
        throw new RangeError('be16: ' + n + ' does not fit in two bytes');
    }
    return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}

/** I2OSP(len(x), 2) || x - the RFCs' length prefix (be16 refuses a field over 65535 bytes). */
export function lp16(x) { return concat([be16(x.length), x]); }
/** A four-byte big-endian length, then the bytes. */
export function lp32(x) { return concat([be32(x.length), x]); }

/** A non-negative integer below 2^53 as len little-endian bytes (the bytes above it are zero). */
export function le_bytes(v, len) {
    var b = new Uint8Array(len);
    for (var i = 0; i < len; i++) { b[i] = v % 256; v = Math.floor(v / 256); }
    return b;
}

/** A 32-bit value as four little-endian bytes. */
export function le32(n) {
    return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

/**
 * A non-negative safe integer (a length, a bit count) as eight little-endian
 * bytes. Division rather than shifts: lengths in BITS pass 2^32.
 *
 * ChaCha20-Poly1305, AEGIS and AES-GCM-SIV each wrote this loop.
 */
export function le64(n) {
    if (!(Number.isSafeInteger(n) && n >= 0)) { throw new RangeError('le64: ' + n + ' is not a non-negative safe integer'); }
    var a = new Uint8Array(8);
    for (var i = 0; i < 8; i++) { a[i] = n % 256; n = Math.floor(n / 256); }
    return a;
}

/**
 * USER TEXT as UTF-8 bytes - passwords, messages, codes - and the "a string
 * or bytes" argument most entry points take.
 *
 * Not ascii(), below, which is for protocol constants and refuses anything
 * else. easy.js, otp.js, schnorr.js, zero_share.js and the compat shims each
 * spelled `new TextEncoder().encode(...)` or this ternary for themselves.
 */
export function utf8(s) { return new TextEncoder().encode(s); }
export function text_or_bytes(x) { return typeof x === 'string' ? utf8(x) : x; }

/**
 * An ASCII string as bytes.
 *
 * Six places wrote this loop before it moved here: the domain strings in
 * ed25519 and ed448, the BIP-340 tags in secp256k1, the HPKE labels, and
 * three separate copies inside sha3.js for cSHAKE, TupleHash and
 * ParallelHash.
 *
 * ASCII rather than UTF-8 ON PURPOSE. Every caller here is encoding a
 * protocol constant from a specification - "SigEd448", "BIP0340/challenge",
 * "HPKE-v1" - and those are ASCII by definition. Silently accepting a
 * non-ASCII character and truncating it to one byte would produce a wrong
 * domain string rather than an error, so it throws.
 *
 * Encoding user text is a different job: use TextEncoder for that.
 */
export function ascii(s) {
    var a = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        if (c > 127) { throw new Error('ascii: not an ASCII string: ' + s); }
        a[i] = c;
    }
    return a;
}

/**
 * A field or ring element as bytes, at the modulus's natural width.
 *
 * Two files needed the same three tokens - ring_pedersen.js and vdf.js - and
 * both for the same reason: hashing a transcript that mixes values modulo N
 * requires them at a FIXED width, or a value that happens to be small
 * serialises shorter and two different transcripts collide.
 */
export function mod_bytes(v, N) {
    return bigint_to_bytes(((v % N) + N) % N, (N.toString(2).length + 7) >> 3);
}

/**
 * Bytes from the platform's secure random source.
 *
 * Every randomness parameter of the library left out, or null, comes from
 * here (commons/primes.js's require_rng); a caller's own rng or bytes are
 * used instead, exactly. random.js is its public form.
 *
 * ⚠ getRandomValues FILLS AT MOST 65,536 BYTES A CALL, and throws
 *   QuotaExceededError above that, in browsers and in Node alike. A larger
 *   request is filled in pieces of that size - one source, so the pieces
 *   are as good as one draw.
 *
 * @throws when no secure source exists, rather than falling back to
 *         Math.random - which is how several libraries have shipped keys an
 *         attacker could predict
 */
var RANDOM_PIECE = 65536;
export function secure_random(n) {
    /*
     * Zero bytes of randomness is never what a caller means, and returning
     * it quietly is how a nonce or a key ends up empty.
     */
    if (typeof n !== 'number' || n <= 0 || (n | 0) !== n) {
        throw new TypeError('bytes: secure_random needs a positive byte count');
    }
    var out = new Uint8Array(n);
    if (typeof globalThis !== 'undefined' && globalThis.crypto &&
        globalThis.crypto.getRandomValues) {
        for (var off = 0; off < n; off += RANDOM_PIECE) {
            globalThis.crypto.getRandomValues(out.subarray(off, Math.min(n, off + RANDOM_PIECE)));
        }
        return out;
    }
    throw new Error('bytes: no secure random source available');
}

/* ==================== base64 ==================== */

/*
 * ⚠ base64 IS NOT A CRYPTOGRAPHIC PRIMITIVE, and it is here anyway.
 *
 * Every key format above the byte level needs it - JWK, JWS, JWE, PEM,
 * WebAuthn - and the alternatives are worse. `btoa`/`atob` do not exist in
 * Node before 16 and mangle anything outside Latin-1; `Buffer` does not
 * exist in a browser. Depending on either makes a library that runs in one
 * place and not the other.
 *
 * The URL-safe alphabet is the one JOSE uses everywhere, and its padding is
 * FORBIDDEN rather than optional - RFC 7515 section 2 says so, and a decoder
 * that accepts padded input silently admits two encodings of one value.
 */

var B64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var B64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/*
 * ⭐ THE GENERIC CODEC IS EXPORTED, with the alphabet as a parameter, because
 *   bcrypt's $2b$ encoding is this packing - three bytes to four characters,
 *   most significant bits first, no padding - over a different alphabet.
 *   bcrypt.js used to translate characters to and from the standard
 *   alphabet, and before that it and compat/bcrypt.js each carried a whole
 *   packer of their own.
 *
 *   yescrypt's crypt(3) encoding is NOT this - it packs little-endian - and
 *   keeps its own code.
 */

/**
 * @param {Uint8Array|Array<number>} bytes
 * @param {string}  alphabet  64 distinct characters
 * @param {boolean} pad       append '=' to a whole number of 4-character groups
 * @return {string}
 */
export function b64_encode(bytes, alphabet, pad) {
    var out = '', i;
    for (i = 0; i + 2 < bytes.length; i += 3) {
        var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        out += alphabet[(n >> 18) & 63] + alphabet[(n >> 12) & 63] +
               alphabet[(n >> 6) & 63] + alphabet[n & 63];
    }
    var rem = bytes.length - i;
    if (rem === 1) {
        var a = bytes[i] << 16;
        out += alphabet[(a >> 18) & 63] + alphabet[(a >> 12) & 63];
        if (pad) { out += '=='; }
    } else if (rem === 2) {
        var b = (bytes[i] << 16) | (bytes[i + 1] << 8);
        out += alphabet[(b >> 18) & 63] + alphabet[(b >> 12) & 63] +
               alphabet[(b >> 6) & 63];
        if (pad) { out += '='; }
    }
    return out;
}

/**
 * @param {string} str
 * @param {string} alphabet  64 distinct characters
 * @param {object} [opts]
 *   opts.pad    trailing '=' are accepted and stripped; without it any '='
 *               is refused
 *   opts.loose  decode the way bcrypt's reference does: stop at the first
 *               character outside the alphabet as if the string ended there,
 *               and ignore the unused bits of the last character. Never for
 *               a format where those bits are defined to be zero - which is
 *               every RFC 4648 one - since it admits several encodings of
 *               one value.
 * @return {Uint8Array|null}  null on a bad character, bad length or stray
 *                            bits, unless `loose` says to overlook them
 */
export function b64_decode(str, alphabet, opts) {
    var allow_pad = !!(opts && opts.pad), loose = !!(opts && opts.loose);
    var rev = {}, i;
    for (i = 0; i < 64; i++) { rev[alphabet[i]] = i; }

    var s = str;
    if (allow_pad) {
        while (s.length && s.charAt(s.length - 1) === '=') { s = s.slice(0, -1); }
    } else if (!loose && s.indexOf('=') >= 0) {
        return null;   /* padding is forbidden in base64url per RFC 7515 */
    }
    if (loose) {
        for (i = 0; i < s.length && rev[s.charAt(i)] !== undefined; i++) { /* scan */ }
        s = s.slice(0, i);
    } else if (s.length % 4 === 1) { return null; }

    var out = new Uint8Array((s.length * 3) >> 2);
    var acc = 0, bits = 0, o = 0;
    for (i = 0; i < s.length; i++) {
        var v = rev[s.charAt(i)];
        if (v === undefined) { return null; }
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (acc >> bits) & 0xff; }
    }
    /*
     * The leftover bits of the final character must be zero. Otherwise two
     * different strings decode to the same bytes, which is the same
     * malleability a lenient DER parser allows.
     */
    if (!loose && bits > 0 && (acc & ((1 << bits) - 1)) !== 0) { return null; }
    return out.subarray(0, o);
}

/** Standard base64, with padding. */
export function to_base64(bytes) { return b64_encode(bytes, B64_STD, true); }

/** @return {Uint8Array|null} null on any character outside the alphabet */
export function from_base64(str) { return b64_decode(str, B64_STD, { pad: true }); }

/** base64url, WITHOUT padding - the JOSE and WebAuthn form. */
export function to_base64url(bytes) { return b64_encode(bytes, B64_URL, false); }

/** @return {Uint8Array|null} null on padding, bad characters or stray bits */
export function from_base64url(str) { return b64_decode(str, B64_URL, { pad: false }); }

/*
 * An _into form's output (a keyed context's encrypt_into, decrypt_into) must
 * hold the result from `offset`; a RangeError otherwise, before anything is
 * written.
 */
export function check_room(who, out, offset, length) {
    if (offset + length > out.length) {
        throw new RangeError(who + ': the output has ' + Math.max(0, out.length - offset) +
            ' bytes from the offset; the result needs ' + length);
    }
}

/*
 * Would writing `length` bytes into out from `offset`, as `input` is read,
 * overwrite input not yet read? True when the two share memory and overlap
 * anywhere but at the same position - where a stream cipher reads each byte
 * before it writes it, so the same memory in and out is safe. An _into form
 * of the pure code writes straight into out unless this says so, and then
 * computes its result whole first.
 */
export function overlaps_elsewhere(out, offset, length, input) {
    if (!(input instanceof Uint8Array) || out.buffer !== input.buffer) { return false; }
    var a = out.byteOffset + offset, b = input.byteOffset;
    return a !== b && a < b + input.length && b < a + length;
}
