/**
 * Bit packing, least or most significant bit first, and bit reversal - the
 * bit-level jobs the lattice schemes share.
 *
 * ONE COPY, BECAUSE THERE WERE TWO. ml_dsa.js had pack_bits/unpack_bits and
 * ml_kem.js had byte_encode/byte_decode: the same loop, value by value, bit
 * by bit, least significant first (FIPS 203 Algorithms 5-6 and FIPS 204
 * Algorithms 16-19 define the same order). Checked byte for byte against
 * each other at every width from 1 to 12 before they were merged, and
 * expand_mask in ml_dsa.js had a third copy inlined.
 *
 * THE OUTPUT ARRAY IS THE CALLER'S. ML-KEM keeps coefficients in Int16Array
 * (three times faster than Int32Array there - see commons/kyber_ring.js) and
 * ML-DSA in Int32Array, so unpack_bits writes into whatever it is handed
 * rather than choosing a type for both.
 *
 * Not in an inner loop of anything: a key or ciphertext is packed once.
 */

/** Bit i of a byte string, the least significant bit of each byte first. */
export function bit_le(b, i) { return (b[i >> 3] >> (i & 7)) & 1; }

/** The n bits of a byte string from bit pos (least significant first), as an integer. */
export function bits_le(b, pos, n) {
    for (var v = 0, i = 0; i < n; i++) { v |= bit_le(b, pos + i) << i; }
    return v;
}

/**
 * Write values[0..values.length) as `bits`-bit fields into out, starting at
 * byte `off`. Bits are ORed in, so `out` must be zero over the range.
 */
export function pack_bits(values, bits, out, off) {
    var bit = off * 8;
    for (var i = 0; i < values.length; i++) {
        var v = values[i];
        for (var b = 0; b < bits; b++) {
            if ((v >> b) & 1) { out[bit >> 3] |= 1 << (bit & 7); }
            bit++;
        }
    }
}

/**
 * Read `count` fields of `bits` bits from `bytes` at byte `off`.
 *
 * @param {Int16Array|Int32Array} [out]  destination; a fresh Int32Array(count)
 *                                       when omitted
 */
export function unpack_bits(bytes, off, count, bits, out) {
    var o = out || new Int32Array(count);
    var bit = off * 8;
    for (var i = 0; i < count; i++) {
        var v = 0;
        for (var b = 0; b < bits; b++) {
            v |= ((bytes[bit >> 3] >> (bit & 7)) & 1) << b;
            bit++;
        }
        o[i] = v;
    }
    return o;
}

/**
 * The same, most significant bit first - Falcon's order for its keys
 * (public key coefficients, and the private key's f, g, F). Values are
 * masked to `bits`, so a signed value packs as its two's complement.
 * Returns the number of bytes written, ceil(count * bits / 8).
 */
export function pack_bits_be(values, bits, out, off) {
    var acc = 0, len = 0, pos = off, mask = (1 << bits) - 1;
    for (var i = 0; i < values.length; i++) {
        acc = ((acc << bits) | (values[i] & mask)) >>> 0;
        len += bits;
        while (len >= 8) { len -= 8; out[pos++] = (acc >>> len) & 0xff; }
        acc &= (1 << len) - 1;
    }
    if (len > 0) { out[pos++] = (acc << (8 - len)) & 0xff; }
    return pos - off;
}

/**
 * Read `count` fields of `bits` bits, most significant first. Returns the
 * fields and the unused low bits of the last byte, which a canonical
 * encoding requires to be zero.
 */
export function unpack_bits_be(bytes, off, count, bits, out) {
    var o = out || new Int32Array(count), acc = 0, len = 0, pos = off, mask = (1 << bits) - 1;
    for (var i = 0; i < count; i++) {
        while (len < bits) { acc = ((acc << 8) | bytes[pos++]) >>> 0; len += 8; }
        len -= bits;
        o[i] = (acc >>> len) & mask;
        acc &= (1 << len) - 1;
    }
    return { values: o, rest: acc };
}

/**
 * x with its low `bits` bits in reverse order - the index permutation both
 * NTT twiddle tables (commons/dilithium_ring.js, commons/kyber_ring.js) are
 * stored in. Each table generator had its own copy of this loop.
 */
export function bit_reverse(x, bits) {
    var r = 0;
    for (var b = 0; b < bits; b++) { r = (r << 1) | (x & 1); x >>= 1; }
    return r;
}
