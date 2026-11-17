/**
 * The Ascon permutation
 *
 * A 320-bit state as five 64-bit words, permuted by 12, 8 or 6 rounds. It is
 * the single primitive underneath everything in NIST SP 800-232: the AEAD,
 * the hash and both XOFs are sponge constructions over this one function,
 * which is most of why Ascon is small enough for constrained devices.
 *
 * WORDS ARE CARRIED AS hi/lo INT32 PAIRS, the same decision as sha2.js and
 * blake2b for the same measured reason: BigInt is several times slower at
 * this width. commons/modp.js reverses that decision at 256 bits, where the
 * arithmetic is large enough to amortise BigInt's allocation - see the note
 * there.
 *
 * The state is module-level and reused, so this is NOT reentrant. No caller
 * here interleaves work, and a 320-bit allocation per permutation call would
 * dominate the cost of the permutation itself.
 */

/*
 * Round constants: 0xf0, 0xe1, ... 0x0f, one nibble pair counting in opposite
 * directions. A 12-round permutation uses all of them; 8 rounds start at
 * index 4 and 6 rounds at index 6, so the LAST rounds are always the same -
 * which is what lets one constant table serve every variant.
 */
var RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b];

/* five 64-bit words, high and low halves */
export var sh = new Int32Array(5);
export var sl = new Int32Array(5);

/** Rotate a 64-bit word right by n, returning [hi, lo]. */
function rotr64(hi, lo, n) {
    if (n === 0) { return [hi, lo]; }
    if (n < 32) {
        return [((hi >>> n) | (lo << (32 - n))) | 0,
                ((lo >>> n) | (hi << (32 - n))) | 0];
    }
    if (n === 32) { return [lo, hi]; }
    n -= 32;
    return [((lo >>> n) | (hi << (32 - n))) | 0,
            ((hi >>> n) | (lo << (32 - n))) | 0];
}

/**
 * @param {number} rounds  12, 8 or 6
 *
 * The substitution layer is a 5-bit S-box applied BITSLICED - across the five
 * words at once rather than to each word in turn. That is the whole trick
 * behind Ascon's speed in software: sixty-four S-box evaluations happen in
 * parallel as a handful of word operations, and there is no table, so there
 * is no cache-timing channel of the kind aes.js has to warn about.
 */
export function ascon_p(rounds) {
    var start = 12 - rounds;

    for (var r = start; r < 12; r++) {
        /* add the round constant to x2 */
        sl[2] ^= RC[r];

        /* substitution layer, bitsliced */
        sh[0] ^= sh[4]; sl[0] ^= sl[4];
        sh[4] ^= sh[3]; sl[4] ^= sl[3];
        sh[2] ^= sh[1]; sl[2] ^= sl[1];

        var t0h = (~sh[0]) & sh[1], t0l = (~sl[0]) & sl[1];
        var t1h = (~sh[1]) & sh[2], t1l = (~sl[1]) & sl[2];
        var t2h = (~sh[2]) & sh[3], t2l = (~sl[2]) & sl[3];
        var t3h = (~sh[3]) & sh[4], t3l = (~sl[3]) & sl[4];
        var t4h = (~sh[4]) & sh[0], t4l = (~sl[4]) & sl[0];

        sh[0] ^= t1h; sl[0] ^= t1l;
        sh[1] ^= t2h; sl[1] ^= t2l;
        sh[2] ^= t3h; sl[2] ^= t3l;
        sh[3] ^= t4h; sl[3] ^= t4l;
        sh[4] ^= t0h; sl[4] ^= t0l;

        sh[1] ^= sh[0]; sl[1] ^= sl[0];
        sh[0] ^= sh[4]; sl[0] ^= sl[4];
        sh[3] ^= sh[2]; sl[3] ^= sl[2];
        sh[2] = ~sh[2]; sl[2] = ~sl[2];

        /* linear diffusion: each word xored with two rotations of itself */
        var a, b;
        a = rotr64(sh[0], sl[0], 19); b = rotr64(sh[0], sl[0], 28);
        sh[0] ^= a[0] ^ b[0]; sl[0] ^= a[1] ^ b[1];
        a = rotr64(sh[1], sl[1], 61); b = rotr64(sh[1], sl[1], 39);
        sh[1] ^= a[0] ^ b[0]; sl[1] ^= a[1] ^ b[1];
        a = rotr64(sh[2], sl[2], 1);  b = rotr64(sh[2], sl[2], 6);
        sh[2] ^= a[0] ^ b[0]; sl[2] ^= a[1] ^ b[1];
        a = rotr64(sh[3], sl[3], 10); b = rotr64(sh[3], sl[3], 17);
        sh[3] ^= a[0] ^ b[0]; sl[3] ^= a[1] ^ b[1];
        a = rotr64(sh[4], sl[4], 7);  b = rotr64(sh[4], sl[4], 41);
        sh[4] ^= a[0] ^ b[0]; sl[4] ^= a[1] ^ b[1];
    }
}

/*
 * ==================== BYTES IN AND OUT OF THE STATE ====================
 *
 * Every helper below takes a byte order. Ascon v1.2 puts the first byte of a
 * block in the MOST significant byte of a word; NIST SP 800-232 puts it in the
 * LEAST - see the long note in ascon.js. These were big-endian only, nothing
 * imported them, and ascon.js wrote its own byte-order-aware versions; those
 * are what is here now, so there is one set and it is used.
 *
 * @param {boolean} [le]  NIST order; v1.2 (big-endian) when omitted
 */

/** XOR byte value v into byte k (0..7) of state word i. */
export function xor_byte(i, k, v, le) {
    if (le) {
        if (k < 4) { sl[i] ^= (v << (8 * k)); }
        else       { sh[i] ^= (v << (8 * (k - 4))); }
    } else {
        if (k < 4) { sh[i] ^= (v << (24 - 8 * k)); }
        else       { sl[i] ^= (v << (24 - 8 * (k - 4))); }
    }
}

/** Read byte k (0..7) of state word i. */
export function byte_of(i, k, le) {
    if (le) {
        return (k < 4 ? (sl[i] >>> (8 * k)) : (sh[i] >>> (8 * (k - 4)))) & 0xff;
    }
    return (k < 4 ? (sh[i] >>> (24 - 8 * k)) : (sl[i] >>> (24 - 8 * (k - 4)))) & 0xff;
}

/** XOR `len` bytes (default 8) of b, from off, into state word i. */
export function xor_word(i, b, off, len, le) {
    var n = len === undefined ? 8 : len;
    for (var k = 0; k < n; k++) { xor_byte(i, k, b[off + k], le); }
}

/** Load eight bytes of b, from off, as state word i. */
export function load_word(i, b, off, le) {
    sh[i] = 0; sl[i] = 0;
    xor_word(i, b, off, 8, le);
}

/** Store state word i as eight bytes. */
export function store_word(i, out, off, le) {
    for (var k = 0; k < 8; k++) { out[off + k] = byte_of(i, k, le); }
}

/** Set slot i from a literal 64-bit value given as two halves. */
export function set_word(i, hi, lo) { sh[i] = hi | 0; sl[i] = lo | 0; }

export function clear_state() {
    for (var i = 0; i < 5; i++) { sh[i] = 0; sl[i] = 0; }
}
