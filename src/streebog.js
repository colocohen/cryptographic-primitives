/**
 * Streebog  -  GOST R 34.11-2012, RFC 6986
 *
 * The Russian federal hash standard, and the last of the national ciphers
 * this library was missing: SM3 and SM4 are Chinese, ARIA and SEED Korean,
 * Camellia Japanese, and this one closes the set.
 *
 * IT MATTERS BECAUSE IT IS MANDATORY IN ITS JURISDICTION. Russian government
 * systems, banking and the national PKI require it, and no JavaScript
 * implementation covers it well - the same gap that made RSA and Ascon worth
 * writing here.
 *
 * THE DESIGN is an AES-like block cipher used in Miyaguchi-Preneel mode: the
 * compression function is E(LPS(h XOR N), m) XOR h XOR m, where E is twelve
 * rounds of substitute-permute-linear over a 512-bit state.
 *
 * WHY IT LOOKS DIFFERENT FROM SHA-2. Streebog carries TWO extra 512-bit
 * accumulators alongside the state: N counts the bits absorbed and Sigma is
 * the running sum of the message blocks. Both are folded in at the end. That
 * makes length-extension impossible by construction rather than by a
 * truncation trick, which is what SHA-512/256 has to do.
 *
 * ITS S-BOX HAS A HISTORY. Pi was published with no design rationale, and in
 * 2016 Biryukov, Perrin and Udovenko recovered a hidden algebraic structure
 * in it - the substitution turns out to be built from a much simpler
 * construction over GF(2^8) than its random-looking table suggests. No attack
 * followed, and the finding is unexplained rather than damning, but it is the
 * reason this file derives what it can and states what it cannot.
 *
 * COEFFICIENTS: Pi, Tau, the linear transform's basis and the round constants
 * are all EXTRACTED PROGRAMMATICALLY from RFC 6986 rather than typed. The
 * lookup tables the implementation actually uses are then COMPUTED from
 * those, so an error would have to survive both the extraction and the
 * derivation.
 *
 * BIGINT IS USED HERE and that is a measured choice - see the note on the
 * precomputed tables below.
 */

import { GOST_PI as PI } from './commons/gost.js';

/* Tau, the byte permutation, section 6.3 */
var TAU = new Uint8Array([0,8,16,24,32,40,48,56,1,9,17,25,33,41,49,57,2,10,18,26,34,42,50,58,3,11,19,27,35,43,51,59,4,12,20,28,36,44,52,60,5,13,21,29,37,45,53,61,6,14,22,30,38,46,54,62,7,15,23,31,39,47,55,63]);

/* A, the linear transform's 64 basis vectors, section 6.4 */
var A_MATRIX = [
    0x8e20faa72ba0b470n,
    0x47107ddd9b505a38n,
    0xad08b0e0c3282d1cn,
    0xd8045870ef14980en,
    0x6c022c38f90a4c07n,
    0x3601161cf205268dn,
    0x1b8e0b0e798c13c8n,
    0x83478b07b2468764n,
    0xa011d380818e8f40n,
    0x5086e740ce47c920n,
    0x2843fd2067adea10n,
    0x14aff010bdd87508n,
    0x0ad97808d06cb404n,
    0x05e23c0468365a02n,
    0x8c711e02341b2d01n,
    0x46b60f011a83988en,
    0x90dab52a387ae76fn,
    0x486dd4151c3dfdb9n,
    0x24b86a840e90f0d2n,
    0x125c354207487869n,
    0x092e94218d243cban,
    0x8a174a9ec8121e5dn,
    0x4585254f64090fa0n,
    0xaccc9ca9328a8950n,
    0x9d4df05d5f661451n,
    0xc0a878a0a1330aa6n,
    0x60543c50de970553n,
    0x302a1e286fc58ca7n,
    0x18150f14b9ec46ddn,
    0x0c84890ad27623e0n,
    0x0642ca05693b9f70n,
    0x0321658cba93c138n,
    0x86275df09ce8aaa8n,
    0x439da0784e745554n,
    0xafc0503c273aa42an,
    0xd960281e9d1d5215n,
    0xe230140fc0802984n,
    0x71180a8960409a42n,
    0xb60c05ca30204d21n,
    0x5b068c651810a89en,
    0x456c34887a3805b9n,
    0xac361a443d1c8cd2n,
    0x561b0d22900e4669n,
    0x2b838811480723ban,
    0x9bcf4486248d9f5dn,
    0xc3e9224312c8c1a0n,
    0xeffa11af0964ee50n,
    0xf97d86d98a327728n,
    0xe4fa2054a80b329cn,
    0x727d102a548b194en,
    0x39b008152acb8227n,
    0x9258048415eb419dn,
    0x492c024284fbaec0n,
    0xaa16012142f35760n,
    0x550b8e9e21f7a530n,
    0xa48b474f9ef5dc18n,
    0x70a6a56e2440598en,
    0x3853dc371220a247n,
    0x1ca76e95091051adn,
    0x0edd37c48a08a6d8n,
    0x07e095624504536cn,
    0x8d70c431ac02a736n,
    0xc83862965601dd1bn,
    0x641c314b2b8ee083n
];

/* the twelve round constants, section 8 */
var C = [
    0xb1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507n,
    0x6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7n,
    0xf574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2n,
    0xef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12en,
    0x4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57n,
    0xae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6en,
    0xf4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493n,
    0x9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71en,
    0x378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adbn,
    0xabbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459cedn,
    0x7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1bn,
    0x378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720n
];

/**
 * The LPS transform, precomputed as eight tables of 256 sixty-four-bit values.
 *
 * L, P and S applied in sequence are equivalent to eight table lookups and
 * seven XORs, which is the standard optimisation and the reason Streebog is
 * fast in software at all. Applying the 64x64 binary matrix directly would be
 * 4096 bit tests per byte column.
 *
 * These are DERIVED from PI and A_MATRIX at load rather than shipped as a
 * literal, which is 2048 constants that would otherwise have to be trusted.
 */
var LPS = /* @__PURE__ */ (function () {
    var t = [];
    for (var i = 0; i < 8; i++) {
        var row = new Array(256);
        for (var b = 0; b < 256; b++) {
            var v = 0n;
            var s = PI[b];
            for (var bit = 0; bit < 8; bit++) {
                if ((s >> (7 - bit)) & 1) { v ^= A_MATRIX[i * 8 + bit]; }
            }
            row[b] = v;
        }
        t.push(row);
    }
    return t;
}());

var MASK = (1n << 512n) - 1n;

/*
 * BYTE ORDER. The standard writes a 512-bit vector most significant byte
 * FIRST, and the padding example in RFC 6986 section 10.1.1 makes the
 * consequence concrete: a 63-byte message pads to `01 || M`, with the 1 bit
 * at the TOP of the block and the message RIGHT-ALIGNED inside it. Loading a
 * message left-aligned and appending the pad - the SHA-2 convention, and the
 * first thing this implementation did - produces a completely different value.
 */
function to_int(b) {
    var v = 0n;
    for (var i = 0; i < 64; i++) { v = (v << 8n) | BigInt(b[i]); }
    return v;
}

function to_bytes(v) {
    var out = new Uint8Array(64);
    for (var i = 63; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
}

/**
 * L(P(S(x))) in one pass.
 *
 * The byte at position Tau[i] contributes to output word i/8, which is why
 * the permutation disappears into the indexing rather than becoming a
 * separate step.
 */
/*
 * ⚠ THIS FILE IS BigInt THROUGHOUT, AND THAT IS WHY IT IS SLOW.
 *
 *   MEASURED: 1 MB/s, against sha256's 91. Streebog works on 512-bit blocks
 *   as eight 64-bit words, and JavaScript has no 64-bit integer type - so
 *   every xor, every add and every table lookup allocates.
 *
 *   The LPS table is already there, so the algorithm is not the problem:
 *   the representation is. A rewrite on (hi, lo) pairs of 32-bit words -
 *   the shape siphash24, the GHASH table and gf128 all use - is what would
 *   fix it.
 *
 * ⛔ AND THAT REWRITE IS NOT A TRANSCRIPTION. One was attempted for
 *   HighwayHash in this library and abandoned: its mixing step adds MASKED
 *   64-bit values and then shifts, so carries cross word boundaries and a
 *   naive split is wrong. Streebog's add512 has the same property - it is a
 *   512-bit addition, and the carry runs the whole width.
 *
 *   So it is left as it is, measured and labelled, rather than half-rewritten.
 *   ⭐ Use sha256 or blake2s unless you need Streebog's output.
 */
function lps(x) {
    var b = to_bytes(x);
    var out = 0n;
    for (var i = 0; i < 8; i++) {
        var w = 0n;
        for (var j = 0; j < 8; j++) {
            w ^= LPS[j][b[TAU[i * 8 + j]]];
        }
        /*
         * Word i is the i-th from the TOP, because to_bytes writes the most
         * significant byte at index 0 and Tau indexes into that layout.
         * Shifting by 64*i instead reverses the eight output words - which
         * still passes a test on an all-zero input, since every word is then
         * identical.
         */
        out |= w << BigInt(64 * (7 - i));
    }
    return out;
}

/** Twelve rounds of the key schedule and the cipher, both LPS-based. */
function E(K, m) {
    var state = m ^ K;
    var key = K;
    for (var i = 0; i < 12; i++) {
        state = lps(state);
        key = lps(key ^ C[i]);
        state ^= key;
    }
    return state;
}

/** The compression function: Miyaguchi-Preneel around E. */
function g(N, h, m) {
    return E(lps(h ^ N), m) ^ h ^ m;
}

function add512(a, b) { return (a + b) & MASK; }

/**
 * @param {Uint8Array} msg
 * @param {number}     bits  256 or 512
 */
function streebog(msg, bits) {
    /*
     * The 512-bit variant starts from zero, the 256-bit one from 0x01 in
     * every byte; build it directly.
     *
     * ⭐ ONCE. A product expression computed the same 0x0101...01 here and was
     *   then overwritten by this loop on the very next line - two derivations
     *   of one constant, the first never used.
     */
    var h = 0n;
    if (bits === 256) {
        for (var q = 0; q < 64; q++) { h |= 0x01n << BigInt(8 * q); }
    }

    var N = 0n, sigma = 0n;
    var i = 0;

    /*
     * BYTE ORDER, PART TWO. The standard's own test vector gives this away:
     * its M1 begins 32 31 30 39, which is ASCII for "2109" - the string
     * "0123..." written BACKWARDS. A message is loaded into the 512-bit
     * vector with its FIRST byte at the LOWEST position, so the buffer is
     * filled in reverse.
     *
     * Every other hash in this library loads bytes in order. Getting this
     * wrong produces a working, self-consistent hash function that agrees
     * with nothing.
     */
    var blk = new Uint8Array(64);

    /* stage 2: full 64-byte blocks */
    for (; msg.length - i >= 64; i += 64) {
        for (var z = 0; z < 64; z++) { blk[63 - z] = msg[i + z]; }
        var m = to_int(blk);
        h = g(N, h, m);
        N = add512(N, 512n);
        sigma = add512(sigma, m);
    }

    /* stage 3: the remainder, padded with a single 1 bit */
    var rem = msg.length - i;
    var last = new Uint8Array(64);
    for (var y = 0; y < rem; y++) { last[63 - y] = msg[i + y]; }
    last[63 - rem] = 0x01;
    var ml = to_int(last);
    h = g(N, h, ml);
    N = add512(N, BigInt(rem * 8));
    sigma = add512(sigma, ml);

    /* the two accumulators are folded in - this is what removes
       length-extension without needing truncation */
    h = g(0n, h, N);
    h = g(0n, h, sigma);

    /*
     * The digest comes back out in the same reversed convention it went in.
     * The 256-bit variant is the HIGH half of the 512-bit state, which after
     * reversal is the SECOND half of the byte string.
     */
    var v = to_bytes(h);
    var out = new Uint8Array(64);
    for (var z = 0; z < 64; z++) { out[z] = v[63 - z]; }
    return bits === 256 ? out.subarray(32) : out;
}

/** GOST R 34.11-2012 with a 256-bit digest. */
export var streebog256 = /* @__PURE__ */ (function () {
    function f(msg) { return streebog(msg, 256); }
    f.BLOCK_SIZE = 64; f.DIGEST_SIZE = 32;
    f.create = streebog256_create;
    return f;
}());

/** GOST R 34.11-2012 with a 512-bit digest. */
export var streebog512 = /* @__PURE__ */ (function () {
    function f(msg) { return streebog(msg, 512); }
    f.BLOCK_SIZE = 64; f.DIGEST_SIZE = 64;
    f.create = streebog512_create;
    return f;
}());

/* ---------------- Incremental ---------------- */
/*
 * The same hash fed in pieces: update() as often as needed, digest() once;
 * copy() forks the state. The chaining value and both accumulators are
 * BigInts, which are immutable, so a copy is the three values and the
 * buffered partial block.
 *
 * A full 64-byte block is compressed as soon as it is complete: stage 2
 * above takes every full block, and the padded final block is always a
 * separate one, even when it carries no message bytes.
 */
function streebog_create(bits) {
    var h = 0n;
    if (bits === 256) {
        for (var q = 0; q < 64; q++) { h |= 0x01n << BigInt(8 * q); }
    }
    return streebog_instance(bits, h, 0n, 0n, new Uint8Array(64), 0);
}

function streebog_instance(bits, h, N, sigma, buf, buf_len) {
    var done = false;
    var blk = new Uint8Array(64);

    function check() {
        if (done) { throw new Error('streebog: digest() was already called on this instance'); }
    }
    /* stage 2 for one full block at src[off..off+64), loaded reversed */
    function block(src, off) {
        for (var z = 0; z < 64; z++) { blk[63 - z] = src[off + z]; }
        var m = to_int(blk);
        h = g(N, h, m);
        N = add512(N, 512n);
        sigma = add512(sigma, m);
    }

    var self = {
        update: function (msg) {
            check();
            var len = msg.length, off = 0, i;
            if (buf_len > 0) {
                var take = Math.min(64 - buf_len, len);
                for (i = 0; i < take; i++) { buf[buf_len + i] = msg[i]; }
                buf_len += take;
                off = take;
                if (buf_len < 64) { return self; }
                block(buf, 0);
                buf_len = 0;
            }
            for (; len - off >= 64; off += 64) { block(msg, off); }
            for (i = 0; off + i < len; i++) { buf[i] = msg[off + i]; }
            buf_len = len - off;
            return self;
        },
        copy: function () {
            check();
            return streebog_instance(bits, h, N, sigma, new Uint8Array(buf), buf_len);
        },
        digest: function () {
            check();
            done = true;
            /* stage 3, as in streebog() */
            var last = new Uint8Array(64);
            for (var y = 0; y < buf_len; y++) { last[63 - y] = buf[y]; }
            last[63 - buf_len] = 0x01;
            var ml = to_int(last);
            h = g(N, h, ml);
            N = add512(N, BigInt(buf_len * 8));
            sigma = add512(sigma, ml);
            h = g(0n, h, N);
            h = g(0n, h, sigma);
            var v = to_bytes(h);
            var out = new Uint8Array(64);
            for (var z = 0; z < 64; z++) { out[z] = v[63 - z]; }
            buf.fill(0);
            return bits === 256 ? out.slice(32) : out;
        }
    };
    return self;
}

/** @return {{update: function(Uint8Array): object, copy: function(): object, digest: function(): Uint8Array}} */
export function streebog256_create() { return streebog_create(256); }

/** @return {{update: function(Uint8Array): object, copy: function(): object, digest: function(): Uint8Array}} */
export function streebog512_create() { return streebog_create(512); }
