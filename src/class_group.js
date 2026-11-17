/**
 * Class groups of imaginary quadratic fields  -  binary quadratic forms
 *
 * A group whose ORDER NOBODY KNOWS, and needs no one to forget it. An RSA
 * modulus has a known order for whoever made it (vdf.js says so at length);
 * here the group is fixed by a negative discriminant D, derived from a public
 * seed, and computing its order (the class number) is a hard problem with no
 * trapdoor: there is nothing to destroy, because nothing was ever known. This
 * is the group Chia's proofs of time run in, and what vdf_class.js runs
 * Wesolowski's VDF over.
 *
 * ========================== THE OBJECTS ==========================
 *
 * An element is a reduced binary quadratic form (a, b, c), a·x² + b·xy + c·y²
 * with b² − 4ac = D:
 *
 *     -a < b <= a <= c,  and b >= 0 when a == c
 *
 * Every class has exactly ONE reduced form, so equality is equality of
 * (a, b) and every operation here returns reduced forms. c follows from
 * (a, b) and D. The identity is (1, 1, (1−D)/4); (2, 1, (1−D)/8) is the
 * "generator" Chia starts from (it exists when D ≡ 1 mod 8).
 *
 * ========================== THE OPERATIONS ==========================
 *
 *   NUDUPL   squaring, Shanks' NUCOMP specialised (Jacobson and van der
 *            Poorten): a partial extended gcd stopped at |D|^(1/4) leaves
 *            the result almost reduced, so reduction is a step or two.
 *   NUCOMP   composition of two forms, the same way.
 *   reduce   Gauss's: normalise b into (−a, a], swap while a > c.
 *
 * The NUCOMP and NUDUPL here are chiavdf's (src/nucomp.h, nucomp_phases.h,
 * after William Hart's in Antic), statement for statement, with GMP's
 * operations spelled in BigInt - floor or truncating division as each one
 * is. Their outputs are reduced afterwards, so what is compared anywhere is
 * the unique reduced form. The extended gcds are Euclid's, run several
 * steps at a time by Lehmer's method (each step proved to be Euclid's, so
 * every remainder and cofactor is Euclid's own); the partial one stops at
 * exactly the state chiavdf's stops at. Lehmer is most of the speed: a
 * squaring at 1024 bits went from 0.14 ms to 0.04 ms.
 *
 * ========================== THE ENCODINGS ==========================
 *
 *   compressed     chiavdf's BQFC (src/bqfc.c): (a, b) as (a/g, t/g, g, b0)
 *                  with t from the partial gcd of (a, |b|) stopped at √a -
 *                  about three quarters of |D| in bits. 100 bytes for
 *                  |D| <= 1024 bits, as Chia; above that, its own width
 *                  formula, (bits rounded up to 32)/32·3 + 4.
 *   uncompressed   a flag byte (b's sign), a and |b| at ⌈bits/16⌉ bytes each.
 *
 * ⭐ ONE BYTE STRING PER ELEMENT, IN BOTH. A decoder that accepted two
 *    encodings of one element would let two parties agree on the element and
 *    disagree on its bytes - fatal where the bytes are hashed (Wesolowski's
 *    challenge) or compared (consensus). So decode() rebuilds the form, checks
 *    it is reduced and of this discriminant, encodes it again and requires
 *    the same bytes - padding and every unused bit included (chiavdf's
 *    bqfc_verify_canon does the same).
 *
 * ========================== THE DISCRIMINANT ==========================
 *
 * discriminant(seed, bits) is chiavdf's CreateDiscriminant: HashPrime over
 * SHA-256 of the seed with a counter, bits 0, 1, 2 and the top one set - so
 * p ≡ 7 (mod 8), D = −p ≡ 1 (mod 8) - the first probable prime (Baillie-PSW,
 * as chiavdf). Same seed, same D, bit for bit; any bits a multiple of 8
 * (chiavdf stops at 1024; this does not). -D prime makes the class number
 * odd: no element of order 2 to start a sequence from.
 *
 * ⚠️ Variable time throughout: everything here is public - a VDF has no
 *    secret.
 */

import { sha256 } from './sha2.js';
import { is_probable_prime, isqrt, jacobi } from './commons/primes.js';
import { concat, bytes_to_bigint, bigint_to_bytes, utf8 } from './commons/bytes.js';

/* ------------------------------------------------------------ integers */

function abs(x) { return x < 0n ? -x : x; }
/* GMP's floor division and remainder (fdiv_q / fdiv_r): the remainder takes the divisor's sign */
function fdiv_q(n, d) { var q = n / d; return (n % d !== 0n && ((n < 0n) !== (d < 0n))) ? q - 1n : q; }
function fdiv_r(n, d) { var r = n % d; return (r !== 0n && ((r < 0n) !== (d < 0n))) ? r + d : r; }
function bitlen(x) {
    if (x === 0n) { return 0; }
    var h = abs(x).toString(16);
    return (h.length - 1) * 4 + (32 - Math.clz32(parseInt(h[0], 16)));
}

/*
 * EUCLID, SEVERAL STEPS AT A TIME (Lehmer; Knuth, TAOCP vol. 2, 4.5.2,
 * Algorithm L). For u >= v > 0, the quotients of Euclid's algorithm are
 * worked out on the top 50 bits of u and v alone, and each is kept only once
 * Knuth's test proves it the true one: ⌊(û+A)/(v̂+C)⌋ = ⌊(û+B)/(v̂+D)⌋. The
 * steps are Euclid's own, so every remainder and cofactor after them is
 * exactly what one step at a time gives - only cheaper: the matrix of a
 * whole run is applied to the full numbers once, in place of a division and
 * four multiplications per step. Returns [A, B, C, D] with the new
 * (u, v) = (A·u + B·v, C·u + D·v), or null when not one step was proved (the
 * caller then takes one full step). Every value stays below 2^52: exact in a
 * double.
 */
var LEHMER_MIN = 1n << 64n;     /* below this a step at a time is as fast */
function lehmer(u, v) {
    /* u's bit length, or one more - either leaves û below 2^50 */
    var f = Number(u), e = f < Infinity ? Math.floor(Math.log2(f)) + 1 : bitlen(u);
    var shift = BigInt(e - 50);
    var uh = Number(u >> shift), vh = Number(v >> shift);
    var A = 1, B = 0, C = 0, D = 1;
    for (;;) {
        var d1 = vh + C, d2 = vh + D;
        if (d1 === 0 || d2 === 0) { break; }
        var q = floor_div(uh + A, d1);
        if (q !== floor_div(uh + B, d2)) { break; }
        var t = A - q * C; A = C; C = t;
        t = B - q * D; B = D; D = t;
        t = uh - q * vh; uh = vh; vh = t;
    }
    return B === 0 ? null : [BigInt(A), BigInt(B), BigInt(C), BigInt(D)];
}
/* ⌊n/d⌋ for integers below 2^52, exact (a double's division can round across an integer) */
function floor_div(n, d) {
    var q = Math.floor(n / d);
    if (d > 0) { while (q * d > n) { q--; } while ((q + 1) * d <= n) { q++; } }
    else { while (q * d < n) { q--; } while ((q + 1) * d >= n) { q++; } }
    return q;
}
/* the pair (x, y) under the matrix m: (A·x + B·y, C·x + D·y) */
function apply(m, x, y) { return [m[0] * x + m[1] * y, m[2] * x + m[3] * y]; }

/**
 * g = gcd(a, b) and s, t with g = s·a + t·b, for a, b >= 0 (GMP's
 * mpz_gcdext up to the cofactor chosen). Only s is tracked; t is
 * (g − s·a)/b, one division at the end.
 */
function gcdext(a, b) {
    var r0 = a, r1 = b, s0 = 1n, s1 = 0n, p;
    while (r1 !== 0n) {
        var m = r0 >= LEHMER_MIN && r0 >= r1 ? lehmer(r0, r1) : null;
        if (m) {
            p = apply(m, r0, r1); r0 = p[0]; r1 = p[1];
            p = apply(m, s0, s1); s0 = p[0]; s1 = p[1];
            continue;
        }
        var q = r0 / r1, r2 = r0 - q * r1;
        r0 = r1; r1 = r2;
        var s2 = s0 - q * s1; s0 = s1; s1 = s2;
    }
    return { g: r0, s: s0, t: b === 0n ? 0n : (r0 - s0 * a) / b };
}

function gcd(a, b) { a = abs(a); b = abs(b); while (b) { var t = a % b; a = b; b = t; } return a; }

/*
 * chiavdf's mpz_xgcd_partial (src/xgcd_partial.c): Euclid on (r2, r1),
 * both >= 0, until r1 <= L, tracking co2 and co1 from (0, −1) - and stopping
 * at exactly that state matters, for the compressed encoding's t is this
 * co1. Lehmer's runs keep it exact for free: remainders only shrink, so a
 * run that ends above L crossed nothing; one that ends at or below L is
 * undone and the rest is taken a step at a time.
 */
function xgcd_partial(r2, r1, L) {
    var co2 = 0n, co1 = -1n, fast = true, p, c;
    while (r1 !== 0n && r1 > L) {
        var m = fast && r2 >= LEHMER_MIN && r2 >= r1 ? lehmer(r2, r1) : null;
        if (m) {
            p = apply(m, r2, r1);
            if (p[1] > L) {
                r2 = p[0]; r1 = p[1];
                c = apply(m, co2, co1); co2 = c[0]; co1 = c[1];
                continue;
            }
            fast = false;
        }
        var q = r2 / r1, r = r2 - q * r1;
        r2 = r1; r1 = r;
        var t = co2 - q * co1; co2 = co1; co1 = t;
    }
    if (r2 < 0n) { co2 = -co2; co1 = -co1; r2 = -r2; }
    return { co2: co2, co1: co1, r2: r2, r1: r1 };
}

/* ------------------------------------------------------------ the discriminant */

/**
 * chiavdf's HashPrime (src/proof_common.h): SHA-256 of the seed, the seed
 * read as a big-endian counter incremented before every hash, enough hashes
 * for `bits`; the bits in `mask` and bit 0 set; again until a probable prime.
 *
 * @param {Uint8Array} seed  not empty; its length is the counter's, so a
 *                           seed of a byte or two runs out (a RangeError)
 * @param {number} bits      a multiple of 8
 * @param {number[]} mask    bit positions to set
 * @param {function} [accept] a further condition on the candidate, tested
 *                           before primality: the first that meets both
 */
export function hash_prime(seed, bits, mask, accept) {
    if (!(seed instanceof Uint8Array) || seed.length === 0) { throw new TypeError('class_group: the seed is non-empty bytes'); }
    if (!Number.isInteger(bits) || bits <= 0 || bits % 8 !== 0) { throw new RangeError('class_group: bits is a positive multiple of 8'); }
    var sprout = Uint8Array.from(seed), blob = new Uint8Array(bits / 8);
    /* a short seed is a short counter: past 256^length hashes it repeats, and
       no prime in the cycle would mean no end (chiavdf's loop has none) */
    var hashes = 0, cycle = seed.length < 6 ? Math.pow(256, seed.length) : Infinity;
    for (;;) {
        for (var off = 0; off < blob.length;) {
            if (++hashes > cycle) { throw new RangeError('class_group: no prime before the seed\'s counter repeats - a longer seed'); }
            for (var i = sprout.length - 1; i >= 0; i--) { sprout[i] = (sprout[i] + 1) & 0xff; if (sprout[i] !== 0) { break; } }
            var h = sha256(sprout), take = Math.min(32, blob.length - off);
            blob.set(h.subarray(0, take), off);
            off += take;
        }
        var p = bytes_to_bigint(blob) | 1n;
        for (var j = 0; j < mask.length; j++) { p |= 1n << BigInt(mask[j]); }
        /* Baillie-PSW, no random rounds: the answer must be the same everywhere */
        if ((!accept || accept(p)) && is_probable_prime(p)) { return p; }
    }
}

/**
 * A discriminant from a public seed: −HashPrime(seed, bits, {0, 1, 2, bits−1}),
 * chiavdf's CreateDiscriminant for any bits (a multiple of 8, at least 16).
 * The size is the caller's choice (see vdf_class.js on choosing it).
 */
export function discriminant(seed, bits) {
    if (!Number.isInteger(bits) || bits < 16) { throw new RangeError('class_group: a discriminant of at least 16 bits'); }
    return -hash_prime(seed, bits, [0, 1, 2, bits - 1]);
}

/* ------------------------------------------------------------ the group */

var GROUPS = new Map();

/**
 * The class group of discriminant D: its operations and encodings.
 *
 * @param {bigint} D   negative, D ≡ 1 (mod 4), −D prime (checked once - a
 *                     composite −D gives elements of order 2 and an order
 *                     that its factors help compute)
 */
export function group(D) {
    if (typeof D !== 'bigint' || D >= 0n || ((-D) & 3n) !== 3n) {
        throw new TypeError('class_group: D is a negative bigint, D ≡ 1 (mod 4)');
    }
    var key = D.toString(16), cached = GROUPS.get(key);
    if (cached) { return cached; }
    if (!is_probable_prime(-D)) { throw new RangeError('class_group: −D must be prime'); }
    var G = make(D);
    GROUPS.set(key, G);
    return G;
}

function make(D) {
    var L = isqrt(isqrt(-D));                 /* ⌊|D|^(1/4)⌋, NUCOMP's stopping bound - chiavdf's root(−D, 4) */
    var BITS = bitlen(D);
    var D_BITS = (BITS + 31) & ~31;           /* the compressed encoding's width, bits rounded up to 32 */
    var C_SIZE = ((Math.max(BITS, 1024) + 31) >> 5) * 3 + 4;   /* 100 up to 1024 bits, as chiavdf pads to */
    var U_HALF = Math.ceil(BITS / 16);        /* a < √(|D|/3) and |b| <= a fit in ⌈bits/2⌉ bits */

    function form(a, b) {
        var n = b * b - D, d = 4n * a;
        if (a <= 0n || n % d !== 0n) { return null; }
        return { a: a, b: b, c: n / d };
    }
    function is_reduced(f) {
        return f.b > -f.a && f.b <= f.a && f.a <= f.c && (f.a !== f.c || f.b >= 0n) && f.b * f.b - 4n * f.a * f.c === D;
    }
    /* Gauss: normalise b into (−a, a], swap (a, b, c) → (c, −b, a) while a > c */
    function reduce(f) {
        var a = f.a, b = f.b, c = f.c;
        for (;;) {
            if (!(b > -a && b <= a)) {
                var r = fdiv_q(a - b, 2n * a);
                c = a * r * r + b * r + c;
                b = b + 2n * r * a;
            }
            if (a > c || (a === c && b < 0n)) { var t = a; a = c; c = t; b = -b; continue; }
            return { a: a, b: b, c: c };
        }
    }

    /* NUDUPL (chiavdf nucomp.h qfb_nudupl, phases in nucomp_phases.h) */
    function nudupl(f) {
        var a1 = f.a, c1 = f.c, b = f.b;
        var e = gcdext(abs(b), a1), s = e.g, v2 = b < 0n ? -e.s : e.s;
        var k = -(v2 * c1);
        if (s !== 1n) { a1 = fdiv_q(a1, s); c1 = c1 * s; }
        k = fdiv_r(k, a1);
        var ra, cb, rc;
        if (a1 < L) {
            var t = a1 * k;
            ra = a1 * a1;
            cb = 2n * t + b;
            rc = fdiv_q((b + t) * k + c1, a1);
        } else {
            var x = xgcd_partial(a1, k, L), r1 = x.r1, co1 = x.co1, co2 = x.co2;
            var m2 = (b * r1 - c1 * co1) / a1;
            ra = r1 * r1 - co1 * m2;
            if (co1 >= 0n) { ra = -ra; }
            cb = fdiv_r(2n * (a1 * r1 - ra * co2) / co1 - b, 2n * ra);
            rc = (cb * cb - D) / ra / 4n;
            if (ra < 0n) { ra = -ra; rc = -rc; }
        }
        return reduce({ a: ra, b: cb, c: rc });
    }

    /* NUCOMP (chiavdf nucomp.h qfb_nucomp): left is the operand with the smaller a */
    function nucomp(f, g) {
        var left = f, right = g;
        if (f.a > g.a) { left = g; right = f; }
        var a1 = left.a, a2 = right.a, c2 = right.c;
        var ss = (left.b + right.b) >> 1n, m = (left.b - right.b) >> 1n;
        var t = fdiv_r(a2, a1), sp, v1;
        if (t === 0n) { v1 = 0n; sp = a1; } else { var e = gcdext(t, a1); sp = e.g; v1 = e.s; }
        var k = fdiv_r(m * v1, a1);
        if (sp !== 1n) {
            var e2 = gcdext(ss < 0n ? -ss : ss, sp), s = e2.g, v2 = ss < 0n ? -e2.s : e2.s, u2 = e2.t;
            k = k * u2 - v2 * c2;
            if (s !== 1n) { a1 = a1 / s; a2 = a2 / s; c2 = c2 * s; }
            k = fdiv_r(k, a1);
        }
        var ca, cb, cc;
        if (a1 < L) {
            t = a2 * k;
            ca = a2 * a1;
            cb = 2n * t + right.b;
            cc = ((right.b + t) * k + c2) / a1;
        } else {
            var x = xgcd_partial(a1, k, L), r1 = x.r1, co1 = x.co1, co2 = x.co2;
            t = a2 * r1;
            var m1 = (m * co1 + t) / a1;
            var m2 = (ss * r1 - c2 * co1) / a1;
            ca = co1 < 0n ? r1 * m1 - co1 * m2 : co1 * m2 - r1 * m1;
            cb = fdiv_r(2n * (t - ca * co2) / co1 - right.b, 2n * ca);
            cc = fdiv_q((cb * cb - D) / ca, 4n);
            if (ca < 0n) { ca = -ca; cc = -cc; }
        }
        return reduce({ a: ca, b: cb, c: cc });
    }

    var ONE = { a: 1n, b: 1n, c: (1n - D) / 4n };

    function pow(f, e) {
        if (e < 0n) { return pow(inverse(f), -e); }
        var r = ONE;
        for (var i = bitlen(e) - 1; i >= 0; i--) {
            r = nudupl(r);
            if ((e >> BigInt(i)) & 1n) { r = nucomp(r, f); }
        }
        return r;
    }
    function inverse(f) { return reduce({ a: f.a, b: -f.b, c: f.c }); }
    function equals(f, g) { return f.a === g.a && f.b === g.b; }

    /* ---------------------------------------------- compressed (chiavdf bqfc.c) */

    function le_export(out, off, size, n) {
        var v = abs(n);
        if (bitlen(v) > size * 8) { throw new Error('class_group: a value does not fit the compressed encoding'); }
        for (var i = 0; i < size; i++) { out[off + i] = Number(v & 0xffn); v >>= 8n; }
    }
    function le_import(bytes, off, size) {
        var v = 0n;
        for (var i = size - 1; i >= 0; i--) { v = (v << 8n) | BigInt(bytes[off + i]); }
        return v;
    }
    function encode_compressed(f) {
        var out = new Uint8Array(C_SIZE), a = f.a, b = f.b;
        if (b === 1n && a <= 2n) { out[0] = a === 2n ? 8 : 4; return out; }
        var t, g, a2, b0, sign = false;
        if (a === b) {
            a2 = a; t = 0n; g = 0n; b0 = 0n;
        } else {
            sign = b < 0n;
            t = -xgcd_partial(a, abs(b), isqrt(a)).co1;
            g = gcd(a, t);
            if (g === 1n) { a2 = a; b0 = 0n; }
            else { a2 = a / g; t = t / g; b0 = b / a2; if (sign) { b0 = -b0; } }
        }
        var g_size = Math.ceil(Math.max(bitlen(g), 1) / 8) - 1;
        out[0] = (sign ? 1 : 0) | (t < 0n ? 2 : 0);
        out[1] = g_size;
        var off = 2;
        le_export(out, off, D_BITS / 16 - g_size, a2); off += D_BITS / 16 - g_size;
        le_export(out, off, D_BITS / 32 - g_size, t);  off += D_BITS / 32 - g_size;
        le_export(out, off, g_size + 1, g);            off += g_size + 1;
        le_export(out, off, g_size + 1, b0);
        return out;
    }
    /* (a, b) from the compressed fields, or null (chiavdf bqfc_deserialize_only + bqfc_decompr) */
    function decompress(bytes) {
        if (bytes[0] & 12) { return { a: bytes[0] & 8 ? 2n : 1n, b: 1n }; }
        var g_size = bytes[1];
        if (g_size >= D_BITS / 32) { return null; }
        var off = 2, n;
        n = D_BITS / 16 - g_size; var a2 = le_import(bytes, off, n); off += n;
        n = D_BITS / 32 - g_size; var t = le_import(bytes, off, n); off += n;
        var g = le_import(bytes, off, g_size + 1); off += g_size + 1;
        var b0 = le_import(bytes, off, g_size + 1);
        var sign = (bytes[0] & 1) !== 0;
        if (bytes[0] & 2) { t = -t; }
        if (t === 0n) { return { a: a2, b: a2 }; }
        if (a2 === 0n) { return null; }
        var tt = t < 0n ? t + a2 : t;
        var e = gcdext(tt, a2);
        if (e.g !== 1n) { return null; }
        var t_inv = e.s < 0n ? e.s + a2 : e.s;
        var dd = fdiv_r(D, a2);
        var sq = ((t * t) % a2) * dd % a2;
        var root = isqrt(sq);
        if (root * root !== sq) { return null; }
        var b = (root * t_inv) % a2;
        var a = g > 1n ? a2 * g : a2;
        if (b0 > 0n) { b += a2 * b0; }
        if (sign) { b = -b; }
        return { a: a, b: b };
    }

    /* ---------------------------------------------- uncompressed */

    function encode_uncompressed(f) {
        var out = new Uint8Array(1 + 2 * U_HALF);
        out[0] = f.b < 0n ? 1 : 0;
        out.set(bigint_to_bytes(f.a, U_HALF), 1);
        out.set(bigint_to_bytes(abs(f.b), U_HALF), 1 + U_HALF);
        return out;
    }
    function unpack_uncompressed(bytes) {
        if (bytes[0] > 1) { return null; }
        var a = bytes_to_bigint(bytes.subarray(1, 1 + U_HALF)), b = bytes_to_bigint(bytes.subarray(1 + U_HALF));
        return { a: a, b: bytes[0] ? -b : b };
    }

    /**
     * Bytes → the element, or null: the one encoding of a reduced form of this
     * discriminant, or nothing (see the header: rebuilt, checked, re-encoded,
     * compared byte for byte).
     */
    function decode(bytes, compressed) {
        if (!(bytes instanceof Uint8Array)) { return null; }
        var comp = compressed !== false;
        if (bytes.length !== (comp ? C_SIZE : 1 + 2 * U_HALF)) { return null; }
        var ab = comp ? decompress(bytes) : unpack_uncompressed(bytes);
        if (!ab) { return null; }
        var f = form(ab.a, ab.b);
        if (!f || !is_reduced(f)) { return null; }
        var again = comp ? encode_compressed(f) : encode_uncompressed(f);
        for (var i = 0; i < again.length; i++) { if (again[i] !== bytes[i]) { return null; } }
        return f;
    }

    /**
     * Bytes → an element, deterministically: the reduced form of a prime form
     * (p, b) with p ≡ 3 (mod 4) prime of about half D's bits and D a square
     * mod p - b = D^((p+1)/4) mod p, made odd. The input is bound with D and a
     * tag, and the search is HashPrime's.
     */
    function hash_to_group(input) {
        var bytes = typeof input === 'string' ? utf8(input) : input;
        if (!(bytes instanceof Uint8Array)) { throw new TypeError('class_group: hash_to_group takes bytes or a string'); }
        var pbits = Math.max(16, ((BITS >> 1) - 8) & ~7);
        var seed = sha256(concat([utf8('cryptographic-primitives/class-group/hash-to-group/v1'), bigint_to_bytes(-D, (BITS + 7) >> 3), bytes]));
        /* one HashPrime stream, the first prime with D a square mod p */
        var p = hash_prime(seed, pbits, [0, 1, pbits - 1], function (c) { return jacobi(D, c) === 1; });
        var b = modpow(fdiv_r(D, p), (p + 1n) / 4n, p);
        if ((b & 1n) === 0n) { b = p - b; }              /* b odd, as D: then 4p | b² − D */
        return reduce(form(p, b));
    }

    return {
        D: D, L: L, bits: BITS,
        /** byte lengths of the two encodings */
        COMPRESSED_BYTES: C_SIZE, UNCOMPRESSED_BYTES: 1 + 2 * U_HALF,
        identity: function () { return ONE; },
        /** (2, 1, (1−D)/8), reduced - the element Chia starts from (D ≡ 1 mod 8) */
        generator: function () {
            if (((-D) & 7n) !== 7n) { throw new RangeError('class_group: (2, 1) is a form only for D ≡ 1 (mod 8)'); }
            return reduce(form(2n, 1n));
        },
        /** the reduced form with these a, b (c from D), or null when there is none */
        form: function (a, b) { var f = form(a, b); return f && reduce(f); },
        reduce: reduce, is_reduced: is_reduced,
        square: nudupl, mul: nucomp, pow: pow, inverse: inverse, equals: equals,
        hash_to_group: hash_to_group,
        encode: function (f, opts) { return opts && opts.compressed === false ? encode_uncompressed(f) : encode_compressed(f); },
        decode: function (bytes, opts) { return decode(bytes, !(opts && opts.compressed === false)); }
    };
}

function modpow(b, e, m) {
    var r = 1n; b %= m;
    while (e > 0n) { if (e & 1n) { r = r * b % m; } b = b * b % m; e >>= 1n; }
    return r;
}
