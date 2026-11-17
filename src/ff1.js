/**
 * FF1  -  format-preserving encryption, NIST SP 800-38G
 *
 * Encrypts a string into another string of the SAME LENGTH over the SAME
 * ALPHABET. A sixteen-digit card number encrypts to sixteen digits; a
 * nine-character identifier to nine characters.
 *
 * WHY THAT MATTERS. Ordinary encryption turns a card number into binary that
 * is longer, has no digits in it, and fits no existing column, index or
 * validation rule. Retrofitting AES-GCM into a system built around
 * sixteen-digit fields means changing every schema, every form, every report
 * and every integration. FF1 changes none of them - which is why PCI DSS
 * tokenisation, healthcare identifier protection and a great deal of
 * mainframe migration work runs on it.
 *
 * IT IS A COMPROMISE AND IT IS WORTH BEING CLEAR ABOUT WHY.
 *
 *   - THE DOMAIN IS TINY. Sixteen digits is about 2^53 possibilities. That is
 *     not a security parameter, it is the size of the message space, and no
 *     cipher can hide a value inside a space an attacker can enumerate. FF1's
 *     guarantee is that the permutation is pseudorandom, NOT that a
 *     ciphertext is unguessable.
 *   - IT IS DETERMINISTIC without a tweak. The same card number under the
 *     same key always encrypts the same way, so equal ciphertexts mean equal
 *     plaintexts. THE TWEAK EXISTS TO FIX THIS: pass something that varies
 *     per record - an account id, a row key - and identical values stop
 *     colliding. A tweak is not secret and does not need to be.
 *   - THERE IS NO AUTHENTICATION. The output is the same size as the input,
 *     so there is nowhere to put a tag. A modified ciphertext decrypts to a
 *     different valid-looking value with no error. Anything that needs
 *     integrity needs a MAC alongside.
 *
 * WHY FF1 AND NOTHING ELSE. The 2013 draft of SP 800-38G specified three
 * modes, and only one of them is still standing:
 *
 *   FF1  (FFX)    approved 2016, never broken
 *   FF2  (VAES3)  REMOVED BEFORE PUBLICATION. NIST's own analysis in 2015 -
 *                 Dworkin and Perlner, "Analysis of VAES3 (FF2)" - gave a
 *                 chosen-plaintext attack showing its strength is below 128
 *                 bits despite a 128-bit key. It was dropped from the final
 *                 document and never became a standard.
 *   FF3  (BPS)    approved 2016, BROKEN in 2017 by Durak and Vaudenay, who
 *                 recovered the whole permutation from about 2^32 queries.
 *                 Revised to FF3-1 in 2019 by narrowing the tweak from 64
 *                 bits to 56, and further attacks on small domains have
 *                 appeared since.
 *
 * Two of the three original candidates were broken, one of them by NIST
 * before it could ship. FF1 is implemented here and the others deliberately
 * are not: FF2 has no final specification and no official test vectors, and
 * FF3-1's margin is thinner than FF1's for no benefit this library needs.
 */

import { aes_block_fn } from './aes.js';
import { cbc_mac } from './commons/cmac.js';
import { bytes_to_bigint, bigint_to_bytes, wr_be32 } from './commons/bytes.js';

var BLOCK = 16;

/*
 * The key is expanded once per call rather than once per block - FF1 runs ten
 * rounds and each performs at least one block encryption - by aes_block_fn.
 * This file used to rebuild that from aes_expand_key with its own copy of the
 * round-count formula.
 *
 * THE PRF of SP 800-38G is CBC-MAC under AES with a zero IV: cbc_mac from
 * commons/cmac.js, which CMAC and CCM use too. A raw CBC-MAC is unsafe as a
 * general MAC over variable-length messages, and that is fine here: every
 * input is built internally to a fixed shape, a whole number of blocks, with
 * the length bound into the first block. It is not exposed.
 */

/** numerals -> integer, most significant first */
function num(numerals, radix) {
    var r = BigInt(radix), v = 0n;
    for (var i = 0; i < numerals.length; i++) { v = v * r + BigInt(numerals[i]); }
    return v;
}

/** integer -> exactly `len` numerals, most significant first */
function str_num(v, radix, len) {
    var r = BigInt(radix);
    var out = new Array(len);
    for (var i = len - 1; i >= 0; i--) { out[i] = Number(v % r); v /= r; }
    return out;
}

/**
 * @param {Uint8Array} key       AES key: 16, 24 or 32 bytes
 * @param {number[]}   numerals  each in [0, radix)
 * @param {number}     radix     2 to 65536
 * @param {Uint8Array} [tweak]   NOT secret; vary it per record
 * @param {boolean}    decrypting
 */
function ff1(key, numerals, radix, tweak, decrypting) {
    var n = numerals.length;
    var T = tweak || new Uint8Array(0);
    var t = T.length;

    if (radix < 2 || radix > 65536) { throw new Error('ff1: radix must be 2 to 65536'); }
    /*
     * The minimum length is not arbitrary: radix^n must be at least a million,
     * or the domain is small enough that the permutation is distinguishable
     * from random by exhaustive search.
     *
     * ⚠ THIS IS THE 2019 REVISION'S BOUND, NOT THE 2016 ONE.
     *
     * SP 800-38G as published in 2016 asked only for radix^n >= 100. The
     * draft revision raised it to a million after Bellare, Hoang and Tessaro
     * showed message-recovery attacks on small domains. Wycheproof's vectors
     * follow the original, so its base-10 cases of length 2 to 5 are marked
     * VALID and are refused here - 321 of them, deliberately.
     *
     * Refusing is the right side to be on: a four-digit domain has ten
     * thousand elements, and an attacker who can query the permutation
     * enumerates it. A caller who needs the looser bound is asking for a
     * cipher that can be inverted by brute force.
     */
    if (Math.pow(radix, n) < 1000000) {
        throw new Error('ff1: radix^length must be at least 1000000 - the domain is too small');
    }
    for (var q = 0; q < n; q++) {
        if (!(numerals[q] >= 0 && numerals[q] < radix)) {
            throw new Error('ff1: numeral out of range for this radix');
        }
    }

    var cipher = aes_block_fn(key);

    var u = n >> 1, v = n - u;
    var A = numerals.slice(0, u);
    var B = numerals.slice(u);

    var b = Math.ceil(Math.ceil(v * Math.log2(radix)) / 8);
    var d = 4 * Math.ceil(b / 4) + 4;

    /* the fixed first block: version, method, addition, radix, split, lengths */
    var P = new Uint8Array(16);
    P[0] = 1;                    /* version */
    P[1] = 2;                    /* method: two-part Feistel */
    P[2] = 1;                    /* addition: modular */
    P[3] = (radix >>> 16) & 0xff;
    P[4] = (radix >>> 8) & 0xff;
    P[5] = radix & 0xff;
    P[6] = 10;                   /* rounds */
    P[7] = u & 0xff;             /* the split point */
    wr_be32(P, 8, n);            /* message length */
    wr_be32(P, 12, t);           /* tweak length */

    var pad = ((-t - b - 1) % 16 + 16) % 16;
    var qlen = t + pad + 1 + b;
    var Q = new Uint8Array(qlen);
    Q.set(T, 0);

    var PQ = new Uint8Array(16 + qlen);
    PQ.set(P, 0);

    for (var round = 0; round < 10; round++) {
        var i = decrypting ? (9 - round) : round;

        /* the round number and the other half, as b big-endian bytes */
        Q[t + pad] = i & 0xff;
        var other = decrypting ? A : B;
        Q.set(bigint_to_bytes(num(other, radix), b), t + pad + 1);
        PQ.set(Q, 16);

        var R = cbc_mac(cipher, PQ);

        /* stretch R to d bytes by encrypting R xor counter */
        /*
         * ROUNDED UP TO A WHOLE NUMBER OF BLOCKS, and it used not to be.
         *
         * The loop below writes a full 16-byte block at a time until it has
         * produced d bytes. Sizing S at exactly d means the last write runs
         * past the end whenever d is not a multiple of 16 - which throws
         * "offset is out of bounds", not a padding error, so it reads as a
         * buffer bug rather than a length one.
         *
         * d is 16 for short messages, which is why every test passed: at
         * radix 10 the first length that breaks it is 57. Found by running
         * Wycheproof's LargeMessageSize vectors, which nothing here had.
         */
        var S = new Uint8Array(Math.ceil(Math.max(d, BLOCK) / BLOCK) * BLOCK);
        S.set(R, 0);
        var produced = BLOCK, ctr = 1;
        while (produced < d) {
            /* R xored with the counter in its last four bytes */
            var x = new Uint8Array(R);
            var cb = new Uint8Array(4);
            wr_be32(cb, 0, ctr);
            for (var k = 0; k < 4; k++) { x[12 + k] ^= cb[k]; }
            cipher(x, 0, S, produced);
            produced += BLOCK;
            ctr++;
        }

        var y = bytes_to_bigint(S.subarray(0, d));
        var m = ((i & 1) === 0) ? u : v;
        var mod = BigInt(radix) ** BigInt(m);

        var c;
        if (decrypting) {
            c = ((num(B, radix) - y) % mod + mod) % mod;
            B = A;
            A = str_num(c, radix, m);
        } else {
            c = (num(A, radix) + y) % mod;
            A = B;
            B = str_num(c, radix, m);
        }
    }

    return A.concat(B);
}

/**
 * @return {number[]} the same length and alphabet as the input
 */
export function ff1_encrypt(key, numerals, radix, tweak) {
    return ff1(key, numerals, radix, tweak, false);
}

export function ff1_decrypt(key, numerals, radix, tweak) {
    return ff1(key, numerals, radix, tweak, true);
}

/**
 * Convenience for decimal strings - card numbers, account identifiers.
 *
 * @param {string} digits  '0'..'9' only
 * @return {string}        the same number of digits
 */
export function ff1_encrypt_digits(key, digits, tweak) {
    return ff1_encrypt(key, to_digits(digits), 10, tweak).join('');
}

export function ff1_decrypt_digits(key, digits, tweak) {
    return ff1_decrypt(key, to_digits(digits), 10, tweak).join('');
}

function to_digits(s) {
    var out = new Array(s.length);
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i) - 48;
        if (c < 0 || c > 9) { throw new Error('ff1: not a decimal string'); }
        out[i] = c;
    }
    return out;
}

/**
 * Encrypt a card number while leaving the leading digits and the last four
 * in place - the shape PCI DSS actually asks for.
 *
 * The first six digits are the issuer identifier: changing them breaks
 * routing and card-type detection. The last four are what appears on
 * receipts. Everything between them is what identifies the cardholder, and
 * that is what gets encrypted.
 *
 * THE PRESERVED DIGITS ARE NOT PROTECTED. They are visible in the output
 * because that is the point. This function protects the middle only.
 *
 * @param {number} [keep_first=6]
 * @param {number} [keep_last=4]
 */
export function ff1_encrypt_pan(key, pan, tweak, keep_first, keep_last) {
    return pan_apply(key, pan, tweak, keep_first, keep_last, ff1_encrypt_digits);
}

export function ff1_decrypt_pan(key, pan, tweak, keep_first, keep_last) {
    return pan_apply(key, pan, tweak, keep_first, keep_last, ff1_decrypt_digits);
}

function pan_apply(key, pan, tweak, keep_first, keep_last, fn) {
    var kf = keep_first === undefined ? 6 : keep_first;
    var kl = keep_last === undefined ? 4 : keep_last;
    var middle = pan.length - kf - kl;
    if (middle < 6) {
        throw new Error('ff1: fewer than six digits left to encrypt - ' +
                        'the domain would be below the SP 800-38G minimum');
    }
    return pan.slice(0, kf) + fn(key, pan.slice(kf, kf + middle), tweak) + pan.slice(kf + middle);
}

/**
 * The Luhn check digit, for reconstructing a valid-looking card number.
 *
 * NOT cryptography and not a security control - it is a typo check from 1954
 * that every payment system still validates. An encrypted PAN will usually
 * fail it, so a system that validates before storing needs the check digit
 * recomputed. That is a formatting concern, and it is here because leaving it
 * out is the thing that makes format-preserving encryption not actually
 * preserve the format.
 */
export function luhn_check_digit(digits) {
    var sum = 0, alt = true;
    for (var i = digits.length - 1; i >= 0; i--) {
        var d = digits.charCodeAt(i) - 48;
        if (d < 0 || d > 9) { throw new Error('ff1: not a decimal string'); }
        if (alt) { d *= 2; if (d > 9) { d -= 9; } }
        sum += d;
        alt = !alt;
    }
    return (10 - (sum % 10)) % 10;
}

/** @return {boolean} whether the string already carries a valid check digit */
export function luhn_valid(digits) {
    if (digits.length < 2) { return false; }
    return luhn_check_digit(digits.slice(0, -1)) === (digits.charCodeAt(digits.length - 1) - 48);
}
