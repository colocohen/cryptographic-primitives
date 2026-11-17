/**
 * Deterministic random bit generators  -  NIST SP 800-90A
 *
 * A DRBG stretches a small amount of real entropy into an arbitrary stream of
 * bits that is computationally indistinguishable from random. Every operating
 * system has one; these exist for the cases where you need to control it.
 *
 * WHY YOU WOULD WANT ONE EXPLICITLY:
 *
 *   - REPRODUCIBILITY. Seed it and every subsequent byte is determined. That
 *     makes a randomised algorithm testable, and it is how deterministic
 *     signatures work: RFC 6979 is HMAC_DRBG seeded with the private key and
 *     the message, which is why an ECDSA nonce derived that way is unique per
 *     message and impossible to repeat by accident.
 *
 *   - ENVIRONMENTS WITHOUT ONE. An embedded target, a deterministic sandbox,
 *     or a WASM runtime with no host entropy call.
 *
 *   - COMPLIANCE. FIPS 140 requires an approved DRBG between the entropy
 *     source and the consumer; a raw read from the OS is not enough on its
 *     own.
 *
 * THE ENTROPY IS STILL YOURS TO SUPPLY. A DRBG does not create randomness, it
 * expands it. Seeding one from a predictable value gives predictable output,
 * which is the whole failure mode of every broken RNG in history - the Debian
 * OpenSSL bug in 2008 left 32,768 possible SSH keys because the seed lost its
 * entropy, not because the generator was weak.
 *
 * THREE MECHANISMS, and the differences are practical rather than a security
 * ranking - all three are approved.
 *
 *   HMAC_DRBG   simplest to implement, needs only a hash. Used by RFC 6979.
 *   Hash_DRBG   slightly faster, more fiddly - a derivation function and
 *               440-bit modular addition.
 *   CTR_DRBG    a block cipher instead of a hash. The default in most
 *               hardware, because an AES engine is often the only primitive
 *               available.
 *
 * ENTROPY LEFT OUT (undefined or null), at instantiation or at a reseed, is
 * drawn from the platform: as many bytes as the instance's security strength
 * (SP 800-90A section 8.6.7 and table 2 / table 3), 16, 24 or 32 for a hash
 * by its digest size and the key length for CTR_DRBG, or seedlen bytes of
 * full entropy for CTR_DRBG without the derivation function (10.2.1.3.1).
 * The nonce stays the caller's to give; left out, there is none, as before.
 *
 * PREDICTION RESISTANCE, which the standard also defines, means reseeding
 * from fresh entropy before every generate call. It is not implemented here:
 * it turns the DRBG into a thin wrapper over the entropy source, and a caller
 * who wants that should read the source directly.
 */

import { hmac } from './hmac.js';
import { counter_kdf } from './kdf.js';
import { concat, inc_be, be32, wr_be32, secure_random } from './commons/bytes.js';
import { aes_block_fn } from './aes.js';
import { cbc_mac } from './commons/cmac.js';
import { ctr_stream } from './commons/block_modes.js';

/*
 * The security strength of a hash-based DRBG, in bytes (SP 800-90A table 2):
 * SHA-1's 128 bits, SHA-224's and SHA-512/224's 192, 256 above.
 */
function hash_strength(hash) {
    var d = hash.DIGEST_SIZE;
    return d >= 32 ? 32 : d >= 28 ? 24 : 16;
}

/* ---------------- HMAC_DRBG, section 10.1.2 ---------------- */

/**
 * @param {function}   hash     e.g. sha256
 * @param {Uint8Array} [entropy]  the seed. Its ENTROPY is what determines
 *                                security, not its length. Omitted or null
 *                                draws fresh bytes from the platform, the
 *                                security strength's worth
 * @param {Uint8Array} [nonce]
 * @param {Uint8Array} [perso]  personalization - domain separation between
 *                              two generators seeded from the same source
 */
export function hmac_drbg(hash, entropy, nonce, perso) {
    var strength = hash_strength(hash);
    if (entropy == null) { entropy = secure_random(strength); }
    var outlen = hash.DIGEST_SIZE;
    var K = new Uint8Array(outlen);            /* zeros */
    var V = new Uint8Array(outlen).fill(0x01);
    var counter = 1;

    /**
     * The update function. Note it runs TWICE when there is provided data and
     * once when there is not - the second pass with a 0x01 separator is what
     * mixes the data in rather than merely re-keying.
     */
    function update(data) {
        K = hmac(hash, K, concat([V, new Uint8Array([0x00]), data || new Uint8Array(0)]));
        V = hmac(hash, K, V);
        if (!data || data.length === 0) { return; }
        K = hmac(hash, K, concat([V, new Uint8Array([0x01]), data]));
        V = hmac(hash, K, V);
    }

    update(concat([entropy, nonce || new Uint8Array(0), perso || new Uint8Array(0)]));

    return {
        /** Mix fresh entropy in, resetting the reseed counter; omitted or null draws it from the platform. */
        reseed: function (new_entropy, additional) {
            if (new_entropy == null) { new_entropy = secure_random(strength); }
            update(concat([new_entropy, additional || new Uint8Array(0)]));
            counter = 1;
        },

        /**
         * @param  {number}     n            bytes
         * @param  {Uint8Array} [additional] extra input mixed in before and
         *                                   after, per the standard
         * @return {Uint8Array}
         */
        generate: function (n, additional) {
            if (additional && additional.length) { update(additional); }
            /*
             * V = HMAC(K, V), output V, until n bytes - section 10.1.2.5's
             * loop, with the block assembly done by kdf.js's counter_kdf
             * like every other "append digests up to n" loop in the library.
             *
             * ⛔ V IS THE CHAIN, SO A COPY IS RETURNED. counter_kdf wipes each
             *   block after copying it out; handing it V itself would zero
             *   the state the next block and the final update depend on.
             */
            var out = counter_kdf(function () {
                V = hmac(hash, K, V);
                return Uint8Array.from(V);
            }, n, outlen);
            update(additional);
            counter++;
            return out;
        },

        reseed_counter: function () { return counter; }
    };
}

/* ---------------- Hash_DRBG, section 10.1.1 ---------------- */

/**
 * The derivation function of section 10.3.1: condense arbitrary input to
 * exactly `n` bytes by hashing a counter and a length prefix.
 */
function hash_df(hash, input, n) {
    var prefix = new Uint8Array(5);
    wr_be32(prefix, 1, n * 8);
    /*
     * ⭐ THROUGH counter_kdf: H(counter || no_of_bits || input), counter from
     *   1, which is that function's loop exactly - this used to be its own
     *   copy. The counter is one byte; seedlen is at most 111 here, so it
     *   never passes 4.
     */
    return counter_kdf(function (i) {
        prefix[0] = i & 0xff;
        return hash(concat([prefix, input]));
    }, n, hash.DIGEST_SIZE);
}

/** Add `add` into `v` in place, both big-endian, modulo 2^(8*v.length). */
function add_be(v, add) {
    var carry = 0;
    var i = v.length - 1, j = add.length - 1;
    for (; i >= 0; i--, j--) {
        var s = v[i] + (j >= 0 ? add[j] : 0) + carry;
        v[i] = s & 0xff;
        carry = s >> 8;
    }
}

function add_int(v, x) {
    var carry = x;
    for (var i = v.length - 1; i >= 0 && carry; i--) {
        var s = v[i] + (carry & 0xff);
        v[i] = s & 0xff;
        carry = (carry >>> 8) + (s >> 8);
    }
}

/**
 * @param {function} hash  e.g. sha256
 * @param {Uint8Array} [entropy]  omitted or null draws fresh bytes from the
 *                                platform, the security strength's worth;
 *                                so does a reseed's
 *
 * The seed length is 440 bits for digests up to 256 and 888 above, which is
 * from the standard's table rather than from anything derivable.
 */
export function hash_drbg(hash, entropy, nonce, perso) {
    var seedlen = hash.DIGEST_SIZE <= 32 ? 55 : 111;   /* 440 or 888 bits */
    var strength = hash_strength(hash);
    if (entropy == null) { entropy = secure_random(strength); }
    var V = hash_df(hash, concat([entropy, nonce || new Uint8Array(0), perso || new Uint8Array(0)]), seedlen);

    /* C = Hash_df(0x00 || V), the same derivation at instantiate and at
       every reseed - written once rather than at both sites */
    function derive_c() { return hash_df(hash, concat([new Uint8Array([0x00]), V]), seedlen); }

    var C = derive_c();
    var counter = 1;

    return {
        reseed: function (new_entropy, additional) {
            if (new_entropy == null) { new_entropy = secure_random(strength); }
            V = hash_df(hash, concat([new Uint8Array([0x01]), V, new_entropy,
                                      additional || new Uint8Array(0)]), seedlen);
            C = derive_c();
            counter = 1;
        },

        generate: function (n, additional) {
            if (additional && additional.length) {
                var w = hash(concat([new Uint8Array([0x02]), V, additional]));
                add_be(V, w);
            }

            /* Hashgen: hash a working copy of V, incrementing it each block -
               counter_kdf's loop again, with the counter living in `data` */
            var data = Uint8Array.from(V);
            var out = counter_kdf(function () {
                var h = hash(data);
                add_int(data, 1);
                return h;
            }, n, hash.DIGEST_SIZE);

            var H = hash(concat([new Uint8Array([0x03]), V]));
            add_be(V, H);
            add_be(V, C);
            var cb = new Uint8Array(4);
            wr_be32(cb, 0, counter);
            add_be(V, cb);

            counter++;
            return out;
        },

        reseed_counter: function () { return counter; }
    };
}

/* ---------------- CTR_DRBG, section 10.2.1 ---------------- */

var BLOCK = 16;

/* AES as (src, out): aes.js's aes_block_fn, which owns the round-count rule
   this file used to restate (10/12/14 from the key length) */
function aes_block(key) {
    var f = aes_block_fn(key);
    return function (src, out) { f(src, 0, out, 0); };
}
/**
 * The block-cipher derivation function, section 10.3.2.
 *
 * More involved than the hash one: it runs CBC-MAC under a fixed key over a
 * length-prefixed input, then uses the result as a key to generate the
 * output. Needed whenever the seed material is not already exactly seedlen.
 */
function block_cipher_df(input, keylen, n) {
    var seedlen = keylen + BLOCK;
    var S = concat([be32(input.length), be32(n), input, new Uint8Array([0x80])]);
    var pad = (BLOCK - (S.length % BLOCK)) % BLOCK;
    if (pad) { S = concat([S, new Uint8Array(pad)]); }

    /* the fixed key 0x000102... is from the standard, not a choice */
    var k = new Uint8Array(keylen);
    for (var i = 0; i < keylen; i++) { k[i] = i; }
    var block = aes_block_fn(k);   /* (src, off, out, off): cbc_mac's shape */

    var temp = new Uint8Array(0);
    var iv = new Uint8Array(BLOCK);
    var out_block = new Uint8Array(BLOCK);
    var counter = 0;

    while (temp.length < seedlen) {
        iv.fill(0);
        wr_be32(iv, 0, counter);

        /* BCC is CBC-MAC with a zero IV over iv || S, both whole blocks:
           commons/cmac.js cbc_mac, the one CMAC, CCM and FF1 use */
        temp = concat([temp, cbc_mac(block, concat([iv, S]))]);
        counter++;
    }

    var K = temp.subarray(0, keylen);
    var X = Uint8Array.from(temp.subarray(keylen, keylen + BLOCK));
    var enc = aes_block(K);

    var result = new Uint8Array(0);
    while (result.length < n) {
        enc(X, out_block);
        X.set(out_block);
        result = concat([result, Uint8Array.from(X)]);
    }
    return result.subarray(0, n);
}

/**
 * @param {number}     keylen   16, 24 or 32 - the AES key size
 * @param {Uint8Array} [entropy]  omitted or null draws fresh bytes from the
 *                              platform: keylen of them (the security
 *                              strength) with use_df, keylen+16 without;
 *                              so does a reseed's
 * @param {boolean}    use_df   whether to run the derivation function on the
 *                              seed. WITHOUT it the seed material must be
 *                              exactly keylen+16 bytes, which is what the
 *                              "no df" CAVP vectors exercise; with it any
 *                              length works. Real use should use it.
 */
export function ctr_drbg(keylen, entropy, nonce, perso, use_df) {
    var seedlen = keylen + BLOCK;
    var fresh = use_df ? keylen : seedlen;
    if (entropy == null) { entropy = secure_random(fresh); }
    var Key = new Uint8Array(keylen);
    var V = new Uint8Array(BLOCK);
    var counter = 1;

    /* the counter, shared with the block-cipher modes - the carry trap is
       documented at its definition */
    function inc_v() { inc_be(V); }

    /**
     * n bytes of keystream: increment V, encrypt it, repeat.
     *
     * ⭐ SHARED by update and generate, which each wrote this loop out. The
     *   increment comes BEFORE the encryption, the opposite of
     *   commons/block_modes.js ctr(), and V is left at the last value used -
     *   which is why that function is not a drop-in here.
     */
    function keystream(n) {
        /* commons/block_modes.js ctr_stream: it steps the counter BETWEEN
           blocks and leaves it on the last value used, so the pre-increment
           this generator needs is the one inc_be before the call; n = 0 must
           not move V at all */
        if (n === 0) { return new Uint8Array(0); }
        inc_v();
        return ctr_stream(aes_block_fn(Key), V, new Uint8Array(n), BLOCK, inc_be);
    }

    /**
     * The update: generate seedlen bytes of keystream, XOR the provided data
     * into it, and SPLIT THE RESULT into the new key and the new counter.
     * Both halves change on every call, which is what stops the state from
     * being recoverable from output.
     */
    function update(data) {
        var temp = keystream(seedlen);
        if (data) {
            for (var i = 0; i < seedlen; i++) { temp[i] ^= data[i]; }
        }
        Key = temp.subarray(0, keylen);
        V = Uint8Array.from(temp.subarray(keylen));
    }

    /**
     * Seed material from raw input: through the derivation function, or -
     * without one - padded or truncated to seedlen.
     *
     * ⭐ ONE COPY FOR ALL THREE CALLERS. Instantiate, reseed and the
     *   additional input to generate each carried their own "df or pad"
     *   branch; the three were the same code over differently assembled
     *   input.
     */
    function seed_material(raw) {
        if (use_df) { return block_cipher_df(raw, keylen, seedlen); }
        var m = new Uint8Array(seedlen);
        m.set(raw.subarray(0, Math.min(raw.length, seedlen)), 0);
        return m;
    }

    update(seed_material(concat([entropy, nonce || new Uint8Array(0), perso || new Uint8Array(0)])));

    return {
        reseed: function (new_entropy, additional) {
            if (new_entropy == null) { new_entropy = secure_random(fresh); }
            update(seed_material(concat([new_entropy, additional || new Uint8Array(0)])));
            counter = 1;
        },

        generate: function (n, additional) {
            var add = null;
            if (additional && additional.length) {
                add = seed_material(additional);
                update(add);
            }

            var out = keystream(n);

            update(add);
            counter++;
            return out;
        },

        reseed_counter: function () { return counter; }
    };
}
