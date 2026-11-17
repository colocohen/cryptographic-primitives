/**
 * The modes every block cipher here exposes, bound once
 *
 * ARIA, Camellia, SEED, SM4 and AES each carried the same seventeen wrappers -
 * ECB, CBC with PKCS#7, CTR, GCM, CCM, GMAC, CMAC, KW and KWP - and Blowfish,
 * DES, Triple DES and RC2 the 64-bit subset. aria.js and camellia.js were
 * identical below the key schedule apart from the name. The copies drifted the
 * way copies do:
 *
 *   - DES, 3DES and RC2 lost the "unpadded data must be aligned" check, so
 *     no_pad with 13 bytes returned 13 bytes nothing could decrypt (fixed
 *     first in block_modes.js, which now checks for itself);
 *   - SEED went without GCM, CCM, GMAC and CMAC, and SM4 without KW, for long
 *     enough that both have comments saying so.
 *
 * A cipher now supplies one thing: make(key, decrypting), returning its block
 * function in the shape block_modes.js uses. The argument checks, the order
 * they run in, the error texts and the null-on-failure rules are here.
 *
 * ⚠ THE 128-BIT MODES ARE OFFERED ONLY FOR A 16-BYTE BLOCK. GCM, CCM, CMAC as
 *   specified, key wrap and EAX are all defined over a 128-bit block, which is
 *   the reason block_modes.js keeps them out of the generic plumbing. Binding
 *   them here for any other size would make that mistake one call away.
 *
 * ⚠ THE KEY SCHEDULE IS BUILT AFTER THE CHEAP CHECKS, exactly as each wrapper
 *   did - an IV of the wrong length is reported as that, and costs no key
 *   expansion.
 *
 * EVERY BLOCK CIPHER IN THE LIBRARY IS BOUND HERE - AES, ARIA, Camellia,
 * SEED, SM4, Kuznyechik (the 128-bit ones, with every mode) and DES/3DES,
 * Blowfish, RC2, Magma (64-bit: ECB, CBC, CTR). GOST used to keep its own
 * wrappers with a different API (padded ECB, no no_pad, no IV check); RC2's
 * effective key length now travels with the key ({key, effective_bits}).
 */

import { pkcs7_pad, pkcs7_unpad, ecb, ecb_into, cbc_encrypt, cbc_decrypt, ctr, ctr_create as ctr_incremental } from './block_modes.js';
import { gcm_encrypt, gcm_decrypt, gcm_create, gmac, gmac_verify } from './gcm.js';
import { ccm_encrypt, ccm_decrypt } from './ccm.js';
import { cmac, cmac_verify, cmac_create } from './cmac.js';
import { kw_wrap, kw_unwrap, kwp_wrap, kwp_unwrap } from './kw.js';
import { eax_encrypt, eax_decrypt } from './eax.js';

function check_iv(label, iv, block) {
    if (iv.length !== block) {
        throw new Error(label + ': iv must be ' + block + ' bytes');
    }
}

/*
 * The three wrappers with logic in them. `get` builds the block function on
 * demand, after the argument checks. (They were exported for rc2.js until its
 * effective key length moved into the key; every cipher now goes through
 * bind_modes.)
 */

/** CBC with PKCS#7 unless no_pad; unpadded input must already be aligned. */
/* no_pad is a flag: a number there is a call written for an older
   signature (RC2's effective_bits used to sit in that position) */
function check_flag(label, no_pad) {
    if (no_pad !== undefined && typeof no_pad !== 'boolean') {
        throw new TypeError(label + ': no_pad must be true, false or omitted');
    }
}
function cbc_encrypt_padded(name, block, get, iv, data, no_pad) {
    check_iv(name + '_cbc', iv, block);
    check_flag(name + '_cbc', no_pad);
    var input = no_pad ? data : pkcs7_pad(data, block);
    if (input.length % block !== 0) {
        throw new Error(name + '_cbc: unpadded data must be a multiple of ' + block + ' bytes');
    }
    return cbc_encrypt(get(), iv, input, block);
}

/**
 * @return {Uint8Array|null} null on unaligned input or bad padding - one
 *                           indistinguishable failure, see block_modes.js
 */
function cbc_decrypt_padded(name, block, get, iv, data, no_pad) {
    check_iv(name + '_cbc', iv, block);
    check_flag(name + '_cbc', no_pad);
    if (data.length === 0 || data.length % block !== 0) { return null; }
    var out = cbc_decrypt(get(), iv, data, block);
    return no_pad ? out : pkcs7_unpad(out, block);
}

/** The whole block is the counter - see block_modes.js. */
function ctr_checked(name, block, get, iv, data) {
    check_iv(name + '_ctr', iv, block);
    return ctr(get(), iv, data, block);
}

/* name the generated functions after the exports they become, so a stack
   trace says aria_gcm_decrypt rather than gcm_decrypt */
function named(prefix, obj) {
    for (var k in obj) {
        Object.defineProperty(obj[k], 'name', { value: prefix + '_' + k });
    }
    return obj;
}

/**
 * @param {string}   name   the export prefix: 'aria', 'des3' ...; also the
 *                          prefix of every error message
 * @param {number}   block  8 or 16
 * @param {function} make   make(key, decrypting) -> block(src, off, out, out_off)
 * @return {object} ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt, ctr,
 *                  and for a 16-byte block also gcm_*, ccm_*, gmac,
 *                  gmac_verify, cmac, cmac_verify, kw_*, kwp_*, eax_*
 */
export function bind_modes(name, block, make) {
    function enc(key) { return make(key, false); }
    function dec(key) { return make(key, true); }

    var m = {
        ecb_encrypt: function (key, data) { return ecb(enc(key), data, block, name + '_ecb'); },
        ecb_decrypt: function (key, data) { return ecb(dec(key), data, block, name + '_ecb'); },
        cbc_encrypt: function (key, iv, data, no_pad) {
            return cbc_encrypt_padded(name, block, function () { return enc(key); }, iv, data, no_pad);
        },
        cbc_decrypt: function (key, iv, data, no_pad) {
            return cbc_decrypt_padded(name, block, function () { return dec(key); }, iv, data, no_pad);
        },
        ctr: function (key, iv, data) {
            return ctr_checked(name, block, function () { return enc(key); }, iv, data);
        },
        /*
         * ECB under a key set once: the key schedule is computed here, and
         * each call then costs only its blocks. For a protocol that encrypts
         * one block per packet - QUIC header protection (RFC 9001 §5.4.3) -
         * the schedule is most of the one-shot form's cost.
         */
        ecb_create: function (key) {
            var e = enc(key), d = dec(key);
            return {
                encrypt: function (data) { return ecb(e, data, block, name + '_ecb'); },
                decrypt: function (data) { return ecb(d, data, block, name + '_ecb'); },
                /* straight into out - nothing made per call (block_modes.js, ecb_into) */
                encrypt_into: function (out, offset, data) { return ecb_into(e, data, block, name + '_ecb.encrypt', out, offset); },
                decrypt_into: function (out, offset, data) { return ecb_into(d, data, block, name + '_ecb.decrypt', out, offset); }
            };
        },
        /* CTR fed in pieces: update(data) -> data xor keystream, both directions */
        ctr_create: function (key, iv) {
            check_iv(name + '_ctr', iv, block);
            return ctr_incremental(enc(key), iv, block);
        }
    };
    if (block !== 16) { return named(name, m); }

    /* every 128-bit mode below uses only the forward cipher, except unwrap */
    m.gcm_encrypt = function (key, iv, plaintext, aad) { return gcm_encrypt(enc(key), iv, plaintext, aad); };
    m.gcm_decrypt = function (key, iv, sealed, aad) { return gcm_decrypt(enc(key), iv, sealed, aad); };
    /*
     * ⭐ KEYED CONTEXTS: the key schedule (and for GCM the hash key and its
     *   table) is computed once, and each message then takes only its nonce.
     *   For a protocol that seals many records under one key - TLS, QUIC -
     *   this is the per-message setup the one-shot forms repeat.
     */
    m.gcm_create = function (key) { return gcm_create(enc(key)); };
    m.ccm_create = function (key) {
        var e = enc(key);
        return {
            encrypt: function (nonce, plaintext, aad, tag_len) { return ccm_encrypt(e, nonce, plaintext, aad, tag_len); },
            decrypt: function (nonce, sealed, aad, tag_len) { return ccm_decrypt(e, nonce, sealed, aad, tag_len); }
        };
    };
    m.eax_create = function (key) {
        var e = enc(key);
        return {
            encrypt: function (nonce, plaintext, aad, tag_len) { return eax_encrypt(e, nonce, plaintext, aad, tag_len); },
            decrypt: function (nonce, sealed, aad, tag_len) { return eax_decrypt(e, nonce, sealed, aad, tag_len); }
        };
    };
    m.ccm_encrypt = function (key, nonce, plaintext, aad, tag_len) {
        return ccm_encrypt(enc(key), nonce, plaintext, aad, tag_len);
    };
    m.ccm_decrypt = function (key, nonce, sealed, aad, tag_len) {
        return ccm_decrypt(enc(key), nonce, sealed, aad, tag_len);
    };
    m.gmac = function (key, iv, data) { return gmac(enc(key), iv, data); };
    m.gmac_verify = function (key, iv, data, tag) { return gmac_verify(enc(key), iv, data, tag); };
    m.cmac = function (key, msg) { return cmac(enc(key), msg); };
    m.cmac_verify = function (key, msg, tag) { return cmac_verify(enc(key), msg, tag); };
    /* CMAC under a key set once: update(msg), copy(), digest() - see commons/cmac.js */
    m.cmac_create = function (key) { return cmac_create(enc(key)); };
    m.kw_wrap = function (kek, data) { return kw_wrap(enc(kek), data); };
    m.kw_unwrap = function (kek, wrapped) { return kw_unwrap(enc(kek), dec(kek), wrapped); };
    m.kwp_wrap = function (kek, data) { return kwp_wrap(enc(kek), data); };
    m.kwp_unwrap = function (kek, wrapped) { return kwp_unwrap(enc(kek), dec(kek), wrapped); };
    m.eax_encrypt = function (key, nonce, plaintext, aad, tag_len) {
        return eax_encrypt(enc(key), nonce, plaintext, aad, tag_len);
    };
    m.eax_decrypt = function (key, nonce, sealed, aad, tag_len) {
        return eax_decrypt(enc(key), nonce, sealed, aad, tag_len);
    };
    return named(name, m);
}
