/**
 * CryptoJS format  -  READING ONLY
 *
 * Opens data produced by CryptoJS.AES.encrypt(message, password), so that
 * existing records can be migrated:
 *
 *     import { open_cryptojs } from 'cryptographic-primitives/compat/cryptojs.js';
 *     import { seal_with_password } from 'cryptographic-primitives/easy.js';
 *
 *     const data  = open_cryptojs(password, old_base64);
 *     const fresh = seal_with_password(password, data);
 *
 * ============ THERE IS DELIBERATELY NO ENCRYPT FUNCTION ============
 *
 * Every other file in compat/ is a drop-in replacement. This one is not, and
 * the reason is that CryptoJS's encryption is not something to reproduce:
 *
 *     KDF          EvpKDF - MD5, ONE iteration
 *     Cipher       AES-256-CBC with NO authentication
 *     Salt         8 bytes
 *
 * One MD5 iteration is not key derivation. A password from any wordlist falls
 * to a GPU in seconds, and an 8-byte salt is short by modern standards. And
 * CBC without a MAC means an attacker who can modify the stored bytes can
 * flip plaintext bits in a controlled way - the ciphertext carries no
 * evidence that it was tampered with, so decryption succeeds and returns
 * something the attacker chose.
 *
 * Providing a seal_cryptojs() would mean shipping that as a supported option,
 * and a caller who reached for it while writing new code would get it. Making
 * it impossible to write the format is the point.
 *
 * ================= WHAT SUCCESSFUL DECRYPTION MEANS =================
 *
 * NOT MUCH. Because there is no authentication, this returns whatever the
 * bytes decrypt to, and the only check is that PKCS#7 padding is well formed
 * - which a wrong password passes about one time in 256. A caller migrating
 * records should verify the plaintext looks like what it expects, and should
 * not treat a non-null return as proof the password was right.
 *
 * ==================== THE OTHER CRYPTOJS MODES ====================
 *
 * CryptoJS also accepts a WordArray key instead of a password string, in
 * which case no salt or KDF is involved and the caller supplies the IV. That
 * form has no fixed container - it is just raw CBC - so there is nothing to
 * detect and nothing to write here. Use aes_cbc_decrypt from aes.js directly.
 *
 * Node's own createDecipher (removed in Node 22) used the SAME EvpKDF
 * construction with the same MD5 and single iteration, so evp_kdf below opens
 * that data too.
 */

import { md5 } from '../md5.js';
import { aes_cbc_decrypt } from '../aes.js';
import { concat, from_base64 } from '../commons/bytes.js';
import { text_or_bytes } from './_common.js';

var MAGIC = 'Salted__';

/**
 * OpenSSL's EVP_BytesToKey, which is what CryptoJS calls EvpKDF.
 *
 * Each block is MD5(previous_block || password || salt), and blocks are
 * concatenated until key and IV are both filled. ONE HASH PER BLOCK - there
 * is no iteration count and no way to raise the cost.
 *
 * It is reproduced here exactly because opening old data requires it, not
 * because it is defensible. Anything new should use argon2.
 */
export function evp_kdf(password, salt, key_len, iv_len) {
    var out = new Uint8Array(0);
    var prev = new Uint8Array(0);
    while (out.length < key_len + iv_len) {
        prev = md5(concat([prev, password, salt]));
        out = concat([out, prev]);
    }
    return { key: out.subarray(0, key_len), iv: out.subarray(key_len, key_len + iv_len) };
}



/**
 * Decrypt a CryptoJS.AES.encrypt(...).toString() value.
 *
 * @param  {string|Uint8Array} password  the same password CryptoJS was given
 * @param  {string|Uint8Array} data      the base64 string, or its raw bytes
 * @param  {number}            [key_bits=256]  CryptoJS's default is 256
 * @return {Uint8Array|null}   null when the container is malformed or the
 *                             padding does not check out - which is NOT proof
 *                             the password was wrong; see the note at the top
 */
export function open_cryptojs(password, data, key_bits) {
    try {
        /* the container checks are parse_cryptojs's - this used to repeat
           them, and only parse learned to refuse non-base64 text */
        var c = parse_cryptojs(data);
        if (c === null) { return null; }
        var body = c.ciphertext;
        if (body.length === 0 || (body.length % 16) !== 0) { return null; }

        var bits = key_bits || 256;
        var d = evp_kdf(text_or_bytes(password), c.salt, bits >> 3, 16);
        return aes_cbc_decrypt(d.key, d.iv, body);
    } catch (err) {
        return null;
    }
}

/**
 * The raw container fields, for a caller who wants to inspect before
 * decrypting - checking a salt against a known record, for instance.
 *
 * @return {{salt: Uint8Array, ciphertext: Uint8Array}|null}
 */
export function parse_cryptojs(data) {
    var raw = typeof data === 'string' ? from_base64(data) : data;
    /* from_base64 returns null for text that is not base64: "!!!" threw a
       TypeError here, from a function documented to answer yes or no */
    if (!(raw instanceof Uint8Array) || raw.length < 24) { return null; }
    for (var i = 0; i < 8; i++) {
        if (raw[i] !== MAGIC.charCodeAt(i)) { return null; }
    }
    return { salt: raw.subarray(8, 16), ciphertext: raw.subarray(16) };
}

/**
 * Whether these bytes look like a CryptoJS container.
 *
 * Only checks the magic prefix, so it distinguishes the format from other
 * data - it says nothing about whether the contents will decrypt.
 */
export function is_cryptojs(data) {
    return parse_cryptojs(data) !== null;
}
