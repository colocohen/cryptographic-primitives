/**
 * Camellia (RFC 3713), in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../camellia.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * It runs the pure JavaScript in ../camellia.js.
 */

import * as pure from '../camellia.js';
import { define } from '../engines/select.js';

var camellia_ecb_encrypt_ops = define('camellia_ecb_encrypt', { sync: pure.camellia_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var camellia_ecb_decrypt_ops = define('camellia_ecb_decrypt', { sync: pure.camellia_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var camellia_cbc_encrypt_ops = define('camellia_cbc_encrypt', { sync: pure.camellia_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var camellia_cbc_decrypt_ops = define('camellia_cbc_decrypt', { sync: pure.camellia_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var camellia_ctr_ops = define('camellia_ctr', { sync: pure.camellia_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var camellia_gcm_encrypt_ops = define('camellia_gcm_encrypt', { sync: pure.camellia_gcm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'iv' } });
var camellia_gcm_decrypt_ops = define('camellia_gcm_decrypt', { sync: pure.camellia_gcm_decrypt, text: [3], bytes: { 0: 'key', 1: 'iv', 2: 'sealed' } });
var camellia_gcm_create_ops = define('camellia_gcm', { create: pure.camellia_gcm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var camellia_ccm_create_ops = define('camellia_ccm', { create: pure.camellia_ccm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var camellia_eax_create_ops = define('camellia_eax', { create: pure.camellia_eax_create, kind: 'aead', create_bytes: { 0: 'key' } });
var camellia_ecb_create_ops = define('camellia_ecb', { create: pure.camellia_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var camellia_ctr_create_ops = define('camellia_ctr', { create: pure.camellia_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });
var camellia_gmac_ops = define('camellia_gmac', { sync: pure.camellia_gmac, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var camellia_gmac_verify_ops = define('camellia_gmac_verify', { sync: pure.camellia_gmac_verify, text: [2], bytes: { 0: 'key', 1: 'iv', 3: 'tag' } });
var camellia_ccm_encrypt_ops = define('camellia_ccm_encrypt', { sync: pure.camellia_ccm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var camellia_ccm_decrypt_ops = define('camellia_ccm_decrypt', { sync: pure.camellia_ccm_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var camellia_cmac_ops = define('camellia_cmac', { sync: pure.camellia_cmac, create: pure.camellia_cmac_create, text: [1], bytes: { 0: 'key' }, create_bytes: { 0: 'key' } });
var camellia_cmac_verify_ops = define('camellia_cmac_verify', { sync: pure.camellia_cmac_verify, text: [1], bytes: { 0: 'key', 2: 'tag' } });
var camellia_kw_wrap_ops = define('camellia_kw_wrap', { sync: pure.camellia_kw_wrap, text: [1], bytes: { 0: 'kek' } });
var camellia_kw_unwrap_ops = define('camellia_kw_unwrap', { sync: pure.camellia_kw_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var camellia_kwp_wrap_ops = define('camellia_kwp_wrap', { sync: pure.camellia_kwp_wrap, text: [1], bytes: { 0: 'kek' } });
var camellia_kwp_unwrap_ops = define('camellia_kwp_unwrap', { sync: pure.camellia_kwp_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var camellia_eax_encrypt_ops = define('camellia_eax_encrypt', { sync: pure.camellia_eax_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var camellia_eax_decrypt_ops = define('camellia_eax_decrypt', { sync: pure.camellia_eax_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });

export var camellia_ecb_encrypt = camellia_ecb_encrypt_ops.async;
export var camellia_ecb_encrypt_sync = camellia_ecb_encrypt_ops.sync;
export var camellia_ecb_decrypt = camellia_ecb_decrypt_ops.async;
export var camellia_ecb_decrypt_sync = camellia_ecb_decrypt_ops.sync;
export var camellia_cbc_encrypt = camellia_cbc_encrypt_ops.async;
export var camellia_cbc_encrypt_sync = camellia_cbc_encrypt_ops.sync;
export var camellia_cbc_decrypt = camellia_cbc_decrypt_ops.async;
export var camellia_cbc_decrypt_sync = camellia_cbc_decrypt_ops.sync;
export var camellia_ctr = camellia_ctr_ops.async;
export var camellia_ctr_sync = camellia_ctr_ops.sync;
export var camellia_gcm_encrypt = camellia_gcm_encrypt_ops.async;
export var camellia_gcm_encrypt_sync = camellia_gcm_encrypt_ops.sync;
export var camellia_gcm_decrypt = camellia_gcm_decrypt_ops.async;
export var camellia_gcm_decrypt_sync = camellia_gcm_decrypt_ops.sync;
export var camellia_gcm_create = camellia_gcm_create_ops.create;
export var camellia_ccm_create = camellia_ccm_create_ops.create;
export var camellia_eax_create = camellia_eax_create_ops.create;
export var camellia_ecb_create = camellia_ecb_create_ops.create;
export var camellia_ctr_create = camellia_ctr_create_ops.create;
export var camellia_gmac = camellia_gmac_ops.async;
export var camellia_gmac_sync = camellia_gmac_ops.sync;
export var camellia_gmac_verify = camellia_gmac_verify_ops.async;
export var camellia_gmac_verify_sync = camellia_gmac_verify_ops.sync;
export var camellia_ccm_encrypt = camellia_ccm_encrypt_ops.async;
export var camellia_ccm_encrypt_sync = camellia_ccm_encrypt_ops.sync;
export var camellia_ccm_decrypt = camellia_ccm_decrypt_ops.async;
export var camellia_ccm_decrypt_sync = camellia_ccm_decrypt_ops.sync;
export var camellia_cmac = camellia_cmac_ops.async;
export var camellia_cmac_sync = camellia_cmac_ops.sync;
export var camellia_cmac_create = camellia_cmac_ops.create;
export var camellia_cmac_verify = camellia_cmac_verify_ops.async;
export var camellia_cmac_verify_sync = camellia_cmac_verify_ops.sync;
export var camellia_kw_wrap = camellia_kw_wrap_ops.async;
export var camellia_kw_wrap_sync = camellia_kw_wrap_ops.sync;
export var camellia_kw_unwrap = camellia_kw_unwrap_ops.async;
export var camellia_kw_unwrap_sync = camellia_kw_unwrap_ops.sync;
export var camellia_kwp_wrap = camellia_kwp_wrap_ops.async;
export var camellia_kwp_wrap_sync = camellia_kwp_wrap_ops.sync;
export var camellia_kwp_unwrap = camellia_kwp_unwrap_ops.async;
export var camellia_kwp_unwrap_sync = camellia_kwp_unwrap_ops.sync;
export var camellia_eax_encrypt = camellia_eax_encrypt_ops.async;
export var camellia_eax_encrypt_sync = camellia_eax_encrypt_ops.sync;
export var camellia_eax_decrypt = camellia_eax_decrypt_ops.async;
export var camellia_eax_decrypt_sync = camellia_eax_decrypt_ops.sync;
