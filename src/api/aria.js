/**
 * ARIA (RFC 5794), in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../aria.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * It runs the pure JavaScript in ../aria.js.
 */

import * as pure from '../aria.js';
import { define } from '../engines/select.js';

var aria_ecb_encrypt_ops = define('aria_ecb_encrypt', { sync: pure.aria_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var aria_ecb_decrypt_ops = define('aria_ecb_decrypt', { sync: pure.aria_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var aria_cbc_encrypt_ops = define('aria_cbc_encrypt', { sync: pure.aria_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var aria_cbc_decrypt_ops = define('aria_cbc_decrypt', { sync: pure.aria_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var aria_ctr_ops = define('aria_ctr', { sync: pure.aria_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var aria_gcm_encrypt_ops = define('aria_gcm_encrypt', { sync: pure.aria_gcm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'iv' } });
var aria_gcm_decrypt_ops = define('aria_gcm_decrypt', { sync: pure.aria_gcm_decrypt, text: [3], bytes: { 0: 'key', 1: 'iv', 2: 'sealed' } });
var aria_gcm_create_ops = define('aria_gcm', { create: pure.aria_gcm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var aria_ccm_create_ops = define('aria_ccm', { create: pure.aria_ccm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var aria_eax_create_ops = define('aria_eax', { create: pure.aria_eax_create, kind: 'aead', create_bytes: { 0: 'key' } });
var aria_ecb_create_ops = define('aria_ecb', { create: pure.aria_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var aria_ctr_create_ops = define('aria_ctr', { create: pure.aria_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });
var aria_gmac_ops = define('aria_gmac', { sync: pure.aria_gmac, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var aria_gmac_verify_ops = define('aria_gmac_verify', { sync: pure.aria_gmac_verify, text: [2], bytes: { 0: 'key', 1: 'iv', 3: 'tag' } });
var aria_ccm_encrypt_ops = define('aria_ccm_encrypt', { sync: pure.aria_ccm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var aria_ccm_decrypt_ops = define('aria_ccm_decrypt', { sync: pure.aria_ccm_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var aria_cmac_ops = define('aria_cmac', { sync: pure.aria_cmac, create: pure.aria_cmac_create, text: [1], bytes: { 0: 'key' }, create_bytes: { 0: 'key' } });
var aria_cmac_verify_ops = define('aria_cmac_verify', { sync: pure.aria_cmac_verify, text: [1], bytes: { 0: 'key', 2: 'tag' } });
var aria_kw_wrap_ops = define('aria_kw_wrap', { sync: pure.aria_kw_wrap, text: [1], bytes: { 0: 'kek' } });
var aria_kw_unwrap_ops = define('aria_kw_unwrap', { sync: pure.aria_kw_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var aria_kwp_wrap_ops = define('aria_kwp_wrap', { sync: pure.aria_kwp_wrap, text: [1], bytes: { 0: 'kek' } });
var aria_kwp_unwrap_ops = define('aria_kwp_unwrap', { sync: pure.aria_kwp_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var aria_eax_encrypt_ops = define('aria_eax_encrypt', { sync: pure.aria_eax_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var aria_eax_decrypt_ops = define('aria_eax_decrypt', { sync: pure.aria_eax_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });

export var aria_ecb_encrypt = aria_ecb_encrypt_ops.async;
export var aria_ecb_encrypt_sync = aria_ecb_encrypt_ops.sync;
export var aria_ecb_decrypt = aria_ecb_decrypt_ops.async;
export var aria_ecb_decrypt_sync = aria_ecb_decrypt_ops.sync;
export var aria_cbc_encrypt = aria_cbc_encrypt_ops.async;
export var aria_cbc_encrypt_sync = aria_cbc_encrypt_ops.sync;
export var aria_cbc_decrypt = aria_cbc_decrypt_ops.async;
export var aria_cbc_decrypt_sync = aria_cbc_decrypt_ops.sync;
export var aria_ctr = aria_ctr_ops.async;
export var aria_ctr_sync = aria_ctr_ops.sync;
export var aria_gcm_encrypt = aria_gcm_encrypt_ops.async;
export var aria_gcm_encrypt_sync = aria_gcm_encrypt_ops.sync;
export var aria_gcm_decrypt = aria_gcm_decrypt_ops.async;
export var aria_gcm_decrypt_sync = aria_gcm_decrypt_ops.sync;
export var aria_gcm_create = aria_gcm_create_ops.create;
export var aria_ccm_create = aria_ccm_create_ops.create;
export var aria_eax_create = aria_eax_create_ops.create;
export var aria_ecb_create = aria_ecb_create_ops.create;
export var aria_ctr_create = aria_ctr_create_ops.create;
export var aria_gmac = aria_gmac_ops.async;
export var aria_gmac_sync = aria_gmac_ops.sync;
export var aria_gmac_verify = aria_gmac_verify_ops.async;
export var aria_gmac_verify_sync = aria_gmac_verify_ops.sync;
export var aria_ccm_encrypt = aria_ccm_encrypt_ops.async;
export var aria_ccm_encrypt_sync = aria_ccm_encrypt_ops.sync;
export var aria_ccm_decrypt = aria_ccm_decrypt_ops.async;
export var aria_ccm_decrypt_sync = aria_ccm_decrypt_ops.sync;
export var aria_cmac = aria_cmac_ops.async;
export var aria_cmac_sync = aria_cmac_ops.sync;
export var aria_cmac_create = aria_cmac_ops.create;
export var aria_cmac_verify = aria_cmac_verify_ops.async;
export var aria_cmac_verify_sync = aria_cmac_verify_ops.sync;
export var aria_kw_wrap = aria_kw_wrap_ops.async;
export var aria_kw_wrap_sync = aria_kw_wrap_ops.sync;
export var aria_kw_unwrap = aria_kw_unwrap_ops.async;
export var aria_kw_unwrap_sync = aria_kw_unwrap_ops.sync;
export var aria_kwp_wrap = aria_kwp_wrap_ops.async;
export var aria_kwp_wrap_sync = aria_kwp_wrap_ops.sync;
export var aria_kwp_unwrap = aria_kwp_unwrap_ops.async;
export var aria_kwp_unwrap_sync = aria_kwp_unwrap_ops.sync;
export var aria_eax_encrypt = aria_eax_encrypt_ops.async;
export var aria_eax_encrypt_sync = aria_eax_encrypt_ops.sync;
export var aria_eax_decrypt = aria_eax_decrypt_ops.async;
export var aria_eax_decrypt_sync = aria_eax_decrypt_ops.sync;
