/**
 * SM4 (GB/T 32907), in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../sm4.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * It runs the pure JavaScript in ../sm4.js.
 */

import * as pure from '../sm4.js';
import { define } from '../engines/select.js';

var sm4_ecb_encrypt_ops = define('sm4_ecb_encrypt', { sync: pure.sm4_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var sm4_ecb_decrypt_ops = define('sm4_ecb_decrypt', { sync: pure.sm4_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var sm4_cbc_encrypt_ops = define('sm4_cbc_encrypt', { sync: pure.sm4_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var sm4_cbc_decrypt_ops = define('sm4_cbc_decrypt', { sync: pure.sm4_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var sm4_ctr_ops = define('sm4_ctr', { sync: pure.sm4_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var sm4_gcm_encrypt_ops = define('sm4_gcm_encrypt', { sync: pure.sm4_gcm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'iv' } });
var sm4_gcm_decrypt_ops = define('sm4_gcm_decrypt', { sync: pure.sm4_gcm_decrypt, text: [3], bytes: { 0: 'key', 1: 'iv', 2: 'sealed' } });
var sm4_gcm_create_ops = define('sm4_gcm', { create: pure.sm4_gcm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var sm4_ccm_create_ops = define('sm4_ccm', { create: pure.sm4_ccm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var sm4_eax_create_ops = define('sm4_eax', { create: pure.sm4_eax_create, kind: 'aead', create_bytes: { 0: 'key' } });
var sm4_ecb_create_ops = define('sm4_ecb', { create: pure.sm4_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var sm4_ctr_create_ops = define('sm4_ctr', { create: pure.sm4_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });
var sm4_gmac_ops = define('sm4_gmac', { sync: pure.sm4_gmac, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var sm4_gmac_verify_ops = define('sm4_gmac_verify', { sync: pure.sm4_gmac_verify, text: [2], bytes: { 0: 'key', 1: 'iv', 3: 'tag' } });
var sm4_ccm_encrypt_ops = define('sm4_ccm_encrypt', { sync: pure.sm4_ccm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var sm4_ccm_decrypt_ops = define('sm4_ccm_decrypt', { sync: pure.sm4_ccm_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var sm4_cmac_ops = define('sm4_cmac', { sync: pure.sm4_cmac, create: pure.sm4_cmac_create, text: [1], bytes: { 0: 'key' }, create_bytes: { 0: 'key' } });
var sm4_cmac_verify_ops = define('sm4_cmac_verify', { sync: pure.sm4_cmac_verify, text: [1], bytes: { 0: 'key', 2: 'tag' } });
var sm4_kw_wrap_ops = define('sm4_kw_wrap', { sync: pure.sm4_kw_wrap, text: [1], bytes: { 0: 'kek' } });
var sm4_kw_unwrap_ops = define('sm4_kw_unwrap', { sync: pure.sm4_kw_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var sm4_kwp_wrap_ops = define('sm4_kwp_wrap', { sync: pure.sm4_kwp_wrap, text: [1], bytes: { 0: 'kek' } });
var sm4_kwp_unwrap_ops = define('sm4_kwp_unwrap', { sync: pure.sm4_kwp_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var sm4_eax_encrypt_ops = define('sm4_eax_encrypt', { sync: pure.sm4_eax_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var sm4_eax_decrypt_ops = define('sm4_eax_decrypt', { sync: pure.sm4_eax_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });

export var sm4_ecb_encrypt = sm4_ecb_encrypt_ops.async;
export var sm4_ecb_encrypt_sync = sm4_ecb_encrypt_ops.sync;
export var sm4_ecb_decrypt = sm4_ecb_decrypt_ops.async;
export var sm4_ecb_decrypt_sync = sm4_ecb_decrypt_ops.sync;
export var sm4_cbc_encrypt = sm4_cbc_encrypt_ops.async;
export var sm4_cbc_encrypt_sync = sm4_cbc_encrypt_ops.sync;
export var sm4_cbc_decrypt = sm4_cbc_decrypt_ops.async;
export var sm4_cbc_decrypt_sync = sm4_cbc_decrypt_ops.sync;
export var sm4_ctr = sm4_ctr_ops.async;
export var sm4_ctr_sync = sm4_ctr_ops.sync;
export var sm4_gcm_encrypt = sm4_gcm_encrypt_ops.async;
export var sm4_gcm_encrypt_sync = sm4_gcm_encrypt_ops.sync;
export var sm4_gcm_decrypt = sm4_gcm_decrypt_ops.async;
export var sm4_gcm_decrypt_sync = sm4_gcm_decrypt_ops.sync;
export var sm4_gcm_create = sm4_gcm_create_ops.create;
export var sm4_ccm_create = sm4_ccm_create_ops.create;
export var sm4_eax_create = sm4_eax_create_ops.create;
export var sm4_ecb_create = sm4_ecb_create_ops.create;
export var sm4_ctr_create = sm4_ctr_create_ops.create;
export var sm4_gmac = sm4_gmac_ops.async;
export var sm4_gmac_sync = sm4_gmac_ops.sync;
export var sm4_gmac_verify = sm4_gmac_verify_ops.async;
export var sm4_gmac_verify_sync = sm4_gmac_verify_ops.sync;
export var sm4_ccm_encrypt = sm4_ccm_encrypt_ops.async;
export var sm4_ccm_encrypt_sync = sm4_ccm_encrypt_ops.sync;
export var sm4_ccm_decrypt = sm4_ccm_decrypt_ops.async;
export var sm4_ccm_decrypt_sync = sm4_ccm_decrypt_ops.sync;
export var sm4_cmac = sm4_cmac_ops.async;
export var sm4_cmac_sync = sm4_cmac_ops.sync;
export var sm4_cmac_create = sm4_cmac_ops.create;
export var sm4_cmac_verify = sm4_cmac_verify_ops.async;
export var sm4_cmac_verify_sync = sm4_cmac_verify_ops.sync;
export var sm4_kw_wrap = sm4_kw_wrap_ops.async;
export var sm4_kw_wrap_sync = sm4_kw_wrap_ops.sync;
export var sm4_kw_unwrap = sm4_kw_unwrap_ops.async;
export var sm4_kw_unwrap_sync = sm4_kw_unwrap_ops.sync;
export var sm4_kwp_wrap = sm4_kwp_wrap_ops.async;
export var sm4_kwp_wrap_sync = sm4_kwp_wrap_ops.sync;
export var sm4_kwp_unwrap = sm4_kwp_unwrap_ops.async;
export var sm4_kwp_unwrap_sync = sm4_kwp_unwrap_ops.sync;
export var sm4_eax_encrypt = sm4_eax_encrypt_ops.async;
export var sm4_eax_encrypt_sync = sm4_eax_encrypt_ops.sync;
export var sm4_eax_decrypt = sm4_eax_decrypt_ops.async;
export var sm4_eax_decrypt_sync = sm4_eax_decrypt_ops.sync;
