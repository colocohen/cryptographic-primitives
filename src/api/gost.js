/**
 * GOST R 34.12-2015: Kuznyechik and Magma, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../gost.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * It runs the pure JavaScript in ../gost.js.
 */

import * as pure from '../gost.js';
import { define } from '../engines/select.js';

var kuznyechik_ecb_encrypt_ops = define('kuznyechik_ecb_encrypt', { sync: pure.kuznyechik_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var kuznyechik_ecb_decrypt_ops = define('kuznyechik_ecb_decrypt', { sync: pure.kuznyechik_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var kuznyechik_cbc_encrypt_ops = define('kuznyechik_cbc_encrypt', { sync: pure.kuznyechik_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var kuznyechik_cbc_decrypt_ops = define('kuznyechik_cbc_decrypt', { sync: pure.kuznyechik_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var kuznyechik_ctr_ops = define('kuznyechik_ctr', { sync: pure.kuznyechik_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var kuznyechik_ecb_create_ops = define('kuznyechik_ecb', { create: pure.kuznyechik_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var kuznyechik_ctr_create_ops = define('kuznyechik_ctr', { create: pure.kuznyechik_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });
var kuznyechik_gcm_encrypt_ops = define('kuznyechik_gcm_encrypt', { sync: pure.kuznyechik_gcm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'iv' } });
var kuznyechik_gcm_decrypt_ops = define('kuznyechik_gcm_decrypt', { sync: pure.kuznyechik_gcm_decrypt, text: [3], bytes: { 0: 'key', 1: 'iv', 2: 'sealed' } });
var kuznyechik_gcm_create_ops = define('kuznyechik_gcm', { create: pure.kuznyechik_gcm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var kuznyechik_ccm_create_ops = define('kuznyechik_ccm', { create: pure.kuznyechik_ccm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var kuznyechik_eax_create_ops = define('kuznyechik_eax', { create: pure.kuznyechik_eax_create, kind: 'aead', create_bytes: { 0: 'key' } });
var kuznyechik_gmac_ops = define('kuznyechik_gmac', { sync: pure.kuznyechik_gmac, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var kuznyechik_gmac_verify_ops = define('kuznyechik_gmac_verify', { sync: pure.kuznyechik_gmac_verify, text: [2], bytes: { 0: 'key', 1: 'iv', 3: 'tag' } });
var kuznyechik_ccm_encrypt_ops = define('kuznyechik_ccm_encrypt', { sync: pure.kuznyechik_ccm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var kuznyechik_ccm_decrypt_ops = define('kuznyechik_ccm_decrypt', { sync: pure.kuznyechik_ccm_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var kuznyechik_cmac_ops = define('kuznyechik_cmac', { sync: pure.kuznyechik_cmac, create: pure.kuznyechik_cmac_create, text: [1], bytes: { 0: 'key' }, create_bytes: { 0: 'key' } });
var kuznyechik_cmac_verify_ops = define('kuznyechik_cmac_verify', { sync: pure.kuznyechik_cmac_verify, text: [1], bytes: { 0: 'key', 2: 'tag' } });
var kuznyechik_kw_wrap_ops = define('kuznyechik_kw_wrap', { sync: pure.kuznyechik_kw_wrap, text: [1], bytes: { 0: 'kek' } });
var kuznyechik_kw_unwrap_ops = define('kuznyechik_kw_unwrap', { sync: pure.kuznyechik_kw_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var kuznyechik_kwp_wrap_ops = define('kuznyechik_kwp_wrap', { sync: pure.kuznyechik_kwp_wrap, text: [1], bytes: { 0: 'kek' } });
var kuznyechik_kwp_unwrap_ops = define('kuznyechik_kwp_unwrap', { sync: pure.kuznyechik_kwp_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var kuznyechik_eax_encrypt_ops = define('kuznyechik_eax_encrypt', { sync: pure.kuznyechik_eax_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var kuznyechik_eax_decrypt_ops = define('kuznyechik_eax_decrypt', { sync: pure.kuznyechik_eax_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var magma_ecb_encrypt_ops = define('magma_ecb_encrypt', { sync: pure.magma_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var magma_ecb_decrypt_ops = define('magma_ecb_decrypt', { sync: pure.magma_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var magma_cbc_encrypt_ops = define('magma_cbc_encrypt', { sync: pure.magma_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var magma_cbc_decrypt_ops = define('magma_cbc_decrypt', { sync: pure.magma_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var magma_ctr_ops = define('magma_ctr', { sync: pure.magma_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var magma_ecb_create_ops = define('magma_ecb', { create: pure.magma_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var magma_ctr_create_ops = define('magma_ctr', { create: pure.magma_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });

export var kuznyechik_ecb_encrypt = kuznyechik_ecb_encrypt_ops.async;
export var kuznyechik_ecb_encrypt_sync = kuznyechik_ecb_encrypt_ops.sync;
export var kuznyechik_ecb_decrypt = kuznyechik_ecb_decrypt_ops.async;
export var kuznyechik_ecb_decrypt_sync = kuznyechik_ecb_decrypt_ops.sync;
export var kuznyechik_cbc_encrypt = kuznyechik_cbc_encrypt_ops.async;
export var kuznyechik_cbc_encrypt_sync = kuznyechik_cbc_encrypt_ops.sync;
export var kuznyechik_cbc_decrypt = kuznyechik_cbc_decrypt_ops.async;
export var kuznyechik_cbc_decrypt_sync = kuznyechik_cbc_decrypt_ops.sync;
export var kuznyechik_ctr = kuznyechik_ctr_ops.async;
export var kuznyechik_ctr_sync = kuznyechik_ctr_ops.sync;
export var kuznyechik_ecb_create = kuznyechik_ecb_create_ops.create;
export var kuznyechik_ctr_create = kuznyechik_ctr_create_ops.create;
export var kuznyechik_gcm_encrypt = kuznyechik_gcm_encrypt_ops.async;
export var kuznyechik_gcm_encrypt_sync = kuznyechik_gcm_encrypt_ops.sync;
export var kuznyechik_gcm_decrypt = kuznyechik_gcm_decrypt_ops.async;
export var kuznyechik_gcm_decrypt_sync = kuznyechik_gcm_decrypt_ops.sync;
export var kuznyechik_gcm_create = kuznyechik_gcm_create_ops.create;
export var kuznyechik_ccm_create = kuznyechik_ccm_create_ops.create;
export var kuznyechik_eax_create = kuznyechik_eax_create_ops.create;
export var kuznyechik_gmac = kuznyechik_gmac_ops.async;
export var kuznyechik_gmac_sync = kuznyechik_gmac_ops.sync;
export var kuznyechik_gmac_verify = kuznyechik_gmac_verify_ops.async;
export var kuznyechik_gmac_verify_sync = kuznyechik_gmac_verify_ops.sync;
export var kuznyechik_ccm_encrypt = kuznyechik_ccm_encrypt_ops.async;
export var kuznyechik_ccm_encrypt_sync = kuznyechik_ccm_encrypt_ops.sync;
export var kuznyechik_ccm_decrypt = kuznyechik_ccm_decrypt_ops.async;
export var kuznyechik_ccm_decrypt_sync = kuznyechik_ccm_decrypt_ops.sync;
export var kuznyechik_cmac = kuznyechik_cmac_ops.async;
export var kuznyechik_cmac_sync = kuznyechik_cmac_ops.sync;
export var kuznyechik_cmac_create = kuznyechik_cmac_ops.create;
export var kuznyechik_cmac_verify = kuznyechik_cmac_verify_ops.async;
export var kuznyechik_cmac_verify_sync = kuznyechik_cmac_verify_ops.sync;
export var kuznyechik_kw_wrap = kuznyechik_kw_wrap_ops.async;
export var kuznyechik_kw_wrap_sync = kuznyechik_kw_wrap_ops.sync;
export var kuznyechik_kw_unwrap = kuznyechik_kw_unwrap_ops.async;
export var kuznyechik_kw_unwrap_sync = kuznyechik_kw_unwrap_ops.sync;
export var kuznyechik_kwp_wrap = kuznyechik_kwp_wrap_ops.async;
export var kuznyechik_kwp_wrap_sync = kuznyechik_kwp_wrap_ops.sync;
export var kuznyechik_kwp_unwrap = kuznyechik_kwp_unwrap_ops.async;
export var kuznyechik_kwp_unwrap_sync = kuznyechik_kwp_unwrap_ops.sync;
export var kuznyechik_eax_encrypt = kuznyechik_eax_encrypt_ops.async;
export var kuznyechik_eax_encrypt_sync = kuznyechik_eax_encrypt_ops.sync;
export var kuznyechik_eax_decrypt = kuznyechik_eax_decrypt_ops.async;
export var kuznyechik_eax_decrypt_sync = kuznyechik_eax_decrypt_ops.sync;
export var magma_ecb_encrypt = magma_ecb_encrypt_ops.async;
export var magma_ecb_encrypt_sync = magma_ecb_encrypt_ops.sync;
export var magma_ecb_decrypt = magma_ecb_decrypt_ops.async;
export var magma_ecb_decrypt_sync = magma_ecb_decrypt_ops.sync;
export var magma_cbc_encrypt = magma_cbc_encrypt_ops.async;
export var magma_cbc_encrypt_sync = magma_cbc_encrypt_ops.sync;
export var magma_cbc_decrypt = magma_cbc_decrypt_ops.async;
export var magma_cbc_decrypt_sync = magma_cbc_decrypt_ops.sync;
export var magma_ctr = magma_ctr_ops.async;
export var magma_ctr_sync = magma_ctr_ops.sync;
export var magma_ecb_create = magma_ecb_create_ops.create;
export var magma_ctr_create = magma_ctr_create_ops.create;
