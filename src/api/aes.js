/**
 * AES, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../aes.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * node:crypto runs AES-GCM (one-shot and keyed context) and AES-CTR;
 * everything else is the pure JavaScript in ../aes.js.
 */

import * as pure from '../aes.js';
import { define } from '../engines/select.js';

var aes_ecb_encrypt_ops = define('aes_ecb_encrypt', { sync: pure.aes_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var aes_ecb_decrypt_ops = define('aes_ecb_decrypt', { sync: pure.aes_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var aes_ctr_ops = define('aes_ctr', { sync: pure.aes_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var aes_cbc_encrypt_ops = define('aes_cbc_encrypt', { sync: pure.aes_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var aes_cbc_decrypt_ops = define('aes_cbc_decrypt', { sync: pure.aes_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var aes_ige_encrypt_ops = define('aes_ige_encrypt', { sync: pure.aes_ige_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var aes_ige_decrypt_ops = define('aes_ige_decrypt', { sync: pure.aes_ige_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var aes_cmac_ops = define('aes_cmac', { sync: pure.aes_cmac, create: pure.aes_cmac_create, text: [1], bytes: { 0: 'key' }, create_bytes: { 0: 'key' } });
var aes_cmac_verify_ops = define('aes_cmac_verify', { sync: pure.aes_cmac_verify, text: [1], bytes: { 0: 'key', 2: 'tag' } });
var aes_kw_wrap_ops = define('aes_kw_wrap', { sync: pure.aes_kw_wrap, text: [1], bytes: { 0: 'kek' } });
var aes_kw_unwrap_ops = define('aes_kw_unwrap', { sync: pure.aes_kw_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var aes_kwp_wrap_ops = define('aes_kwp_wrap', { sync: pure.aes_kwp_wrap, text: [1], bytes: { 0: 'kek' } });
var aes_kwp_unwrap_ops = define('aes_kwp_unwrap', { sync: pure.aes_kwp_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var aes_siv_encrypt_ops = define('aes_siv_encrypt', { sync: pure.aes_siv_encrypt, text: [1], bytes: { 0: 'key' } });
var aes_siv_decrypt_ops = define('aes_siv_decrypt', { sync: pure.aes_siv_decrypt, bytes: { 0: 'key', 1: 'sealed' } });
var aes_gcm_siv_encrypt_ops = define('aes_gcm_siv_encrypt', { sync: pure.aes_gcm_siv_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var aes_gcm_siv_decrypt_ops = define('aes_gcm_siv_decrypt', { sync: pure.aes_gcm_siv_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var aes_ofb_ops = define('aes_ofb', { sync: pure.aes_ofb, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var aes_cfb_encrypt_ops = define('aes_cfb_encrypt', { sync: pure.aes_cfb_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var aes_cfb_decrypt_ops = define('aes_cfb_decrypt', { sync: pure.aes_cfb_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var aes_cfb8_encrypt_ops = define('aes_cfb8_encrypt', { sync: pure.aes_cfb8_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var aes_cfb8_decrypt_ops = define('aes_cfb8_decrypt', { sync: pure.aes_cfb8_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var aes_xts_encrypt_ops = define('aes_xts_encrypt', { sync: pure.aes_xts_encrypt, text: [2], bytes: { 0: 'key' } });
var aes_xts_decrypt_ops = define('aes_xts_decrypt', { sync: pure.aes_xts_decrypt, bytes: { 0: 'key', 2: 'data' } });
var aes_ocb_encrypt_ops = define('aes_ocb_encrypt', { sync: pure.aes_ocb_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var aes_ocb_decrypt_ops = define('aes_ocb_decrypt', { sync: pure.aes_ocb_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var aes_gcm_encrypt_ops = define('aes_gcm_encrypt', { sync: pure.aes_gcm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'iv' } });
var aes_gcm_decrypt_ops = define('aes_gcm_decrypt', { sync: pure.aes_gcm_decrypt, text: [3], bytes: { 0: 'key', 1: 'iv', 2: 'sealed' } });
var aes_gcm_create_ops = define('aes_gcm', { create: pure.aes_gcm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var aes_ccm_create_ops = define('aes_ccm', { create: pure.aes_ccm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var aes_eax_create_ops = define('aes_eax', { create: pure.aes_eax_create, kind: 'aead', create_bytes: { 0: 'key' } });
var aes_ecb_create_ops = define('aes_ecb', { create: pure.aes_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var aes_ctr_create_ops = define('aes_ctr', { create: pure.aes_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });
var aes_ccm_encrypt_ops = define('aes_ccm_encrypt', { sync: pure.aes_ccm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var aes_ccm_decrypt_ops = define('aes_ccm_decrypt', { sync: pure.aes_ccm_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var aes_gmac_ops = define('aes_gmac', { sync: pure.aes_gmac, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var aes_gmac_verify_ops = define('aes_gmac_verify', { sync: pure.aes_gmac_verify, text: [2], bytes: { 0: 'key', 1: 'iv', 3: 'tag' } });
var aes_eax_encrypt_ops = define('aes_eax_encrypt', { sync: pure.aes_eax_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var aes_eax_decrypt_ops = define('aes_eax_decrypt', { sync: pure.aes_eax_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });

export var aes_ecb_encrypt = aes_ecb_encrypt_ops.async;
export var aes_ecb_encrypt_sync = aes_ecb_encrypt_ops.sync;
export var aes_ecb_decrypt = aes_ecb_decrypt_ops.async;
export var aes_ecb_decrypt_sync = aes_ecb_decrypt_ops.sync;
export var aes_ctr = aes_ctr_ops.async;
export var aes_ctr_sync = aes_ctr_ops.sync;
export var aes_cbc_encrypt = aes_cbc_encrypt_ops.async;
export var aes_cbc_encrypt_sync = aes_cbc_encrypt_ops.sync;
export var aes_cbc_decrypt = aes_cbc_decrypt_ops.async;
export var aes_cbc_decrypt_sync = aes_cbc_decrypt_ops.sync;
export var aes_expand_key = pure.aes_expand_key;
export var aes_encrypt_block = pure.aes_encrypt_block;
export var aes_block_fn = pure.aes_block_fn;
export var aes_ige_encrypt = aes_ige_encrypt_ops.async;
export var aes_ige_encrypt_sync = aes_ige_encrypt_ops.sync;
export var aes_ige_decrypt = aes_ige_decrypt_ops.async;
export var aes_ige_decrypt_sync = aes_ige_decrypt_ops.sync;
export var aes_cmac = aes_cmac_ops.async;
export var aes_cmac_sync = aes_cmac_ops.sync;
export var aes_cmac_create = aes_cmac_ops.create;
export var aes_cmac_verify = aes_cmac_verify_ops.async;
export var aes_cmac_verify_sync = aes_cmac_verify_ops.sync;
export var aes_kw_wrap = aes_kw_wrap_ops.async;
export var aes_kw_wrap_sync = aes_kw_wrap_ops.sync;
export var aes_kw_unwrap = aes_kw_unwrap_ops.async;
export var aes_kw_unwrap_sync = aes_kw_unwrap_ops.sync;
export var aes_kwp_wrap = aes_kwp_wrap_ops.async;
export var aes_kwp_wrap_sync = aes_kwp_wrap_ops.sync;
export var aes_kwp_unwrap = aes_kwp_unwrap_ops.async;
export var aes_kwp_unwrap_sync = aes_kwp_unwrap_ops.sync;
export var aes_siv_encrypt = aes_siv_encrypt_ops.async;
export var aes_siv_encrypt_sync = aes_siv_encrypt_ops.sync;
export var aes_siv_decrypt = aes_siv_decrypt_ops.async;
export var aes_siv_decrypt_sync = aes_siv_decrypt_ops.sync;
export var aes_gcm_siv_encrypt = aes_gcm_siv_encrypt_ops.async;
export var aes_gcm_siv_encrypt_sync = aes_gcm_siv_encrypt_ops.sync;
export var aes_gcm_siv_decrypt = aes_gcm_siv_decrypt_ops.async;
export var aes_gcm_siv_decrypt_sync = aes_gcm_siv_decrypt_ops.sync;
export var aes_ofb = aes_ofb_ops.async;
export var aes_ofb_sync = aes_ofb_ops.sync;
export var aes_cfb_encrypt = aes_cfb_encrypt_ops.async;
export var aes_cfb_encrypt_sync = aes_cfb_encrypt_ops.sync;
export var aes_cfb_decrypt = aes_cfb_decrypt_ops.async;
export var aes_cfb_decrypt_sync = aes_cfb_decrypt_ops.sync;
export var aes_cfb8_encrypt = aes_cfb8_encrypt_ops.async;
export var aes_cfb8_encrypt_sync = aes_cfb8_encrypt_ops.sync;
export var aes_cfb8_decrypt = aes_cfb8_decrypt_ops.async;
export var aes_cfb8_decrypt_sync = aes_cfb8_decrypt_ops.sync;
export var aes_xts_encrypt = aes_xts_encrypt_ops.async;
export var aes_xts_encrypt_sync = aes_xts_encrypt_ops.sync;
export var aes_xts_decrypt = aes_xts_decrypt_ops.async;
export var aes_xts_decrypt_sync = aes_xts_decrypt_ops.sync;
export var aes_ocb_encrypt = aes_ocb_encrypt_ops.async;
export var aes_ocb_encrypt_sync = aes_ocb_encrypt_ops.sync;
export var aes_ocb_decrypt = aes_ocb_decrypt_ops.async;
export var aes_ocb_decrypt_sync = aes_ocb_decrypt_ops.sync;
export var aes_gcm_encrypt = aes_gcm_encrypt_ops.async;
export var aes_gcm_encrypt_sync = aes_gcm_encrypt_ops.sync;
export var aes_gcm_decrypt = aes_gcm_decrypt_ops.async;
export var aes_gcm_decrypt_sync = aes_gcm_decrypt_ops.sync;
export var aes_gcm_create = aes_gcm_create_ops.create;
export var aes_ccm_create = aes_ccm_create_ops.create;
export var aes_eax_create = aes_eax_create_ops.create;
export var aes_ecb_create = aes_ecb_create_ops.create;
export var aes_ctr_create = aes_ctr_create_ops.create;
export var aes_ccm_encrypt = aes_ccm_encrypt_ops.async;
export var aes_ccm_encrypt_sync = aes_ccm_encrypt_ops.sync;
export var aes_ccm_decrypt = aes_ccm_decrypt_ops.async;
export var aes_ccm_decrypt_sync = aes_ccm_decrypt_ops.sync;
export var aes_gmac = aes_gmac_ops.async;
export var aes_gmac_sync = aes_gmac_ops.sync;
export var aes_gmac_verify = aes_gmac_verify_ops.async;
export var aes_gmac_verify_sync = aes_gmac_verify_ops.sync;
export var aes_eax_encrypt = aes_eax_encrypt_ops.async;
export var aes_eax_encrypt_sync = aes_eax_encrypt_ops.sync;
export var aes_eax_decrypt = aes_eax_decrypt_ops.async;
export var aes_eax_decrypt_sync = aes_eax_decrypt_ops.sync;
