/**
 * SEED (RFC 4269), in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../seed.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * It runs the pure JavaScript in ../seed.js.
 */

import * as pure from '../seed.js';
import { define } from '../engines/select.js';

var seed_ecb_encrypt_ops = define('seed_ecb_encrypt', { sync: pure.seed_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var seed_ecb_decrypt_ops = define('seed_ecb_decrypt', { sync: pure.seed_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var seed_cbc_encrypt_ops = define('seed_cbc_encrypt', { sync: pure.seed_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var seed_cbc_decrypt_ops = define('seed_cbc_decrypt', { sync: pure.seed_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var seed_ctr_ops = define('seed_ctr', { sync: pure.seed_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var seed_gcm_encrypt_ops = define('seed_gcm_encrypt', { sync: pure.seed_gcm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'iv' } });
var seed_gcm_decrypt_ops = define('seed_gcm_decrypt', { sync: pure.seed_gcm_decrypt, text: [3], bytes: { 0: 'key', 1: 'iv', 2: 'sealed' } });
var seed_gcm_create_ops = define('seed_gcm', { create: pure.seed_gcm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var seed_ccm_create_ops = define('seed_ccm', { create: pure.seed_ccm_create, kind: 'aead', create_bytes: { 0: 'key' } });
var seed_eax_create_ops = define('seed_eax', { create: pure.seed_eax_create, kind: 'aead', create_bytes: { 0: 'key' } });
var seed_ecb_create_ops = define('seed_ecb', { create: pure.seed_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var seed_ctr_create_ops = define('seed_ctr', { create: pure.seed_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });
var seed_gmac_ops = define('seed_gmac', { sync: pure.seed_gmac, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var seed_gmac_verify_ops = define('seed_gmac_verify', { sync: pure.seed_gmac_verify, text: [2], bytes: { 0: 'key', 1: 'iv', 3: 'tag' } });
var seed_ccm_encrypt_ops = define('seed_ccm_encrypt', { sync: pure.seed_ccm_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var seed_ccm_decrypt_ops = define('seed_ccm_decrypt', { sync: pure.seed_ccm_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var seed_cmac_ops = define('seed_cmac', { sync: pure.seed_cmac, create: pure.seed_cmac_create, text: [1], bytes: { 0: 'key' }, create_bytes: { 0: 'key' } });
var seed_cmac_verify_ops = define('seed_cmac_verify', { sync: pure.seed_cmac_verify, text: [1], bytes: { 0: 'key', 2: 'tag' } });
var seed_kw_wrap_ops = define('seed_kw_wrap', { sync: pure.seed_kw_wrap, text: [1], bytes: { 0: 'kek' } });
var seed_kw_unwrap_ops = define('seed_kw_unwrap', { sync: pure.seed_kw_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var seed_kwp_wrap_ops = define('seed_kwp_wrap', { sync: pure.seed_kwp_wrap, text: [1], bytes: { 0: 'kek' } });
var seed_kwp_unwrap_ops = define('seed_kwp_unwrap', { sync: pure.seed_kwp_unwrap, bytes: { 0: 'kek', 1: 'wrapped' } });
var seed_eax_encrypt_ops = define('seed_eax_encrypt', { sync: pure.seed_eax_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var seed_eax_decrypt_ops = define('seed_eax_decrypt', { sync: pure.seed_eax_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });

export var seed_ecb_encrypt = seed_ecb_encrypt_ops.async;
export var seed_ecb_encrypt_sync = seed_ecb_encrypt_ops.sync;
export var seed_ecb_decrypt = seed_ecb_decrypt_ops.async;
export var seed_ecb_decrypt_sync = seed_ecb_decrypt_ops.sync;
export var seed_cbc_encrypt = seed_cbc_encrypt_ops.async;
export var seed_cbc_encrypt_sync = seed_cbc_encrypt_ops.sync;
export var seed_cbc_decrypt = seed_cbc_decrypt_ops.async;
export var seed_cbc_decrypt_sync = seed_cbc_decrypt_ops.sync;
export var seed_ctr = seed_ctr_ops.async;
export var seed_ctr_sync = seed_ctr_ops.sync;
export var seed_gcm_encrypt = seed_gcm_encrypt_ops.async;
export var seed_gcm_encrypt_sync = seed_gcm_encrypt_ops.sync;
export var seed_gcm_decrypt = seed_gcm_decrypt_ops.async;
export var seed_gcm_decrypt_sync = seed_gcm_decrypt_ops.sync;
export var seed_gcm_create = seed_gcm_create_ops.create;
export var seed_ccm_create = seed_ccm_create_ops.create;
export var seed_eax_create = seed_eax_create_ops.create;
export var seed_ecb_create = seed_ecb_create_ops.create;
export var seed_ctr_create = seed_ctr_create_ops.create;
export var seed_gmac = seed_gmac_ops.async;
export var seed_gmac_sync = seed_gmac_ops.sync;
export var seed_gmac_verify = seed_gmac_verify_ops.async;
export var seed_gmac_verify_sync = seed_gmac_verify_ops.sync;
export var seed_ccm_encrypt = seed_ccm_encrypt_ops.async;
export var seed_ccm_encrypt_sync = seed_ccm_encrypt_ops.sync;
export var seed_ccm_decrypt = seed_ccm_decrypt_ops.async;
export var seed_ccm_decrypt_sync = seed_ccm_decrypt_ops.sync;
export var seed_cmac = seed_cmac_ops.async;
export var seed_cmac_sync = seed_cmac_ops.sync;
export var seed_cmac_create = seed_cmac_ops.create;
export var seed_cmac_verify = seed_cmac_verify_ops.async;
export var seed_cmac_verify_sync = seed_cmac_verify_ops.sync;
export var seed_kw_wrap = seed_kw_wrap_ops.async;
export var seed_kw_wrap_sync = seed_kw_wrap_ops.sync;
export var seed_kw_unwrap = seed_kw_unwrap_ops.async;
export var seed_kw_unwrap_sync = seed_kw_unwrap_ops.sync;
export var seed_kwp_wrap = seed_kwp_wrap_ops.async;
export var seed_kwp_wrap_sync = seed_kwp_wrap_ops.sync;
export var seed_kwp_unwrap = seed_kwp_unwrap_ops.async;
export var seed_kwp_unwrap_sync = seed_kwp_unwrap_ops.sync;
export var seed_eax_encrypt = seed_eax_encrypt_ops.async;
export var seed_eax_encrypt_sync = seed_eax_encrypt_ops.sync;
export var seed_eax_decrypt = seed_eax_decrypt_ops.async;
export var seed_eax_decrypt_sync = seed_eax_decrypt_ops.sync;
