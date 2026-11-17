/**
 * DES and Triple DES - legacy; for interoperability only, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../des.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * It runs the pure JavaScript in ../des.js.
 */

import * as pure from '../des.js';
import { define } from '../engines/select.js';

var des_ecb_encrypt_ops = define('des_ecb_encrypt', { sync: pure.des_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var des_ecb_decrypt_ops = define('des_ecb_decrypt', { sync: pure.des_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var des_cbc_encrypt_ops = define('des_cbc_encrypt', { sync: pure.des_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var des_cbc_decrypt_ops = define('des_cbc_decrypt', { sync: pure.des_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var des_ctr_ops = define('des_ctr', { sync: pure.des_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var des_ecb_create_ops = define('des_ecb', { create: pure.des_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var des_ctr_create_ops = define('des_ctr', { create: pure.des_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });
var des3_ecb_encrypt_ops = define('des3_ecb_encrypt', { sync: pure.des3_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var des3_ecb_decrypt_ops = define('des3_ecb_decrypt', { sync: pure.des3_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var des3_cbc_encrypt_ops = define('des3_cbc_encrypt', { sync: pure.des3_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var des3_cbc_decrypt_ops = define('des3_cbc_decrypt', { sync: pure.des3_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var des3_ctr_ops = define('des3_ctr', { sync: pure.des3_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var des3_ecb_create_ops = define('des3_ecb', { create: pure.des3_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var des3_ctr_create_ops = define('des3_ctr', { create: pure.des3_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });

export var des_ecb_encrypt = des_ecb_encrypt_ops.async;
export var des_ecb_encrypt_sync = des_ecb_encrypt_ops.sync;
export var des_ecb_decrypt = des_ecb_decrypt_ops.async;
export var des_ecb_decrypt_sync = des_ecb_decrypt_ops.sync;
export var des_cbc_encrypt = des_cbc_encrypt_ops.async;
export var des_cbc_encrypt_sync = des_cbc_encrypt_ops.sync;
export var des_cbc_decrypt = des_cbc_decrypt_ops.async;
export var des_cbc_decrypt_sync = des_cbc_decrypt_ops.sync;
export var des_ctr = des_ctr_ops.async;
export var des_ctr_sync = des_ctr_ops.sync;
export var des_ecb_create = des_ecb_create_ops.create;
export var des_ctr_create = des_ctr_create_ops.create;
export var des3_ecb_encrypt = des3_ecb_encrypt_ops.async;
export var des3_ecb_encrypt_sync = des3_ecb_encrypt_ops.sync;
export var des3_ecb_decrypt = des3_ecb_decrypt_ops.async;
export var des3_ecb_decrypt_sync = des3_ecb_decrypt_ops.sync;
export var des3_cbc_encrypt = des3_cbc_encrypt_ops.async;
export var des3_cbc_encrypt_sync = des3_cbc_encrypt_ops.sync;
export var des3_cbc_decrypt = des3_cbc_decrypt_ops.async;
export var des3_cbc_decrypt_sync = des3_cbc_decrypt_ops.sync;
export var des3_ctr = des3_ctr_ops.async;
export var des3_ctr_sync = des3_ctr_ops.sync;
export var des3_ecb_create = des3_ecb_create_ops.create;
export var des3_ctr_create = des3_ctr_create_ops.create;
