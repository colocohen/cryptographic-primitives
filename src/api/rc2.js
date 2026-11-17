/**
 * RC2 - legacy; for interoperability only, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../rc2.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * It runs the pure JavaScript in ../rc2.js.
 */

import * as pure from '../rc2.js';
import { define } from '../engines/select.js';

var rc2_ecb_encrypt_ops = define('rc2_ecb_encrypt', { sync: pure.rc2_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var rc2_ecb_decrypt_ops = define('rc2_ecb_decrypt', { sync: pure.rc2_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var rc2_cbc_encrypt_ops = define('rc2_cbc_encrypt', { sync: pure.rc2_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var rc2_cbc_decrypt_ops = define('rc2_cbc_decrypt', { sync: pure.rc2_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var rc2_ctr_ops = define('rc2_ctr', { sync: pure.rc2_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var rc2_ecb_create_ops = define('rc2_ecb', { create: pure.rc2_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var rc2_ctr_create_ops = define('rc2_ctr', { create: pure.rc2_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });

export var rc2_ecb_encrypt = rc2_ecb_encrypt_ops.async;
export var rc2_ecb_encrypt_sync = rc2_ecb_encrypt_ops.sync;
export var rc2_ecb_decrypt = rc2_ecb_decrypt_ops.async;
export var rc2_ecb_decrypt_sync = rc2_ecb_decrypt_ops.sync;
export var rc2_cbc_encrypt = rc2_cbc_encrypt_ops.async;
export var rc2_cbc_encrypt_sync = rc2_cbc_encrypt_ops.sync;
export var rc2_cbc_decrypt = rc2_cbc_decrypt_ops.async;
export var rc2_cbc_decrypt_sync = rc2_cbc_decrypt_ops.sync;
export var rc2_ctr = rc2_ctr_ops.async;
export var rc2_ctr_sync = rc2_ctr_ops.sync;
export var rc2_ecb_create = rc2_ecb_create_ops.create;
export var rc2_ctr_create = rc2_ctr_create_ops.create;
