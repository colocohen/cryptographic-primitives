/**
 * Blowfish - legacy; for interoperability only, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../blowfish.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * It runs the pure JavaScript in ../blowfish.js.
 */

import * as pure from '../blowfish.js';
import { define } from '../engines/select.js';

var blowfish_ecb_encrypt_ops = define('blowfish_ecb_encrypt', { sync: pure.blowfish_ecb_encrypt, text: [1], bytes: { 0: 'key' } });
var blowfish_ecb_decrypt_ops = define('blowfish_ecb_decrypt', { sync: pure.blowfish_ecb_decrypt, bytes: { 0: 'key', 1: 'data' } });
var blowfish_cbc_encrypt_ops = define('blowfish_cbc_encrypt', { sync: pure.blowfish_cbc_encrypt, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var blowfish_cbc_decrypt_ops = define('blowfish_cbc_decrypt', { sync: pure.blowfish_cbc_decrypt, bytes: { 0: 'key', 1: 'iv', 2: 'data' } });
var blowfish_ctr_ops = define('blowfish_ctr', { sync: pure.blowfish_ctr, text: [2], bytes: { 0: 'key', 1: 'iv' } });
var blowfish_ecb_create_ops = define('blowfish_ecb', { create: pure.blowfish_ecb_create, kind: 'block', create_bytes: { 0: 'key' } });
var blowfish_ctr_create_ops = define('blowfish_ctr', { create: pure.blowfish_ctr_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'iv' } });

export var blowfish_ecb_encrypt = blowfish_ecb_encrypt_ops.async;
export var blowfish_ecb_encrypt_sync = blowfish_ecb_encrypt_ops.sync;
export var blowfish_ecb_decrypt = blowfish_ecb_decrypt_ops.async;
export var blowfish_ecb_decrypt_sync = blowfish_ecb_decrypt_ops.sync;
export var blowfish_cbc_encrypt = blowfish_cbc_encrypt_ops.async;
export var blowfish_cbc_encrypt_sync = blowfish_cbc_encrypt_ops.sync;
export var blowfish_cbc_decrypt = blowfish_cbc_decrypt_ops.async;
export var blowfish_cbc_decrypt_sync = blowfish_cbc_decrypt_ops.sync;
export var blowfish_ctr = blowfish_ctr_ops.async;
export var blowfish_ctr_sync = blowfish_ctr_ops.sync;
export var blowfish_ecb_create = blowfish_ecb_create_ops.create;
export var blowfish_ctr_create = blowfish_ctr_create_ops.create;
