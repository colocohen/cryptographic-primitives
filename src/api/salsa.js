/**
 * Salsa20, XSalsa20 and secretbox (NaCl), in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../salsa.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * It runs the pure JavaScript in ../salsa.js.
 */

import * as pure from '../salsa.js';
import { define } from '../engines/select.js';

var salsa20_ops = define('salsa20', { sync: pure.salsa20, text: [2], bytes: { 0: 'key', 1: 'nonce' } });
var hsalsa20_ops = define('hsalsa20', { sync: pure.hsalsa20, bytes: { 0: 'key', 1: 'nonce' } });
var xsalsa20_ops = define('xsalsa20', { sync: pure.xsalsa20, text: [2], bytes: { 0: 'key', 1: 'nonce' } });
var secretbox_ops = define('secretbox', { sync: pure.secretbox, text: [2], bytes: { 0: 'key', 1: 'nonce' } });
var secretbox_open_ops = define('secretbox_open', { sync: pure.secretbox_open, bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var xsalsa20poly1305_encrypt_ops = define('xsalsa20poly1305_encrypt', { sync: pure.xsalsa20poly1305_encrypt, text: [2], bytes: { 0: 'key', 1: 'nonce' } });
var xsalsa20poly1305_decrypt_ops = define('xsalsa20poly1305_decrypt', { sync: pure.xsalsa20poly1305_decrypt, bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var salsa20_create_ops = define('salsa20', { create: pure.salsa20_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'nonce' } });
var xsalsa20_create_ops = define('xsalsa20', { create: pure.xsalsa20_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'nonce' } });

export var salsa20 = salsa20_ops.async;
export var salsa20_sync = salsa20_ops.sync;
export var hsalsa20 = hsalsa20_ops.async;
export var hsalsa20_sync = hsalsa20_ops.sync;
export var xsalsa20 = xsalsa20_ops.async;
export var xsalsa20_sync = xsalsa20_ops.sync;
export var secretbox = secretbox_ops.async;
export var secretbox_sync = secretbox_ops.sync;
export var secretbox_open = secretbox_open_ops.async;
export var secretbox_open_sync = secretbox_open_ops.sync;
export var xsalsa20poly1305_encrypt = xsalsa20poly1305_encrypt_ops.async;
export var xsalsa20poly1305_encrypt_sync = xsalsa20poly1305_encrypt_ops.sync;
export var xsalsa20poly1305_decrypt = xsalsa20poly1305_decrypt_ops.async;
export var xsalsa20poly1305_decrypt_sync = xsalsa20poly1305_decrypt_ops.sync;
export var salsa20_create = salsa20_create_ops.create;
export var xsalsa20_create = xsalsa20_create_ops.create;
