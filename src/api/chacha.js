/**
 * ChaCha20, XChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439), in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../chacha.js. Decryption that fails authentication
 * gives null, in both forms.
 *
 *     <mode>_create(key)     a keyed AEAD context, the key prepared once:
 *                            { encrypt(nonce, pt, aad, cb), encrypt_sync,
 *                              decrypt(nonce, sealed, aad, cb), decrypt_sync, wipe }
 *     <stream>_create(...)   a keystream cipher fed in pieces:
 *                            { update(data) -> data xor keystream, copy, wipe }
 *
 * Plaintext and associated data may be strings (UTF-8).
 * node:crypto runs ChaCha20 and ChaCha20-Poly1305 (one-shot and keyed
 * context); everything else is the pure JavaScript in ../chacha.js.
 */

import * as pure from '../chacha.js';
import { define } from '../engines/select.js';

var chacha20_ops = define('chacha20', { sync: pure.chacha20, text: [2], bytes: { 0: 'key', 1: 'nonce' } });
var hchacha20_ops = define('hchacha20', { sync: pure.hchacha20, bytes: { 0: 'key', 1: 'nonce' } });
var xchacha20_ops = define('xchacha20', { sync: pure.xchacha20, text: [2], bytes: { 0: 'key', 1: 'nonce' } });
var poly1305_ops = define('poly1305', { sync: pure.poly1305, text: [1], bytes: { 0: 'key' } });
var chacha20poly1305_encrypt_ops = define('chacha20poly1305_encrypt', { sync: pure.chacha20poly1305_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var chacha20poly1305_decrypt_ops = define('chacha20poly1305_decrypt', { sync: pure.chacha20poly1305_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var xchacha20poly1305_encrypt_ops = define('xchacha20poly1305_encrypt', { sync: pure.xchacha20poly1305_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var xchacha20poly1305_decrypt_ops = define('xchacha20poly1305_decrypt', { sync: pure.xchacha20poly1305_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var chacha8_ops = define('chacha8', { sync: pure.chacha8, text: [2], bytes: { 0: 'key', 1: 'nonce' } });
var chacha12_ops = define('chacha12', { sync: pure.chacha12, text: [2], bytes: { 0: 'key', 1: 'nonce' } });
var chacha20_orig_ops = define('chacha20_orig', { sync: pure.chacha20_orig, text: [2], bytes: { 0: 'key', 1: 'nonce' } });
var chacha20_create_ops = define('chacha20', { create: pure.chacha20_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'nonce' } });
var chacha12_create_ops = define('chacha12', { create: pure.chacha12_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'nonce' } });
var chacha8_create_ops = define('chacha8', { create: pure.chacha8_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'nonce' } });
var xchacha20_create_ops = define('xchacha20', { create: pure.xchacha20_create, kind: 'stream', create_bytes: { 0: 'key', 1: 'nonce' } });
var chacha20poly1305_create_ops = define('chacha20poly1305', { create: pure.chacha20poly1305_create, kind: 'aead', create_bytes: { 0: 'key' } });
var xchacha20poly1305_create_ops = define('xchacha20poly1305', { create: pure.xchacha20poly1305_create, kind: 'aead', create_bytes: { 0: 'key' } });

export var chacha20 = chacha20_ops.async;
export var chacha20_sync = chacha20_ops.sync;
export var hchacha20 = hchacha20_ops.async;
export var hchacha20_sync = hchacha20_ops.sync;
export var xchacha20 = xchacha20_ops.async;
export var xchacha20_sync = xchacha20_ops.sync;
export var poly1305 = poly1305_ops.async;
export var poly1305_sync = poly1305_ops.sync;
export var chacha20poly1305_encrypt = chacha20poly1305_encrypt_ops.async;
export var chacha20poly1305_encrypt_sync = chacha20poly1305_encrypt_ops.sync;
export var chacha20poly1305_decrypt = chacha20poly1305_decrypt_ops.async;
export var chacha20poly1305_decrypt_sync = chacha20poly1305_decrypt_ops.sync;
export var xchacha20poly1305_encrypt = xchacha20poly1305_encrypt_ops.async;
export var xchacha20poly1305_encrypt_sync = xchacha20poly1305_encrypt_ops.sync;
export var xchacha20poly1305_decrypt = xchacha20poly1305_decrypt_ops.async;
export var xchacha20poly1305_decrypt_sync = xchacha20poly1305_decrypt_ops.sync;
export var chacha8 = chacha8_ops.async;
export var chacha8_sync = chacha8_ops.sync;
export var chacha12 = chacha12_ops.async;
export var chacha12_sync = chacha12_ops.sync;
export var chacha20_orig = chacha20_orig_ops.async;
export var chacha20_orig_sync = chacha20_orig_ops.sync;
export var chacha20_create = chacha20_create_ops.create;
export var chacha12_create = chacha12_create_ops.create;
export var chacha8_create = chacha8_create_ops.create;
export var xchacha20_create = xchacha20_create_ops.create;
export var chacha20poly1305_create = chacha20poly1305_create_ops.create;
export var xchacha20poly1305_create = xchacha20poly1305_create_ops.create;
