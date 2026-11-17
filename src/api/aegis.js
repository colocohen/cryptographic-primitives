/**
 * aegis, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../aegis.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../aegis.js.
 */

import * as pure from '../aegis.js';
import { define } from '../engines/select.js';

var aegis128l_decrypt_ops = define('aegis.aegis128l_decrypt', { sync: pure.aegis128l_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var aegis128l_encrypt_ops = define('aegis.aegis128l_encrypt', { sync: pure.aegis128l_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var aegis256_decrypt_ops = define('aegis.aegis256_decrypt', { sync: pure.aegis256_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var aegis256_encrypt_ops = define('aegis.aegis256_encrypt', { sync: pure.aegis256_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });

export var aegis128l_decrypt = aegis128l_decrypt_ops.async;
export var aegis128l_decrypt_sync = aegis128l_decrypt_ops.sync;
export var aegis128l_encrypt = aegis128l_encrypt_ops.async;
export var aegis128l_encrypt_sync = aegis128l_encrypt_ops.sync;
export var aegis256_decrypt = aegis256_decrypt_ops.async;
export var aegis256_decrypt_sync = aegis256_decrypt_ops.sync;
export var aegis256_encrypt = aegis256_encrypt_ops.async;
export var aegis256_encrypt_sync = aegis256_encrypt_ops.sync;
