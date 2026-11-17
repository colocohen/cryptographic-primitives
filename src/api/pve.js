/**
 * pve, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../pve.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../pve.js.
 */

import * as pure from '../pve.js';
import { define } from '../engines/select.js';

var decode_ops = define('pve.decode', { sync: pure.decode });
var decrypt_ops = define('pve.decrypt', { sync: pure.decrypt, text: [3], bytes: { 2: 'dk' } });
var encode_ops = define('pve.encode', { sync: pure.encode });
var encrypt_ops = define('pve.encrypt', { sync: pure.encrypt, text: [3], bytes: { 2: 'ek' } });
var size_ops = define('pve.size', { sync: pure.size });
var verify_ops = define('pve.verify', { sync: pure.verify, text: [3], bytes: { 2: 'ek' } });

export var REPS = pure.REPS;
export var decode = decode_ops.async;
export var decode_sync = decode_ops.sync;
export var decrypt = decrypt_ops.async;
export var decrypt_sync = decrypt_ops.sync;
export var encode = encode_ops.async;
export var encode_sync = encode_ops.sync;
export var encrypt = encrypt_ops.async;
export var encrypt_sync = encrypt_ops.sync;
export var size = size_ops.async;
export var size_sync = size_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
