/**
 * schnorr, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../schnorr.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../schnorr.js.
 */

import * as pure from '../schnorr.js';
import { define } from '../engines/select.js';

var sign_ops = define('schnorr.sign', { sync: pure.sign, text: [2, 4] });
var verify_ops = define('schnorr.verify', { sync: pure.verify, text: [2, 4], bytes: { 3: 'sig' } });
var verify_batch_ops = define('schnorr.verify_batch', { sync: pure.verify_batch, text: [1] });
var verify_batch_find_ops = define('schnorr.verify_batch_find', { sync: pure.verify_batch_find, text: [1] });

export var sign = sign_ops.async;
export var sign_sync = sign_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
export var verify_batch = verify_batch_ops.async;
export var verify_batch_sync = verify_batch_ops.sync;
export var verify_batch_find = verify_batch_find_ops.async;
export var verify_batch_find_sync = verify_batch_find_ops.sync;
