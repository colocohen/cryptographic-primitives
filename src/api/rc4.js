/**
 * rc4, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../rc4.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../rc4.js.
 */

import * as pure from '../rc4.js';
import { define } from '../engines/select.js';

var rc4_ops = define('rc4.rc4', { sync: pure.rc4, text: [1], bytes: { 0: 'key' } });

export var rc4 = rc4_ops.async;
export var rc4_sync = rc4_ops.sync;
