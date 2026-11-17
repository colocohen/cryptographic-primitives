/**
 * kemeleon, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../kemeleon.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../kemeleon.js.
 */

import * as pure from '../kemeleon.js';
import { define } from '../engines/select.js';

var kemeleon_ops = define('kemeleon.kemeleon', { sync: pure.kemeleon });

export var kemeleon = kemeleon_ops.async;
export var kemeleon_sync = kemeleon_ops.sync;
