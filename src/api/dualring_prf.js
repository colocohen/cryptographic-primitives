/**
 * dualring_prf, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../dualring_prf.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../dualring_prf.js.
 */

import * as pure from '../dualring_prf.js';
import { define } from '../engines/select.js';

var dualring_prf_ops = define('dualring_prf.dualring_prf', { sync: pure.dualring_prf });

export var dualring_prf = dualring_prf_ops.async;
export var dualring_prf_sync = dualring_prf_ops.sync;
