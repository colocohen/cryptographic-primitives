/**
 * musig2_suites, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../musig2_suites.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../musig2_suites.js.
 */

import * as pure from '../musig2_suites.js';
import { define } from '../engines/select.js';

var key_sort_ops = define('musig2_suites.key_sort', { sync: pure.key_sort });
var musig2_on_ops = define('musig2_suites.musig2_on', { sync: pure.musig2_on });

export var key_sort = key_sort_ops.async;
export var key_sort_sync = key_sort_ops.sync;
export var musig2_on = musig2_on_ops.async;
export var musig2_on_sync = musig2_on_ops.sync;
