/**
 * cmp_setup, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../cmp_setup.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../cmp_setup.js.
 */

import * as pure from '../cmp_setup.js';
import { define } from '../engines/select.js';

var precompute_aux_ops = define('cmp_setup.precompute_aux', { sync: pure.precompute_aux });

export var precompute_aux = precompute_aux_ops.async;
export var precompute_aux_sync = precompute_aux_ops.sync;
