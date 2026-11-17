/**
 * legendre_oprf, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../legendre_oprf.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../legendre_oprf.js.
 */

import * as pure from '../legendre_oprf.js';
import { define } from '../engines/select.js';

var legendre_oprf_ops = define('legendre_oprf.legendre_oprf', { sync: pure.legendre_oprf });

export var legendre_oprf = legendre_oprf_ops.async;
export var legendre_oprf_sync = legendre_oprf_ops.sync;
