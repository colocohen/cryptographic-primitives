/**
 * lb_vrf, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../lb_vrf.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../lb_vrf.js.
 */

import * as pure from '../lb_vrf.js';
import { define } from '../engines/select.js';

var evaluate_ops = define('lb_vrf.evaluate', { sync: pure.evaluate, bytes: { 1: 'sk', 3: 'rnd' } });
var keygen_ops = define('lb_vrf.keygen', { sync: pure.keygen, bytes: { 1: 'seed' } });
var params_ops = define('lb_vrf.params', { sync: pure.params, bytes: { 0: 'seed' } });
var verify_ops = define('lb_vrf.verify', { sync: pure.verify, bytes: { 1: 'pk' } });

export var SIZES = pure.SIZES;
export var evaluate = evaluate_ops.async;
export var evaluate_sync = evaluate_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var params = params_ops.async;
export var params_sync = params_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
