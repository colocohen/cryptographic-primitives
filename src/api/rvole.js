/**
 * rvole, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../rvole.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../rvole.js.
 */

import * as pure from '../rvole.js';
import { define } from '../engines/select.js';

var alice_multiply_ops = define('rvole.alice_multiply', { sync: pure.alice_multiply, text: [5] });
var bob_sample_ops = define('rvole.bob_sample', { sync: pure.bob_sample, text: [3] });
var bob_share_ops = define('rvole.bob_share', { sync: pure.bob_share, text: [1] });
var params_ops = define('rvole.params', { sync: pure.params });

export var LAMBDA_S = pure.LAMBDA_S;
export var alice_multiply = alice_multiply_ops.async;
export var alice_multiply_sync = alice_multiply_ops.sync;
export var bob_sample = bob_sample_ops.async;
export var bob_sample_sync = bob_sample_ops.sync;
export var bob_share = bob_share_ops.async;
export var bob_share_sync = bob_share_ops.sync;
export var params = params_ops.async;
export var params_sync = params_ops.sync;
