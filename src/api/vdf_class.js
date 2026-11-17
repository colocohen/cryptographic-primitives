/**
 * vdf_class, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../vdf_class.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../vdf_class.js.
 */

import * as pure from '../vdf_class.js';
import { define } from '../engines/select.js';

var challenge_ops = define('vdf_class.challenge', { sync: pure.challenge });
var evaluate_ops = define('vdf_class.evaluate', { sync: pure.evaluate });
var verify_ops = define('vdf_class.verify', { sync: pure.verify });

export var PRIME_BITS = pure.PRIME_BITS;
export var challenge = challenge_ops.async;
export var challenge_sync = challenge_ops.sync;
export var evaluate = evaluate_ops.async;
export var evaluate_sync = evaluate_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
