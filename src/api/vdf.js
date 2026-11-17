/**
 * vdf, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../vdf.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../vdf.js.
 */

import * as pure from '../vdf.js';
import { define } from '../engines/select.js';

var eval_raw_ops = define('vdf.eval_raw', { sync: pure.eval_raw });
var eval_with_trapdoor_ops = define('vdf.eval_with_trapdoor', { sync: pure.eval_with_trapdoor });
var evaluate_ops = define('vdf.evaluate', { sync: pure.evaluate });
var hash_to_group_ops = define('vdf.hash_to_group', { sync: pure.hash_to_group, text: [0] });
var hash_to_prime_ops = define('vdf.hash_to_prime', { sync: pure.hash_to_prime });
var setup_unsafe_ops = define('vdf.setup_unsafe', { sync: pure.setup_unsafe });
var verify_ops = define('vdf.verify', { sync: pure.verify });

export var RSA_2048 = pure.RSA_2048;
export var eval_raw = eval_raw_ops.async;
export var eval_raw_sync = eval_raw_ops.sync;
export var eval_with_trapdoor = eval_with_trapdoor_ops.async;
export var eval_with_trapdoor_sync = eval_with_trapdoor_ops.sync;
export var evaluate = evaluate_ops.async;
export var evaluate_sync = evaluate_ops.sync;
export var hash_to_group = hash_to_group_ops.async;
export var hash_to_group_sync = hash_to_group_ops.sync;
export var hash_to_prime = hash_to_prime_ops.async;
export var hash_to_prime_sync = hash_to_prime_ops.sync;
export var setup_unsafe = setup_unsafe_ops.async;
export var setup_unsafe_sync = setup_unsafe_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
