/**
 * pedersen, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../pedersen.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../pedersen.js.
 */

import * as pure from '../pedersen.js';
import { define } from '../engines/select.js';

var add_ops = define('pedersen.add', { sync: pure.add });
var commit_ops = define('pedersen.commit', { sync: pure.commit });
var commit_bytes_ops = define('pedersen.commit_bytes', { sync: pure.commit_bytes });
var generators_ops = define('pedersen.generators', { sync: pure.generators });
var prove_equal_ops = define('pedersen.prove_equal', { sync: pure.prove_equal, text: [6] });
var random_blinding_ops = define('pedersen.random_blinding', { sync: pure.random_blinding });
var scale_ops = define('pedersen.scale', { sync: pure.scale });
var sub_ops = define('pedersen.sub', { sync: pure.sub });
var sum_ops = define('pedersen.sum', { sync: pure.sum });
var verify_ops = define('pedersen.verify', { sync: pure.verify });
var verify_balance_ops = define('pedersen.verify_balance', { sync: pure.verify_balance });
var verify_equal_ops = define('pedersen.verify_equal', { sync: pure.verify_equal, text: [4] });

export var GROUPS = pure.GROUPS;
export var add = add_ops.async;
export var add_sync = add_ops.sync;
export var commit = commit_ops.async;
export var commit_sync = commit_ops.sync;
export var commit_bytes = commit_bytes_ops.async;
export var commit_bytes_sync = commit_bytes_ops.sync;
export var generators = generators_ops.async;
export var generators_sync = generators_ops.sync;
export var prove_equal = prove_equal_ops.async;
export var prove_equal_sync = prove_equal_ops.sync;
export var random_blinding = random_blinding_ops.async;
export var random_blinding_sync = random_blinding_ops.sync;
export var scale = scale_ops.async;
export var scale_sync = scale_ops.sync;
export var sub = sub_ops.async;
export var sub_sync = sub_ops.sync;
export var sum = sum_ops.async;
export var sum_sync = sum_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
export var verify_balance = verify_balance_ops.async;
export var verify_balance_sync = verify_balance_ops.sync;
export var verify_equal = verify_equal_ops.async;
export var verify_equal_sync = verify_equal_ops.sync;
