/**
 * ot_extend, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ot_extend.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ot_extend.js.
 */

import * as pure from '../ot_extend.js';
import { define } from '../engines/select.js';

var challenge_seed_ops = define('ot_extend.challenge_seed', { sync: pure.challenge_seed, text: [0] });
var receiver_extend_ops = define('ot_extend.receiver_extend', { sync: pure.receiver_extend, text: [3] });
var receiver_key_ops = define('ot_extend.receiver_key', { sync: pure.receiver_key });
var sender_extend_ops = define('ot_extend.sender_extend', { sync: pure.sender_extend, text: [4] });
var sender_keys_ops = define('ot_extend.sender_keys', { sync: pure.sender_keys });

export var KAPPA = pure.KAPPA;
export var S = pure.S;
export var challenge_seed = challenge_seed_ops.async;
export var challenge_seed_sync = challenge_seed_ops.sync;
export var receiver_extend = receiver_extend_ops.async;
export var receiver_extend_sync = receiver_extend_ops.sync;
export var receiver_key = receiver_key_ops.async;
export var receiver_key_sync = receiver_key_ops.sync;
export var sender_extend = sender_extend_ops.async;
export var sender_extend_sync = sender_extend_ops.sync;
export var sender_keys = sender_keys_ops.async;
export var sender_keys_sync = sender_keys_ops.sync;
