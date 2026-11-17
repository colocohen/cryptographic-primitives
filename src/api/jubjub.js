/**
 * jubjub, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../jubjub.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../jubjub.js.
 */

import * as pure from '../jubjub.js';
import { define } from '../engines/select.js';

var base_mul_ops = define('jubjub.base_mul', { sync: pure.base_mul });
var decode_ops = define('jubjub.decode', { sync: pure.decode });
var encode_ops = define('jubjub.encode', { sync: pure.encode });
var in_subgroup_ops = define('jubjub.in_subgroup', { sync: pure.in_subgroup });
var is_small_order_ops = define('jubjub.is_small_order', { sync: pure.is_small_order });
var mul_ops = define('jubjub.mul', { sync: pure.mul });
var keygen_ops = define('jubjub.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });

export var CURVE = pure.CURVE;
export var FIELD = pure.FIELD;
export var GENERATOR = pure.GENERATOR;
export var GROUP = pure.GROUP;
export var IDENTITY = pure.IDENTITY;
export var POINT = pure.POINT;
export var base_mul = base_mul_ops.async;
export var base_mul_sync = base_mul_ops.sync;
export var decode = decode_ops.async;
export var decode_sync = decode_ops.sync;
export var encode = encode_ops.async;
export var encode_sync = encode_ops.sync;
export var in_subgroup = in_subgroup_ops.async;
export var in_subgroup_sync = in_subgroup_ops.sync;
export var is_small_order = is_small_order_ops.async;
export var is_small_order_sync = is_small_order_ops.sync;
export var mul = mul_ops.async;
export var mul_sync = mul_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
