/**
 * babyjubjub, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../babyjubjub.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../babyjubjub.js.
 */

import * as pure from '../babyjubjub.js';
import { define } from '../engines/select.js';

var add_ops = define('babyjubjub.add', { sync: pure.add });
var base_mul_ops = define('babyjubjub.base_mul', { sync: pure.base_mul });
var decode_ops = define('babyjubjub.decode', { sync: pure.decode });
var encode_ops = define('babyjubjub.encode', { sync: pure.encode });
var eq_ops = define('babyjubjub.eq', { sync: pure.eq });
var in_subgroup_ops = define('babyjubjub.in_subgroup', { sync: pure.in_subgroup });
var is_on_curve_ops = define('babyjubjub.is_on_curve', { sync: pure.is_on_curve });
var mul_ops = define('babyjubjub.mul', { sync: pure.mul });
var neg_ops = define('babyjubjub.neg', { sync: pure.neg });
var sub_ops = define('babyjubjub.sub', { sync: pure.sub });
var keygen_ops = define('babyjubjub.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });

export var BASE8 = pure.BASE8;
export var CURVE = pure.CURVE;
export var FIELD = pure.FIELD;
export var GENERATOR = pure.GENERATOR;
export var IDENTITY = pure.IDENTITY;
export var POINT = pure.POINT;
export var add = add_ops.async;
export var add_sync = add_ops.sync;
export var base_mul = base_mul_ops.async;
export var base_mul_sync = base_mul_ops.sync;
export var decode = decode_ops.async;
export var decode_sync = decode_ops.sync;
export var encode = encode_ops.async;
export var encode_sync = encode_ops.sync;
export var eq = eq_ops.async;
export var eq_sync = eq_ops.sync;
export var in_subgroup = in_subgroup_ops.async;
export var in_subgroup_sync = in_subgroup_ops.sync;
export var is_on_curve = is_on_curve_ops.async;
export var is_on_curve_sync = is_on_curve_ops.sync;
export var mul = mul_ops.async;
export var mul_sync = mul_ops.sync;
export var neg = neg_ops.async;
export var neg_sync = neg_ops.sync;
export var sub = sub_ops.async;
export var sub_sync = sub_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
