/**
 * decaf448, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../decaf448.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../decaf448.js.
 */

import * as pure from '../decaf448.js';
import { define } from '../engines/select.js';

var add_ops = define('decaf448.add', { sync: pure.add });
var base_mul_ops = define('decaf448.base_mul', { sync: pure.base_mul });
var decode_ops = define('decaf448.decode', { sync: pure.decode });
var encode_ops = define('decaf448.encode', { sync: pure.encode, text: [0] });
var equals_ops = define('decaf448.equals', { sync: pure.equals });
var from_uniform_bytes_ops = define('decaf448.from_uniform_bytes', { sync: pure.from_uniform_bytes });
var hash_to_group_ops = define('decaf448.hash_to_group', { sync: pure.hash_to_group, text: [0, 1] });
var mul_ops = define('decaf448.mul', { sync: pure.mul });
var mul_vartime_ops = define('decaf448.mul_vartime', { sync: pure.mul_vartime });
var neg_ops = define('decaf448.neg', { sync: pure.neg });
var scalar_bytes_ops = define('decaf448.scalar_bytes', { sync: pure.scalar_bytes });
var scalar_from_canonical_bytes_ops = define('decaf448.scalar_from_canonical_bytes', { sync: pure.scalar_from_canonical_bytes });
var sub_ops = define('decaf448.sub', { sync: pure.sub });
var keygen_ops = define('decaf448.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });

export var BASE = pure.BASE;
export var CONSTANTS = pure.CONSTANTS;
export var GROUP = pure.GROUP;
export var IDENTITY = pure.IDENTITY;
export var ORDER = pure.ORDER;
export var add = add_ops.async;
export var add_sync = add_ops.sync;
export var base_mul = base_mul_ops.async;
export var base_mul_sync = base_mul_ops.sync;
export var decode = decode_ops.async;
export var decode_sync = decode_ops.sync;
export var encode = encode_ops.async;
export var encode_sync = encode_ops.sync;
export var equals = equals_ops.async;
export var equals_sync = equals_ops.sync;
export var from_uniform_bytes = from_uniform_bytes_ops.async;
export var from_uniform_bytes_sync = from_uniform_bytes_ops.sync;
export var hash_to_group = hash_to_group_ops.async;
export var hash_to_group_sync = hash_to_group_ops.sync;
export var mul = mul_ops.async;
export var mul_sync = mul_ops.sync;
export var mul_vartime = mul_vartime_ops.async;
export var mul_vartime_sync = mul_vartime_ops.sync;
export var neg = neg_ops.async;
export var neg_sync = neg_ops.sync;
export var scalar_bytes = scalar_bytes_ops.async;
export var scalar_bytes_sync = scalar_bytes_ops.sync;
export var scalar_from_canonical_bytes = scalar_from_canonical_bytes_ops.async;
export var scalar_from_canonical_bytes_sync = scalar_from_canonical_bytes_ops.sync;
export var sub = sub_ops.async;
export var sub_sync = sub_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
