/**
 * ristretto255, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ristretto255.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ristretto255.js.
 */

import * as pure from '../ristretto255.js';
import { define } from '../engines/select.js';

var add_ops = define('ristretto255.add', { sync: pure.add });
var base_mul_ops = define('ristretto255.base_mul', { sync: pure.base_mul });
var decode_ops = define('ristretto255.decode', { sync: pure.decode });
var double_mul_vartime_ops = define('ristretto255.double_mul_vartime', { sync: pure.double_mul_vartime });
var encode_ops = define('ristretto255.encode', { sync: pure.encode, text: [0] });
var equals_ops = define('ristretto255.equals', { sync: pure.equals });
var from_uniform_bytes_ops = define('ristretto255.from_uniform_bytes', { sync: pure.from_uniform_bytes });
var hash_to_group_ops = define('ristretto255.hash_to_group', { sync: pure.hash_to_group, text: [0, 1] });
var mul_ops = define('ristretto255.mul', { sync: pure.mul });
var mul_vartime_ops = define('ristretto255.mul_vartime', { sync: pure.mul_vartime });
var neg_ops = define('ristretto255.neg', { sync: pure.neg });
var scalar_add_ops = define('ristretto255.scalar_add', { sync: pure.scalar_add });
var scalar_bytes_ops = define('ristretto255.scalar_bytes', { sync: pure.scalar_bytes });
var scalar_from_canonical_bytes_ops = define('ristretto255.scalar_from_canonical_bytes', { sync: pure.scalar_from_canonical_bytes });
var scalar_from_uniform_bytes_ops = define('ristretto255.scalar_from_uniform_bytes', { sync: pure.scalar_from_uniform_bytes });
var scalar_inv_ops = define('ristretto255.scalar_inv', { sync: pure.scalar_inv });
var scalar_inv_batch_ops = define('ristretto255.scalar_inv_batch', { sync: pure.scalar_inv_batch });
var scalar_mod_ops = define('ristretto255.scalar_mod', { sync: pure.scalar_mod });
var scalar_mul_ops = define('ristretto255.scalar_mul', { sync: pure.scalar_mul });
var scalar_pow_ops = define('ristretto255.scalar_pow', { sync: pure.scalar_pow });
var scalar_sub_ops = define('ristretto255.scalar_sub', { sync: pure.scalar_sub });
var sub_ops = define('ristretto255.sub', { sync: pure.sub });
var keygen_ops = define('ristretto255.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });

export var BASE = pure.BASE;
export var GROUP = pure.GROUP;
export var IDENTITY = pure.IDENTITY;
export var ORDER = pure.ORDER;
export var add = add_ops.async;
export var add_sync = add_ops.sync;
export var base_mul = base_mul_ops.async;
export var base_mul_sync = base_mul_ops.sync;
export var decode = decode_ops.async;
export var decode_sync = decode_ops.sync;
export var double_mul_vartime = double_mul_vartime_ops.async;
export var double_mul_vartime_sync = double_mul_vartime_ops.sync;
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
export var scalar_add = scalar_add_ops.async;
export var scalar_add_sync = scalar_add_ops.sync;
export var scalar_bytes = scalar_bytes_ops.async;
export var scalar_bytes_sync = scalar_bytes_ops.sync;
export var scalar_from_canonical_bytes = scalar_from_canonical_bytes_ops.async;
export var scalar_from_canonical_bytes_sync = scalar_from_canonical_bytes_ops.sync;
export var scalar_from_uniform_bytes = scalar_from_uniform_bytes_ops.async;
export var scalar_from_uniform_bytes_sync = scalar_from_uniform_bytes_ops.sync;
export var scalar_inv = scalar_inv_ops.async;
export var scalar_inv_sync = scalar_inv_ops.sync;
export var scalar_inv_batch = scalar_inv_batch_ops.async;
export var scalar_inv_batch_sync = scalar_inv_batch_ops.sync;
export var scalar_mod = scalar_mod_ops.async;
export var scalar_mod_sync = scalar_mod_ops.sync;
export var scalar_mul = scalar_mul_ops.async;
export var scalar_mul_sync = scalar_mul_ops.sync;
export var scalar_pow = scalar_pow_ops.async;
export var scalar_pow_sync = scalar_pow_ops.sync;
export var scalar_sub = scalar_sub_ops.async;
export var scalar_sub_sync = scalar_sub_ops.sync;
export var sub = sub_ops.async;
export var sub_sync = sub_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
