/**
 * bn254, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../bn254.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../bn254.js.
 */

import * as pure from '../bn254.js';
import { define, scheme } from '../engines/select.js';

var pair_ops = define('bn254.pair', { sync: pure.pair });
var pair_product_ops = define('bn254.pair_product', { sync: pure.pair_product });

export var BASE1 = pure.BASE1;
export var BASE2 = pure.BASE2;
export var CURVE = pure.CURVE;
export var FIELD = pure.FIELD;
export var FIELD12 = pure.FIELD12;
export var FIELD2 = pure.FIELD2;
export var PAIRING = scheme('PAIRING', pure.PAIRING);
export var POINT1 = scheme('POINT1', pure.POINT1);
export var POINT2 = scheme('POINT2', pure.POINT2);
export var pair = pair_ops.async;
export var pair_sync = pair_ops.sync;
export var pair_product = pair_product_ops.async;
export var pair_product_sync = pair_product_ops.sync;
