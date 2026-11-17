/**
 * paillier_range_exact, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier_range_exact.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier_range_exact.js.
 */

import * as pure from '../paillier_range_exact.js';
import { define } from '../engines/select.js';

var decode_range_exact_ops = define('paillier_range_exact.decode_range_exact', { sync: pure.decode_range_exact });
var encode_range_exact_ops = define('paillier_range_exact.encode_range_exact', { sync: pure.encode_range_exact });
var prove_range_exact_ops = define('paillier_range_exact.prove_range_exact', { sync: pure.prove_range_exact, text: [9], bytes: { 0: 'pk' } });
var range_squares_ops = define('paillier_range_exact.range_squares', { sync: pure.range_squares });
var verify_range_exact_ops = define('paillier_range_exact.verify_range_exact', { sync: pure.verify_range_exact, text: [7], bytes: { 0: 'pk' } });

export var decode_range_exact = decode_range_exact_ops.async;
export var decode_range_exact_sync = decode_range_exact_ops.sync;
export var encode_range_exact = encode_range_exact_ops.async;
export var encode_range_exact_sync = encode_range_exact_ops.sync;
export var prove_range_exact = prove_range_exact_ops.async;
export var prove_range_exact_sync = prove_range_exact_ops.sync;
export var range_squares = range_squares_ops.async;
export var range_squares_sync = range_squares_ops.sync;
export var verify_range_exact = verify_range_exact_ops.async;
export var verify_range_exact_sync = verify_range_exact_ops.sync;
