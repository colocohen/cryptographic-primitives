/**
 * paillier_mul, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier_mul.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier_mul.js.
 */

import * as pure from '../paillier_mul.js';
import { define } from '../engines/select.js';

var decode_mul_ops = define('paillier_mul.decode_mul', { sync: pure.decode_mul });
var encode_mul_ops = define('paillier_mul.encode_mul', { sync: pure.encode_mul });
var prove_mul_ops = define('paillier_mul.prove_mul', { sync: pure.prove_mul, text: [5], bytes: { 0: 'pk' } });
var verify_mul_ops = define('paillier_mul.verify_mul', { sync: pure.verify_mul, text: [4], bytes: { 0: 'pk' } });

export var decode_mul = decode_mul_ops.async;
export var decode_mul_sync = decode_mul_ops.sync;
export var encode_mul = encode_mul_ops.async;
export var encode_mul_sync = encode_mul_ops.sync;
export var prove_mul = prove_mul_ops.async;
export var prove_mul_sync = prove_mul_ops.sync;
export var verify_mul = verify_mul_ops.async;
export var verify_mul_sync = verify_mul_ops.sync;
