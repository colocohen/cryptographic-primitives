/**
 * paillier_zero, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier_zero.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier_zero.js.
 */

import * as pure from '../paillier_zero.js';
import { define } from '../engines/select.js';

var decode_zero_ops = define('paillier_zero.decode_zero', { sync: pure.decode_zero });
var encode_zero_ops = define('paillier_zero.encode_zero', { sync: pure.encode_zero });
var prove_zero_ops = define('paillier_zero.prove_zero', { sync: pure.prove_zero, text: [5], bytes: { 0: 'pk' } });
var verify_zero_ops = define('paillier_zero.verify_zero', { sync: pure.verify_zero, text: [4], bytes: { 0: 'pk' } });

export var decode_zero = decode_zero_ops.async;
export var decode_zero_sync = decode_zero_ops.sync;
export var encode_zero = encode_zero_ops.async;
export var encode_zero_sync = encode_zero_ops.sync;
export var prove_zero = prove_zero_ops.async;
export var prove_zero_sync = prove_zero_ops.sync;
export var verify_zero = verify_zero_ops.async;
export var verify_zero_sync = verify_zero_ops.sync;
