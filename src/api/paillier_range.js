/**
 * paillier_range, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier_range.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier_range.js.
 */

import * as pure from '../paillier_range.js';
import { define } from '../engines/select.js';

var decode_ops = define('paillier_range.decode', { sync: pure.decode });
var encode_ops = define('paillier_range.encode', { sync: pure.encode, bytes: { 1: 'pk' } });
var prove_ops = define('paillier_range.prove', { sync: pure.prove, bytes: { 0: 'pk' } });
var verify_ops = define('paillier_range.verify', { sync: pure.verify, bytes: { 0: 'pk' } });

export var ELL = pure.ELL;
export var EPS = pure.EPS;
export var decode = decode_ops.async;
export var decode_sync = decode_ops.sync;
export var encode = encode_ops.async;
export var encode_sync = encode_ops.sync;
export var prove = prove_ops.async;
export var prove_sync = prove_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
