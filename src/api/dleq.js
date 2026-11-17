/**
 * dleq, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../dleq.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../dleq.js.
 */

import * as pure from '../dleq.js';
import { define } from '../engines/select.js';

var decode_ops = define('dleq.decode', { sync: pure.decode });
var encode_ops = define('dleq.encode', { sync: pure.encode });
var prove_ops = define('dleq.prove', { sync: pure.prove, text: [5] });
var prove_with_generator_ops = define('dleq.prove_with_generator', { sync: pure.prove_with_generator, text: [4] });
var verify_ops = define('dleq.verify', { sync: pure.verify, text: [6] });
var verify_with_generator_ops = define('dleq.verify_with_generator', { sync: pure.verify_with_generator, text: [5] });

export var decode = decode_ops.async;
export var decode_sync = decode_ops.sync;
export var encode = encode_ops.async;
export var encode_sync = encode_ops.sync;
export var prove = prove_ops.async;
export var prove_sync = prove_ops.sync;
export var prove_with_generator = prove_with_generator_ops.async;
export var prove_with_generator_sync = prove_with_generator_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
export var verify_with_generator = verify_with_generator_ops.async;
export var verify_with_generator_sync = verify_with_generator_ops.sync;
