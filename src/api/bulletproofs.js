/**
 * bulletproofs, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../bulletproofs.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../bulletproofs.js.
 */

import * as pure from '../bulletproofs.js';
import { define } from '../engines/select.js';

var blinding_generator_ops = define('bulletproofs.blinding_generator', { sync: pure.blinding_generator });
var proof_size_ops = define('bulletproofs.proof_size', { sync: pure.proof_size });
var prove_range_ops = define('bulletproofs.prove_range', { sync: pure.prove_range, task: pure.prove_range_task });
var verify_range_ops = define('bulletproofs.verify_range', { sync: pure.verify_range });

export var blinding_generator = blinding_generator_ops.async;
export var blinding_generator_sync = blinding_generator_ops.sync;
export var proof_size = proof_size_ops.async;
export var proof_size_sync = proof_size_ops.sync;
export var prove_range = prove_range_ops.async;
export var prove_range_sync = prove_range_ops.sync;
export var verify_range = verify_range_ops.async;
export var verify_range_sync = verify_range_ops.sync;
