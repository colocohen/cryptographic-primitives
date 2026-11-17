/**
 * poseidon, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../poseidon.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../poseidon.js.
 */

import * as pure from '../poseidon.js';
import { define } from '../engines/select.js';

var poseidon_ops = define('poseidon.poseidon', { sync: pure.poseidon });
var poseidon_bytes_ops = define('poseidon.poseidon_bytes', { sync: pure.poseidon_bytes });
var poseidon_with_state_ops = define('poseidon.poseidon_with_state', { sync: pure.poseidon_with_state });

export var P = pure.P;
export var poseidon = poseidon_ops.async;
export var poseidon_sync = poseidon_ops.sync;
export var poseidon_bytes = poseidon_bytes_ops.async;
export var poseidon_bytes_sync = poseidon_bytes_ops.sync;
export var poseidon_with_state = poseidon_with_state_ops.async;
export var poseidon_with_state_sync = poseidon_with_state_ops.sync;
