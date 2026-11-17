/**
 * vector_commit, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../vector_commit.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../vector_commit.js.
 */

import * as pure from '../vector_commit.js';
import { define } from '../engines/select.js';

var commit_ops = define('vector_commit.commit', { sync: pure.commit });
var open_ops = define('vector_commit.open', { sync: pure.open });
var position_prime_ops = define('vector_commit.position_prime', { sync: pure.position_prime });
var setup_unsafe_ops = define('vector_commit.setup_unsafe', { sync: pure.setup_unsafe });
var to_bytes_ops = define('vector_commit.to_bytes', { sync: pure.to_bytes });
var update_ops = define('vector_commit.update', { sync: pure.update });
var update_witness_ops = define('vector_commit.update_witness', { sync: pure.update_witness });
var verify_ops = define('vector_commit.verify', { sync: pure.verify });

export var VALUE_BITS = pure.VALUE_BITS;
export var commit = commit_ops.async;
export var commit_sync = commit_ops.sync;
export var open = open_ops.async;
export var open_sync = open_ops.sync;
export var position_prime = position_prime_ops.async;
export var position_prime_sync = position_prime_ops.sync;
export var setup_unsafe = setup_unsafe_ops.async;
export var setup_unsafe_sync = setup_unsafe_ops.sync;
export var to_bytes = to_bytes_ops.async;
export var to_bytes_sync = to_bytes_ops.sync;
export var update = update_ops.async;
export var update_sync = update_ops.sync;
export var update_witness = update_witness_ops.async;
export var update_witness_sync = update_witness_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
