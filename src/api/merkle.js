/**
 * merkle, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../merkle.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../merkle.js.
 */

import * as pure from '../merkle.js';
import { define } from '../engines/select.js';

var build_ops = define('merkle.build', { sync: pure.build });
var decode_proof_ops = define('merkle.decode_proof', { sync: pure.decode_proof });
var encode_proof_ops = define('merkle.encode_proof', { sync: pure.encode_proof });
var hash_leaf_ops = define('merkle.hash_leaf', { sync: pure.hash_leaf, text: [1] });
var hash_node_ops = define('merkle.hash_node', { sync: pure.hash_node });
var proof_ops = define('merkle.proof', { sync: pure.proof });
var root_ops = define('merkle.root', { sync: pure.root });
var verify_ops = define('merkle.verify', { sync: pure.verify });

export var build = build_ops.async;
export var build_sync = build_ops.sync;
export var decode_proof = decode_proof_ops.async;
export var decode_proof_sync = decode_proof_ops.sync;
export var encode_proof = encode_proof_ops.async;
export var encode_proof_sync = encode_proof_ops.sync;
export var hash_leaf = hash_leaf_ops.async;
export var hash_leaf_sync = hash_leaf_ops.sync;
export var hash_node = hash_node_ops.async;
export var hash_node_sync = hash_node_ops.sync;
export var proof = proof_ops.async;
export var proof_sync = proof_ops.sync;
export var root = root_ops.async;
export var root_sync = root_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
