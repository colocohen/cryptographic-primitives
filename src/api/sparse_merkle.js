/**
 * sparse_merkle, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../sparse_merkle.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../sparse_merkle.js.
 */

import * as pure from '../sparse_merkle.js';
import { define } from '../engines/select.js';

var sparse_merkle_ops = define('sparse_merkle.sparse_merkle', { sync: pure.sparse_merkle });
var verify_sparse_ops = define('sparse_merkle.verify_sparse', { sync: pure.verify_sparse });

export var sparse_merkle = sparse_merkle_ops.async;
export var sparse_merkle_sync = sparse_merkle_ops.sync;
export var verify_sparse = verify_sparse_ops.async;
export var verify_sparse_sync = verify_sparse_ops.sync;
