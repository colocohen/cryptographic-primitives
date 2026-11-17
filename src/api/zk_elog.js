/**
 * zk_elog, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../zk_elog.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../zk_elog.js.
 */

import * as pure from '../zk_elog.js';
import { define } from '../engines/select.js';

var decode_elog_ops = define('zk_elog.decode_elog', { sync: pure.decode_elog });
var encode_elog_ops = define('zk_elog.encode_elog', { sync: pure.encode_elog });
var prove_elog_ops = define('zk_elog.prove_elog', { sync: pure.prove_elog, text: [4] });
var verify_elog_ops = define('zk_elog.verify_elog', { sync: pure.verify_elog, text: [3] });

export var decode_elog = decode_elog_ops.async;
export var decode_elog_sync = decode_elog_ops.sync;
export var encode_elog = encode_elog_ops.async;
export var encode_elog_sync = encode_elog_ops.sync;
export var prove_elog = prove_elog_ops.async;
export var prove_elog_sync = prove_elog_ops.sync;
export var verify_elog = verify_elog_ops.async;
export var verify_elog_sync = verify_elog_ops.sync;
