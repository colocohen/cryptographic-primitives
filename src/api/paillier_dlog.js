/**
 * paillier_dlog, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier_dlog.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier_dlog.js.
 */

import * as pure from '../paillier_dlog.js';
import { define } from '../engines/select.js';

var decode_dlog_ops = define('paillier_dlog.decode_dlog', { sync: pure.decode_dlog });
var encode_dlog_ops = define('paillier_dlog.encode_dlog', { sync: pure.encode_dlog });
var prove_dlog_ops = define('paillier_dlog.prove_dlog', { sync: pure.prove_dlog, text: [9], bytes: { 0: 'pk' } });
var verify_dlog_ops = define('paillier_dlog.verify_dlog', { sync: pure.verify_dlog, text: [7], bytes: { 0: 'pk' } });

export var decode_dlog = decode_dlog_ops.async;
export var decode_dlog_sync = decode_dlog_ops.sync;
export var encode_dlog = encode_dlog_ops.async;
export var encode_dlog_sync = encode_dlog_ops.sync;
export var prove_dlog = prove_dlog_ops.async;
export var prove_dlog_sync = prove_dlog_ops.sync;
export var verify_dlog = verify_dlog_ops.async;
export var verify_dlog_sync = verify_dlog_ops.sync;
