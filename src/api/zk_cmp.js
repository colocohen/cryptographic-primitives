/**
 * zk_cmp, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../zk_cmp.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../zk_cmp.js.
 */

import * as pure from '../zk_cmp.js';
import { define } from '../engines/select.js';

var decode_fac_ops = define('zk_cmp.decode_fac', { sync: pure.decode_fac });
var decode_sch_ops = define('zk_cmp.decode_sch', { sync: pure.decode_sch });
var encode_fac_ops = define('zk_cmp.encode_fac', { sync: pure.encode_fac });
var encode_sch_ops = define('zk_cmp.encode_sch', { sync: pure.encode_sch });
var prove_fac_ops = define('zk_cmp.prove_fac', { sync: pure.prove_fac, text: [6] });
var prove_sch_ops = define('zk_cmp.prove_sch', { sync: pure.prove_sch, text: [4] });
var verify_fac_ops = define('zk_cmp.verify_fac', { sync: pure.verify_fac, text: [4] });
var verify_sch_ops = define('zk_cmp.verify_sch', { sync: pure.verify_sch, text: [3] });

export var decode_fac = decode_fac_ops.async;
export var decode_fac_sync = decode_fac_ops.sync;
export var decode_sch = decode_sch_ops.async;
export var decode_sch_sync = decode_sch_ops.sync;
export var encode_fac = encode_fac_ops.async;
export var encode_fac_sync = encode_fac_ops.sync;
export var encode_sch = encode_sch_ops.async;
export var encode_sch_sync = encode_sch_ops.sync;
export var prove_fac = prove_fac_ops.async;
export var prove_fac_sync = prove_fac_ops.sync;
export var prove_sch = prove_sch_ops.async;
export var prove_sch_sync = prove_sch_ops.sync;
export var verify_fac = verify_fac_ops.async;
export var verify_fac_sync = verify_fac_ops.sync;
export var verify_sch = verify_sch_ops.async;
export var verify_sch_sync = verify_sch_ops.sync;
