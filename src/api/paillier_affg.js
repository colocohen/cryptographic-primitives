/**
 * paillier_affg, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier_affg.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier_affg.js.
 */

import * as pure from '../paillier_affg.js';
import { define } from '../engines/select.js';

var decode_affg_ops = define('paillier_affg.decode_affg', { sync: pure.decode_affg });
var encode_affg_ops = define('paillier_affg.encode_affg', { sync: pure.encode_affg });
var prove_affg_ops = define('paillier_affg.prove_affg', { sync: pure.prove_affg, text: [14] });
var verify_affg_ops = define('paillier_affg.verify_affg', { sync: pure.verify_affg, text: [10] });

export var decode_affg = decode_affg_ops.async;
export var decode_affg_sync = decode_affg_ops.sync;
export var encode_affg = encode_affg_ops.async;
export var encode_affg_sync = encode_affg_ops.sync;
export var prove_affg = prove_affg_ops.async;
export var prove_affg_sync = prove_affg_ops.sync;
export var verify_affg = verify_affg_ops.async;
export var verify_affg_sync = verify_affg_ops.sync;
