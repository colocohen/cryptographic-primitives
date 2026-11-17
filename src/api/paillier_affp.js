/**
 * paillier_affp, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier_affp.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier_affp.js.
 */

import * as pure from '../paillier_affp.js';
import { define } from '../engines/select.js';

var decode_affp_ops = define('paillier_affp.decode_affp', { sync: pure.decode_affp });
var encode_affp_ops = define('paillier_affp.encode_affp', { sync: pure.encode_affp });
var prove_affp_ops = define('paillier_affp.prove_affp', { sync: pure.prove_affp, text: [7] });
var verify_affp_ops = define('paillier_affp.verify_affp', { sync: pure.verify_affp, text: [6] });

export var decode_affp = decode_affp_ops.async;
export var decode_affp_sync = decode_affp_ops.sync;
export var encode_affp = encode_affp_ops.async;
export var encode_affp_sync = encode_affp_ops.sync;
export var prove_affp = prove_affp_ops.async;
export var prove_affp_sync = prove_affp_ops.sync;
export var verify_affp = verify_affp_ops.async;
export var verify_affp_sync = verify_affp_ops.sync;
