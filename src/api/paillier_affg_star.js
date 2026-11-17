/**
 * paillier_affg_star, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier_affg_star.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier_affg_star.js.
 */

import * as pure from '../paillier_affg_star.js';
import { define } from '../engines/select.js';

var decode_affg_star_ops = define('paillier_affg_star.decode_affg_star', { sync: pure.decode_affg_star });
var encode_affg_star_ops = define('paillier_affg_star.encode_affg_star', { sync: pure.encode_affg_star });
var prove_affg_star_ops = define('paillier_affg_star.prove_affg_star', { sync: pure.prove_affg_star, text: [7] });
var verify_affg_star_ops = define('paillier_affg_star.verify_affg_star', { sync: pure.verify_affg_star, text: [6] });

export var decode_affg_star = decode_affg_star_ops.async;
export var decode_affg_star_sync = decode_affg_star_ops.sync;
export var encode_affg_star = encode_affg_star_ops.async;
export var encode_affg_star_sync = encode_affg_star_ops.sync;
export var prove_affg_star = prove_affg_star_ops.async;
export var prove_affg_star_sync = prove_affg_star_ops.sync;
export var verify_affg_star = verify_affg_star_ops.async;
export var verify_affg_star_sync = verify_affg_star_ops.sync;
