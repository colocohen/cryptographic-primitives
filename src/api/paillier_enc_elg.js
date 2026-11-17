/**
 * paillier_enc_elg, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier_enc_elg.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier_enc_elg.js.
 */

import * as pure from '../paillier_enc_elg.js';
import { define } from '../engines/select.js';

var decode_enc_elg_ops = define('paillier_enc_elg.decode_enc_elg', { sync: pure.decode_enc_elg });
var encode_enc_elg_ops = define('paillier_enc_elg.encode_enc_elg', { sync: pure.encode_enc_elg });
var prove_enc_elg_ops = define('paillier_enc_elg.prove_enc_elg', { sync: pure.prove_enc_elg, text: [7], bytes: { 1: 'pk' } });
var verify_enc_elg_ops = define('paillier_enc_elg.verify_enc_elg', { sync: pure.verify_enc_elg, text: [6], bytes: { 1: 'pk' } });

export var decode_enc_elg = decode_enc_elg_ops.async;
export var decode_enc_elg_sync = decode_enc_elg_ops.sync;
export var encode_enc_elg = encode_enc_elg_ops.async;
export var encode_enc_elg_sync = encode_enc_elg_ops.sync;
export var prove_enc_elg = prove_enc_elg_ops.async;
export var prove_enc_elg_sync = prove_enc_elg_ops.sync;
export var verify_enc_elg = verify_enc_elg_ops.async;
export var verify_enc_elg_sync = verify_enc_elg_ops.sync;
