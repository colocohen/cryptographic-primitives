/**
 * paillier_dec, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier_dec.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier_dec.js.
 */

import * as pure from '../paillier_dec.js';
import { define } from '../engines/select.js';

var decode_dec_ops = define('paillier_dec.decode_dec', { sync: pure.decode_dec });
var encode_dec_ops = define('paillier_dec.encode_dec', { sync: pure.encode_dec });
var prove_dec_ops = define('paillier_dec.prove_dec', { sync: pure.prove_dec, text: [6], bytes: { 1: 'pk' } });
var verify_dec_ops = define('paillier_dec.verify_dec', { sync: pure.verify_dec, text: [5], bytes: { 1: 'pk' } });

export var decode_dec = decode_dec_ops.async;
export var decode_dec_sync = decode_dec_ops.sync;
export var encode_dec = encode_dec_ops.async;
export var encode_dec_sync = encode_dec_ops.sync;
export var prove_dec = prove_dec_ops.async;
export var prove_dec_sync = prove_dec_ops.sync;
export var verify_dec = verify_dec_ops.async;
export var verify_dec_sync = verify_dec_ops.sync;
