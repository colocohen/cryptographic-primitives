/**
 * pqpake, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../pqpake.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../pqpake.js.
 */

import * as pure from '../pqpake.js';
import { define } from '../engines/select.js';

var encode_public_context_ops = define('pqpake.encode_public_context', { sync: pure.encode_public_context, text: [0] });
var ksf_scrypt_ops = define('pqpake.ksf_scrypt', { sync: pure.ksf_scrypt });
var lv_decode_ops = define('pqpake.lv_decode', { sync: pure.lv_decode });
var lv_encode_ops = define('pqpake.lv_encode', { sync: pure.lv_encode });
var ml_bua_skem_ops = define('pqpake.ml_bua_skem', { sync: pure.ml_bua_skem });
var pqpake_ops = define('pqpake.pqpake', { sync: pure.pqpake });

export var CONFIG_IDS = pure.CONFIG_IDS;
export var PC_KEMS = pure.PC_KEMS;
export var encode_public_context = encode_public_context_ops.async;
export var encode_public_context_sync = encode_public_context_ops.sync;
export var ksf_scrypt = ksf_scrypt_ops.async;
export var ksf_scrypt_sync = ksf_scrypt_ops.sync;
export var lv_decode = lv_decode_ops.async;
export var lv_decode_sync = lv_decode_ops.sync;
export var lv_encode = lv_encode_ops.async;
export var lv_encode_sync = lv_encode_ops.sync;
export var ml_bua_skem = ml_bua_skem_ops.async;
export var ml_bua_skem_sync = ml_bua_skem_ops.sync;
export var pqpake = pqpake_ops.async;
export var pqpake_sync = pqpake_ops.sync;
