/**
 * adaptor, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../adaptor.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../adaptor.js.
 */

import * as pure from '../adaptor.js';
import { define } from '../engines/select.js';

var dleq_challenge_ops = define('adaptor.dleq_challenge', { sync: pure.dleq_challenge });
var dleq_prove_ops = define('adaptor.dleq_prove', { sync: pure.dleq_prove });
var dleq_share_ok_ops = define('adaptor.dleq_share_ok', { sync: pure.dleq_share_ok });
var dleq_verify_ops = define('adaptor.dleq_verify', { sync: pure.dleq_verify });
var ecdsa_complete_ops = define('adaptor.ecdsa_complete', { sync: pure.ecdsa_complete });
var ecdsa_decode_ops = define('adaptor.ecdsa_decode', { sync: pure.ecdsa_decode });
var ecdsa_encode_ops = define('adaptor.ecdsa_encode', { sync: pure.ecdsa_encode });
var ecdsa_extract_ops = define('adaptor.ecdsa_extract', { sync: pure.ecdsa_extract, bytes: { 2: 'sig' } });
var ecdsa_message_scalar_ops = define('adaptor.ecdsa_message_scalar', { sync: pure.ecdsa_message_scalar, text: [1] });
var ecdsa_pre_sign_ops = define('adaptor.ecdsa_pre_sign', { sync: pure.ecdsa_pre_sign, bytes: { 1: 'msg32', 4: 'aux' } });
var ecdsa_sizes_ops = define('adaptor.ecdsa_sizes', { sync: pure.ecdsa_sizes });
var ecdsa_verify_ops = define('adaptor.ecdsa_verify', { sync: pure.ecdsa_verify, text: [1] });
var ecdsa_x_scalar_ops = define('adaptor.ecdsa_x_scalar', { sync: pure.ecdsa_x_scalar });
var schnorr_complete_ops = define('adaptor.schnorr_complete', { sync: pure.schnorr_complete });
var schnorr_extract_ops = define('adaptor.schnorr_extract', { sync: pure.schnorr_extract });
var schnorr_nonce_ops = define('adaptor.schnorr_nonce', { sync: pure.schnorr_nonce });
var schnorr_pre_sign_ops = define('adaptor.schnorr_pre_sign', { sync: pure.schnorr_pre_sign, text: [2] });
var schnorr_verify_ops = define('adaptor.schnorr_verify', { sync: pure.schnorr_verify, text: [2] });

export var dleq_challenge = dleq_challenge_ops.async;
export var dleq_challenge_sync = dleq_challenge_ops.sync;
export var dleq_prove = dleq_prove_ops.async;
export var dleq_prove_sync = dleq_prove_ops.sync;
export var dleq_share_ok = dleq_share_ok_ops.async;
export var dleq_share_ok_sync = dleq_share_ok_ops.sync;
export var dleq_verify = dleq_verify_ops.async;
export var dleq_verify_sync = dleq_verify_ops.sync;
export var ecdsa_complete = ecdsa_complete_ops.async;
export var ecdsa_complete_sync = ecdsa_complete_ops.sync;
export var ecdsa_decode = ecdsa_decode_ops.async;
export var ecdsa_decode_sync = ecdsa_decode_ops.sync;
export var ecdsa_encode = ecdsa_encode_ops.async;
export var ecdsa_encode_sync = ecdsa_encode_ops.sync;
export var ecdsa_extract = ecdsa_extract_ops.async;
export var ecdsa_extract_sync = ecdsa_extract_ops.sync;
export var ecdsa_message_scalar = ecdsa_message_scalar_ops.async;
export var ecdsa_message_scalar_sync = ecdsa_message_scalar_ops.sync;
export var ecdsa_pre_sign = ecdsa_pre_sign_ops.async;
export var ecdsa_pre_sign_sync = ecdsa_pre_sign_ops.sync;
export var ecdsa_sizes = ecdsa_sizes_ops.async;
export var ecdsa_sizes_sync = ecdsa_sizes_ops.sync;
export var ecdsa_verify = ecdsa_verify_ops.async;
export var ecdsa_verify_sync = ecdsa_verify_ops.sync;
export var ecdsa_x_scalar = ecdsa_x_scalar_ops.async;
export var ecdsa_x_scalar_sync = ecdsa_x_scalar_ops.sync;
export var schnorr_complete = schnorr_complete_ops.async;
export var schnorr_complete_sync = schnorr_complete_ops.sync;
export var schnorr_extract = schnorr_extract_ops.async;
export var schnorr_extract_sync = schnorr_extract_ops.sync;
export var schnorr_nonce = schnorr_nonce_ops.async;
export var schnorr_nonce_sync = schnorr_nonce_ops.sync;
export var schnorr_pre_sign = schnorr_pre_sign_ops.async;
export var schnorr_pre_sign_sync = schnorr_pre_sign_ops.sync;
export var schnorr_verify = schnorr_verify_ops.async;
export var schnorr_verify_sync = schnorr_verify_ops.sync;
