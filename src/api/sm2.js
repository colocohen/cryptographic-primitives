/**
 * sm2, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../sm2.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../sm2.js.
 */

import * as pure from '../sm2.js';
import { define } from '../engines/select.js';

var compute_z_ops = define('sm2.compute_z', { sync: pure.compute_z, text: [1], bytes: { 0: 'public_key' } });
var decrypt_ops = define('sm2.decrypt', { sync: pure.decrypt, bytes: { 1: 'ct' } });
var encrypt_ops = define('sm2.encrypt', { sync: pure.encrypt, text: [1], bytes: { 0: 'public_key' } });
var exchange_public_ops = define('sm2.exchange_public', { sync: pure.exchange_public });
var get_public_key_ops = define('sm2.get_public_key', { sync: pure.get_public_key });
var is_valid_secret_ops = define('sm2.is_valid_secret', { sync: pure.is_valid_secret });
var key_exchange_ops = define('sm2.key_exchange', { sync: pure.key_exchange });
var sig_from_bytes_ops = define('sm2.sig_from_bytes', { sync: pure.sig_from_bytes });
var sig_to_bytes_ops = define('sm2.sig_to_bytes', { sync: pure.sig_to_bytes, bytes: { 0: 'sig' } });
var sign_ops = define('sm2.sign', { sync: pure.sign, text: [0, 3] });
var verify_ops = define('sm2.verify', { sync: pure.verify, text: [0, 3], bytes: { 1: 'sig', 2: 'public_key' } });
var keygen_ops = define('sm2.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });

export var CURVE = pure.CURVE;
export var DEFAULT_ID = pure.DEFAULT_ID;
export var FIELD = pure.FIELD;
export var POINT = pure.POINT;
export var compute_z = compute_z_ops.async;
export var compute_z_sync = compute_z_ops.sync;
export var decrypt = decrypt_ops.async;
export var decrypt_sync = decrypt_ops.sync;
export var encrypt = encrypt_ops.async;
export var encrypt_sync = encrypt_ops.sync;
export var exchange_public = exchange_public_ops.async;
export var exchange_public_sync = exchange_public_ops.sync;
export var get_public_key = get_public_key_ops.async;
export var get_public_key_sync = get_public_key_ops.sync;
export var is_valid_secret = is_valid_secret_ops.async;
export var is_valid_secret_sync = is_valid_secret_ops.sync;
export var key_exchange = key_exchange_ops.async;
export var key_exchange_sync = key_exchange_ops.sync;
export var sig_from_bytes = sig_from_bytes_ops.async;
export var sig_from_bytes_sync = sig_from_bytes_ops.sync;
export var sig_to_bytes = sig_to_bytes_ops.async;
export var sig_to_bytes_sync = sig_to_bytes_ops.sync;
export var sign = sign_ops.async;
export var sign_sync = sign_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
