/**
 * bcrypt, and bcrypt_pbkdf (OpenSSH's key derivation):
 *
 *     bcrypt(password, salt, cost, function (err, hash) {})   and _sync
 *     bcrypt_verify(password, stored, cb)                     and _sync
 *
 * Arguments are those of ../bcrypt.js. No platform ships bcrypt, so it runs
 * the pure JavaScript there.
 */

import * as pure from '../bcrypt.js';
import { define } from '../engines/select.js';

var bcrypt_raw_ops = define('bcrypt_raw', { sync: pure.bcrypt_raw, task: pure.bcrypt_raw_task, text: [0], bytes: { 1: 'salt' } });
var bcrypt_pbkdf_ops = define('bcrypt_pbkdf', { sync: pure.bcrypt_pbkdf, task: pure.bcrypt_pbkdf_task, text: [0, 1] });
var bcrypt_ops = define('bcrypt', { sync: pure.bcrypt, task: pure.bcrypt_task, text: [0], bytes: { 1: 'salt' } });
var bcrypt_verify_ops = define('bcrypt_verify', { sync: pure.bcrypt_verify, task: pure.bcrypt_verify_task, text: [0] });

export var bcrypt_raw = bcrypt_raw_ops.async;
export var bcrypt_raw_sync = bcrypt_raw_ops.sync;
export var bcrypt_pbkdf = bcrypt_pbkdf_ops.async;
export var bcrypt_pbkdf_sync = bcrypt_pbkdf_ops.sync;
export var bcrypt = bcrypt_ops.async;
export var bcrypt_sync = bcrypt_ops.sync;
export var bcrypt_verify = bcrypt_verify_ops.async;
export var bcrypt_verify_sync = bcrypt_verify_ops.sync;
export var bcrypt_base64_encode = pure.bcrypt_base64_encode;
export var bcrypt_base64_decode = pure.bcrypt_base64_decode;
