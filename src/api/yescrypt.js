/**
 * yescrypt, the password hash of current Linux distributions' /etc/shadow:
 *
 *     yescrypt(...args, function (err, key) {})   and _sync
 *     crypt(password, setting, cb)                and _sync
 *     crypt_verify(password, stored, cb)          and _sync
 *
 * Arguments are those of ../yescrypt.js. No platform ships yescrypt, so it
 * runs the pure JavaScript there.
 */

import * as pure from '../yescrypt.js';
import { define } from '../engines/select.js';

var yescrypt_ops = define('yescrypt', { sync: pure.yescrypt, task: pure.yescrypt_task, text: [0, 1] });
var crypt_ops = define('crypt', { sync: pure.crypt, task: pure.crypt_task, text: [0] });
var crypt_verify_ops = define('crypt_verify', { sync: pure.crypt_verify, task: pure.crypt_verify_task, text: [0] });

export var yescrypt = yescrypt_ops.async;
export var yescrypt_sync = yescrypt_ops.sync;
export var crypt = crypt_ops.async;
export var crypt_sync = crypt_ops.sync;
export var crypt_verify = crypt_verify_ops.async;
export var crypt_verify_sync = crypt_verify_ops.sync;
export var encode_setting = pure.encode_setting;
export var decode_setting = pure.decode_setting;
export var YESCRYPT_RW = pure.YESCRYPT_RW;
export var YESCRYPT_ROUNDS_6 = pure.YESCRYPT_ROUNDS_6;
export var YESCRYPT_GATHER_4 = pure.YESCRYPT_GATHER_4;
export var YESCRYPT_SIMPLE_2 = pure.YESCRYPT_SIMPLE_2;
export var YESCRYPT_SBOX_12K = pure.YESCRYPT_SBOX_12K;
export var YESCRYPT_DEFAULTS = pure.YESCRYPT_DEFAULTS;
