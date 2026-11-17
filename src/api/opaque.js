/**
 * opaque, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../opaque.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../opaque.js.
 */

import * as pure from '../opaque.js';
import { define } from '../engines/select.js';

var ksf_argon2id_ops = define('opaque.ksf_argon2id', { sync: pure.ksf_argon2id });
var ksf_identity_ops = define('opaque.ksf_identity', { sync: pure.ksf_identity, text: [0] });
var ksf_scrypt_ops = define('opaque.ksf_scrypt', { sync: pure.ksf_scrypt });
var opaque_suite_ops = define('opaque.opaque_suite', { sync: pure.opaque_suite });

export var DH_GROUPS = pure.DH_GROUPS;
export var ksf_argon2id = ksf_argon2id_ops.async;
export var ksf_argon2id_sync = ksf_argon2id_ops.sync;
export var ksf_identity = ksf_identity_ops.async;
export var ksf_identity_sync = ksf_identity_ops.sync;
export var ksf_scrypt = ksf_scrypt_ops.async;
export var ksf_scrypt_sync = ksf_scrypt_ops.sync;
export var opaque_suite = opaque_suite_ops.async;
export var opaque_suite_sync = opaque_suite_ops.sync;
