/**
 * x448, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../x448.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../x448.js.
 */

import * as pure from '../x448.js';
import { define } from '../engines/select.js';

var get_public_key_ops = define('x448.get_public_key', { sync: pure.get_public_key });
var x448_ops = define('x448.x448', { sync: pure.x448 });
var x448_checked_ops = define('x448.x448_checked', { sync: pure.x448_checked });
var keygen_ops = define('x448.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });
var context_ops = define('x448.x448_create', { create: pure.x448_create, kind: 'x448', create_bytes: { 0: 'secret' } });

export var BYTES = pure.BYTES;
export var get_public_key = get_public_key_ops.async;
export var get_public_key_sync = get_public_key_ops.sync;
export var x448 = x448_ops.async;
export var x448_sync = x448_ops.sync;
export var x448_checked = x448_checked_ops.async;
export var x448_checked_sync = x448_checked_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;

/* x448_create(secret?): one secret for many agreements - { pk, x448(peer), x448_checked(peer), wipe() } */
export var x448_create = context_ops.create;
