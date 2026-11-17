/**
 * x25519, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../x25519.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../x25519.js.
 */

import * as pure from '../x25519.js';
import { define } from '../engines/select.js';

var get_public_key_ops = define('x25519.get_public_key', { sync: pure.get_public_key });
var x25519_ops = define('x25519.x25519', { sync: pure.x25519 });
var x25519_checked_ops = define('x25519.x25519_checked', { sync: pure.x25519_checked });
var keygen_ops = define('x25519.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });
var context_ops = define('x25519.x25519_create', { create: pure.x25519_create, kind: 'x25519', create_bytes: { 0: 'secret' } });

export var BYTES = pure.BYTES;
export var get_public_key = get_public_key_ops.async;
export var get_public_key_sync = get_public_key_ops.sync;
export var x25519 = x25519_ops.async;
export var x25519_sync = x25519_ops.sync;
export var x25519_checked = x25519_checked_ops.async;
export var x25519_checked_sync = x25519_checked_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;

/* x25519_create(secret?): one secret for many agreements - { pk, x25519(peer), x25519_checked(peer), wipe() } */
export var x25519_create = context_ops.create;
