/**
 * dh, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../dh.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../dh.js.
 */

import * as pure from '../dh.js';
import { define } from '../engines/select.js';

var compute_secret_ops = define('dh.compute_secret', { sync: pure.compute_secret, bytes: { 0: 'key' } });
var group_order_ops = define('dh.group_order', { sync: pure.group_order });
var keygen_ops = define('dh.keygen', { sync: pure.keygen });
var validate_public_ops = define('dh.validate_public', { sync: pure.validate_public });

export var GROUPS = pure.GROUPS;
export var compute_secret = compute_secret_ops.async;
export var compute_secret_sync = compute_secret_ops.sync;
export var group_order = group_order_ops.async;
export var group_order_sync = group_order_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var validate_public = validate_public_ops.async;
export var validate_public_sync = validate_public_ops.sync;
