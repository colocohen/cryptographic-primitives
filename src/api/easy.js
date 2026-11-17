/**
 * easy, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../easy.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../easy.js.
 */

import * as pure from '../easy.js';
import { define } from '../engines/select.js';

var hash_password_ops = define('easy.hash_password', { sync: pure.hash_password, task: pure.hash_password_task, text: [0] });
var needs_rehash_ops = define('easy.needs_rehash', { sync: pure.needs_rehash });
var open_with_password_ops = define('easy.open_with_password', { sync: pure.open_with_password, task: pure.open_with_password_task, text: [0], bytes: { 1: 'sealed' } });
var seal_with_password_ops = define('easy.seal_with_password', { sync: pure.seal_with_password, task: pure.seal_with_password_task, text: [0, 1] });
var verify_password_ops = define('easy.verify_password', { sync: pure.verify_password, task: pure.verify_password_task, text: [0] });

export var MEMORY_KIB = pure.MEMORY_KIB;
export var PARALLELISM = pure.PARALLELISM;
export var SALT_BYTES = pure.SALT_BYTES;
export var TIME_COST = pure.TIME_COST;
export var hash_password = hash_password_ops.async;
export var hash_password_sync = hash_password_ops.sync;
export var needs_rehash = needs_rehash_ops.async;
export var needs_rehash_sync = needs_rehash_ops.sync;
export var open_with_password = open_with_password_ops.async;
export var open_with_password_sync = open_with_password_ops.sync;
export var seal_with_password = seal_with_password_ops.async;
export var seal_with_password_sync = seal_with_password_ops.sync;
export var verify_password = verify_password_ops.async;
export var verify_password_sync = verify_password_ops.sync;
