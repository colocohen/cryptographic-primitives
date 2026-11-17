/**
 * class_group, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../class_group.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../class_group.js.
 */

import * as pure from '../class_group.js';
import { define } from '../engines/select.js';

var discriminant_ops = define('class_group.discriminant', { sync: pure.discriminant, bytes: { 0: 'seed' } });
var group_ops = define('class_group.group', { sync: pure.group });
var hash_prime_ops = define('class_group.hash_prime', { sync: pure.hash_prime, bytes: { 0: 'seed' } });

export var discriminant = discriminant_ops.async;
export var discriminant_sync = discriminant_ops.sync;
export var group = group_ops.async;
export var group_sync = group_ops.sync;
export var hash_prime = hash_prime_ops.async;
export var hash_prime_sync = hash_prime_ops.sync;
