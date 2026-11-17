/**
 * material, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../material.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../material.js.
 */

import * as pure from '../material.js';
import { define } from '../engines/select.js';

var generate_material_ops = define('material.generate_material', { sync: pure.generate_material, task: pure.generate_material_task });

export var generate_material = generate_material_ops.async;
export var generate_material_sync = generate_material_ops.sync;
