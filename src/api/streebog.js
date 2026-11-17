/**
 * Streebog (GOST R 34.11-2012), in the three forms every operation takes:
 *
 *     streebog256(msg, function (err, digest) {})
 *     streebog256_sync(msg)
 *     streebog256_create()            { update(msg), copy(), digest() }
 *
 * and the same for streebog512. A message may be a string (UTF-8). No
 * platform ships it, so it runs the pure JavaScript in ../streebog.js.
 */

import * as pure from '../streebog.js';
import { define } from '../engines/select.js';

var streebog256_ops = define('streebog256', { sync: pure.streebog256, create: pure.streebog256_create, text: [0] });
var streebog512_ops = define('streebog512', { sync: pure.streebog512, create: pure.streebog512_create, text: [0] });

export var streebog256        = streebog256_ops.async;
export var streebog256_sync   = streebog256_ops.sync;
export var streebog256_create = streebog256_ops.create;
export var streebog512        = streebog512_ops.async;
export var streebog512_sync   = streebog512_ops.sync;
export var streebog512_create = streebog512_ops.create;
