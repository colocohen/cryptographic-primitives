/**
 * BLAKE2b and BLAKE2s (RFC 7693), in the three forms every operation takes:
 *
 *     blake2b(msg, [out_len], [key], [opts], function (err, digest) {})
 *     blake2b_sync(msg, [out_len], [key], [opts])
 *     blake2b_create([out_len], [key], [opts])   { update(msg), copy(), digest() }
 *
 * out_len defaults to the full 64 (BLAKE2s: 32) bytes; key makes it a MAC;
 * opts is { salt, personal }. A message or key may be a string (UTF-8).
 * node:crypto runs the plain unkeyed full-length hash; everything else, and
 * every call in a browser, runs the pure JavaScript in ../blake2.js.
 */

import * as pure from '../blake2.js';
import { define } from '../engines/select.js';

var b_ops = define('blake2b', { sync: pure.blake2b, create: pure.blake2b_create, text: [0, 2], create_text: [1] });
var s_ops = define('blake2s', { sync: pure.blake2s, create: pure.blake2s_create, text: [0, 2], create_text: [1] });

export var blake2b        = b_ops.async;
export var blake2b_sync   = b_ops.sync;
export var blake2b_create = b_ops.create;
export var blake2s        = s_ops.async;
export var blake2s_sync   = s_ops.sync;
export var blake2s_create = s_ops.create;
