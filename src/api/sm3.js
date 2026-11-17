/**
 * SM3 (GB/T 32905).
 *
 *     sm3(msg, function (err, digest) {})   on a later turn of the event loop
 *     sm3_sync(msg)                         the digest, directly
 *     sm3_create()                          { update(msg), copy(), digest() }
 *
 * A message may be a Uint8Array or a string, which is hashed as UTF-8.
 * The platform's crypto runs it where it has it (engines/), the pure
 * JavaScript in ../sm3.js everywhere else, with the same result.
 */

import * as pure from '../sm3.js';
import { define } from '../engines/select.js';

var ops = define('sm3', { sync: pure.sm3, create: pure.sm3_create, text: [0] });

export var sm3        = ops.async;
export var sm3_sync   = ops.sync;
export var sm3_create = ops.create;
