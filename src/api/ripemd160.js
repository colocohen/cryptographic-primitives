/**
 * RIPEMD-160.
 *
 *     ripemd160(msg, function (err, digest) {})   on a later turn of the event loop
 *     ripemd160_sync(msg)                         the digest, directly
 *     ripemd160_create()                          { update(msg), copy(), digest() }
 *
 * A message may be a Uint8Array or a string, which is hashed as UTF-8.
 * The platform's crypto runs it where it has it (engines/), the pure
 * JavaScript in ../ripemd160.js everywhere else, with the same result.
 */

import * as pure from '../ripemd160.js';
import { define } from '../engines/select.js';

var ops = define('ripemd160', { sync: pure.ripemd160, create: pure.ripemd160_create, text: [0] });

export var ripemd160        = ops.async;
export var ripemd160_sync   = ops.sync;
export var ripemd160_create = ops.create;
