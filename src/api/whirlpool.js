/**
 * Whirlpool.
 *
 *     whirlpool(msg, function (err, digest) {})   on a later turn of the event loop
 *     whirlpool_sync(msg)                         the digest, directly
 *     whirlpool_create()                          { update(msg), copy(), digest() }
 *
 * A message may be a Uint8Array or a string, which is hashed as UTF-8.
 * The platform's crypto runs it where it has it (engines/), the pure
 * JavaScript in ../whirlpool.js everywhere else, with the same result.
 */

import * as pure from '../whirlpool.js';
import { define } from '../engines/select.js';

var ops = define('whirlpool', { sync: pure.whirlpool, create: pure.whirlpool_create, text: [0] });

export var whirlpool        = ops.async;
export var whirlpool_sync   = ops.sync;
export var whirlpool_create = ops.create;
