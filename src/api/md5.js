/**
 * MD5. Broken for collision resistance; here for checksums and the protocols
 * that still name it.
 *
 *     md5(msg, function (err, digest) {})   on a later turn of the event loop
 *     md5_sync(msg)                         the digest, directly
 *     md5_create()                          { update(msg), copy(), digest() }
 *
 * A message may be a Uint8Array or a string, which is hashed as UTF-8.
 * The platform's crypto runs it where it has it (engines/), the pure
 * JavaScript in ../md5.js everywhere else, with the same result.
 */

import * as pure from '../md5.js';
import { define } from '../engines/select.js';

var ops = define('md5', { sync: pure.md5, create: pure.md5_create, text: [0] });

export var md5        = ops.async;
export var md5_sync   = ops.sync;
export var md5_create = ops.create;
