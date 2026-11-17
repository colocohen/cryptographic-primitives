/**
 * SHA-1. Broken for collision resistance; here for the protocols that still
 * name it (HMAC-SHA1, TOTP, WebSocket, Git).
 *
 *     sha1(msg, function (err, digest) {})   on a later turn of the event loop
 *     sha1_sync(msg)                         the digest, directly
 *     sha1_create()                          { update(msg), copy(), digest() }
 *
 * A message may be a Uint8Array or a string, which is hashed as UTF-8.
 * The platform's crypto runs it where it has it (engines/), the pure
 * JavaScript in ../sha1.js everywhere else, with the same result.
 */

import * as pure from '../sha1.js';
import { define } from '../engines/select.js';

var ops = define('sha1', { sync: pure.sha1, create: pure.sha1_create, text: [0] });

export var sha1        = ops.async;
export var sha1_sync   = ops.sync;
export var sha1_create = ops.create;
