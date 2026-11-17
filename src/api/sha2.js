/**
 * SHA-2, in the three forms every operation takes:
 *
 *     sha256(msg, function (err, digest) {})   on a later turn of the event loop
 *     sha256_sync(msg)                         the digest, directly
 *     sha256_create()                          { update(msg), copy(), digest() }
 *
 * A message may be a Uint8Array or a string, which is hashed as UTF-8.
 * node:crypto or WebCrypto runs it where the platform has it (engines/), the
 * pure JavaScript in ../sha2.js everywhere else, with the same result.
 */

import * as pure from '../sha2.js';
import { define } from '../engines/select.js';

var sha256_ops = define('sha256', { sync: pure.sha256, create: pure.sha256_create, text: [0] });
var sha224_ops = define('sha224', { sync: pure.sha224, create: pure.sha224_create, text: [0] });
var sha512_ops = define('sha512', { sync: pure.sha512, create: pure.sha512_create, text: [0] });
var sha384_ops = define('sha384', { sync: pure.sha384, create: pure.sha384_create, text: [0] });
var sha512_224_ops = define('sha512_224', { sync: pure.sha512_224, create: pure.sha512_224_create, text: [0] });
var sha512_256_ops = define('sha512_256', { sync: pure.sha512_256, create: pure.sha512_256_create, text: [0] });

export var sha256            = sha256_ops.async;
export var sha256_sync       = sha256_ops.sync;
export var sha256_create     = sha256_ops.create;
export var sha224            = sha224_ops.async;
export var sha224_sync       = sha224_ops.sync;
export var sha224_create     = sha224_ops.create;
export var sha512            = sha512_ops.async;
export var sha512_sync       = sha512_ops.sync;
export var sha512_create     = sha512_ops.create;
export var sha384            = sha384_ops.async;
export var sha384_sync       = sha384_ops.sync;
export var sha384_create     = sha384_ops.create;
export var sha512_224        = sha512_224_ops.async;
export var sha512_224_sync   = sha512_224_ops.sync;
export var sha512_224_create = sha512_224_ops.create;
export var sha512_256        = sha512_256_ops.async;
export var sha512_256_sync   = sha512_256_ops.sync;
export var sha512_256_create = sha512_256_ops.create;
