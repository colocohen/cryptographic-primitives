/**
 * MD4. Broken; here for NTLM and other legacy formats.
 *
 *     md4(msg, function (err, digest) {})   on a later turn of the event loop
 *     md4_sync(msg)                         the digest, directly
 *     md4_create()                          { update(msg), copy(), digest() }
 *
 * A message may be a Uint8Array or a string, which is hashed as UTF-8.
 * The platform's crypto runs it where it has it (engines/), the pure
 * JavaScript in ../md4.js everywhere else, with the same result.
 */

import * as pure from '../md4.js';
import { define } from '../engines/select.js';

var ops = define('md4', { sync: pure.md4, create: pure.md4_create, text: [0] });

export var md4        = ops.async;
export var md4_sync   = ops.sync;
export var md4_create = ops.create;

/* NTLM: MD4 of the password as UTF-16LE. The string is passed as is - it is
   not UTF-8 - and ../md4.js does the encoding. */
var ntlm_ops = define('ntlm', { sync: pure.ntlm });

export var ntlm      = ntlm_ops.async;
export var ntlm_sync = ntlm_ops.sync;
