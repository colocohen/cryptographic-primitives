/**
 * scrypt (RFC 7914):
 *
 *     scrypt(password, salt, N, r, p, length, function (err, key) {})
 *     scrypt_sync(password, salt, N, r, p, length)
 *
 * A password or salt may be a string (UTF-8). node:crypto runs it where it
 * has it, the callback form on its thread pool so the event loop stays free;
 * elsewhere it is the pure JavaScript in ../scrypt.js, whose callback form
 * runs in slices of a few milliseconds, yielding to the event loop between.
 */

import * as pure from '../scrypt.js';
import { define } from '../engines/select.js';

var scrypt_ops = define('scrypt', { sync: pure.scrypt, task: pure.scrypt_task, text: [0, 1] });

export var scrypt = scrypt_ops.async;
export var scrypt_sync = scrypt_ops.sync;
