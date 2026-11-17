/**
 * Argon2 (RFC 9106):
 *
 *     argon2id({ password, salt, m, t, p, length, secret?, ad? }, function (err, tag) {})
 *     argon2id_sync({ ... })
 *
 * and the same for argon2d and argon2i. m is memory in KiB, t the passes,
 * p the lanes. password and salt are Uint8Arrays.
 *
 * node:crypto runs it where it has it (Node 24.7 and later), the callback
 * form on its thread pool so the event loop stays free; elsewhere it is the
 * pure JavaScript in ../argon2.js, whose callback form runs in slices of a
 * few milliseconds, yielding to the event loop between them.
 */

import * as pure from '../argon2.js';
import { define } from '../engines/select.js';

/* the options a person may write as text: taken as UTF-8 */
var TEXT_FIELDS = { 0: ['password', 'salt', 'secret', 'ad'] };

var argon2d_ops = define('argon2d', { sync: pure.argon2d, task: pure.argon2d_task, fields: TEXT_FIELDS });
var argon2i_ops = define('argon2i', { sync: pure.argon2i, task: pure.argon2i_task, fields: TEXT_FIELDS });
var argon2id_ops = define('argon2id', { sync: pure.argon2id, task: pure.argon2id_task, fields: TEXT_FIELDS });

export var argon2d = argon2d_ops.async;
export var argon2d_sync = argon2d_ops.sync;
export var argon2i = argon2i_ops.async;
export var argon2i_sync = argon2i_ops.sync;
export var argon2id = argon2id_ops.async;
export var argon2id_sync = argon2id_ops.sync;
export var ARGON2D = pure.ARGON2D;
export var ARGON2I = pure.ARGON2I;
export var ARGON2ID = pure.ARGON2ID;
