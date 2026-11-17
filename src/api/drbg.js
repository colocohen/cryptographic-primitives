/**
 * drbg, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../drbg.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../drbg.js.
 */

import * as pure from '../drbg.js';
import { define } from '../engines/select.js';

var ctr_drbg_ops = define('drbg.ctr_drbg', { sync: pure.ctr_drbg, text: [3], bytes: { 1: 'entropy', 2: 'nonce' } });
var hash_drbg_ops = define('drbg.hash_drbg', { sync: pure.hash_drbg, text: [3], bytes: { 1: 'entropy', 2: 'nonce' } });
var hmac_drbg_ops = define('drbg.hmac_drbg', { sync: pure.hmac_drbg, text: [3], bytes: { 1: 'entropy', 2: 'nonce' } });

export var ctr_drbg = ctr_drbg_ops.async;
export var ctr_drbg_sync = ctr_drbg_ops.sync;
export var hash_drbg = hash_drbg_ops.async;
export var hash_drbg_sync = hash_drbg_ops.sync;
export var hmac_drbg = hmac_drbg_ops.async;
export var hmac_drbg_sync = hmac_drbg_ops.sync;
