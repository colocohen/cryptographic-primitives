/**
 * zk_dlenc, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../zk_dlenc.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../zk_dlenc.js.
 */

import * as pure from '../zk_dlenc.js';
import { define } from '../engines/select.js';

var challenge_ops = define('zk_dlenc.challenge', { sync: pure.challenge, text: [4] });
var prove_dlenc_ops = define('zk_dlenc.prove_dlenc', { sync: pure.prove_dlenc, text: [4] });
var verify_dlenc_ops = define('zk_dlenc.verify_dlenc', { sync: pure.verify_dlenc, text: [3] });

export var challenge = challenge_ops.async;
export var challenge_sync = challenge_ops.sync;
export var prove_dlenc = prove_dlenc_ops.async;
export var prove_dlenc_sync = prove_dlenc_ops.sync;
export var verify_dlenc = verify_dlenc_ops.async;
export var verify_dlenc_sync = verify_dlenc_ops.sync;
