/**
 * ot_base, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ot_base.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ot_base.js.
 */

import * as pure from '../ot_base.js';
import { define } from '../engines/select.js';

var receiver_choose_ops = define('ot_base.receiver_choose', { sync: pure.receiver_choose });
var receiver_key_ops = define('ot_base.receiver_key', { sync: pure.receiver_key, text: [3] });
var sender_keys_ops = define('ot_base.sender_keys', { sync: pure.sender_keys, text: [3] });
var sender_setup_ops = define('ot_base.sender_setup', { sync: pure.sender_setup });
var transfer_ops = define('ot_base.transfer', { sync: pure.transfer, text: [5] });

export var receiver_choose = receiver_choose_ops.async;
export var receiver_choose_sync = receiver_choose_ops.sync;
export var receiver_key = receiver_key_ops.async;
export var receiver_key_sync = receiver_key_ops.sync;
export var sender_keys = sender_keys_ops.async;
export var sender_keys_sync = sender_keys_ops.sync;
export var sender_setup = sender_setup_ops.async;
export var sender_setup_sync = sender_setup_ops.sync;
export var transfer = transfer_ops.async;
export var transfer_sync = transfer_ops.sync;
