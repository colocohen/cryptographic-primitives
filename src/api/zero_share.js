/**
 * zero_share, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../zero_share.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../zero_share.js.
 */

import * as pure from '../zero_share.js';
import { define } from '../engines/select.js';

var zero_share_ops = define('zero_share.zero_share', { sync: pure.zero_share, text: [3], bytes: { 5: 'tag' } });
var zero_share_pair_ops = define('zero_share.zero_share_pair', { sync: pure.zero_share_pair, bytes: { 0: 'seed' } });

export var zero_share = zero_share_ops.async;
export var zero_share_sync = zero_share_ops.sync;
export var zero_share_pair = zero_share_pair_ops.async;
export var zero_share_pair_sync = zero_share_pair_ops.sync;
