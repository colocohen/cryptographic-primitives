/**
 * frost, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../frost.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../frost.js.
 */

import * as pure from '../frost.js';
import { define } from '../engines/select.js';

var aggregate_ops = define('frost.aggregate', { sync: pure.aggregate, text: [1] });
var commit_ops = define('frost.commit', { sync: pure.commit });
var keygen_dealer_ops = define('frost.keygen_dealer', { sync: pure.keygen_dealer });
var sign_ops = define('frost.sign', { sync: pure.sign, text: [4] });
var verify_ops = define('frost.verify', { sync: pure.verify, text: [0], bytes: { 1: 'sig' } });
var verify_share_ops = define('frost.verify_share', { sync: pure.verify_share, text: [6] });

export var aggregate = aggregate_ops.async;
export var aggregate_sync = aggregate_ops.sync;
export var commit = commit_ops.async;
export var commit_sync = commit_ops.sync;
export var keygen_dealer = keygen_dealer_ops.async;
export var keygen_dealer_sync = keygen_dealer_ops.sync;
export var sign = sign_ops.async;
export var sign_sync = sign_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
export var verify_share = verify_share_ops.async;
export var verify_share_sync = verify_share_ops.sync;
