/**
 * leap, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../leap.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../leap.js.
 */

import * as pure from '../leap.js';
import { define } from '../engines/select.js';

var bch_ops = define('leap.bch', { sync: pure.bch });
var client_finish_ops = define('leap.client_finish', { sync: pure.client_finish });
var client_ole_ops = define('leap.client_ole', { sync: pure.client_ole });
var client_round_ops = define('leap.client_round', { sync: pure.client_round });
var client_start_ops = define('leap.client_start', { sync: pure.client_start });
var evaluate_ops = define('leap.evaluate', { sync: pure.evaluate, bytes: { 0: 'key' } });
var intt_ops = define('leap.intt', { sync: pure.intt });
var keygen_ops = define('leap.keygen', { sync: pure.keygen });
var ntt_ops = define('leap.ntt', { sync: pure.ntt });
var server_ole_ops = define('leap.server_ole', { sync: pure.server_ole });
var server_round_ops = define('leap.server_round', { sync: pure.server_round });
var server_start_ops = define('leap.server_start', { sync: pure.server_start, bytes: { 0: 'key' } });
var server_subset_ops = define('leap.server_subset', { sync: pure.server_subset });
var spring_ops = define('leap.spring', { sync: pure.spring, bytes: { 0: 'key' } });

export var SIZES = pure.SIZES;
export var bch = bch_ops.async;
export var bch_sync = bch_ops.sync;
export var client_finish = client_finish_ops.async;
export var client_finish_sync = client_finish_ops.sync;
export var client_ole = client_ole_ops.async;
export var client_ole_sync = client_ole_ops.sync;
export var client_round = client_round_ops.async;
export var client_round_sync = client_round_ops.sync;
export var client_start = client_start_ops.async;
export var client_start_sync = client_start_ops.sync;
export var evaluate = evaluate_ops.async;
export var evaluate_sync = evaluate_ops.sync;
export var intt = intt_ops.async;
export var intt_sync = intt_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var ntt = ntt_ops.async;
export var ntt_sync = ntt_ops.sync;
export var server_ole = server_ole_ops.async;
export var server_ole_sync = server_ole_ops.sync;
export var server_round = server_round_ops.async;
export var server_round_sync = server_round_ops.sync;
export var server_start = server_start_ops.async;
export var server_start_sync = server_start_ops.sync;
export var server_subset = server_subset_ops.async;
export var server_subset_sync = server_subset_ops.sync;
export var spring = spring_ops.async;
export var spring_sync = spring_ops.sync;
