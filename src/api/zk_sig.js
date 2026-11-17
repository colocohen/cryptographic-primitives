/**
 * zk_sig, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../zk_sig.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../zk_sig.js.
 */

import * as pure from '../zk_sig.js';
import { define } from '../engines/select.js';

var challenge_ops = define('zk_sig.challenge', { sync: pure.challenge, text: [4] });
var independent_generators_ops = define('zk_sig.independent_generators', { sync: pure.independent_generators, text: [1] });
var prove_sig_ops = define('zk_sig.prove_sig', { sync: pure.prove_sig, text: [4] });
var verify_sig_ops = define('zk_sig.verify_sig', { sync: pure.verify_sig, text: [3] });

export var challenge = challenge_ops.async;
export var challenge_sync = challenge_ops.sync;
export var independent_generators = independent_generators_ops.async;
export var independent_generators_sync = independent_generators_ops.sync;
export var prove_sig = prove_sig_ops.async;
export var prove_sig_sync = prove_sig_ops.sync;
export var verify_sig = verify_sig_ops.async;
export var verify_sig_sync = verify_sig_ops.sync;
