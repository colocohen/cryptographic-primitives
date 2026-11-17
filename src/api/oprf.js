/**
 * oprf, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../oprf.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../oprf.js.
 */

import * as pure from '../oprf.js';
import { define } from '../engines/select.js';

var blind_ops = define('oprf.blind', { sync: pure.blind, text: [0] });
var blind_evaluate_ops = define('oprf.blind_evaluate', { sync: pure.blind_evaluate, bytes: { 0: 'sk' } });
var blind_evaluate_partial_ops = define('oprf.blind_evaluate_partial', { sync: pure.blind_evaluate_partial, text: [2], bytes: { 0: 'sk' } });
var blind_evaluate_verifiable_ops = define('oprf.blind_evaluate_verifiable', { sync: pure.blind_evaluate_verifiable, bytes: { 0: 'sk', 1: 'pk' } });
var derive_keypair_ops = define('oprf.derive_keypair', { sync: pure.derive_keypair, text: [1], bytes: { 0: 'seed' } });
var evaluate_ops = define('oprf.evaluate', { sync: pure.evaluate, text: [1, 3], bytes: { 0: 'sk' } });
var finalize_ops = define('oprf.finalize', { sync: pure.finalize, text: [0] });
var finalize_partial_ops = define('oprf.finalize_partial', { sync: pure.finalize_partial, text: [0, 6], bytes: { 4: 'pk' } });
var finalize_verifiable_ops = define('oprf.finalize_verifiable', { sync: pure.finalize_verifiable, text: [0], bytes: { 4: 'pk' } });
var oprf_suite_ops = define('oprf.oprf_suite', { sync: pure.oprf_suite });
var suite_ops = define('oprf.suite', { sync: pure.suite });

export var MODE_OPRF = pure.MODE_OPRF;
export var MODE_POPRF = pure.MODE_POPRF;
export var MODE_VOPRF = pure.MODE_VOPRF;
export var SUITE_IDS = pure.SUITE_IDS;
export var blind = blind_ops.async;
export var blind_sync = blind_ops.sync;
export var blind_evaluate = blind_evaluate_ops.async;
export var blind_evaluate_sync = blind_evaluate_ops.sync;
export var blind_evaluate_partial = blind_evaluate_partial_ops.async;
export var blind_evaluate_partial_sync = blind_evaluate_partial_ops.sync;
export var blind_evaluate_verifiable = blind_evaluate_verifiable_ops.async;
export var blind_evaluate_verifiable_sync = blind_evaluate_verifiable_ops.sync;
export var derive_keypair = derive_keypair_ops.async;
export var derive_keypair_sync = derive_keypair_ops.sync;
export var evaluate = evaluate_ops.async;
export var evaluate_sync = evaluate_ops.sync;
export var finalize = finalize_ops.async;
export var finalize_sync = finalize_ops.sync;
export var finalize_partial = finalize_partial_ops.async;
export var finalize_partial_sync = finalize_partial_ops.sync;
export var finalize_verifiable = finalize_verifiable_ops.async;
export var finalize_verifiable_sync = finalize_verifiable_ops.sync;
export var oprf_suite = oprf_suite_ops.async;
export var oprf_suite_sync = oprf_suite_ops.sync;
export var suite = suite_ops.async;
export var suite_sync = suite_ops.sync;
