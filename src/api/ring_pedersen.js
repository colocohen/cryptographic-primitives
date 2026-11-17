/**
 * ring_pedersen, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ring_pedersen.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ring_pedersen.js.
 */

import * as pure from '../ring_pedersen.js';
import { define } from '../engines/select.js';

var commit_ops = define('ring_pedersen.commit', { sync: pure.commit });
var keygen_ops = define('ring_pedersen.keygen', { sync: pure.keygen, task: pure.keygen_task });
var keygen_rough_ops = define('ring_pedersen.keygen_rough', { sync: pure.keygen_rough, task: pure.keygen_rough_task });
var large_challenge_ops = define('ring_pedersen.large_challenge', { sync: pure.large_challenge, text: [3] });
var prove_df_small_ops = define('ring_pedersen.prove_df_small', { sync: pure.prove_df_small, text: [4] });
var prove_modulus_ops = define('ring_pedersen.prove_modulus', { sync: pure.prove_modulus, text: [5] });
var prove_params_ops = define('ring_pedersen.prove_params', { sync: pure.prove_params, text: [4] });
var prove_params_large_ops = define('ring_pedersen.prove_params_large', { sync: pure.prove_params_large, text: [4] });
var sample_df_ops = define('ring_pedersen.sample_df', { sync: pure.sample_df, task: pure.sample_df_task });
var verify_df_small_ops = define('ring_pedersen.verify_df_small', { sync: pure.verify_df_small, text: [3] });
var verify_modulus_ops = define('ring_pedersen.verify_modulus', { sync: pure.verify_modulus, text: [3] });
var verify_params_ops = define('ring_pedersen.verify_params', { sync: pure.verify_params, text: [3] });
var verify_params_large_ops = define('ring_pedersen.verify_params_large', { sync: pure.verify_params_large, text: [3] });

export var commit = commit_ops.async;
export var commit_sync = commit_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var keygen_rough = keygen_rough_ops.async;
export var keygen_rough_sync = keygen_rough_ops.sync;
export var large_challenge = large_challenge_ops.async;
export var large_challenge_sync = large_challenge_ops.sync;
export var prove_df_small = prove_df_small_ops.async;
export var prove_df_small_sync = prove_df_small_ops.sync;
export var prove_modulus = prove_modulus_ops.async;
export var prove_modulus_sync = prove_modulus_ops.sync;
export var prove_params = prove_params_ops.async;
export var prove_params_sync = prove_params_ops.sync;
export var prove_params_large = prove_params_large_ops.async;
export var prove_params_large_sync = prove_params_large_ops.sync;
export var sample_df = sample_df_ops.async;
export var sample_df_sync = sample_df_ops.sync;
export var verify_df_small = verify_df_small_ops.async;
export var verify_df_small_sync = verify_df_small_ops.sync;
export var verify_modulus = verify_modulus_ops.async;
export var verify_modulus_sync = verify_modulus_ops.sync;
export var verify_params = verify_params_ops.async;
export var verify_params_sync = verify_params_ops.sync;
export var verify_params_large = verify_params_large_ops.async;
export var verify_params_large_sync = verify_params_large_ops.sync;
