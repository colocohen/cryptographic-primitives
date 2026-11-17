/**
 * frost_pure, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../frost_pure.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../frost_pure.js.
 */

import * as pure from '../frost_pure.js';
import { define } from '../engines/select.js';

var group_commitment_ops = define('frost_pure.group_commitment', { sync: pure.group_commitment });
var has_odd_y_ops = define('frost_pure.has_odd_y', { sync: pure.has_odd_y });
var nonce_generate_ops = define('frost_pure.nonce_generate', { sync: pure.nonce_generate });
var pok_challenge_ops = define('frost_pure.pok_challenge', { sync: pure.pok_challenge, text: [2] });
var pok_prove_ops = define('frost_pure.pok_prove', { sync: pure.pok_prove, text: [2] });
var pok_verify_ops = define('frost_pure.pok_verify', { sync: pure.pok_verify, text: [2] });
var poly_commit_ops = define('frost_pure.poly_commit', { sync: pure.poly_commit });
var random_scalar_ops = define('frost_pure.random_scalar', { sync: pure.random_scalar });
var rerandomize_public_ops = define('frost_pure.rerandomize_public', { sync: pure.rerandomize_public });
var rerandomize_secret_ops = define('frost_pure.rerandomize_secret', { sync: pure.rerandomize_secret });
var sign_share_ops = define('frost_pure.sign_share', { sync: pure.sign_share, text: [2] });
var verify_share_ops = define('frost_pure.verify_share', { sync: pure.verify_share, text: [2] });
var verify_signature_ops = define('frost_pure.verify_signature', { sync: pure.verify_signature, text: [2] });
var verify_signature_batch_ops = define('frost_pure.verify_signature_batch', { sync: pure.verify_signature_batch, text: [2] });
var verify_signature_batch_find_ops = define('frost_pure.verify_signature_batch_find', { sync: pure.verify_signature_batch_find, text: [2] });
var vss_combine_ops = define('frost_pure.vss_combine', { sync: pure.vss_combine });
var vss_eval_ops = define('frost_pure.vss_eval', { sync: pure.vss_eval });
var vss_verify_ops = define('frost_pure.vss_verify', { sync: pure.vss_verify });

export var group_commitment = group_commitment_ops.async;
export var group_commitment_sync = group_commitment_ops.sync;
export var has_odd_y = has_odd_y_ops.async;
export var has_odd_y_sync = has_odd_y_ops.sync;
export var nonce_generate = nonce_generate_ops.async;
export var nonce_generate_sync = nonce_generate_ops.sync;
export var pok_challenge = pok_challenge_ops.async;
export var pok_challenge_sync = pok_challenge_ops.sync;
export var pok_prove = pok_prove_ops.async;
export var pok_prove_sync = pok_prove_ops.sync;
export var pok_verify = pok_verify_ops.async;
export var pok_verify_sync = pok_verify_ops.sync;
export var poly_commit = poly_commit_ops.async;
export var poly_commit_sync = poly_commit_ops.sync;
export var random_scalar = random_scalar_ops.async;
export var random_scalar_sync = random_scalar_ops.sync;
export var rerandomize_public = rerandomize_public_ops.async;
export var rerandomize_public_sync = rerandomize_public_ops.sync;
export var rerandomize_secret = rerandomize_secret_ops.async;
export var rerandomize_secret_sync = rerandomize_secret_ops.sync;
export var sign_share = sign_share_ops.async;
export var sign_share_sync = sign_share_ops.sync;
export var verify_share = verify_share_ops.async;
export var verify_share_sync = verify_share_ops.sync;
export var verify_signature = verify_signature_ops.async;
export var verify_signature_sync = verify_signature_ops.sync;
export var verify_signature_batch = verify_signature_batch_ops.async;
export var verify_signature_batch_sync = verify_signature_batch_ops.sync;
export var verify_signature_batch_find = verify_signature_batch_find_ops.async;
export var verify_signature_batch_find_sync = verify_signature_batch_find_ops.sync;
export var vss_combine = vss_combine_ops.async;
export var vss_combine_sync = vss_combine_ops.sync;
export var vss_eval = vss_eval_ops.async;
export var vss_eval_sync = vss_eval_ops.sync;
export var vss_verify = vss_verify_ops.async;
export var vss_verify_sync = vss_verify_ops.sync;
