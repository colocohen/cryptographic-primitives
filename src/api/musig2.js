/**
 * musig2, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../musig2.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../musig2.js.
 */

import * as pure from '../musig2.js';
import { define } from '../engines/select.js';

var apply_tweak_ops = define('musig2.apply_tweak', { sync: pure.apply_tweak, text: [0] });
var get_plain_pubkey_ops = define('musig2.get_plain_pubkey', { sync: pure.get_plain_pubkey, text: [0] });
var get_xonly_pubkey_ops = define('musig2.get_xonly_pubkey', { sync: pure.get_xonly_pubkey, text: [0] });
var key_agg_ops = define('musig2.key_agg', { sync: pure.key_agg });
var nonce_agg_ops = define('musig2.nonce_agg', { sync: pure.nonce_agg });
var nonce_gen_ops = define('musig2.nonce_gen', { sync: pure.nonce_gen, text: [4], bytes: { 2: 'pubkey' } });
var partial_sig_agg_ops = define('musig2.partial_sig_agg', { sync: pure.partial_sig_agg, text: [1, 3] });
var partial_verify_ops = define('musig2.partial_verify', { sync: pure.partial_verify, text: [3, 5], bytes: { 2: 'pubkey' } });
var session_values_ops = define('musig2.session_values', { sync: pure.session_values, text: [0, 2] });
var sign_ops = define('musig2.sign', { sync: pure.sign, text: [2, 4] });

export var apply_tweak = apply_tweak_ops.async;
export var apply_tweak_sync = apply_tweak_ops.sync;
export var get_plain_pubkey = get_plain_pubkey_ops.async;
export var get_plain_pubkey_sync = get_plain_pubkey_ops.sync;
export var get_xonly_pubkey = get_xonly_pubkey_ops.async;
export var get_xonly_pubkey_sync = get_xonly_pubkey_ops.sync;
export var key_agg = key_agg_ops.async;
export var key_agg_sync = key_agg_ops.sync;
export var nonce_agg = nonce_agg_ops.async;
export var nonce_agg_sync = nonce_agg_ops.sync;
export var nonce_gen = nonce_gen_ops.async;
export var nonce_gen_sync = nonce_gen_ops.sync;
export var partial_sig_agg = partial_sig_agg_ops.async;
export var partial_sig_agg_sync = partial_sig_agg_ops.sync;
export var partial_verify = partial_verify_ops.async;
export var partial_verify_sync = partial_verify_ops.sync;
export var session_values = session_values_ops.async;
export var session_values_sync = session_values_ops.sync;
export var sign = sign_ops.async;
export var sign_sync = sign_ops.sync;
