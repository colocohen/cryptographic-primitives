/**
 * ed25519, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ed25519.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ed25519.js.
 */

import * as pure from '../ed25519.js';
import { define, scheme } from '../engines/select.js';

var base_mul_ops = define('ed25519.base_mul', { sync: pure.base_mul });
var decode_point_ops = define('ed25519.decode_point', { sync: pure.decode_point });
var encode_point_ops = define('ed25519.encode_point', { sync: pure.encode_point });
var expand_seed_ops = define('ed25519.expand_seed', { sync: pure.expand_seed, bytes: { 0: 'seed' } });
var from_x25519_ops = define('ed25519.from_x25519', { sync: pure.from_x25519 });
var get_public_key_ops = define('ed25519.get_public_key', { sync: pure.get_public_key, bytes: { 0: 'seed' } });
var keygen_ops = define('ed25519.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });
var sign_ops = define('ed25519.sign', { sync: pure.sign, text: [0, 2], bytes: { 1: 'seed' } });
var sign_ctx_ops = define('ed25519.sign_ctx', { sync: pure.sign_ctx, text: [0, 2], bytes: { 1: 'seed' } });
var sign_expanded_ops = define('ed25519.sign_expanded', { sync: pure.sign_expanded, text: [0, 2] });
var sign_ph_ops = define('ed25519.sign_ph', { sync: pure.sign_ph, text: [0, 2], bytes: { 1: 'seed' } });
var signer_ops = define('ed25519.signer', { create: pure.signer_create, kind: 'signer', create_text: [1], create_bytes: { 0: 'seed' } });
var to_x25519_ops = define('ed25519.to_x25519', { sync: pure.to_x25519 });
var verifier_ops = define('ed25519.verifier', { create: pure.verifier_create, kind: 'verifier', create_text: [1], create_bytes: { 0: 'public_key' } });
var verify_ops = define('ed25519.verify', { sync: pure.verify, text: [0, 3], bytes: { 1: 'sig', 2: 'public_key' } });
var verify_batch_ops = define('ed25519.verify_batch', { sync: pure.verify_batch, text: [0] });
var verify_batch_find_ops = define('ed25519.verify_batch_find', { sync: pure.verify_batch_find, text: [0] });
var verify_ctx_ops = define('ed25519.verify_ctx', { sync: pure.verify_ctx, text: [0, 3], bytes: { 1: 'sig', 2: 'pk' } });
var verify_ph_ops = define('ed25519.verify_ph', { sync: pure.verify_ph, text: [0, 3], bytes: { 1: 'sig', 2: 'pk' } });

export var B = pure.B;
export var CURVE = pure.CURVE;
export var FIELD = pure.FIELD;
export var GROUP = pure.GROUP;
export var POINT = pure.POINT;
export var base_mul = base_mul_ops.async;
export var base_mul_sync = base_mul_ops.sync;
export var decode_point = decode_point_ops.async;
export var decode_point_sync = decode_point_ops.sync;
export var ed25519_h2c = scheme('ed25519_h2c', pure.ed25519_h2c, {
    encode_to_curve: { text: [0, 1] },
    hash_to_curve: { text: [0, 1] },
    hash_to_field: { text: [0, 2] }
});
export var encode_point = encode_point_ops.async;
export var encode_point_sync = encode_point_ops.sync;
export var expand_seed = expand_seed_ops.async;
export var expand_seed_sync = expand_seed_ops.sync;
export var from_x25519 = from_x25519_ops.async;
export var from_x25519_sync = from_x25519_ops.sync;
export var get_public_key = get_public_key_ops.async;
export var get_public_key_sync = get_public_key_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var sign = sign_ops.async;
export var sign_sync = sign_ops.sync;
export var sign_ctx = sign_ctx_ops.async;
export var sign_ctx_sync = sign_ctx_ops.sync;
export var sign_expanded = sign_expanded_ops.async;
export var sign_expanded_sync = sign_expanded_ops.sync;
export var sign_ph = sign_ph_ops.async;
export var sign_ph_sync = sign_ph_ops.sync;
export var signer_create = signer_ops.create;
export var to_x25519 = to_x25519_ops.async;
export var to_x25519_sync = to_x25519_ops.sync;
export var verifier_create = verifier_ops.create;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
export var verify_batch = verify_batch_ops.async;
export var verify_batch_sync = verify_batch_ops.sync;
export var verify_batch_find = verify_batch_find_ops.async;
export var verify_batch_find_sync = verify_batch_find_ops.sync;
export var verify_ctx = verify_ctx_ops.async;
export var verify_ctx_sync = verify_ctx_ops.sync;
export var verify_ph = verify_ph_ops.async;
export var verify_ph_sync = verify_ph_ops.sync;
