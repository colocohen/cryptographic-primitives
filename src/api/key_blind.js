/**
 * key_blind, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../key_blind.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../key_blind.js.
 */

import * as pure from '../key_blind.js';
import { define, scheme } from '../engines/select.js';

var blind_public_key_ops = define('key_blind.blind_public_key', { sync: pure.blind_public_key, text: [2], bytes: { 0: 'pk' } });
var blind_public_key_from_seed_ops = define('key_blind.blind_public_key_from_seed', { sync: pure.blind_public_key_from_seed, text: [2], bytes: { 0: 'seed' } });
var blind_sign_ops = define('key_blind.blind_sign', { sync: pure.blind_sign, text: [2, 3], bytes: { 0: 'seed' } });
var blinding_scalar_ops = define('key_blind.blinding_scalar', { sync: pure.blinding_scalar, text: [2] });
var ecdsa_blind_public_key_ops = define('key_blind.ecdsa_blind_public_key', { sync: pure.ecdsa_blind_public_key, text: [3], bytes: { 1: 'pk' } });
var ecdsa_blind_secret_ops = define('key_blind.ecdsa_blind_secret', { sync: pure.ecdsa_blind_secret, text: [3], bytes: { 1: 'sk' } });
var ecdsa_blind_sign_ops = define('key_blind.ecdsa_blind_sign', { sync: pure.ecdsa_blind_sign, text: [3, 4], bytes: { 1: 'sk', 5: 'extra' } });
var ecdsa_unblind_public_key_ops = define('key_blind.ecdsa_unblind_public_key', { sync: pure.ecdsa_unblind_public_key, text: [3] });
var unblind_public_key_ops = define('key_blind.unblind_public_key', { sync: pure.unblind_public_key, text: [2] });

export var ECDSA_P256 = scheme('ECDSA_P256', pure.ECDSA_P256, {
    hash: { text: [0] }
});
export var ECDSA_P384 = scheme('ECDSA_P384', pure.ECDSA_P384, {
    hash: { text: [0] }
});
export var ED25519 = scheme('ED25519', pure.ED25519, {
    blind_public_key: { text: [2], bytes: { 0: 'pk' } },
    blind_public_key_from_seed: { text: [2], bytes: { 0: 'seed' } },
    blind_sign: { text: [2, 3], bytes: { 0: 'seed' } },
    scalar: { text: [1] },
    unblind_public_key: { text: [2] }
});
export var ED448 = scheme('ED448', pure.ED448, {
    blind_public_key: { text: [2], bytes: { 0: 'pk' } },
    blind_public_key_from_seed: { text: [2], bytes: { 0: 'seed' } },
    blind_sign: { text: [2, 3], bytes: { 0: 'seed' } },
    scalar: { text: [1] },
    unblind_public_key: { text: [2] }
});
export var blind_public_key = blind_public_key_ops.async;
export var blind_public_key_sync = blind_public_key_ops.sync;
export var blind_public_key_from_seed = blind_public_key_from_seed_ops.async;
export var blind_public_key_from_seed_sync = blind_public_key_from_seed_ops.sync;
export var blind_sign = blind_sign_ops.async;
export var blind_sign_sync = blind_sign_ops.sync;
export var blinding_scalar = blinding_scalar_ops.async;
export var blinding_scalar_sync = blinding_scalar_ops.sync;
export var ecdsa_blind_public_key = ecdsa_blind_public_key_ops.async;
export var ecdsa_blind_public_key_sync = ecdsa_blind_public_key_ops.sync;
export var ecdsa_blind_secret = ecdsa_blind_secret_ops.async;
export var ecdsa_blind_secret_sync = ecdsa_blind_secret_ops.sync;
export var ecdsa_blind_sign = ecdsa_blind_sign_ops.async;
export var ecdsa_blind_sign_sync = ecdsa_blind_sign_ops.sync;
export var ecdsa_unblind_public_key = ecdsa_unblind_public_key_ops.async;
export var ecdsa_unblind_public_key_sync = ecdsa_unblind_public_key_ops.sync;
export var unblind_public_key = unblind_public_key_ops.async;
export var unblind_public_key_sync = unblind_public_key_ops.sync;
