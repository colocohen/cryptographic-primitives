/**
 * secp256k1, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../secp256k1.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../secp256k1.js.
 */

import * as pure from '../secp256k1.js';
import { define, scheme } from '../engines/select.js';

var base_mul_ops = define('secp256k1.base_mul', { sync: pure.base_mul });
var bip340_challenge_ops = define('secp256k1.bip340_challenge', { sync: pure.bip340_challenge, text: [2] });
var decode_point_ops = define('secp256k1.decode_point', { sync: pure.decode_point });
var ecdh_ops = define('secp256k1.ecdh', { sync: pure.ecdh, bytes: { 1: 'peer_public_key' } });
var encode_point_ops = define('secp256k1.encode_point', { sync: pure.encode_point });
var get_public_key_ops = define('secp256k1.get_public_key', { sync: pure.get_public_key });
var keygen_ops = define('secp256k1.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });
var is_valid_secret_ops = define('secp256k1.is_valid_secret', { sync: pure.is_valid_secret });
var lift_x_even_ops = define('secp256k1.lift_x_even', { sync: pure.lift_x_even });
var mul_vartime_ops = define('secp256k1.mul_vartime', { sync: pure.mul_vartime });
var normalize_s_ops = define('secp256k1.normalize_s', { sync: pure.normalize_s });
var private_key_from_der_ops = define('secp256k1.private_key_from_der', { sync: pure.private_key_from_der });
var private_key_to_der_ops = define('secp256k1.private_key_to_der', { sync: pure.private_key_to_der });
var recover_ops = define('secp256k1.recover', { sync: pure.recover, bytes: { 0: 'msg_hash', 1: 'sig' } });
var recovery_id_ops = define('secp256k1.recovery_id', { sync: pure.recovery_id });
var schnorr_get_public_key_ops = define('secp256k1.schnorr_get_public_key', { sync: pure.schnorr_get_public_key });
var schnorr_keygen_ops = define('secp256k1.schnorr_keygen', { sync: pure.schnorr_keygen, bytes: { 0: 'seed' } });
var schnorr_sign_ops = define('secp256k1.schnorr_sign', { sync: pure.schnorr_sign, text: [0], bytes: { 2: 'aux' } });
var schnorr_verify_ops = define('secp256k1.schnorr_verify', { sync: pure.schnorr_verify, text: [0], bytes: { 1: 'sig', 2: 'public_key' } });
var schnorr_verify_batch_ops = define('secp256k1.schnorr_verify_batch', { sync: pure.schnorr_verify_batch, text: [0] });
var schnorr_verify_batch_find_ops = define('secp256k1.schnorr_verify_batch_find', { sync: pure.schnorr_verify_batch_find, text: [0] });
var sig_from_compact_ops = define('secp256k1.sig_from_compact', { sync: pure.sig_from_compact });
var sig_from_der_ops = define('secp256k1.sig_from_der', { sync: pure.sig_from_der });
var sig_to_compact_ops = define('secp256k1.sig_to_compact', { sync: pure.sig_to_compact, bytes: { 0: 'sig' } });
var sig_to_der_ops = define('secp256k1.sig_to_der', { sync: pure.sig_to_der, bytes: { 0: 'sig' } });
var sign_ops = define('secp256k1.sign', { sync: pure.sign, bytes: { 0: 'msg_hash', 2: 'extra' } });
var tagged_hash_ops = define('secp256k1.tagged_hash', { sync: pure.tagged_hash, bytes: { 0: 'tag' } });
var verify_ops = define('secp256k1.verify', { sync: pure.verify, bytes: { 0: 'msg_hash', 1: 'sig', 2: 'public_key' } });

var sign_message_ops = define('secp256k1.sign_message', { sync: pure.sign_message, text: [1], bytes: { 3: 'extra' } });
var signer_ops = define('secp256k1.signer_create', { create: pure.signer_create, kind: 'ecdsa_signer', create_bytes: { 0: 'secret' } });
var verifier_ops = define('secp256k1.verifier_create', { create: pure.verifier_create, kind: 'ecdsa_verifier', create_bytes: { 0: 'public_key' } });
var verify_message_ops = define('secp256k1.verify_message', { sync: pure.verify_message, text: [1], bytes: { 2: 'sig', 3: 'public_key' } });
export var CURVE = pure.CURVE;
export var FIELD = pure.FIELD;
export var G = pure.G;
export var GROUP = pure.GROUP;
export var POINT = pure.POINT;
export var SCALAR = scheme('SCALAR', pure.SCALAR);
export var base_mul = base_mul_ops.async;
export var base_mul_sync = base_mul_ops.sync;
export var bip340_challenge = bip340_challenge_ops.async;
export var bip340_challenge_sync = bip340_challenge_ops.sync;
export var decode_point = decode_point_ops.async;
export var decode_point_sync = decode_point_ops.sync;
export var ecdh = ecdh_ops.async;
export var ecdh_sync = ecdh_ops.sync;
export var encode_point = encode_point_ops.async;
export var encode_point_sync = encode_point_ops.sync;
export var get_public_key = get_public_key_ops.async;
export var get_public_key_sync = get_public_key_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var is_valid_secret = is_valid_secret_ops.async;
export var is_valid_secret_sync = is_valid_secret_ops.sync;
export var lift_x_even = lift_x_even_ops.async;
export var lift_x_even_sync = lift_x_even_ops.sync;
export var mul_vartime = mul_vartime_ops.async;
export var mul_vartime_sync = mul_vartime_ops.sync;
export var normalize_s = normalize_s_ops.async;
export var normalize_s_sync = normalize_s_ops.sync;
export var private_key_from_der = private_key_from_der_ops.async;
export var private_key_from_der_sync = private_key_from_der_ops.sync;
export var private_key_to_der = private_key_to_der_ops.async;
export var private_key_to_der_sync = private_key_to_der_ops.sync;
export var recover = recover_ops.async;
export var recover_sync = recover_ops.sync;
export var recovery_id = recovery_id_ops.async;
export var recovery_id_sync = recovery_id_ops.sync;
export var schnorr_get_public_key = schnorr_get_public_key_ops.async;
export var schnorr_get_public_key_sync = schnorr_get_public_key_ops.sync;
export var schnorr_keygen = schnorr_keygen_ops.async;
export var schnorr_keygen_sync = schnorr_keygen_ops.sync;
export var schnorr_sign = schnorr_sign_ops.async;
export var schnorr_sign_sync = schnorr_sign_ops.sync;
export var schnorr_verify = schnorr_verify_ops.async;
export var schnorr_verify_sync = schnorr_verify_ops.sync;
export var schnorr_verify_batch = schnorr_verify_batch_ops.async;
export var schnorr_verify_batch_sync = schnorr_verify_batch_ops.sync;
export var schnorr_verify_batch_find = schnorr_verify_batch_find_ops.async;
export var schnorr_verify_batch_find_sync = schnorr_verify_batch_find_ops.sync;
export var secp256k1_h2c = scheme('secp256k1_h2c', pure.secp256k1_h2c, {
    encode_to_curve: { text: [0, 1] },
    hash_to_curve: { text: [0, 1] },
    hash_to_field: { text: [0, 2] }
});
export var sig_from_compact = sig_from_compact_ops.async;
export var sig_from_compact_sync = sig_from_compact_ops.sync;
export var sig_from_der = sig_from_der_ops.async;
export var sig_from_der_sync = sig_from_der_ops.sync;
export var sig_to_compact = sig_to_compact_ops.async;
export var sig_to_compact_sync = sig_to_compact_ops.sync;
export var sig_to_der = sig_to_der_ops.async;
export var sig_to_der_sync = sig_to_der_ops.sync;
export var sign = sign_ops.async;
export var sign_sync = sign_ops.sync;
export var tagged_hash = tagged_hash_ops.async;
export var tagged_hash_sync = tagged_hash_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
export var sign_message = sign_message_ops.async;
export var sign_message_sync = sign_message_ops.sync;
export var verify_message = verify_message_ops.async;
export var verify_message_sync = verify_message_ops.sync;

/* signer_create(secret): one secret for many ECDSA signatures - sign, sign_message, wipe() */
export var signer_create = signer_ops.create;
/* verifier_create(public_key): one public key for many ECDSA verifications - verify, verify_message */
export var verifier_create = verifier_ops.create;
