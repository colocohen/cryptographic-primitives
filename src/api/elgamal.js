/**
 * elgamal, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../elgamal.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../elgamal.js.
 */

import * as pure from '../elgamal.js';
import { define } from '../engines/select.js';

var add_encrypted_ops = define('elgamal.add_encrypted', { sync: pure.add_encrypted });
var combine_shares_ops = define('elgamal.combine_shares', { sync: pure.combine_shares });
var decrypt_ops = define('elgamal.decrypt', { sync: pure.decrypt });
var decrypt_share_ops = define('elgamal.decrypt_share', { sync: pure.decrypt_share });
var encrypt_ops = define('elgamal.encrypt', { sync: pure.encrypt, bytes: { 1: 'publicKey' } });
var encrypt_number_ops = define('elgamal.encrypt_number', { sync: pure.encrypt_number, bytes: { 1: 'publicKey' } });
var encrypt_number_proved_ops = define('elgamal.encrypt_number_proved', { sync: pure.encrypt_number_proved, text: [5], bytes: { 1: 'publicKey' } });
var encrypt_with_randomness_ops = define('elgamal.encrypt_with_randomness', { sync: pure.encrypt_with_randomness, bytes: { 1: 'publicKey' } });
var interpolate_points_ops = define('elgamal.interpolate_points', { sync: pure.interpolate_points });
var keygen_ops = define('elgamal.keygen', { sync: pure.keygen });
var open_with_point_ops = define('elgamal.open_with_point', { sync: pure.open_with_point, text: [3], bytes: { 2: 'sealed' } });
var prove_in_range_ops = define('elgamal.prove_in_range', { sync: pure.prove_in_range, text: [7], bytes: { 1: 'publicKey', 2: 'ct' } });
var prove_share_ops = define('elgamal.prove_share', { sync: pure.prove_share, text: [4] });
var recover_number_ops = define('elgamal.recover_number', { sync: pure.recover_number });
var seal_to_threshold_ops = define('elgamal.seal_to_threshold', { sync: pure.seal_to_threshold, text: [2, 4], bytes: { 1: 'publicKey' } });
var verify_in_range_ops = define('elgamal.verify_in_range', { sync: pure.verify_in_range, text: [5], bytes: { 1: 'publicKey', 2: 'ct' } });
var verify_sealed_ops = define('elgamal.verify_sealed', { sync: pure.verify_sealed, text: [3], bytes: { 1: 'publicKey', 2: 'sealed' } });
var verify_share_ops = define('elgamal.verify_share', { sync: pure.verify_share, text: [5] });

export var RECOVER_MAX = pure.RECOVER_MAX;
export var add_encrypted = add_encrypted_ops.async;
export var add_encrypted_sync = add_encrypted_ops.sync;
export var combine_shares = combine_shares_ops.async;
export var combine_shares_sync = combine_shares_ops.sync;
export var decrypt = decrypt_ops.async;
export var decrypt_sync = decrypt_ops.sync;
export var decrypt_share = decrypt_share_ops.async;
export var decrypt_share_sync = decrypt_share_ops.sync;
export var encrypt = encrypt_ops.async;
export var encrypt_sync = encrypt_ops.sync;
export var encrypt_number = encrypt_number_ops.async;
export var encrypt_number_sync = encrypt_number_ops.sync;
export var encrypt_number_proved = encrypt_number_proved_ops.async;
export var encrypt_number_proved_sync = encrypt_number_proved_ops.sync;
export var encrypt_with_randomness = encrypt_with_randomness_ops.async;
export var encrypt_with_randomness_sync = encrypt_with_randomness_ops.sync;
export var interpolate_points = interpolate_points_ops.async;
export var interpolate_points_sync = interpolate_points_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var open_with_point = open_with_point_ops.async;
export var open_with_point_sync = open_with_point_ops.sync;
export var prove_in_range = prove_in_range_ops.async;
export var prove_in_range_sync = prove_in_range_ops.sync;
export var prove_share = prove_share_ops.async;
export var prove_share_sync = prove_share_ops.sync;
export var recover_number = recover_number_ops.async;
export var recover_number_sync = recover_number_ops.sync;
export var seal_to_threshold = seal_to_threshold_ops.async;
export var seal_to_threshold_sync = seal_to_threshold_ops.sync;
export var verify_in_range = verify_in_range_ops.async;
export var verify_in_range_sync = verify_in_range_ops.sync;
export var verify_sealed = verify_sealed_ops.async;
export var verify_sealed_sync = verify_sealed_ops.sync;
export var verify_share = verify_share_ops.async;
export var verify_share_sync = verify_share_ops.sync;
