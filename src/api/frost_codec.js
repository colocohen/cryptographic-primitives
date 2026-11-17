/**
 * frost_codec, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../frost_codec.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../frost_codec.js.
 */

import * as pure from '../frost_codec.js';
import { define } from '../engines/select.js';

var H1_ops = define('H1', { sync: pure.H1, text: [1] });
var H2_ops = define('H2', { sync: pure.H2, text: [1] });
var H3_ops = define('H3', { sync: pure.H3, text: [1] });
var H4_ops = define('H4', { sync: pure.H4, text: [1] });
var H5_ops = define('H5', { sync: pure.H5, text: [1] });
var binding_factor_input_ops = define('frost_codec.binding_factor_input', { sync: pure.binding_factor_input, text: [2] });
var compute_binding_factors_ops = define('frost_codec.compute_binding_factors', { sync: pure.compute_binding_factors, text: [2] });
var compute_challenge_ops = define('frost_codec.compute_challenge', { sync: pure.compute_challenge, text: [3] });
var derive_interpolating_value_ops = define('frost_codec.derive_interpolating_value', { sync: pure.derive_interpolating_value });
var deserialize_scalar_ops = define('frost_codec.deserialize_scalar', { sync: pure.deserialize_scalar });
var deserialize_signature_ops = define('frost_codec.deserialize_signature', { sync: pure.deserialize_signature });
var encode_group_commitment_list_ops = define('frost_codec.encode_group_commitment_list', { sync: pure.encode_group_commitment_list });
var hash_to_scalar_labelled_ops = define('frost_codec.hash_to_scalar_labelled', { sync: pure.hash_to_scalar_labelled, text: [1, 2] });
var invert_ops = define('frost_codec.invert', { sync: pure.invert });
var mod_ops = define('frost_codec.mod', { sync: pure.mod });
var randomizer_from_seed_ops = define('frost_codec.randomizer_from_seed', { sync: pure.randomizer_from_seed, bytes: { 1: 'seed' } });
var serialize_scalar_ops = define('frost_codec.serialize_scalar', { sync: pure.serialize_scalar });
var serialize_signature_ops = define('frost_codec.serialize_signature', { sync: pure.serialize_signature });
var suite_ops = define('frost_codec.suite', { sync: pure.suite });

export var CIPHERSUITES = pure.CIPHERSUITES;
export var H1 = H1_ops.async;
export var H1_sync = H1_ops.sync;
export var H2 = H2_ops.async;
export var H2_sync = H2_ops.sync;
export var H3 = H3_ops.async;
export var H3_sync = H3_ops.sync;
export var H4 = H4_ops.async;
export var H4_sync = H4_ops.sync;
export var H5 = H5_ops.async;
export var H5_sync = H5_ops.sync;
export var binding_factor_input = binding_factor_input_ops.async;
export var binding_factor_input_sync = binding_factor_input_ops.sync;
export var compute_binding_factors = compute_binding_factors_ops.async;
export var compute_binding_factors_sync = compute_binding_factors_ops.sync;
export var compute_challenge = compute_challenge_ops.async;
export var compute_challenge_sync = compute_challenge_ops.sync;
export var derive_interpolating_value = derive_interpolating_value_ops.async;
export var derive_interpolating_value_sync = derive_interpolating_value_ops.sync;
export var deserialize_scalar = deserialize_scalar_ops.async;
export var deserialize_scalar_sync = deserialize_scalar_ops.sync;
export var deserialize_signature = deserialize_signature_ops.async;
export var deserialize_signature_sync = deserialize_signature_ops.sync;
export var encode_group_commitment_list = encode_group_commitment_list_ops.async;
export var encode_group_commitment_list_sync = encode_group_commitment_list_ops.sync;
export var hash_to_scalar_labelled = hash_to_scalar_labelled_ops.async;
export var hash_to_scalar_labelled_sync = hash_to_scalar_labelled_ops.sync;
export var invert = invert_ops.async;
export var invert_sync = invert_ops.sync;
export var mod = mod_ops.async;
export var mod_sync = mod_ops.sync;
export var randomizer_from_seed = randomizer_from_seed_ops.async;
export var randomizer_from_seed_sync = randomizer_from_seed_ops.sync;
export var serialize_scalar = serialize_scalar_ops.async;
export var serialize_scalar_sync = serialize_scalar_ops.sync;
export var serialize_signature = serialize_signature_ops.async;
export var serialize_signature_sync = serialize_signature_ops.sync;
export var suite = suite_ops.async;
export var suite_sync = suite_ops.sync;
