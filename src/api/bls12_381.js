/**
 * bls12_381, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../bls12_381.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../bls12_381.js.
 */

import * as pure from '../bls12_381.js';
import { define, scheme } from '../engines/select.js';

var _clear_cofactor_g2_for_tests_ops = define('bls12_381._clear_cofactor_g2_for_tests', { sync: pure._clear_cofactor_g2_for_tests });
var aggregate_public_keys_ops = define('bls12_381.aggregate_public_keys', { sync: pure.aggregate_public_keys });
var aggregate_public_keys_short_ops = define('bls12_381.aggregate_public_keys_short', { sync: pure.aggregate_public_keys_short });
var aggregate_signatures_ops = define('bls12_381.aggregate_signatures', { sync: pure.aggregate_signatures });
var aggregate_signatures_short_ops = define('bls12_381.aggregate_signatures_short', { sync: pure.aggregate_signatures_short });
var aggregate_verify_ops = define('bls12_381.aggregate_verify', { sync: pure.aggregate_verify, text: [0, 3], bytes: { 1: 'sig' } });
var batch_verify_ops = define('bls12_381.batch_verify', { sync: pure.batch_verify, text: [0, 4] });
var combine_weighted_ops = define('bls12_381.combine_weighted', { sync: pure.combine_weighted });
var compress_point_g1_ops = define('bls12_381.compress_point_g1', { sync: pure.compress_point_g1 });
var compress_point_g2_ops = define('bls12_381.compress_point_g2', { sync: pure.compress_point_g2 });
var decompress_point_g1_ops = define('bls12_381.decompress_point_g1', { sync: pure.decompress_point_g1 });
var decompress_point_g2_ops = define('bls12_381.decompress_point_g2', { sync: pure.decompress_point_g2 });
var dkg_combine_shares_ops = define('bls12_381.dkg_combine_shares', { sync: pure.dkg_combine_shares });
var dkg_group_public_key_ops = define('bls12_381.dkg_group_public_key', { sync: pure.dkg_group_public_key });
var fast_aggregate_verify_ops = define('bls12_381.fast_aggregate_verify', { sync: pure.fast_aggregate_verify, text: [0, 3], bytes: { 1: 'sig' } });
var fast_aggregate_verify_short_ops = define('bls12_381.fast_aggregate_verify_short', { sync: pure.fast_aggregate_verify_short, text: [0, 3], bytes: { 1: 'sig' } });
var get_public_key_ops = define('bls12_381.get_public_key', { sync: pure.get_public_key });
var get_public_key_short_ops = define('bls12_381.get_public_key_short', { sync: pure.get_public_key_short });
var hash_to_g1_ops = define('bls12_381.hash_to_g1', { sync: pure.hash_to_g1, text: [0, 1] });
var hash_to_g2_ops = define('bls12_381.hash_to_g2', { sync: pure.hash_to_g2, text: [0, 1] });
var prove_possession_ops = define('bls12_381.prove_possession', { sync: pure.prove_possession });
var prove_possession_short_ops = define('bls12_381.prove_possession_short', { sync: pure.prove_possession_short });
var share_public_key_ops = define('bls12_381.share_public_key', { sync: pure.share_public_key });
var sign_ops = define('bls12_381.sign', { sync: pure.sign, text: [0, 2] });
var sign_short_ops = define('bls12_381.sign_short', { sync: pure.sign_short, text: [0, 2] });
var split_secret_ops = define('bls12_381.split_secret', { sync: pure.split_secret });
var threshold_combine_ops = define('bls12_381.threshold_combine', { sync: pure.threshold_combine });
var threshold_public_key_ops = define('bls12_381.threshold_public_key', { sync: pure.threshold_public_key });
var threshold_sign_ops = define('bls12_381.threshold_sign', { sync: pure.threshold_sign, text: [0, 2] });
var verify_ops = define('bls12_381.verify', { sync: pure.verify, text: [0, 3], bytes: { 1: 'sig', 2: 'public_key' } });
var verify_possession_ops = define('bls12_381.verify_possession', { sync: pure.verify_possession, bytes: { 0: 'public_key' } });
var verify_possession_short_ops = define('bls12_381.verify_possession_short', { sync: pure.verify_possession_short, bytes: { 0: 'public_key' } });
var verify_short_ops = define('bls12_381.verify_short', { sync: pure.verify_short, text: [0, 3], bytes: { 1: 'sig', 2: 'public_key' } });
var vss_deal_ops = define('bls12_381.vss_deal', { sync: pure.vss_deal });
var vss_eval_g1_ops = define('bls12_381.vss_eval_g1', { sync: pure.vss_eval_g1 });
var vss_verify_share_ops = define('bls12_381.vss_verify_share', { sync: pure.vss_verify_share });
var keygen_ops = define('bls12_381.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });

export var BASE1 = pure.BASE1;
export var BASE2 = pure.BASE2;
export var CURVE = pure.CURVE;
export var DST_POP = pure.DST_POP;
export var DST_POP_SHORT = pure.DST_POP_SHORT;
export var FIELD = pure.FIELD;
export var FIELD12 = pure.FIELD12;
export var FIELD2 = pure.FIELD2;
export var GROUP_G1 = scheme('GROUP_G1', pure.GROUP_G1, {
    hash_to_scalar: { text: [0] }
});
export var PAIRING = scheme('PAIRING', pure.PAIRING);
export var POINT1 = scheme('POINT1', pure.POINT1);
export var POINT2 = scheme('POINT2', pure.POINT2);
export var _clear_cofactor_g2_for_tests = _clear_cofactor_g2_for_tests_ops.async;
export var _clear_cofactor_g2_for_tests_sync = _clear_cofactor_g2_for_tests_ops.sync;
export var aggregate_public_keys = aggregate_public_keys_ops.async;
export var aggregate_public_keys_sync = aggregate_public_keys_ops.sync;
export var aggregate_public_keys_short = aggregate_public_keys_short_ops.async;
export var aggregate_public_keys_short_sync = aggregate_public_keys_short_ops.sync;
export var aggregate_signatures = aggregate_signatures_ops.async;
export var aggregate_signatures_sync = aggregate_signatures_ops.sync;
export var aggregate_signatures_short = aggregate_signatures_short_ops.async;
export var aggregate_signatures_short_sync = aggregate_signatures_short_ops.sync;
export var aggregate_verify = aggregate_verify_ops.async;
export var aggregate_verify_sync = aggregate_verify_ops.sync;
export var batch_verify = batch_verify_ops.async;
export var batch_verify_sync = batch_verify_ops.sync;
export var combine_weighted = combine_weighted_ops.async;
export var combine_weighted_sync = combine_weighted_ops.sync;
export var compress_point_g1 = compress_point_g1_ops.async;
export var compress_point_g1_sync = compress_point_g1_ops.sync;
export var compress_point_g2 = compress_point_g2_ops.async;
export var compress_point_g2_sync = compress_point_g2_ops.sync;
export var decompress_point_g1 = decompress_point_g1_ops.async;
export var decompress_point_g1_sync = decompress_point_g1_ops.sync;
export var decompress_point_g2 = decompress_point_g2_ops.async;
export var decompress_point_g2_sync = decompress_point_g2_ops.sync;
export var dkg_combine_shares = dkg_combine_shares_ops.async;
export var dkg_combine_shares_sync = dkg_combine_shares_ops.sync;
export var dkg_group_public_key = dkg_group_public_key_ops.async;
export var dkg_group_public_key_sync = dkg_group_public_key_ops.sync;
export var fast_aggregate_verify = fast_aggregate_verify_ops.async;
export var fast_aggregate_verify_sync = fast_aggregate_verify_ops.sync;
export var fast_aggregate_verify_short = fast_aggregate_verify_short_ops.async;
export var fast_aggregate_verify_short_sync = fast_aggregate_verify_short_ops.sync;
export var get_public_key = get_public_key_ops.async;
export var get_public_key_sync = get_public_key_ops.sync;
export var get_public_key_short = get_public_key_short_ops.async;
export var get_public_key_short_sync = get_public_key_short_ops.sync;
export var hash_to_g1 = hash_to_g1_ops.async;
export var hash_to_g1_sync = hash_to_g1_ops.sync;
export var hash_to_g2 = hash_to_g2_ops.async;
export var hash_to_g2_sync = hash_to_g2_ops.sync;
export var prove_possession = prove_possession_ops.async;
export var prove_possession_sync = prove_possession_ops.sync;
export var prove_possession_short = prove_possession_short_ops.async;
export var prove_possession_short_sync = prove_possession_short_ops.sync;
export var share_public_key = share_public_key_ops.async;
export var share_public_key_sync = share_public_key_ops.sync;
export var sign = sign_ops.async;
export var sign_sync = sign_ops.sync;
export var sign_short = sign_short_ops.async;
export var sign_short_sync = sign_short_ops.sync;
export var split_secret = split_secret_ops.async;
export var split_secret_sync = split_secret_ops.sync;
export var threshold_combine = threshold_combine_ops.async;
export var threshold_combine_sync = threshold_combine_ops.sync;
export var threshold_public_key = threshold_public_key_ops.async;
export var threshold_public_key_sync = threshold_public_key_ops.sync;
export var threshold_sign = threshold_sign_ops.async;
export var threshold_sign_sync = threshold_sign_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
export var verify_possession = verify_possession_ops.async;
export var verify_possession_sync = verify_possession_ops.sync;
export var verify_possession_short = verify_possession_short_ops.async;
export var verify_possession_short_sync = verify_possession_short_ops.sync;
export var verify_short = verify_short_ops.async;
export var verify_short_sync = verify_short_ops.sync;
export var vss_deal = vss_deal_ops.async;
export var vss_deal_sync = vss_deal_ops.sync;
export var vss_eval_g1 = vss_eval_g1_ops.async;
export var vss_eval_g1_sync = vss_eval_g1_ops.sync;
export var vss_verify_share = vss_verify_share_ops.async;
export var vss_verify_share_sync = vss_verify_share_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
