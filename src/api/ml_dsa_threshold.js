/**
 * ml_dsa_threshold, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ml_dsa_threshold.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ml_dsa_threshold.js.
 */

import * as pure from '../ml_dsa_threshold.js';
import { define } from '../engines/select.js';

var budget_of_ops = define('ml_dsa_threshold.budget_of', { sync: pure.budget_of });
var challenge_ops = define('ml_dsa_threshold.challenge', { sync: pure.challenge });
var combine_ops = define('ml_dsa_threshold.combine', { sync: pure.combine, bytes: { 1: 'pk' } });
var commit_ops = define('ml_dsa_threshold.commit', { sync: pure.commit });
var deal_ops = define('ml_dsa_threshold.deal', { sync: pure.deal });
var deal_existing_ops = define('ml_dsa_threshold.deal_existing', { sync: pure.deal_existing, bytes: { 1: 'sk' } });
var minimal_sets_ops = define('ml_dsa_threshold.minimal_sets', { sync: pure.minimal_sets });
var params_ops = define('ml_dsa_threshold.params', { sync: pure.params });
var params_for_ops = define('ml_dsa_threshold.params_for', { sync: pure.params_for });
var partial_secret_ops = define('ml_dsa_threshold.partial_secret', { sync: pure.partial_secret });
var partition_ops = define('ml_dsa_threshold.partition', { sync: pure.partition });
var policy_family_ops = define('ml_dsa_threshold.policy_family', { sync: pure.policy_family });
var public_condition_ops = define('ml_dsa_threshold.public_condition', { sync: pure.public_condition });
var response_residual_ops = define('ml_dsa_threshold.response_residual', { sync: pure.response_residual });
var round1_ops = define('ml_dsa_threshold.round1', { sync: pure.round1 });
var round3_ops = define('ml_dsa_threshold.round3', { sync: pure.round3 });
var set_name_ops = define('ml_dsa_threshold.set_name', { sync: pure.set_name });
var signable_ops = define('ml_dsa_threshold.signable', { sync: pure.signable });
var structure_ops = define('ml_dsa_threshold.structure', { sync: pure.structure });
var subsets_ops = define('ml_dsa_threshold.subsets', { sync: pure.subsets });
var sum_commitments_ops = define('ml_dsa_threshold.sum_commitments', { sync: pure.sum_commitments });
var sum_parts_hat_ops = define('ml_dsa_threshold.sum_parts_hat', { sync: pure.sum_parts_hat });
var t0_from_parts_ops = define('ml_dsa_threshold.t0_from_parts', { sync: pure.t0_from_parts, bytes: { 2: 'pk' } });
var threshold_family_ops = define('ml_dsa_threshold.threshold_family', { sync: pure.threshold_family });
var wide_set_ops = define('ml_dsa_threshold.wide_set', { sync: pure.wide_set });

export var BUDGETS = pure.BUDGETS;
export var DEFAULT_BUDGET = pure.DEFAULT_BUDGET;
export var DSA = pure.DSA;
export var MAX_ATTEMPT_BYTES = pure.MAX_ATTEMPT_BYTES;
export var budget_of = budget_of_ops.async;
export var budget_of_sync = budget_of_ops.sync;
export var challenge = challenge_ops.async;
export var challenge_sync = challenge_ops.sync;
export var combine = combine_ops.async;
export var combine_sync = combine_ops.sync;
export var commit = commit_ops.async;
export var commit_sync = commit_ops.sync;
export var deal = deal_ops.async;
export var deal_sync = deal_ops.sync;
export var deal_existing = deal_existing_ops.async;
export var deal_existing_sync = deal_existing_ops.sync;
export var minimal_sets = minimal_sets_ops.async;
export var minimal_sets_sync = minimal_sets_ops.sync;
export var params = params_ops.async;
export var params_sync = params_ops.sync;
export var params_for = params_for_ops.async;
export var params_for_sync = params_for_ops.sync;
export var partial_secret = partial_secret_ops.async;
export var partial_secret_sync = partial_secret_ops.sync;
export var partition = partition_ops.async;
export var partition_sync = partition_ops.sync;
export var policy_family = policy_family_ops.async;
export var policy_family_sync = policy_family_ops.sync;
export var public_condition = public_condition_ops.async;
export var public_condition_sync = public_condition_ops.sync;
export var response_residual = response_residual_ops.async;
export var response_residual_sync = response_residual_ops.sync;
export var round1 = round1_ops.async;
export var round1_sync = round1_ops.sync;
export var round3 = round3_ops.async;
export var round3_sync = round3_ops.sync;
export var set_name = set_name_ops.async;
export var set_name_sync = set_name_ops.sync;
export var signable = signable_ops.async;
export var signable_sync = signable_ops.sync;
export var structure = structure_ops.async;
export var structure_sync = structure_ops.sync;
export var subsets = subsets_ops.async;
export var subsets_sync = subsets_ops.sync;
export var sum_commitments = sum_commitments_ops.async;
export var sum_commitments_sync = sum_commitments_ops.sync;
export var sum_parts_hat = sum_parts_hat_ops.async;
export var sum_parts_hat_sync = sum_parts_hat_ops.sync;
export var t0_from_parts = t0_from_parts_ops.async;
export var t0_from_parts_sync = t0_from_parts_ops.sync;
export var threshold_family = threshold_family_ops.async;
export var threshold_family_sync = threshold_family_ops.sync;
export var wide_set = wide_set_ops.async;
export var wide_set_sync = wide_set_ops.sync;
