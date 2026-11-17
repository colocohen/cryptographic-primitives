/**
 * access, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../access.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../access.js.
 */

import * as pure from '../access.js';
import { define } from '../engines/select.js';

var authorized_ops = define('access.authorized', { sync: pure.authorized });
var canonical_ops = define('access.canonical', { sync: pure.canonical });
var check_commitments_ops = define('access.check_commitments', { sync: pure.check_commitments });
var check_points_ops = define('access.check_points', { sync: pure.check_points });
var coefficients_ops = define('access.coefficients', { sync: pure.coefficients });
var combine_ops = define('access.combine', { sync: pure.combine });
var commit_ops = define('access.commit', { sync: pure.commit });
var deal_ops = define('access.deal', { sync: pure.deal });
var integer_coefficients_ops = define('access.integer_coefficients', { sync: pure.integer_coefficients });
var integer_deal_ops = define('access.integer_deal', { sync: pure.integer_deal });
var integer_delta_ops = define('access.integer_delta', { sync: pure.integer_delta });
var integer_multiplier_ops = define('access.integer_multiplier', { sync: pure.integer_multiplier });
var leaf_point_ops = define('access.leaf_point', { sync: pure.leaf_point });
var leaves_ops = define('access.leaves', { sync: pure.leaves });
var names_ops = define('access.names', { sync: pure.names });
var repair_coefficients_ops = define('access.repair_coefficients', { sync: pure.repair_coefficients });
var select_ops = define('access.select', { sync: pure.select });
var verify_leaf_ops = define('access.verify_leaf', { sync: pure.verify_leaf });

export var authorized = authorized_ops.async;
export var authorized_sync = authorized_ops.sync;
export var canonical = canonical_ops.async;
export var canonical_sync = canonical_ops.sync;
export var check_commitments = check_commitments_ops.async;
export var check_commitments_sync = check_commitments_ops.sync;
export var check_points = check_points_ops.async;
export var check_points_sync = check_points_ops.sync;
export var coefficients = coefficients_ops.async;
export var coefficients_sync = coefficients_ops.sync;
export var combine = combine_ops.async;
export var combine_sync = combine_ops.sync;
export var commit = commit_ops.async;
export var commit_sync = commit_ops.sync;
export var deal = deal_ops.async;
export var deal_sync = deal_ops.sync;
export var integer_coefficients = integer_coefficients_ops.async;
export var integer_coefficients_sync = integer_coefficients_ops.sync;
export var integer_deal = integer_deal_ops.async;
export var integer_deal_sync = integer_deal_ops.sync;
export var integer_delta = integer_delta_ops.async;
export var integer_delta_sync = integer_delta_ops.sync;
export var integer_multiplier = integer_multiplier_ops.async;
export var integer_multiplier_sync = integer_multiplier_ops.sync;
export var leaf_point = leaf_point_ops.async;
export var leaf_point_sync = leaf_point_ops.sync;
export var leaves = leaves_ops.async;
export var leaves_sync = leaves_ops.sync;
export var names = names_ops.async;
export var names_sync = names_ops.sync;
export var repair_coefficients = repair_coefficients_ops.async;
export var repair_coefficients_sync = repair_coefficients_ops.sync;
export var select = select_ops.async;
export var select_sync = select_ops.sync;
export var verify_leaf = verify_leaf_ops.async;
export var verify_leaf_sync = verify_leaf_ops.sync;
