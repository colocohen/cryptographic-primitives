/**
 * shamir, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../shamir.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../shamir.js.
 */

import * as pure from '../shamir.js';
import { define } from '../engines/select.js';

var combine_ops = define('shamir.combine', { sync: pure.combine });
var combine_bytes_ops = define('shamir.combine_bytes', { sync: pure.combine_bytes });
var combine_points_ops = define('shamir.combine_points', { sync: pure.combine_points });
var evaluate_ops = define('shamir.evaluate', { sync: pure.evaluate });
var lagrange_at_zero_ops = define('shamir.lagrange_at_zero', { sync: pure.lagrange_at_zero });
var lagrange_coeffs_at_zero_ops = define('shamir.lagrange_coeffs_at_zero', { sync: pure.lagrange_coeffs_at_zero });
var lagrange_integer_at_zero_ops = define('shamir.lagrange_integer_at_zero', { sync: pure.lagrange_integer_at_zero });
var polynomial_ops = define('shamir.polynomial', { sync: pure.polynomial });
var split_ops = define('shamir.split', { sync: pure.split });
var split_bytes_ops = define('shamir.split_bytes', { sync: pure.split_bytes });

export var P256_PRIME = pure.P256_PRIME;
export var combine = combine_ops.async;
export var combine_sync = combine_ops.sync;
export var combine_bytes = combine_bytes_ops.async;
export var combine_bytes_sync = combine_bytes_ops.sync;
export var combine_points = combine_points_ops.async;
export var combine_points_sync = combine_points_ops.sync;
export var evaluate = evaluate_ops.async;
export var evaluate_sync = evaluate_ops.sync;
export var lagrange_at_zero = lagrange_at_zero_ops.async;
export var lagrange_at_zero_sync = lagrange_at_zero_ops.sync;
export var lagrange_coeffs_at_zero = lagrange_coeffs_at_zero_ops.async;
export var lagrange_coeffs_at_zero_sync = lagrange_coeffs_at_zero_ops.sync;
export var lagrange_integer_at_zero = lagrange_integer_at_zero_ops.async;
export var lagrange_integer_at_zero_sync = lagrange_integer_at_zero_ops.sync;
export var polynomial = polynomial_ops.async;
export var polynomial_sync = polynomial_ops.sync;
export var split = split_ops.async;
export var split_sync = split_ops.sync;
export var split_bytes = split_bytes_ops.async;
export var split_bytes_sync = split_bytes_ops.sync;
