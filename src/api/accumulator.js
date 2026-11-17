/**
 * accumulator, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../accumulator.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../accumulator.js.
 */

import * as pure from '../accumulator.js';
import { define } from '../engines/select.js';

var accumulate_ops = define('accumulator.accumulate', { sync: pure.accumulate });
var add_ops = define('accumulator.add', { sync: pure.add });
var aggregate_witnesses_ops = define('accumulator.aggregate_witnesses', { sync: pure.aggregate_witnesses });
var element_to_prime_ops = define('accumulator.element_to_prime', { sync: pure.element_to_prime });
var non_membership_ops = define('accumulator.non_membership', { sync: pure.non_membership });
var setup_unsafe_ops = define('accumulator.setup_unsafe', { sync: pure.setup_unsafe });
var to_bytes_ops = define('accumulator.to_bytes', { sync: pure.to_bytes });
var update_witness_ops = define('accumulator.update_witness', { sync: pure.update_witness });
var verify_aggregate_ops = define('accumulator.verify_aggregate', { sync: pure.verify_aggregate });
var verify_membership_ops = define('accumulator.verify_membership', { sync: pure.verify_membership });
var verify_non_membership_ops = define('accumulator.verify_non_membership', { sync: pure.verify_non_membership });
var witness_ops = define('accumulator.witness', { sync: pure.witness });

export var accumulate = accumulate_ops.async;
export var accumulate_sync = accumulate_ops.sync;
export var add = add_ops.async;
export var add_sync = add_ops.sync;
export var aggregate_witnesses = aggregate_witnesses_ops.async;
export var aggregate_witnesses_sync = aggregate_witnesses_ops.sync;
export var element_to_prime = element_to_prime_ops.async;
export var element_to_prime_sync = element_to_prime_ops.sync;
export var non_membership = non_membership_ops.async;
export var non_membership_sync = non_membership_ops.sync;
export var setup_unsafe = setup_unsafe_ops.async;
export var setup_unsafe_sync = setup_unsafe_ops.sync;
export var to_bytes = to_bytes_ops.async;
export var to_bytes_sync = to_bytes_ops.sync;
export var update_witness = update_witness_ops.async;
export var update_witness_sync = update_witness_ops.sync;
export var verify_aggregate = verify_aggregate_ops.async;
export var verify_aggregate_sync = verify_aggregate_ops.sync;
export var verify_membership = verify_membership_ops.async;
export var verify_membership_sync = verify_membership_ops.sync;
export var verify_non_membership = verify_non_membership_ops.async;
export var verify_non_membership_sync = verify_non_membership_ops.sync;
export var witness = witness_ops.async;
export var witness_sync = witness_ops.sync;
