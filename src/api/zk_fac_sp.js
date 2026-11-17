/**
 * zk_fac_sp, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../zk_fac_sp.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../zk_fac_sp.js.
 */

import * as pure from '../zk_fac_sp.js';
import { define } from '../engines/select.js';

var generators_ops = define('zk_fac_sp.generators', { sync: pure.generators });
var is_safe_prime_ops = define('zk_fac_sp.is_safe_prime', { sync: pure.is_safe_prime });
var prove_fac_sp_ops = define('zk_fac_sp.prove_fac_sp', { sync: pure.prove_fac_sp });
var verify_fac_sp_ops = define('zk_fac_sp.verify_fac_sp', { sync: pure.verify_fac_sp });

export var PAPER_D = pure.PAPER_D;
export var RFC3526_4096 = pure.RFC3526_4096;
export var generators = generators_ops.async;
export var generators_sync = generators_ops.sync;
export var is_safe_prime = is_safe_prime_ops.async;
export var is_safe_prime_sync = is_safe_prime_ops.sync;
export var prove_fac_sp = prove_fac_sp_ops.async;
export var prove_fac_sp_sync = prove_fac_sp_ops.sync;
export var verify_fac_sp = verify_fac_sp_ops.async;
export var verify_fac_sp_sync = verify_fac_sp_ops.sync;
