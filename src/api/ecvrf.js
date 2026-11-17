/**
 * ecvrf, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ecvrf.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ecvrf.js.
 */

import * as pure from '../ecvrf.js';
import { define } from '../engines/select.js';

var decode_proof_ops = define('ecvrf.decode_proof', { sync: pure.decode_proof });
var get_public_key_ops = define('ecvrf.get_public_key', { sync: pure.get_public_key, bytes: { 0: 'seed' } });
var proof_to_hash_ops = define('ecvrf.proof_to_hash', { sync: pure.proof_to_hash });
var prove_ops = define('ecvrf.prove', { sync: pure.prove, bytes: { 0: 'seed' } });
var validate_key_ops = define('ecvrf.validate_key', { sync: pure.validate_key, bytes: { 0: 'pk' } });
var verify_ops = define('ecvrf.verify', { sync: pure.verify, bytes: { 0: 'pk' } });

export var decode_proof = decode_proof_ops.async;
export var decode_proof_sync = decode_proof_ops.sync;
export var get_public_key = get_public_key_ops.async;
export var get_public_key_sync = get_public_key_ops.sync;
export var proof_to_hash = proof_to_hash_ops.async;
export var proof_to_hash_sync = proof_to_hash_ops.sync;
export var prove = prove_ops.async;
export var prove_sync = prove_ops.sync;
export var validate_key = validate_key_ops.async;
export var validate_key_sync = validate_key_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
