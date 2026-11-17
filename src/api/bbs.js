/**
 * bbs, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../bbs.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../bbs.js.
 */

import * as pure from '../bbs.js';
import { define } from '../engines/select.js';

var calculate_domain_ops = define('bbs.calculate_domain', { sync: pure.calculate_domain, text: [3], bytes: { 0: 'pk_bytes' } });
var core_proof_gen_ops = define('bbs.core_proof_gen', { sync: pure.core_proof_gen, text: [2, 5], bytes: { 0: 'pk_bytes', 1: 'sig' } });
var core_proof_verify_ops = define('bbs.core_proof_verify', { sync: pure.core_proof_verify, text: [2, 4], bytes: { 0: 'pk_bytes' } });
var core_sign_ops = define('bbs.core_sign', { sync: pure.core_sign, text: [2, 3], bytes: { 0: 'sk', 1: 'pk_bytes' } });
var core_verify_ops = define('bbs.core_verify', { sync: pure.core_verify, text: [2, 3], bytes: { 0: 'pk_bytes', 1: 'sig' } });
var create_generators_ops = define('bbs.create_generators', { sync: pure.create_generators });
var keygen_ops = define('bbs.keygen', { sync: pure.keygen, text: [0, 1] });
var message_to_scalar_ops = define('bbs.message_to_scalar', { sync: pure.message_to_scalar, text: [0] });
var messages_to_scalars_ops = define('bbs.messages_to_scalars', { sync: pure.messages_to_scalars, text: [0] });
var octets_to_proof_ops = define('bbs.octets_to_proof', { sync: pure.octets_to_proof });
var octets_to_signature_ops = define('bbs.octets_to_signature', { sync: pure.octets_to_signature });
var point_bytes_ops = define('bbs.point_bytes', { sync: pure.point_bytes });
var proof_to_octets_ops = define('bbs.proof_to_octets', { sync: pure.proof_to_octets });
var signature_to_octets_ops = define('bbs.signature_to_octets', { sync: pure.signature_to_octets, bytes: { 0: 'sig' } });
var sk_to_pk_ops = define('bbs.sk_to_pk', { sync: pure.sk_to_pk, bytes: { 0: 'sk' } });

export var API_ID = pure.API_ID;
export var calculate_domain = calculate_domain_ops.async;
export var calculate_domain_sync = calculate_domain_ops.sync;
export var core_proof_gen = core_proof_gen_ops.async;
export var core_proof_gen_sync = core_proof_gen_ops.sync;
export var core_proof_verify = core_proof_verify_ops.async;
export var core_proof_verify_sync = core_proof_verify_ops.sync;
export var core_sign = core_sign_ops.async;
export var core_sign_sync = core_sign_ops.sync;
export var core_verify = core_verify_ops.async;
export var core_verify_sync = core_verify_ops.sync;
export var create_generators = create_generators_ops.async;
export var create_generators_sync = create_generators_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var message_to_scalar = message_to_scalar_ops.async;
export var message_to_scalar_sync = message_to_scalar_ops.sync;
export var messages_to_scalars = messages_to_scalars_ops.async;
export var messages_to_scalars_sync = messages_to_scalars_ops.sync;
export var octets_to_proof = octets_to_proof_ops.async;
export var octets_to_proof_sync = octets_to_proof_ops.sync;
export var octets_to_signature = octets_to_signature_ops.async;
export var octets_to_signature_sync = octets_to_signature_ops.sync;
export var point_bytes = point_bytes_ops.async;
export var point_bytes_sync = point_bytes_ops.sync;
export var proof_to_octets = proof_to_octets_ops.async;
export var proof_to_octets_sync = proof_to_octets_ops.sync;
export var signature_to_octets = signature_to_octets_ops.async;
export var signature_to_octets_sync = signature_to_octets_ops.sync;
export var sk_to_pk = sk_to_pk_ops.async;
export var sk_to_pk_sync = sk_to_pk_ops.sync;
