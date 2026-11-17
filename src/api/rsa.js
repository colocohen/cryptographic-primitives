/**
 * rsa, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../rsa.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../rsa.js.
 */

import * as pure from '../rsa.js';
import { define } from '../engines/select.js';

var decrypt_oaep_ops = define('rsa.decrypt_oaep', { sync: pure.decrypt_oaep, text: [4], bytes: { 0: 'key', 1: 'ct' } });
var decrypt_pkcs1_ops = define('rsa.decrypt_pkcs1', { sync: pure.decrypt_pkcs1, bytes: { 0: 'key', 1: 'ct' } });
var encode_fdh_vrf_ops = define('rsa.encode_fdh_vrf', { sync: pure.encode_fdh_vrf, bytes: { 0: 'key' } });
var encode_pkcs1_ops = define('rsa.encode_pkcs1', { sync: pure.encode_pkcs1, bytes: { 0: 'key', 1: 'msg_hash' } });
var encode_pss_ops = define('rsa.encode_pss', { sync: pure.encode_pss, text: [3], bytes: { 0: 'key', 1: 'msg_hash' } });
var encrypt_oaep_ops = define('rsa.encrypt_oaep', { sync: pure.encrypt_oaep, text: [1, 4], bytes: { 0: 'key' } });
var encrypt_pkcs1_ops = define('rsa.encrypt_pkcs1', { sync: pure.encrypt_pkcs1, text: [1], bytes: { 0: 'key' } });
var fdh_vrf_proof_to_hash_ops = define('rsa.fdh_vrf_proof_to_hash', { sync: pure.fdh_vrf_proof_to_hash });
var fdh_vrf_prove_ops = define('rsa.fdh_vrf_prove', { sync: pure.fdh_vrf_prove, bytes: { 0: 'key' } });
var fdh_vrf_verify_ops = define('rsa.fdh_vrf_verify', { sync: pure.fdh_vrf_verify, bytes: { 0: 'key' } });
var keygen_ops = define('rsa.keygen', { sync: pure.keygen, task: pure.keygen_task });
var private_key_from_d_ops = define('rsa.private_key_from_d', { sync: pure.private_key_from_d });
var private_key_from_der_ops = define('rsa.private_key_from_der', { sync: pure.private_key_from_der });
var private_key_to_der_ops = define('rsa.private_key_to_der', { sync: pure.private_key_to_der, bytes: { 0: 'key' } });
var private_key_to_jwk_ops = define('rsa.private_key_to_jwk', { sync: pure.private_key_to_jwk, bytes: { 0: 'key' } });
var public_key_ops = define('rsa.public_key', { sync: pure.public_key, bytes: { 0: 'key' } });
var public_key_from_der_ops = define('rsa.public_key_from_der', { sync: pure.public_key_from_der });
var public_key_to_der_ops = define('rsa.public_key_to_der', { sync: pure.public_key_to_der, bytes: { 0: 'key' } });
var sign_pkcs1_ops = define('rsa.sign_pkcs1', { sync: pure.sign_pkcs1, bytes: { 0: 'key', 1: 'msg_hash' } });
var sign_pss_ops = define('rsa.sign_pss', { sync: pure.sign_pss, bytes: { 0: 'key', 1: 'msg_hash' } });
var verify_pkcs1_ops = define('rsa.verify_pkcs1', { sync: pure.verify_pkcs1, bytes: { 0: 'key', 1: 'msg_hash', 2: 'sig' } });
var verify_pss_ops = define('rsa.verify_pss', { sync: pure.verify_pss, bytes: { 0: 'key', 1: 'msg_hash', 2: 'sig' } });

var sign_pss_message_ops = define('rsa.sign_pss_message', { sync: pure.sign_pss_message, text: [1], bytes: { 0: 'key' } });
var verify_pss_message_ops = define('rsa.verify_pss_message', { sync: pure.verify_pss_message, text: [1], bytes: { 0: 'key', 2: 'sig' } });
var sign_pkcs1_message_ops = define('rsa.sign_pkcs1_message', { sync: pure.sign_pkcs1_message, text: [1], bytes: { 0: 'key' } });
var signer_ops = define('rsa.signer_create', { create: pure.signer_create, kind: 'rsa_signer', create_bytes: { 0: 'key' } });
var verifier_ops = define('rsa.verifier_create', { create: pure.verifier_create, kind: 'rsa_verifier', create_bytes: { 0: 'key' } });
var verify_pkcs1_message_ops = define('rsa.verify_pkcs1_message', { sync: pure.verify_pkcs1_message, text: [1], bytes: { 0: 'key', 2: 'sig' } });
export var decrypt_oaep = decrypt_oaep_ops.async;
export var decrypt_oaep_sync = decrypt_oaep_ops.sync;
export var decrypt_pkcs1 = decrypt_pkcs1_ops.async;
export var decrypt_pkcs1_sync = decrypt_pkcs1_ops.sync;
export var encode_fdh_vrf = encode_fdh_vrf_ops.async;
export var encode_fdh_vrf_sync = encode_fdh_vrf_ops.sync;
export var encode_pkcs1 = encode_pkcs1_ops.async;
export var encode_pkcs1_sync = encode_pkcs1_ops.sync;
export var encode_pss = encode_pss_ops.async;
export var encode_pss_sync = encode_pss_ops.sync;
export var encrypt_oaep = encrypt_oaep_ops.async;
export var encrypt_oaep_sync = encrypt_oaep_ops.sync;
export var encrypt_pkcs1 = encrypt_pkcs1_ops.async;
export var encrypt_pkcs1_sync = encrypt_pkcs1_ops.sync;
export var fdh_vrf_proof_to_hash = fdh_vrf_proof_to_hash_ops.async;
export var fdh_vrf_proof_to_hash_sync = fdh_vrf_proof_to_hash_ops.sync;
export var fdh_vrf_prove = fdh_vrf_prove_ops.async;
export var fdh_vrf_prove_sync = fdh_vrf_prove_ops.sync;
export var fdh_vrf_verify = fdh_vrf_verify_ops.async;
export var fdh_vrf_verify_sync = fdh_vrf_verify_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var private_key_from_d = private_key_from_d_ops.async;
export var private_key_from_d_sync = private_key_from_d_ops.sync;
export var private_key_from_der = private_key_from_der_ops.async;
export var private_key_from_der_sync = private_key_from_der_ops.sync;
export var private_key_to_der = private_key_to_der_ops.async;
export var private_key_to_der_sync = private_key_to_der_ops.sync;
export var private_key_to_jwk = private_key_to_jwk_ops.async;
export var private_key_to_jwk_sync = private_key_to_jwk_ops.sync;
export var public_key = public_key_ops.async;
export var public_key_sync = public_key_ops.sync;
export var public_key_from_der = public_key_from_der_ops.async;
export var public_key_from_der_sync = public_key_from_der_ops.sync;
export var public_key_to_der = public_key_to_der_ops.async;
export var public_key_to_der_sync = public_key_to_der_ops.sync;
export var sign_pkcs1 = sign_pkcs1_ops.async;
export var sign_pkcs1_sync = sign_pkcs1_ops.sync;
export var sign_pss = sign_pss_ops.async;
export var sign_pss_sync = sign_pss_ops.sync;
export var verify_pkcs1 = verify_pkcs1_ops.async;
export var verify_pkcs1_sync = verify_pkcs1_ops.sync;
export var verify_pss = verify_pss_ops.async;
export var verify_pss_sync = verify_pss_ops.sync;
export var sign_pss_message = sign_pss_message_ops.async;
export var sign_pss_message_sync = sign_pss_message_ops.sync;
export var verify_pss_message = verify_pss_message_ops.async;
export var verify_pss_message_sync = verify_pss_message_ops.sync;
export var sign_pkcs1_message = sign_pkcs1_message_ops.async;
export var sign_pkcs1_message_sync = sign_pkcs1_message_ops.sync;
export var verify_pkcs1_message = verify_pkcs1_message_ops.async;
export var verify_pkcs1_message_sync = verify_pkcs1_message_ops.sync;

/* signer_create(key): one private key for many signatures - sign_pss, sign_pkcs1 and their _message forms, and wipe() */
export var signer_create = signer_ops.create;
/* verifier_create(key): one public key for many verifications - verify_pss, verify_pkcs1 and their _message forms */
export var verifier_create = verifier_ops.create;
