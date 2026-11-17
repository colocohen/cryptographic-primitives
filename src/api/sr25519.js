/**
 * sr25519, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../sr25519.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../sr25519.js.
 */

import * as pure from '../sr25519.js';
import { define } from '../engines/select.js';

var challenge_ops = define('sr25519.challenge', { sync: pure.challenge, text: [0, 1], bytes: { 2: 'publicKey' } });
var challenge_of_ops = define('sr25519.challenge_of', { sync: pure.challenge_of, bytes: { 1: 'publicKey' } });
var decode_public_key_ops = define('sr25519.decode_public_key', { sync: pure.decode_public_key, bytes: { 0: 'pk' } });
var decode_signature_ops = define('sr25519.decode_signature', { sync: pure.decode_signature, bytes: { 0: 'sig' } });
var derive_soft_ops = define('sr25519.derive_soft', { sync: pure.derive_soft, bytes: { 0: 'publicKey' } });
var encode_secret_ops = define('sr25519.encode_secret', { sync: pure.encode_secret, bytes: { 1: 'nonce' } });
var encode_signature_ops = define('sr25519.encode_signature', { sync: pure.encode_signature });
var get_public_key_ops = define('sr25519.get_public_key', { sync: pure.get_public_key, bytes: { 0: 'secretKey' } });
var secret_from_seed_ops = define('sr25519.secret_from_seed', { sync: pure.secret_from_seed, bytes: { 0: 'seed' } });
var secret_hard_ops = define('sr25519.secret_hard', { sync: pure.secret_hard, bytes: { 0: 'secretKey' } });
var secret_scalar_ops = define('sr25519.secret_scalar', { sync: pure.secret_scalar, bytes: { 0: 'secretKey' } });
var secret_soft_ops = define('sr25519.secret_soft', { sync: pure.secret_soft, bytes: { 0: 'secretKey' } });
var shared_secret_ops = define('sr25519.shared_secret', { sync: pure.shared_secret, bytes: { 0: 'secretKey', 1: 'publicKey' } });
var sign_ops = define('sr25519.sign', { sync: pure.sign, text: [1, 2], bytes: { 0: 'secretKey' } });
var signing_message_ops = define('sr25519.signing_message', { sync: pure.signing_message, text: [0, 1] });
var signing_transcript_ops = define('sr25519.signing_transcript', { sync: pure.signing_transcript, text: [0, 1] });
var split_signing_message_ops = define('sr25519.split_signing_message', { sync: pure.split_signing_message });
var verify_ops = define('sr25519.verify', { sync: pure.verify, text: [0, 3], bytes: { 1: 'signature', 2: 'publicKey' } });
var verify_batch_ops = define('sr25519.verify_batch', { sync: pure.verify_batch, text: [0] });
var verify_batch_find_ops = define('sr25519.verify_batch_find', { sync: pure.verify_batch_find, text: [0] });
var vrf_challenge_ops = define('sr25519.vrf_challenge', { sync: pure.vrf_challenge, bytes: { 4: 'publicKey' } });
var vrf_encode_ops = define('sr25519.vrf_encode', { sync: pure.vrf_encode });
var vrf_input_point_ops = define('sr25519.vrf_input_point', { sync: pure.vrf_input_point, text: [0, 1], bytes: { 2: 'publicKey' } });
var vrf_sign_ops = define('sr25519.vrf_sign', { sync: pure.vrf_sign, text: [0, 2], bytes: { 1: 'secretKey' } });
var vrf_transcript_ops = define('sr25519.vrf_transcript', { sync: pure.vrf_transcript, text: [0, 1] });
var vrf_verify_ops = define('sr25519.vrf_verify', { sync: pure.vrf_verify, text: [0, 3], bytes: { 2: 'publicKey' } });
var keygen_ops = define('sr25519.keygen', { sync: pure.keygen, bytes: { 0: 'seed' } });

export var challenge = challenge_ops.async;
export var challenge_sync = challenge_ops.sync;
export var challenge_of = challenge_of_ops.async;
export var challenge_of_sync = challenge_of_ops.sync;
export var decode_public_key = decode_public_key_ops.async;
export var decode_public_key_sync = decode_public_key_ops.sync;
export var decode_signature = decode_signature_ops.async;
export var decode_signature_sync = decode_signature_ops.sync;
export var derive_soft = derive_soft_ops.async;
export var derive_soft_sync = derive_soft_ops.sync;
export var encode_secret = encode_secret_ops.async;
export var encode_secret_sync = encode_secret_ops.sync;
export var encode_signature = encode_signature_ops.async;
export var encode_signature_sync = encode_signature_ops.sync;
export var get_public_key = get_public_key_ops.async;
export var get_public_key_sync = get_public_key_ops.sync;
export var secret_from_seed = secret_from_seed_ops.async;
export var secret_from_seed_sync = secret_from_seed_ops.sync;
export var secret_hard = secret_hard_ops.async;
export var secret_hard_sync = secret_hard_ops.sync;
export var secret_scalar = secret_scalar_ops.async;
export var secret_scalar_sync = secret_scalar_ops.sync;
export var secret_soft = secret_soft_ops.async;
export var secret_soft_sync = secret_soft_ops.sync;
export var shared_secret = shared_secret_ops.async;
export var shared_secret_sync = shared_secret_ops.sync;
export var sign = sign_ops.async;
export var sign_sync = sign_ops.sync;
export var signing_message = signing_message_ops.async;
export var signing_message_sync = signing_message_ops.sync;
export var signing_transcript = signing_transcript_ops.async;
export var signing_transcript_sync = signing_transcript_ops.sync;
export var split_signing_message = split_signing_message_ops.async;
export var split_signing_message_sync = split_signing_message_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
export var verify_batch = verify_batch_ops.async;
export var verify_batch_sync = verify_batch_ops.sync;
export var verify_batch_find = verify_batch_find_ops.async;
export var verify_batch_find_sync = verify_batch_find_ops.sync;
export var vrf_challenge = vrf_challenge_ops.async;
export var vrf_challenge_sync = vrf_challenge_ops.sync;
export var vrf_encode = vrf_encode_ops.async;
export var vrf_encode_sync = vrf_encode_ops.sync;
export var vrf_input_point = vrf_input_point_ops.async;
export var vrf_input_point_sync = vrf_input_point_ops.sync;
export var vrf_sign = vrf_sign_ops.async;
export var vrf_sign_sync = vrf_sign_ops.sync;
export var vrf_transcript = vrf_transcript_ops.async;
export var vrf_transcript_sync = vrf_transcript_ops.sync;
export var vrf_verify = vrf_verify_ops.async;
export var vrf_verify_sync = vrf_verify_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
