/**
 * bfv, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../bfv.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../bfv.js.
 */

import * as pure from '../bfv.js';
import { define } from '../engines/select.js';

var add_ops = define('bfv.add', { sync: pure.add, text: [0] });
var batch_context_ops = define('bfv.batch_context', { sync: pure.batch_context, text: [0] });
var batch_decode_ops = define('bfv.batch_decode', { sync: pure.batch_decode });
var batch_encode_ops = define('bfv.batch_encode', { sync: pure.batch_encode });
var batching_modulus_ops = define('bfv.batching_modulus', { sync: pure.batching_modulus });
var decode_ops = define('bfv.decode', { sync: pure.decode, text: [0] });
var decode_vector_ops = define('bfv.decode_vector', { sync: pure.decode_vector, text: [0] });
var decrypt_ops = define('bfv.decrypt', { sync: pure.decrypt, text: [0], bytes: { 1: 'sk', 2: 'ct' } });
var encode_ops = define('bfv.encode', { sync: pure.encode, text: [0] });
var encode_vector_ops = define('bfv.encode_vector', { sync: pure.encode_vector, text: [0] });
var encrypt_ops = define('bfv.encrypt', { sync: pure.encrypt, text: [0], bytes: { 1: 'pk' } });
var keygen_ops = define('bfv.keygen', { sync: pure.keygen });
var mul_ops = define('bfv.mul', { sync: pure.mul, text: [0] });
var mul_plain_ops = define('bfv.mul_plain', { sync: pure.mul_plain, text: [0], bytes: { 1: 'ct' } });
var noise_budget_ops = define('bfv.noise_budget', { sync: pure.noise_budget, text: [0], bytes: { 1: 'sk', 2: 'ct' } });
var relin_keygen_ops = define('bfv.relin_keygen', { sync: pure.relin_keygen, text: [0], bytes: { 1: 'sk' } });
var ring_ops = define('bfv.ring', { sync: pure.ring });
var rns_add_ops = define('bfv.rns_add', { sync: pure.rns_add });
var rns_context_ops = define('bfv.rns_context', { sync: pure.rns_context });
var rns_ct_add_ops = define('bfv.rns_ct_add', { sync: pure.rns_ct_add, text: [0] });
var rns_ct_sub_ops = define('bfv.rns_ct_sub', { sync: pure.rns_ct_sub, text: [0] });
var rns_decrypt_ops = define('bfv.rns_decrypt', { sync: pure.rns_decrypt, text: [0], bytes: { 1: 'sk', 2: 'ct' } });
var rns_encrypt_ops = define('bfv.rns_encrypt', { sync: pure.rns_encrypt, text: [0], bytes: { 1: 'pk' } });
var rns_join_ops = define('bfv.rns_join', { sync: pure.rns_join });
var rns_keygen_ops = define('bfv.rns_keygen', { sync: pure.rns_keygen });
var rns_mul_ops = define('bfv.rns_mul', { sync: pure.rns_mul });
var rns_mul_ct_ops = define('bfv.rns_mul_ct', { sync: pure.rns_mul_ct, text: [0] });
var rns_mul_plain_ops = define('bfv.rns_mul_plain', { sync: pure.rns_mul_plain, text: [0], bytes: { 1: 'ct' } });
var rns_noise_budget_ops = define('bfv.rns_noise_budget', { sync: pure.rns_noise_budget, text: [0], bytes: { 1: 'sk', 2: 'ct' } });
var rns_primes_ops = define('bfv.rns_primes', { sync: pure.rns_primes });
var rns_relin_keygen_ops = define('bfv.rns_relin_keygen', { sync: pure.rns_relin_keygen, text: [0], bytes: { 1: 'sk' } });
var rns_split_ops = define('bfv.rns_split', { sync: pure.rns_split });
var rns_sub_ops = define('bfv.rns_sub', { sync: pure.rns_sub });
var sub_ops = define('bfv.sub', { sync: pure.sub, text: [0] });

export var PARAMS = pure.PARAMS;
export var add = add_ops.async;
export var add_sync = add_ops.sync;
export var batch_context = batch_context_ops.async;
export var batch_context_sync = batch_context_ops.sync;
export var batch_decode = batch_decode_ops.async;
export var batch_decode_sync = batch_decode_ops.sync;
export var batch_encode = batch_encode_ops.async;
export var batch_encode_sync = batch_encode_ops.sync;
export var batching_modulus = batching_modulus_ops.async;
export var batching_modulus_sync = batching_modulus_ops.sync;
export var decode = decode_ops.async;
export var decode_sync = decode_ops.sync;
export var decode_vector = decode_vector_ops.async;
export var decode_vector_sync = decode_vector_ops.sync;
export var decrypt = decrypt_ops.async;
export var decrypt_sync = decrypt_ops.sync;
export var encode = encode_ops.async;
export var encode_sync = encode_ops.sync;
export var encode_vector = encode_vector_ops.async;
export var encode_vector_sync = encode_vector_ops.sync;
export var encrypt = encrypt_ops.async;
export var encrypt_sync = encrypt_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var mul = mul_ops.async;
export var mul_sync = mul_ops.sync;
export var mul_plain = mul_plain_ops.async;
export var mul_plain_sync = mul_plain_ops.sync;
export var noise_budget = noise_budget_ops.async;
export var noise_budget_sync = noise_budget_ops.sync;
export var relin_keygen = relin_keygen_ops.async;
export var relin_keygen_sync = relin_keygen_ops.sync;
export var ring = ring_ops.async;
export var ring_sync = ring_ops.sync;
export var rns_add = rns_add_ops.async;
export var rns_add_sync = rns_add_ops.sync;
export var rns_context = rns_context_ops.async;
export var rns_context_sync = rns_context_ops.sync;
export var rns_ct_add = rns_ct_add_ops.async;
export var rns_ct_add_sync = rns_ct_add_ops.sync;
export var rns_ct_sub = rns_ct_sub_ops.async;
export var rns_ct_sub_sync = rns_ct_sub_ops.sync;
export var rns_decrypt = rns_decrypt_ops.async;
export var rns_decrypt_sync = rns_decrypt_ops.sync;
export var rns_encrypt = rns_encrypt_ops.async;
export var rns_encrypt_sync = rns_encrypt_ops.sync;
export var rns_join = rns_join_ops.async;
export var rns_join_sync = rns_join_ops.sync;
export var rns_keygen = rns_keygen_ops.async;
export var rns_keygen_sync = rns_keygen_ops.sync;
export var rns_mul = rns_mul_ops.async;
export var rns_mul_sync = rns_mul_ops.sync;
export var rns_mul_ct = rns_mul_ct_ops.async;
export var rns_mul_ct_sync = rns_mul_ct_ops.sync;
export var rns_mul_plain = rns_mul_plain_ops.async;
export var rns_mul_plain_sync = rns_mul_plain_ops.sync;
export var rns_noise_budget = rns_noise_budget_ops.async;
export var rns_noise_budget_sync = rns_noise_budget_ops.sync;
export var rns_primes = rns_primes_ops.async;
export var rns_primes_sync = rns_primes_ops.sync;
export var rns_relin_keygen = rns_relin_keygen_ops.async;
export var rns_relin_keygen_sync = rns_relin_keygen_ops.sync;
export var rns_split = rns_split_ops.async;
export var rns_split_sync = rns_split_ops.sync;
export var rns_sub = rns_sub_ops.async;
export var rns_sub_sync = rns_sub_ops.sync;
export var sub = sub_ops.async;
export var sub_sync = sub_ops.sync;
