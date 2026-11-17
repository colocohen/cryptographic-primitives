/**
 * paillier, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../paillier.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../paillier.js.
 */

import * as pure from '../paillier.js';
import { define } from '../engines/select.js';

var add_ops = define('paillier.add', { sync: pure.add, bytes: { 0: 'pk' } });
var add_plain_ops = define('paillier.add_plain', { sync: pure.add_plain, bytes: { 0: 'pk' } });
var decrypt_ops = define('paillier.decrypt', { sync: pure.decrypt, bytes: { 0: 'sk' } });
var decrypt_signed_ops = define('paillier.decrypt_signed', { sync: pure.decrypt_signed, bytes: { 0: 'sk' } });
var decrypt_with_randomness_ops = define('paillier.decrypt_with_randomness', { sync: pure.decrypt_with_randomness, bytes: { 0: 'sk' } });
var enc_raw_ops = define('paillier.enc_raw', { sync: pure.enc_raw });
var enc_raw_sk_ops = define('paillier.enc_raw_sk', { sync: pure.enc_raw_sk, bytes: { 0: 'sk' } });
var encrypt_ops = define('paillier.encrypt', { sync: pure.encrypt, bytes: { 0: 'pk' } });
var encrypt_with_randomness_ops = define('paillier.encrypt_with_randomness', { sync: pure.encrypt_with_randomness, bytes: { 0: 'pk' } });
var keygen_ops = define('paillier.keygen', { sync: pure.keygen, task: pure.keygen_task });
var mul_plain_ops = define('paillier.mul_plain', { sync: pure.mul_plain, bytes: { 0: 'pk' } });
var public_key_ops = define('paillier.public_key', { sync: pure.public_key, bytes: { 0: 'sk' } });
var rerandomise_ops = define('paillier.rerandomise', { sync: pure.rerandomise, bytes: { 0: 'pk' } });
var sum_ops = define('paillier.sum', { sync: pure.sum, bytes: { 0: 'pk' } });

export var add = add_ops.async;
export var add_sync = add_ops.sync;
export var add_plain = add_plain_ops.async;
export var add_plain_sync = add_plain_ops.sync;
export var decrypt = decrypt_ops.async;
export var decrypt_sync = decrypt_ops.sync;
export var decrypt_signed = decrypt_signed_ops.async;
export var decrypt_signed_sync = decrypt_signed_ops.sync;
export var decrypt_with_randomness = decrypt_with_randomness_ops.async;
export var decrypt_with_randomness_sync = decrypt_with_randomness_ops.sync;
export var enc_raw = enc_raw_ops.async;
export var enc_raw_sync = enc_raw_ops.sync;
export var enc_raw_sk = enc_raw_sk_ops.async;
export var enc_raw_sk_sync = enc_raw_sk_ops.sync;
export var encrypt = encrypt_ops.async;
export var encrypt_sync = encrypt_ops.sync;
export var encrypt_with_randomness = encrypt_with_randomness_ops.async;
export var encrypt_with_randomness_sync = encrypt_with_randomness_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var mul_plain = mul_plain_ops.async;
export var mul_plain_sync = mul_plain_ops.sync;
export var public_key = public_key_ops.async;
export var public_key_sync = public_key_ops.sync;
export var rerandomise = rerandomise_ops.async;
export var rerandomise_sync = rerandomise_ops.sync;
export var sum = sum_ops.async;
export var sum_sync = sum_ops.sync;
