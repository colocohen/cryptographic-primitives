/**
 * BLAKE3, in the three forms every operation takes:
 *
 *     blake3(msg, [out_len], function (err, digest) {})
 *     blake3_sync(msg, [out_len])
 *     blake3_create([out_len])                     { update(msg), copy(), digest() }
 *
 *     blake3_keyed(msg, key, [out_len], cb)        and _sync, _create(key, [out_len])
 *     blake3_derive_key(context, material, [out_len], cb)
 *                                                  and _sync, _create(context, [out_len])
 *
 * Plus the verified-streaming tree: blake3_proof, blake3_verify_chunk,
 * blake3_chunk_count. A message, key or context may be a string (UTF-8).
 * No platform ships BLAKE3, so everything runs the pure JavaScript in
 * ../blake3.js.
 */

import * as pure from '../blake3.js';
import { define } from '../engines/select.js';

var plain = define('blake3', { sync: pure.blake3, create: pure.blake3_create, text: [0] });
var keyed = define('blake3_keyed', { sync: pure.blake3_keyed, create: pure.blake3_keyed_create, text: [0], bytes: { 1: 'key' }, create_bytes: { 0: 'key' } });
var derive = define('blake3_derive_key', { sync: pure.blake3_derive_key, create: pure.blake3_derive_key_create, text: [0, 1], create_text: [0] });
var proof = define('blake3_proof', { sync: pure.blake3_proof, text: [0], bytes: { 2: 'key' } });
var verify = define('blake3_verify_chunk', { sync: pure.blake3_verify_chunk, bytes: { 3: 'key' } });

export var blake3                   = plain.async;
export var blake3_sync              = plain.sync;
export var blake3_create            = plain.create;
export var blake3_keyed             = keyed.async;
export var blake3_keyed_sync        = keyed.sync;
export var blake3_keyed_create      = keyed.create;
export var blake3_derive_key        = derive.async;
export var blake3_derive_key_sync   = derive.sync;
export var blake3_derive_key_create = derive.create;
export var blake3_proof             = proof.async;
export var blake3_proof_sync        = proof.sync;
export var blake3_verify_chunk      = verify.async;
export var blake3_verify_chunk_sync = verify.sync;

/* Arithmetic on a length, not cryptography: one form. */
export var blake3_chunk_count = pure.blake3_chunk_count;
export var BLAKE3_CHUNK_LEN   = pure.BLAKE3_CHUNK_LEN;
