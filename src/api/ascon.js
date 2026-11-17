/**
 * Ascon (NIST SP 800-232, and the v1.2 forms), in the forms every operation
 * takes:
 *
 *     ascon_hash256(msg, cb)    ascon_hash256_sync(msg)    ascon_hash256_create()
 *     ascon_xof128(msg, out_len, cb)  and _sync; _create() has digest(n) and read(n)
 *     ascon_cxof128(msg, out_len, custom, cb)  and _sync; _create(custom)
 *     ascon_aead128_encrypt(key, nonce, pt, aad, cb)  and _sync
 *     ascon_aead128_decrypt(key, nonce, sealed, aad, cb)  and _sync (null when
 *                                                    authentication fails)
 *
 * and the v1.2 names (ascon128, ascon128a, ascon80pq, ascon_hash_v12,
 * ascon_xof_v12). A message or associated data may be a string (UTF-8). No
 * platform ships Ascon, so it runs the pure JavaScript in ../ascon.js.
 */

import * as pure from '../ascon.js';
import { define } from '../engines/select.js';

var ascon_hash256_ops         = define('ascon_hash256', { sync: pure.ascon_hash256, create: pure.ascon_hash256_create, text: [0] });
var ascon_xof128_ops          = define('ascon_xof128', { sync: pure.ascon_xof128, create: pure.ascon_xof128_create, text: [0] });
var ascon_cxof128_ops         = define('ascon_cxof128', { sync: pure.ascon_cxof128, create: pure.ascon_cxof128_create, text: [0, 2], create_text: [0] });
var ascon_hash_v12_ops        = define('ascon_hash_v12', { sync: pure.ascon_hash_v12, create: pure.ascon_hash_v12_create, text: [0] });
var ascon_xof_v12_ops         = define('ascon_xof_v12', { sync: pure.ascon_xof_v12, create: pure.ascon_xof_v12_create, text: [0] });
var ascon_aead128_encrypt_ops = define('ascon_aead128_encrypt', { sync: pure.ascon_aead128_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var ascon_aead128_decrypt_ops = define('ascon_aead128_decrypt', { sync: pure.ascon_aead128_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var ascon128_encrypt_ops      = define('ascon128_encrypt', { sync: pure.ascon128_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var ascon128_decrypt_ops      = define('ascon128_decrypt', { sync: pure.ascon128_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var ascon128a_encrypt_ops     = define('ascon128a_encrypt', { sync: pure.ascon128a_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var ascon128a_decrypt_ops     = define('ascon128a_decrypt', { sync: pure.ascon128a_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });
var ascon80pq_encrypt_ops     = define('ascon80pq_encrypt', { sync: pure.ascon80pq_encrypt, text: [2, 3], bytes: { 0: 'key', 1: 'nonce' } });
var ascon80pq_decrypt_ops     = define('ascon80pq_decrypt', { sync: pure.ascon80pq_decrypt, text: [3], bytes: { 0: 'key', 1: 'nonce', 2: 'sealed' } });

export var ascon_hash256                = ascon_hash256_ops.async;
export var ascon_hash256_sync           = ascon_hash256_ops.sync;
export var ascon_hash256_create         = ascon_hash256_ops.create;
export var ascon_xof128                 = ascon_xof128_ops.async;
export var ascon_xof128_sync            = ascon_xof128_ops.sync;
export var ascon_xof128_create          = ascon_xof128_ops.create;
export var ascon_cxof128                = ascon_cxof128_ops.async;
export var ascon_cxof128_sync           = ascon_cxof128_ops.sync;
export var ascon_cxof128_create         = ascon_cxof128_ops.create;
export var ascon_hash_v12               = ascon_hash_v12_ops.async;
export var ascon_hash_v12_sync          = ascon_hash_v12_ops.sync;
export var ascon_hash_v12_create        = ascon_hash_v12_ops.create;
export var ascon_xof_v12                = ascon_xof_v12_ops.async;
export var ascon_xof_v12_sync           = ascon_xof_v12_ops.sync;
export var ascon_xof_v12_create         = ascon_xof_v12_ops.create;
export var ascon_aead128_encrypt        = ascon_aead128_encrypt_ops.async;
export var ascon_aead128_encrypt_sync   = ascon_aead128_encrypt_ops.sync;
export var ascon_aead128_decrypt        = ascon_aead128_decrypt_ops.async;
export var ascon_aead128_decrypt_sync   = ascon_aead128_decrypt_ops.sync;
export var ascon128_encrypt             = ascon128_encrypt_ops.async;
export var ascon128_encrypt_sync        = ascon128_encrypt_ops.sync;
export var ascon128_decrypt             = ascon128_decrypt_ops.async;
export var ascon128_decrypt_sync        = ascon128_decrypt_ops.sync;
export var ascon128a_encrypt            = ascon128a_encrypt_ops.async;
export var ascon128a_encrypt_sync       = ascon128a_encrypt_ops.sync;
export var ascon128a_decrypt            = ascon128a_decrypt_ops.async;
export var ascon128a_decrypt_sync       = ascon128a_decrypt_ops.sync;
export var ascon80pq_encrypt            = ascon80pq_encrypt_ops.async;
export var ascon80pq_encrypt_sync       = ascon80pq_encrypt_ops.sync;
export var ascon80pq_decrypt            = ascon80pq_decrypt_ops.async;
export var ascon80pq_decrypt_sync       = ascon80pq_decrypt_ops.sync;
