/**
 * Key derivation: HKDF, PBKDF2, and the standard KDFs of NIST, ANSI, TLS,
 * SSH and PKCS#12, as a callback and a _sync form:
 *
 *     hkdf(sha256, ikm, length, salt, info, function (err, key) {})
 *     hkdf_sync(sha256, ikm, length, salt, info)
 *
 * The hash is any of the library's hash functions (sha256 from
 * 'cryptographic-primitives/sha2.js', its _sync form, or a pure one).
 * Arguments are those of ../kdf.js; a password, salt or info may be a
 * string (UTF-8).
 *
 * node:crypto runs HKDF and PBKDF2 for the hashes it has, and their callback
 * forms on its thread pool, so the event loop stays free. Everything else is
 * the pure JavaScript in ../kdf.js; PBKDF2's callback form there runs in
 * slices of a few milliseconds, yielding to the event loop between them.
 */

import * as pure from '../kdf.js';
import { define } from '../engines/select.js';

var hkdf_extract_ops = define('hkdf_extract', { sync: pure.hkdf_extract, text: [1, 2] });
var hkdf_expand_ops = define('hkdf_expand', { sync: pure.hkdf_expand, text: [3], bytes: { 1: 'prk' } });
var hkdf_ops = define('hkdf', { sync: pure.hkdf, text: [1, 3, 4] });
var pbkdf2_ops = define('pbkdf2', { sync: pure.pbkdf2, task: pure.pbkdf2_task, text: [1, 2] });
var counter_kdf_ops = define('counter_kdf', { sync: pure.counter_kdf });
var concat_kdf_ops = define('concat_kdf', { sync: pure.concat_kdf, text: [3] });
var concat_kdf_hmac_ops = define('concat_kdf_hmac', { sync: pure.concat_kdf_hmac, text: [3, 4] });
var x963_kdf_ops = define('x963_kdf', { sync: pure.x963_kdf, text: [3] });
var kbkdf_counter_ops = define('kbkdf_counter', { sync: pure.kbkdf_counter, text: [1, 3, 4] });
var kbkdf_feedback_ops = define('kbkdf_feedback', { sync: pure.kbkdf_feedback, text: [1, 3, 4], bytes: { 5: 'iv' } });
var kbkdf_pipeline_ops = define('kbkdf_pipeline', { sync: pure.kbkdf_pipeline, text: [1, 3, 4] });
var tls1_prf_ops = define('tls1_prf', { sync: pure.tls1_prf, bytes: { 3: 'seed' } });
var sshkdf_ops = define('sshkdf', { sync: pure.sshkdf, text: [4] });
var x942_kdf_ops = define('x942_kdf', { sync: pure.x942_kdf, text: [3] });
var pkcs12_kdf_ops = define('pkcs12_kdf', { sync: pure.pkcs12_kdf, text: [1, 2] });

export var hkdf_extract = hkdf_extract_ops.async;
export var hkdf_extract_sync = hkdf_extract_ops.sync;
export var hkdf_expand = hkdf_expand_ops.async;
export var hkdf_expand_sync = hkdf_expand_ops.sync;
export var hkdf = hkdf_ops.async;
export var hkdf_sync = hkdf_ops.sync;
export var pbkdf2 = pbkdf2_ops.async;
export var pbkdf2_sync = pbkdf2_ops.sync;
export var counter_kdf = counter_kdf_ops.async;
export var counter_kdf_sync = counter_kdf_ops.sync;
export var concat_kdf = concat_kdf_ops.async;
export var concat_kdf_sync = concat_kdf_ops.sync;
export var concat_kdf_hmac = concat_kdf_hmac_ops.async;
export var concat_kdf_hmac_sync = concat_kdf_hmac_ops.sync;
export var x963_kdf = x963_kdf_ops.async;
export var x963_kdf_sync = x963_kdf_ops.sync;
export var kbkdf_counter = kbkdf_counter_ops.async;
export var kbkdf_counter_sync = kbkdf_counter_ops.sync;
export var kbkdf_feedback = kbkdf_feedback_ops.async;
export var kbkdf_feedback_sync = kbkdf_feedback_ops.sync;
export var kbkdf_pipeline = kbkdf_pipeline_ops.async;
export var kbkdf_pipeline_sync = kbkdf_pipeline_ops.sync;
export var tls1_prf = tls1_prf_ops.async;
export var tls1_prf_sync = tls1_prf_ops.sync;
export var sshkdf = sshkdf_ops.async;
export var sshkdf_sync = sshkdf_ops.sync;
export var x942_kdf = x942_kdf_ops.async;
export var x942_kdf_sync = x942_kdf_ops.sync;
export var pkcs12_kdf = pkcs12_kdf_ops.async;
export var pkcs12_kdf_sync = pkcs12_kdf_ops.sync;
