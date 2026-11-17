/**
 * mta, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../mta.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../mta.js.
 */

import * as pure from '../mta.js';
import { define } from '../engines/select.js';

var alice_decrypt_ops = define('mta.alice_decrypt', { sync: pure.alice_decrypt, bytes: { 0: 'sk' } });
var alice_encrypt_ops = define('mta.alice_encrypt', { sync: pure.alice_encrypt, bytes: { 0: 'pk' } });
var bob_respond_ops = define('mta.bob_respond', { sync: pure.bob_respond, bytes: { 0: 'pk' } });
var modulus_fits_ops = define('mta.modulus_fits', { sync: pure.modulus_fits });
var mta_ops = define('mta.mta', { sync: pure.mta });

export var MASK_SLACK = pure.MASK_SLACK;
export var MIN_MODULUS_BITS = pure.MIN_MODULUS_BITS;
export var alice_decrypt = alice_decrypt_ops.async;
export var alice_decrypt_sync = alice_decrypt_ops.sync;
export var alice_encrypt = alice_encrypt_ops.async;
export var alice_encrypt_sync = alice_encrypt_ops.sync;
export var bob_respond = bob_respond_ops.async;
export var bob_respond_sync = bob_respond_ops.sync;
export var modulus_fits = modulus_fits_ops.async;
export var modulus_fits_sync = modulus_fits_ops.sync;
export var mta = mta_ops.async;
export var mta_sync = mta_ops.sync;
