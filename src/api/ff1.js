/**
 * ff1, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ff1.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ff1.js.
 */

import * as pure from '../ff1.js';
import { define } from '../engines/select.js';

var ff1_decrypt_ops = define('ff1.ff1_decrypt', { sync: pure.ff1_decrypt, bytes: { 0: 'key' } });
var ff1_decrypt_digits_ops = define('ff1.ff1_decrypt_digits', { sync: pure.ff1_decrypt_digits, bytes: { 0: 'key' } });
var ff1_decrypt_pan_ops = define('ff1.ff1_decrypt_pan', { sync: pure.ff1_decrypt_pan, bytes: { 0: 'key' } });
var ff1_encrypt_ops = define('ff1.ff1_encrypt', { sync: pure.ff1_encrypt, bytes: { 0: 'key' } });
var ff1_encrypt_digits_ops = define('ff1.ff1_encrypt_digits', { sync: pure.ff1_encrypt_digits, bytes: { 0: 'key' } });
var ff1_encrypt_pan_ops = define('ff1.ff1_encrypt_pan', { sync: pure.ff1_encrypt_pan, bytes: { 0: 'key' } });
var luhn_check_digit_ops = define('ff1.luhn_check_digit', { sync: pure.luhn_check_digit });
var luhn_valid_ops = define('ff1.luhn_valid', { sync: pure.luhn_valid });

export var ff1_decrypt = ff1_decrypt_ops.async;
export var ff1_decrypt_sync = ff1_decrypt_ops.sync;
export var ff1_decrypt_digits = ff1_decrypt_digits_ops.async;
export var ff1_decrypt_digits_sync = ff1_decrypt_digits_ops.sync;
export var ff1_decrypt_pan = ff1_decrypt_pan_ops.async;
export var ff1_decrypt_pan_sync = ff1_decrypt_pan_ops.sync;
export var ff1_encrypt = ff1_encrypt_ops.async;
export var ff1_encrypt_sync = ff1_encrypt_ops.sync;
export var ff1_encrypt_digits = ff1_encrypt_digits_ops.async;
export var ff1_encrypt_digits_sync = ff1_encrypt_digits_ops.sync;
export var ff1_encrypt_pan = ff1_encrypt_pan_ops.async;
export var ff1_encrypt_pan_sync = ff1_encrypt_pan_ops.sync;
export var luhn_check_digit = luhn_check_digit_ops.async;
export var luhn_check_digit_sync = luhn_check_digit_ops.sync;
export var luhn_valid = luhn_valid_ops.async;
export var luhn_valid_sync = luhn_valid_ops.sync;
