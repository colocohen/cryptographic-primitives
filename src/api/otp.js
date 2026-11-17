/**
 * otp, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../otp.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../otp.js.
 */

import * as pure from '../otp.js';
import { define } from '../engines/select.js';

var base32_decode_ops = define('otp.base32_decode', { sync: pure.base32_decode });
var base32_encode_ops = define('otp.base32_encode', { sync: pure.base32_encode });
var hotp_ops = define('otp.hotp', { sync: pure.hotp, bytes: { 0: 'key' } });
var hotp_verify_ops = define('otp.hotp_verify', { sync: pure.hotp_verify, bytes: { 0: 'key' } });
var otpauth_uri_ops = define('otp.otpauth_uri', { sync: pure.otpauth_uri });
var totp_ops = define('otp.totp', { sync: pure.totp, bytes: { 0: 'key' } });
var totp_verify_ops = define('otp.totp_verify', { sync: pure.totp_verify, bytes: { 0: 'key' } });

export var base32_decode = base32_decode_ops.async;
export var base32_decode_sync = base32_decode_ops.sync;
export var base32_encode = base32_encode_ops.async;
export var base32_encode_sync = base32_encode_ops.sync;
export var hotp = hotp_ops.async;
export var hotp_sync = hotp_ops.sync;
export var hotp_verify = hotp_verify_ops.async;
export var hotp_verify_sync = hotp_verify_ops.sync;
export var otpauth_uri = otpauth_uri_ops.async;
export var otpauth_uri_sync = otpauth_uri_ops.sync;
export var totp = totp_ops.async;
export var totp_sync = totp_ops.sync;
export var totp_verify = totp_verify_ops.async;
export var totp_verify_sync = totp_verify_ops.sync;
