/**
 * blind, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../blind.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../blind.js.
 */

import * as pure from '../blind.js';
import { define } from '../engines/select.js';

var rsa_blind_ops = define('blind.rsa_blind', { sync: pure.rsa_blind, bytes: { 0: 'pk' } });
var rsa_sign_blinded_ops = define('blind.rsa_sign_blinded', { sync: pure.rsa_sign_blinded, bytes: { 0: 'sk' } });
var rsa_unblind_ops = define('blind.rsa_unblind', { sync: pure.rsa_unblind, bytes: { 0: 'pk' } });
var schnorr_blind_ops = define('blind.schnorr_blind', { sync: pure.schnorr_blind, text: [2], bytes: { 1: 'pubkey' } });
var schnorr_blind_commit_ops = define('blind.schnorr_blind_commit', { sync: pure.schnorr_blind_commit });
var schnorr_sign_blinded_ops = define('blind.schnorr_sign_blinded', { sync: pure.schnorr_sign_blinded });
var schnorr_unblind_ops = define('blind.schnorr_unblind', { sync: pure.schnorr_unblind });

export var rsa_blind = rsa_blind_ops.async;
export var rsa_blind_sync = rsa_blind_ops.sync;
export var rsa_sign_blinded = rsa_sign_blinded_ops.async;
export var rsa_sign_blinded_sync = rsa_sign_blinded_ops.sync;
export var rsa_unblind = rsa_unblind_ops.async;
export var rsa_unblind_sync = rsa_unblind_ops.sync;
export var schnorr_blind = schnorr_blind_ops.async;
export var schnorr_blind_sync = schnorr_blind_ops.sync;
export var schnorr_blind_commit = schnorr_blind_commit_ops.async;
export var schnorr_blind_commit_sync = schnorr_blind_commit_ops.sync;
export var schnorr_sign_blinded = schnorr_sign_blinded_ops.async;
export var schnorr_sign_blinded_sync = schnorr_sign_blinded_ops.sync;
export var schnorr_unblind = schnorr_unblind_ops.async;
export var schnorr_unblind_sync = schnorr_unblind_ops.sync;
