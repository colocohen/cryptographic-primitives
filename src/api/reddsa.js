/**
 * reddsa, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../reddsa.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../reddsa.js.
 */

import * as pure from '../reddsa.js';
import { define } from '../engines/select.js';

var h_star_ops = define('reddsa.h_star', { sync: pure.h_star });
var keygen_ops = define('reddsa.keygen', { sync: pure.keygen });
var public_key_ops = define('reddsa.public_key', { sync: pure.public_key, bytes: { 1: 'sk' } });
var randomize_private_ops = define('reddsa.randomize_private', { sync: pure.randomize_private, bytes: { 1: 'sk' } });
var randomize_public_ops = define('reddsa.randomize_public', { sync: pure.randomize_public });
var randomizer_ops = define('reddsa.randomizer', { sync: pure.randomizer });
var sign_ops = define('reddsa.sign', { sync: pure.sign, text: [2], bytes: { 1: 'sk' } });
var verify_ops = define('reddsa.verify', { sync: pure.verify, text: [2], bytes: { 3: 'sig' } });

export var REDJUBJUB_BINDING = pure.REDJUBJUB_BINDING;
export var REDJUBJUB_SPEND_AUTH = pure.REDJUBJUB_SPEND_AUTH;
export var REDPALLAS_BINDING = pure.REDPALLAS_BINDING;
export var REDPALLAS_SPEND_AUTH = pure.REDPALLAS_SPEND_AUTH;
export var h_star = h_star_ops.async;
export var h_star_sync = h_star_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var public_key = public_key_ops.async;
export var public_key_sync = public_key_ops.sync;
export var randomize_private = randomize_private_ops.async;
export var randomize_private_sync = randomize_private_ops.sync;
export var randomize_public = randomize_public_ops.async;
export var randomize_public_sync = randomize_public_ops.sync;
export var randomizer = randomizer_ops.async;
export var randomizer_sync = randomizer_ops.sync;
export var sign = sign_ops.async;
export var sign_sync = sign_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
