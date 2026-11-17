/**
 * xwing, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../xwing.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../xwing.js.
 */

import * as pure from '../xwing.js';
import { define } from '../engines/select.js';

var check_public_key_ops = define('xwing.check_public_key', { sync: pure.check_public_key, bytes: { 0: 'pk' } });
var decaps_ops = define('xwing.decaps', { sync: pure.decaps, bytes: { 0: 'sk', 1: 'ct' } });
var encaps_ops = define('xwing.encaps', { sync: pure.encaps, bytes: { 0: 'pk' } });
var encaps_derand_ops = define('xwing.encaps_derand', { sync: pure.encaps_derand, bytes: { 0: 'pk', 1: 'rnd' } });
var keygen_ops = define('xwing.keygen', { sync: pure.keygen });
var keygen_derand_ops = define('xwing.keygen_derand', { sync: pure.keygen_derand, bytes: { 0: 'seed' } });
var public_key_ops = define('xwing.public_key', { sync: pure.public_key, bytes: { 0: 'sk' } });

export var CT_BYTES = pure.CT_BYTES;
export var PK_BYTES = pure.PK_BYTES;
export var SK_BYTES = pure.SK_BYTES;
export var SS_BYTES = pure.SS_BYTES;
export var check_public_key = check_public_key_ops.async;
export var check_public_key_sync = check_public_key_ops.sync;
export var decaps = decaps_ops.async;
export var decaps_sync = decaps_ops.sync;
export var encaps = encaps_ops.async;
export var encaps_sync = encaps_ops.sync;
export var encaps_derand = encaps_derand_ops.async;
export var encaps_derand_sync = encaps_derand_ops.sync;
export var keygen = keygen_ops.async;
export var keygen_sync = keygen_ops.sync;
export var keygen_derand = keygen_derand_ops.async;
export var keygen_derand_sync = keygen_derand_ops.sync;
export var public_key = public_key_ops.async;
export var public_key_sync = public_key_ops.sync;
