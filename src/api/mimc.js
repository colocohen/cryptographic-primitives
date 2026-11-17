/**
 * mimc, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../mimc.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../mimc.js.
 */

import * as pure from '../mimc.js';
import { define } from '../engines/select.js';

var mimc7_ops = define('mimc.mimc7', { sync: pure.mimc7 });
var mimc7_multi_ops = define('mimc.mimc7_multi', { sync: pure.mimc7_multi, bytes: { 1: 'key' } });
var mimc_feistel_ops = define('mimc.mimc_feistel', { sync: pure.mimc_feistel });
var mimc_sponge_ops = define('mimc.mimc_sponge', { sync: pure.mimc_sponge, bytes: { 2: 'key' } });
var mimc_sponge_hash_ops = define('mimc.mimc_sponge_hash', { sync: pure.mimc_sponge_hash, bytes: { 1: 'key' } });

export var P = pure.P;
export var mimc7 = mimc7_ops.async;
export var mimc7_sync = mimc7_ops.sync;
export var mimc7_multi = mimc7_multi_ops.async;
export var mimc7_multi_sync = mimc7_multi_ops.sync;
export var mimc_feistel = mimc_feistel_ops.async;
export var mimc_feistel_sync = mimc_feistel_ops.sync;
export var mimc_sponge = mimc_sponge_ops.async;
export var mimc_sponge_sync = mimc_sponge_ops.sync;
export var mimc_sponge_hash = mimc_sponge_hash_ops.async;
export var mimc_sponge_hash_sync = mimc_sponge_hash_ops.sync;
