/**
 * pool, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../pool.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../pool.js.
 */

import * as pure from '../pool.js';
import { define, scheme } from '../engines/select.js';

var pool_ops = define('pool.pool', { sync: pure.pool });

export var POOL_100 = scheme('POOL_100', pure.POOL_100, {
    blind_evaluate: { text: [1] },
    evaluate: { bytes: { 0: 'sk' } },
    finalize: { text: [1] },
    server_preprocess: { bytes: { 0: 'sk' } }
});
export var POOL_100_P4 = scheme('POOL_100_P4', pure.POOL_100_P4, {
    blind_evaluate: { text: [1] },
    evaluate: { bytes: { 0: 'sk' } },
    finalize: { text: [1] },
    server_preprocess: { bytes: { 0: 'sk' } }
});
export var POOL_128 = scheme('POOL_128', pure.POOL_128, {
    blind_evaluate: { text: [1] },
    evaluate: { bytes: { 0: 'sk' } },
    finalize: { text: [1] },
    server_preprocess: { bytes: { 0: 'sk' } }
});
export var POOL_128_P4 = scheme('POOL_128_P4', pure.POOL_128_P4, {
    blind_evaluate: { text: [1] },
    evaluate: { bytes: { 0: 'sk' } },
    finalize: { text: [1] },
    server_preprocess: { bytes: { 0: 'sk' } }
});
export var pool = pool_ops.async;
export var pool_sync = pool_ops.sync;
