/**
 * falcon, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../falcon.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../falcon.js.
 */

import * as pure from '../falcon.js';
import { scheme } from '../engines/select.js';

export var PARAMS = pure.PARAMS;
export var falcon1024 = scheme('falcon1024', pure.falcon1024, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var falcon512 = scheme('falcon512', pure.falcon512, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
