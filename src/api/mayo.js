/**
 * mayo, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../mayo.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../mayo.js.
 */

import * as pure from '../mayo.js';
import { scheme } from '../engines/select.js';

export var mayo1 = scheme('mayo1', pure.mayo1, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var mayo2 = scheme('mayo2', pure.mayo2, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var mayo3 = scheme('mayo3', pure.mayo3, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var mayo5 = scheme('mayo5', pure.mayo5, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
