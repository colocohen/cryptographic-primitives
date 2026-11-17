/**
 * hqc, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../hqc.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../hqc.js.
 */

import * as pure from '../hqc.js';
import { scheme } from '../engines/select.js';

export var hqc1 = scheme('hqc1', pure.hqc1, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { text: [2], bytes: { 0: 'pk' } }
});
export var hqc3 = scheme('hqc3', pure.hqc3, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { text: [2], bytes: { 0: 'pk' } }
});
export var hqc5 = scheme('hqc5', pure.hqc5, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { text: [2], bytes: { 0: 'pk' } }
});
