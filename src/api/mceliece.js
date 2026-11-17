/**
 * mceliece, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../mceliece.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../mceliece.js.
 */

import * as pure from '../mceliece.js';
import { scheme } from '../engines/select.js';

export var mceliece348864 = scheme('mceliece348864', pure.mceliece348864, {
    decaps: { bytes: { 0: 'sk' } },
    encaps: { bytes: { 0: 'pk' } }
});
export var mceliece348864f = scheme('mceliece348864f', pure.mceliece348864f, {
    decaps: { bytes: { 0: 'sk' } },
    encaps: { bytes: { 0: 'pk' } }
});
export var mceliece460896 = scheme('mceliece460896', pure.mceliece460896, {
    decaps: { bytes: { 0: 'sk' } },
    encaps: { bytes: { 0: 'pk' } }
});
export var mceliece460896f = scheme('mceliece460896f', pure.mceliece460896f, {
    decaps: { bytes: { 0: 'sk' } },
    encaps: { bytes: { 0: 'pk' } }
});
export var mceliece6688128 = scheme('mceliece6688128', pure.mceliece6688128, {
    decaps: { bytes: { 0: 'sk' } },
    encaps: { bytes: { 0: 'pk' } }
});
export var mceliece6688128f = scheme('mceliece6688128f', pure.mceliece6688128f, {
    decaps: { bytes: { 0: 'sk' } },
    encaps: { bytes: { 0: 'pk' } }
});
export var mceliece6960119 = scheme('mceliece6960119', pure.mceliece6960119, {
    decaps: { bytes: { 0: 'sk' } },
    encaps: { bytes: { 0: 'pk' } }
});
export var mceliece6960119f = scheme('mceliece6960119f', pure.mceliece6960119f, {
    decaps: { bytes: { 0: 'sk' } },
    encaps: { bytes: { 0: 'pk' } }
});
export var mceliece8192128 = scheme('mceliece8192128', pure.mceliece8192128, {
    decaps: { bytes: { 0: 'sk' } },
    encaps: { bytes: { 0: 'pk' } }
});
export var mceliece8192128f = scheme('mceliece8192128f', pure.mceliece8192128f, {
    decaps: { bytes: { 0: 'sk' } },
    encaps: { bytes: { 0: 'pk' } }
});
