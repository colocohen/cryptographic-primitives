/**
 * frodokem, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../frodokem.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../frodokem.js.
 */

import * as pure from '../frodokem.js';
import { scheme } from '../engines/select.js';

export var efrodokem1344_aes = scheme('efrodokem1344_aes', pure.efrodokem1344_aes, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var efrodokem1344_shake = scheme('efrodokem1344_shake', pure.efrodokem1344_shake, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var efrodokem640_aes = scheme('efrodokem640_aes', pure.efrodokem640_aes, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var efrodokem640_shake = scheme('efrodokem640_shake', pure.efrodokem640_shake, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var efrodokem976_aes = scheme('efrodokem976_aes', pure.efrodokem976_aes, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var efrodokem976_shake = scheme('efrodokem976_shake', pure.efrodokem976_shake, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var frodokem1344_aes = scheme('frodokem1344_aes', pure.frodokem1344_aes, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var frodokem1344_shake = scheme('frodokem1344_shake', pure.frodokem1344_shake, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var frodokem640_aes = scheme('frodokem640_aes', pure.frodokem640_aes, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var frodokem640_shake = scheme('frodokem640_shake', pure.frodokem640_shake, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var frodokem976_aes = scheme('frodokem976_aes', pure.frodokem976_aes, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
export var frodokem976_shake = scheme('frodokem976_shake', pure.frodokem976_shake, {
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk' } }
});
