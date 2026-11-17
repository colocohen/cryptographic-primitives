/**
 * qruov, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../qruov.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../qruov.js.
 */

import * as pure from '../qruov.js';
import { scheme } from '../engines/select.js';

export var qruov1q127l10_aes = scheme('qruov1q127l10_aes', pure.qruov1q127l10_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov1q127l10_shake = scheme('qruov1q127l10_shake', pure.qruov1q127l10_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov1q127l3_aes = scheme('qruov1q127l3_aes', pure.qruov1q127l3_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov1q127l3_shake = scheme('qruov1q127l3_shake', pure.qruov1q127l3_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov1q31l10_aes = scheme('qruov1q31l10_aes', pure.qruov1q31l10_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov1q31l10_shake = scheme('qruov1q31l10_shake', pure.qruov1q31l10_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov1q31l3_aes = scheme('qruov1q31l3_aes', pure.qruov1q31l3_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov1q31l3_shake = scheme('qruov1q31l3_shake', pure.qruov1q31l3_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov1q7l10_aes = scheme('qruov1q7l10_aes', pure.qruov1q7l10_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov1q7l10_shake = scheme('qruov1q7l10_shake', pure.qruov1q7l10_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov3q127l10_aes = scheme('qruov3q127l10_aes', pure.qruov3q127l10_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov3q127l10_shake = scheme('qruov3q127l10_shake', pure.qruov3q127l10_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov3q127l3_aes = scheme('qruov3q127l3_aes', pure.qruov3q127l3_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov3q127l3_shake = scheme('qruov3q127l3_shake', pure.qruov3q127l3_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov3q31l10_aes = scheme('qruov3q31l10_aes', pure.qruov3q31l10_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov3q31l10_shake = scheme('qruov3q31l10_shake', pure.qruov3q31l10_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov3q31l3_aes = scheme('qruov3q31l3_aes', pure.qruov3q31l3_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov3q31l3_shake = scheme('qruov3q31l3_shake', pure.qruov3q31l3_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov3q7l10_aes = scheme('qruov3q7l10_aes', pure.qruov3q7l10_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov3q7l10_shake = scheme('qruov3q7l10_shake', pure.qruov3q7l10_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov5q127l10_aes = scheme('qruov5q127l10_aes', pure.qruov5q127l10_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov5q127l10_shake = scheme('qruov5q127l10_shake', pure.qruov5q127l10_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov5q127l3_aes = scheme('qruov5q127l3_aes', pure.qruov5q127l3_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov5q127l3_shake = scheme('qruov5q127l3_shake', pure.qruov5q127l3_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov5q31l10_aes = scheme('qruov5q31l10_aes', pure.qruov5q31l10_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov5q31l10_shake = scheme('qruov5q31l10_shake', pure.qruov5q31l10_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov5q31l3_aes = scheme('qruov5q31l3_aes', pure.qruov5q31l3_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov5q31l3_shake = scheme('qruov5q31l3_shake', pure.qruov5q31l3_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov5q7l10_aes = scheme('qruov5q7l10_aes', pure.qruov5q7l10_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var qruov5q7l10_shake = scheme('qruov5q7l10_shake', pure.qruov5q7l10_shake, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'rnd' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
