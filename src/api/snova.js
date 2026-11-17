/**
 * snova, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../snova.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../snova.js.
 */

import * as pure from '../snova.js';
import { scheme } from '../engines/select.js';

export var snova_i_b = scheme('snova_i_b', pure.snova_i_b, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_i_b_aes = scheme('snova_i_b_aes', pure.snova_i_b_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_i_k = scheme('snova_i_k', pure.snova_i_k, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_i_k_aes = scheme('snova_i_k_aes', pure.snova_i_k_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_i_s = scheme('snova_i_s', pure.snova_i_s, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_i_s_aes = scheme('snova_i_s_aes', pure.snova_i_s_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_iii_b = scheme('snova_iii_b', pure.snova_iii_b, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_iii_b_aes = scheme('snova_iii_b_aes', pure.snova_iii_b_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_iii_k = scheme('snova_iii_k', pure.snova_iii_k, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_iii_k_aes = scheme('snova_iii_k_aes', pure.snova_iii_k_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_iii_s = scheme('snova_iii_s', pure.snova_iii_s, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_iii_s_aes = scheme('snova_iii_s_aes', pure.snova_iii_s_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_v_b = scheme('snova_v_b', pure.snova_v_b, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_v_b_aes = scheme('snova_v_b_aes', pure.snova_v_b_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_v_k = scheme('snova_v_k', pure.snova_v_k, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_v_k_aes = scheme('snova_v_k_aes', pure.snova_v_k_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_v_s = scheme('snova_v_s', pure.snova_v_s, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var snova_v_s_aes = scheme('snova_v_s_aes', pure.snova_v_s_aes, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
