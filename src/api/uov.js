/**
 * uov, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../uov.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../uov.js.
 */

import * as pure from '../uov.js';
import { scheme } from '../engines/select.js';

export var uov_iii = scheme('uov_iii', pure.uov_iii, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_iii_pkc = scheme('uov_iii_pkc', pure.uov_iii_pkc, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_iii_pkc_skc = scheme('uov_iii_pkc_skc', pure.uov_iii_pkc_skc, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_ip = scheme('uov_ip', pure.uov_ip, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_ip_pkc = scheme('uov_ip_pkc', pure.uov_ip_pkc, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_ip_pkc_skc = scheme('uov_ip_pkc_skc', pure.uov_ip_pkc_skc, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_is = scheme('uov_is', pure.uov_is, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_is_pkc = scheme('uov_is_pkc', pure.uov_is_pkc, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_is_pkc_skc = scheme('uov_is_pkc_skc', pure.uov_is_pkc_skc, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_v = scheme('uov_v', pure.uov_v, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_v_pkc = scheme('uov_v_pkc', pure.uov_v_pkc, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var uov_v_pkc_skc = scheme('uov_v_pkc_skc', pure.uov_v_pkc_skc, {
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
