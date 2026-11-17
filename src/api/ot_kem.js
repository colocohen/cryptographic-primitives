/**
 * ot_kem, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ot_kem.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ot_kem.js.
 */

import * as pure from '../ot_kem.js';
import { scheme } from '../engines/select.js';

export var ot_ml_kem1024 = scheme('ot_ml_kem1024', pure.ot_ml_kem1024, {
    receiver_choose: { text: [2] },
    receiver_key: { text: [1] },
    sender_respond: { text: [0, 2] }
});
export var ot_ml_kem512 = scheme('ot_ml_kem512', pure.ot_ml_kem512, {
    receiver_choose: { text: [2] },
    receiver_key: { text: [1] },
    sender_respond: { text: [0, 2] }
});
export var ot_ml_kem768 = scheme('ot_ml_kem768', pure.ot_ml_kem768, {
    receiver_choose: { text: [2] },
    receiver_key: { text: [1] },
    sender_respond: { text: [0, 2] }
});
