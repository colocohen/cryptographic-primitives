/**
 * lms, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../lms.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../lms.js.
 */

import * as pure from '../lms.js';
import { define, scheme } from '../engines/select.js';

var hss_ops = define('lms.hss', { sync: pure.hss });
var lms_ops = define('lms.lms', { sync: pure.lms });

export var LMS_TYPES = pure.LMS_TYPES;
export var OTS_TYPES = pure.OTS_TYPES;
export var hss = hss_ops.async;
export var hss_sync = hss_ops.sync;
export var lms = lms_ops.async;
export var lms_sync = lms_ops.sync;
export var lms_sha256_h10_w4 = scheme('lms_sha256_h10_w4', pure.lms_sha256_h10_w4, {
    keygen: { bytes: { 0: 'seed', 1: 'I' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'C' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var lms_sha256_h10_w8 = scheme('lms_sha256_h10_w8', pure.lms_sha256_h10_w8, {
    keygen: { bytes: { 0: 'seed', 1: 'I' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'C' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var lms_sha256_h15_w8 = scheme('lms_sha256_h15_w8', pure.lms_sha256_h15_w8, {
    keygen: { bytes: { 0: 'seed', 1: 'I' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'C' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var lms_sha256_h20_w8 = scheme('lms_sha256_h20_w8', pure.lms_sha256_h20_w8, {
    keygen: { bytes: { 0: 'seed', 1: 'I' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'C' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var lms_sha256_h5_w1 = scheme('lms_sha256_h5_w1', pure.lms_sha256_h5_w1, {
    keygen: { bytes: { 0: 'seed', 1: 'I' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'C' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var lms_sha256_h5_w2 = scheme('lms_sha256_h5_w2', pure.lms_sha256_h5_w2, {
    keygen: { bytes: { 0: 'seed', 1: 'I' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'C' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var lms_sha256_h5_w4 = scheme('lms_sha256_h5_w4', pure.lms_sha256_h5_w4, {
    keygen: { bytes: { 0: 'seed', 1: 'I' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'C' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
export var lms_sha256_h5_w8 = scheme('lms_sha256_h5_w8', pure.lms_sha256_h5_w8, {
    keygen: { bytes: { 0: 'seed', 1: 'I' } },
    sign: { text: [1], bytes: { 0: 'sk', 2: 'C' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } }
});
