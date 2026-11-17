/**
 * ml_kem, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ml_kem.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ml_kem.js.
 */

import * as pure from '../ml_kem.js';
import { define, scheme } from '../engines/select.js';

var compress_ops = define('ml_kem.compress', { sync: pure.compress });
var decompress_ops = define('ml_kem.decompress', { sync: pure.decompress });
var sample_ntt_ops = define('ml_kem.sample_ntt', { sync: pure.sample_ntt, bytes: { 0: 'seed' } });

export var PARAMS = pure.PARAMS;
export var compress = compress_ops.async;
export var compress_sync = compress_ops.sync;
export var decompress = decompress_ops.async;
export var decompress_sync = decompress_ops.sync;
export var ml_kem1024 = scheme('ml_kem1024', pure.ml_kem1024, {
    check_ek: { bytes: { 0: 'ek' } },
    decaps: { bytes: { 0: 'dk', 1: 'ct' } },
    decaps_create: { kind: 'decaps', bytes: { 0: 'dk' } },
    encaps: { bytes: { 0: 'ek' } },
    keygen: { bytes: { 0: 'seed' } },
    split_ek: { bytes: { 0: 'ek' } }
});
export var ml_kem512 = scheme('ml_kem512', pure.ml_kem512, {
    check_ek: { bytes: { 0: 'ek' } },
    decaps: { bytes: { 0: 'dk', 1: 'ct' } },
    decaps_create: { kind: 'decaps', bytes: { 0: 'dk' } },
    encaps: { bytes: { 0: 'ek' } },
    keygen: { bytes: { 0: 'seed' } },
    split_ek: { bytes: { 0: 'ek' } }
});
export var ml_kem768 = scheme('ml_kem768', pure.ml_kem768, {
    check_ek: { bytes: { 0: 'ek' } },
    decaps: { bytes: { 0: 'dk', 1: 'ct' } },
    decaps_create: { kind: 'decaps', bytes: { 0: 'dk' } },
    encaps: { bytes: { 0: 'ek' } },
    keygen: { bytes: { 0: 'seed' } },
    split_ek: { bytes: { 0: 'ek' } }
});
export var sample_ntt = sample_ntt_ops.async;
export var sample_ntt_sync = sample_ntt_ops.sync;
