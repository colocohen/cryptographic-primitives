/**
 * hybrid_kem, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../hybrid_kem.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../hybrid_kem.js.
 */

import * as pure from '../hybrid_kem.js';
import { scheme } from '../engines/select.js';

export var mlkem1024_p384 = scheme('mlkem1024_p384', pure.mlkem1024_p384, {
    check_public_key: { bytes: { 0: 'pk' } },
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk', 1: 'rnd' } },
    keygen_derand: { bytes: { 0: 'seed' } },
    public_key: { bytes: { 0: 'sk' } },
    sub_keys: { bytes: { 0: 'sk' } }
});
export var mlkem768_p256 = scheme('mlkem768_p256', pure.mlkem768_p256, {
    check_public_key: { bytes: { 0: 'pk' } },
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk', 1: 'rnd' } },
    keygen_derand: { bytes: { 0: 'seed' } },
    public_key: { bytes: { 0: 'sk' } },
    sub_keys: { bytes: { 0: 'sk' } }
});
export var mlkem768_x25519 = scheme('mlkem768_x25519', pure.mlkem768_x25519, {
    check_public_key: { bytes: { 0: 'pk' } },
    decaps: { bytes: { 0: 'sk', 1: 'ct' } },
    encaps: { bytes: { 0: 'pk' } },
    encaps_derand: { bytes: { 0: 'pk', 1: 'rnd' } },
    keygen_derand: { bytes: { 0: 'seed' } },
    public_key: { bytes: { 0: 'sk' } },
    sub_keys: { bytes: { 0: 'sk' } }
});
export var secp256r1mlkem768 = scheme('secp256r1mlkem768', pure.secp256r1mlkem768, {
    decaps: { bytes: { 0: 'sk' } },
    encaps_derand: { bytes: { 1: 'rnd' } },
    keygen_derand: { bytes: { 0: 'sk' } }
});
export var secp384r1mlkem1024 = scheme('secp384r1mlkem1024', pure.secp384r1mlkem1024, {
    decaps: { bytes: { 0: 'sk' } },
    encaps_derand: { bytes: { 1: 'rnd' } },
    keygen_derand: { bytes: { 0: 'sk' } }
});
export var x25519mlkem768 = scheme('x25519mlkem768', pure.x25519mlkem768, {
    decaps: { bytes: { 0: 'sk' } },
    encaps_derand: { bytes: { 1: 'rnd' } },
    keygen_derand: { bytes: { 0: 'sk' } }
});
