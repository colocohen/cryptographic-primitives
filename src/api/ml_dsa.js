/**
 * ml_dsa, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ml_dsa.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ml_dsa.js.
 */

import * as pure from '../ml_dsa.js';
import { scheme } from '../engines/select.js';

export var PARAMS = pure.PARAMS;
export var ml_dsa44 = scheme('ml_dsa44', pure.ml_dsa44, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk_bytes', 2: 'rnd' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk_bytes', 2: 'sig' } }
});
export var ml_dsa65 = scheme('ml_dsa65', pure.ml_dsa65, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk_bytes', 2: 'rnd' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk_bytes', 2: 'sig' } }
});
export var ml_dsa87 = scheme('ml_dsa87', pure.ml_dsa87, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk_bytes', 2: 'rnd' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk_bytes', 2: 'sig' } }
});
