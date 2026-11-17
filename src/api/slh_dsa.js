/**
 * slh_dsa, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../slh_dsa.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../slh_dsa.js.
 */

import * as pure from '../slh_dsa.js';
import { scheme } from '../engines/select.js';

export var PARAMS = pure.PARAMS;
export var slh_dsa_sha2_128f = scheme('slh_dsa_sha2_128f', pure.slh_dsa_sha2_128f, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_sha2_128s = scheme('slh_dsa_sha2_128s', pure.slh_dsa_sha2_128s, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_sha2_192f = scheme('slh_dsa_sha2_192f', pure.slh_dsa_sha2_192f, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_sha2_192s = scheme('slh_dsa_sha2_192s', pure.slh_dsa_sha2_192s, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_sha2_256f = scheme('slh_dsa_sha2_256f', pure.slh_dsa_sha2_256f, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_sha2_256s = scheme('slh_dsa_sha2_256s', pure.slh_dsa_sha2_256s, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_shake_128f = scheme('slh_dsa_shake_128f', pure.slh_dsa_shake_128f, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_shake_128s = scheme('slh_dsa_shake_128s', pure.slh_dsa_shake_128s, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_shake_192f = scheme('slh_dsa_shake_192f', pure.slh_dsa_shake_192f, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_shake_192s = scheme('slh_dsa_shake_192s', pure.slh_dsa_shake_192s, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_shake_256f = scheme('slh_dsa_shake_256f', pure.slh_dsa_shake_256f, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
export var slh_dsa_shake_256s = scheme('slh_dsa_shake_256s', pure.slh_dsa_shake_256s, {
    hash_sign: { text: [1, 4], bytes: { 0: 'sk', 3: 'rnd' } },
    hash_sign_digest: { text: [4], bytes: { 0: 'sk', 1: 'digest', 3: 'rnd' } },
    hash_verify: { text: [1, 4], bytes: { 0: 'pk', 2: 'sig' } },
    hash_verify_digest: { text: [4], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } },
    keygen: { bytes: { 0: 'seed' } },
    sign: { text: [1, 3], bytes: { 0: 'sk', 2: 'rnd' } },
    sign_internal: { bytes: { 0: 'sk', 2: 'opt_rand' } },
    signer_create: { kind: 'fips_signer', bytes: { 0: 'sk' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_internal: { bytes: { 0: 'pk', 2: 'sig' } }
});
