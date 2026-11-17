/**
 * brainpool, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../brainpool.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../brainpool.js.
 */

import * as pure from '../brainpool.js';
import { scheme } from '../engines/select.js';

export var BP256R1_CURVE = pure.BP256R1_CURVE;
export var BP256R1_GROUP = pure.BP256R1_GROUP;
export var BP384R1_CURVE = pure.BP384R1_CURVE;
export var BP384R1_GROUP = pure.BP384R1_GROUP;
export var BP512R1_CURVE = pure.BP512R1_CURVE;
export var BP512R1_GROUP = pure.BP512R1_GROUP;
export var brainpoolP256r1 = scheme('brainpoolP256r1', pure.brainpoolP256r1, {
    ecdh: { bytes: { 1: 'peer_public_key' } },
    ecdh_create: { kind: 'ecdh', bytes: { 0: 'secret' } },
    signer_create: { kind: 'ecdsa_signer', bytes: { 0: 'secret' } },
    verifier_create: { kind: 'ecdsa_verifier', bytes: { 0: 'public_key' } },
    keygen: { bytes: { 0: 'seed' } },
    recover: { bytes: { 0: 'msg_hash', 1: 'sig' } },
    sig_to_compact: { bytes: { 0: 'sig' } },
    sig_to_der: { bytes: { 0: 'sig' } },
    sign: { bytes: { 0: 'msg_hash', 2: 'extra' } },
    sign_message: { text: [1], bytes: { 3: 'extra' } },
    verify: { bytes: { 0: 'msg_hash', 1: 'sig', 2: 'public_key' } },
    verify_message: { text: [1], bytes: { 2: 'sig', 3: 'public_key' } }
});
export var brainpoolP384r1 = scheme('brainpoolP384r1', pure.brainpoolP384r1, {
    ecdh: { bytes: { 1: 'peer_public_key' } },
    ecdh_create: { kind: 'ecdh', bytes: { 0: 'secret' } },
    signer_create: { kind: 'ecdsa_signer', bytes: { 0: 'secret' } },
    verifier_create: { kind: 'ecdsa_verifier', bytes: { 0: 'public_key' } },
    keygen: { bytes: { 0: 'seed' } },
    recover: { bytes: { 0: 'msg_hash', 1: 'sig' } },
    sig_to_compact: { bytes: { 0: 'sig' } },
    sig_to_der: { bytes: { 0: 'sig' } },
    sign: { bytes: { 0: 'msg_hash', 2: 'extra' } },
    sign_message: { text: [1], bytes: { 3: 'extra' } },
    verify: { bytes: { 0: 'msg_hash', 1: 'sig', 2: 'public_key' } },
    verify_message: { text: [1], bytes: { 2: 'sig', 3: 'public_key' } }
});
export var brainpoolP512r1 = scheme('brainpoolP512r1', pure.brainpoolP512r1, {
    ecdh: { bytes: { 1: 'peer_public_key' } },
    ecdh_create: { kind: 'ecdh', bytes: { 0: 'secret' } },
    signer_create: { kind: 'ecdsa_signer', bytes: { 0: 'secret' } },
    verifier_create: { kind: 'ecdsa_verifier', bytes: { 0: 'public_key' } },
    keygen: { bytes: { 0: 'seed' } },
    recover: { bytes: { 0: 'msg_hash', 1: 'sig' } },
    sig_to_compact: { bytes: { 0: 'sig' } },
    sig_to_der: { bytes: { 0: 'sig' } },
    sign: { bytes: { 0: 'msg_hash', 2: 'extra' } },
    sign_message: { text: [1], bytes: { 3: 'extra' } },
    verify: { bytes: { 0: 'msg_hash', 1: 'sig', 2: 'public_key' } },
    verify_message: { text: [1], bytes: { 2: 'sig', 3: 'public_key' } }
});
