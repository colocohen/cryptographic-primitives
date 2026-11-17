/**
 * nist, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../nist.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../nist.js.
 */

import * as pure from '../nist.js';
import { scheme } from '../engines/select.js';

export var P256_CURVE = pure.P256_CURVE;
export var P256_GROUP = pure.P256_GROUP;
export var P384_CURVE = pure.P384_CURVE;
export var P384_GROUP = pure.P384_GROUP;
export var P521_CURVE = pure.P521_CURVE;
export var P521_GROUP = pure.P521_GROUP;
export var p256 = scheme('p256', pure.p256, {
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
export var p256_h2c = scheme('p256_h2c', pure.p256_h2c, {
    encode_to_curve: { text: [0, 1] },
    hash_to_curve: { text: [0, 1] },
    hash_to_field: { text: [0, 2] }
});
export var p384 = scheme('p384', pure.p384, {
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
export var p384_h2c = scheme('p384_h2c', pure.p384_h2c, {
    encode_to_curve: { text: [0, 1] },
    hash_to_curve: { text: [0, 1] },
    hash_to_field: { text: [0, 2] }
});
export var p521 = scheme('p521', pure.p521, {
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
export var p521_h2c = scheme('p521_h2c', pure.p521_h2c, {
    encode_to_curve: { text: [0, 1] },
    hash_to_curve: { text: [0, 1] },
    hash_to_field: { text: [0, 2] }
});
export var prime256v1 = scheme('prime256v1', pure.prime256v1, {
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
export var secp256r1 = scheme('secp256r1', pure.secp256r1, {
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
export var secp384r1 = scheme('secp384r1', pure.secp384r1, {
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
export var secp521r1 = scheme('secp521r1', pure.secp521r1, {
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
