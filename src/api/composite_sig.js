/**
 * composite_sig, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../composite_sig.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../composite_sig.js.
 */

import * as pure from '../composite_sig.js';
import { scheme } from '../engines/select.js';

export var BY_LABEL = pure.BY_LABEL;
export var mldsa44_ecdsa_p256_sha256 = scheme('mldsa44_ecdsa_p256_sha256', pure.mldsa44_ecdsa_p256_sha256, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa44_ed25519_sha512 = scheme('mldsa44_ed25519_sha512', pure.mldsa44_ed25519_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa44_rsa2048_pkcs15_sha256 = scheme('mldsa44_rsa2048_pkcs15_sha256', pure.mldsa44_rsa2048_pkcs15_sha256, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa44_rsa2048_pss_sha256 = scheme('mldsa44_rsa2048_pss_sha256', pure.mldsa44_rsa2048_pss_sha256, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa65_ecdsa_brainpoolp256r1_sha512 = scheme('mldsa65_ecdsa_brainpoolp256r1_sha512', pure.mldsa65_ecdsa_brainpoolp256r1_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa65_ecdsa_p256_sha512 = scheme('mldsa65_ecdsa_p256_sha512', pure.mldsa65_ecdsa_p256_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa65_ecdsa_p384_sha512 = scheme('mldsa65_ecdsa_p384_sha512', pure.mldsa65_ecdsa_p384_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa65_ed25519_sha512 = scheme('mldsa65_ed25519_sha512', pure.mldsa65_ed25519_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa65_rsa3072_pkcs15_sha512 = scheme('mldsa65_rsa3072_pkcs15_sha512', pure.mldsa65_rsa3072_pkcs15_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa65_rsa3072_pss_sha512 = scheme('mldsa65_rsa3072_pss_sha512', pure.mldsa65_rsa3072_pss_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa65_rsa4096_pkcs15_sha512 = scheme('mldsa65_rsa4096_pkcs15_sha512', pure.mldsa65_rsa4096_pkcs15_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa65_rsa4096_pss_sha512 = scheme('mldsa65_rsa4096_pss_sha512', pure.mldsa65_rsa4096_pss_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa87_ecdsa_brainpoolp384r1_sha512 = scheme('mldsa87_ecdsa_brainpoolp384r1_sha512', pure.mldsa87_ecdsa_brainpoolp384r1_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa87_ecdsa_p384_sha512 = scheme('mldsa87_ecdsa_p384_sha512', pure.mldsa87_ecdsa_p384_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa87_ecdsa_p521_sha512 = scheme('mldsa87_ecdsa_p521_sha512', pure.mldsa87_ecdsa_p521_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa87_ed448_shake256 = scheme('mldsa87_ed448_shake256', pure.mldsa87_ed448_shake256, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa87_rsa3072_pss_sha512 = scheme('mldsa87_rsa3072_pss_sha512', pure.mldsa87_rsa3072_pss_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
export var mldsa87_rsa4096_pss_sha512 = scheme('mldsa87_rsa4096_pss_sha512', pure.mldsa87_rsa4096_pss_sha512, {
    assemble: { bytes: { 0: 'mldsa_sig', 1: 'trad_sig' } },
    halves: { text: [0, 1] },
    halves_digest: { text: [1], bytes: { 0: 'digest' } },
    message_representative: { text: [0, 1] },
    public_key: { bytes: { 0: 'sk' } },
    public_key_from: { bytes: { 0: 'mldsa_pk', 1: 'trad_pk' } },
    sign: { text: [1, 2], bytes: { 0: 'sk' } },
    sign_digest: { text: [2], bytes: { 0: 'sk', 1: 'digest' } },
    verify: { text: [1, 3], bytes: { 0: 'pk', 2: 'sig' } },
    verify_digest: { text: [3], bytes: { 0: 'pk', 1: 'digest', 2: 'sig' } }
});
