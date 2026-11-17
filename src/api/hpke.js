/**
 * hpke, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../hpke.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../hpke.js.
 */

import * as pure from '../hpke.js';
import { scheme } from '../engines/select.js';

export var AES_128_GCM = scheme('AES_128_GCM', pure.AES_128_GCM, {
    open: { text: [3] },
    seal: { text: [3] }
});
export var AES_256_GCM = scheme('AES_256_GCM', pure.AES_256_GCM, {
    open: { text: [3] },
    seal: { text: [3] }
});
export var CHACHA20_POLY1305 = scheme('CHACHA20_POLY1305', pure.CHACHA20_POLY1305, {
    open: { text: [3] },
    seal: { text: [3] }
});
export var DHKEM_P256 = scheme('DHKEM_P256', pure.DHKEM_P256, {
    derive_key_pair: { text: [0] },
    derive_pub: { bytes: { 0: 'sk' } },
    dh: { bytes: { 0: 'sk', 1: 'pk' } },
    hash: { text: [0] }
});
export var DHKEM_P384 = scheme('DHKEM_P384', pure.DHKEM_P384, {
    derive_key_pair: { text: [0] },
    derive_pub: { bytes: { 0: 'sk' } },
    dh: { bytes: { 0: 'sk', 1: 'pk' } },
    hash: { text: [0] }
});
export var DHKEM_P521 = scheme('DHKEM_P521', pure.DHKEM_P521, {
    derive_key_pair: { text: [0] },
    derive_pub: { bytes: { 0: 'sk' } },
    dh: { bytes: { 0: 'sk', 1: 'pk' } },
    hash: { text: [0] }
});
export var DHKEM_X25519 = scheme('DHKEM_X25519', pure.DHKEM_X25519, {
    derive_key_pair: { text: [0] },
    dh: { bytes: { 0: 'sk', 1: 'pk' } },
    hash: { text: [0] }
});
export var DHKEM_X448 = scheme('DHKEM_X448', pure.DHKEM_X448, {
    derive_key_pair: { text: [0] },
    dh: { bytes: { 0: 'sk', 1: 'pk' } },
    hash: { text: [0] }
});
export var HKDF_SHA256 = scheme('HKDF_SHA256', pure.HKDF_SHA256, {
    hash: { text: [0] }
});
export var HKDF_SHA384 = scheme('HKDF_SHA384', pure.HKDF_SHA384, {
    hash: { text: [0] }
});
export var HKDF_SHA512 = scheme('HKDF_SHA512', pure.HKDF_SHA512, {
    hash: { text: [0] }
});
export var MLKEM1024_P384 = scheme('MLKEM1024_P384', pure.MLKEM1024_P384, {
    decap: { bytes: { 0: 'enc', 1: 'sk' } },
    derive_key_pair: { text: [0] },
    derive_pub: { bytes: { 0: 'sk' } },
    encap: { bytes: { 0: 'pk' } }
});
export var MLKEM768_P256 = scheme('MLKEM768_P256', pure.MLKEM768_P256, {
    decap: { bytes: { 0: 'enc', 1: 'sk' } },
    derive_key_pair: { text: [0] },
    derive_pub: { bytes: { 0: 'sk' } },
    encap: { bytes: { 0: 'pk' } }
});
export var ML_KEM_1024 = scheme('ML_KEM_1024', pure.ML_KEM_1024, {
    decap: { bytes: { 0: 'enc', 1: 'sk' } },
    derive_key_pair: { text: [0] },
    derive_pub: { bytes: { 0: 'sk' } },
    encap: { bytes: { 0: 'pk' } }
});
export var ML_KEM_512 = scheme('ML_KEM_512', pure.ML_KEM_512, {
    decap: { bytes: { 0: 'enc', 1: 'sk' } },
    derive_key_pair: { text: [0] },
    derive_pub: { bytes: { 0: 'sk' } },
    encap: { bytes: { 0: 'pk' } }
});
export var ML_KEM_768 = scheme('ML_KEM_768', pure.ML_KEM_768, {
    decap: { bytes: { 0: 'enc', 1: 'sk' } },
    derive_key_pair: { text: [0] },
    derive_pub: { bytes: { 0: 'sk' } },
    encap: { bytes: { 0: 'pk' } }
});
export var SHAKE128_KDF = scheme('SHAKE128_KDF', pure.SHAKE128_KDF);
export var SHAKE256_KDF = scheme('SHAKE256_KDF', pure.SHAKE256_KDF);
export var TURBOSHAKE128_KDF = scheme('TURBOSHAKE128_KDF', pure.TURBOSHAKE128_KDF);
export var TURBOSHAKE256_KDF = scheme('TURBOSHAKE256_KDF', pure.TURBOSHAKE256_KDF);
export var XWING = scheme('XWING', pure.XWING, {
    decap: { bytes: { 0: 'enc', 1: 'sk' } },
    derive_key_pair: { text: [0] },
    derive_pub: { bytes: { 0: 'sk' } },
    encap: { bytes: { 0: 'pk' } }
});
export var p256_sha256_aes128gcm = scheme('p256_sha256_aes128gcm', pure.p256_sha256_aes128gcm, {
    open: { text: [3, 4], bytes: { 0: 'sk_r', 1: 'enc', 2: 'ct' } },
    open_context: { text: [2], bytes: { 0: 'sk_r', 1: 'enc' } },
    open_context_with_dh: { text: [3], bytes: { 1: 'enc', 2: 'pk_r' } },
    seal: { text: [1, 3, 4], bytes: { 0: 'pk_r' } },
    seal_context: { text: [2], bytes: { 0: 'pk_r' } }
});
export var p521_sha512_aes256gcm = scheme('p521_sha512_aes256gcm', pure.p521_sha512_aes256gcm, {
    open: { text: [3, 4], bytes: { 0: 'sk_r', 1: 'enc', 2: 'ct' } },
    open_context: { text: [2], bytes: { 0: 'sk_r', 1: 'enc' } },
    open_context_with_dh: { text: [3], bytes: { 1: 'enc', 2: 'pk_r' } },
    seal: { text: [1, 3, 4], bytes: { 0: 'pk_r' } },
    seal_context: { text: [2], bytes: { 0: 'pk_r' } }
});
export var x25519_sha256_aes128gcm = scheme('x25519_sha256_aes128gcm', pure.x25519_sha256_aes128gcm, {
    open: { text: [3, 4], bytes: { 0: 'sk_r', 1: 'enc', 2: 'ct' } },
    open_context: { text: [2], bytes: { 0: 'sk_r', 1: 'enc' } },
    open_context_with_dh: { text: [3], bytes: { 1: 'enc', 2: 'pk_r' } },
    seal: { text: [1, 3, 4], bytes: { 0: 'pk_r' } },
    seal_context: { text: [2], bytes: { 0: 'pk_r' } }
});
export var x25519_sha256_chacha20poly1305 = scheme('x25519_sha256_chacha20poly1305', pure.x25519_sha256_chacha20poly1305, {
    open: { text: [3, 4], bytes: { 0: 'sk_r', 1: 'enc', 2: 'ct' } },
    open_context: { text: [2], bytes: { 0: 'sk_r', 1: 'enc' } },
    open_context_with_dh: { text: [3], bytes: { 1: 'enc', 2: 'pk_r' } },
    seal: { text: [1, 3, 4], bytes: { 0: 'pk_r' } },
    seal_context: { text: [2], bytes: { 0: 'pk_r' } }
});
export var x448_sha512_chacha20poly1305 = scheme('x448_sha512_chacha20poly1305', pure.x448_sha512_chacha20poly1305, {
    open: { text: [3, 4], bytes: { 0: 'sk_r', 1: 'enc', 2: 'ct' } },
    open_context: { text: [2], bytes: { 0: 'sk_r', 1: 'enc' } },
    open_context_with_dh: { text: [3], bytes: { 1: 'enc', 2: 'pk_r' } },
    seal: { text: [1, 3, 4], bytes: { 0: 'pk_r' } },
    seal_context: { text: [2], bytes: { 0: 'pk_r' } }
});
export var xwing_sha256_aes256gcm = scheme('xwing_sha256_aes256gcm', pure.xwing_sha256_aes256gcm, {
    open: { text: [3, 4], bytes: { 0: 'sk_r', 1: 'enc', 2: 'ct' } },
    open_context: { text: [2], bytes: { 0: 'sk_r', 1: 'enc' } },
    open_context_with_dh: { text: [3], bytes: { 1: 'enc', 2: 'pk_r' } },
    seal: { text: [1, 3, 4], bytes: { 0: 'pk_r' } },
    seal_context: { text: [2], bytes: { 0: 'pk_r' } }
});
export var xwing_sha256_chacha20poly1305 = scheme('xwing_sha256_chacha20poly1305', pure.xwing_sha256_chacha20poly1305, {
    open: { text: [3, 4], bytes: { 0: 'sk_r', 1: 'enc', 2: 'ct' } },
    open_context: { text: [2], bytes: { 0: 'sk_r', 1: 'enc' } },
    open_context_with_dh: { text: [3], bytes: { 1: 'enc', 2: 'pk_r' } },
    seal: { text: [1, 3, 4], bytes: { 0: 'pk_r' } },
    seal_context: { text: [2], bytes: { 0: 'pk_r' } }
});
