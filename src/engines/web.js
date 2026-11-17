/**
 * The WebCrypto engine
 *
 * Every use of crypto.subtle in the library is in this file. WebCrypto has
 * no synchronous calls and no incremental hash, so the entries here fill
 * only the callback form; `_sync` and `_create` run pure JavaScript in a
 * browser.
 *
 * Resolved for every platform that is not Node (package.json "imports"), so
 * each entry checks at call time that crypto.subtle exists - it does not on
 * an insecure (http:) page - and the table is empty when it does not.
 *
 * Browsers differ too, so every entry carries a kat() - fixed arguments
 * whose WebCrypto answer must be the pure function's - and select.js runs
 * it on the entry's first use (works): until it has answered, and if it
 * answers otherwise, the entry stays in JavaScript.
 */

import { MSG, K16, N12, AAD, IV16, GCM_SEALED, CBC_CT } from './kat.js';

var subtle = typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle;

function digest_op(name) {
    return {
        async: function (args, cb) {
            subtle.digest(name, args[0]).then(
                function (buf) { cb(null, new Uint8Array(buf)); },
                function (err) { cb(err); }
            );
        },
        kat: function () { return [MSG]; }
    };
}

/*
 * AES through WebCrypto. Each call imports the raw key: WebCrypto has no
 * raw-key encrypt, and a CryptoKey cached across calls would have to be
 * keyed by the key's bytes. The pure keyed context is the one that keeps a
 * prepared key.
 */
function aes_key_ok(key) { return key && (key.length === 16 || key.length === 24 || key.length === 32); }

function aes_op(name, run, accepts, kat) {
    return {
        kat: kat,
        async: function (args, cb) {
            subtle.importKey('raw', args[0], { name: name }, false, ['encrypt', 'decrypt']).then(function (k) {
                return run(k, args);
            }).then(
                function (out) { cb(null, out); },
                function (err) { cb(err); }
            );
        },
        accepts: accepts
    };
}

function u8(buf) { return new Uint8Array(buf); }

function gcm_ok(args) { return aes_key_ok(args[0]) && args[1] && args[1].length > 0; }

var aes_gcm_encrypt = aes_op('AES-GCM', function (k, a) {
    return subtle.encrypt({ name: 'AES-GCM', iv: a[1], additionalData: a[3] || new Uint8Array(0), tagLength: 128 }, k, a[2]).then(u8);
}, gcm_ok, function () { return [K16, N12, MSG, AAD]; });

/* a tag that does not verify rejects; the pure form returns null, and so does this */
var aes_gcm_decrypt = aes_op('AES-GCM', function (k, a) {
    if (a[2].length < 16) { return null; }
    return subtle.decrypt({ name: 'AES-GCM', iv: a[1], additionalData: a[3] || new Uint8Array(0), tagLength: 128 }, k, a[2])
        .then(u8, function () { return null; });
}, gcm_ok, function () { return [K16, N12, GCM_SEALED, AAD]; });

/* the whole 16-byte block is the counter, as aes_ctr increments it */
var aes_ctr = aes_op('AES-CTR', function (k, a) {
    return subtle.encrypt({ name: 'AES-CTR', counter: a[1], length: 128 }, k, a[2]).then(u8);
}, function (args) { return aes_key_ok(args[0]) && args[1] && args[1].length === 16; }, function () { return [K16, IV16, MSG]; });

/* WebCrypto's CBC always pads (PKCS#7): only the padded form runs here */
function cbc_ok(args) { return aes_key_ok(args[0]) && args[1] && args[1].length === 16 && !args[3]; }

var aes_cbc_encrypt = aes_op('AES-CBC', function (k, a) {
    return subtle.encrypt({ name: 'AES-CBC', iv: a[1] }, k, a[2]).then(u8);
}, cbc_ok, function () { return [K16, IV16, MSG]; });

var aes_cbc_decrypt = aes_op('AES-CBC', function (k, a) {
    /* bad padding rejects; the pure form returns null, and so does this */
    return subtle.decrypt({ name: 'AES-CBC', iv: a[1] }, k, a[2]).then(u8, function () { return null; });
}, cbc_ok, function () { return [K16, IV16, CBC_CT]; });

/*
 * ==================== WHEN WEBCRYPTO IS WORTH IT ====================
 *
 * Every WebCrypto call answers through a Promise, after 8 to 25 us whatever
 * its size; the pure JavaScript hashes or encrypts a short input sooner.
 * So each operation runs here only from a size on (`from`, as in
 * engines/select.js), and shorter inputs stay in JavaScript.
 *
 * Measured in headless Chrome 157 on x86-64 (the time from the call to its
 * callback, the fastest of 9 batches): the smallest size from which
 * WebCrypto was faster, and stayed faster, in two runs. A size need not be exact - around
 * it the two are close to even. Re-measure for another browser with
 * bench/routing.html.
 */
var FROM = {
    sha1: [0, 4096], sha256: [0, 4096], sha384: [0, 256], sha512: [0, 1024],
    aes_gcm_encrypt: [2, 1024], aes_gcm_decrypt: [2, 1024],
    aes_ctr: [2, 4096], aes_cbc_encrypt: [2, 1024], aes_cbc_decrypt: [2, 1024]
};

export var ops = subtle ? {
    aes_gcm_encrypt: aes_gcm_encrypt,
    aes_gcm_decrypt: aes_gcm_decrypt,
    aes_ctr: aes_ctr,
    aes_cbc_encrypt: aes_cbc_encrypt,
    aes_cbc_decrypt: aes_cbc_decrypt,
    sha1: digest_op('SHA-1'),
    sha256: digest_op('SHA-256'),
    sha384: digest_op('SHA-384'),
    sha512: digest_op('SHA-512')
} : {};

for (var name in FROM) {
    if (ops[name]) { ops[name].from = { arg: FROM[name][0], bytes: FROM[name][1] }; }
}
