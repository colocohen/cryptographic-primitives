/**
 * HMAC (RFC 2104), over any hash in the library, in the three forms every
 * operation takes:
 *
 *     hmac(sha256, key, msg, function (err, tag) {})
 *     hmac_sync(sha256, key, msg)
 *     hmac_create(sha256, key)               { update(msg), copy(), digest() }
 *     hmac_verify(sha256, key, msg, tag, cb) and hmac_verify_sync - constant time
 *
 * The hash is any of the library's hash functions - sha256 from
 * 'cryptographic-primitives/sha2.js', its _sync form, or a pure one from
 * 'cryptographic-primitives/pure/...'. A key or message may be a string
 * (UTF-8). node:crypto runs the one-shot form for the hashes it has; the
 * incremental form, and everything in a browser, is the pure JavaScript in
 * ../hmac.js.
 */

import * as pure from '../hmac.js';
import { equal } from '../commons/ct.js';
import { define, pure_of } from '../engines/select.js';

var mac = define('hmac', {
    sync: function (hash, key, msg) { return pure.hmac(pure_of(hash), key, msg); },
    create: function (hash, key) { return pure.hmac_create(pure_of(hash), key); },
    text: [1, 2],
    create_text: [1]
});

/* Through mac.sync, so a native HMAC is used for the tag when there is one. */
var verify = define('hmac_verify', {
    sync: function (hash, key, msg, tag) { return equal(mac.sync(hash, key, msg), tag) === 1; },
    text: [1, 2],
    bytes: { 3: 'tag' }
});

export var hmac             = mac.async;
export var hmac_sync        = mac.sync;
export var hmac_create      = mac.create;
export var hmac_verify      = verify.async;
export var hmac_verify_sync = verify.sync;
