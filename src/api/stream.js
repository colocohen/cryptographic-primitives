/**
 * stream, a long message sealed piece by piece (see ../stream.js):
 *
 *     var enc = chacha20poly1305_stream_create(key, rng);
 *     enc.header                                  send it first
 *     enc.push_sync(piece, last, aad)             the sealed piece
 *     enc.push(piece, last, aad, function (err, sealed) {})
 *
 *     var dec = chacha20poly1305_stream_open_create(key, header);
 *     dec.push_sync(sealed, last, aad)            the piece, or null
 *     dec.push(sealed, last, aad, function (err, piece) {})
 *     dec.finished()                              did the last piece arrive
 *
 * and the same for aes_gcm_, and for libsodium's format,
 * xchacha20poly1305_secretstream_ (which also has rekey()). A piece and the
 * associated data may be strings (UTF-8); the key, the header and a sealed
 * piece are bytes only.
 *
 * Each piece goes through the keyed AEAD context of api/aes.js or
 * api/chacha.js, so it runs natively where that is faster for its size
 * (engines/select.js).
 */

import * as pure from '../stream.js';
import { aes_gcm_create } from './aes.js';
import { chacha20poly1305_create } from './chacha.js';
import { scheme } from '../engines/select.js';

/* an api/ context, in the shape ../stream.js drives: synchronous methods */
function maker(create) {
    return function (k) {
        var ctx = create(k);
        return { encrypt: ctx.encrypt_sync, decrypt: ctx.decrypt_sync, wipe: ctx.wipe };
    };
}

function bytes_only(who, name, x) {
    if (typeof x === 'string') {
        throw new TypeError(who + ': ' + name + ' must be a Uint8Array, not a string' +
            ' (strings are taken as UTF-8 only for text such as a message or a password)');
    }
}

/* push in both forms, plus header and finished(), around a pure side */
function sided(op, inner, opening) {
    var push = scheme(op, { push: inner.push }, {
        push: opening ? { text: [2], bytes: { 0: 'sealed' } } : { text: [0, 2] }
    });
    var out = {
        push: push.push,
        push_sync: push.push_sync,
        finished: function () { return inner.finished(); }
    };
    if (!opening) { out.header = inner.header; }
    if (inner.rekey) { out.rekey = function () { inner.rekey(); }; }
    return out;
}

function both(name, create) {
    var make = maker(create);
    return {
        seal: function (key, rng) {
            bytes_only(name + '_stream_create', 'key', key);
            return sided(name + '_stream', pure.stream_seal_with(make, name, key, rng), false);
        },
        open: function (key, header) {
            bytes_only(name + '_stream_open_create', 'key', key);
            bytes_only(name + '_stream_open_create', 'header', header);
            return sided(name + '_stream_open', pure.stream_open_with(make, name, key, header), true);
        }
    };
}

var aes_gcm_sides = both('aes_gcm', aes_gcm_create);
var chacha_sides = both('chacha20poly1305', chacha20poly1305_create);

export var aes_gcm_stream_create = aes_gcm_sides.seal;
export var aes_gcm_stream_open_create = aes_gcm_sides.open;
export var chacha20poly1305_stream_create = chacha_sides.seal;
export var chacha20poly1305_stream_open_create = chacha_sides.open;

/*
 * libsodium's format (crypto_secretstream_xchacha20poly1305): the same
 * push / push_sync / finished, a 24-byte header, and rekey(). Its cipher is
 * fixed and runs in pure JavaScript - no platform has XChaCha20 natively.
 */
export function xchacha20poly1305_secretstream_create(key, rng) {
    bytes_only('xchacha20poly1305_secretstream_create', 'key', key);
    return sided('xchacha20poly1305_secretstream', pure.xchacha20poly1305_secretstream_create(key, rng), false);
}
export function xchacha20poly1305_secretstream_open_create(key, header) {
    bytes_only('xchacha20poly1305_secretstream_open_create', 'key', key);
    bytes_only('xchacha20poly1305_secretstream_open_create', 'header', header);
    return sided('xchacha20poly1305_secretstream_open', pure.xchacha20poly1305_secretstream_open_create(key, header), true);
}
