// cryptographic-primitives - hashes, ciphers, signatures, key exchange and
// the rest, in plain JavaScript, running natively where that is faster.
//
// Every operation comes in the same three forms:
//
//   sha256(data, function (err, digest) {})   the plain name: a callback, the
//                                             work split into slices so the
//                                             event loop keeps moving
//   sha256_sync(data)                         the result, now
//   sha256_create()                           a context, fed in pieces
//
// ⚠ IMPORTING THIS PULLS IN EVERY MODULE. It is here for exploration and for
// environments without a bundler. Import the one module you need instead:
//
//   import { sha256_sync } from 'cryptographic-primitives/sha2.js';
//
// Each module here is the api/ form - it picks node:crypto or WebCrypto when
// they are faster for the input's size, and pure JavaScript otherwise (see
// src/engines/select.js). The pure JavaScript alone, with no engine and no
// callbacks, is under 'cryptographic-primitives/pure/<module>.js'.

export * from './src/api/index.js';
