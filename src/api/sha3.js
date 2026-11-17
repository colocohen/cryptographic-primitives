/**
 * SHA-3 and the Keccak family, in the three forms every operation takes:
 *
 *     sha3_256(msg, function (err, digest) {})
 *     sha3_256_sync(msg)
 *     sha3_256_create()                 { update(msg), copy(), digest() }
 *
 *     shake128(msg, out_len, cb)        and _sync
 *     shake128_create()                 { update(msg), copy(), digest(n), read(n) }
 *
 * The same pattern holds for Keccak-224..512, cSHAKE, TurboSHAKE and KMAC;
 * TupleHash, ParallelHash and KangarooTwelve come as a callback and a _sync
 * form. Arguments are the one-shot functions' in ../sha3.js. A message, key
 * or customisation string may be a string (UTF-8).
 *
 * node:crypto runs SHA3-224..512 in every form and SHAKE's one-shot call;
 * WebCrypto has no SHA-3; everything else is the pure JavaScript.
 */

import * as pure from '../sha3.js';
import { define } from '../engines/select.js';

var sha3_224_ops = define('sha3_224', { sync: pure.sha3_224, create: pure.sha3_224_create, text: [0] });
var sha3_256_ops = define('sha3_256', { sync: pure.sha3_256, create: pure.sha3_256_create, text: [0] });
var sha3_384_ops = define('sha3_384', { sync: pure.sha3_384, create: pure.sha3_384_create, text: [0] });
var sha3_512_ops = define('sha3_512', { sync: pure.sha3_512, create: pure.sha3_512_create, text: [0] });
var keccak224_ops = define('keccak224', { sync: pure.keccak224, create: pure.keccak224_create, text: [0] });
var keccak256_ops = define('keccak256', { sync: pure.keccak256, create: pure.keccak256_create, text: [0] });
var keccak384_ops = define('keccak384', { sync: pure.keccak384, create: pure.keccak384_create, text: [0] });
var keccak512_ops = define('keccak512', { sync: pure.keccak512, create: pure.keccak512_create, text: [0] });
var shake128_ops = define('shake128', { sync: pure.shake128, create: pure.shake128_create, text: [0] });
var shake256_ops = define('shake256', { sync: pure.shake256, create: pure.shake256_create, text: [0] });
var cshake128_ops = define('cshake128', { sync: pure.cshake128, create: pure.cshake128_create, text: [0, 2, 3], create_text: [0, 1] });
var cshake256_ops = define('cshake256', { sync: pure.cshake256, create: pure.cshake256_create, text: [0, 2, 3], create_text: [0, 1] });
var turboshake128_ops = define('turboshake128', { sync: pure.turboshake128, create: pure.turboshake128_create, text: [0, 2], create_text: [0] });
var turboshake256_ops = define('turboshake256', { sync: pure.turboshake256, create: pure.turboshake256_create, text: [0, 2], create_text: [0] });
var kmac128_ops = define('kmac128', { sync: pure.kmac128, create: pure.kmac128_create, text: [0, 1, 3], create_text: [0, 2] });
var kmac256_ops = define('kmac256', { sync: pure.kmac256, create: pure.kmac256_create, text: [0, 1, 3], create_text: [0, 2] });
var kmac128xof_ops = define('kmac128xof', { sync: pure.kmac128xof, create: pure.kmac128xof_create, text: [0, 1, 3], create_text: [0, 1] });
var kmac256xof_ops = define('kmac256xof', { sync: pure.kmac256xof, create: pure.kmac256xof_create, text: [0, 1, 3], create_text: [0, 1] });
var tuplehash128_ops = define('tuplehash128', { sync: pure.tuplehash128, text: [0, 2] });
var tuplehash256_ops = define('tuplehash256', { sync: pure.tuplehash256, text: [0, 2] });
var tuplehash128xof_ops = define('tuplehash128xof', { sync: pure.tuplehash128xof, text: [0, 2] });
var tuplehash256xof_ops = define('tuplehash256xof', { sync: pure.tuplehash256xof, text: [0, 2] });
var parallelhash128_ops = define('parallelhash128', { sync: pure.parallelhash128, text: [0, 3] });
var parallelhash256_ops = define('parallelhash256', { sync: pure.parallelhash256, text: [0, 3] });
var parallelhash128xof_ops = define('parallelhash128xof', { sync: pure.parallelhash128xof, text: [0, 3] });
var parallelhash256xof_ops = define('parallelhash256xof', { sync: pure.parallelhash256xof, text: [0, 3] });
var kt128_ops = define('kt128', { sync: pure.kt128, text: [0, 2] });
var kt256_ops = define('kt256', { sync: pure.kt256, text: [0, 2] });

export var sha3_224 = sha3_224_ops.async;
export var sha3_224_sync = sha3_224_ops.sync;
export var sha3_224_create = sha3_224_ops.create;
export var sha3_256 = sha3_256_ops.async;
export var sha3_256_sync = sha3_256_ops.sync;
export var sha3_256_create = sha3_256_ops.create;
export var sha3_384 = sha3_384_ops.async;
export var sha3_384_sync = sha3_384_ops.sync;
export var sha3_384_create = sha3_384_ops.create;
export var sha3_512 = sha3_512_ops.async;
export var sha3_512_sync = sha3_512_ops.sync;
export var sha3_512_create = sha3_512_ops.create;
export var keccak224 = keccak224_ops.async;
export var keccak224_sync = keccak224_ops.sync;
export var keccak224_create = keccak224_ops.create;
export var keccak256 = keccak256_ops.async;
export var keccak256_sync = keccak256_ops.sync;
export var keccak256_create = keccak256_ops.create;
export var keccak384 = keccak384_ops.async;
export var keccak384_sync = keccak384_ops.sync;
export var keccak384_create = keccak384_ops.create;
export var keccak512 = keccak512_ops.async;
export var keccak512_sync = keccak512_ops.sync;
export var keccak512_create = keccak512_ops.create;
export var shake128 = shake128_ops.async;
export var shake128_sync = shake128_ops.sync;
export var shake128_create = shake128_ops.create;
export var shake256 = shake256_ops.async;
export var shake256_sync = shake256_ops.sync;
export var shake256_create = shake256_ops.create;
export var cshake128 = cshake128_ops.async;
export var cshake128_sync = cshake128_ops.sync;
export var cshake128_create = cshake128_ops.create;
export var cshake256 = cshake256_ops.async;
export var cshake256_sync = cshake256_ops.sync;
export var cshake256_create = cshake256_ops.create;
export var turboshake128 = turboshake128_ops.async;
export var turboshake128_sync = turboshake128_ops.sync;
export var turboshake128_create = turboshake128_ops.create;
export var turboshake256 = turboshake256_ops.async;
export var turboshake256_sync = turboshake256_ops.sync;
export var turboshake256_create = turboshake256_ops.create;
export var kmac128 = kmac128_ops.async;
export var kmac128_sync = kmac128_ops.sync;
export var kmac128_create = kmac128_ops.create;
export var kmac256 = kmac256_ops.async;
export var kmac256_sync = kmac256_ops.sync;
export var kmac256_create = kmac256_ops.create;
export var kmac128xof = kmac128xof_ops.async;
export var kmac128xof_sync = kmac128xof_ops.sync;
export var kmac128xof_create = kmac128xof_ops.create;
export var kmac256xof = kmac256xof_ops.async;
export var kmac256xof_sync = kmac256xof_ops.sync;
export var kmac256xof_create = kmac256xof_ops.create;
export var tuplehash128 = tuplehash128_ops.async;
export var tuplehash128_sync = tuplehash128_ops.sync;
export var tuplehash256 = tuplehash256_ops.async;
export var tuplehash256_sync = tuplehash256_ops.sync;
export var tuplehash128xof = tuplehash128xof_ops.async;
export var tuplehash128xof_sync = tuplehash128xof_ops.sync;
export var tuplehash256xof = tuplehash256xof_ops.async;
export var tuplehash256xof_sync = tuplehash256xof_ops.sync;
export var parallelhash128 = parallelhash128_ops.async;
export var parallelhash128_sync = parallelhash128_ops.sync;
export var parallelhash256 = parallelhash256_ops.async;
export var parallelhash256_sync = parallelhash256_ops.sync;
export var parallelhash128xof = parallelhash128xof_ops.async;
export var parallelhash128xof_sync = parallelhash128xof_ops.sync;
export var parallelhash256xof = parallelhash256xof_ops.async;
export var parallelhash256xof_sync = parallelhash256xof_ops.sync;
export var kt128 = kt128_ops.async;
export var kt128_sync = kt128_ops.sync;
export var kt256 = kt256_ops.async;
export var kt256_sync = kt256_ops.sync;
