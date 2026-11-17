/**
 * Non-cryptographic checksums and fast hashes (CRC, Adler, FNV, xxHash,
 * MurmurHash3, SipHash, HighwayHash), as a callback and a _sync form:
 *
 *     crc32(msg, cb)    crc32_sync(msg)
 *
 * Arguments are those of ../checksum.js. A message may be a string (UTF-8).
 * None of these is for integrity against an attacker, except SipHash and
 * HighwayHash, which are keyed and meant for hash tables.
 */

import * as pure from '../checksum.js';
import { define } from '../engines/select.js';

var xxhash32_ops      = define('xxhash32', { sync: pure.xxhash32, text: [0], bytes: { 1: 'seed' } });
var xxhash64_ops      = define('xxhash64', { sync: pure.xxhash64, text: [0], bytes: { 1: 'seed' } });
var crc32_ops         = define('crc32', { sync: pure.crc32, text: [0], bytes: { 1: 'seed' } });
var crc32c_ops        = define('crc32c', { sync: pure.crc32c, text: [0], bytes: { 1: 'seed' } });
var crc64_ops         = define('crc64', { sync: pure.crc64, text: [0] });
var crc64_iso_ops     = define('crc64_iso', { sync: pure.crc64_iso, text: [0] });
var fnv1a32_ops       = define('fnv1a32', { sync: pure.fnv1a32, text: [0], bytes: { 1: 'seed' } });
var siphash24_ops     = define('siphash24', { sync: pure.siphash24, text: [0], bytes: { 1: 'key' } });
var murmur3_32_ops    = define('murmur3_32', { sync: pure.murmur3_32, text: [0], bytes: { 1: 'seed' } });
var adler32_ops       = define('adler32', { sync: pure.adler32, text: [0] });
var highwayhash64_ops = define('highwayhash64', { sync: pure.highwayhash64, text: [0], bytes: { 1: 'key' } });

export var xxhash32             = xxhash32_ops.async;
export var xxhash32_sync        = xxhash32_ops.sync;
export var xxhash64             = xxhash64_ops.async;
export var xxhash64_sync        = xxhash64_ops.sync;
export var crc32                = crc32_ops.async;
export var crc32_sync           = crc32_ops.sync;
export var crc32c               = crc32c_ops.async;
export var crc32c_sync          = crc32c_ops.sync;
export var crc64                = crc64_ops.async;
export var crc64_sync           = crc64_ops.sync;
export var crc64_iso            = crc64_iso_ops.async;
export var crc64_iso_sync       = crc64_iso_ops.sync;
export var fnv1a32              = fnv1a32_ops.async;
export var fnv1a32_sync         = fnv1a32_ops.sync;
export var siphash24            = siphash24_ops.async;
export var siphash24_sync       = siphash24_ops.sync;
export var murmur3_32           = murmur3_32_ops.async;
export var murmur3_32_sync      = murmur3_32_ops.sync;
export var adler32              = adler32_ops.async;
export var adler32_sync         = adler32_ops.sync;
export var highwayhash64        = highwayhash64_ops.async;
export var highwayhash64_sync   = highwayhash64_ops.sync;
