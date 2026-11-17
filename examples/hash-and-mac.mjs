// Hash and MAC a message: the callback, _sync and _create forms.
// A message, a key of any length or a label may be a string, taken as its
// UTF-8 bytes.
import { sha256, sha256_sync, sha256_create } from 'cryptographic-primitives/sha2.js';
import { hmac_sync, hmac_verify_sync, hmac_create } from 'cryptographic-primitives/hmac.js';
import { blake3_sync } from 'cryptographic-primitives/blake3.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');

// _sync: the result, directly.
console.log(hex(sha256_sync('abc')));  // -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

// _create: a context fed in pieces - the same digest.
const h = sha256_create();
h.update('a').update('bc');
console.log(hex(h.digest()));          // -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

// The plain name: an err-first callback, called on a later turn.
sha256('abc', function (err, digest) {
  console.log('callback', hex(digest).slice(0, 16));  // -> callback ba7816bf8f01cfea
});

// HMAC over any hash in the library - the hash is passed in.
const tag = hmac_sync(sha256, 'key', 'The quick brown fox jumps over the lazy dog');
console.log(hex(tag));                 // -> f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
console.log(hmac_verify_sync(sha256, 'key', 'The quick brown fox jumps over the lazy dog', tag));  // -> true

// One key, many messages: the key prepared once, and copy() per message.
const keyed = hmac_create(sha256, 'key');
const tag2 = keyed.copy().update('The quick brown fox ').update('jumps over the lazy dog').digest();
console.log(hex(tag2) === hex(tag));   // -> true

console.log(hex(blake3_sync('')).slice(0, 16));  // -> af1349b9f5f9a1a6
