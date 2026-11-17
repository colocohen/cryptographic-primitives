// Where randomness comes from, and which engine runs a call.
//
// A randomness parameter left out, or null, is fresh randomness from the
// platform (crypto.getRandomValues - never Math.random), and only then may
// the call run natively. A caller's own rng or bytes run in pure JavaScript,
// and the same bytes give the same result.
import { engine_of, set_engine } from 'cryptographic-primitives/engines.js';
import { rsa } from 'cryptographic-primitives';
import { sha256_sync } from 'cryptographic-primitives/sha2.js';
import { schnorr_sign_sync } from 'cryptographic-primitives/secp256k1.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');

// rsa.keygen(bits, rng, e): a parameter that is not last takes null.
console.log(engine_of('rsa.keygen', 'sync', [2048, null, 65537n]));  // -> native
const key = rsa.keygen_sync(2048, null, 65537n);
console.log(key.bits, key.e);                                       // -> 2048 65537n

// The same call with the caller's rng is pure JavaScript, and exact.
const my_rng = (n) => new Uint8Array(n);
console.log(engine_of('rsa.keygen', 'sync', [2048, my_rng, 65537n]));  // -> js

// BIP-340 Schnorr: aux omitted is fresh; 32 zero bytes is deterministic.
// BIP-340 test vector 0:
const secret = new Uint8Array(32); secret[31] = 3;
const sig = schnorr_sign_sync(new Uint8Array(32), secret, new Uint8Array(32));
console.log(hex(sig).slice(0, 32));                                 // -> e907831f80848d1069a5371b40241036

// By size: below its threshold an input is faster in JavaScript.
console.log(engine_of('sha256', 'sync', [new Uint8Array(64)]));     // -> js
console.log(engine_of('sha256', 'sync', [new Uint8Array(4096)]));   // -> native

// 'js': pure JavaScript everywhere, with the same results.
const native_digest = hex(sha256_sync(new Uint8Array(4096)));
set_engine('js');
console.log(engine_of('sha256', 'sync', [new Uint8Array(4096)]));   // -> js
console.log(hex(sha256_sync(new Uint8Array(4096))) === native_digest);  // -> true
set_engine('auto');
