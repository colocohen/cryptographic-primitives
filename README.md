# cryptographic-primitives

**Cryptographic primitives for JavaScript, in one call shape.**
Hashes, MACs, block and stream ciphers, AEADs, KDFs and password hashes,
elliptic curves, RSA, post-quantum signatures and KEMs, HPKE, PAKEs, OPRFs,
threshold signing, zero-knowledge proofs and homomorphic encryption.

[![npm](https://img.shields.io/npm/v/cryptographic-primitives.svg)](https://www.npmjs.com/package/cryptographic-primitives)
![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen.svg)
![node: >=20](https://img.shields.io/badge/node-%3E%3D20-blue.svg)

```
node:crypto, WebCrypto      what the platform ships, on the platform that
                            ships it, each with its own calling convention
cryptographic-primitives    the same call on every platform - the platform's
                            code where it measured faster, pure JavaScript
                            everywhere else, and 148 modules in all
```

**Each call runs where it measured faster for its input.** On Node, ECDSA P-256
signing of a message goes to OpenSSL (0.40 ms against 0.87 ms in JavaScript); P-384
signing stays in JavaScript, which is faster there (2.18 ms against 3.53).
SHA-256 of a 64-byte message stays in JavaScript, and of a 4 KiB one goes
native. Each engine's result is one the other accepts - a ciphertext opens
and a signature verifies on both - and `set_engine('js')` keeps everything
in JavaScript.

- **Zero dependencies, plain ESM.** 148 modules, about 73,000 lines of
  algorithm code and 10,000 of API and engines. No native addons, no build
  step.
- **Checked against something outside itself.** RFC and FIPS vectors, the
  NIST submitters' KATs, OpenSSL, libsodium, pyca/cryptography,
  libsecp256k1-zkp, chiavdf - the [module reference](#module-reference)
  names each module's.
- **One shape for every operation.** `sha256(msg, cb)` with an err-first
  callback, `sha256_sync(msg)` for the result now, `sha256_create()` for a
  context fed in pieces. No Promises.
- **The event loop keeps running.** PBKDF2, scrypt, Argon2, bcrypt and RSA
  and Paillier key generation run their callback form in 8 ms slices when
  they run in JavaScript. No Workers.
- **Randomness from the platform, or exactly yours.** A randomness argument
  left out, or `null`, is fresh bytes from `crypto.getRandomValues`, which
  throws rather than fall back to `Math.random`. The same bytes passed in
  give the same output.

---

## Contents

- [Why this exists](#why-this-exists)
- [Install](#install)
- [Quick start](#quick-start)
- [If you just want it to work](#if-you-just-want-it-to-work)
- [Migrating from another library](#migrating-from-another-library)
- [Examples](#examples)
- [What it covers](#what-it-covers)
- [What to reach for](#what-to-reach-for)
- [Module reference](#module-reference)
- [Building blocks](#building-blocks)
- [Naming conventions](#naming-conventions)
- [Design](#design)
- [How it is built](#how-it-is-built)
- [Performance](#performance)
- [Errors](#errors)
- [Testing](#testing)
- [Caveats](#caveats)
- [Contributing](#contributing)
- [License](#license)

---

## Why this exists

JavaScript cryptography libraries tend to make one of two trades. They wrap
WebAssembly, which is fast but opaque and does not run everywhere, or they
cover the common twenty algorithms and stop.

This one covers what a modern system reaches for - including what OpenSSL
does not have: BLAKE3, AEGIS, Ascon, yescrypt, BLS12-381, FROST, MuSig2,
BBS, adaptor and blind signatures, key blinding, ristretto255, Pedersen
commitments, Bulletproofs, ring signatures, OPRFs and PAKEs, Paillier, KZG,
Poseidon, sparse Merkle trees, HOTP and TOTP, Falcon, the NIST round-3
signatures, and the post-quantum KEMs beyond ML-KEM. It is readable
JavaScript, the same code in Node and in a browser.

It does not parse certificates: no X.509, no PKCS#8, no general ASN.1.
Parsing attacker-controlled structure is a different problem from computing
on bytes, and belongs in a separate library. The DER this library reads -
RSA keys, EC private keys, ECDSA signatures - goes through one strict
parser.

---

## Install

```bash
npm install cryptographic-primitives
```

ES modules only, Node.js 20 or later. Import one module by its subpath:

```javascript
import { sha256_sync } from 'cryptographic-primitives/sha2.js';
import { ml_kem768 } from 'cryptographic-primitives/ml_kem.js';
```

The package root exports every module as a namespace -
`import { sha2, ml_kem } from 'cryptographic-primitives'` - and so loads
all of them; it is there for exploring and for environments without a
bundler.

The pure JavaScript alone, with no engine and no callbacks - plain
synchronous functions - is under `pure/`:

```javascript
import { sha256 } from 'cryptographic-primitives/pure/sha2.js';
```

In a browser, package.json's `imports` field swaps node:crypto for
WebCrypto, so a bundle never sees `node:crypto`. WebCrypto has no
synchronous calls, so there only the callback forms of SHA-1/256/384/512
and AES-GCM, AES-CTR and AES-CBC go native; everything else runs in
JavaScript. WebCrypto's `crypto.subtle` exists only in a secure context
(https, or localhost); elsewhere every call runs in JavaScript. The
examples use Node's `Buffer` only to read and print hex. The test suite runs on
Node.

---

## Quick start

Encrypt and decrypt a message with a key:

```javascript
import { chacha20poly1305_encrypt_sync, chacha20poly1305_decrypt_sync }
  from 'cryptographic-primitives/chacha.js';

const key = crypto.getRandomValues(new Uint8Array(32));
const nonce = crypto.getRandomValues(new Uint8Array(12));  // never twice with one key

const sealed = chacha20poly1305_encrypt_sync(key, nonce, 'hello', 'v1');
const plain = chacha20poly1305_decrypt_sync(key, nonce, sealed, 'v1');
// plain: the bytes of 'hello' - or null if sealed, nonce or 'v1' changed
```

The message and the associated data may be strings; the key and the nonce
must be bytes. The same operation with a callback is
`chacha20poly1305_encrypt(key, nonce, 'hello', 'v1', function (err, sealed) {})`.

---

## If you just want it to work

`easy.js` does the two things people most often reach for a cryptography
library to do - store a password, and encrypt data under one - with every
parameter already chosen.

[`examples/easy.mjs`](examples/easy.mjs)

```javascript
// Password storage and password-based encryption, with every parameter
// chosen: Argon2id at 64 MiB and t = 3, ChaCha20-Poly1305, a fresh salt and
// nonce on every call, and a version byte in front of every sealed blob.
import {
  hash_password_sync, verify_password_sync, needs_rehash_sync,
  seal_with_password_sync, open_with_password_sync
} from 'cryptographic-primitives/easy.js';

// The string to store: the parameters and the salt are in it.
const stored = hash_password_sync('correct horse battery staple');
console.log(stored.slice(0, 30));                                   // -> $argon2id$v=19$m=65536,t=3,p=1
console.log(verify_password_sync('correct horse battery staple', stored));  // -> true
console.log(verify_password_sync('Tr0ub4dor&3', stored));           // -> false

// A hash made below the current defaults is due for rehashing at the next
// successful login.
console.log(needs_rehash_sync(stored));                             // -> false
console.log(needs_rehash_sync(hash_password_sync('pw', { m: 19456, t: 2 })));  // -> true

// Encrypt under a password; the wrong password opens as null.
const blob = seal_with_password_sync('my password', 'the file contents');
console.log(new TextDecoder().decode(open_with_password_sync('my password', blob)));  // -> the file contents
console.log(open_with_password_sync('wrong password', blob));      // -> null
```

Argon2id at 64 MiB and t = 3, a fresh 16-byte salt and 12-byte nonce on
every call, ChaCha20-Poly1305 because it has no lookup tables to leak
through the cache. The stored string carries its parameters, so a hash
made today still verifies after the defaults rise; the sealed blob starts
with a version byte, so the choices can change without breaking what is
already sealed. `src/easy.js` states each choice and what it costs.

Each function has the callback form too - `hash_password(pw, cb)`,
`verify_password(pw, stored, cb)` - which runs on node:crypto's thread
pool where Node has Argon2, and in 8 ms slices where it does not.
`hash_password(pw, { m, t, p }, cb)` sets the cost; the
[password example](#password-hashing-without-blocking) uses OWASP's minimum.

---

## Migrating from another library

Where the bytes on the wire already match, a shim under `compat/` is a
drop-in: change the import, and the data the other library wrote keeps
working.

```javascript
import nacl from 'cryptographic-primitives/compat/nacl.js';             // tweetnacl
import sodium from 'cryptographic-primitives/compat/sodium.js';         // libsodium-wrappers
import bcrypt from 'cryptographic-primitives/compat/bcrypt.js';         // bcryptjs
import eccrypto from 'cryptographic-primitives/compat/eccrypto.js';     // eccrypto
import util from 'cryptographic-primitives/compat/nacl-util.js';        // tweetnacl-util
import { scrypt } from 'cryptographic-primitives/compat/scrypt-js.js';  // scrypt-js
```

A shim keeps the other library's names and calling convention -
`nacl.secretbox(msg, nonce, key)`, bcryptjs's `hash(password, salt, cb)` -
not this library's three forms. Each was checked byte for byte against the
real library in both directions: their ciphertexts open here, and ours open
there.

**CryptoJS is the exception, and it is read-only.**

[`examples/compat.mjs`](examples/compat.mjs)

```javascript
// Moving off another library. A shim keeps the other library's API and its
// bytes: change the import, and data it wrote opens here.
import nacl from 'cryptographic-primitives/compat/nacl.js';            // tweetnacl
import { open_cryptojs } from 'cryptographic-primitives/compat/cryptojs.js';
import { seal_with_password_sync, open_with_password_sync } from 'cryptographic-primitives/easy.js';

// tweetnacl's secretbox: XSalsa20-Poly1305, the tag first, as NaCl lays it out.
const key = nacl.randomBytes(32);
const nonce = nacl.randomBytes(24);
const box = nacl.secretbox(new TextEncoder().encode('hello'), nonce, key);
console.log(box.length);                                             // -> 21
console.log(new TextDecoder().decode(nacl.secretbox.open(box, nonce, key)));  // -> hello

// CryptoJS.AES.encrypt('the old secret', 'hunter2').toString(), with its salt
// fixed - read once, then sealed again with easy.js.
const old = open_cryptojs('hunter2', 'U2FsdGVkX18BAgMEBQYHCN2cEyAQnAkJsmUXCLHyvME=');
console.log(new TextDecoder().decode(old));                         // -> the old secret
const fresh = seal_with_password_sync('hunter2', old);
console.log(new TextDecoder().decode(open_with_password_sync('hunter2', fresh)));  // -> the old secret
```

There is no `seal_cryptojs`. CryptoJS derives its key with one iteration
of MD5 and encrypts with CBC and no authentication; a writer would ship
that as a supported option. Old data can be read, and no more of it
written. A non-null result is not proof the password was right: without
authentication, a wrong password passes the padding check about one time
in 256.

---

## Examples

Each example below is a file in [`examples/`](examples/) - complete,
runnable with `node examples/<name>.mjs`, and run by the test suite, which
also checks that every `console.log` prints what its `// ->` comment says.
Four more are in the sections they belong to - `easy.mjs`, `compat.mjs`,
`vdf.mjs` and `stateful-signatures.mjs` - and are run the same way.

### Hashes and MACs, in all three forms

[`examples/hash-and-mac.mjs`](examples/hash-and-mac.mjs)

```javascript
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
```

### AES-GCM and ChaCha20-Poly1305

[`examples/aead.mjs`](examples/aead.mjs)

```javascript
// Authenticated encryption: AES-GCM one-shot, and a ChaCha20-Poly1305
// context keyed once for many messages. Plaintext and associated data may
// be strings; a key, a nonce or a sealed message must be bytes.
import { aes_gcm_encrypt_sync, aes_gcm_decrypt_sync } from 'cryptographic-primitives/aes.js';
import { chacha20poly1305_create } from 'cryptographic-primitives/chacha.js';

const key = crypto.getRandomValues(new Uint8Array(32));
const nonce = crypto.getRandomValues(new Uint8Array(12));

// The sealed message is the ciphertext with the 16-byte tag after it.
const sealed = aes_gcm_encrypt_sync(key, nonce, 'attack at dawn', 'header v1');
console.log(sealed.length);                                   // -> 30

const opened = aes_gcm_decrypt_sync(key, nonce, sealed, 'header v1');
console.log(new TextDecoder().decode(opened));                // -> attack at dawn

// A failed authentication is null, never an exception.
console.log(aes_gcm_decrypt_sync(key, nonce, sealed, 'header v2'));  // -> null

// A key written as text is refused before any work.
try {
  aes_gcm_encrypt_sync('00112233445566778899aabbccddeeff', nonce, 'x');
} catch (e) {
  console.log(e.name);                                        // -> TypeError
  console.log(e.message.startsWith('aes_gcm_encrypt_sync: key must be a Uint8Array'));  // -> true
}

// A keyed context: the key prepared once, a fresh nonce per message.
const ctx = chacha20poly1305_create(key);
const n1 = crypto.getRandomValues(new Uint8Array(12));
const box = ctx.encrypt_sync(n1, 'first message', '');
console.log(new TextDecoder().decode(ctx.decrypt_sync(n1, box, '')));  // -> first message
const n2 = crypto.getRandomValues(new Uint8Array(12));
ctx.encrypt(n2, 'callback form', '', function (err, sealed2) {
  console.log(sealed2.length);                                // -> 29
  ctx.wipe();                                                 // zeroes the key it holds
});
```

`encrypt_into_sync(out, offset, nonce, plaintext, aad)` seals straight into
an array of yours - a record's own buffer, in place - and returns the
length written. For speed, seal with `encrypt_into` and open with
`decrypt`: node:crypto cannot write into a given array, so `decrypt` hands
back its output with no copy, and `decrypt_into` would add one.

### Streaming encryption

[`examples/stream.mjs`](examples/stream.mjs)

```javascript
// Seal a long message - a file, a socket - piece by piece. Each piece is
// authenticated on its own: one altered, reordered or out of place opens as
// null. A stream cut short raises nothing, so the receiver checks finished()
// once the input ends, and refuses the message when it is false.
import {
  chacha20poly1305_stream_create, chacha20poly1305_stream_open_create,
  xchacha20poly1305_secretstream_create, xchacha20poly1305_secretstream_open_create
} from 'cryptographic-primitives/stream.js';

const key = crypto.getRandomValues(new Uint8Array(32));
const text = (bytes) => new TextDecoder().decode(bytes);

// Sealing.
const enc = chacha20poly1305_stream_create(key);   // the header's randomness: the platform's
const header = enc.header;
const p1 = enc.push_sync('first piece');
const p2 = enc.push_sync('last piece', true);

// Opening: each piece comes back, or null if it was altered or out of place.
const dec = chacha20poly1305_stream_open_create(key, header);
console.log(dec.push_sync(p2, true));          // -> null
console.log(text(dec.push_sync(p1)));          // -> first piece
console.log(dec.finished());                   // -> false
console.log(text(dec.push_sync(p2, true)));    // -> last piece
console.log(dec.finished());                   // -> true

// libsodium's crypto_secretstream_xchacha20poly1305: a 24-byte header,
// and the same push / push_sync / finished.
const ss = xchacha20poly1305_secretstream_create(key);
console.log(ss.header.length);                 // -> 24
const piece = ss.push_sync('to libsodium', true);
const open = xchacha20poly1305_secretstream_open_create(key, ss.header);
open.push(piece, true, undefined, function (err, plain) {
  console.log(text(plain), open.finished());   // -> to libsodium true
});
```

### Ed25519 and ECDSA

[`examples/signatures.mjs`](examples/signatures.mjs)

```javascript
// Ed25519 and ECDSA P-256: keygen, sign, verify. keygen(seed) gives the same
// key every time; keygen() draws a fresh one from the platform.
import * as ed25519 from 'cryptographic-primitives/ed25519.js';
import { p256 } from 'cryptographic-primitives/nist.js';
import { sha256_sync } from 'cryptographic-primitives/sha2.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const from_hex = (s) => new Uint8Array(Buffer.from(s, 'hex'));

// Ed25519, RFC 8032 section 7.1, test 1.
const ed = ed25519.keygen_sync(from_hex(
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'));
console.log(hex(ed.pk));       // -> d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
const sig = ed25519.sign_sync(new Uint8Array(0), ed.sk);
console.log(hex(sig).slice(0, 32));                          // -> e5564300c360ac729086e2cc806e828a
console.log(ed25519.verify_sync(new Uint8Array(0), sig, ed.pk));  // -> true

// One key, many messages: the key expanded once, the public key decoded once.
const signer = ed25519.signer_create(ed.sk);
console.log(hex(signer.sign_sync(new Uint8Array(0))) === hex(sig));  // -> true
const verifier = ed25519.verifier_create(ed.pk);
console.log(verifier.verify_sync(new Uint8Array(0), sig));           // -> true

// ECDSA: sign_message hashes the message with the hash it is given.
const { sk, pk } = p256.keygen_sync();
const s1 = p256.sign_message_sync(sha256_sync, 'hello', sk);
const s2 = p256.sign_message_sync(sha256_sync, 'hello', sk);
console.log(p256.verify_message_sync(sha256_sync, 'hello', s1, pk));  // -> true
// `extra` left out: fresh randomness, so these two signatures differ.
console.log(s1.r === s2.r);                                  // -> false

// An empty `extra` is classic RFC 6979 - RFC 6979 A.2.5, P-256, SHA-256, "sample".
const x = from_hex('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721');
const s3 = p256.sign_message_sync(sha256_sync, 'sample', x, new Uint8Array(0));
console.log(s3.r.toString(16));  // -> efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716
console.log(p256.sig_to_compact_sync(s3).length);           // -> 64
```

### ML-KEM and ML-DSA

[`examples/post-quantum.mjs`](examples/post-quantum.mjs)

```javascript
// ML-KEM (FIPS 203) to agree on a key, ML-DSA (FIPS 204) to sign.
// A parameter set is an object of operations, each in both forms.
import { ml_kem768 } from 'cryptographic-primitives/ml_kem.js';
import { ml_dsa65 } from 'cryptographic-primitives/ml_dsa.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');

// ML-KEM: the receiver publishes ek, the sender encapsulates to it.
const { ek, dk } = ml_kem768.keygen_sync();
console.log(ek.length, dk.length);                    // -> 1184 2400
const { ct, ss } = ml_kem768.encaps_sync(ek);
console.log(ct.length, ss.length);                    // -> 1088 32
console.log(hex(ml_kem768.decaps_sync(dk, ct)) === hex(ss));  // -> true

// ML-DSA: sign(sk, message, rnd, context).
const { pk, sk } = ml_dsa65.keygen_sync();
const sig = ml_dsa65.sign_sync(sk, 'release 1.4.2');
console.log(sig.length);                              // -> 3309
console.log(ml_dsa65.verify_sync(pk, 'release 1.4.2', sig));  // -> true

// rnd left out is the hedged signature; 32 zero bytes is the deterministic one.
const zero = new Uint8Array(32);
const d1 = ml_dsa65.sign_sync(sk, 'release 1.4.2', zero);
const d2 = ml_dsa65.sign_sync(sk, 'release 1.4.2', zero);
console.log(hex(d1) === hex(d2));                     // -> true

// The callback form of the same operation.
ml_dsa65.verify(pk, 'release 1.4.3', sig, function (err, ok) {
  console.log(err, ok);                               // -> null false
});
```

### Password hashing without blocking

[`examples/password.mjs`](examples/password.mjs)

```javascript
// Password hashing in the callback form, which never holds the event loop
// for the whole computation: node:crypto runs Argon2 on its thread pool
// where it has it, and the pure JavaScript runs in 8 ms slices.
import { argon2id } from 'cryptographic-primitives/argon2.js';
import { bcrypt, bcrypt_verify } from 'cryptographic-primitives/bcrypt.js';
import { hash_password, verify_password } from 'cryptographic-primitives/easy.js';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const fill = (n, byte) => new Uint8Array(n).fill(byte);

// RFC 9106 section 5.3: Argon2id with a secret and associated data - a test
// vector, not a storage recipe (easy.hash_password, below, is that). m is
// memory in KiB, t the passes, p the lanes.
argon2id({
  password: fill(32, 1), salt: fill(16, 2), secret: fill(8, 3), ad: fill(12, 4),
  m: 32, t: 3, p: 4, length: 32
}, function (err, tag) {
  console.log(hex(tag));  // -> 0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659
});

// bcrypt has no native form anywhere, so this is the pure JavaScript - and
// a timer keeps firing while it works.
let ticks = 0;
const timer = setInterval(() => ticks++, 1);
const salt = crypto.getRandomValues(new Uint8Array(16));
bcrypt('correct horse battery staple', salt, 10, function (err, stored) {
  clearInterval(timer);
  console.log(stored.slice(0, 7), ticks > 0);  // -> $2b$10$ true
  bcrypt_verify('correct horse battery staple', stored, function (err2, ok) {
    console.log(ok);                           // -> true
  });
});

// A hash from crypt_blowfish's test vectors (Openwall).
bcrypt_verify('U*U', '$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW',
  function (err, ok) {
    console.log('U*U', ok);                    // -> U*U true
  });

// Password storage with every parameter chosen - Argon2id, a random salt -
// and all of them kept in the string it returns. OWASP's minimum cost here,
// m = 19456 KiB and t = 2; left out, 64 MiB and t = 3.
hash_password('correct horse', { m: 19456, t: 2 }, function (err, stored) {
  console.log(stored.slice(0, 30));            // -> $argon2id$v=19$m=19456,t=2,p=1
  verify_password('correct horse', stored, function (err2, ok) {
    console.log('stored', ok);                 // -> stored true
  });
});
```

### Randomness and engines

[`examples/randomness-and-engines.mjs`](examples/randomness-and-engines.mjs)

```javascript
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
```

---

## What it covers

| area | contents |
|---|---|
| **hashes and XOFs** | SHA-2, SHA-3, SHAKE, cSHAKE, KMAC, TupleHash, ParallelHash, TurboSHAKE, KangarooTwelve, BLAKE2, BLAKE3, SM3, Streebog, Whirlpool, RIPEMD-160; SHA-1, MD5 and MD4 for old data; Poseidon and MiMC for circuits |
| **MACs and checksums** | HMAC over any hash; constant-time comparison of tags and tokens; CMAC, GMAC, Poly1305 and KMAC beside their cipher or hash; HOTP and TOTP; CRC-32, CRC-32C, CRC-64, Adler-32, xxHash, MurmurHash3, FNV-1a, SipHash, HighwayHash |
| **block ciphers** | AES, ARIA, Camellia, SEED, SM4, Kuznyechik, Magma, Triple DES, DES, Blowfish, RC2; ECB, CBC, CFB, OFB, CTR, GCM, GCM-SIV, CCM, EAX, OCB, SIV, XTS, IGE, KW and KWP where the cipher has them; FF1 format-preserving encryption |
| **stream ciphers and AEADs** | ChaCha20, XChaCha20, ChaCha20-Poly1305, XChaCha20-Poly1305, Salsa20, XSalsa20, NaCl secretbox, AEGIS-128L, AEGIS-256, Ascon, RC4 |
| **streaming** | a long message sealed piece by piece: AES-GCM and ChaCha20-Poly1305 in a STREAM construction, and libsodium's `crypto_secretstream_xchacha20poly1305` |
| **KDFs and passwords** | HKDF, PBKDF2, SP 800-108, ConcatKDF, X9.42, X9.63, TLS 1.2 PRF, SSH KDF, PKCS#12 KDF; scrypt, Argon2, bcrypt, bcrypt_pbkdf, yescrypt |
| **randomness** | random bytes from the platform, of any length; Hash_DRBG, HMAC_DRBG, CTR_DRBG (SP 800-90A) |
| **elliptic curves and RSA** | Ed25519, Ed448, X25519, X448, P-256, P-384, P-521, secp256k1 (ECDSA and BIP-340), Brainpool, SM2, ristretto255, decaf448, sr25519, RedDSA, Schnorr over any group; RSA with PSS, PKCS#1 v1.5 and OAEP; finite-field Diffie-Hellman; hash to curve; RSA and EC private keys in DER |
| **pairing and circuit curves** | BLS12-381 with BLS signatures, BN254, Baby Jubjub, Jubjub, Pallas and Vesta |
| **post-quantum** | ML-KEM, ML-DSA and HashML-DSA, SLH-DSA and HashSLH-DSA, Falcon, LMS/HSS, XMSS/XMSS^MT; FrodoKEM, HQC, Classic McEliece; the NIST additional-signature round 3: MAYO, UOV, SNOVA, QR-UOV, SQIsign, FAEST, SDitH, MQOM; Kemeleon encodings |
| **hybrid** | X-Wing, ML-KEM + ECDH hybrid KEMs and TLS's hybrid groups, composite ML-DSA signatures, HPKE with ML-KEM, X-Wing, MLKEM768-P256 and MLKEM1024-P384 |
| **HPKE** | RFC 9180, with DHKEM over P-256, P-384, P-521, X25519 and X448; DeriveKeyPair for every KEM; SHAKE and TurboSHAKE KDFs |
| **threshold and MPC** | FROST, with an sr25519 suite and ZIP 312's re-randomized FROST for Zcash; MuSig2, with tweaks and adaptor points; threshold ML-DSA, threshold BLS, Shamir and access-structure secret sharing, CGGMP21 setup material, MtA, oblivious transfer and OT extension, random VOLE, zero-sharing, verifiable encryption |
| **zero-knowledge** | the CGGMP21 Paillier and ring-Pedersen proofs, Bulletproofs, DLEQ, Pedersen, KZG, vector commitments, RSA accumulators, Merkle and sparse Merkle trees, Merlin transcripts |
| **VRFs, OPRFs, PAKEs** | ECVRF, X-VRF on XMSS, LB-VRF, RSA-FDH-VRF, the sr25519 VRF; OPRF, VOPRF and POPRF, and three post-quantum OPRFs; OPAQUE, CPace, and the post-quantum OQUAKE and CPaceOQUAKE with their augmented forms |
| **special signatures** | ring and linkable ring signatures, blind signatures, BBS, key blinding, adaptor signatures |
| **homomorphic encryption** | Paillier, ElGamal with threshold decryption, BFV |
| **delay functions** | Wesolowski VDFs over an RSA group and over a class group |

---

## What to reach for

| if you need | use |
|---|---|
| to encrypt, without hardware AES | **ChaCha20-Poly1305** |
| to encrypt, with hardware AES | **AES-GCM** or **AEGIS-128L** |
| to store a password | **Argon2id** - `easy.hash_password` |
| to read `/etc/shadow` | **yescrypt** |
| to sign | **Ed25519** |
| to sign for Bitcoin | **Schnorr (BIP-340)** |
| to aggregate thousands of signatures | **BLS12-381** |
| t-of-n signing | **FROST** |
| t-of-n signing for Zcash's shielded pools | **FROST, `redpallas` / `redjubjub`** (ZIP 312) |
| n-of-n signing, no setup | **MuSig2** |
| to survive a quantum computer | **X-Wing** (ML-KEM + X25519), or **HPKE with X-Wing** to encrypt data; **composite ML-DSA** to sign with both kinds at once |
| a signature for decades | **SLH-DSA** - hash-based, no lattice assumption |
| a hash inside a zero-knowledge circuit | **Poseidon** |
| to prove a key is *not* in a set | **sparse Merkle tree** |
| to swap across chains without an intermediary | **adaptor signatures** |
| to show one field of a credential, unlinkably | **BBS** |
| to issue a token without learning who gets it | **blind signatures** |
| a different identity per service, one backup | **key blinding** |
| randomness nobody can compute early | **a VDF** - over a class group when nobody may be trusted with a modulus ([below](#verifiable-delay-rsa-or-a-class-group)) |
| a huge set with constant-size proofs | **an RSA accumulator** |

### Verifiable delay: RSA or a class group

Both are Wesolowski's VDF - y = x^(2^T), T squarings one after another, a
one-element proof checked in milliseconds - over the shared prover in
`commons/wesolowski.js`. They differ in the group, and so in whom you
trust.

| | `vdf` (RSA-2048) | `vdf_class` (class group) |
|---|---|---|
| who could skip the delay | whoever knows RSA-2048's factors (RSA Security said they were destroyed) | nobody: the group comes from a public seed and its order is unknown to all |
| setup | none, if you accept that statement; otherwise a ceremony for a new modulus | none |
| squarings per second, this library | ~178,000 | ~24,000 at 1024 bits, ~15,500 at 1536, ~10,700 at 2048 |
| verify | ~4 ms | ~21 ms at 1024 bits, ~33 at 1536, ~41 at 2048 |
| y and π | 256 bytes each | 100 bytes each up to 1024 bits (148 at 1536, 196 at 2048) |
| proof, beyond the evaluation | ~1/k of it (k ≈ log₂T / 2: 10-20%) | the same |
| compatible with | - | Chia (chiavdf): the same discriminant from the same seed, the same y, the same π, the same bytes |

Measured with T = 20,000 on Node 22, a 2.1 GHz Xeon. The delay is only as
long as the fastest evaluator anyone has: chiavdf in C++ does about 117,000
squarings a second at 1024 bits, and dedicated hardware more. Set T from the
fastest evaluator you expect, not from this table.

**Reach for RSA** when a few hundred bytes and a few milliseconds matter and
the trust in RSA-2048's history is acceptable - or when you run your own
ceremony for N.

**Reach for a class group** when nobody may hold a trapdoor, or when you
need Chia's proofs. Choosing its size:

- What breaks it is computing the class number h(D): then x^(2^T) is
  x^(2^T mod h), one short exponentiation. The best known algorithm is
  subexponential; the usual estimates put 1024 bits around 90-bit work,
  1348 bits at 112-bit and 1827 bits at 128-bit (Hamdy and Möller; Biasse,
  Jacobson and Silvester).
- **One fixed group for years** gives an attacker all that time, and a
  group whose order happens to be smooth stays weak, with no way to test
  for it in advance. Dobson, Galbraith and Smith (ePrint 2020/196) put a
  fixed group for 128-bit security near 3840 bits - 6784 if the chance of a
  weak group must itself be 2^-128.
- **A fresh group per challenge**, as Chia does (1024 bits, a discriminant
  per challenge), leaves an attacker only the challenge's lifetime. A
  long-running system gets the same by rotating D on a schedule - daily,
  say - from a seed nobody knows before the rotation, such as one taken
  from the chain at that point. `class_group.discriminant(seed, bits)`
  makes one from any seed, any size.

[`examples/vdf.mjs`](examples/vdf.mjs)

```javascript
// A verifiable delay function over a class group: y = x^(2^T), T squarings
// one after another, and a proof checked in two short exponentiations. The
// group comes from a public seed, so nobody knows its order - and the bytes
// are chiavdf's, so Chia's proofs verify here and these verify there.
import { discriminant_sync, group_sync } from 'cryptographic-primitives/class_group.js';
import { evaluate_sync, verify_sync } from 'cryptographic-primitives/vdf_class.js';

// The seed: bytes nobody knew in advance, such as a block hash.
const seed = new TextEncoder().encode('block 812345');
const D = discriminant_sync(seed, 1024);
const x = group_sync(D).generator();             // or group_sync(D).hash_to_group(input)

const T = 2000;
const { bytes } = evaluate_sync(x, T, D);
console.log(bytes.y.length, bytes.proof.length);                // -> 100 100
console.log(verify_sync(x, bytes.y, bytes.proof, T, D));        // -> true
console.log(verify_sync(x, bytes.y, bytes.proof, T + 1, D));    // -> false
```

Every parameter is the caller's: the discriminant's size, the challenge
prime's width (`prime_bits`, Chia's 264 by default), the encoding
(`compressed`: chiavdf's BQFC, or a plain one), and the prover's memory
(`k`, `max_checkpoints`), all in the options object `evaluate` and
`verify` take last.

---

## Module reference

Every module is imported by its subpath - `cryptographic-primitives/<module>.js` -
and is also a namespace of the package root. A name in the third column is
an operation, with its `_sync` form beside it; `set.op` is an operation of
a parameter set. The last column is what the module is checked against:
the standard's vectors, the authors' KATs or another implementation, and
for a construction defined by what it must satisfy, those properties -
round trips, tampering refused, the relation a proof claims.

**Hashes and XOFs**

| module | for | main exports | checked against |
|---|---|---|---|
| `sha2` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 (FIPS 180-4) | `sha256`, `sha384`, `sha512`, `sha256_create` | FIPS 180-4 vectors; node:crypto |
| `sha3` | SHA-3, SHAKE, Keccak, cSHAKE, KMAC, TupleHash, ParallelHash (FIPS 202, SP 800-185), TurboSHAKE, KangarooTwelve | `sha3_256`, `shake256`, `keccak256`, `kmac256`, `turboshake128`, `kt128` | FIPS 202 and SP 800-185 vectors; node:crypto |
| `blake2` | BLAKE2b and BLAKE2s, plain or keyed (RFC 7693) | `blake2b`, `blake2s`, `blake2b_create` | RFC 7693 vectors; node:crypto |
| `blake3` | BLAKE3: hash, keyed hash, key derivation, chunk proofs | `blake3`, `blake3_keyed`, `blake3_derive_key`, `blake3_proof`, `blake3_verify_chunk` | the BLAKE3 team's published hashes |
| `sm3` | SM3 (GB/T 32905) | `sm3` | GB/T 32905 vectors; gmssl; node:crypto |
| `streebog` | Streebog-256 and -512 (GOST R 34.11-2012, RFC 6986) | `streebog256`, `streebog512` | RFC 6986 vectors |
| `whirlpool` | Whirlpool (ISO/IEC 10118-3) | `whirlpool` | the published vectors; OpenSSL |
| `ripemd160` | RIPEMD-160 | `ripemd160` | the designers' vectors; node:crypto |
| `sha1` | SHA-1 - broken; for compatibility only | `sha1` | FIPS 180-4 vectors; node:crypto |
| `md5` | MD5 - broken; for checksums and old protocols | `md5` | RFC 1321 vectors; node:crypto |
| `md4` | MD4 - broken; and the NTLM hash built on it | `md4`, `ntlm` | RFC 1320 vectors; OpenSSL |
| `poseidon` | Poseidon, a hash cheap inside a zero-knowledge circuit | `poseidon`, `poseidon_bytes` | circomlib |
| `mimc` | MiMC-7, MiMC sponge and Feistel, for circuits | `mimc7`, `mimc_sponge`, `mimc_feistel` | circomlib |

**MACs, checksums and one-time passwords**

| module | for | main exports | checked against |
|---|---|---|---|
| `hmac` | HMAC over any hash in the library (RFC 2104) | `hmac`, `hmac_create`, `hmac_verify` | node:crypto, over SHA-1, SHA-2, SHA-3, MD5 and BLAKE2b |
| `otp` | HOTP and TOTP (RFC 4226, RFC 6238), `otpauth://` URIs | `totp`, `totp_verify`, `hotp`, `otpauth_uri` | RFC 4226 and RFC 6238 vectors |
| `ct` | comparing secrets - a tag, a token, a ticket's key name - in constant time, in place of `crypto.timingSafeEqual`; unequal lengths are `false`, not an error | `equal` | node:crypto's `timingSafeEqual`; timed against a comparison that stops at the first difference |
| `checksum` | non-cryptographic: CRC-32, CRC-32C, CRC-64, Adler-32, xxHash, MurmurHash3, FNV-1a, SipHash-2-4, HighwayHash | `crc32`, `crc32c`, `xxhash64`, `siphash24` | each algorithm's published vectors |

**Block ciphers and modes**

| module | for | main exports | checked against |
|---|---|---|---|
| `aes` | AES (FIPS 197): ECB, CBC, CFB, CFB8, OFB, CTR, GCM, GCM-SIV, CCM, EAX, OCB, SIV, XTS, IGE, KW, KWP, CMAC, GMAC | `aes_gcm_encrypt`, `aes_gcm_create`, `aes_ctr`, `aes_siv_encrypt`, `aes_kw_wrap`, `aes_cmac` | FIPS 197 and SP 800-38A-G vectors; RFC 3394, 3610, 4493, 5297, 5649, 7253 and 8452 vectors; node:crypto |
| `aria` | ARIA (RFC 5794): ECB, CBC, CTR, GCM, CCM, EAX, KW, KWP, CMAC, GMAC | `aria_gcm_encrypt`, `aria_cbc_encrypt` | RFC 5794 vectors |
| `camellia` | Camellia (RFC 3713), the same modes | `camellia_gcm_encrypt`, `camellia_cbc_encrypt` | RFC 3713 vectors |
| `seed` | SEED (RFC 4269), the same modes | `seed_cbc_encrypt`, `seed_gcm_encrypt` | RFC 4269 vectors; Wycheproof |
| `sm4` | SM4 (GB/T 32907), the same modes | `sm4_gcm_encrypt`, `sm4_cbc_encrypt` | RFC 8998 vectors; gmssl |
| `gost` | Kuznyechik in the same modes, and Magma in ECB, CBC and CTR (GOST R 34.12-2015) | `kuznyechik_gcm_encrypt`, `magma_cbc_encrypt` | RFC 7801 and RFC 8891 vectors; GOST R 34.13 |
| `des` | DES and Triple DES - DES broken, 3DES deprecated; ECB, CBC, CTR | `des3_cbc_decrypt`, `des_ecb_decrypt` | node:crypto |
| `blowfish` | Blowfish: ECB, CBC, CTR | `blowfish_cbc_decrypt` | Schneier's test vectors |
| `rc2` | RC2 (RFC 2268): ECB, CBC, CTR - for S/MIME and PKCS#12 | `rc2_cbc_decrypt` | RFC 2268 vectors |
| `ff1` | FF1 format-preserving encryption (SP 800-38G); digits, card numbers, Luhn | `ff1_encrypt`, `ff1_encrypt_digits`, `ff1_encrypt_pan`, `luhn_valid` | SP 800-38G samples; Wycheproof |

**Stream ciphers and AEADs**

| module | for | main exports | checked against |
|---|---|---|---|
| `chacha` | ChaCha20 (and 8, 12 rounds), XChaCha20, Poly1305, ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305 | `chacha20poly1305_encrypt`, `chacha20poly1305_create`, `xchacha20poly1305_encrypt`, `chacha20`, `poly1305` | RFC 8439 vectors; node:crypto |
| `salsa` | Salsa20, XSalsa20, NaCl `crypto_secretbox` | `secretbox`, `secretbox_open`, `xsalsa20poly1305_encrypt` | libsodium |
| `aegis` | AEGIS-128L and AEGIS-256 (draft-irtf-cfrg-aegis-aead) | `aegis128l_encrypt`, `aegis256_encrypt` | the draft's vectors |
| `ascon` | Ascon (SP 800-232): AEAD128, Hash256, XOF128, CXOF128, and the v1.2 variants | `ascon_aead128_encrypt`, `ascon_hash256`, `ascon_xof128` | NIST's SP 800-232 KATs; two v1.2 references |
| `rc4` | RC4 - broken; for reading old data | `rc4` | RFC 6229 vectors |

**Streaming**

| module | for | main exports | checked against |
|---|---|---|---|
| `stream` | a long message sealed piece by piece; AES-GCM and ChaCha20-Poly1305 in a STREAM construction, and libsodium's secretstream | `chacha20poly1305_stream_create`, `aes_gcm_stream_create`, `xchacha20poly1305_secretstream_create`, and an `_open_create` for each | libsodium 1.0.20, both ways (secretstream); round trips, reordered, cut and tampered pieces refused (STREAM) |

**Key derivation and password hashing**

| module | for | main exports | checked against |
|---|---|---|---|
| `kdf` | HKDF, PBKDF2, SP 800-108 (counter, feedback, pipeline), ConcatKDF, X9.42, X9.63, TLS 1.2 PRF, SSH KDF, PKCS#12 KDF | `hkdf`, `pbkdf2`, `kbkdf_counter`, `x963_kdf`, `tls1_prf`, `sshkdf`, `pkcs12_kdf` | RFC 5869 and RFC 7292 vectors; OpenSSL (`openssl kdf`); node:crypto |
| `scrypt` | scrypt (RFC 7914) | `scrypt` | RFC 7914 vectors; node:crypto |
| `argon2` | Argon2d, Argon2i, Argon2id (RFC 9106) | `argon2id`, `argon2i`, `argon2d` | RFC 9106 vectors; node:crypto |
| `bcrypt` | bcrypt, and OpenSSH's bcrypt_pbkdf | `bcrypt`, `bcrypt_verify`, `bcrypt_pbkdf` | OpenBSD's and crypt_blowfish's vectors; pyca/bcrypt |
| `yescrypt` | yescrypt, and the `$y$` crypt strings of `/etc/shadow` | `yescrypt`, `crypt`, `crypt_verify` | libxcrypt; node:crypto (flags 0, which is scrypt) |
| `easy` | password storage and password-based encryption with every parameter chosen: Argon2id, ChaCha20-Poly1305 | `hash_password`, `verify_password`, `seal_with_password`, `open_with_password`, `needs_rehash` | its parts' references: Argon2id, ChaCha20-Poly1305 |

**Randomness**

| module | for | main exports | checked against |
|---|---|---|---|
| `random` | random bytes from `crypto.getRandomValues`, any length (past its 65,536-byte limit, in pieces), in place of `crypto.randomBytes` | `random_bytes` | every piece of a long request filled; a missing source an error, never `Math.random` |
| `drbg` | Hash_DRBG, HMAC_DRBG, CTR_DRBG (SP 800-90A) | `hmac_drbg`, `hash_drbg`, `ctr_drbg` | SP 800-90A CAVP vectors |

**Elliptic curves, RSA and signatures**

| module | for | main exports | checked against |
|---|---|---|---|
| `ed25519` | Ed25519, Ed25519ctx, Ed25519ph (RFC 8032); hash to curve | `keygen`, `sign`, `verify`, `verify_batch`, `sign_ctx`, `sign_ph`, `to_x25519` | RFC 8032 and RFC 9380 vectors; ed25519-speccheck; Wycheproof; node:crypto |
| `ed448` | Ed448 and Ed448ph (RFC 8032) | `keygen`, `sign`, `verify`, `sign_ph` | RFC 8032 vectors; node:crypto |
| `nist` | P-256, P-384, P-521: ECDSA, ECDH, hash to curve; private keys in DER (ECPrivateKey, RFC 5915) | `p256.sign_message`, `p256.verify_message`, `p256.signer_create`, `p256.verifier_create`, `p256.ecdh`, `p256.ecdh_create`, `p256.recover`, `p256.sig_to_der`, `p256.private_key_to_der`, `p256.private_key_from_der` | RFC 6979 and RFC 9380 vectors; Wycheproof; node:crypto |
| `secp256k1` | secp256k1: ECDSA with key recovery, BIP-340 Schnorr, ECDH; private keys in DER | `sign`, `signer_create`, `verifier_create`, `recover`, `schnorr_sign`, `schnorr_verify`, `schnorr_verify_batch`, `private_key_to_der` | BIP-340 and RFC 6979 vectors; Wycheproof; node:crypto |
| `brainpool` | brainpoolP256r1, P384r1, P512r1 (RFC 5639): ECDSA, ECDH; private keys in DER | `brainpoolP256r1.sign_message`, `brainpoolP256r1.signer_create`, `brainpoolP256r1.verifier_create`, `brainpoolP256r1.ecdh`, `brainpoolP256r1.private_key_to_der` | Wycheproof; node:crypto |
| `sm2` | SM2 (GB/T 32918): signatures, encryption, key exchange | `sign`, `verify`, `encrypt`, `decrypt`, `key_exchange` | GB/T 32918 vectors; gmsm |
| `ristretto255` | ristretto255, a prime-order group over Curve25519 (RFC 9496) | `base_mul`, `encode`, `decode`, `hash_to_group`, `scalar_mul` | RFC 9496 vectors |
| `decaf448` | decaf448, the prime-order group over Ed448 (RFC 9496) | `base_mul`, `encode`, `decode`, `hash_to_group` | RFC 9496 vectors |
| `schnorr` | Schnorr signatures over any prime-order group | `sign`, `verify`, `verify_batch` | round trips; tampering refused; a batch agrees with one by one |
| `sr25519` | sr25519 (schnorrkel, Polkadot): signatures, HDKD, VRF | `sign`, `verify`, `derive_soft`, `secret_hard`, `vrf_sign`, `vrf_verify` | schnorrkel and Substrate (`//Alice`); @scure/sr25519 |
| `reddsa` | RedDSA (Zcash): RedJubjub and RedPallas, keys that can be re-randomized | `sign`, `verify`, `randomize_private`, `randomize_public` | the Zcash Foundation's reddsa crate |
| `rsa` | RSA (RFC 8017): PSS, with MGF1 over the message's hash or another, PKCS#1 v1.5, OAEP, keys in DER and JWK, RSA-FDH-VRF; p and q from (n, e, d) (SP 800-56B C.2) | `keygen`, `sign_pss_message`, `verify_pss_message`, `signer_create`, `verifier_create`, `encrypt_oaep`, `decrypt_oaep`, `private_key_to_der`, `public_key_to_der`, `private_key_from_d` | Wycheproof (PSS with every pairing of message and MGF1 hash; PKCS#1 v1.5 verification, and signing byte for byte); OpenSSL (OAEP, PSS, PKCS#1 v1.5, and an RSASSA-PSS key with MGF1 over SHA-512); RFC 9381 appendix A (RSA-FDH-VRF) |

**Key exchange and HPKE**

| module | for | main exports | checked against |
|---|---|---|---|
| `x25519` | X25519 (RFC 7748); a context holding one secret for many agreements | `keygen`, `x25519`, `x25519_checked`, `x25519_create` | RFC 7748 vectors; node:crypto |
| `x448` | X448 (RFC 7748); a context holding one secret | `keygen`, `x448`, `x448_checked`, `x448_create` | RFC 7748 vectors; node:crypto |
| `dh` | finite-field Diffie-Hellman over the RFC 7919 groups | `GROUPS`, `keygen`, `compute_secret`, `validate_public` | the RFC 7919 primes, recomputed from their formula |
| `hpke` | HPKE (RFC 9180): DHKEM, ML-KEM, X-Wing, MLKEM768-P256 and MLKEM1024-P384 KEMs (draft-ietf-hpke-pq), with DeriveKeyPair for every KEM; HKDF, SHAKE and TurboSHAKE KDFs; AES-GCM and ChaCha20-Poly1305 | `x25519_sha256_chacha20poly1305.seal`, `.open`, a set per suite, and `MLKEM768_P256.derive_key_pair` | RFC 9180 vectors; draft-ietf-hpke-pq vectors |

**Pairing and circuit curves**

| module | for | main exports | checked against |
|---|---|---|---|
| `bls12_381` | BLS12-381 and BLS signatures: aggregation, proofs of possession, threshold signing; `GROUP_G1`, the key group, for protocols over any group | `keygen`, `sign`, `verify`, `aggregate_signatures`, `fast_aggregate_verify`, `threshold_sign`, `combine_weighted` | Ethereum's BLS tests; RFC 9380 vectors |
| `bn254` | the BN254 pairing | `pair`, `pair_product`, `POINT1`, `POINT2` | bilinearity and non-degeneracy |
| `babyjubjub` | Baby Jubjub, the curve inside BN254 circuits | `keygen`, `base_mul`, `encode`, `in_subgroup` | circomlib |
| `jubjub` | Jubjub, the curve inside BLS12-381 circuits (Zcash Sapling) | `keygen`, `base_mul`, `encode`, `in_subgroup` | the Zcash Foundation's jubjub crate |
| `pasta` | Pallas and Vesta, the curve cycle behind Halo2 | `pallas`, `vesta` | pasta_curves |

**Post-quantum signatures**

| module | for | main exports | checked against |
|---|---|---|---|
| `ml_dsa` | ML-DSA-44, -65, -87 (FIPS 204), and HashML-DSA | `ml_dsa65.keygen`, `ml_dsa65.sign`, `ml_dsa65.verify`, `ml_dsa65.hash_sign`, `ml_dsa65.signer_create` | NIST ACVP vectors; Wycheproof; node:crypto |
| `slh_dsa` | SLH-DSA (FIPS 205), all twelve parameter sets, and HashSLH-DSA | `slh_dsa_sha2_128s.sign`, `slh_dsa_shake_128f.verify`, `slh_dsa_sha2_128s.hash_sign`, `slh_dsa_sha2_128s.signer_create` | NIST ACVP vectors |
| `falcon` | Falcon-512 and Falcon-1024 (round 3, v1.2) | `falcon512.keygen`, `.sign`, `.verify` | the submission's KATs, key generation and signing included |
| `lms` | LMS and HSS (RFC 8554, SP 800-208) - stateful | `lms_sha256_h10_w4.sign`, `lms`, `hss` | RFC 8554 vectors |
| `xmss` | XMSS and XMSS^MT (RFC 8391, SP 800-208) - stateful; X-VRF, a post-quantum VRF on every set (ePrint 2021/302) | `xmss_sha2_10_256.sign`, `xmssmt_sha2_20_2_256.sign`, `xmss_sha2_10_256.vrf_eval`, `.vrf_verify` | liboqs's XMSS KATs |
| `mayo` | MAYO (NIST additional signatures, round 3); its bare trapdoor, for schemes built on it | `mayo1.sign`, `mayo2.verify`, `mayo1.trapdoor` | the MAYO team's round-3 KATs |
| `uov` | UOV (round 3) | `uov_ip.sign`, `uov_is_pkc.verify` | the UOV team's round-3 KATs |
| `snova` | SNOVA (round 3) | `snova_i_s.sign` | the SNOVA team's round-3 KATs |
| `qruov` | QR-UOV (round 3) | `qruov1q127l3_shake.sign` | the QR-UOV team's round-3 KATs |
| `sqisign` | SQIsign, isogeny signatures (round 3) | `sqisign_lvl1.sign` | the SQIsign team's round-3 KATs |
| `faest` | FAEST and FAEST-EM: a proof of knowledge of an AES key (round 3) | `faest_128s.sign` | the FAEST team's round-3 KATs |
| `sdith` | SDitH, syndrome decoding in the head (round 3) | `sdith_cat1_fast.sign` | the SDitH team's round-3 KATs |
| `mqom` | MQOM, multivariate quadratic in the head (round 3) | `mqom3_cat1_gf16_fast_ct.sign` | the MQOM team's round-3 KATs |

**Post-quantum KEMs**

| module | for | main exports | checked against |
|---|---|---|---|
| `ml_kem` | ML-KEM-512, -768, -1024 (FIPS 203); FIPS 203's check of an encapsulation key taken from someone else | `ml_kem768.keygen`, `ml_kem768.encaps`, `ml_kem768.decaps`, `ml_kem768.decaps_create`, `ml_kem768.check_ek` | NIST ACVP vectors; Wycheproof; CCTV; Go's accumulated tests; node:crypto |
| `frodokem` | FrodoKEM and eFrodoKEM, AES and SHAKE | `frodokem640_aes.encaps`, `frodokem976_shake.decaps` | the FrodoKEM team's KATs |
| `hqc` | HQC-1, -3, -5 (v5.1.0) | `hqc1.keygen`, `hqc1.encaps`, `hqc1.decaps` | the HQC team's KATs |
| `mceliece` | Classic McEliece, all ten parameter sets | `mceliece348864.encaps`, `mceliece6960119f.decaps` | the Classic McEliece team's KATs |
| `kemeleon` | Kemeleon: ML-KEM keys and ciphertexts as uniform-looking bytes | `kemeleon` | draft-vos-cfrg-pqpake-03 appendix E |

**Hybrid and composite**

| module | for | main exports | checked against |
|---|---|---|---|
| `xwing` | X-Wing: ML-KEM-768 and X25519; the encapsulation-key check | `keygen`, `encaps`, `decaps`, `check_public_key` | draft-irtf-cfrg-concrete-hybrid-kems vectors |
| `hybrid_kem` | ML-KEM with an elliptic curve, and TLS's X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 | `mlkem768_x25519.encaps`, `x25519mlkem768.decaps` | draft-irtf-cfrg-concrete-hybrid-kems vectors; pyca/cryptography (the TLS groups) |
| `composite_sig` | composite ML-DSA (RFC 10073): ML-DSA with RSA, ECDSA or EdDSA, both halves required; the halves signed in two places and assembled | `mldsa65_ed25519_sha512.sign`, `mldsa65_ecdsa_p256_sha512.verify`, `.halves`, `.assemble`, `.public_key_from`, `BY_LABEL` | RFC 10073 vectors |

**Threshold signatures and MPC**

| module | for | main exports | checked against |
|---|---|---|---|
| `frost` | FROST (RFC 9591), two-round threshold Schnorr | `keygen_dealer`, `commit`, `sign`, `aggregate`, `verify` | RFC 9591 vectors |
| `frost_codec` | RFC 9591's encodings, hashes and binding factors, per ciphersuite: the RFC's five, taproot, sr25519 (the aggregate is a schnorrkel signature), and ZIP 312's re-randomized `redjubjub` and `redpallas` | `CIPHERSUITES`, `suite`, `compute_binding_factors`, `compute_challenge` | RFC 9591 vectors; the Zcash Foundation's frost-rerandomized |
| `frost_pure` | FROST's arithmetic over any group: VSS, proofs of possession, re-randomization | `vss_eval`, `poly_commit`, `pok_prove`, `sign_share`, `verify_signature_batch` | RFC 9591 vectors |
| `musig2` | MuSig2 (BIP 327), n-of-n Schnorr on secp256k1; plain and x-only tweaks, and an adaptor point | `key_agg`, `nonce_gen`, `sign`, `partial_sig_agg`, `apply_tweak` | BIP-327 vectors |
| `musig2_suites` | MuSig2 on Ed25519, Ed448, ristretto255 and sr25519; plain tweaks and an adaptor point | `musig2_on`, `key_sort` | the aggregate verifies as the suite's ordinary signature |
| `ml_dsa_threshold` | threshold ML-DSA (Mithril), up to 6 parties, giving an ordinary FIPS 204 signature; parameter rows for 2^50, 2^45 or 2^40 signatures per key, an existing key dealt, and a strict mode | `deal`, `deal_existing`, `round1`, `round3`, `combine`, `signable` | the result verifies under FIPS 204 |
| `shamir` | Shamir secret sharing and Lagrange interpolation | `split`, `combine`, `split_bytes`, `combine_bytes` | any t shares rebuild the secret |
| `access` | secret sharing for a nested t-of-n access structure; one leaf rebuilt from the others | `deal`, `combine`, `authorized`, `commit`, `verify_leaf`, `repair_coefficients` | every authorized set rebuilds the secret, and no other |
| `cmp_setup` | CGGMP21 auxiliary data in one call: a Paillier key and ring-Pedersen parameters | `precompute_aux` | the parameters' relations, and their proofs |
| `material` | the same material, in slices, from fresh primes | `generate_material` | the parameters' relations, and their proofs |
| `mta` | multiplicative-to-additive share conversion over Paillier | `mta`, `alice_encrypt`, `bob_respond`, `alice_decrypt` | the shares add up to the product |
| `ot_base` | oblivious transfer (Chou-Orlandi) | `sender_setup`, `receiver_choose`, `transfer` | the receiver's key is the sender's chosen one |
| `ot_extend` | OT extension: 128 base transfers into any number | `sender_extend`, `receiver_extend` | the receiver's key is the sender's chosen one |
| `ot_kem` | post-quantum base OT from ML-KEM | `ot_ml_kem768.receiver_choose`, `.sender_respond`, `.receiver_key` | the receiver's key is the sender's chosen one |
| `rvole` | random vector OLE from oblivious transfer | `bob_sample`, `alice_multiply`, `bob_share` | the relation the functionality demands |
| `zero_share` | pseudorandom zero-sharing over the integers | `zero_share`, `zero_share_pair` | the shares sum to zero |
| `pve` | publicly verifiable encryption of a discrete log, to an X-Wing key | `encrypt`, `verify`, `decrypt` | round trips; tampering refused |

**Paillier and CGGMP21 proofs**

| module | for | main exports | checked against |
|---|---|---|---|
| `paillier_range` | Π^enc: a Paillier plaintext is in range | `prove`, `verify` | honest proofs verify; every field tampered is refused |
| `paillier_range_exact` | a Paillier plaintext is in [a, b] exactly | `prove_range_exact`, `verify_range_exact` | honest proofs verify; every field tampered is refused |
| `paillier_affg` | Π^aff-g: an affine operation on a ciphertext, with a group commitment | `prove_affg`, `verify_affg` | honest proofs verify; every field tampered is refused |
| `paillier_affg_star` | Π^aff-g*: the same, without ring-Pedersen parameters | `prove_affg_star`, `verify_affg_star` | honest proofs verify; every field tampered is refused |
| `paillier_affp` | Π^aff-p: the same, with a Paillier commitment | `prove_affp`, `verify_affp` | honest proofs verify; every field tampered is refused |
| `paillier_dec` | Π^dec: decryption in the exponent | `prove_dec`, `verify_dec` | honest proofs verify; every field tampered is refused |
| `paillier_dlog` | Π^enc-exp: a ciphertext and an exponent in a group of hidden order hold the same integer | `prove_dlog`, `verify_dlog` | honest proofs verify; every field tampered is refused |
| `paillier_enc_elg` | Π^enc-elg: a Paillier plaintext equals an ElGamal commitment's value | `prove_enc_elg`, `verify_enc_elg` | honest proofs verify; every field tampered is refused |
| `paillier_mul` | Π^mul: a ciphertext is the product of two | `prove_mul`, `verify_mul` | honest proofs verify; every field tampered is refused |
| `paillier_zero` | Π^zero: a ciphertext encrypts zero | `prove_zero`, `verify_zero` | honest proofs verify; every field tampered is refused |
| `ring_pedersen` | ring-Pedersen commitments, and the proofs of their parameters (Π^prm, Π^mod) | `keygen`, `commit`, `prove_params`, `prove_modulus` | honest proofs verify; every field tampered is refused |
| `zk_cmp` | Π^sch and Π^fac | `prove_sch`, `prove_fac`, `verify_fac` | honest proofs verify, every field tampered is refused; the relations compared with the LFDT-Lockness specification |
| `zk_elog` | Π^elog: a discrete log equals an ElGamal plaintext | `prove_elog`, `verify_elog` | honest proofs verify; every field tampered is refused |
| `zk_dlenc` | Π_dlenc: one secret in a group element and a Paillier ciphertext (ePrint 2024/1950) | `prove_dlenc`, `verify_dlenc` | honest proofs verify; every field tampered is refused |
| `zk_fac_sp` | N has no small factors, proved in a safe-prime group (ePrint 2024/1950) | `prove_fac_sp`, `verify_fac_sp` | honest proofs verify; every field tampered is refused |
| `zk_sig` | Π_sig: a well-formed signature (ePrint 2024/1950; generic group model) | `prove_sig`, `verify_sig` | honest proofs verify; every field tampered is refused |

**Zero-knowledge, commitments and Merkle trees**

| module | for | main exports | checked against |
|---|---|---|---|
| `pedersen` | Pedersen commitments, with balance and equality proofs | `commit`, `verify`, `verify_balance`, `prove_equal` | honest proofs verify; every field tampered is refused |
| `bulletproofs` | Bulletproofs range proofs | `prove_range`, `verify_range` | honest proofs verify; every field tampered is refused |
| `dleq` | Chaum-Pedersen: two discrete logs are equal | `prove`, `verify` | honest proofs verify; every field tampered is refused |
| `kzg` | KZG polynomial commitments over BLS12-381 | `setup`, `commit`, `open`, `verify` | honest proofs verify; every field tampered is refused |
| `vector_commit` | a vector commitment over an RSA group | `commit`, `open`, `verify`, `update` | honest proofs verify; every field tampered is refused |
| `accumulator` | an RSA accumulator: membership and non-membership | `accumulate`, `witness`, `verify_membership`, `non_membership` | honest proofs verify; every field tampered is refused |
| `merkle` | Merkle trees over any hash, with RFC 6962's leaf and node prefixes against second preimages | `build`, `root`, `proof`, `verify` | proofs verify; tampering refused |
| `sparse_merkle` | a sparse Merkle tree: proofs that a key is absent | `sparse_merkle`, `verify_sparse` | proofs verify; tampering refused |
| `merlin` | Merlin transcripts over STROBE, for Fiat-Shamir | `Transcript` | the merlin crate |

**VRFs, OPRFs and PAKEs**

| module | for | main exports | checked against |
|---|---|---|---|
| `ecvrf` | ECVRF (RFC 9381) | `prove`, `verify`, `proof_to_hash` | RFC 9381 appendix B vectors |
| `lb_vrf` | LB-VRF, a lattice one-time VRF | `keygen`, `evaluate`, `verify` | proofs verify; tampering refused |
| `oprf` | OPRF, VOPRF and POPRF (RFC 9497), five suites | `blind`, `blind_evaluate`, `finalize`, `oprf_suite` | RFC 9497 vectors |
| `leap` | Leap, a post-quantum OPRF from the Spring PRF | `client_start`, `server_start`, `client_finish` | the protocol's output is the PRF's; cheating servers refused |
| `legendre_oprf` | the 2Hash Legendre OPRF, post-quantum | `legendre_oprf` | the protocol's output is the PRF's; cheating servers refused |
| `pool` | Pool, a post-quantum OPRF from rounding and oblivious transfer | `POOL_128.request`, `.blind_evaluate`, `.finalize` | the protocol's output is the PRF's; cheating servers refused |
| `opaque` | OPAQUE, an augmented PAKE (RFC 9807) | `opaque_suite` | RFC 9807 vectors, real and fake |
| `cpace` | CPace, a balanced PAKE (draft-irtf-cfrg-cpace) | `CPACE_X25519_SHA512.party`, `cpace_suite` | draft-irtf-cfrg-cpace-21 appendix B vectors |
| `pqpake` | post-quantum and hybrid PAKEs (draft-vos-cfrg-pqpake): OQUAKE, CPaceOQUAKE, OQUAKE+ and CPaceOQUAKE+ | `pqpake`, `CONFIG_IDS` | draft-vos-cfrg-pqpake-03 appendix E vectors |

**Ring, blind and adaptor signatures**

| module | for | main exports | checked against |
|---|---|---|---|
| `ring` | SAG and LSAG ring signatures | `sign`, `verify`, `sign_linkable`, `linked` | round trips; tampering refused |
| `ring_aes` | post-quantum ring, linkable ring and threshold ring signatures from AES | `ring_aes_128f.sign`, `lrs_aes_128f.linked` | round trips; tampering refused |
| `dualring_prf` | DualRing-PRF post-quantum ring and linkable ring signatures | `dualring_prf` | round trips; tampering refused |
| `blind` | blind RSA and blind Schnorr signatures | `rsa_blind`, `rsa_sign_blinded`, `rsa_unblind`, `schnorr_blind` | round trips; tampering refused |
| `pomfrit` | PoMFRIT, post-quantum blind signatures from MAYO | `pomfrit_128s.request`, `.issue`, `.finish`, `.verify` | round trips; tampering refused |
| `bbs` | BBS: one signature over many messages, proofs that disclose a chosen few | `keygen`, `core_sign`, `core_proof_gen`, `core_proof_verify` | the BBS draft's vectors |
| `key_blind` | key blinding: unlinkable public keys from one key (Ed25519, Ed448, ECDSA) | `blind_public_key`, `blind_sign`, `unblind_public_key` | the key-blinding draft's vectors; OpenSSL (Ed448) |
| `adaptor` | adaptor signatures for Schnorr and ECDSA | `schnorr_pre_sign`, `schnorr_complete`, `schnorr_extract`, `ecdsa_pre_sign` | libsecp256k1-zkp (ECDSA) |

**Homomorphic encryption**

| module | for | main exports | checked against |
|---|---|---|---|
| `paillier` | Paillier, additively homomorphic | `keygen`, `encrypt`, `decrypt`, `add`, `mul_plain` | round trips, and the homomorphisms |
| `elgamal` | ElGamal, with threshold decryption | `encrypt`, `decrypt_share`, `combine_shares`, `seal_to_threshold` | round trips, and the homomorphisms |
| `bfv` | BFV lattice homomorphic encryption: add and multiply ciphertexts | `keygen`, `encrypt`, `add`, `mul`, `decrypt`, `batch_encode` | round trips, and the homomorphisms |

**Verifiable delay functions**

| module | for | main exports | checked against |
|---|---|---|---|
| `vdf` | Wesolowski's VDF over an RSA group | `evaluate`, `verify` | proofs verify; a wrong T or y is refused |
| `vdf_class` | Wesolowski's VDF over a class group, with no trusted setup; byte-compatible with Chia's chiavdf | `evaluate`, `verify` | chiavdf, both ways |
| `class_group` | class groups of imaginary quadratic fields | `discriminant`, `group` | chiavdf |

**Engines**

| module | for | main exports | checked against |
|---|---|---|---|
| `engines` | which engine runs a call, and the switch to pure JavaScript | `engine_of`, `set_engine` | the pure code: both engines give the same result |

---

## Building blocks

Shared mechanisms live in `src/commons/`. They are the pure code - plain
synchronous functions, no engine, no callback forms - and each is
importable by its path, `cryptographic-primitives/commons/<name>.js`:

```javascript
import { table_lookup } from 'cryptographic-primitives/commons/ct.js';

table_lookup(table, secret_index, 32);  // reads every entry, returns one
```

Comparing secrets has a public module of its own, `ct.js` -
`equal_sync(tag, expected)` - and random bytes one too, `random.js`.

```
voleith.js         VOLE-in-the-head, FAEST's proof system on its own: a proof
                   of knowledge for any statement of polynomial constraints
                   over GF(2^λ), in one or two stages; faest, ring_aes and
                   pomfrit use it. one_hot_select: an OR over public values,
                   a committed index into a list
keccak_circuit.js  Keccak-f[1600] as such constraints, round by round, or in
                   blocks proven forward and back
aes_circuit.js     AES / Rijndael as such constraints - FAEST's statement
group.js           the prime-order group interface frost, musig2, ecvrf,
                   oprf, dleq, adaptor, ring and pedersen are written over
wesolowski.js      Wesolowski's proof of exponentiation over any group of
                   unknown order - vdf and vdf_class
der.js             strict DER, the one parser for RSA keys, EC private keys
                   and ECDSA signatures
ct.js              constant-time comparison, selection and table lookup
fixed_window.js    constant-time fixed-window and fixed-base multiplication,
                   and wNAF and multi-scalar multiplication for verification
glv.js             secp256k1's endomorphism
batch.js           what every batch verification shares: random weights, and
                   finding the bad item in a failed batch
h2c.js             hashing to curves (RFC 9380)
kyber_ring.js,     the rings underneath ML-KEM and ML-DSA, with their NTTs
dilithium_ring.js
module_lattice.js  what ML-KEM and ML-DSA share above their rings: the
                   matrix A from its seed, and a row of it times a vector
primes.js          primality (Baillie-PSW), prime and safe-prime search
task.js            long computations cut into resumable steps - what the
                   callback forms run in slices
```

`mayo.js`'s parameter sets expose MAYO's bare trapdoor, `mayo1.trapdoor`,
for schemes built on it, as PoMFRIT is. A building block is shaped by
what the modules above it need, so it may change with them.

---

## Naming conventions

The names follow a small set of rules, so the one you need can usually be
guessed.

| | rule | examples |
|---|---|---|
| **forms** | `name(..., cb)` with the callback last; `name_sync(...)` returns the result; `name_create(...)` makes a context | `sha256`, `sha256_sync`, `sha256_create` |
| **parameter sets** | an object of operations, each in both forms | `ml_dsa65.sign_sync`, `p256.ecdh`, `hqc1.encaps_sync` |
| **contexts** | a hash: `update(msg)`, `copy()`, `digest()`; a keyed AEAD: `encrypt`, `encrypt_sync`, `decrypt`, `decrypt_sync`, `wipe()`; a keyed block cipher (ECB): the same four methods, each taking whole blocks; each method also as `_into(out, offset, ...)`, writing into the caller's array and returning the length; a keyed MAC: as a hash, and `copy()` per message; a signer: the module's signing operations with the key taken out of their arguments, each in both forms, and `wipe()`, after which it throws; a verifier: the module's verifying operations with the key taken out of their arguments, each in both forms; a key agreement: the operation under its own name, its public key as `pk` (`ek` for ML-KEM), and `wipe()`, after which it throws; a keystream: `update(data)` | `sha3_256_create()`, `aes_gcm_create(key)`, `aes_ecb_create(key)`, `aes_cmac_create(key)`, `ed25519.signer_create(seed)`, `p256.signer_create(sk)`, `rsa.signer_create(key)`, `p256.verifier_create(pk)`, `x25519_create()`, `p256.ecdh_create(sk)`, `ml_kem768.decaps_create()`, `chacha20_create(key, nonce)` |
| **cipher modes** | `<cipher>_<mode>_encrypt` / `_decrypt`; a keystream mode is one call both ways | `aes_gcm_encrypt`, `aria_cbc_decrypt`, `aes_ctr`, `camellia_kw_wrap` |
| **MACs** | the tag, and `_verify` that compares it in constant time | `hmac`, `hmac_verify`, `aes_cmac_verify`, `sm4_gmac_verify` |
| **keys** | on a curve or a post-quantum parameter set, `keygen(seed?)` returns `{ sk, pk }` - ML-KEM `{ ek, dk }`; without a seed, a random key | `ed25519.keygen`, `p256.keygen`, `ml_kem768.keygen` |
| **deterministic variants** | `_derand` takes the randomness as bytes | `xwing.encaps_derand`, `hqc1.keygen_derand` |
| **ECDSA: hash, or message** | `sign` takes a hash; `sign_message` takes the message and the hash function | `p256.sign(hash, sk)`, `p256.sign_message(sha256, msg, sk)` |
| **proofs** | `prove_<x>`, `verify_<x>`, `encode_<x>`, `decode_<x>` | `prove_affg`, `verify_log`, `encode_zero` |
| **results** | a verify returns a boolean; a decrypt that fails authentication returns `null` | `ed25519.verify`, `aes_gcm_decrypt` |
| **constants** | upper case | `PARAMS`, `CURVE`, `GROUPS`, `SIZES` |

A scheme whose keys need parameters takes them first, and the randomness
after them: `rsa.keygen(bits, rng, e)` returns
`{ n, e, d, p, q, dp, dq, qinv, bits, size }`; `paillier.keygen(bits, rng)`,
`dh.keygen(group_name, rng)`.

---

## Design

### Three forms of every operation

Each operation is defined once, in the engine layer
(`src/engines/select.js`), and published three ways. `name(..., cb)` calls
`cb(err, result)` on a later turn of the event loop - never before the
function returns, whichever engine answered, so the code after the call
always runs first. `name_sync(...)` returns the result. `name_create(...)`,
where it fits, is a context fed in pieces: a hash, a keystream, or an AEAD
keyed once for many messages.

### Native where it measured faster

A native call pays a fixed price before its first byte: about 1 µs for a
hash and 3 to 6 µs for a cipher in node:crypto, 8 to 25 µs for any
WebCrypto call. On a short input the JavaScript is done sooner. So an
operation runs natively only from the size at which it measured faster,
and stayed faster - the sizes are in
[Performance](#native-or-javascript).

An engine entry can also refuse arguments it would handle differently.
node:crypto's BLAKE2 has no key and a fixed length, so a keyed BLAKE2 runs
in JavaScript. RFC 8032 allows two verification equations, and OpenSSL
answers crafted signatures by a rule of its own, neither of this library's
two - the cofactored default and `'strict'`, libsodium's rule - so Ed25519
verification goes to OpenSSL only where OpenSSL's answer is the library's:
a non-canonical key or R, or an S not below L, is refused before it; in
`'strict'`, so is a small-order key or R; in the default mode a yes from
OpenSSL stands, and a no is checked again in JavaScript. An honest
signature verifies at OpenSSL's speed - about 0.13 ms against 1.1 ms -
and the verdict is the same on both engines, checked on ed25519-speccheck,
Wycheproof and signatures built around every small-order point. Ed448
verification stays in JavaScript.

Key generation goes native only with its randomness left to the platform -
X25519, X448, the NIST curves and ML-KEM, whose expanded decapsulation key
is built from OpenSSL's seed without the matrix A, the same bytes as
`keygen(seed)`; with a seed, it is the pure code. node:crypto then imports a
raw secret on every call, at about the cost of the operation, so a
key-agreement context - `x25519_create()`, `p256.ecdh_create()`,
`ml_kem768.decaps_create()` - imports it once, checks an ML-KEM key once,
and zeroes its copy on `wipe()`. A handshake's share of it, on Node 26.13:

| | pure JavaScript | native | native, with the context |
|---|---|---|---|
| X25519: keygen, then one agreement | 1.8 ms | 0.16 ms | 0.11 ms |
| P-256: keygen, then one ECDH | 2.0 ms | 0.22 ms | 0.19 ms |
| ML-KEM-768: keygen, then decaps | 0.88 ms | 0.52 ms | 0.22 ms |
| ML-KEM-768: encaps | 0.39 ms | 0.09 ms | - |

A one-shot signature pays the same import, and an RSA key also pays
OpenSSL's setup on its first use, about 0.45 ms. A signer context -
`p256.signer_create(sk)`, `rsa.signer_create(key)`,
`ml_dsa65.signer_create(sk)`, `ed25519.signer_create(seed)` - imports the
key once, and from then on signs at node:crypto's speed with the key held.
The hash, the salt and the ML-DSA context are arguments of each signature,
so one signer serves every scheme a protocol negotiates. It signs natively
by the rule above: with the randomness left to the platform, or where the
signature is deterministic and the same (PKCS#1 v1.5, EdDSA); with a value
of yours, in the pure code, the same bytes. RSA is the pure encoding and
OpenSSL's raw private operation, so PSS takes any salt length and MGF1
hash on both engines. Per signature of a 100-byte message, on Node 26.13:

| | node:crypto, key held | signer | one-shot | pure JavaScript signer |
|---|---|---|---|---|
| ECDSA P-256 | 0.03 ms | 0.04 ms | 0.14 ms | 0.57 ms |
| ECDSA P-384 | 0.74 ms | 0.73 ms | 1.28 ms | 1.25 ms |
| ECDSA P-521 | 1.72 ms | 1.72 ms | 2.27 ms | 2.14 ms |
| RSA-2048 PSS | 0.34 ms | 0.34 ms | 0.71 ms | 4.1 ms |
| RSA-2048 PKCS#1 v1.5 | 0.33 ms | 0.33 ms | 0.66 ms | 4.2 ms |
| Ed25519 | 0.04 ms | 0.04 ms | 0.09 ms | 0.27 ms |
| ML-DSA-65 | 0.76 ms | 0.74 ms | 1.01 ms | 5.3 ms |

In a one-shot call, of the ECDSA curves only P-256 signs natively: with
the key imported each time, OpenSSL measured slower than this library's
JavaScript on P-384, P-521 and Brainpool, and no faster on secp256k1.

Verifying is the same story for a key that verifies more than once - a
certificate authority's, a peer's across sessions. A one-shot verification
imports the public key and pays OpenSSL's first use of it; a verifier
context - `p256.verifier_create(public_key)`, `rsa.verifier_create({ n, e })`,
`ed25519.verifier_create(public_key)` - imports it once. Its message forms
are native by the one-shots' rule; the digest forms, which node:crypto
cannot take, run in the pure code over the key decoded once. The hash, the
salt and the MGF1 hash are arguments of each verification. Per
verification of a 100-byte message, on Node 26.13:

| | node:crypto, key held | verifier | one-shot | pure JavaScript verifier |
|---|---|---|---|---|
| ECDSA P-256 | 0.082 ms | 0.085 ms | 0.11 ms | 1.54 ms |
| ECDSA P-384 | 0.63 ms | 0.64 ms | 0.66 ms | 3.6 ms |
| RSA-2048 PSS | 0.025 ms | 0.024 ms | 0.044 ms | 0.096 ms |
| RSA-2048 PKCS#1 v1.5 | 0.023 ms | 0.024 ms | 0.040 ms | 0.094 ms |

### Long work in slices

PBKDF2, scrypt, Argon2, bcrypt, yescrypt, RSA, Paillier and ring-Pedersen
key generation, CMP material and Bulletproofs are written as tasks: a step
does a bounded piece of work. The callback form runs steps until 8 ms have
passed, gives the event loop back, and continues on the next turn - so
timers, I/O and rendering keep running. The `_sync` form runs the same
steps without stopping, so the two cannot disagree. Where node:crypto has
the operation, its callback form runs on libuv's thread pool instead.

### Text is UTF-8; keys are bytes

A value a person may write as text - a message, associated data, a
password, a salt, an info, label, context or domain string, a key of any
length (HMAC, KMAC, keyed BLAKE2) - may be a string, and is taken as its
UTF-8 bytes. A value of fixed size - a cipher key, a nonce, a seed, a
secret or public key, a signature, a ciphertext - must be bytes. A hex or
base64 key passed as a string would be read as its characters, so it is
refused with a `TypeError` that names the parameter, before any work.

The exceptions follow their standards: the NTLM hash takes the password as
UTF-16LE, the PKCS#12 KDF a string password as UTF-16BE, and an SM2
identity is text. A bcrypt salt is bytes only.

### Randomness

Every randomness parameter - an `rng` function `n => Uint8Array`, or random
bytes such as `rnd`, `aux` or a seed - follows one rule:

```
left out, or null    fresh randomness from crypto.getRandomValues, which
                     throws where it is missing - never Math.random
a value of yours     used exactly as given: the same bytes, the same output
```

Only randomness left to the platform may run natively; a caller's own
value keeps the call in JavaScript, which is what makes the result exact.
A parameter that is not last takes `null`:
`rsa.keygen_sync(2048, null, 65537n)`.

A signature's deterministic variant is a value passed where its randomness
goes: ML-DSA's `rnd` of 32 zero bytes, SLH-DSA's `pk_seed` (the secret
key's bytes 2n to 3n), BIP-340 Schnorr's `aux` of 32 zero bytes. ECDSA's
`extra` is RFC 6979 section 3.6's additional data:

| `extra` | the signature |
|---|---|
| left out or `null` | hedged: 32 fresh bytes, and the nonce still depends on the key and the message |
| bytes | deterministic, given those bytes |
| `new Uint8Array(0)` | classic RFC 6979, the signature of its test vectors |

On Node, P-256 with `extra` left out signs in OpenSSL, which draws its own
nonce. A KEM with a `_derand` function takes its randomness there:
`xwing.encaps_derand(pk, rnd)`.

### The pure code alone

The algorithm files (`src/<module>.js`) never import the engine layer, and
use no platform API but `crypto.getRandomValues`: they are plain
synchronous JavaScript, and the engines are laid over them.
`cryptographic-primitives/pure/<module>.js` is that code, for a caller who
wants one implementation on every platform without `set_engine`.

---

## How it is built

**Every algorithm is checked against something outside itself** - the
standard's vectors, the submitters' KATs, OpenSSL through node:crypto, or
another implementation such as libsodium, gmssl, libxcrypt, circomlib or
chiavdf. The last column of the [module reference](#module-reference)
names it - and, for a construction defined by what it must satisfy, the
properties it is checked by.

**Round trips are tested both ways.** Every reversible operation is checked
in both directions. An encryption can match every published vector while
its decryption is wrong, and only a round trip shows it.

**Shared mechanisms live in `src/commons/`, and nothing else does.** The rule
is the audience, not the number of callers: if a user would import it, it
goes in `src/`. The [building blocks](#building-blocks) are listed above.

**Constants are derived, not transcribed, wherever that is possible.** AES's
S-box is recomputed as x^254 in the field. FFDHE's primes come from `e`.
Poseidon's round constants come from the Grain LFSR the paper specifies.
MiMC's come from iterated Keccak. Each derivation is checked against the
published values. Where something *is* transcribed - Poseidon's MDS
parameters - the file says so and explains what was verified instead.

**Timing behaviour is stated, never assumed.** A function that leaks
through timing says so in its name (`inv_vartime`, `sqrt_vartime`,
`to_affine_public`) or in a note at the top of its file explaining why
that is acceptable there. Comparisons on secrets go through
`commons/ct.js`.

---

## Performance

### Against other JavaScript libraries

Measured against `@noble`, the fastest pure-JavaScript library, with this
library in pure JavaScript - what `pure/` and `set_engine('js')` run.
Ratios, not absolute times: the absolute numbers depend on the machine,
the ratios far less.

| | vs noble |
|---|---|
| BLAKE3 | **2.2× faster** |
| BLAKE2s | **2.8× faster** |
| secp256k1 k·P, constant time | **1.6× faster** |
| ristretto255 k·G | **1.45× faster** |
| secp256k1 / P-256 k·G | **1.2× faster** |
| sr25519 sign / verify (vs @scure/sr25519) | **1.3× / 1.45× faster** |
| BIP-340 sign / verify | **1.3× / 1.2× faster** |
| ECDSA verify, secp256k1 | **1.2× faster** |
| Ed25519 verify | **1.1× faster** |
| Ed25519, Ed448 sign | ~equal |
| P-256 verify | **1.1× faster** |
| X25519 | ~equal |
| SHA-256, SHA-512 | 1.1-1.2× slower |
| AES-GCM | 1.8× slower |
| ChaCha20-Poly1305 | about 3× slower |

The curve code gets there with a fixed-base comb for key generation and
signing, wNAF with Shamir's trick for verification, and the GLV
endomorphism on secp256k1:

- **signed digits** (`commons/fixed_window.js`): a window's table holds
  0..2^(w−1) multiples and the sign is a constant-time negation, so every
  table scan reads half the entries;
- **a point-level select** on every curve, instead of the generic one;
- **the constant-time k·P is a signed fixed window**, not the Montgomery
  ladder: the same doublings, one addition per four bits instead of one
  per bit;
- **cached base tables** on Edwards curves: affine, T·d precomputed - two
  multiplications fewer per addition, three coordinates to scan;
- **the blinded inverse** for points from secrets (`inv_blinded`):
  1/a = r·1/(a·r), the inner inverse by fast Euclid on a value uniform and
  independent of a - constant time where it matters, a tenth of Fermat's
  cost;
- **one wNAF engine for verification** (`wnaf_sum`): wNAF instead of fixed
  windows (about half the additions), the generator's table kept at w = 8
  in cached form, doublings without T where no addition follows, and on
  secp256k1 the endomorphism on projective points, with no inversions.
  Variable time, as verification is: every scalar in it is public.

**Batch verification** - Ed25519, Ed448, BIP-340, and every prime-order
group through `commons/batch.js`: sr25519's `verify_batch`, `schnorr`'s
`verify_batch`, and FROST signatures of every suite through `frost_pure`'s
`verify_signature_batch` - is one multi-scalar multiplication over the
whole batch. Against verifying each signature on the same machine (these
numbers move by ±15% between runs):

| signatures | 1 | 8 | 64 | 256 | 1024 |
|---|---|---|---|---|---|
| Ed25519 | ~equal (checked one by one) | 1.1-1.2× | 1.5-1.8× | 1.8-1.9× | 2.3× |
| Ed448 | ~equal (one by one) | 1.1× | 1.65× | 1.9× | 1.8× |
| BIP-340 | ~equal (one by one) | ~equal (one by one) | 1.5× | 2.1× | 2.1× |
| sr25519 | ~equal (one by one) | 1.05× | 1.75× | 2.1× | 2.0× |
| Schnorr (`schnorr`), P-256 | ~equal (one by one) | 1.5× | 2.6× | 3.5× | 3.3× |
| Schnorr (`schnorr`), ristretto255 | ~equal (one by one) | 1.1× | 1.5× | 2.1× | 2.1× |

Below a break-even size a batch is checked one by one - 8 signatures on
Ed25519 and Ed448, 16 on BIP-340. On BIP-340 the batch splits its
full-width terms with secp256k1's endomorphism before the multiplication,
as the single verify does (`commons/glv.js`, `glv_msm_terms`): about 1.25×
on the multiplication, 1.05-1.15× on the whole batch. What is left at 1024
is mostly each signature's own work - decoding its points (a square root
each) and its hash - which a batch cannot share; signatures under one key
share its decoding and its term.

**Constant time is kept, and tested.** `window_mul` and `fixed_base`
perform the same sequence - additions, doublings, scans, negations -
whatever the scalar, and a test counts them. Where noble is still ahead
(Ed25519 and Ed448 signing, within 10%), it is that choice: every secret
table lookup here scans the whole table, where noble indexes it.

SHA-512 accumulates its carries in a double rather than detecting them with
unsigned comparisons - the sum of five 32-bit values stays inside the 2^53
a double represents exactly - which doubles its speed.

**AES is deliberately not the fastest thing here.** GHASH multiplies bit by
bit in constant time rather than through tables indexed by the secret. The
T-tables used for the cipher itself widen the cache-timing exposure from
two bits to four per measurement, a trade `aes.js` documents - and neither
choice makes AES safe on shared hardware. **On shared hardware, use
ChaCha20-Poly1305. It has no tables at all.** Where node:crypto or
WebCrypto runs AES, it uses the processor's AES instructions where the
processor has them.

### Native or JavaScript

Nothing about the platform is assumed. node:crypto is OpenSSL in Node and
BoringSSL in Bun, WebCrypto differs between browsers, and each lacks some
algorithms or options the others have. So no operation runs natively until
it has shown, on this platform, that it gives the pure code's answer: each
native entry carries a check - fixed inputs whose result must be the pure
function's, or, for a key pair or a hedged signature, one run that the pure
code checks - run on the entry's first use and remembered for the life of
the process. An entry that fails its check runs in JavaScript, with the
same results. On Bun 1.4, ChaCha20, ChaCha20-Poly1305, Ed448, X448 and
ML-DSA fail theirs and run in JavaScript, and everything else runs
natively; in a browser, a WebCrypto entry runs in JavaScript until its
check has answered. A check costs from microseconds to some tens of
milliseconds, once - the most where the pure reference is slow: P-521,
X448, ML-DSA.

Each operation runs natively from the size at which that measured faster,
and stayed faster:

```
                          node:crypto      WebCrypto (callback form only)
sha256                    128 bytes        4,096 bytes
sha1                      256              4,096
sha224                    192              -
sha384, sha512            any size         256, 1,024
md5                       768              -
ripemd160, sm3            128              -
blake2s                   96               -
shake128, shake256        192              -
aes_ctr                   96               4,096
aes_gcm_encrypt/decrypt   64               1,024
aes_cbc_encrypt/decrypt   -                1,024
chacha20                  1,024            -
chacha20poly1305_encrypt  2,048            -
chacha20poly1305_decrypt  512              -
aes_gcm_create()          128 per message  -
aes_ecb_create()          128 per message  -
chacha20poly1305_create() 768 per message  -
```

A dash is an operation that engine does not have, so it always runs in
JavaScript there. Every other operation node:crypto has measured faster at
every size - the rest of SHA-2 and SHA-3, BLAKE2b, HMAC, HKDF, the
password hashes, and the signatures and key agreements it runs.

The node:crypto sizes come from `node bench/routing.js` (Node 26.13 and
22, x86-64 with AES-NI, one quiet core; each time the median of batches
long enough to carry their share of the garbage collector's work - the
native objects node:crypto makes per call, and the pure code's
allocations); the WebCrypto sizes from `bench/routing.html` in
headless Chrome 157. Rerun them for another machine - near a threshold the
two engines are close to even, so it need not be exact.

---

## Errors

```javascript
import { aes_gcm_encrypt_sync } from 'cryptographic-primitives/aes.js';

try {
  aes_gcm_encrypt_sync('00112233445566778899aabbccddeeff', nonce, 'x');
} catch (e) {
  e.name     // 'TypeError'
  e.message  // 'aes_gcm_encrypt_sync: key must be a Uint8Array, not a string
             //  (strings are taken as UTF-8 only for text such as a message
             //  or a password)'
}
```

A `TypeError` means the call itself was wrong. A string where bytes are
required, and a callback form called without a callback, are thrown at
once, in both forms, before any work.

What the computation refuses - a salt too short, a point not on the curve,
an `rng` that is not a function - has a message that starts with the name
of the module or operation. The `_sync` form throws it; the callback form
passes it as `err`.

Two outcomes are not errors. A decryption that fails authentication
returns `null`, and a signature or proof that does not verify returns
`false`.

---

## Testing

The tests are in `test/`, run by Node's own runner:

```bash
npm test                  # node --test "test/*.test.mjs"
npm run test:slow         # the same, with every KAT record of the slow sets
node bench/routing.js     # re-measure where native becomes faster
```

Beside the tests of each family (below), these check the package as a
whole:

```
routing.test.mjs     every native entry carries its check, each passes on
                     Node but where node:crypto lacks the algorithm, and a
                     failing one keeps its entry in JavaScript; every
                     operation routed by size goes native exactly from
                     its threshold and gives the pure bytes around it; the
                     keyed contexts open each other's output; native EdDSA,
                     X25519, ECDH, RSA, Paillier and the KDFs give results
                     the pure code accepts; the signer contexts (ECDSA,
                     RSA, ML-DSA, SLH-DSA, EdDSA) give the pure bytes and
                     errors, and nothing after wipe(); the verifier contexts
                     (ECDSA, RSA) the one-shot verdict; one verdict on both
                     engines - ECDSA over Wycheproof, Ed25519 in both
                     modes over ed25519-speccheck, Wycheproof and
                     signatures built around every small-order point; and
                     set_engine('js') keeps every call in JavaScript
randomness.test.mjs  a randomness argument left out, null, or given, across
                     the curves, post-quantum schemes and protocols; native
                     only with the randomness left to the platform; the
                     deterministic variants - RFC 6979, BIP-340, ML-DSA,
                     SLH-DSA - are values in its place
stream.test.mjs      the stream formats round-trip and refuse reordered,
                     repeated, dropped, cut and tampered pieces; the
                     secretstream opens what libsodium 1.0.20 sealed, and
                     seals the bytes libsodium opened
ct_random.test.mjs   ct.equal against timingSafeEqual, false on unequal
                     lengths, timed against an early-exit comparison;
                     random_bytes past getRandomValues' 65,536-byte limit
examples.test.mjs    every example runs and prints what it says
readme.test.mjs      this README names every module, its imports and main
                     exports exist, and its examples are the files
structure.test.mjs   the layout: every module public in its three forms,
                     the pure code never reaching the engines, node:crypto
                     only in engines/node.js, no import cycles
```

Each algorithm is also checked against something outside this library -
the standard's own vectors, OpenSSL through node:crypto, or an independent
implementation - and every bug fixed has a test built around the failure.
By family:

| family | covers | checked against |
|---|---|---|
| ciphers | AES and all its modes, ChaCha and Salsa, ARIA, Camellia, SEED, SM4, GOST, DES, Blowfish, RC2, RC4, Ascon, AEGIS, FF1 | FIPS 197, SP 800-38A-G, RFC 3610/4493/3394/5649/7253/8452/5297/8439/5794/3713/4269/8998/7801/8891/2268/6229, GOST R 34.13, NIST's Ascon KATs, node:crypto |
| hashes and KDFs | SHA-1/2/3, SHAKE, SP 800-185, K12, BLAKE2/3, MD4/5, RIPEMD, SM3, Whirlpool, Streebog, HMAC, HKDF, PBKDF2, scrypt, Argon2, bcrypt, yescrypt, the KDFs, DRBGs, checksums, Merkle | FIPS 180/202, RFCs, OpenSSL's `openssl kdf`, libxcrypt, an SP 800-90A reference, node:crypto |
| curves | ECDSA, EdDSA and its batch verification, X25519/X448, BIP-340, MuSig2 (BIP-327 and the other suites), sr25519 and Merlin, hash to curve, ristretto255 and decaf448, FROST, OPRF, ECVRF, BLS, BBS, KZG, SM2, Jubjub, Pallas, RedDSA and ZIP 312, key blinding, the group interface | RFC 6979/8032/7748/9380/9496/9591/9497/9381, BIP-340/327, Wycheproof, ed25519-speccheck ("Taming the many EdDSAs"), the merlin crate, schnorrkel and Substrate (`//Alice`), @scure/sr25519, Ethereum's BLS tests, the BBS draft, the key-blinding draft, gmsm, the Zcash Foundation's jubjub, pasta_curves, reddsa and frost-rerandomized, node:crypto |
| PAKEs | CPace, OPAQUE, OQUAKE, CPaceOQUAKE, OQUAKE+, CPaceOQUAKE+, ML-BUA-sKEM, Kemeleon | draft-irtf-cfrg-cpace-21 (every suite, the low-order and invalid inputs), RFC 9807 (real and fake vectors), draft-vos-cfrg-pqpake-03 appendix E |
| post-quantum and hybrid | ML-KEM, ML-DSA, SLH-DSA, LMS/HSS, XMSS/XMSS^MT, Falcon, UOV, MAYO, SNOVA, QR-UOV, MQOM, SDitH, FAEST, SQIsign, FrodoKEM, HQC, Classic McEliece, the hybrid KEMs and TLS groups, HPKE, composite ML-DSA; threshold ML-DSA, PoMFRIT, the AES and DualRing-PRF ring signatures and LB-VRF by their properties | NIST ACVP, Wycheproof, CCTV, Go's accumulated tests, RFC 8554/9180/10073, the draft-ietf-hpke-pq and concrete-hybrid-kems vectors, pyca/cryptography, the FrodoKEM, HQC and Classic McEliece teams' KATs, Falcon's (key generation and signing too), liboqs's XMSS KATs, the round-3 KATs of UOV, MAYO, SNOVA, QR-UOV, MQOM, SDitH, FAEST and SQIsign, @noble/post-quantum |
| number theory and RSA | primality, modular arithmetic, samplers, Shamir, Paillier, ring-Pedersen, RSA, RSA-FDH-VRF | known pseudoprimes, RFC 3526/7919, Wycheproof (RSA PSS with every MGF1 hash, PKCS#1 v1.5 signing and verification, on both engines, one-shot and through verifier_create), OpenSSL (OAEP, PSS, PKCS#1), RFC 9381 appendix A (all nine RSA-FDH-VRF examples) |
| zero-knowledge | every zero-knowledge proof, Fiat-Shamir framing, accumulators, VDFs, Bulletproofs | honest proofs and each field tampered, transcript binding; chiavdf for the class-group VDF |
| OT, OPRFs, compat | OT (elliptic-curve and ML-KEM), OT extension, rVOLE; the Pool, Legendre and Leap OPRFs over them (by their properties, cheating servers included); the compatibility shims | libsodium, pyca/bcrypt, argon2-cffi, CryptoJS/OpenSSL |

---

## Caveats

**Stateful signatures: store the key before the signature leaves.**
LMS, HSS, XMSS and XMSS^MT sign with one-time keys. `sign` returns the
advanced key beside the signature and leaves the one passed in as it was:
persist the new one before the signature goes anywhere. A key restored from
an older copy - a backup, a VM snapshot, a second machine - signs with a
one-time key it already used, and two signatures from one one-time key let
anyone forge.

[`examples/stateful-signatures.mjs`](examples/stateful-signatures.mjs)

```javascript
// LMS and XMSS keys are stateful: each signature spends a one-time key, and
// sign returns the advanced key beside the signature. Store that key before
// the signature leaves - a key restored from an older copy signs with a
// one-time key it already used, and two signatures from one one-time key
// let anyone forge.
import { lms_sha256_h5_w8 } from 'cryptographic-primitives/lms.js';

let { pk, sk } = lms_sha256_h5_w8.keygen_sync();
console.log(lms_sha256_h5_w8.MAX_SIGNATURES);                 // -> 32

const { sig, sk: next, remaining } = lms_sha256_h5_w8.sign_sync(sk, 'release 1.4.2');
sk = next;                                                    // persist sk here, then send sig
console.log(remaining);                                       // -> 31
console.log(lms_sha256_h5_w8.verify_sync(pk, 'release 1.4.2', sig));  // -> true
```

**Constant time in JavaScript is best effort.** The code does not branch on
secrets or index tables by them where that matters, and compares secrets
through `commons/ct.js`. But the JavaScript engine compiles and optimizes
it, and can bring back a data-dependent timing that no source code can
rule out. Where an operation cannot be made constant time, its file says
so.

**Verifying a signature on a secret message** - a private token whose
verification time someone can measure - is the one case where a verifier's
timing matters: it follows the message's hash, and so lets guesses of the
message be tested. Verification here is variable time, as everywhere; for
that case, verify with the group's constant-time multiplication.

**AES in software leaks through the cache** on hardware shared with an
attacker, whatever the implementation does - see
[Performance](#against-other-javascript-libraries). ChaCha20-Poly1305 does
not.

---

## Contributing

The source follows a few rules:

- every use of `node:crypto` is in `src/engines/node.js`, and every use of
  `crypto.subtle` in `src/engines/web.js`
- the algorithm files never import the engine layer
- module bodies are ES5 (`var`, `function`) inside ES modules
- an operation routed by size has a call in `bench/calls.js`, which
  `bench/routing.js` times and `test/routing.test.mjs` runs through both
  engines

---

## License

Apache-2.0
