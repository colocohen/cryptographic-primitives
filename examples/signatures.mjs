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
