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
