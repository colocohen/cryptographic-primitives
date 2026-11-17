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
