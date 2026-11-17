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
