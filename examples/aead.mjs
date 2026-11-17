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
