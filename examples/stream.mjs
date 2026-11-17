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
