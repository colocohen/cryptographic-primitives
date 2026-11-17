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
