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
