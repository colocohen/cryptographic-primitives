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
