/**
 * X-Wing - the general-purpose hybrid post-quantum KEM
 * draft-connolly-cfrg-xwing-kem (CFRG; -11, September 2026)
 *
 * ML-KEM-768 and X25519 side by side, with both shared secrets and the
 * X25519 ciphertext and public key hashed together:
 *
 *     ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || XWingLabel )
 *
 * Breaking it needs breaking BOTH: a quantum computer gets past X25519 and
 * still faces Module-LWE; a flaw in the young lattice standard still leaves
 * X25519. It is the same idea as the X25519MLKEM768 key exchange TLS uses,
 * packaged as a KEM that any protocol can call.
 *
 * WHY THE ML-KEM CIPHERTEXT IS NOT IN THE HASH. A generic combiner would
 * hash everything. X-Wing leaves ct_M out because ML-KEM's shared secret is
 * already bound to its ciphertext (the Fujisaki-Okamoto transform hashes it),
 * and the draft's proof (Barbosa et al., "X-Wing: The Hybrid KEM You've Been
 * Looking For", 2024) uses exactly that. It is safe for ML-KEM specifically,
 * not for an arbitrary KEM substituted in its place.
 *
 * THE SECRET KEY IS A 32-BYTE SEED, expanded with SHAKE256 into the ML-KEM
 * (d, z) seeds and the X25519 scalar. The expanded form must never be sent
 * anywhere; it is recomputed on each decapsulation (cheap next to the
 * decapsulation itself).
 *
 * IT IS ONE OF THREE: hybrid_kem.js builds X-Wing (mlkem768_x25519),
 * MLKEM768-P256 and MLKEM1024-P384 from one framework (commons/hybrid_kem.js),
 * and this file is X-Wing's own names for the first.
 *
 * A PRIMITIVE, NOT AN ENCRYPTION SCHEME. It moves a 32-byte secret; to
 * encrypt data, use it as the KEM inside HPKE (hpke.js, KEM id 0x647a).
 *
 * Sizes: pk 1216, sk 32, ct 1120, ss 32 bytes.
 */

import { mlkem768_x25519 as K } from './hybrid_kem.js';

export var PK_BYTES = K.PK_BYTES;      /* 1216 */
export var SK_BYTES = K.SK_BYTES;      /* 32 */
export var CT_BYTES = K.CT_BYTES;      /* 1120 */
export var SS_BYTES = K.SS_BYTES;      /* 32 */

/**
 * The key pair for a 32-byte seed (GenerateKeyPairDerand). The seed IS the
 * secret key.
 * @return {{ sk: Uint8Array, pk: Uint8Array }}
 */
export var keygen_derand = K.keygen_derand;

/** A fresh key pair. @param rng (n) -> Uint8Array */
export var keygen = K.keygen;

/** The public key of a secret key. */
export var public_key = K.public_key;

/**
 * Encapsulate with explicit randomness (EncapsulateDerand): eseed is 64
 * bytes, the ML-KEM randomness then the X25519 ephemeral scalar.
 * ML-KEM's FIPS 203 encapsulation-key check runs inside and throws on a
 * malformed key - the draft's MUST, and HPKE's EncapError.
 * @return {{ ss: Uint8Array, ct: Uint8Array }}
 */
export var encaps_derand = K.encaps_derand;

/**
 * Is `pk` an X-Wing public key that can be encapsulated to - 1216 bytes,
 * whose ML-KEM half passes FIPS 203's encapsulation-key checks? (Any 32
 * bytes are an X25519 key.) For a caller that takes keys from others and
 * wants to refuse a bad one where it arrives, not where it is first used.
 */
export var check_public_key = K.check_public_key;

/** Encapsulate to `pk` with fresh randomness. */
export var encaps = K.encaps;

/**
 * Decapsulate. Like ML-KEM it never reports failure: a bad ciphertext yields
 * a pseudorandom secret (implicit rejection), and the caller learns of it
 * when the derived key does not work.
 * @return {Uint8Array} 32 bytes
 */
export var decaps = K.decaps;
