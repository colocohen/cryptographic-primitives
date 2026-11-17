/**
 * The Brainpool curves  -  RFC 5639
 *
 * Published in 2005 by a working group led by the German federal information
 * security office, as an answer to the one complaint about the NIST curves
 * that has never been resolved: nobody can explain where their parameters
 * came from.
 *
 * WHAT "VERIFIABLY PSEUDO-RANDOM" MEANS HERE, and why it is the whole point.
 * Every Brainpool coefficient is derived by hashing a fixed, published seed
 * string - the digits of pi and of e - through a specified procedure. Anyone
 * can rerun that procedure and confirm the numbers were not chosen. The NIST
 * curves are also seeded, but their seeds are arbitrary strings that have
 * never been accounted for, which is the objection secp256k1 was designed to
 * sidestep in a different way.
 *
 * No weakness has ever been demonstrated in either family. The difference is
 * about what can be verified, not what is known to be broken.
 *
 * They also differ technically: a is a full-size random-looking value rather
 * than -3, so the doubling shortcut the NIST curves rely on does not apply.
 * The complete formulas in commons/weierstrass.js take a as an argument and
 * never used that shortcut anyway, so nothing here changes.
 *
 * Where they turn up: German and European government PKI, ICAO machine-
 * readable travel documents, and TLS profiles that specify them by name.
 *
 * THE PARAMETERS BELOW WERE EXTRACTED PROGRAMMATICALLY FROM RFC 5639, and
 * that still went wrong once. The RFC lists each r1 curve immediately
 * followed by its TWISTED variant - brainpoolP256t1 and friends - which
 * repeat the labels A, B, x and y with different values. The first extraction
 * ran past the boundary and picked up the twisted coefficients, producing
 * curves where the generator was a perfectly valid point of the right order
 * on a perfectly valid curve, just not the standardised one.
 *
 * The tell was that a came out equal to p-3: the twisted representation is
 * defined to have a = -3, and the r1 curves emphatically do not. The
 * arithmetic checks all passed - G was on the curve, n*G was the identity -
 * because those hold for the wrong curve too. Only comparing a public key
 * against another implementation caught it.
 */

import { ecdsa } from './commons/ecdsa.js';
import { ecdsa_group } from './commons/group.js';
import { sha256, sha384, sha512 } from './sha2.js';

export var BP256R1_CURVE = {
    name: 'brainpoolP256r1',
    oid: '1.3.36.3.3.2.8.1.1.7',      /* the namedCurve OBJECT IDENTIFIER */
    p:  0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377n,
    n:  0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7n,
    a:  0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9n,
    b:  0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6n,
    Gx: 0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262n,
    Gy: 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997n,
    hash: sha256
};

export var BP384R1_CURVE = {
    name: 'brainpoolP384r1',
    oid: '1.3.36.3.3.2.8.1.1.11',      /* the namedCurve OBJECT IDENTIFIER */
    p:  0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53n,
    n:  0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565n,
    a:  0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826n,
    b:  0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11n,
    Gx: 0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1en,
    Gy: 0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315n,
    hash: sha384
};

export var BP512R1_CURVE = {
    name: 'brainpoolP512r1',
    oid: '1.3.36.3.3.2.8.1.1.13',      /* the namedCurve OBJECT IDENTIFIER */
    p:  0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3n,
    n:  0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069n,
    a:  0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94can,
    b:  0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723n,
    Gx: 0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822n,
    Gy: 0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892n,
    hash: sha512
};

var E256 = /* @__PURE__ */ ecdsa(BP256R1_CURVE);
var E384 = /* @__PURE__ */ ecdsa(BP384R1_CURVE);
var E512 = /* @__PURE__ */ ecdsa(BP512R1_CURVE);

/**
 * Same API as secp256k1 and the NIST curves: keygen, is_valid_secret,
 * get_public_key, encode_point, decode_point, sign, verify, recover, ecdh,
 * sig_to_der, sig_to_compact, sig_from_compact - sign hedged unless its
 * `extra` is given, as commons/ecdsa.js explains.
 */
export var brainpoolP256r1 = E256;
export var brainpoolP384r1 = E384;
export var brainpoolP512r1 = E512;

/*
 * The prime-order group interface - see commons/group.js.
 *
 * ⚠ THESE DID NOT EXIST, and the reason was only that nobody had written the
 *   binding: cofactor 1, SEC 1 encodings, the comb table - everything a GROUP
 *   needs was already here. FROST-style protocols, ElGamal and Schnorr can
 *   now run on Brainpool.
 *
 * ⛔ NO hash. RFC 9380 registers no suite for the Brainpool curves, and one
 *   invented here would produce points that agree with nothing; GROUP.hash
 *   is absent and a caller needing it fails at the call site.
 */
export var BP256R1_GROUP = /* @__PURE__ */ ecdsa_group('brainpoolP256r1', E256);
export var BP384R1_GROUP = /* @__PURE__ */ ecdsa_group('brainpoolP384r1', E384);
export var BP512R1_GROUP = /* @__PURE__ */ ecdsa_group('brainpoolP512r1', E512);
