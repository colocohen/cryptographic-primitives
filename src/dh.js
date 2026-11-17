/**
 * Finite-field Diffie-Hellman  -  RFC 7919
 *
 * The original Diffie-Hellman from 1976: both sides raise a generator to a
 * secret exponent modulo a large prime, and `g^ab mod p` is the shared
 * secret. Elliptic curves replaced it because they reach the same security
 * with keys an order of magnitude smaller - X25519 is 32 bytes against
 * ffdhe2048's 256 - but it is still specified in TLS and required by some
 * compliance profiles.
 *
 * WHY RFC 7919 EXISTS: LOGJAM. Before it, every server chose its own prime,
 * and the 2015 Logjam work found that most of the internet was sharing a
 * handful of them. The number field sieve's expensive stage depends only on
 * the PRIME, not on the key, so precomputing against one 1024-bit prime -
 * costly but a one-off - breaks every connection that uses it. The paper's
 * conclusion was that a state-level adversary had plausibly done exactly
 * that, which would explain a great deal of passively decrypted VPN traffic.
 *
 * RFC 7919 fixed named groups so both sides know which prime is in use and
 * arbitrary ones cannot be negotiated. Deployment made the smallest group
 * 2048 bits, and TLS 1.3 forbids anything smaller.
 *
 * THE PRIMES ARE DERIVED FROM e, exactly as Brainpool's curves are derived
 * from pi and e, and for the same reason: so that nobody can claim the
 * modulus was chosen to hide something. Each is
 *
 *     p = 2^b - 2^(b-64) + {[2^(b-130) * e] + offset} * 2^64 - 1
 *
 * and all five were RECOMPUTED from that formula and checked against the
 * hexadecimal in the RFC before being written here - two independent sources
 * agreeing, rather than one transcription.
 *
 * EVERY GROUP IS A SAFE PRIME: p = 2q + 1 with q prime. That makes the only
 * subgroups trivial ones, so a small-subgroup attack has nowhere to go, and
 * it is why the validity check below is as short as it is.
 */

import { powmod_ct, powmod, random_below_biased, require_rng } from './commons/primes.js';
import { bytes_to_bigint, bigint_to_bytes } from './commons/bytes.js';

/**
 * The five named groups. `min_x` is the RFC's recommended minimum exponent
 * size in bits for peers that want a short exponent - the security is set by
 * the group, not by the exponent, once the exponent is comfortably above
 * twice the symmetric-equivalent strength.
 */
export var GROUPS = {
    ffdhe2048: {
        bits: 2048,
        code: 256,
        min_x: 225,
        p: 0xffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffffn
    },
    ffdhe3072: {
        bits: 3072,
        code: 257,
        min_x: 275,
        p: 0xffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffffn
    },
    ffdhe4096: {
        bits: 4096,
        code: 258,
        min_x: 325,
        p: 0xffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e655f6affffffffffffffffn
    },
    ffdhe6144: {
        bits: 6144,
        code: 259,
        min_x: 375,
        p: 0xffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e0dd9020bfd64b645036c7a4e677d2c38532a3a23ba4442caf53ea63bb454329b7624c8917bdd64b1c0fd4cb38e8c334c701c3acdad0657fccfec719b1f5c3e4e46041f388147fb4cfdb477a52471f7a9a96910b855322edb6340d8a00ef092350511e30abec1fff9e3a26e7fb29f8c183023c3587e38da0077d9b4763e4e4b94b2bbc194c6651e77caf992eeaac0232a281bf6b3a739c1226116820ae8db5847a67cbef9c9091b462d538cd72b03746ae77f5e62292c311562a846505dc82db854338ae49f5235c95b91178ccf2dd5cacef403ec9d1810c6272b045b3b71f9dc6b80d63fdd4a8e9adb1e6962a69526d43161c1a41d570d7938dad4a40e329cd0e40e65ffffffffffffffffn
    },
    ffdhe8192: {
        bits: 8192,
        code: 260,
        min_x: 400,
        p: 0xffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617ad3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797abc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f619172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035bbc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91caefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e0dd9020bfd64b645036c7a4e677d2c38532a3a23ba4442caf53ea63bb454329b7624c8917bdd64b1c0fd4cb38e8c334c701c3acdad0657fccfec719b1f5c3e4e46041f388147fb4cfdb477a52471f7a9a96910b855322edb6340d8a00ef092350511e30abec1fff9e3a26e7fb29f8c183023c3587e38da0077d9b4763e4e4b94b2bbc194c6651e77caf992eeaac0232a281bf6b3a739c1226116820ae8db5847a67cbef9c9091b462d538cd72b03746ae77f5e62292c311562a846505dc82db854338ae49f5235c95b91178ccf2dd5cacef403ec9d1810c6272b045b3b71f9dc6b80d63fdd4a8e9adb1e6962a69526d43161c1a41d570d7938dad4a40e329ccff46aaa36ad004cf600c8381e425a31d951ae64fdb23fcec9509d43687feb69edd1cc5e0b8cc3bdf64b10ef86b63142a3ab8829555b2f747c932665cb2c0f1cc01bd70229388839d2af05e454504ac78b7582822846c0ba35c35f5c59160cc046fd8251541fc68c9c86b022bb7099876a460e7451a8a93109703fee1c217e6c3826e52c51aa691e0e423cfc99e9e31650c1217b624816cdad9a95f9d5b8019488d9c0a0a1fe3075a577e23183f81d4a3f2fa4571efc8ce0ba8a4fe8b6855dfe72b0a66eded2fbabfbe58a30fafabe1c5d71a87e2f741ef8c1fe86fea6bbfde530677f0d97d11d49f7a8443d0822e506a9f4614e011e2a94838ff88cd68c8bb7c5c6424cffffffffffffffffn
    }
};

/** The generator is 2 for every RFC 7919 group. */
var G = 2n;

function group_of(name) {
    var g = GROUPS[name];
    if (!g) { throw new Error('dh: unknown group ' + name); }
    return g;
}

/**
 * @param  {string}   name  one of the GROUPS keys
 * @param  {function} [rng] (n) -> Uint8Array; omitted or null draws fresh ones from the platform
 * @return {{x: bigint, public: Uint8Array}}
 *
 * The private exponent is drawn from [2, q-1] where q = (p-1)/2. Drawing the
 * full width rather than the RFC's short-exponent minimum costs a little time
 * and removes a parameter that can be got wrong.
 */
export function keygen(name, rng) {
    rng = require_rng('dh.keygen', rng);
    var grp = group_of(name);
    var nbytes = grp.bits / 8;
    var q = (grp.p - 1n) / 2n;
    /*
     * x uniform in [1, q-1], as SP 800-56A rev. 3 section 5.6.1.1.4 ("key
     * pair generation using extra random bits") specifies for safe-prime
     * groups: c from at least len(q) + 64 random bits, x = (c mod (q-1)) + 1.
     * That is primes.random_below_biased(q - 1) + 1, with 128 extra bits.
     *
     * ⚠ IT WAS len(p) BITS mod q, x < 2 redrawn: 1 extra bit rather than 64.
     *   With these primes the excess is concentrated - values below
     *   2^len(p) - 2q, about 2^-63 of the range, came up 3 times to everyone
     *   else's 2 - so the bias was small, but it was not the specified
     *   construction and the range was [2, q-1] rather than [1, q-1].
     */
    var x = random_below_biased(q - 1n, rng) + 1n;
/*
     * ⛔ SECRET EXPONENT - see powmod_ct in commons/primes.js for why the
     *   variable-time powmod leaks it, and what the flat path does and does
     *   not guarantee.
     */
    return { group: name, x: x,
             public: bigint_to_bytes(powmod_ct(G, x, grp.p), nbytes) };
}

/**
 * Validate a peer's public value.
 *
 * REQUIRED, and cheap here. The check is that 1 < y < p-1: because p is a
 * SAFE prime the only elements of small order are 1 and p-1, so excluding
 * them excludes every small subgroup. With an arbitrary prime this check
 * would have to be the far more expensive y^q == 1.
 *
 * @return {boolean}
 */
export function validate_public(name, peer) {
    var grp = group_of(name);
    if (peer.length !== grp.bits / 8) { return false; }
    var y = bytes_to_bigint(peer);
    return y > 1n && y < grp.p - 1n;
}

/**
 * @return {Uint8Array|null} the shared secret, or null if the peer's value is
 *                           invalid. Same length as the modulus, left-padded -
 *                           which matters, because a secret that happens to be
 *                           short must still hash to the same length.
 */
export function compute_secret(key, peer) {
    var grp = group_of(key.group);
    if (!validate_public(key.group, peer)) { return null; }
    var y = bytes_to_bigint(peer);
    /* ⛔ key.x is the long-lived private exponent - see keygen */
    var s = powmod_ct(y, key.x, grp.p);
    /*
     * The raw secret is NOT a key. It is a group element with structure - it
     * is a quadratic residue, and its high bits are not uniform. Every
     * protocol that uses it runs it through a KDF first, and this returns the
     * raw value because the KDF and its context belong to the caller.
     */
    return bigint_to_bytes(s, grp.bits / 8);
}

/** The group's order, q = (p-1)/2. Exposed for exponent bounds and testing. */
export function group_order(name) { return (group_of(name).p - 1n) / 2n; }
