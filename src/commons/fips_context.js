/**
 * The message encodings of FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA), and the
 * signing interfaces built on them.
 *
 * Both standards sign a formatted message M' with an internal algorithm
 * (ML-DSA.Sign_internal, slh_sign_internal), and offer two ways to form it:
 *
 *   pure        M' = 0 ‖ |ctx| ‖ ctx ‖ M                 (FIPS 204 Alg 2/3, 205 Alg 22/24)
 *   pre-hash    M' = 1 ‖ |ctx| ‖ ctx ‖ OID(PH) ‖ PH(M)   (FIPS 204 Alg 4/5, 205 Alg 23/25)
 *
 * The pre-hash form - HashML-DSA, HashSLH-DSA - signs a digest, so a message
 * too large to hold, or one hashed elsewhere (an HSM, a streaming reader),
 * can be signed from its digest alone. The OID binds the hash function, and
 * the leading byte keeps the two forms apart: a pure signature never
 * verifies as a pre-hash one, or the reverse.
 *
 * ONE COPY, BECAUSE TWO DRIFTED. Both standards define the same bytes and both
 * require a context of at most 255 bytes, in signing AND in verification.
 * ml_dsa.js learned that from Wycheproof (a 256-byte context had its length
 * byte truncated to 0x00, so a signature verified under a context it was never
 * made for); slh_dsa.js wrote its own encoding and its verify() kept the bug -
 * a signature over (ctx = empty, msg = ctx' || msg') verified as
 * (ctx', msg') for any 256-byte ctx'.
 */
import { concat } from './bytes.js';
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '../sha2.js';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '../sha3.js';

/**
 * @param {Uint8Array} [ctx]  defaults to empty
 * @param {Uint8Array} msg
 * @return {Uint8Array|null}  null when ctx is longer than 255 bytes: the
 *         signer throws on null, the verifier returns false
 */
export function fips_message(ctx, msg) {
    var c = ctx || new Uint8Array(0);
    if (c.length > 255) { return null; }
    return concat([new Uint8Array([0, c.length]), c, msg]);
}

/*
 * The pre-hash functions FIPS 204 and 205 name, under their NIST (ACVP)
 * names, each with its DER-encoded OID (2.16.840.1.101.3.4.2.x) and digest
 * length. SHAKE128 and SHAKE256 are used at 256 and 512 bits.
 */
function ph(arc, hash, len) {
    return { oid: new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, arc]), hash: hash, len: len };
}
export var PREHASH = {
    'SHA2-256':     ph(0x01, sha256, 32),
    'SHA2-384':     ph(0x02, sha384, 48),
    'SHA2-512':     ph(0x03, sha512, 64),
    'SHA2-224':     ph(0x04, sha224, 28),
    'SHA2-512/224': ph(0x05, sha512_224, 28),
    'SHA2-512/256': ph(0x06, sha512_256, 32),
    'SHA3-224':     ph(0x07, sha3_224, 28),
    'SHA3-256':     ph(0x08, sha3_256, 32),
    'SHA3-384':     ph(0x09, sha3_384, 48),
    'SHA3-512':     ph(0x0a, sha3_512, 64),
    'SHAKE-128':    ph(0x0b, function (m) { return shake128(m, 32); }, 32),
    'SHAKE-256':    ph(0x0c, function (m) { return shake256(m, 64); }, 64)
};

/**
 * M' for the pre-hash interface, from the digest.
 *
 * @param {Uint8Array} [ctx]
 * @param {string} name      a key of PREHASH
 * @param {Uint8Array} digest  PH(M), of that function's length
 * @return {Uint8Array|null}  null for an unknown function, a digest of the
 *         wrong length, or a context over 255 bytes
 */
export function fips_prehash_message(ctx, name, digest) {
    var c = ctx || new Uint8Array(0), f = Object.prototype.hasOwnProperty.call(PREHASH, name) ? PREHASH[name] : null;
    if (!f || !(digest instanceof Uint8Array) || digest.length !== f.len || c.length > 255) { return null; }
    return concat([new Uint8Array([1, c.length]), c, f.oid, digest]);
}

/**
 * The public signing interfaces of a FIPS 204/205 scheme, from its internal
 * pair: pure, pre-hash from the message, and pre-hash from a digest.
 *
 *   sign(sk, msg, rnd, ctx)                       verify(pk, msg, sig, ctx)
 *   hash_sign(sk, msg, ph, rnd, ctx)              hash_verify(pk, msg, sig, ph, ctx)
 *   hash_sign_digest(sk, digest, ph, rnd, ctx)    hash_verify_digest(pk, digest, sig, ph, ctx)
 *
 * and signer_create(sk): the three signing forms with sk taken out of
 * their arguments, and wipe(), after which they throw.
 *
 * The signers throw on a bad context, function name or digest; the
 * verifiers return false.
 *
 * @param {string} who
 * @param {function(sk, mp, rnd)} sign_internal
 * @param {function(pk, mp, sig): boolean} verify_internal
 * @param {function(sk): {sign: function(mp, rnd), wipe: function()}} [signing_state]
 *        what a signer holds: by default a copy of sk, signed with by
 *        sign_internal; a scheme with work to do once per key (ML-DSA's A)
 *        gives its own
 */
export function fips_interfaces(who, sign_internal, verify_internal, signing_state) {
    function known(name) { return Object.prototype.hasOwnProperty.call(PREHASH, name); }
    function digest_of(name, msg) { return known(name) ? PREHASH[name].hash(msg) : null; }
    /* the signer says which input was wrong; sign_mp(mp, rnd) signs M' */
    function sign_checked(sign_mp, ctx, rnd, name, digest, msg) {
        if (ctx && ctx.length > 255) { throw new Error(who + ': context too long'); }
        if (name === undefined) { return sign_mp(fips_message(ctx, msg), rnd); }
        if (!known(name)) { throw new Error(who + ': unknown pre-hash function ' + name); }
        if (!(digest instanceof Uint8Array) || digest.length !== PREHASH[name].len) {
            throw new Error(who + ': a ' + name + ' digest is ' + PREHASH[name].len + ' bytes');
        }
        return sign_mp(fips_prehash_message(ctx, name, digest), rnd);
    }
    function with_sk(sk) { return function (mp, rnd) { return sign_internal(sk, mp, rnd); }; }
    function verified(pk, mp, sig) { return mp ? verify_internal(pk, mp, sig) : false; }
    var state_of = signing_state || function (sk) {
        if (!(sk instanceof Uint8Array)) { throw new TypeError(who + ': sk must be a Uint8Array'); }
        var own = new Uint8Array(sk);
        return { sign: with_sk(own), wipe: function () { own.fill(0); } };
    };
    return {
        sign: function (sk, msg, rnd, ctx) { return sign_checked(with_sk(sk), ctx, rnd, undefined, null, msg); },
        verify: function (pk, msg, sig, ctx) { return verified(pk, fips_message(ctx, msg), sig); },
        hash_sign: function (sk, msg, name, rnd, ctx) { return sign_checked(with_sk(sk), ctx, rnd, name, digest_of(name, msg)); },
        hash_verify: function (pk, msg, sig, name, ctx) { return verified(pk, fips_prehash_message(ctx, name, digest_of(name, msg)), sig); },
        hash_sign_digest: function (sk, digest, name, rnd, ctx) { return sign_checked(with_sk(sk), ctx, rnd, name, digest); },
        hash_verify_digest: function (pk, digest, sig, name, ctx) { return verified(pk, fips_prehash_message(ctx, name, digest), sig); },
        signer_create: function (sk) {
            var st = state_of(sk);
            function sign_mp(mp, rnd) {
                if (st === null) { throw new Error(who + ': the signer was wiped'); }
                return st.sign(mp, rnd);
            }
            return {
                sign: function (msg, rnd, ctx) { return sign_checked(sign_mp, ctx, rnd, undefined, null, msg); },
                hash_sign: function (msg, name, rnd, ctx) { return sign_checked(sign_mp, ctx, rnd, name, digest_of(name, msg)); },
                hash_sign_digest: function (digest, name, rnd, ctx) { return sign_checked(sign_mp, ctx, rnd, name, digest); },
                wipe: function () { if (st !== null) { st.wipe(); st = null; } }
            };
        }
    };
}
