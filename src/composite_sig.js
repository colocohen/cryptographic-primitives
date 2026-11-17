/**
 * Composite ML-DSA - RFC 10073 (draft-ietf-lamps-pq-composite-sigs)
 *
 * One signature made of two: ML-DSA and a traditional algorithm (RSA, ECDSA
 * or EdDSA), both over the same message representative, both required to
 * verify. Forging it needs breaking BOTH - a quantum computer gets past the
 * traditional half and still faces ML-DSA; a flaw in ML-DSA still leaves the
 * traditional one. The X.509 / PKIX profile for the migration years.
 *
 *     M' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ PH(M)
 *     s  = ML-DSA.Sign(mldsaSK, M', ctx = Label) ‖ Trad.Sign(tradSK, M')
 *     pk = mldsaPK ‖ tradPK        sk = mldsaSeed (32) ‖ tradSK
 *
 * Prefix is "CompositeAlgorithmSignatures2025"; Label names the combination,
 * so a component signature lifted out of one composite does not verify in
 * another, or alone. ML-DSA is pure ML-DSA (the pre-hash is the composite's
 * own), with the label as its FIPS 204 context.
 *
 * Encodings (§5): RSA keys are RSAPublicKey / RSAPrivateKey DER, ECDSA
 * public keys uncompressed points, private keys ECPrivateKey DER with the
 * curve OID, signatures Ecdsa-Sig-Value DER; EdDSA keys and signatures raw.
 *
 * ⛔ COMPONENT KEYS ARE NEVER REUSED (§3.1): not between composites, not
 *    with the same key alone. keygen makes both fresh; importing one key
 *    into several uses is what the label cannot protect against.
 *
 * SIGNED IN TWO PLACES. A caller whose halves are signed elsewhere - an HSM
 * per half, or two threshold protocols - takes `halves(msg, ctx)`: the
 * ML-DSA half's M' and context, and what the traditional signer is given
 * (`TRAD` says which signer: ECDSA a digest of M', EdDSA M' itself, RSA M'
 * with its padding and hash); then `assemble` makes the composite signature
 * from the two, ECDSA's (r, s) DER-encoded here, and `public_key_from` the
 * composite key from the two public keys. `BY_LABEL` finds a composite by
 * its label.
 */
import { ml_dsa44, ml_dsa65, ml_dsa87 } from './ml_dsa.js';
import * as rsa from './rsa.js';
import { p256, p384, p521 } from './nist.js';
import { brainpoolP256r1, brainpoolP384r1 } from './brainpool.js';
import * as ed25519 from './ed25519.js';
import * as ed448 from './ed448.js';
import { sha256, sha384, sha512 } from './sha2.js';
import { shake256 } from './sha3.js';
import { concat } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';

var PREFIX = /* @__PURE__ */ new TextEncoder().encode('CompositeAlgorithmSignatures2025');

/* ---------------- the traditional halves ---------------- */
/*
 * Each: keygen(rng) -> { pk, sk } in the composite's encodings, sign(sk, m,
 * rng), verify(pk, m, sig) - over M' itself, each with its own hash.
 */
/* the traditional halves' encodings of a signature and a public key, from what a signer elsewhere returns */
function rsa_signature(bits) {
    return function (sig) {
        if (!(sig instanceof Uint8Array) || sig.length !== bits / 8) { throw new Error('composite_sig: an RSA-' + bits + ' signature is ' + (bits / 8) + ' bytes'); }
        return sig;
    };
}
function rsa_public_key(bits) {
    return function (pk) {
        var der = pk instanceof Uint8Array ? pk : (pk && typeof pk.n === 'bigint' && typeof pk.e === 'bigint' ? rsa.public_key_to_der(pk) : null);
        var k = der && rsa.public_key_from_der(der);
        if (!k || k.bits !== bits) { throw new Error('composite_sig: an RSA-' + bits + ' public key, as RSAPublicKey DER or {n, e}'); }
        return der;
    };
}
function hash_name(hash) { return hash === sha256 ? 'sha256' : hash === sha384 ? 'sha384' : 'sha512'; }
function rsa_pss(bits, hash, salt) {
    return {
        INFO: { kind: 'rsa-pss', bits: bits, hash: hash_name(hash), salt: salt },
        input: function (m) { return m; },
        encode_signature: rsa_signature(bits),
        encode_public_key: rsa_public_key(bits),
        keygen: function (rng) { var k = rsa.keygen(bits, rng); return { pk: rsa.public_key_to_der(k), sk: rsa.private_key_to_der(k) }; },
        sign: function (sk, m, rng) { return rsa.sign_pss(key_of(sk), hash(m), hash, rng, salt); },
        verify: function (pk, m, sig) { var k = rsa.public_key_from_der(pk); return !!k && k.bits === bits && rsa.verify_pss(k, hash(m), sig, hash, salt); }
    };
}
function rsa_pkcs1(bits, hash, name) {
    return {
        INFO: { kind: 'rsa-pkcs1', bits: bits, hash: name },
        input: function (m) { return m; },
        encode_signature: rsa_signature(bits),
        encode_public_key: rsa_public_key(bits),
        keygen: function (rng) { var k = rsa.keygen(bits, rng); return { pk: rsa.public_key_to_der(k), sk: rsa.private_key_to_der(k) }; },
        sign: function (sk, m, rng) { return rsa.sign_pkcs1(key_of(sk), hash(m), name, rng); },
        verify: function (pk, m, sig) { var k = rsa.public_key_from_der(pk); return !!k && k.bits === bits && rsa.verify_pkcs1(k, hash(m), sig, name); }
    };
}
function key_of(sk) {
    var k = rsa.private_key_from_der(sk);
    if (!k) { throw new Error('composite_sig: the RSA private key is not an RSAPrivateKey'); }
    return k;
}
function ecdsa(curve, name, hash) {
    var N = curve.CURVE.n, NB = (N.toString(2).length + 7) >> 3;
    return {
        INFO: { kind: 'ecdsa', curve: name, hash: hash_name(hash) },
        /* ECDSA signs a digest: Hash(M') */
        input: function (m) { return hash(m); },
        /** (r, s) - {r, s}, r ‖ s, or DER - as Ecdsa-Sig-Value DER; refused outside [1, n) */
        encode_signature: function (sig) {
            var rs = sig instanceof Uint8Array ? (sig.length === 2 * NB ? curve.sig_from_compact(sig) : curve.sig_from_der(sig)) : sig;
            if (!rs || typeof rs.r !== 'bigint' || typeof rs.s !== 'bigint' || rs.r <= 0n || rs.r >= N || rs.s <= 0n || rs.s >= N) {
                throw new Error('composite_sig: an ECDSA ' + name + ' signature is (r, s): {r, s}, r ‖ s or DER');
            }
            return curve.sig_to_der(rs);
        },
        /** a point, compressed or not, as the uncompressed point; refused off the curve */
        encode_public_key: function (pk) {
            var P = pk instanceof Uint8Array ? curve.decode_point(pk) : null;
            if (!P) { throw new Error('composite_sig: an ECDSA ' + name + ' public key is a point on the curve'); }
            return curve.encode_point(P.x, P.y, false);
        },
        keygen: function (rng) {
            /* the top byte masked to the order's width (P-521: 521 bits in 66 bytes), then rejection */
            var mask = 0xff >> (8 * curve.BYTES - curve.CURVE.n.toString(2).length);
            for (var i = 0; i < 64; i++) {
                var sk = rng(curve.BYTES);
                sk[0] &= mask;
                if (curve.is_valid_secret(sk)) { return { pk: curve.get_public_key(sk, false), sk: curve.private_key_to_der(sk) }; }
            }
            throw new Error('composite_sig: key generation failed');
        },
        /* RFC 6979 with the composite's rng as k' (section 3.6): deterministic given it */
        sign: function (sk, m, rng) {
            var d = curve.private_key_from_der(sk);
            if (!d) { throw new Error('composite_sig: the EC private key is not an ECPrivateKey of this curve'); }
            return curve.sig_to_der(curve.sign(hash(m), d, rng(32)));
        },
        verify: function (pk, m, sig) {
            if (pk.length !== 1 + 2 * curve.BYTES || pk[0] !== 4) { return false; }
            var s = curve.sig_from_der(sig);
            return !!s && curve.verify(hash(m), s, pk);
        }
    };
}
function eddsa(E, name, n) {
    return {
        INFO: { kind: 'eddsa', curve: name },
        /* EdDSA signs M' itself (pure, no context) */
        input: function (m) { return m; },
        encode_signature: function (sig) {
            if (!(sig instanceof Uint8Array) || sig.length !== 2 * n) { throw new Error('composite_sig: an ' + name + ' signature is ' + (2 * n) + ' bytes'); }
            return sig;
        },
        encode_public_key: function (pk) {
            if (!(pk instanceof Uint8Array) || pk.length !== n) { throw new Error('composite_sig: an ' + name + ' public key is ' + n + ' bytes'); }
            return pk;
        },
        keygen: function (rng) { var sk = rng(n); return { pk: E.get_public_key(sk), sk: sk }; },
        sign: function (sk, m) {
            if (sk.length !== n) { throw new Error('composite_sig: the EdDSA private key is ' + n + ' bytes'); }
            return E.sign(m, sk);
        },
        verify: function (pk, m, sig) { return pk.length === n && E.verify(m, sig, pk); }
    };
}

/* ---------------- the composite ---------------- */

function composite(o) {
    var M = o.mldsa, label = new TextEncoder().encode(o.label), T = o.trad;
    var PKM = M.PK_BYTES, SIGM = M.SIG_BYTES;

    /* M' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ PH(M), from the digest; null for a context over 255 bytes */
    function representative(digest, ctx) {
        var c = ctx || new Uint8Array(0);
        if (c.length > 255) { return null; }
        return concat([PREFIX, label, new Uint8Array([c.length]), c, digest]);
    }
    function sign_rep(sk, mp, rng) {
        if (!mp) { throw new Error('composite_sig: context too long'); }
        if (!(sk instanceof Uint8Array) || sk.length <= 32) { throw new Error('composite_sig: a private key is the 32-byte ML-DSA seed and the traditional key'); }
        rng = require_rng('composite_sig.sign', rng);
        var k = M.keygen(sk.subarray(0, 32));
        try {
            var s1 = M.sign(k.sk, mp, rng(32), label);
            var s2 = T.sign(sk.subarray(32), mp, rng);
            return concat([s1, s2]);
        } finally { k.sk.fill(0); }
    }
    function verify_rep(pk, mp, sig) {
        if (!mp || !(pk instanceof Uint8Array) || !(sig instanceof Uint8Array) || pk.length <= PKM || sig.length <= SIGM) { return false; }
        try {
            return M.verify(pk.subarray(0, PKM), mp, sig.subarray(0, SIGM), label) &&
                   T.verify(pk.subarray(PKM), mp, sig.subarray(SIGM));
        } catch (e) { return false; }
    }
    return {
        OID: o.oid, LABEL: o.label, PH: o.ph_name,
        ML_DSA_PK_BYTES: PKM, ML_DSA_SIG_BYTES: SIGM,

        /** Fresh keys for both halves - never imported from another use (§3.1). */
        keygen: function (rng) {
            rng = require_rng('composite_sig.keygen', rng);
            var seed = rng(32), m = M.keygen(seed), t = T.keygen(rng);
            m.sk.fill(0);
            return { pk: concat([m.pk, t.pk]), sk: concat([seed, t.sk]) };
        },
        /** The public key of a private key. */
        public_key: function (sk) { var m = M.keygen(sk.subarray(0, 32)); m.sk.fill(0); return m.pk; },

        /**
         * @param {function} [rng]  the randomness of both halves: ML-DSA's
         *                          rnd, ECDSA's RFC 6979 extra data, the PSS
         *                          salt and the RSA blinding (PKCS #1 v1.5's
         *                          output is deterministic all the same);
         *                          EdDSA has none. Left out or null, fresh
         *                          bytes from the platform; an rng of yours
         *                          gives the same composite for the same
         *                          bytes.
         */
        sign: function (sk, msg, ctx, rng) { return sign_rep(sk, representative(o.ph(msg), ctx), rng); },
        verify: function (pk, msg, sig, ctx) { return verify_rep(pk, representative(o.ph(msg), ctx), sig); },

        /** The same from PH(M), computed elsewhere (§10.4, external pre-hashing). */
        sign_digest: function (sk, digest, ctx, rng) {
            if (!(digest instanceof Uint8Array) || digest.length !== o.ph_len) { throw new Error('composite_sig: PH(M) is ' + o.ph_len + ' bytes'); }
            return sign_rep(sk, representative(digest, ctx), rng);
        },
        verify_digest: function (pk, digest, sig, ctx) {
            return digest instanceof Uint8Array && digest.length === o.ph_len && verify_rep(pk, representative(digest, ctx), sig);
        },

        /** M' itself, for a caller that signs the halves elsewhere (an HSM per half). */
        message_representative: function (msg, ctx) { return representative(o.ph(msg), ctx); },

        /* ---- signed in two places ---- */

        /** The traditional half's signer: {kind, curve | bits, hash, salt}. */
        TRAD: T.INFO,
        /**
         * What each half signs: ML-DSA (pure) M' under the label as its
         * context; the traditional signer `trad.message` (Hash(M') for ECDSA,
         * M' for EdDSA and RSA, which pads and hashes it as TRAD says).
         */
        halves: function (msg, ctx) { return halves_of(representative(o.ph(msg), ctx)); },
        halves_digest: function (digest, ctx) {
            if (!(digest instanceof Uint8Array) || digest.length !== o.ph_len) { throw new Error('composite_sig: PH(M) is ' + o.ph_len + ' bytes'); }
            return halves_of(representative(digest, ctx));
        },
        /** The composite signature from the halves: ML-DSA's, then the traditional one's encoding. */
        assemble: function (mldsa_sig, trad_sig) {
            if (!(mldsa_sig instanceof Uint8Array) || mldsa_sig.length !== SIGM) { throw new Error('composite_sig: the ML-DSA half is ' + SIGM + ' bytes'); }
            return concat([mldsa_sig, T.encode_signature(trad_sig)]);
        },
        /** The composite public key from the halves' public keys. */
        public_key_from: function (mldsa_pk, trad_pk) {
            if (!(mldsa_pk instanceof Uint8Array) || mldsa_pk.length !== PKM) { throw new Error('composite_sig: the ML-DSA public key is ' + PKM + ' bytes'); }
            return concat([mldsa_pk, T.encode_public_key(trad_pk)]);
        }
    };
    function halves_of(mp) {
        if (!mp) { throw new Error('composite_sig: context too long'); }
        return { mldsa: { message: mp, context: label }, trad: { message: T.input(mp) } };
    }
}

var PH = {
    SHA256: [sha256, 32],
    SHA512: [sha512, 64],
    SHAKE256: [function (m) { return shake256(m, 64); }, 64]
};
function make(oid_arc, label, mldsa, ph, trad) {
    return composite({ oid: '1.3.6.1.5.5.7.6.' + oid_arc, label: label, mldsa: mldsa, ph_name: ph, ph: PH[ph][0], ph_len: PH[ph][1], trad: trad });
}

/* RFC 10073 §7, in its order. RSA-PSS at 2048/3072 bits is SHA-256 with a
   32-byte salt, at 4096 bits SHA-384 with 48 (§7.1). */
export var mldsa44_rsa2048_pss_sha256 = /* @__PURE__ */ make(37, 'COMPSIG-MLDSA44-RSA2048-PSS-SHA256', ml_dsa44, 'SHA256', rsa_pss(2048, sha256, 32));
export var mldsa44_rsa2048_pkcs15_sha256 = /* @__PURE__ */ make(38, 'COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256', ml_dsa44, 'SHA256', rsa_pkcs1(2048, sha256, 'sha256'));
export var mldsa44_ed25519_sha512 = /* @__PURE__ */ make(39, 'COMPSIG-MLDSA44-Ed25519-SHA512', ml_dsa44, 'SHA512', eddsa(ed25519, 'ed25519', 32));
export var mldsa44_ecdsa_p256_sha256 = /* @__PURE__ */ make(40, 'COMPSIG-MLDSA44-ECDSA-P256-SHA256', ml_dsa44, 'SHA256', ecdsa(p256, 'p256', sha256));
export var mldsa65_rsa3072_pss_sha512 = /* @__PURE__ */ make(41, 'COMPSIG-MLDSA65-RSA3072-PSS-SHA512', ml_dsa65, 'SHA512', rsa_pss(3072, sha256, 32));
export var mldsa65_rsa3072_pkcs15_sha512 = /* @__PURE__ */ make(42, 'COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512', ml_dsa65, 'SHA512', rsa_pkcs1(3072, sha256, 'sha256'));
export var mldsa65_rsa4096_pss_sha512 = /* @__PURE__ */ make(43, 'COMPSIG-MLDSA65-RSA4096-PSS-SHA512', ml_dsa65, 'SHA512', rsa_pss(4096, sha384, 48));
export var mldsa65_rsa4096_pkcs15_sha512 = /* @__PURE__ */ make(44, 'COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512', ml_dsa65, 'SHA512', rsa_pkcs1(4096, sha384, 'sha384'));
export var mldsa65_ecdsa_p256_sha512 = /* @__PURE__ */ make(45, 'COMPSIG-MLDSA65-ECDSA-P256-SHA512', ml_dsa65, 'SHA512', ecdsa(p256, 'p256', sha256));
export var mldsa65_ecdsa_p384_sha512 = /* @__PURE__ */ make(46, 'COMPSIG-MLDSA65-ECDSA-P384-SHA512', ml_dsa65, 'SHA512', ecdsa(p384, 'p384', sha384));
export var mldsa65_ecdsa_brainpoolp256r1_sha512 = /* @__PURE__ */ make(47, 'COMPSIG-MLDSA65-ECDSA-BP256-SHA512', ml_dsa65, 'SHA512', ecdsa(brainpoolP256r1, 'brainpoolP256r1', sha256));
export var mldsa65_ed25519_sha512 = /* @__PURE__ */ make(48, 'COMPSIG-MLDSA65-Ed25519-SHA512', ml_dsa65, 'SHA512', eddsa(ed25519, 'ed25519', 32));
export var mldsa87_ecdsa_p384_sha512 = /* @__PURE__ */ make(49, 'COMPSIG-MLDSA87-ECDSA-P384-SHA512', ml_dsa87, 'SHA512', ecdsa(p384, 'p384', sha384));
export var mldsa87_ecdsa_brainpoolp384r1_sha512 = /* @__PURE__ */ make(50, 'COMPSIG-MLDSA87-ECDSA-BP384-SHA512', ml_dsa87, 'SHA512', ecdsa(brainpoolP384r1, 'brainpoolP384r1', sha384));
export var mldsa87_ed448_shake256 = /* @__PURE__ */ make(51, 'COMPSIG-MLDSA87-Ed448-SHAKE256', ml_dsa87, 'SHAKE256', eddsa(ed448, 'ed448', 57));
export var mldsa87_rsa3072_pss_sha512 = /* @__PURE__ */ make(52, 'COMPSIG-MLDSA87-RSA3072-PSS-SHA512', ml_dsa87, 'SHA512', rsa_pss(3072, sha256, 32));
export var mldsa87_rsa4096_pss_sha512 = /* @__PURE__ */ make(53, 'COMPSIG-MLDSA87-RSA4096-PSS-SHA512', ml_dsa87, 'SHA512', rsa_pss(4096, sha384, 48));
export var mldsa87_ecdsa_p521_sha512 = /* @__PURE__ */ make(54, 'COMPSIG-MLDSA87-ECDSA-P521-SHA512', ml_dsa87, 'SHA512', ecdsa(p521, 'p521', sha512));

/** Every composite, by its label (COMPSIG-...). */
export var BY_LABEL = /* @__PURE__ */ (function () {
    var all = [mldsa44_rsa2048_pss_sha256, mldsa44_rsa2048_pkcs15_sha256, mldsa44_ed25519_sha512, mldsa44_ecdsa_p256_sha256, mldsa65_rsa3072_pss_sha512, mldsa65_rsa3072_pkcs15_sha512, mldsa65_rsa4096_pss_sha512, mldsa65_rsa4096_pkcs15_sha512, mldsa65_ecdsa_p256_sha512, mldsa65_ecdsa_p384_sha512, mldsa65_ecdsa_brainpoolp256r1_sha512, mldsa65_ed25519_sha512, mldsa87_ecdsa_p384_sha512, mldsa87_ecdsa_brainpoolp384r1_sha512, mldsa87_ed448_shake256, mldsa87_rsa3072_pss_sha512, mldsa87_rsa4096_pss_sha512, mldsa87_ecdsa_p521_sha512], out = {};
    for (var i = 0; i < all.length; i++) { out[all[i].LABEL] = all[i]; }
    return out;
}());
