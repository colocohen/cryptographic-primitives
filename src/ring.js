/**
 * Ring signatures  -  SAG and LSAG
 *
 * A signature that proves "one of these n keys signed this" WITHOUT revealing
 * which. The signer picks the ring themselves, from any public keys they can
 * find; the other key holders are never asked and never know they were
 * included.
 *
 * WHAT MAKES IT UNUSUAL AMONG THE SIGNATURE SCHEMES HERE. FROST needs two
 * rounds of communication and a prior key-generation ceremony. BLS threshold
 * needs shares dealt in advance. A ring signature needs NOTHING from anyone:
 * one signer, one pass, no setup, no interaction. The anonymity set is
 * assembled at signing time out of keys that already exist.
 *
 * THE CONSTRUCTION is a ring of Schnorr challenges that closes on itself.
 * The signer starts at their own position with a random nonce, walks forward
 * around the ring producing a challenge and a random response at each other
 * member's position, and on returning to their own position uses their secret
 * key to compute the one response that makes the ring close. A verifier can
 * walk the whole ring and check it closes, but cannot tell where the walk
 * began - every position looks identical.
 *
 * TWO VARIANTS:
 *
 *   SAG   Spontaneous Anonymous Group. Pure anonymity: two signatures by the
 *         same key are unlinkable.
 *   LSAG  Linkable. Each signature carries a KEY IMAGE, I = x*H(scope, P),
 *         which is constant for a signer WITHIN ONE SCOPE and reveals nothing
 *         about which member they are. Two signatures with the same key image
 *         came from the same signer - without saying who.
 *
 * ⭐ THE SCOPE IS THE CALLER'S (11-13), and required. It decides where
 *    signatures link: one poll, one election, one coin's spends. Before it,
 *    the image was x*H(P) under a tag of this library's, so a member who
 *    voted in two polls - or in two applications - gave the same image in
 *    both, and anyone could tell the two votes were one person's. Across
 *    scopes the images are unrelated (a different H for each); within one,
 *    linking works as it did. A coin that wants every spend to link passes
 *    one constant scope.
 *
 * LINKABILITY IS WHAT MAKES IT USEFUL RATHER THAN JUST PRIVATE. It is how
 * Monero prevents double spends: the network sees that an output was already
 * used without learning whose it was. The same mechanism gives one-vote-per-
 * member anonymous voting, and rate-limited anonymous reporting.
 *
 * ANONYMITY IS BOUNDED BY THE RING, and that is the practical failure mode. A
 * ring of 2 gives one bit. A ring whose other members are obviously
 * implausible - inactive keys, keys the signer controls - gives less than its
 * size suggests. Monero's history is largely a history of learning this:
 * early rings of 3 were deanonymised by chain analysis, and the minimum has
 * risen repeatedly.
 *
 * ============================ VERIFICATION STATUS ============================
 * There is no RFC and no published test vectors for SAG or LSAG. This is
 * tested for completeness, unforgeability without a secret key, correct
 * linking behaviour, and rejection of every tampered component - but it has
 * NOT been checked against another implementation, and its wire format is
 * this library's own. Do not expect Monero to accept these.
 * =============================================================================
 */

import * as r255 from './ristretto255.js';
import { sha512 } from './sha2.js';
import { concat, ascii, be16 } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';
import { equal_bool } from './commons/ct.js';

var scalar_mod = r255.scalar_mod;
var scalar_add = r255.scalar_add;
var scalar_sub = r255.scalar_sub;
var scalar_mul = r255.scalar_mul;

/**
 * The challenge hash.
 *
 * EVERY VALUE THE VERIFIER USES IS ABSORBED: the message, the whole ring, the
 * key image when there is one, and both points for this step. Leaving the
 * ring out is the classic mistake - it would let an attacker take a valid
 * signature and present it against a DIFFERENT ring containing their own key.
 */
function challenge(domain, msg, ring, image, L, R, scope) {
    var parts = [ascii('cryptographic-primitives/ring/v1'), ascii(domain),
                 be16(msg.length), msg, be16(ring.length)];
    if (scope) { parts.push(ascii('S'), be16(scope.length), scope); }
    for (var i = 0; i < ring.length; i++) { parts.push(ring[i]); }
    if (image) { parts.push(ascii('I'), image); }
    parts.push(ascii('L'), r255.encode(L));
    if (R) { parts.push(ascii('R'), r255.encode(R)); }
    return r255.scalar_from_uniform_bytes(sha512(concat(parts)));
}

/**
 * What both signers check before they start: an rng, a ring of at least two
 * valid keys, an index inside it, and that the secret really is ring[index].
 * sign() and sign_linkable() each carried these eleven lines.
 *
 * @return {{ n: number, pts: Array, x: bigint }}
 */
function signer_setup(who, ring, secret, index, rng) {
    rng = require_rng(who, rng);
    var n = ring.length;
    if (n < 2) { throw new Error('ring: need at least two members'); }
    if (index < 0 || index >= n) { throw new Error('ring: index out of range'); }

    var pts = decode_ring(ring);
    if (!pts) { throw new Error('ring: invalid public key in the ring'); }

    var x = scalar_mod(secret);
    if (!r255.equals(r255.base_mul(x), pts[index])) {
        throw new Error('ring: the secret does not match ring[index]');
    }
    return { n: n, pts: pts, x: x };
}

function decode_ring(ring) {
    var pts = [];
    for (var i = 0; i < ring.length; i++) {
        var P = r255.decode(ring[i]);
        if (!P) { return null; }
        pts.push(P);
    }
    return pts;
}

/* ---------------- SAG: unlinkable ---------------- */

/**
 * @param  {Uint8Array}        msg
 * @param  {Array<Uint8Array>} ring    every member's public key, encoded
 * @param  {bigint}            secret  the signer's private scalar
 * @param  {number}            index   the signer's position in `ring`
 * @return {{c0: Uint8Array, s: Array<Uint8Array>}}
 *
 * THE RING MUST CONTAIN THE SIGNER'S OWN PUBLIC KEY AT `index`, and the
 * function checks it - a mismatch would produce a signature that verifies
 * against nothing, silently.
 */
export function sign(msg, ring, secret, index, rng) {
    var st = signer_setup('sign', ring, secret, index, rng);
    var n = st.n, pts = st.pts, x = st.x;

    var s = new Array(n);
    var c = new Array(n);

    /* start at the signer's position with a random nonce */
    var alpha = r255.scalar_from_uniform_bytes(rng(64));
    c[(index + 1) % n] = challenge('sag', msg, ring, null, r255.base_mul(alpha), null);

    /* walk forward with random responses until we come back around */
    for (var k = 1; k < n; k++) {
        var i = (index + k) % n;
        s[i] = r255.scalar_from_uniform_bytes(rng(64));
        var L = r255.add(r255.base_mul(s[i]), r255.mul(c[i], pts[i]));
        c[(i + 1) % n] = challenge('sag', msg, ring, null, L, null);
    }

    /*
     * The one step that needs the secret: choose s so that
     * s*G + c*P = alpha*G, which requires s = alpha - c*x.
     * Every other s was random, so no position is distinguishable.
     */
    s[index] = scalar_sub(alpha, scalar_mul(c[index], x));

    return {
        c0: r255.scalar_bytes(c[0]),
        s: s.map(r255.scalar_bytes)
    };
}

/** @return {boolean} */
/**
 * The verifier's walk, shared by SAG and LSAG: from c0, each member's
 * L = s_i·G + c·P_i, and `next(i, s_i, c, L)` the next challenge. The ring
 * closes only if the walk returns to where it started.
 */
function ring_closes(sig, pts, next) {
    var c = r255.scalar_from_canonical_bytes(sig.c0);
    if (c === null) { return false; }
    var c0 = c;
    for (var i = 0; i < pts.length; i++) {
        var si = r255.scalar_from_canonical_bytes(sig.s[i]);
        if (si === null) { return false; }
        var L = r255.add(r255.base_mul(si), r255.mul_vartime(c, pts[i]));
        c = next(i, si, c, L);
    }
    return c === c0;
}

export function verify(msg, sig, ring) {
    var n = ring.length;
    if (n < 2 || !sig.s || sig.s.length !== n) { return false; }
    var pts = decode_ring(ring);
    if (!pts) { return false; }
    return ring_closes(sig, pts, function (i, si, c, L) { return challenge('sag', msg, ring, null, L, null); });
}

/* ---------------- LSAG: linkable ---------------- */

/**
 * The key image, I = x * H(P).
 *
 * H(P) is a point whose discrete log relative to G is unknown, so the image
 * reveals nothing about x - but it is DETERMINED by x, so the same signer
 * always produces the same image. That is the whole linking mechanism.
 */
export function key_image(secret, public_key, scope) {
    var Hp = hash_point(public_key, scope_bytes(scope, 'key_image'));
    /* ⛔ NOT mul_vartime. This sits between two verify functions and the
       scalar is the SIGNING KEY - a variable-time multiply here publishes it
       in the timing. A sweep over "the verify paths" catches this line by
       position; only the argument tells you it must not be touched. */
    return r255.encode(r255.mul(scalar_mod(secret), Hp));
}

/* H(scope, P): the point the key image is a multiple of. key_image() used
   to spell the same hash_to_group call out a second time. The scope comes
   first, length-prefixed, so no (scope, P) pair reads as another. */
function hash_point(pk, scope) {
    return r255.hash_to_group(concat([be16(scope.length), scope, pk]), ascii('cryptographic-primitives/ring/keyimage/v2'));
}

/* the caller's scope as bytes: a string (UTF-8) or bytes, 1 to 65535 of them */
function scope_bytes(scope, who) {
    var b = typeof scope === 'string' ? ascii(scope) : scope;
    if (!(b instanceof Uint8Array) || b.length === 0 || b.length > 0xffff) {
        throw new TypeError('ring ' + who + ': scope is required - a string or bytes naming where signatures link (a poll, an election, an application)');
    }
    return b;
}

/**
 * @param  scope  where signatures link: a string or bytes, required (the header)
 * @return {{c0, s, image}} the image is public and is what links signatures
 */
export function sign_linkable(msg, ring, secret, index, rng, scope) {
    var sc = scope_bytes(scope, 'sign_linkable');
    var st = signer_setup('sign_linkable', ring, secret, index, rng);
    var n = st.n, pts = st.pts, x = st.x;

    var image_bytes = key_image(x, ring[index], sc);
    var I = r255.decode(image_bytes);

    var s = new Array(n);
    var c = new Array(n);

    /*
     * The linkable version runs TWO parallel checks per position: one against
     * G and the signer's public key, one against H(P_i) and the key image.
     * Both must close, which is what ties the image to the actual signer
     * rather than to a value they chose freely.
     */
    var alpha = r255.scalar_from_uniform_bytes(rng(64));
    var L0 = r255.base_mul(alpha);
    var R0 = r255.mul(alpha, hash_point(ring[index], sc));
    c[(index + 1) % n] = challenge('lsag', msg, ring, image_bytes, L0, R0, sc);

    for (var k = 1; k < n; k++) {
        var i = (index + k) % n;
        s[i] = r255.scalar_from_uniform_bytes(rng(64));
        var L = r255.add(r255.base_mul(s[i]), r255.mul(c[i], pts[i]));
        var R = r255.add(r255.mul(s[i], hash_point(ring[i], sc)), r255.mul(c[i], I));
        c[(i + 1) % n] = challenge('lsag', msg, ring, image_bytes, L, R, sc);
    }

    s[index] = scalar_sub(alpha, scalar_mul(c[index], x));

    return {
        c0: r255.scalar_bytes(c[0]),
        s: s.map(r255.scalar_bytes),
        image: image_bytes
    };
}

/** @return {boolean}  scope: the one it was signed in (required) */
export function verify_linkable(msg, sig, ring, scope) {
    var sc = scope_bytes(scope, 'verify_linkable');
    var n = ring.length;
    if (n < 2 || !sig.s || sig.s.length !== n || !sig.image) { return false; }
    var pts = decode_ring(ring);
    if (!pts) { return false; }
    var I = r255.decode(sig.image);
    if (!I) { return false; }
    return ring_closes(sig, pts, function (i, si, c, L) {
        /* ⭐ both points are arbitrary here, so the walk is shared. L keeps
           base_mul (ring_closes): its comb table beats a folded walk. */
        var R = r255.double_mul_vartime(si, hash_point(ring[i], sc), c, I);
        return challenge('lsag', msg, ring, sig.image, L, R, sc);
    });
}

/**
 * Whether two linkable signatures came from the same signer.
 *
 * IT DOES NOT SAY WHO. Comparing images tells you that one ring member signed
 * twice; identifying them still requires the discrete log.
 *
 * Note that the image depends on the signer's PUBLIC KEY as well as their
 * secret, so it is stable across different rings - a signer in ring A and
 * ring B produces the same image, which is what makes double-spend detection
 * work across transactions. Within ONE scope: two signatures verified in
 * different scopes never link, which is the point of the scope.
 *
 * @return {boolean}
 */
export function linked(sig_a, sig_b) {
    if (!sig_a.image || !sig_b.image) { return false; }
    /* key images are public, so constant time is not needed here - but the
       byte loop this replaces was a copy of ct.equal_bool all the same */
    return equal_bool(sig_a.image, sig_b.image);
}

/** The signature's size in bytes: 32 per member, plus c0, plus any image. */
export function signature_size(n, linkable) {
    return 32 * (n + 1) + (linkable ? 32 : 0);
}
