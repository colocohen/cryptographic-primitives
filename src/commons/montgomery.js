/**
 * The Montgomery ladder on x coordinates
 *
 * For curves of the form B*y^2 = x^3 + A*x^2 + x - Curve25519 and Curve448.
 * Used for key agreement only: X25519 and X448.
 *
 * WHAT MAKES THIS DIFFERENT FROM EVERY OTHER CURVE FILE HERE
 * There is no y coordinate anywhere. On a Montgomery curve the x coordinate
 * of P + Q can be computed from the x coordinates of P, Q and P - Q, which is
 * enough to run a ladder. Dropping y removes half the arithmetic, removes
 * point compression and decompression entirely, and removes the sign
 * ambiguity that Weierstrass and Edwards both have to encode.
 *
 * The consequence is that this cannot sign. A signature needs a group where
 * points can be added freely; x-only arithmetic gives a quotient of that
 * group where P and -P are the same element. That is precisely why Ed25519
 * exists alongside X25519 on the same underlying curve - one for signing on
 * the Edwards form, one for key agreement on the Montgomery form.
 *
 * WHY THIS IS THE SAFEST CURVE CODE IN THE LIBRARY
 *   - Every 32-byte string is a valid scalar, after clamping.
 *   - EVERY 32-byte string is a valid public key. There is no point to
 *     validate, no invalid-curve attack to defend against, and no way for a
 *     caller to forget the check. The twist of Curve25519 was chosen to have
 *     a large prime order for exactly this reason.
 *   - The ladder is uniform by construction, not by discipline.
 *
 * RFC 7748 designed away the failure modes rather than documenting them,
 * which is why X25519 has had no implementation disasters of the kind ECDSA
 * has had repeatedly.
 */

import { cselect } from './modp.js';
import { secure_random } from './bytes.js';
import { held } from './ct.js';
import { key_from_seed } from './group.js';

/**
 * @param {object} F     the field
 * @param {bigint} a24   (A - 2) / 4 - 121665 for Curve25519, 39081 for Curve448
 * @param {number} bits  ladder width
 */
export function montgomery(F, a24, bits) {
    return {
        /**
         * The scalar multiplication, and the whole of the curve arithmetic.
         *
         * Each iteration performs one differential addition and one doubling,
         * with the two accumulators conditionally swapped. The `swap` running
         * xor is the standard trick: it lets consecutive iterations share a
         * swap instead of performing two, without ever branching on a bit.
         *
         * @param {bigint} k  the clamped scalar
         * @param {bigint} u  the base x coordinate
         */
        ladder: function (k, u) {
            var m = F.mul, ad = F.add, s = F.sub, sq = F.sqr;

            var x1 = u;
            var x2 = 1n, z2 = 0n;
            var x3 = u,  z3 = 1n;
            var swap = 0n;

            for (var t = bits - 1; t >= 0; t--) {
                var kt = (k >> BigInt(t)) & 1n;
                swap ^= kt;

                var nx2 = cselect(swap, x3, x2), nx3 = cselect(swap, x2, x3);
                var nz2 = cselect(swap, z3, z2), nz3 = cselect(swap, z2, z3);
                x2 = nx2; x3 = nx3; z2 = nz2; z3 = nz3;
                swap = kt;

                var A = ad(x2, z2);
                var AA = sq(A);
                var B = s(x2, z2);
                var BB = sq(B);
                var E = s(AA, BB);
                var Cc = ad(x3, z3);
                var D = s(x3, z3);
                var DA = m(D, A);
                var CB = m(Cc, B);

                x3 = sq(ad(DA, CB));
                z3 = m(x1, sq(s(DA, CB)));
                x2 = m(AA, BB);
                z2 = m(E, ad(AA, m(a24, E)));
            }

            var fx2 = cselect(swap, x3, x2);
            var fz2 = cselect(swap, z3, z2);

            /* one inversion, at the very end - the only one in the whole
               operation, which is most of why X25519 is fast */
            return m(fx2, F.inv(fz2));
        }
    };
}

/**
 * Reject the all-zero shared secret.
 *
 * Certain malicious public keys - the small-order points - force the shared
 * secret to a value the attacker already knows regardless of the honest
 * party's key. RFC 7748 leaves the check optional because some protocols need
 * the raw behaviour, but any protocol that treats the output as a secret must
 * do it.
 *
 * CONSTANT TIME: every byte is ORed together and the branch is on the
 * accumulated result, so the timing does not reveal WHERE a non-zero byte was.
 *
 * @return {Uint8Array|null}
 */
export function reject_zero(out) {
    var acc = 0;
    for (var i = 0; i < out.length; i++) { acc |= out[i]; }
    return acc === 0 ? null : out;
}

/**
 * The context of x25519_create / x448_create: a copy of the secret (a fresh
 * one when it is left out), its public key, and the two agreements over
 * it, named as the module names them. wipe() zeroes the copy, and a call
 * after it throws.
 */
export function agreement_context(name, bytes, dh, dh_checked, public_key, secret) {
    var sk = key_from_seed(name + '.' + name + '_create', secret, function () { return secure_random(bytes); });
    if (sk.length !== bytes) { throw new Error(name + ': secret must be ' + bytes + ' bytes'); }
    var key = held(name, sk);
    var ctx = { pk: public_key(sk), wipe: key.wipe };
    ctx[name] = function (peer) { return dh(key.use(), peer); };
    ctx[name + '_checked'] = function (peer) { return dh_checked(key.use(), peer); };
    return ctx;
}
