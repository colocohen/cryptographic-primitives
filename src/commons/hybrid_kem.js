/**
 * commons/hybrid_kem.js - a post-quantum KEM and an elliptic-curve group,
 * combined so that breaking the result needs breaking both
 * (draft-irtf-cfrg-hybrid-kems, the "CG" framework: a C2PRI combiner over a
 * nominal group).
 *
 *     sk                 32-byte seed; PRG(sk) = seed_PQ ‖ seed_T
 *     pk  = ek_PQ ‖ ek_T     ek_T = g^RandomScalar(seed_T)
 *     ct  = ct_PQ ‖ ct_T     ct_T = g^e, the encapsulator's ephemeral scalar
 *     ss  = KDF(ss_PQ ‖ ss_T ‖ ct_T ‖ ek_T ‖ label)
 *
 * WHY ct_PQ AND ek_PQ ARE NOT HASHED. ML-KEM's shared secret is already bound
 * to its ciphertext and key (its Fujisaki-Okamoto transform hashes both), so
 * the combiner needs only the group half's; that is what C2PRI names, and
 * what X-Wing's proof uses (Barbosa et al.). It is for a PQ KEM with that
 * property, not an arbitrary one.
 *
 * This file is the mechanism and knows no curve: hybrid_kem.js supplies the
 * three instances of draft-irtf-cfrg-concrete-hybrid-kems - MLKEM768-X25519
 * (X-Wing), MLKEM768-P256 and MLKEM1024-P384.
 */
import { concat } from './bytes.js';
import { require_rng } from './primes.js';

/**
 * @param {object} o
 *   name     for errors
 *   label    the combiner's domain label
 *   pq       { keygen(seed64) -> {ek, dk}, encaps(ek, m32) -> {ss, ct},
 *              decaps(dk, ct), check_ek(ek), EK_BYTES, CT_BYTES } - an ML-KEM
 *   group    { SEED, ELEM, scalar(seed) -> sk, element(sk) -> bytes,
 *              shared(sk, element) -> bytes } - the nominal group
 *   prg      (seed, len) -> bytes
 *   kdf      bytes -> 32 bytes
 */
export function hybrid_kem(o) {
    var pq = o.pq, G = o.group, PQ_SEED = 64, PQ_RAND = 32;
    var PK_BYTES = pq.EK_BYTES + G.ELEM, CT_BYTES = pq.CT_BYTES + G.ELEM, SK_BYTES = 32, SS_BYTES = 32;
    var RAND_BYTES = PQ_RAND + G.SEED;

    function bytes_of(v, len, what) {
        if (!(v instanceof Uint8Array) || v.length !== len) { throw new Error(o.name + ': ' + what + ' must be ' + len + ' bytes'); }
    }

    /* the seed's expansion: the ML-KEM key, the group scalar and both public halves */
    function expand(sk) {
        bytes_of(sk, SK_BYTES, 'secret key');
        var e = o.prg(sk, PQ_SEED + G.SEED);
        var kp = pq.keygen(e.subarray(0, PQ_SEED));
        var skT = G.scalar(e.subarray(PQ_SEED));
        return { dkPQ: kp.dk, ekPQ: kp.ek, skT: skT, ekT: G.element(skT), e: e };
    }
    function wipe(x) { x.dkPQ.fill(0); x.skT.fill(0); x.e.fill(0); }

    function combine(ssPQ, ssT, ctT, ekT) { return o.kdf(concat([ssPQ, ssT, ctT, ekT, o.label])); }

    function keygen_derand(seed) {
        var x = expand(seed);
        try { return { sk: new Uint8Array(seed), pk: concat([x.ekPQ, x.ekT]) }; } finally { wipe(x); }
    }

    function encaps_derand(pk, rnd) {
        bytes_of(pk, PK_BYTES, 'public key');
        bytes_of(rnd, RAND_BYTES, 'encapsulation randomness');
        var ekPQ = pk.subarray(0, pq.EK_BYTES), ekT = pk.subarray(pq.EK_BYTES);
        var eT = G.scalar(rnd.subarray(PQ_RAND));
        var ctT = G.element(eT), ssT = G.shared(eT, ekT);
        var m = pq.encaps(ekPQ, rnd.subarray(0, PQ_RAND));      /* FIPS 203's key check throws inside */
        try { return { ss: combine(m.ss, ssT, ctT, ekT), ct: concat([m.ct, ctT]) }; } finally { eT.fill(0); ssT.fill(0); m.ss.fill(0); }
    }

    return {
        PK_BYTES: PK_BYTES, SK_BYTES: SK_BYTES, CT_BYTES: CT_BYTES, SS_BYTES: SS_BYTES, RAND_BYTES: RAND_BYTES,

        /** The key pair of a 32-byte seed (DeriveKeyPair); the seed IS the secret key. */
        keygen_derand: keygen_derand,
        keygen: function (rng) { rng = require_rng(o.name + '.keygen', rng); return keygen_derand(rng(SK_BYTES)); },
        public_key: function (sk) { return keygen_derand(sk).pk; },

        /** EncapsDerand: rnd is the ML-KEM randomness (32) then the group seed. */
        encaps_derand: encaps_derand,
        encaps: function (pk, rng) {
            rng = require_rng(o.name + '.encaps', rng);
            var r = rng(RAND_BYTES);
            try { return encaps_derand(pk, r); } finally { r.fill(0); }
        },

        /**
         * Decapsulate. The ML-KEM half never fails (implicit rejection); a
         * group element that is not one throws.
         */
        decaps: function (sk, ct) {
            bytes_of(ct, CT_BYTES, 'ciphertext');
            var x = expand(sk);
            try {
                var ctT = ct.subarray(pq.CT_BYTES);
                var ssPQ = pq.decaps(x.dkPQ, ct.subarray(0, pq.CT_BYTES));
                var ssT = G.shared(x.skT, ctT);
                try { return combine(ssPQ, ssT, ctT, x.ekT); } finally { ssPQ.fill(0); ssT.fill(0); }
            } finally { wipe(x); }
        },

        /** Can `pk` be encapsulated to: its length, and FIPS 203's checks on the ML-KEM half. */
        check_public_key: function (pk) {
            return pk instanceof Uint8Array && pk.length === PK_BYTES && pq.check_ek(pk.subarray(0, pq.EK_BYTES)) &&
                   (!G.check || G.check(pk.subarray(pq.EK_BYTES)));
        },

        /** ⚠ HAZMAT: the sub-keys of a secret key - the 64-byte ML-KEM seed and the group scalar (the vectors' dk_pq, dk_t). */
        sub_keys: function (sk) {
            var x = expand(sk), out = { dk_pq: x.e.slice(0, PQ_SEED), dk_t: new Uint8Array(x.skT), ek_pq: x.ekPQ, ek_t: x.ekT };
            wipe(x);
            return out;
        }
    };
}
