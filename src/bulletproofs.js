/**
 * Bulletproofs  -  Bunz, Bootle, Boneh, Poelstra, Wuille, Maxwell (2018)
 *
 * A zero-knowledge proof that a Pedersen commitment hides a value in
 * [0, 2^n), with a proof of size 2*log2(n) + 9 group elements.
 *
 * WHY THIS COMPLETES pedersen.js. That file's verify_balance proves that a
 * set of commitments sums correctly WITHOUT proving any value is
 * non-negative - a participant can commit to -1000, balance the equation, and
 * create value from nothing. The warning is written there; this is the fix.
 *
 * THE SIZE IS THE POINT. A range proof over 64 bits is 672 bytes and does not
 * grow with the range - earlier constructions needed one commitment per bit,
 * around 2 KB, and could not be aggregated. Monero switched in 2018 and
 * transaction sizes fell by roughly 80%.
 *
 * NO TRUSTED SETUP, which is the other reason to prefer this over a
 * zk-SNARK. Every generator is derived by hashing, so there is no ceremony
 * whose output has to be believed and no toxic waste to destroy.
 *
 * THE COST IS VERIFICATION TIME. The proof is logarithmic in size but
 * verification is LINEAR in the bit width - the verifier reconstructs the
 * generator vector and does an O(n) multi-scalar multiplication. That is the
 * trade against SNARKs, which verify in constant time but need the setup.
 *
 * ============================ VERIFICATION STATUS ============================
 *
 * THIS IMPLEMENTATION HAS NOT BEEN CHECKED AGAINST ANOTHER ONE. There is no
 * RFC, no published test vectors, and the one JavaScript package available
 * derives its second generator as sha256(G)*G - which means it KNOWS the
 * discrete log and its commitments are not binding. Matching it would have
 * imported that flaw.
 *
 * What IS tested, and tested hard: completeness (an in-range value always
 * proves), soundness (an out-of-range value cannot be made to verify), and
 * resistance to tampering with every component of the proof.
 *
 * WHAT THAT DOES NOT COVER: a proof system can be complete and sound and
 * still differ from every other implementation - and a Fiat-Shamir transcript
 * that hashes too little is exactly that kind of error, invisible to
 * self-testing. The transcript below is written to absorb every value the
 * verifier uses, and that decision has not been corroborated by anyone else.
 *
 * If you need to interoperate with Monero, Grin or secp256k1-zkp, VERIFY THE
 * WIRE FORMAT AGAINST THEM before relying on this.
 * =============================================================================
 */

import * as r255 from './ristretto255.js';
import { msm as pippenger, msm_task as pippenger_task } from './commons/fixed_window.js';
import { finish_task, map_task, then_task, done_task } from './commons/task.js';
import { sha512 } from './sha2.js';
import { concat, ascii, be16 } from './commons/bytes.js';
import { require_rng } from './commons/primes.js';

/* scalar arithmetic, shared with every other file over this group */
var scalar_mod = r255.scalar_mod;
var scalar_inv = r255.scalar_inv;
var scalar_pow = r255.scalar_pow;

var ORDER = r255.ORDER;

/* ---------------- generators ---------------- */

/**
 * The generator vectors g[] and h[], plus the blinding generator H.
 *
 * EVERY ONE IS HASHED TO THE CURVE, so no discrete-log relation between any
 * of them is known to anybody. That is the entire security assumption of the
 * commitment scheme: if a prover knew the log of any generator in terms of
 * another, they could open a commitment to any value they liked.
 *
 * Derived on demand and cached, because a 64-bit proof needs 128 of them and
 * recomputing that per proof would dominate the cost.
 */
var GEN_CACHE = {};

function generators(n) {
    if (GEN_CACHE[n]) { return GEN_CACHE[n]; }
    var g = [], h = [];
    for (var i = 0; i < n; i++) {
        /*
         * ⚠ THESE ARE GENERATORS, NOT DOMAIN SEPARATION, and the difference
         *   decides who owns the string.
         *
         *   A generator derived from a different label is a DIFFERENT
         *   commitment scheme: a prover and a verifier who disagree here
         *   agree on nothing, and a commitment made under one set cannot be
         *   opened under the other. So this is a system parameter and is
         *   correctly fixed by the library.
         *
         *   Contrast ot_extend, where the constant was doing the job a
         *   session identifier should have done - there the library was
         *   deciding something only the caller can know, and it was a bug.
         */
        g.push(r255.hash_to_group(be16(i), ascii('cryptographic-primitives/bp/G')));
        h.push(r255.hash_to_group(be16(i), ascii('cryptographic-primitives/bp/H')));
    }
    var out = {
        g: g,
        h: h,
        H: r255.hash_to_group(new Uint8Array(0), ascii('cryptographic-primitives/bp/blinding'))
    };
    GEN_CACHE[n] = out;
    return out;
}

/** The blinding generator, exposed so commitments can be built to match. */
export function blinding_generator() { return r255.encode(generators(1).H); }

/* ---------------- the transcript ---------------- */

/**
 * Fiat-Shamir.
 *
 * THE ONLY THING PROTECTING SOUNDNESS IS WHAT GOES IN HERE. Every value the
 * verifier will use must be absorbed before the challenge that depends on it
 * is drawn; a prover who can predict a challenge before committing to the
 * values it constrains can forge. The append calls below are ordered to match
 * the protocol exactly, and each is length-prefixed so that two different
 * sequences cannot produce the same transcript.
 */
function transcript(label) {
    var state = concat([ascii('cryptographic-primitives/bulletproofs/v1'), ascii(label)]);
    return {
        append: function (tag, bytes) {
            state = concat([state, be16(tag.length), ascii(tag), be16(bytes.length), bytes]);
        },
        append_point: function (tag, P) {
            this.append(tag, r255.encode(P));
        },
        append_scalar: function (tag, s) {
            this.append(tag, r255.scalar_bytes(s));
        },
        challenge: function (tag) {
            var h = sha512(concat([state, ascii('challenge'), ascii(tag)]));
            /* the challenge is absorbed too, so the next one depends on it */
            state = concat([state, ascii('chal:'), ascii(tag), h.subarray(0, 32)]);
            var c = r255.scalar_from_uniform_bytes(h);
            /* zero would collapse the check; astronomically unlikely, but the
               branch costs nothing and the failure would be silent */
            return c === 0n ? 1n : c;
        }
    };
}

/* ---------------- vector helpers ---------------- */

function vec_scalar_mul(v, s) { return v.map(function (x) { return scalar_mod(x * s); }); }
function vec_add(a, b) { return a.map(function (x, i) { return scalar_mod(x + b[i]); }); }
function vec_sub(a, b) { return a.map(function (x, i) { return scalar_mod(x - b[i]); }); }
function vec_hadamard(a, b) { return a.map(function (x, i) { return scalar_mod(x * b[i]); }); }

/*
 * ⭐ ACCUMULATE, THEN REDUCE ONCE.
 *
 *   The loop used to take `% L` on every step. The products are each under
 *   2^506 and n is at most a few hundred, so the running sum stays under
 *   2^515 - a size BigInt handles without difficulty, and one reduction at
 *   the end gives the same answer as n of them.
 *
 *   Measured on a 128-element product: 2050 ns reducing per step against
 *   900 accumulating.
 *
 * ⚠ THE BOUND IS WHAT MAKES IT SAFE, and it depends on n. Two 253-bit
 *   factors give a 506-bit product; a million of them would reach 526 bits,
 *   which is still fine - BigInt has no width limit and the only cost of a
 *   larger accumulator is a slightly slower add. There is no silent overflow
 *   here, which is exactly what would make this dangerous in a fixed-width
 *   language.
 */
function inner_product(a, b) {
    var s = 0n;
    for (var i = 0; i < a.length; i++) { s += a[i] * b[i]; }
    return scalar_mod(s);
}

function powers(x, n) {
    var out = [], v = 1n;
    for (var i = 0; i < n; i++) { out.push(v); v = scalar_mod(v * x); }
    return out;
}

/**
 * sum(scalars[i] * points[i]) - the operation that dominates the cost.
 *
 * Pippenger's algorithm from commons/fixed_window.js, which is roughly 4x at
 * sixteen terms and 9x at two hundred and fifty-six. A range proof over 64
 * bits does several of these on vectors of that length.
 *
 * IT IS NOT CONSTANT TIME, and here that is fine: every multi-scalar
 * multiplication in this file is over values the verifier will see - the
 * generator vectors, the challenge powers, the proof's own components. The
 * blinding factors never reach it.
 */
/* ristretto255 exposes operations rather than a curve object, so the
   adapter is built by hand rather than through msm_group */
var GROUP = {
    ZERO: r255.IDENTITY,
    add: r255.add,
    dbl: function (P) { return r255.add(P, P); },
    neg: r255.neg
};

/* every msm below reduces its scalars first; the loop was written four times */
function reduced(scalars) {
    var s = new Array(scalars.length);
    for (var i = 0; i < scalars.length; i++) { s[i] = scalar_mod(scalars[i]); }
    return s;
}

function msm(scalars, points) {
    return pippenger(GROUP, reduced(scalars), points, 253);
}

/*
 * ⛔ THE PROVE PATH MUST USE THIS ONE. Pippenger skips zero digits, so its
 *   running time counts the non-zero digits of the scalar vector - and in a
 *   range proof that vector IS the secret. The leak does not come from a_L,
 *   whose entries are 0 or 1 and barely differ: it comes from a_R = a_L - 1,
 *   where a zero bit becomes scalar_mod(-1) = L-1, a full-width scalar, and
 *   a one bit becomes 0 and is skipped outright. MEASURED over 64 terms:
 *   9,667us against 1,000us between the extremes, a factor of 9.7.
 *
 * ⚠ IT COSTS REAL TIME - every scalar now buys a bucket add in every window.
 *   The same 64 terms go to about 15,000us. That is the price of the proof
 *   not announcing what it commits to.
 */
function msm_secret_task(scalars, points) {
    return pippenger_task(GROUP, reduced(scalars), points, 253, true);
}

/* msm_secret_task(s1, p1) + msm_secret_task(s2, p2), as one task, in that order */
function msm_secret_sum_task(s1, p1, s2, p2) {
    return then_task(msm_secret_task(s1, p1), function (a) {
        return map_task(msm_secret_task(s2, p2), function (b) { return r255.add(a, b); });
    });
}

/* ---------------- the inner-product argument ---------------- */

/**
 * Prove knowledge of vectors a and b with <a,b> = c, in 2*log2(n) elements.
 *
 * THIS RECURSION IS WHERE THE LOGARITHMIC SIZE COMES FROM. Each round splits
 * both vectors in half, sends two group elements L and R, draws a challenge
 * x, and folds the halves into a single vector of half the length weighted by
 * x and x^-1. After log2(n) rounds a single scalar pair remains.
 *
 * The generators fold the same way, with the INVERSE weights - which is what
 * makes the verifier's reconstructed commitment match the prover's.
 */
/**
 * One inner-product round, once the four commitments are in hand.
 *
 * ⭐ ONE FUNCTION, from when ip_prove and a callback copy of it held the
 *   same seventeen lines: a divergence would have produced a well-formed
 *   proof under a different transcript, visible only to a cross-check.
 *   There is one prover now (ip_prove_task), and this is its fold.
 */
function ip_fold(T, Lp, Rp, aL, aR, bL, bR, gL, gR, hL, hR, m) {
    T.append_point('L', Lp);
    T.append_point('R', Rp);
    var x = T.challenge('ip');
    var xi = scalar_inv(x);

    var a = vec_add(vec_scalar_mul(aL, x), vec_scalar_mul(aR, xi));
    var b = vec_add(vec_scalar_mul(bL, xi), vec_scalar_mul(bR, x));

    var ng = [], nh = [];
    for (var i = 0; i < m; i++) {
        ng.push(r255.add(r255.mul(xi, gL[i]), r255.mul(x, gR[i])));
        nh.push(r255.add(r255.mul(x, hL[i]), r255.mul(xi, hR[i])));
    }
    return { a: a, b: b, g: ng, h: nh };
}

/** One round's halves of the inner-product argument, and the cross terms cL = ⟨aL, bR⟩, cR = ⟨aR, bL⟩. */
function ip_halves(a, b, g, h) {
    var m = a.length >> 1;
    var aL = a.slice(0, m), aR = a.slice(m), bL = b.slice(0, m), bR = b.slice(m);
    return { m: m, aL: aL, aR: aR, bL: bL, bR: bR,
             gL: g.slice(0, m), gR: g.slice(m), hL: h.slice(0, m), hR: h.slice(m),
             cL: inner_product(aL, bR), cR: inner_product(aR, bL) };
}

/**
 * The inner-product prover as a task (commons/task.js). A round is four
 * msms - each a task of window steps - then the fold; there are log2(n)
 * rounds, about 8 for a 32-bit range proof, and the state between them is
 * exactly (a, b, g, h, L, R).
 *
 * ⚠ ROUNDS ARE NOT UNIFORM: the first runs its msms over n/2 terms, the
 *   last over one, so the steps shrink geometrically.
 */
function ip_prove_task(T, g, h, u, a, b) {
    var L = [], R = [];

    function round() {
        if (a.length <= 1) { return done_task({ L: L, R: R, a: a[0], b: b[0] }); }
        var hv = ip_halves(a, b, g, h), m = hv.m;
        var aL = hv.aL, aR = hv.aR, bL = hv.bL, bR = hv.bR, gL = hv.gL, gR = hv.gR, hL = hv.hL, hR = hv.hR;

        return then_task(msm_secret_sum_task(aL, gR, bR, hL), function (l) {
            var Lp = r255.add(l, r255.mul(hv.cL, u));
            return then_task(msm_secret_sum_task(aR, gL, bL, hR), function (r) {
                var Rp = r255.add(r, r255.mul(hv.cR, u));
                L.push(Lp); R.push(Rp);
                var f = ip_fold(T, Lp, Rp, aL, aR, bL, bR, gL, gR, hL, hR, m);
                a = f.a; b = f.b; g = f.g; h = f.h;
                return round();
            });
        });
    }
    return round();
}

/**
 * The verifier's side. Rather than folding the generators round by round -
 * which would cost O(n log n) - it computes the FINAL exponent of each
 * generator directly from the challenge bits, which is O(n).
 */
/*
 * ⭐ VARIABLE-TIME, like its caller verify_range - see the note there. The
 *   challenges x and their inverses come from the transcript, and a, b and
 *   the L/R points come from the proof; all of it is published.
 *
 * ⛔ ip_prove ABOVE KEEPS THE LADDER. Its scalars are the witness vectors.
 */
function ip_verify(T, g, h, u, P, proof, n) {
    var rounds = proof.L.length;
    if ((1 << rounds) !== n) { return false; }

    var x = [], xi = [];
    for (var j = 0; j < rounds; j++) {
        T.append_point('L', proof.L[j]);
        T.append_point('R', proof.R[j]);
        var c = T.challenge('ip');
        x.push(c); xi.push(scalar_inv(c));
    }

    /*
     * s[i] is the product of the challenges selected by the bits of i. The
     * bit ordering has to match the recursion: the FIRST round splits on the
     * most significant bit, so round j corresponds to bit (rounds-1-j).
     */
    var s = new Array(n);
    for (var i = 0; i < n; i++) {
        var acc = 1n;
        for (var jj = 0; jj < rounds; jj++) {
            var bit = (i >> (rounds - 1 - jj)) & 1;
            acc = scalar_mod(acc * (bit ? x[jj] : xi[jj]));
        }
        s[i] = acc;
    }
    /*
     * ⭐ ONE INVERSION FOR THE WHOLE VECTOR. Each scalar_inv is 253 squarings
     *   at 101 us; Montgomery's trick makes n of them one plus 3n multiplies.
     *
     * ⚠ THESE ARE PRODUCTS OF CHALLENGE POWERS and cannot be zero - a zero
     *   would poison every entry rather than just its own, which is the one
     *   way this differs from a loop of scalar_inv.
     */
    var s_inv = r255.scalar_inv_batch(s);

    /* P must equal <a*s, g> + <b*s^-1, h> + a*b*u, plus the L/R corrections */
    var lhs = P;
    for (var k = 0; k < rounds; k++) {
        lhs = r255.add(lhs, r255.mul_vartime(scalar_mod(x[k] * x[k]), proof.L[k]));
        lhs = r255.add(lhs, r255.mul_vartime(scalar_mod(xi[k] * xi[k]), proof.R[k]));
    }

    var rhs = r255.add(
        r255.add(msm(vec_scalar_mul(s, proof.a), g),
                 msm(vec_scalar_mul(s_inv, proof.b), h)),
        r255.mul_vartime(scalar_mod(proof.a * proof.b), u));

    return r255.equals(lhs, rhs);
}

/* ---------------- range proof ---------------- */

/**
 * The bit decomposition both range provers start from.
 *
 * ⭐ ONE COPY: it was duplicated between prove_range and an old callback
 *   prover, which had to produce IDENTICAL vectors, and two copies is how
 *   one gets a correction and the other does not. There is one prover now.
 *
 * ⚠ A divergence here would be silent: both would still produce well-formed
 *   proofs, under different commitments, and only the cross-check would show
 *   it.
 */
function bit_vectors(values, bits, m) {
    var aL = [], aR = [];
    for (var j = 0; j < m; j++) {
        for (var b = 0; b < bits; b++) {
            var bit = (values[j] >> BigInt(b)) & 1n;
            aL.push(bit);
            aR.push(scalar_mod(bit - 1n));
        }
    }
    return { aL: aL, aR: aR };
}

/** The proof object both provers assemble. */
function assemble_proof(V, A, S, T1, T2, tau_x, mu, t_hat, ip, bits, m) {
    return {
        commitments: V.map(r255.encode),
        proof: {
            A: r255.encode(A), S: r255.encode(S),
            T1: r255.encode(T1), T2: r255.encode(T2),
            tau_x: r255.scalar_bytes(tau_x),
            mu: r255.scalar_bytes(mu),
            t_hat: r255.scalar_bytes(t_hat),
            L: ip.L.map(r255.encode), R: ip.R.map(r255.encode),
            a: r255.scalar_bytes(ip.a), b: r255.scalar_bytes(ip.b),
            bits: bits, m: m
        }
    };
}

/**
 * Prove that each of `values` lies in [0, 2^bits).
 *
 * AGGREGATION IS NEARLY FREE: proving m values costs one extra group element
 * per doubling of m, not one proof each. That is why confidential
 * transactions aggregate all their outputs into a single proof.
 *
 * @param {Array<bigint>}  values     each must already be in range
 * @param {Array<bigint>}  blindings  the Pedersen blinding of each commitment
 * @param {number}         bits       a power of two, at most 64
 * @param {function}       [rng]      n => n random bytes; omitted or null
 *                                    draws fresh ones from the platform
 * @return {{proof: object, commitments: Array<Uint8Array>}}
 */
export function prove_range(values, blindings, bits, rng) {
    rng = require_rng('bulletproofs.prove_range', rng);
    return finish_task(prove_range_task(values, blindings, bits, rng));
}

/**
 * prove_range as a task (commons/task.js): its ten msms in sequence, a
 * window a step, each depending on the last through the transcript - about
 * 890 ms at 32 bits in one piece otherwise, nearly all of it msm.
 *
 * ⚠ THE RNG ORDER IS PART OF THE CONTRACT: alpha, then sL/sR pairwise, then
 *   rho, then tau1 and tau2 (range_core) - the same draws, in the same order,
 *   as before the prover was a task, so the same rng gives the same proof.
 */
export function prove_range_task(values, blindings, bits, rng) {
    rng = require_rng('bulletproofs.prove_range_task', rng);
    var st = range_setup(values, blindings, bits);
    var gen = st.gen, H = st.H;
    var alpha = r255.scalar_from_uniform_bytes(rng(64));

    return then_task(msm_secret_sum_task(st.aL, gen.g, st.aR, gen.h), function (a_sum) {
        var A = r255.add(a_sum, r255.mul(alpha, H));
        var sv = blinding_vectors(st.n, rng);
        return then_task(msm_secret_sum_task(sv.sL, gen.g, sv.sR, gen.h), function (s_sum) {
            var S = r255.add(s_sum, r255.mul(sv.rho, H));
            var c = range_core(st, A, S, alpha, sv, blindings, rng);
            return then_task(h_prime_task(gen.h, c.y_inv), function (hp) {
                return map_task(ip_prove_task(st.T, gen.g.slice(), hp, c.u, c.l.slice(), c.r.slice()), function (ip) {
                    return assemble_proof(st.V, A, S, c.T1, c.T2, c.tau_x, c.mu, c.t_hat, ip, bits, st.m);
                });
            });
        });
    });
}

/*
 * ==================== THE PARTS BOTH PROVERS SHARE ====================
 *
 * ⭐ prove_range and an old callback prover held the same seventy lines
 *   twice; they were split out here, and there is one prover now
 *   (prove_range_task).
 *
 * ⚠ THE RNG ORDER IS PART OF THE CONTRACT: alpha, then sL/sR pairwise,
 *   then rho, then tau1 and tau2 - fixed here, in one place.
 */

/** Validate, commit, open the transcript, and decompose into bits. */
function range_setup(values, blindings, bits) {
    var m = values.length;
    if (m === 0) { throw new Error('bulletproofs: no values'); }
    if ((m & (m - 1)) !== 0) { throw new Error('bulletproofs: aggregate size must be a power of two'); }
    if ((bits & (bits - 1)) !== 0 || bits > 64) {
        throw new Error('bulletproofs: bits must be a power of two, at most 64');
    }

    var n = bits * m;
    var gen = generators(n);
    var G = r255.BASE, H = gen.H;

    for (var q = 0; q < m; q++) {
        if (values[q] < 0n || values[q] >= (1n << BigInt(bits))) {
            throw new Error('bulletproofs: value out of range');
        }
    }

    var V = values.map(function (v, i) {
        return r255.add(r255.mul(scalar_mod(v), G), r255.mul(scalar_mod(blindings[i]), H));
    });

    var T = transcript('range');
    T.append('bits', be16(bits));
    T.append('m', be16(m));
    for (var i = 0; i < m; i++) { T.append_point('V', V[i]); }

    /* aL is the bit decomposition of every value, concatenated; aR = aL - 1 */
    var bv = bit_vectors(values, bits, m);
    return { m: m, n: n, bits: bits, gen: gen, G: G, H: H, V: V, T: T, aL: bv.aL, aR: bv.aR };
}

/** sL, sR and rho - drawn pairwise, as both provers always have. */
function blinding_vectors(n, rng) {
    var sL = [], sR = [];
    for (var k = 0; k < n; k++) {
        sL.push(r255.scalar_from_uniform_bytes(rng(64)));
        sR.push(r255.scalar_from_uniform_bytes(rng(64)));
    }
    return { sL: sL, sR: sR, rho: r255.scalar_from_uniform_bytes(rng(64)) };
}

/**
 * From A and S to the vectors the inner-product argument runs on: the y and z
 * challenges, T1 and T2, x, and w.
 */
function range_core(st, A, S, alpha, sv, blindings, rng) {
    var T = st.T, n = st.n, m = st.m, bits = st.bits, G = st.G, H = st.H;
    var aL = st.aL, aR = st.aR;

    T.append_point('A', A);
    T.append_point('S', S);
    var y = T.challenge('y');
    var z = T.challenge('z');

    var yn = powers(y, n);
    var y_inv = powers(scalar_inv(y), n);
    var two = powers(2n, bits);

    /* l(X) = aL - z*1 + sL*X,  r(X) = y^n o (aR + z*1 + sR*X) + z^2 * 2^n */
    var z_vec = new Array(n).fill(z);
    var l0 = vec_sub(aL, z_vec);
    var l1 = sv.sL;

    var zsq_two = new Array(n).fill(0n);
    for (var jj = 0; jj < m; jj++) {
        var zpow = scalar_pow(z, BigInt(jj + 2));
        for (var bb = 0; bb < bits; bb++) {
            zsq_two[jj * bits + bb] = scalar_mod(zpow * two[bb]);
        }
    }
    var r0 = vec_add(vec_hadamard(yn, vec_add(aR, z_vec)), zsq_two);
    var r1 = vec_hadamard(yn, sv.sR);

    var t1 = scalar_mod(inner_product(l0, r1) + inner_product(l1, r0));
    var t2 = inner_product(l1, r1);

    var tau1 = r255.scalar_from_uniform_bytes(rng(64));
    var tau2 = r255.scalar_from_uniform_bytes(rng(64));
    var T1 = r255.add(r255.mul(scalar_mod(t1), G), r255.mul(tau1, H));
    var T2 = r255.add(r255.mul(scalar_mod(t2), G), r255.mul(tau2, H));

    T.append_point('T1', T1);
    T.append_point('T2', T2);
    var x = T.challenge('x');

    var l = vec_add(l0, vec_scalar_mul(l1, x));
    var r = vec_add(r0, vec_scalar_mul(r1, x));
    var t_hat = inner_product(l, r);

    /* the blinding of t_hat folds in each commitment's blinding, weighted by
       z^(j+2) - which is what binds the proof to those exact commitments */
    var tau_x = scalar_mod(tau2 * x * x + tau1 * x);
    for (var jz = 0; jz < m; jz++) {
        tau_x = scalar_mod(tau_x + scalar_pow(z, BigInt(jz + 2)) * blindings[jz]);
    }
    var mu = scalar_mod(alpha + sv.rho * x);

    T.append_scalar('tau_x', tau_x);
    T.append_scalar('mu', mu);
    T.append_scalar('t_hat', t_hat);
    var w = T.challenge('w');

    var u = r255.mul(w, r255.hash_to_group(new Uint8Array(0), ascii('cryptographic-primitives/bp/u')));

    return { T1: T1, T2: T2, tau_x: tau_x, mu: mu, t_hat: t_hat, l: l, r: r, y_inv: y_inv, u: u };
}

/*
 * The inner-product argument runs against generators h' = y^-i o h, which
 * is what lets the two vectors l and r be checked as a single inner product
 * rather than as two separate commitments. n full multiplications - about
 * 300 ms at 32 bits - so a task, one multiplication a step.
 */
function h_prime_task(h, y_inv) {
    var out = [];
    return {
        step: function () {
            if (out.length < h.length) { out.push(r255.mul(y_inv[out.length], h[out.length])); }
            return out.length === h.length;
        },
        result: function () { return out; }
    };
}

/*
 * A scalar ARRIVING IN THE PROOF: 32 bytes, canonical (below L), or null.
 *
 * ⛔ It used to be scalar_from_uniform_bytes, which REDUCED - so s and s + L
 *   decoded alike (a second encoding of every proof) - and which, once it
 *   started refusing inputs shorter than 48 bytes, made every verification
 *   throw. A received scalar is decoded, never reduced.
 */
var s_from_bytes = r255.scalar_from_canonical_bytes;

/**
 * @param  {Array<Uint8Array>} commitments
 * @return {boolean}
 */
/*
 * ⭐ VERIFICATION USES THE VARIABLE-TIME MULTIPLY THROUGHOUT.
 *
 *   Every scalar here comes from the proof itself or from a Fiat-Shamir
 *   challenge - a hash of published commitments. There is nothing to hide
 *   from anyone who can time this, because they already have all of it.
 *
 *   53 constant-time ladders ran per verification, one per generator among
 *   other things. wNAF at width 5 measured 0.70 ms against 1.57 for the
 *   ladder on this curve.
 *
 * ⛔ prove_range KEEPS THE LADDER, and must. Its scalars include the values
 *   being proved and the blinding factors alpha, rho, tau_x and mu - a
 *   timing signal on any of those breaks the hiding property the proof
 *   exists to provide.
 *
 * ⚠ THE TWO RETURN IDENTICAL POINTS. Nothing distinguishes a wrong choice
 *   except reading which function it is in, which is why this note sits at
 *   the boundary rather than at each call.
 */
export function verify_range(commitments, proof) {
    /* a verifier answers; malformed input is a false, not an exception */
    try { return verify_range_unsafe(commitments, proof); } catch (e) { return false; }
}

function verify_range_unsafe(commitments, proof) {
    var m = proof.m, bits = proof.bits;
    if (commitments.length !== m) { return false; }
    if ((m & (m - 1)) !== 0 || (bits & (bits - 1)) !== 0 || bits > 64) { return false; }

    var n = bits * m;
    var gen = generators(n);
    var G = r255.BASE, H = gen.H;

    var V = [];
    for (var i = 0; i < m; i++) {
        var P = r255.decode(commitments[i]);
        if (!P) { return false; }
        V.push(P);
    }
    var A = r255.decode(proof.A), S = r255.decode(proof.S);
    var T1 = r255.decode(proof.T1), T2 = r255.decode(proof.T2);
    if (!A || !S || !T1 || !T2) { return false; }

    var tau_x = s_from_bytes(proof.tau_x);
    var mu = s_from_bytes(proof.mu);
    var t_hat = s_from_bytes(proof.t_hat);
    if (tau_x === null || mu === null || t_hat === null) { return false; }

    var T = transcript('range');
    T.append('bits', be16(bits));
    T.append('m', be16(m));
    for (var v = 0; v < m; v++) { T.append_point('V', V[v]); }
    T.append_point('A', A);
    T.append_point('S', S);
    var y = T.challenge('y');
    var z = T.challenge('z');
    T.append_point('T1', T1);
    T.append_point('T2', T2);
    var x = T.challenge('x');

    var yn = powers(y, n);
    var y_inv = powers(scalar_inv(y), n);
    var two = powers(2n, bits);

    /* delta(y,z) = (z - z^2)*<1,y^n> - sum_j z^(j+3) * <1, 2^n> */
    var sum_y = 0n;
    for (var a = 0; a < n; a++) { sum_y = scalar_mod(sum_y + yn[a]); }
    var sum_two = 0n;
    for (var b2 = 0; b2 < bits; b2++) { sum_two = scalar_mod(sum_two + two[b2]); }

    var zsq = scalar_mod(z * z);
    var delta = scalar_mod((z - zsq) * sum_y);
    for (var j = 0; j < m; j++) {
        delta = scalar_mod(delta - scalar_pow(z, BigInt(j + 3)) * sum_two);
    }

    /*
     * CHECK 1: t_hat*G + tau_x*H must equal
     *          sum_j z^(j+2) * V_j + delta*G + x*T1 + x^2*T2
     *
     * THIS IS THE CHECK THAT ENFORCES THE RANGE. delta encodes what the inner
     * product must be if every bit of every value really is a bit; a value
     * outside [0, 2^bits) cannot produce vectors satisfying it.
     */
    var lhs1 = r255.add(r255.mul_vartime(t_hat, G), r255.mul_vartime(tau_x, H));
    var rhs1 = r255.mul_vartime(delta, G);
    for (var jv = 0; jv < m; jv++) {
        rhs1 = r255.add(rhs1, r255.mul_vartime(scalar_pow(z, BigInt(jv + 2)), V[jv]));
    }
    rhs1 = r255.add(rhs1, r255.add(r255.mul_vartime(x, T1), r255.mul_vartime(scalar_mod(x * x), T2)));
    if (!r255.equals(lhs1, rhs1)) { return false; }

    T.append_scalar('tau_x', tau_x);
    T.append_scalar('mu', mu);
    T.append_scalar('t_hat', t_hat);
    var w = T.challenge('w');

    /* CHECK 2: the inner-product argument, against the reconstructed P */
    var hp = gen.h.map(function (P2, i2) { return r255.mul_vartime(y_inv[i2], P2); });
    var u = r255.mul_vartime(w, r255.hash_to_group(new Uint8Array(0), ascii('cryptographic-primitives/bp/u')));

    /* P = A + x*S - mu*H + <-z, g> + <z*y^n + z^(j+2)*2^n, h'> */
    var neg_z = new Array(n).fill(scalar_mod(-z));
    var hp_exp = new Array(n);
    for (var jj = 0; jj < m; jj++) {
        var zp = scalar_pow(z, BigInt(jj + 2));
        for (var bb = 0; bb < bits; bb++) {
            var idx = jj * bits + bb;
            hp_exp[idx] = scalar_mod(z * yn[idx] + zp * two[bb]);
        }
    }

    var P = r255.add(A, r255.mul_vartime(x, S));
    P = r255.sub(P, r255.mul_vartime(mu, H));
    P = r255.add(P, msm(neg_z, gen.g));
    P = r255.add(P, msm(hp_exp, hp));
    P = r255.add(P, r255.mul_vartime(t_hat, u));

    var Ls = proof.L.map(r255.decode);
    var Rs = proof.R.map(r255.decode);
    for (var li = 0; li < Ls.length; li++) { if (!Ls[li] || !Rs[li]) { return false; } }

    var a = s_from_bytes(proof.a), b = s_from_bytes(proof.b);
    if (a === null || b === null) { return false; }
    return ip_verify(T, gen.g, hp, u, P, { L: Ls, R: Rs, a: a, b: b }, n);
}

/** The proof's size in bytes, for budgeting. */
export function proof_size(proof) {
    return 4 * 32 + 3 * 32 + (proof.L.length + proof.R.length) * 32 + 2 * 32;
}

