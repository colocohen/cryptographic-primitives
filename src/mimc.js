/**
 * MiMC  -  the first hash designed to be cheap inside a circuit
 *
 * MiMC came before Poseidon and shares its goal: minimise MULTIPLICATIONS in
 * an arithmetic circuit rather than instructions on a CPU. It is simpler and
 * older, and it is still in production because contracts deployed years ago
 * cannot change their hash.
 *
 * THE ENTIRE ROUND IS ONE LINE:
 *
 *     x  <-  (x + k + c_i)^7
 *
 * No S-box tables, no matrix, no state array. Security comes from raising to
 * a power that has no low-degree inverse over the field, repeated 91 times.
 *
 * WHY 7 AND WHY 91. The exponent must be coprime to p-1 so that the map is a
 * permutation; for BN254's scalar field 3 is not coprime and 5 has a
 * structure the designers avoided, leaving 7. The round count is then set so
 * that the algebraic degree exceeds what a Groebner basis attack can handle -
 * 91 is ceil(log_7(p)), which is the paper's requirement rather than a
 * margin.
 *
 * MiMC VERSUS POSEIDON:
 *
 *     MiMC       ~91 constraints for one field element. Simplest possible
 *                design, longest history, still used by Tornado Cash and
 *                other deployed contracts.
 *     Poseidon   ~250 constraints but absorbs several elements at once, so
 *                per input it is cheaper. What new work uses.
 *
 * A Merkle tree is the usual comparison: MiMC hashes two elements with two
 * calls plus a combine; Poseidon takes both in one permutation.
 *
 * THE CONSTANTS ARE DERIVED, NOT SHIPPED. They are iterated Keccak-256 of the
 * ASCII string "mimc", which is a nothing-up-my-sleeve construction in the
 * same spirit as Brainpool's curves from pi. The derivation is checked
 * against circomlib's values by the test suite.
 */

import { BN254_FR, pow5 as F_pow5, pow7 as F_pow7 } from './commons/modp.js';
import { field } from './commons/modp.js';
import { keccak256 } from './sha3.js';
import { ascii, bytes_to_bigint } from './commons/bytes.js';

/** BN254's scalar field, the same one Poseidon uses and for the same reason. */
export var P = BN254_FR;

var F = /* @__PURE__ */ field(P);
var N_ROUNDS = 91;

/**
 * The round constants: Keccak-256 applied repeatedly to "mimc".
 *
 * c[0] IS ZERO and the chain starts from keccak("mimc") for c[1] - an
 * asymmetry that looks like an off-by-one and is what circomlib does, so it
 * is what every deployed contract expects.
 */
/*
 * ⭐ ONE CHAIN, TWO SEEDS. MiMC7 and MiMC-Sponge derive their constants the
 *   same way and differ only in the seed string and the count, so the chain
 *   is written once here; it used to be two copies of this loop.
 */
function keccak_chain(seed, n) {
    var cts = new Array(n);
    cts[0] = 0n;
    var c = keccak256(ascii(seed));
    for (var i = 1; i < n; i++) {
        c = keccak256(c);
        cts[i] = bytes_to_bigint(c) % P;
    }
    return cts;
}

var CONSTANTS = /* @__PURE__ */ keccak_chain('mimc', N_ROUNDS);

/* x^7 - four multiplications, and the only non-linear step. Shared with
   poseidon.js's x^5; both live in commons/modp.js. */
function pow7(x) { return F_pow7(F, x); }

/**
 * MiMC7's block function: encrypt x under key k.
 *
 * @param  {bigint} x
 * @param  {bigint} k
 * @return {bigint}
 */
export function mimc7(x, k) {
    var xi = F.mod(x), ki = F.mod(k);
    var r = 0n;
    for (var i = 0; i < N_ROUNDS; i++) {
        var t = (i === 0) ? F.add(xi, ki) : F.add(F.add(r, ki), CONSTANTS[i]);
        r = pow7(t);
    }
    return F.add(r, ki);
}

/**
 * Hash a list of elements by chaining the block function.
 *
 * Each element is absorbed with the running value as its key - a
 * Miyaguchi-Preneel style construction, which is what turns a keyed
 * permutation into a hash.
 *
 * @param  {Array<bigint>} inputs
 * @param  {bigint}        [key=0]
 * @return {bigint}
 */
export function mimc7_multi(inputs, key) {
    var r = F.mod(key === undefined ? 0n : key);
    for (var i = 0; i < inputs.length; i++) {
        var x = F.mod(inputs[i]);
        r = F.add(F.add(r, x), mimc7(x, r));
    }
    return r;
}

/* ---------------- MiMC-Sponge ---------------- */

/*
 * The sponge variant, which is what circomlib's `mimcSponge` implements and
 * what several deployed contracts call.
 *
 * It differs from MiMC7 in three ways that all matter for compatibility: the
 * exponent is 5 rather than 7, there are 220 rounds rather than 91, and the
 * state is a Feistel pair rather than a single value. The seed string is
 * "mimcsponge", so the constants are a different chain entirely.
 */
var SPONGE_ROUNDS = 220;

var SPONGE_CONSTANTS = /* @__PURE__ */ (function () {
    var cts = keccak_chain('mimcsponge', SPONGE_ROUNDS);
    /* the LAST constant is zero as well, which is part of the specification
       and not a truncation of the chain */
    cts[SPONGE_ROUNDS - 1] = 0n;
    return cts;
}());

function pow5(x) { return F_pow5(F, x); }

/**
 * The Feistel permutation on a pair.
 *
 * @return {{xL: bigint, xR: bigint}}
 */
export function mimc_feistel(xL_in, xR_in, k) {
    var xL = F.mod(xL_in), xR = F.mod(xR_in), ki = F.mod(k);
    for (var i = 0; i < SPONGE_ROUNDS; i++) {
        var t = (i === 0) ? F.add(ki, xL) : F.add(F.add(ki, xL), SPONGE_CONSTANTS[i]);
        var xT = pow5(t);
        if (i < SPONGE_ROUNDS - 1) {
            var tmp = xL;
            xL = F.add(xR, xT);
            xR = tmp;
        } else {
            /* the final round does NOT swap - dropping that makes the
               permutation its own inverse, which it must not be */
            xR = F.add(xR, xT);
        }
    }
    return { xL: xL, xR: xR };
}

/**
 * The sponge hash: absorb every input, then squeeze `n_outputs` values.
 *
 * @param  {Array<bigint>} inputs
 * @param  {number}        n_outputs
 * @param  {bigint}        [key=0]
 * @return {Array<bigint>}
 */
export function mimc_sponge(inputs, n_outputs, key) {
    var k = F.mod(key === undefined ? 0n : key);
    var S = { xL: 0n, xR: 0n };

    for (var i = 0; i < inputs.length; i++) {
        S = mimc_feistel(F.add(S.xL, F.mod(inputs[i])), S.xR, k);
    }

    var out = [S.xL];
    for (var j = 1; j < n_outputs; j++) {
        S = mimc_feistel(S.xL, S.xR, k);
        out.push(S.xL);
    }
    return out;
}

/** The common case: several inputs, one output. */
export function mimc_sponge_hash(inputs, key) {
    return mimc_sponge(inputs, 1, key)[0];
}
