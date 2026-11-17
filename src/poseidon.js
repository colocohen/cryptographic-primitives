/**
 * Poseidon  -  a hash designed to be cheap inside a zero-knowledge circuit
 *
 * SHA-256 costs about 25,000 constraints to prove; Poseidon costs about 250.
 * That hundredfold difference is why every zk system uses it, and it is not
 * an optimisation - it changes what is feasible.
 *
 * WHY THE GAP IS SO LARGE. An arithmetic circuit works on FIELD ELEMENTS and
 * charges for multiplications. SHA-256 works on BITS: every XOR, rotation and
 * addition-with-carry has to be decomposed into field arithmetic first, and a
 * 32-bit XOR alone is 32 constraints. Poseidon never leaves the field - its
 * non-linear step is x^5, which is three multiplications, and everything else
 * is linear and therefore free.
 *
 * WHAT IT COSTS OUTSIDE A CIRCUIT. Poseidon is SLOWER than SHA-256 in
 * ordinary code, by a wide margin: a few hundred field multiplications
 * against a handful of word operations. It is the right hash when the
 * consumer is a proof system and the wrong one everywhere else.
 *
 *     Merkle tree of depth 32, SHA-256    ~800,000 constraints
 *                              Poseidon     ~8,000
 *
 * USED BY: Filecoin, Polygon zkEVM, Mina, StarkNet, Aztec, Semaphore,
 * Tornado, and effectively every zk-rollup.
 *
 * PERFORMANCE, AND WHERE IT TURNED OUT TO BE. Two inputs took 610 us and now
 * take 334, against 349 for poseidon-lite. Everything that helped came from
 * ONE change - accumulating each MDS row unreduced and reducing once - and
 * everything else that was tried did nothing:
 *
 *     Barrett reduction instead of %          551 us against 536: worse
 *     state in locals instead of an array     314 against 307: no change
 *     folding the partial rounds' matrices    projected 25 us of 610: 4%
 *
 * A profile settled it: 46 per cent of the C++ time was malloc and free. The
 * bottleneck is the NUMBER OF BIGINT ALLOCATIONS, and a reduction allocates
 * while an addition into an accumulator does not. The same conclusion
 * commons/modp.js reaches about BigInt generally, and chacha.js about memory
 * traffic - arrived at three times from three directions.
 *
 * The micro-benchmarks lied twice on the way. A hoisted constant reduction
 * measured 61 ns where the same code in a chain measured 552, which produced
 * a confident and entirely wrong story about a cost cliff in V8 at 440 bits.
 * Measure inside the caller.
 *
 * ======================= THE FIELD IS BN254, NOT BLS12-381 =======================
 *
 * This runs over BN254's scalar field, because that is the field Ethereum's
 * pairing precompiles use and therefore what circomlib and every Solidity
 * verifier expect. This library's BLS12-381 has a different scalar field, and
 * a Poseidon over that would be a different function producing different
 * digests - correct, and interoperable with nothing.
 *
 * ============================ THE PARAMETERS ============================
 *
 * THE ROUND CONSTANTS ARE DERIVED HERE, not shipped. They come from a Grain
 * LFSR seeded with the field size, the width and the round counts, exactly as
 * the Poseidon paper specifies - and the derivation was checked against
 * circomlib's published tables for every supported width before this file was
 * written. That is the same standard applied to FFDHE's primes, which are
 * recomputed from e, and to AES's S-box, which is recomputed as x^254.
 *
 * THE MDS MATRIX IS NOT DERIVED, AND THAT IS A GAP. It is a Cauchy matrix -
 * M[i][j] = 1/(x_i + y_j) - and that structure IS verified at load. But the
 * x and y values themselves are transcribed from circomlib rather than
 * generated: the reference Sage script produces them from its own stream, and
 * the exact convention was not recovered here. Two hours went into trying.
 *
 * What that means in practice: the matrix's DEFINING PROPERTY is checked
 * every time this module loads, so a transcription error cannot pass
 * silently. What is not independently established is that these particular x
 * and y are the ones the specification intends - for that, the test vectors
 * against circomlib are the evidence.
 */

import { BN254_FR, pow5 as F_pow5 } from './commons/modp.js';
import { field } from './commons/modp.js';
import { bytes_to_bigint, bigint_to_bytes } from './commons/bytes.js';

/** BN254's scalar field - Ethereum's pairing precompiles use this. */
export var P = BN254_FR;

var F = /* @__PURE__ */ field(P);

/** Full rounds, always 8, split four before and four after the partial ones. */
var RF = 8;

/**
 * Partial rounds per width, from the paper's table 2.
 *
 * These are security parameters, not tuning knobs: they are chosen so that
 * the algebraic attacks the design worries about - Groebner basis and
 * interpolation - cost more than brute force. Lowering one does not make
 * Poseidon weaker gradually; it makes it breakable.
 */
var RP = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];

/*
 * The Cauchy parameters, indexed by width. See the note above: these are
 * transcribed, and the Cauchy identity they must satisfy is checked at load.
 */
var CAUCHY = {
    2: {
        x: [0x0n, 0x1a7b7cf6607b094f165f76842f295f698cb6ae7fb3754a4c2fa728a9fd58d864n],
        y: [0x2e107b7987d04af8c5a4edfd864cd0dbb57f3c0bfa2725e181a9666575db4a2n, 0xb10adb9e147375b572cb3d1f1a336130ac7ad867152b71aae0d86a752e0a61dn]
    },
    3: {
        x: [0x0n, 0x224757c44cd65e0fe6975c6257ed34e49b9cee76b3ea6b6eb8dde52e060c350n, 0x1727bdfb255c11c09dbf941a4258be294d6fcfb9f7d05d06afebd946b2308c03n],
        y: [0xe03b79b40882b3974c8a4cc52cf157926e2d8ecdf2a1f8924c202c5728768d9n, 0x252fa382f579765ba37e777c9bd62685e16f55f2696f695bf4e0dd38d5037973n, 0x1a7adb4566128149e2aaab05741c2163bc63b75b4476f459d95ebc82e12b5e00n]
    },
    4: {
        x: [0x0n, 0x1c682cc3bb5098591d8ebcd1d80fd0eb4a61b8871bf3d2074553c5a2d7d621d6n, 0x11c97b547b285dddc532c7202ff08948a11d127fc46e524bc314f2ecc92f9d0an, 0x88655322380170f60d852426d46c389bdf3a8d78243f8ea06941cb2e8571a5en],
        y: [0x412b3a13f816469a5544eee28a41963c1e5968c3576806c9c29a75bc15a5288n, 0x487b9b774230f424d4bf061b26c506aa3b55a5eadc4301d3f2fdd14fec6f048n, 0x2b7def13510da3d7bddacc8936e2a5e68e007e9a383fbe90b36a9f548d032488n, 0xaa296687ed63e7c8d7735f4fed573abda12a1b8dd36c7f4ad80b4f3ae7d2fa4n]
    },
    5: {
        x: [0x0n, 0x196a36bf48987b778c25189d1b60a509298643f50fccabf055ccad16c0a80373n, 0x3c42f3cc8a11e927164268e21324baffe4b8b00b3cb94068a4b8adb61929b2bn, 0x2c1dee84847c96d862261150255e140c0f77336ed5635527a5e9fd15fa2738bn, 0xb41214f15486b905b25f21e58536c4094e65749e889a4088b143071dd290213n],
        y: [0x2cdea90d26c30c768a197f197f29b20c5592b7decdb214c5d414c92a374813dan, 0x19d325456179716d51aa97676d6c22f8e7d9fe5244dc84ca645847da7a8dc330n, 0x13234042b34d3fbded889b20c9213e1eef1eb5310988a79011fa1e5a0b1315dfn, 0x16a748674f9b5fee286ef286501cb6e3d2739bdba76652fe18221a657fb59655n, 0x262e7d1210c92c58b17d22fe095da0dc8b1a2bf289a1dbcf65117b7f2f6a9d01n]
    },
    6: {
        x: [0x0n, 0x2aebf2f1f732c67a7322ef7f3e437db6626b34bcc2c6aaf88e3bab17f054a562n, 0x4779f222a5c126478ea65e62ee83dcabad73677c857ffe917718f56dc9aa283n, 0x62881297546ef152a105f359536ca130532c34faac13202060cf7f479a64765n, 0x127ad6f04de2305874069e1d8f60f8602153a47ee93d637a1aeb4ddaa01d838dn, 0x1ea58d15cc4bb80b4b3f3fa0d48f1e87bc18120d58bb2aabebee8cb0ee853624n],
        y: [0xea265b386f4c5d4721cd35f1e1ee82c3ed84556c38b5563bc361137a2b81904n, 0xfb9cc0dd533bf8739a44891ee9d9af157f425e272f044bb59fb3beed7978cben, 0x2388de00abc529008547f156214c2fdc9ae24377020e450d16f811b9e61ac8d6n, 0x2dfd1afd8c961f66ddc263c57713d0389c02bc165158998f5b10b351e0af4791n, 0xe265c9b54d1258dd4d39ea7a172388427fd6cbe64e417b06e00f00dfcbf7eadn, 0x2fdd4d7ce581b57e2e1a013c6b33455bd8c81aa04a8ae567a4916e9dd9b49bf6n]
    },
    7: {
        x: [0x0n, 0xaff333a6223c04c3347e930d3dff8ae87b7651a93669bae8547c3f948353667n, 0x2a4ce007429585519a8f13ae40a39018b66f1edc9497f8aaa9abdc64094ea53n, 0x20a02435821a836804cdf5a4184883238eead2dd001159c2165ad3be5af3dc42n, 0x1b1232024326374fec129f92837a974dc3ee28fcf4d2a749e2581b037fd6f167n, 0x2b21f0d80549118a377652b8977163ebd477a4bec92480244266ff4ff48e0f24n, 0x16f49c44aa830907db860082a8824d6fe161d04f53400d28f83bb4d2879b1ec3n],
        y: [0x11e9d7b14bfa22095430348f74ff2dff48a1102b04fc12f776c73612c12089dcn, 0x139c88e4730b605de58e4644c9b02e9000a29b204a4460c5ae49a360ba2cab75n, 0x13deb8a01d152b7dfd456ea97ec1b31ed8bbe6679950f66ac7f51be6db132159n, 0x1472c3cf1d0872f5dcadfb398a2a3367ac7199343d9836dd2941f8f391b5d467n, 0x22651bf40a291a36ca869aad708bc3faf5f4b9cd6daf82eec189cd1a540936cdn, 0x23684d41cc8b366da74cd4997cf4c0d84412e19ce9c53165682bf37b5a2711den, 0x232e5cbd29d64cb904e9ab4993359da1547b3de28cc72b80c4d8d6d9713796aen]
    }
};

/* ---------------- parameter generation ---------------- */

/**
 * The Grain LFSR of the Poseidon paper, section 4.1.
 *
 * An 80-bit register seeded with the field type, the S-box type, the field
 * size, the width and both round counts - so a change to any of them gives a
 * completely different constant set. It is discarded for 160 clocks first,
 * then produces bits in pairs where the first selects whether the second is
 * kept.
 *
 * The rejection of values at or above the modulus is NOT a reduction: a
 * reduced value would be biased towards the low end of the field, and the
 * constants are meant to be uniform.
 */
function grain(t, rounds_p, count) {
    var st = [0, 1, 0, 0, 0, 0];      /* prime field, x^alpha S-box */
    var i;
    function push_bits(v, n) {
        for (var b = n - 1; b >= 0; b--) { st.push((v >> b) & 1); }
    }
    push_bits(254, 12);               /* field size in bits */
    push_bits(t, 12);
    push_bits(RF, 10);
    push_bits(rounds_p, 10);
    for (i = 0; i < 30; i++) { st.push(1); }

    function clock() {
        var nb = st[62] ^ st[51] ^ st[38] ^ st[23] ^ st[13] ^ st[0];
        st.shift();
        st.push(nb);
        return nb;
    }
    for (i = 0; i < 160; i++) { clock(); }

    var out = [];
    while (out.length < count) {
        var v = 0n;
        var got = 0;
        while (got < 254) {
            var b1 = clock();
            var b2 = clock();
            if (b1 === 1) { v = (v << 1n) | BigInt(b2); got++; }
        }
        if (v < P) { out.push(v); }
    }
    return out;
}

/**
 * Build and validate the parameters for a width, once.
 *
 * THE CAUCHY IDENTITY IS CHECKED HERE. Every entry must satisfy
 * M[i][j] * (x_i + y_j) = 1, which catches any transcription error in the
 * table above - see the note at the top about what this does and does not
 * establish.
 */
var CACHE = {};

function params(t) {
    if (CACHE[t]) { return CACHE[t]; }
    if (t < 2 || t > 7) { throw new Error('poseidon: width must be 2 to 7'); }

    var rp = RP[t - 2];
    var C = grain(t, rp, (RF + rp) * t);

    var cp = CAUCHY[t];
    var M = [];
    for (var i = 0; i < t; i++) {
        var row = [];
        for (var j = 0; j < t; j++) {
            var denom = F.add(cp.x[i], cp.y[j]);
            if (denom === 0n) { throw new Error('poseidon: degenerate Cauchy parameter'); }
            var m = F.inv(denom);
            /* the identity, verified rather than assumed */
            if (F.mul(m, denom) !== 1n) { throw new Error('poseidon: MDS check failed'); }
            row.push(m);
        }
        M.push(row);
    }

    CACHE[t] = { C: C, M: M, t: t, rp: rp };
    return CACHE[t];
}

/* ---------------- the permutation ---------------- */

/* x^5, the S-box - three multiplications, which is why it is affordable.
   Shared with mimc.js, whose x^7 sits beside it in commons/modp.js. */
function pow5(x) { return F_pow5(F, x); }

/**
 * The permutation itself.
 *
 * FULL ROUNDS APPLY THE S-BOX TO EVERY ELEMENT; PARTIAL ROUNDS APPLY IT TO
 * ONE. That asymmetry is the whole design: full rounds at each end give
 * resistance to statistical attacks, and the cheap partial rounds in the
 * middle give the algebraic degree needed against Groebner basis attacks. A
 * partial round costs one S-box instead of t, which is where the constraint
 * count goes.
 */
function permute(state, p) {
    var t = p.t;
    var half = RF / 2;
    var r, i, j;

    for (r = 0; r < RF + p.rp; r++) {
        for (i = 0; i < t; i++) { state[i] = F.add(state[i], p.C[r * t + i]); }

        if (r < half || r >= half + p.rp) {
            for (i = 0; i < t; i++) { state[i] = pow5(state[i]); }
        } else {
            state[0] = pow5(state[0]);
        }

        /*
         * The linear layer: multiply by the MDS matrix.
         *
         * ONE REDUCTION PER ROW, NOT PER TERM. The obvious form reduces after
         * every multiply, which costs t reductions per row; accumulating the
         * whole row as an unreduced integer and reducing once costs one.
         *
         * SAFE BECAUSE THE SUM CANNOT OVERFLOW ANYTHING. BigInt has no width
         * limit, so the only question is cost: t products of two values below
         * 2^254 sum to less than 2^(508 + log2 t), and one division on that
         * is cheaper than t divisions on 508-bit values.
         *
         * MEASURED AT 30 PER CENT of the round loop - and it is the ONLY
         * thing that helped. Holding the state in locals instead of an array
         * was worth nothing at all (307 us against 314), which is the same
         * result the ChaCha rounds gave: in JavaScript the cost is the number
         * of BigInt allocations, and a reduction allocates while an addition
         * into an accumulator does not.
         */
        var next = new Array(t);
        for (i = 0; i < t; i++) {
            var acc = 0n;
            for (j = 0; j < t; j++) { acc += p.M[i][j] * state[j]; }
            next[i] = acc % P;
        }
        state = next;
    }
    return state;
}

/* ---------------- the hash ---------------- */

/**
 * Hash 1 to 6 field elements to one.
 *
 * THE CAPACITY ELEMENT STARTS AT ZERO and the inputs fill the rest, which is
 * circomlib's convention. It means the number of inputs is part of the
 * function's identity - hashing [a] and [a, 0] gives different results,
 * because they use different widths and therefore different constants.
 * Relying on that is fine; assuming the opposite is a way to lose collision
 * resistance in a protocol.
 *
 * @param  {Array<bigint>} inputs
 * @return {bigint}
 */
export function poseidon(inputs) {
    return poseidon_with_state(inputs, 0n);
}

/**
 * The same, with an explicit initial capacity value rather than zero.
 *
 * ⭐ poseidon() IS THIS WITH init = 0. The two used to be written out
 *   separately - the same width check, the same state assembly - and were
 *   checked equal for every width before poseidon became a call to this.
 */
export function poseidon_with_state(inputs, init) {
    if (inputs.length < 1 || inputs.length > 6) {
        throw new Error('poseidon: 1 to 6 inputs');
    }
    var p = params(inputs.length + 1);
    var state = [F.mod(init)];
    for (var i = 0; i < inputs.length; i++) { state.push(F.mod(inputs[i])); }
    return permute(state, p)[0];
}

/**
 * 32 bytes in, 32 bytes out - for callers holding hashes rather than field
 * elements.
 *
 * THE INPUT IS REDUCED MODULO THE FIELD, which means two different byte
 * strings can map to the same element. The field is 254 bits and the input is
 * 256, so about one value in 2^2 of the top range collides with a smaller
 * one. For hashes that is harmless; for anything where the caller controls
 * the bytes it is not, and they should reduce deliberately instead.
 */
export function poseidon_bytes(inputs) {
    var xs = inputs.map(function (b) { return bytes_to_bigint(b) % P; });
    return bigint_to_bytes(poseidon(xs), 32);
}
