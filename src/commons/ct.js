/**
 * Constant-time comparison
 *
 * Every comparison that touches a secret - an authentication tag, a MAC, a
 * signature - goes through here. Never ===, never an early break.
 *
 * The reason is that a naive comparison returns as soon as it finds a
 * differing byte. An attacker who can time the answer learns how many
 * leading bytes were right, and can then forge a tag one byte at a time
 * instead of guessing the whole thing.
 *
 * HONEST LIMIT: JS cannot guarantee constant time. The JIT optimises, the GC
 * pauses, and number representation differs between engines. What this
 * removes is the obvious leak - branching on a secret value and returning
 * early. It is not a proof. Against a local attacker with precise timing
 * measurement, only WASM or hardware will do.
 */

/**
 * Returns 1 if equal, 0 otherwise.
 *
 * A number rather than a boolean on purpose, so a caller can keep computing
 * a mask without introducing a branch.
 *
 * Length mismatch does leak - there is no way around that - but lengths in
 * cryptography are almost always public.
 *
 * ⚠ TWO EMPTY ARRAYS COMPARE EQUAL, which is mathematically right and is a
 *   trap in a tag comparison: with a tag length of zero every tag matches.
 *   No caller here can reach it - the AEAD modes reject a zero tag length
 *   before this is called, and every MAC has a fixed digest size - but a
 *   caller slicing a tag to a length it computed should check that length
 *   rather than trusting this to notice.
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @return {number} 1 or 0
 */
export function equal(a, b) {
    if (a.length !== b.length) { return 0; }
    /*
     * Each difference folded to ONE BIT before it is accumulated.
     *
     * ⚠ It used to OR the raw differences and map diff - 1 through the sign
     *   bit, which is right for bytes and wrong for 32-bit words: a difference
     *   of 0xffffffff is -1 as an int32, and -1 - 1 is negative, so two
     *   different word arrays compared EQUAL (93,714 of 100,000 random pairs).
     *   No caller passes words today; nothing stopped one from doing so.
     *   x | -x has its sign bit set for every non-zero int32 x, including
     *   -2^31.
     */
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
        var x = a[i] ^ b[i];
        diff |= (x | -x) >>> 31;
    }
    return diff ^ 1;
}

/** Boolean form, for use only where the result is exposed anyway. */
export function equal_bool(a, b) { return equal(a, b) === 1; }

/**
 * Zero a buffer that held key material.
 *
 * WHAT IT DOES AND DOES NOT DO. It overwrites the array, which shortens the
 * window in which a heap dump, a swap file or a later allocation of the same
 * memory would expose the value. It CANNOT guarantee the secret is gone: a
 * JavaScript engine may have copied the buffer during a garbage-collection
 * move, and nothing here can reach those copies. Treat it as reducing
 * exposure, not eliminating it.
 *
 * It also cannot be optimised away here the way a C compiler would remove a
 * dead memset, because the array is externally visible - which is one thing
 * JavaScript makes easier than C.
 *
 * Three files defined this identically before it moved here.
 */
export function wipe(a) {
    for (var i = 0; i < a.length; i++) { a[i] = 0; }
}

/**
 * A secret a context holds (x25519_create, ecdh_create, decaps_create):
 * use() gives it, wipe() zeroes it, and use() after wipe() throws - a
 * context that went on with a zeroed key would answer with a stranger's
 * results instead of an error.
 */
export function held(who, secret) {
    var live = true;
    return {
        use: function () {
            if (!live) { throw new Error(who + ': the context was wiped'); }
            return secret;
        },
        wipe: function () { wipe(secret); live = false; }
    };
}

/* ==================== selection ==================== */

/**
 * A mask of all ones when `bit` is 1, all zeros when it is 0.
 *
 * The building block for everything below: `(a & m) | (b & ~m)` picks between
 * two values with no branch, so nothing about `bit` reaches the branch
 * predictor or the instruction cache.
 *
 * @param {number} bit  0 or 1; ANY other value gives a meaningless mask
 */
export function mask(bit) {
    /*
     * ANYTHING BUT 0 OR 1 THROWS, and it used to silently take the low bit.
     *
     * `select(2, a, b)` returned b, quietly - and 2 is what `x & 4` gives, or
     * a bit extracted at the wrong shift. A selector built from a bit test is
     * the normal way to call this, and taking the low bit of a wrong value
     * picks the wrong branch with no indication.
     *
     * `true` and `false` are accepted because they coerce exactly and reading
     * `select(a > b, ...)` is natural.
     */
    if (bit === true) { bit = 1; }
    if (bit === false) { bit = 0; }
    if (bit !== 0 && bit !== 1) {
        throw new TypeError('ct: selector must be 0, 1, true or false - got ' + bit);
    }
    return -bit | 0;
}

/** `bit ? a : b`, for 32-bit values, with no branch on bit. */
export function select(bit, a, b) {
    var m = mask(bit);
    return ((a & m) | (b & ~m)) | 0;
}

/**
 * Copy `a` when bit is 1 and `b` when it is 0, into a fresh array.
 *
 * ⚠ THIS IS THE PRIMITIVE OBLIVIOUS TRANSFER NEEDS, and the reason it is
 *   here before OT is. An OT extension makes millions of choices driven by
 *   the receiver's selection bits, and a branch on any of them leaks the
 *   choice through timing - which is precisely the secret the protocol
 *   exists to protect.
 *
 *   And a timing leak DOES NOT FAIL. The protocol runs, the outputs are
 *   correct, every test passes. Nothing short of a deliberate measurement
 *   shows it, which is why ct_timing_ratio below exists.
 */
export function select_bytes(bit, a, b) {
    if (a.length !== b.length) { throw new Error('ct: length mismatch'); }
    var m = mask(bit) & 0xff;
    var out = new Uint8Array(a.length);
    for (var i = 0; i < a.length; i++) {
        out[i] = (a[i] & m) | (b[i] & ~m);
    }
    return out;
}

/** The same, writing into `dst` - for the inner loop of an OT extension. */
export function select_into(dst, bit, a, b) {
    var m = mask(bit) & 0xff;
    for (var i = 0; i < dst.length; i++) {
        dst[i] = (a[i] & m) | (b[i] & ~m);
    }
    return dst;
}

/**
 * Swap `a` and `b` in place when bit is 1.
 *
 * The shape a Montgomery ladder wants, and the one an OT extension wants for
 * transposing a bit matrix without revealing which rows moved.
 */
export function swap_bytes(bit, a, b) {
    var m = mask(bit) & 0xff;
    for (var i = 0; i < a.length; i++) {
        var d = (a[i] ^ b[i]) & m;
        a[i] ^= d;
        b[i] ^= d;
    }
}

/**
 * Read element `idx` from `table` without the index reaching a memory
 * address.
 *
 * A plain `table[idx]` leaks through the CACHE, not the branch predictor: an
 * attacker who can evict cache lines learns which one was touched. Scanning
 * the whole table and masking is the only defence available in a scripting
 * language, and it costs O(n) per lookup - which is why callers should keep
 * these tables small.
 *
 * @param {Array} table  entries of equal length
 * @param {number} idx   the secret index
 */
export function table_lookup(table, idx, width) {
    /*
     * `width` used to be optional in effect - omitting it made
     * `new Uint8Array(undefined)` an empty array, and the function returned
     * [] rather than failing. An empty lookup is never what a caller wants.
     */
    if (typeof width !== 'number' || width <= 0) {
        throw new TypeError('ct: table_lookup needs the entry width');
    }
    if (!table || !table.length) {
        throw new TypeError('ct: table_lookup needs a non-empty table');
    }
    var out = new Uint8Array(width);
    for (var j = 0; j < table.length; j++) {
        /* eq is 1 exactly when j === idx, computed without a comparison */
        var diff = j ^ idx;
        var eq = ((diff - 1) >>> 31) & 1;
        var m = mask(eq) & 0xff;
        for (var i = 0; i < width; i++) {
            out[i] |= table[j][i] & m;
        }
    }
    return out;
}

/**
 * Measure whether a one-argument function's running time depends on its
 * input, and return the ratio between the slowest and fastest case.
 *
 * NOT A PROOF, AND CANNOT BE ONE. A JIT that has warmed on one input and not
 * another, a garbage collection landing in the wrong sample, a CPU changing
 * frequency - all show up here as noise. What it does catch is the gross
 * case: a function that branches on its input and takes twice as long on one
 * side. That is the failure that reached production in Taproot, where a
 * signature verified in about a quarter of runs and Bitcoin accepted the
 * signatures anyway.
 *
 * A ratio near 1 means nothing was detected. It does not mean nothing is
 * there - and the reverse is also true: a single run of this has been seen
 * to report 1.44 on a function with no branch at all, purely from a garbage
 * collection landing badly. Run it more than once before believing a number,
 * and treat anything under about 1.2 as noise.
 *
 * @param {function} fn      called as fn(input)
 * @param {Array} inputs     the cases to compare
 * @param {number} [rounds]  iterations per case
 */
export function timing_ratio(fn, inputs, rounds) {
    /*
     * THE SECOND ARGUMENT IS A LIST OF INPUTS, NOT A SECOND FUNCTION.
     *
     * Called as timing_ratio(fnA, fnB) it used to return NaN - and NaN is the
     * worst possible answer from a safety check. `if (r < 1.2) pass()` fails
     * closed by accident, but `if (r > 1.2) warn()` NEVER FIRES, so a caller
     * measuring a leaky function concludes there is none while having
     * measured nothing at all.
     */
    if (typeof fn !== 'function') {
        throw new TypeError('ct: timing_ratio takes (fn, inputs) - fn is not a function');
    }
    if (!Array.isArray(inputs) || inputs.length < 2) {
        throw new TypeError('ct: timing_ratio needs an ARRAY of at least two ' +
                            'inputs to compare, not a second function');
    }
    var reps = rounds || 2000;
    var i, j, batch;

    /* warm the JIT on every input, or the first one measured is slow for
       reasons that have nothing to do with the data */
    for (i = 0; i < inputs.length; i++) {
        for (j = 0; j < 500; j++) { fn(inputs[i]); }
    }

    var now = (typeof process !== 'undefined' && process.hrtime && process.hrtime.bigint)
        ? function () { return Number(process.hrtime.bigint()); }
        : function () { return Date.now() * 1e6; };

    /*
     * INTERLEAVED, not one input then the next.
     *
     * Measuring all of input A and then all of input B attributes any drift -
     * a GC pause, the CPU changing frequency, another process waking up - to
     * whichever input happened to be running. Alternating spreads that noise
     * across both, so what is left is more likely to be the data.
     */
    var best = [];
    for (i = 0; i < inputs.length; i++) { best.push(Infinity); }

    for (batch = 0; batch < 15; batch++) {
        for (i = 0; i < inputs.length; i++) {
            var t0 = now();
            for (j = 0; j < reps; j++) { fn(inputs[i]); }
            var dt = now() - t0;
            /* the MINIMUM, not the mean: noise only ever adds time, so the
               smallest observation is closest to the true cost */
            if (dt < best[i]) { best[i] = dt; }
        }
    }

    var lo = Math.min.apply(null, best), hi = Math.max.apply(null, best);
    if (!(lo > 0)) {
        throw new Error('ct: timing_ratio measured zero elapsed time - raise ' +
                        'rounds, or the input is too small to time');
    }
    return hi / lo;
}

/**
 * The same measurement, with the evidence needed to interpret it.
 *
 * A BARE RATIO CANNOT BE READ ON ITS OWN. 1.0 means either "no leak" or "the
 * measurement was blind", and nothing in the number distinguishes them. So
 * this returns the control alongside it:
 *
 *     control  the ratio for a function that DEFINITELY leaks - an early-exit
 *              comparison over the same input size
 *
 * If the control is not large, the setup is not sensitive enough for the
 * subject's number to mean anything. Measured here: at 64 bytes the control
 * reaches only 4 to 12, at 8192 bytes about 1600. So a subject reading 1.05
 * on a small input has not been shown to be clean - the apparatus could not
 * have seen a leak that size either.
 *
 * @return {{ratio, control, sensitive, samples}}
 */
export function timing_report(fn, inputs, size, rounds) {
    var n = size || 8192;
    var ratio = timing_ratio(fn, inputs, rounds);

    /* the control: a comparison that returns as soon as it finds a
       difference, which is the classic leak and the loudest one */
    var ref = new Uint8Array(n);
    for (var i = 0; i < n; i++) { ref[i] = (i * 37) & 0xff; }
    var early = new Uint8Array(ref); early[0] ^= 1;
    var late = new Uint8Array(ref); late[n - 1] ^= 1;
    function leaky(which) {
        var x = which ? late : early;
        for (var k = 0; k < n; k++) { if (x[k] !== ref[k]) { return false; } }
        return true;
    }
    var control = timing_ratio(leaky, [0, 1], rounds);

    return {
        ratio: ratio,
        control: control,
        /* a control under 50 means the apparatus is too coarse to conclude
           anything from `ratio` */
        sensitive: control > 50,
        samples: rounds || 2000
    };
}
