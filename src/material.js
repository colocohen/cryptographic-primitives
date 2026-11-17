/**
 * material.js - CMP setup material: a Paillier key and ring-Pedersen
 * parameters, from fresh primes.
 *
 * ==================== WHY THIS FILE EXISTS ====================
 *
 * cmp_setup.precompute_aux does the same work in one call and holds the
 * thread for the whole of it. At the sizes production needs that is not a
 * pause, it is an outage:
 *
 *     1024-bit, unsafe primes        659 ms
 *     2048-bit, unsafe primes      8,911 ms
 *     1024-bit, SAFE primes       18,291 ms   <- what CGGMP21 requires
 *     2048-bit, safe primes            minutes
 *
 * In a browser the tab freezes. On a server nothing else is served.
 *
 * So the work is a task (commons/task.js) whose step is one primality test,
 * and the callback form in api/material.js runs it a few milliseconds at a
 * time, handing the event loop back between (engines/select.js). The
 * synchronous form runs the same steps without stopping.
 *
 * ==================== "MAKE IT ASYNC" IS NOT THE FIX ====================
 *
 * MEASURED, on the same 512-bit workload with a 1 ms interval counting
 * ticks:
 *
 *     wrapped in async, awaited        0 ticks
 *     callbacks with an explicit yield  28 ticks
 *     plain blocking call               0 ticks
 *
 * An `async` function that runs a blocking loop returns a Promise and holds
 * the loop until it finishes, exactly like the synchronous version. What
 * releases the loop is stopping between pieces of work - which a task makes
 * possible and select.js does.
 */

import { random_prime_task, safe_prime_task, require_rng } from './commons/primes.js';
import { finish_task, map_task, then_task, repeat_task } from './commons/task.js';
import { keygen as paillier_keygen } from './paillier.js';
import { keygen as rp_keygen } from './ring_pedersen.js';

/**
 * Generate CMP setup material.
 *
 * @param {object} params
 * @param {number} params.bits        modulus size, 1024 or 2048
 * @param {number} [params.rpBits]    ring-Pedersen size; defaults to bits
 * @param {function} [params.rng]  omitted or null: the platform's
 * @param {boolean} [params.safe=true] safe primes, which CGGMP21 requires
 * @param {function} [params.onProgress]  (stage, tried) on every candidate
 * @return {{paillier, ring_pedersen}}
 */
export function generate_material(params) {
    return finish_task(generate_material_task(params));
}

/** generate_material as a task (commons/task.js): a primality test a step. */
export function generate_material_task(params) {
    var bits = params.bits;
    var rng = require_rng('material.generate_material', params.rng);
    var safe = params.safe === undefined ? true : !!params.safe;
    var onProgress = params.onProgress;
    var rpBits = params.rpBits || bits;

    if (!bits) { throw new TypeError('material: bits is required'); }

    /*
     * Two DISTINCT primes for one stage: equal primes make n a perfect
     * square, whose factorisation is a square root. A second prime equal to
     * the first is drawn again. A safe prime comes as { p, q } (q = (p-1)/2),
     * which ring_pedersen.keygen takes as it is; Paillier takes the p's.
     */
    function stage(name, size, want_safe) {
        var report = onProgress ? function (tried) { onProgress(name, tried); } : undefined;
        function search() {
            return want_safe ? safe_prime_task(size, rng, report)
                             : map_task(random_prime_task(size, rng, 8, undefined, report), function (p) { return { p: p }; });
        }
        return then_task(search(), function (a) {
            return map_task(repeat_task(search, function (b) { return b.p !== a.p; }),
                            function (b) { return [a, b]; });
        });
    }

    return then_task(stage('paillier', bits >> 1, safe), function (ps) {
        var paillier = paillier_keygen(bits, rng, { safe: safe, primes: [ps[0].p, ps[1].p] });
        /* the ring-Pedersen modulus needs SAFE primes regardless of the
           paillier setting - the proofs depend on the subgroup structure */
        return map_task(stage('ring_pedersen', rpBits >> 1, true), function (rps) {
            return { paillier: paillier, ring_pedersen: rp_keygen(rpBits, rng, undefined, rps) };
        });
    });
}
