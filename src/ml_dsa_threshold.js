/**
 * ml_dsa_threshold.js - threshold ML-DSA, the pure half.
 *
 * "Efficient Threshold ML-DSA" (Celi, del Pino, Espitau, Niot, Prest; USENIX
 * Security 2026, ePrint 2026/013, full version), nicknamed Mithril. Up to 6
 * parties, 2 <= T <= N <= 6 where a parameter row fits (below), ML-DSA-44/65/87,
 * and the output is an
 * ORDINARY FIPS 204 signature that any ML-DSA verifier accepts.
 *
 * ⭐ Like frost_pure.js, every function below is arithmetic with no rounds,
 *   no parties and no state. Sessions, commitments, transcripts, the reveal
 *   log and the DKG belong to the protocol that uses them.
 *
 * ⭐ THE SIGNING BUDGET (11-12). The proof (paper Theorem 3.2) covers
 *   Qs = 1/(K·ε) signing queries per key, ε = ½·I_{1−1/φ²}((d+1)/2, ½),
 *   d = 256(k+ℓ). The paper's table was generated with φ = 7 / 8 / 9 and a
 *   bound on I that does not hold at these d — the exact ε is 2^-34.5,
 *   2^-36.1, 2^-38.6, so its rows covered 2^26 to 2^37 queries, not the
 *   2^50 they were computed for. The rows here (commons/ml_dsa_threshold_rows.js) are the paper's
 *   method with the EXACT ε, for a budget of 2^50 (the default), 2^45 or
 *   2^40 signatures per key, and only where an attempt costs a party at
 *   most 16 MB. The derivation is in tools/mithril_params/.
 *
 * ⚠ THE CONSTRUCTION HAS A PROOF (ROM, static corruption). A round-1 sample used
 *   twice leaks the share by subtraction (z' - z = (c' - c)*s; Meng, ePrint
 *   2026/2566) - preventing that is the CALLER's: use each round1() result
 *   for exactly one round3().
 *
 * THE CONSTRUCTION (paper section 3, Figs. 5-7):
 *
 *   key      short REPLICATED secret sharing: one ML-DSA secret s_I for
 *            every set I of N-T+1 parties; s = sum s_I; each party holds the
 *            s_I of every set it belongs to. t = A*s1 + s2, pk = (rho, t1).
 *   round 1  each party samples r uniformly in a hyperball of radius r'
 *            (first l coordinates stretched by nu), commits to w = [A|I]*round(r),
 *            for K slots in parallel
 *   round 3  c = SampleInBall(H(mu || HighBits(sum w))); each party adds
 *            c*s_part to its sample and keeps it only if it lands in the
 *            ball of radius r (LOCAL rejection: a rejected slot is never sent)
 *   combine  z = sum z_i; hint from w - (A*z - c*t1*2^d); the result is
 *            (ctilde, z, h), checked as any ML-DSA signature
 *
 * ⭐ AND ONE ADDITION THAT IS NOT IN THE PAPER: response_residual(), the
 *   per-signer measurement an identifiable abort can be built on (the
 *   paper: "We do not consider identifiable aborts"). Only the arithmetic
 *   is here; the thresholds and what to do about them are the protocol's.
 *   It needs each set's public part t_S = [A|I]*s_S; deal() returns them.
 *
 * ⭐ AND THE STRICT MODE (11-12, tools/mithril_params/strict.py), also not in
 *   the paper: every signer also rejects unless its own response lies in a
 *   box, ||z_i||inf <= b1 = floor((gamma1 - beta - 1)/T) and ||e_i||inf <= b2
 *   (round3), and a slot needs the public condition ||c*t0||inf <=
 *   gamma2 - T*b2 (public_condition). Then a slot every signer answered
 *   inside its box cannot fail the final bounds on z or on the hint's delta -
 *   an arithmetic fact - so a signer that blocks signatures is either
 *   outside its box, which anyone checks, or not blocking. Its own rows
 *   (STRICT_ROWS): the box costs epsilon a factor 2/p.
 */
import { ml_dsa44, ml_dsa65, ml_dsa87 } from './ml_dsa.js';
import { canonical as access_canonical, names as access_names, authorized as access_authorized } from './access.js';
import { ntt_inverse, poly_add, poly_new, to_positive, smod, vec_ntt, N, Q } from './commons/dilithium_ring.js';
import { equal as ct_equal } from './commons/ct.js';
import { require_rng } from './commons/primes.js';
import { ROWS, STRICT_ROWS, BUDGETS, DEFAULT_BUDGET, MAX_ATTEMPT_BYTES } from './commons/ml_dsa_threshold_rows.js';

export { BUDGETS, DEFAULT_BUDGET, MAX_ATTEMPT_BYTES };

export var DSA = { 44: ml_dsa44, 65: ml_dsa65, 87: ml_dsa87 };

/* nu, the stretch of the first l coordinates, per level (paper Appendix A) */
var NU = { 44: 3, 65: 6, 87: 7 };

function binom(n, k) {
    var r = 1;
    for (var i = 1; i <= k; i++) { r = r * (n - k + i) / i; }
    return Math.round(r);
}

/**
 * What depends on the level and the sharing alone - enough to deal or run
 * the DKG: { level, dsa, h, p, nu, n, sets }. `sets` the family (below), as
 * sorted position arrays; `n` the party count.
 */
export function structure(level, n, sets) {
    var Dm = DSA[level];
    if (!Dm) { throw new Error('ml_dsa_threshold: level must be 44, 65 or 87'); }
    if (!(Number.isInteger(n) && n >= 2 && n <= 6)) {
        throw new Error('ml_dsa_threshold: needs 2 to 6 parties (the paper\'s parameter range)');
    }
    return { level: level, dsa: Dm, h: Dm.hazmat, p: Dm.hazmat.PARAMS, nu: NU[level], n: n, sets: sets };
}

/**
 * Everything that depends on (level, T, N) and the budget: a T-of-N key, T
 * signers. `strict`: the strict mode's rows and boxes (the header).
 */
export function params(level, T, Nn, budget, strict) {
    if (!DSA[level]) { throw new Error('ml_dsa_threshold: level must be 44, 65 or 87'); }
    if (!(Number.isInteger(T) && Number.isInteger(Nn) && T >= 2 && T <= Nn && Nn <= 6)) {
        throw new Error('ml_dsa_threshold: needs integers 2 <= T <= N <= 6 (the paper\'s parameter range)');
    }
    /* RSSRecover balances the family to at most ceil(C(N, T-1)/T) secrets per signer */
    return with_row(structure(level, Nn, threshold_family(Nn, T)), T, Math.ceil(binom(Nn, T - 1) / T), budget, strict);
}

/** A refusal's advice, only what could change the answer: no lower budget below the lowest, no ML-DSA-87 at 87. */
function what_may_fit(budget, level) {
    var ways = [];
    if (budget > BUDGETS[BUDGETS.length - 1]) { ways.push('a lower budget'); }
    ways.push('fewer signers');
    if (level !== 87) { ways.push('ML-DSA-87 (its eta is 2)'); }
    var text = ways.length < 2 ? ways[0] : ways.slice(0, -1).join(', ') + ' or ' + ways[ways.length - 1];
    return text.charAt(0).toUpperCase() + text.slice(1);
}

/** A budget, checked: 2^50 (the default), 2^45 or 2^40 signatures per key. */
export function budget_of(budget) {
    var b = budget == null ? DEFAULT_BUDGET : budget;
    if (BUDGETS.indexOf(b) < 0) { throw new Error('ml_dsa_threshold: the signing budget is 2^' + BUDGETS.join(', 2^') + ' signatures per key (log2: ' + BUDGETS.join(', ') + ')'); }
    return b;
}

/**
 * The signing parameters for T signers holding at most `load` secrets each,
 * under a budget: the cheapest row with per >= load. The row's r, r' and K
 * depend on the load only through B (below), so a row for more secrets is
 * sound for fewer. Throws when no row is - the attempt would cost a party
 * more than MAX_ATTEMPT_BYTES, or the load is past the rows.
 */
function with_row(st, T, load, budget, strict) {
    var b = budget_of(budget), p = st.p, nu = st.nu, best = null;
    var rows = (strict === true ? STRICT_ROWS : ROWS)[st.level][b];
    for (var per = Math.max(1, load); per <= 12; per++) {
        var row = rows[T + ',' + per];
        if (row && (best === null || row[2] < best.row[2])) { best = { per: per, row: row }; }
    }
    if (best === null) {
        throw new Error('ml_dsa_threshold: ' + T + ' signers holding ' + load + ' secrets each have no ' + (strict === true ? 'strict-mode ' : '') +
                        'parameters at ML-DSA-' + st.level + ' and a budget of 2^' + b + ' signatures - an attempt would cost each party more than ' +
                        MAX_ATTEMPT_BYTES / 1e6 + ' MB. ' + what_may_fit(b, st.level) + (strict === true ? ', or the ordinary mode,' : '') + ' may fit');
    }
    /*
     * B: the overwhelming bound on ||(c*s1/nu, c*s2)||_2 the parameters assume
     * (paper section 3.4, 13 standard deviations). Enforced in round3, not
     * only assumed: a slot whose c*s_part exceeds it is dropped.
     */
    var B = 1.3 * Math.sqrt(p.tau) * Math.sqrt(N * (p.k + p.l / (nu * nu))) *
            Math.sqrt(p.eta * (p.eta + 1) / 3) * Math.sqrt(best.per);
    var P = Object.assign({}, st, { T: T, r: best.row[0], rp: best.row[1], K: best.row[2], phi: best.row[3], per: best.per,
                                    budget: b, B: B, dim: N * (p.k + p.l) });
    if (strict === true) {
        /* the boxes: T·b1 < gamma1 - beta, so the sum of T boxed z_i is in FIPS 204's bound */
        P.strict = true;
        P.b1 = Math.floor((p.gamma1 - p.beta - 1) / T);
        P.b2 = best.row[4];
    }
    return P;
}

/*
 * ⭐ ACCESS STRUCTURES (Ito-Saito-Nishizeki 1987). The replicated sharing is
 *    the threshold case of a general one: one secret s_S for every
 *    COMPLEMENT of a maximal unauthorized set. A set of parties is
 *    authorized exactly when it meets every such complement - so it holds
 *    every s_S - and an unauthorized one misses at least one. For T-of-N the
 *    maximal unauthorized sets are the (T-1)-sets and the complements the
 *    (N-T+1)-sets: threshold_family.
 *
 *    The paper's r, r' and K (section 3.5) depend on N only through the
 *    secrets per signer: its Theorems 3.1 and 3.2 involve T, K, M, epsilon
 *    and B, and B is the bound on ||c*s_part|| that round3 ENFORCES. So the
 *    rows are by (T, per), and any row whose per is at least what a
 *    balanced partition of the family needs is sound for that signing set
 *    (params_for).
 */

/** The T-of-n family: every set of n-T+1 positions. */
export function threshold_family(n, T) { return subsets(n, n - T + 1); }

/**
 * The family of a policy over `parties` (sorted; a position is an index):
 * the complements of its maximal unauthorized sets, as sorted position
 * arrays in lexicographic order.
 */
export function policy_family(policy, parties) {
    var pol = access_canonical(policy), n = parties.length, i;
    var names = access_names(pol).slice().sort();
    var want = parties.map(String).slice().sort();
    if (names.length !== want.length || names.some(function (x, k) { return x !== want[k]; })) {
        throw new Error('ml_dsa_threshold: the policy names exactly the parties');
    }
    if (!(n >= 2 && n <= 6)) { throw new Error('ml_dsa_threshold: needs 2 to 6 parties (the paper\'s parameter range)'); }
    var unauth = [];
    for (var m = 0; m < (1 << n); m++) {
        var set = [];
        for (i = 0; i < n; i++) { if (m & (1 << i)) { set.push(i); } }
        if (!access_authorized(pol, set.map(function (q) { return String(parties[q]); }))) { unauth.push(m); }
    }
    var out = [];
    unauth.forEach(function (u) {
        var maximal = !unauth.some(function (v) { return v !== u && (u & v) === u; });
        if (!maximal) { return; }
        var c = [];
        for (i = 0; i < n; i++) { if (!(u & (1 << i))) { c.push(i); } }
        if (c.length === 0) { throw new Error('ml_dsa_threshold: the policy authorizes no set of these parties'); }
        out.push(c);
    });
    out.sort(function (a, b) { return set_name(a) < set_name(b) ? -1 : 1; });
    return out;
}

/**
 * The signing parameters for an ACTIVE set on a family: the balanced
 * partition's load, and the cheapest table row (T = |act|) whose per covers
 * it. Throws when act is not authorized (misses a set), or when no row
 * covers it - more signers spread the load.
 */
export function params_for(level, n, sets, act, opts) {
    var o = opts || {}, st = structure(level, n, sets), T = act.length;
    if (!(T >= 2 && T <= 6)) { throw new Error('ml_dsa_threshold: 2 to 6 signers'); }
    for (var i = 0; i < sets.length; i++) {
        if (!sets[i].some(function (a) { return act.indexOf(a) >= 0; })) {
            throw new Error('ml_dsa_threshold: the signers miss set ' + set_name(sets[i]) + ' - they are not an authorized set');
        }
    }
    var load = 0;
    if (o.wide != null) {
        load = wide_assign(sets, act, o.wide).load;
    } else {
        for (var cap = Math.ceil(sets.length / T); cap <= sets.length; cap++) {
            if (assign(sets, act, cap) !== null) { load = cap; break; }
        }
    }
    var P = with_row(st, T, load, o.budget, o.strict);
    if (o.wide != null) { P.wide = o.wide; }
    return P;
}

/** The minimal authorized sets of a family, as sorted position arrays. */
export function minimal_sets(n, sets) {
    var authorized = function (mask) { return sets.every(function (S) { return S.some(function (a) { return (mask >> a) & 1; }); }); };
    var out = [];
    for (var m = 1; m < (1 << n); m++) {
        if (!authorized(m)) { continue; }
        var isMin = true;
        for (var i = 0; i < n && isMin; i++) { if (((m >> i) & 1) && authorized(m & ~(1 << i))) { isMin = false; } }
        if (!isMin) { continue; }
        var act = [];
        for (var a = 0; a < n; a++) { if ((m >> a) & 1) { act.push(a); } }
        out.push(act);
    }
    return out;
}

/**
 * ⭐ CAN EVERY MINIMAL AUTHORIZED SET SIGN? Checked when a key is made (DKG,
 *    deal, import), so a key is never created that some authorized group
 *    cannot use. The worst row, or a throw naming the set that cannot.
 *    (A one-party authorized set needs no threshold signing: skipped.)
 */
export function signable(level, n, sets, opts) {
    var worst = null;
    minimal_sets(n, sets).forEach(function (act) {
        if (act.length < 2) { return; }
        var P;
        try { P = params_for(level, n, sets, act, opts); }
        catch (e) { throw new Error(e.message + ' (signers ' + act.join(',') + ' of this structure)'); }
        if (worst === null || P.K > worst.K) { worst = P; }
    });
    return worst;
}

/*
 * ⭐ AN IMPORTED KEY'S WIDE SET (11-12). deal_existing puts the remainder
 *    s − Σ_{S≠S0} s_S in one set S0; every other set is fresh. A signer's
 *    partial is then
 *
 *        holding S0:  s − Σ_{S not in its part} s_S
 *        not:         Σ_{S in its part} s_S
 *
 *    each a sum of independent uniform short secrets (s, FIPS 204's, is one
 *    too): its "load" is how many — 1 + |F| − |part| at S0's holder,
 *    |part| elsewhere. So S0's holder takes EVERY set it holds (its load
 *    falls as its part grows), the rest go balanced to the others, and the
 *    row is the cheapest whose per covers the max: B, enforced in round3,
 *    then bounds ||c·s_part|| exactly as for a dealt key.
 *
 *    S0's holder in act is the one that leaves the fewest sets to others
 *    (lowest position on a tie): optimal, since its load is 1 + all sets
 *    given elsewhere, and every other load is at most that minus one.
 */
function wide_assign(sets, act, wide) {
    var w = -1, k;
    for (k = 0; k < sets.length; k++) { if (set_name(sets[k]) === wide) { w = k; } }
    if (w < 0) { throw new Error('ml_dsa_threshold: the wide set ' + wide + ' is not a set of this family'); }
    var q0 = null, rest = null;
    for (k = 0; k < act.length; k++) {
        var a = act[k];
        if (sets[w].indexOf(a) < 0) { continue; }
        var r = sets.filter(function (S) { return S.indexOf(a) < 0; });
        if (rest === null || r.length < rest.length) { q0 = a; rest = r; }
    }
    if (q0 === null) { throw new Error('ml_dsa_threshold: no signer holds the wide set'); }
    var others = act.filter(function (a) { return a !== q0; });
    var parts = rest.length === 0 ? {} : null;
    for (var cap = Math.ceil(rest.length / others.length); parts === null && cap <= rest.length; cap++) { parts = assign(rest, others, cap); }
    if (parts === null) { throw new Error('ml_dsa_threshold: the signers miss a set - they are not an authorized set'); }
    for (k = 0; k < others.length; k++) { if (!parts[others[k]]) { parts[others[k]] = []; } }
    parts[q0] = sets.filter(function (S) { return S.indexOf(q0) >= 0; }).map(set_name);
    /* every other signer holds at most |rest| sets, one fewer than S0's holder's load */
    return { parts: parts, load: 1 + rest.length };
}

/**
 * The wide set for an import onto this family: the one whose worst load
 * over the minimal authorized sets is least, and that load. Throws when no
 * choice leaves every minimal authorized set a parameter row under the
 * budget — the wide holder's load is too large.
 */
export function wide_set(level, n, sets, budget, strict) {
    var best = null;
    for (var k = 0; k < sets.length; k++) {
        var name = set_name(sets[k]);
        /* signable throws when this choice of wide set does not fit: only the throw matters here */
        try { signable(level, n, sets, { wide: name, budget: budget, strict: strict }); } catch (e) { continue; }
        var load = 0;
        minimal_sets(n, sets).forEach(function (act) { if (act.length >= 2) { load = Math.max(load, wide_assign(sets, act, name).load); } });
        if (best === null || load < best.load) { best = { name: name, load: load }; }
    }
    if (best === null) {
        throw new Error('ml_dsa_threshold: an existing key cannot be imported onto this structure at a budget of 2^' + budget_of(budget) +
                        ' - some authorized set would hold more secrets than any parameter row allows. ' +
                        (budget_of(budget) > BUDGETS[BUDGETS.length - 1] ? 'A lower budget may fit, or rotate' : 'Rotate') +
                        ' to a key dealt for it');
    }
    return best;
}

/* ------------------------------------------------------------------ the sharing */

/** All subsets of [0..n) of size m, lexicographic, as sorted index arrays. */
export function subsets(n, m) {
    var out = [], cur = [];
    (function go(start) {
        if (cur.length === m) { out.push(cur.slice()); return; }
        for (var i = start; i < n; i++) { cur.push(i); go(i + 1); cur.pop(); }
    }(0));
    return out;
}

/** A set's name: its positions as digits, "013". */
export function set_name(I) { return I.join(''); }

/**
 * RSSRecover: assign every set of the family to one ACTIVE member of it, at
 * most P.per per party - the balance the parameters assume. Deterministic,
 * so every party computes the same partition from the active set alone.
 * (The paper hard-codes optimal tables; a depth-first search finds an
 * assignment meeting the same bound, and fails loudly.)
 *
 * @param P    params / params_for: its sets and per
 * @param act  sorted positions of the active parties (0-based)
 * @return {Object}  position -> set names
 */
export function partition(P, act) {
    if (P.wide != null) { return wide_assign(P.sets, act, P.wide).parts; }
    var out = assign(P.sets, act, P.per);
    if (out === null) { throw new Error('ml_dsa_threshold: no balanced partition'); }
    return out;
}

function assign(all, act, cap) {
    var load = {}, out = {}, k;
    for (k = 0; k < act.length; k++) { load[act[k]] = 0; out[act[k]] = []; }
    var pick = new Array(all.length);
    var found = (function go(i) {
        if (i === all.length) { return true; }
        for (var q = 0; q < act.length; q++) {
            var a = act[q];
            if (all[i].indexOf(a) < 0 || load[a] >= cap) { continue; }
            load[a]++; pick[i] = a;
            if (go(i + 1)) { return true; }
            load[a]--;
        }
        return false;
    }(0));
    if (!found) { return null; }
    for (k = 0; k < all.length; k++) { out[pick[k]].push(set_name(all[k])); }
    return out;
}

/** count uniform integers in [-eta, eta], by rejection from bytes. */
function small(rng, eta, count) {
    var out = new Int32Array(count), span = 2 * eta + 1;
    var lim = 256 - (256 % span);
    var i = 0;
    while (i < count) {
        var b = rng(Math.max(32, count - i));
        for (var j = 0; j < b.length && i < count; j++) { if (b[j] < lim) { out[i++] = (b[j] % span) - eta; } }
    }
    return out;
}

/**
 * acc += v, polynomial by polynomial, over the INTEGERS.
 *
 * Not commons/dilithium_ring.js's poly_add: that one reduces mod q and
 * assumes inputs in [0, q), and these are signed secrets and responses whose
 * exact values the norm checks read. deal(), partial_secret() and combine()
 * each had this loop written out.
 */
/** acc += sign·v, coefficientwise. */
function add_into(acc, v, sign) {
    var k = sign == null ? 1 : sign;
    for (var i = 0; i < acc.length; i++) {
        for (var j = 0; j < N; j++) { acc[i][j] += k * v[i][j]; }
    }
}

function zero_vec(n) {
    var out = [];
    for (var i = 0; i < n; i++) { out.push(new Int32Array(N)); }
    return out;
}

function vec_small(rng, eta, polys) {
    var flat = small(rng, eta, polys * N), out = [];
    for (var i = 0; i < polys; i++) { out.push(Int32Array.from(flat.subarray(i * N, (i + 1) * N))); }
    return out;
}

/** [A|I]*(v1, v2) = A*v1 + v2 mod q, for signed integer vectors. */
export function commit(P, A, v1, v2) {
    /* vec_ntt reduces first, so signed vectors go straight in (this file's
       to_ntt was the same function under another name) */
    var v1h = vec_ntt(v1), out = [];
    for (var i = 0; i < P.p.k; i++) {
        var t = P.h.row_dot(A[i], v1h);
        ntt_inverse(t);
        var w = new Int32Array(N);
        for (var j = 0; j < N; j++) { w[j] = to_positive(t[j] + v2[i][j]); }
        out.push(w);
    }
    return out;
}

/**
 * A trusted dealer's key (Fig. 5), for tests and single-machine ceremonies.
 * A DKG producing the same distribution is the protocol library's.
 *
 * @param rng  n => n random bytes; omitted or null draws fresh ones from the platform
 * @return {{ pk, tr, shares: { pos: { setName: { s1, s2 } } }, parts: { setName: t_S } }}
 *   `parts` are the PUBLIC t_S = [A|I]*s_S, for response_consistent().
 */
export function deal(P, rng) {
    rng = require_rng('ml_dsa_threshold.deal', rng);
    var rho = rng(32), secret = {};
    for (var k = 0; k < P.sets.length; k++) {
        secret[set_name(P.sets[k])] = { s1: vec_small(rng, P.p.eta, P.p.l), s2: vec_small(rng, P.p.eta, P.p.k) };
    }
    return finish_deal(P, rho, secret);
}

/**
 * ⭐ AN EXISTING FIPS 204 KEY, DEALT ONTO THE FAMILY (11-12): every set but
 *    one fresh and uniform in [−η, η], as deal() makes them; the wide set
 *    (wide_set) the remainder s − Σ others. The same public key.
 *
 *    A coalition that misses the wide set knows every fresh secret, and
 *    faces s itself — FIPS 204's own key recovery. One that misses another
 *    set S holds the remainder, so it knows s − s_S, and faces s_S — a fresh
 *    uniform secret, as in a dealt key. Neither is anything but MLWE with
 *    the standard secret distribution.
 *
 * @param sk      a FIPS 204 private key of P's level
 * @param rng     n => n random bytes; omitted or null draws fresh ones from
 *                the platform (pass null to give budget or strict)
 * @param budget  the signing budget the key will sign under (it decides
 *                which structures can carry the wide set)
 * @param strict  whether it will sign in the strict mode (its rows decide too)
 * @return deal()'s, and `wide`: the remainder's set
 */
export function deal_existing(P, sk, rng, budget, strict) {
    rng = require_rng('ml_dsa_threshold.deal_existing', rng);
    var d = P.h.sk_decode(sk), wide = wide_set(P.level, P.n, P.sets, budget, strict).name;
    var r1 = d.s1.map(function (v) { return Int32Array.from(v, signed); }), r2 = d.s2.map(function (v) { return Int32Array.from(v, signed); });
    var secret = {};
    for (var k = 0; k < P.sets.length; k++) {
        var S = set_name(P.sets[k]);
        if (S === wide) { continue; }
        var a = vec_small(rng, P.p.eta, P.p.l), b = vec_small(rng, P.p.eta, P.p.k);
        secret[S] = { s1: a, s2: b };
        add_into(r1, a, -1);
        add_into(r2, b, -1);
    }
    secret[wide] = { s1: r1, s2: r2 };
    var out = finish_deal(P, d.rho, secret);
    if (!ct_equal(out.tr, d.tr)) { throw new Error('ml_dsa_threshold: the secret key does not match its own public key'); }
    out.wide = wide;
    return out;
}

/* sk_decode keeps coefficients mod q; the remainder needs them signed */
function signed(a) { return a > (Q >> 1) ? a - Q : a; }

/** The public key, the parts and every position's sets, from the sets' secrets. */
function finish_deal(P, rho, secret) {
    var A = P.h.expand_a(rho), sets = P.sets, parts = {};
    var s1 = zero_vec(P.p.l), s2 = zero_vec(P.p.k), i, j, k;
    for (k = 0; k < sets.length; k++) {
        var x = secret[set_name(sets[k])];
        parts[set_name(sets[k])] = commit(P, A, x.s1, x.s2);
        add_into(s1, x.s1);
        add_into(s2, x.s2);
    }
    var t = commit(P, A, s1, s2), t1 = [];
    for (i = 0; i < t.length; i++) {
        var o = new Int32Array(N);
        for (j = 0; j < N; j++) { o[j] = P.h.power2round(t[i][j])[0]; }
        t1.push(o);
    }
    var pk = P.h.pk_encode(rho, t1);
    var shares = {};
    for (var pos = 0; pos < P.n; pos++) {
        shares[pos] = {};
        for (k = 0; k < sets.length; k++) {
            if (sets[k].indexOf(pos) >= 0) { shares[pos][set_name(sets[k])] = secret[set_name(sets[k])]; }
        }
    }
    for (i = 0; i < P.p.l; i++) { s1[i].fill(0); }
    for (i = 0; i < P.p.k; i++) { s2[i].fill(0); }
    return { pk: pk, tr: P.h.tr(pk), shares: shares, parts: parts };
}

/* ------------------------------------------------------------------ signing */

/** A uniform double in (0, 1], 53 bits from the CSPRNG. */
function unit(rng) {
    var b = rng(7), v = 0;
    for (var i = 0; i < 7; i++) { v = v * 256 + b[i]; }
    v = Math.floor(v / 8);                                   /* 53 bits */
    return (v + 1) / 9007199254740992;
}

/**
 * A point uniform in the dim-dimensional ball of radius rp: a Gaussian
 * direction (Box-Muller), scaled by rp*u^(1/dim).
 */
function sample_ball(P, rng) {
    var d = P.dim, g = new Float64Array(d), i;
    for (i = 0; i < d; i += 2) {
        var a = Math.sqrt(-2 * Math.log(unit(rng))), th = 2 * Math.PI * unit(rng);
        g[i] = a * Math.cos(th);
        if (i + 1 < d) { g[i + 1] = a * Math.sin(th); }
    }
    var n2 = 0;
    for (i = 0; i < d; i++) { n2 += g[i] * g[i]; }
    var scale = P.rp * Math.pow(unit(rng), 1 / d) / Math.sqrt(n2);
    for (i = 0; i < d; i++) { g[i] *= scale; }
    return g;
}

/**
 * Round 1 for one slot: the sample x, its rounding r = round((nu*x1, x2)), and
 * the commitment w = [A|I]*r. Everything but w is SECRET and single-use.
 * rng (n => n random bytes) omitted or null draws from the platform.
 */
export function round1(P, A, rng) {
    rng = require_rng('ml_dsa_threshold.round1', rng);
    var x = sample_ball(P, rng);
    var r1 = [], r2 = [], i, j, p;
    for (i = 0; i < P.p.l; i++) {
        p = new Int32Array(N);
        for (j = 0; j < N; j++) { p[j] = Math.round(P.nu * x[i * N + j]); }
        r1.push(p);
    }
    for (i = 0; i < P.p.k; i++) {
        p = new Int32Array(N);
        for (j = 0; j < N; j++) { p[j] = Math.round(x[(P.p.l + i) * N + j]); }
        r2.push(p);
    }
    return { x: x, r1: r1, r2: r2, w: commit(P, A, r1, r2) };
}

/** c*a over the integers, exactly (c has tau coefficients +-1; a is small). */
function mul_small(c, a) {
    var out = new Int32Array(N);
    for (var i = 0; i < N; i++) {
        var ci = smod(c[i]);
        if (ci === 0) { continue; }
        for (var j = 0; j < N; j++) {
            var k = i + j, v = ci * a[j];
            if (k < N) { out[k] += v; } else { out[k - N] -= v; }      /* x^N = -1 */
        }
    }
    return out;
}

/** A party's partial secret for this signing set: sum of s_I over its part of the partition. */
export function partial_secret(P, mine, names) {
    var s1 = zero_vec(P.p.l), s2 = zero_vec(P.p.k);
    for (var q = 0; q < names.length; q++) {
        var s = mine[names[q]];
        if (!s) { throw new Error('ml_dsa_threshold: this party does not hold secret ' + names[q]); }
        add_into(s1, s.s1);
        add_into(s2, s.s2);
    }
    return { s1: s1, s2: s2 };
}

/** The challenge for a slot from the aggregated commitment. */
export function challenge(P, mu, w) {
    var ctilde = P.h.challenge(mu, P.h.high_bits_vec(w));
    return { ctilde: ctilde, c: P.h.sample_in_ball(ctilde) };
}

/**
 * Round 3 for one slot (HRej, Fig. 4): z = (c*s1/nu + x1, c*s2 + x2) is kept
 * only if ||z||_2 <= r, and then z^(1) = c*s1 + round(nu*x1) is returned. A
 * rejected slot returns null and must reveal nothing.
 */
export function round3(P, slot, c, part) {
    var v1 = [], v2 = [], i, j;
    for (i = 0; i < part.s1.length; i++) { v1.push(mul_small(c, part.s1[i])); }
    for (i = 0; i < part.s2.length; i++) { v2.push(mul_small(c, part.s2[i])); }
    var nv = 0, nz = 0, a, z;
    for (i = 0; i < P.p.l; i++) {
        for (j = 0; j < N; j++) {
            a = v1[i][j] / P.nu; nv += a * a;
            z = a + slot.x[i * N + j]; nz += z * z;
        }
    }
    for (i = 0; i < P.p.k; i++) {
        for (j = 0; j < N; j++) {
            a = v2[i][j]; nv += a * a;
            z = a + slot.x[(P.p.l + i) * N + j]; nz += z * z;
        }
    }
    var out = null;
    if (Math.sqrt(nv) <= P.B && Math.sqrt(nz) <= P.r) {            /* the analysed bound; local rejection */
        out = [];
        for (i = 0; i < P.p.l; i++) {
            var o = new Int32Array(N);
            for (j = 0; j < N; j++) { o[j] = v1[i][j] + slot.r1[i][j]; }
            out.push(o);
        }
        /*
         * ⭐ STRICT: the box, on the very numbers that are sent - z_i, and
         *   e_i = r2 + c·s2, which every other signer recomputes from public
         *   data (response_residual). A function of the accepted sample
         *   alone, so it reveals nothing about s. Rejected exactly as
         *   a sample outside the ball is: nothing is sent.
         */
        if (P.strict && !in_box(P, out, v2, slot.r2)) { for (i = 0; i < out.length; i++) { out[i].fill(0); } out = null; }
    }
    for (i = 0; i < v1.length; i++) { v1[i].fill(0); }
    for (i = 0; i < v2.length; i++) { v2[i].fill(0); }
    return out;
}

/** ||z||inf <= b1 and ||r2 + c·s2||inf <= b2 - the strict mode's box. */
function in_box(P, z, cs2, r2) {
    var i, j;
    for (i = 0; i < z.length; i++) { for (j = 0; j < N; j++) { if (Math.abs(z[i][j]) > P.b1) { return false; } } }
    for (i = 0; i < cs2.length; i++) { for (j = 0; j < N; j++) { if (Math.abs(cs2[i][j] + r2[i][j]) > P.b2) { return false; } } }
    return true;
}

/** sum of commitments, coefficientwise mod q. */
export function sum_commitments(P, ws) {
    var out = [];
    for (var i = 0; i < P.p.k; i++) {
        var o = poly_new();
        for (var q = 0; q < ws.length; q++) { poly_add(o, o, ws[q][i]); }
        out.push(o);
    }
    return out;
}

/*
 * A*z - c*t is P.h.az_minus_ct, and t1*2^d in the NTT domain is P.h.t1_hat:
 * both used to be written out here, as second copies of what ml_dsa.js's
 * verify() computes inline. They moved into ml_dsa's hazmat and verify()
 * calls them too, so a threshold signature and its verification run the
 * same code.
 */

/**
 * Combine one slot (Fig. 7): z = sum z_i^(1), the hint, the bounds. Returns
 * the FIPS 204 signature bytes, or null when this slot does not fit.
 *
 * @param w    the aggregated commitment sum w_i (k polys mod q)
 * @param why  optional: given an object, its `reason` is set when the slot
 *             does not fit - 'z', 'delta' or 'hints', the three bounds
 *             (the strict mode tells an impossible failure from an ordinary one)
 */
export function combine(P, pk, A, ctilde, c, w, zs, why) {
    var z = zero_vec(P.p.l), i, j, q;
    var fail = function (r) { if (why) { why.reason = r; } return null; };
    for (q = 0; q < zs.length; q++) { add_into(z, zs[q]); }
    for (i = 0; i < z.length; i++) {
        for (j = 0; j < N; j++) { if (Math.abs(z[i][j]) >= P.p.gamma1 - P.p.beta) { return fail('z'); } }
    }
    var rows = P.h.az_minus_ct(A, c, z, P.h.t1_hat(P.h.pk_decode(pk).t1));
    var hint = [], weight = 0;
    for (i = 0; i < P.p.k; i++) {
        var rr = rows[i];
        var h = new Uint8Array(N);
        for (j = 0; j < N; j++) {
            var rj = to_positive(rr[j]);
            var delta = smod(w[i][j] - rj);
            if (Math.abs(delta) > P.p.gamma2) { return fail('delta'); }     /* the hint could not recover HighBits(w) */
            h[j] = P.h.make_hint(delta, rj);
            weight += h[j];
        }
        hint.push(h);
    }
    if (weight > P.p.omega) { return fail('hints'); }
    return P.h.sig_encode(ctilde, z, hint);
}

/**
 * The key's t0 from every set's public part: t = sum t_S (mod q), and t0 the
 * low bits power2round drops. t0 is not secret in ML-DSA's analysis - FIPS
 * 204 keeps it in sk only so the public key is shorter - and every strict
 * signer has all the t_S anyway (each signer reveals its own sets' parts).
 *
 * @param tlist  every set's t_S, k polys mod q each - ALL the family's sets
 * @param pk     checked: the t1 these give must be the key's
 * @return {Int32Array[]} t0, centered
 */
export function t0_from_parts(P, tlist, pk) {
    var t = sum_commitments(P, tlist), t1 = P.h.pk_decode(pk).t1, t0 = [], i, j;
    for (i = 0; i < P.p.k; i++) {
        var o = new Int32Array(N);
        for (j = 0; j < N; j++) {
            var pr = P.h.power2round(t[i][j]);
            if (pr[0] !== t1[i][j]) { throw new Error('ml_dsa_threshold: the public parts do not add up to this key'); }
            o[j] = pr[1];
        }
        t0.push(o);
    }
    return t0;
}

/**
 * The strict mode's public condition for a slot: ||c*t0||inf <= gamma2 - T*b2.
 *
 * Nobody chooses it: c is the hash of the summed commitments, which include
 * an honest signer's random ones, committed before anyone saw the others. A
 * slot that fails it fails for everyone, and blames nobody.
 */
export function public_condition(P, c, t0) {
    var lim = P.p.gamma2 - P.T * P.b2, i, j;
    for (i = 0; i < t0.length; i++) {
        var v = mul_small(c, t0[i]);
        for (j = 0; j < N; j++) { if (Math.abs(v[j]) > lim) { return false; } }
    }
    return true;
}

/* ------------------------------------------------------------------ identifying a cheater */

/** sum of public parts t_S (mod q), in the NTT domain, for response_residual(). */
export function sum_parts_hat(P, tlist) {
    return vec_ntt(sum_commitments(P, tlist));
}

/**
 * ONE SIGNER'S RESPONSE, MEASURED ON ITS OWN - the arithmetic only; what
 * counts as too large is the protocol's decision.
 *
 * With t_part = sum of t_S over the signer's part of the partition (public),
 *
 *     e = w_i - (A*z_i - c*t_part) = r2_i + c*s2_part        (mod q)
 *
 * so for an honest response (z_i/nu, e) is the accepted vector of the local
 * rejection, up to rounding.
 *
 * ⚠ NOT FROM THE PAPER. ePrint 2026/013 has no identifiable abort; this
 *   relation is what one can be built on.
 *
 * @param tpart_hat  sum_parts_hat() of the signer's t_S
 * @return {{ norm: number, max_z: number, max_z1: number, max_e: number }}
 *   the l2 norm of (z/nu, e), the largest |z_j/nu|, the largest |z_j| (an
 *   integer: the strict mode's box is on z itself), and the largest |e_j|
 */
export function response_residual(P, A, c, w, z, tpart_hat) {
    var n2 = 0, mz1 = 0, me = 0, i, j, v;
    for (i = 0; i < P.p.l; i++) {
        for (j = 0; j < N; j++) { v = z[i][j] / P.nu; n2 += v * v; if (Math.abs(z[i][j]) > mz1) { mz1 = Math.abs(z[i][j]); } }
    }
    var rows = P.h.az_minus_ct(A, c, z, tpart_hat);
    for (i = 0; i < P.p.k; i++) {
        for (j = 0; j < N; j++) {
            v = smod(w[i][j] - to_positive(rows[i][j])); n2 += v * v;
            if (Math.abs(v) > me) { me = Math.abs(v); }
        }
    }
    return { norm: Math.sqrt(n2), max_z: mz1 / P.nu, max_z1: mz1, max_e: me };
}
