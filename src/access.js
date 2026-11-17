/**
 * access.js - secret sharing for an ACCESS STRUCTURE, not just a threshold.
 *
 *     { t: 2, of: [ { t: 2, of: ['a1', 'a2'] },
 *                   { t: 2, of: ['b1', 'b2', 'b3', 'b4', 'b5'] } ] }
 *
 * reads "both of a1, a2 AND two of the five b's". A gate is "t of these
 * children", so AND is t = all, OR is t = 1, and gates nest. A leaf is a
 * name; one name may sit at several leaves, and then its holder holds
 * several shares.
 *
 * THE CONSTRUCTION - Benaloh and Leichter (CRYPTO 1988), in its Shamir form:
 * share the secret at the root with a polynomial of degree t-1, hand child i
 * the value at x = i (1-based, the child's position), and share THAT at the
 * child the same way, down to the leaves. A set of names is authorized when
 * the root gate is satisfied, recursively. It is a LINEAR scheme: for every
 * authorized set there are public coefficients c_leaf with
 *
 *     secret = sum over the chosen leaves of  c_leaf * share_leaf
 *
 * - each c_leaf the product of the Lagrange coefficients (at 0, over the
 *   chosen sibling positions) along its path. That is the one fact every
 *   threshold protocol needs: Schnorr, BLS, ElGamal decryption, DH and the
 *   additive form ECDSA signs with all combine shares linearly, so they run
 *   unchanged with c_leaf in place of a Lagrange coefficient.
 *
 * FELDMAN, PER GATE. A dealer commits to each gate's polynomial; a leaf
 * share is checked against its parent gate's commitment at its position,
 * and a child gate's constant term must equal that same evaluation - so the
 * whole tree is one consistent sharing of the root's constant term, which is
 * the public key.
 *
 * Paths name nodes: '' is the root, '2' its second child, '2.3' that child's
 * third. They are what the shares and commitments are keyed by.
 */

import { require_rng, mod, mod_inverse } from './commons/primes.js';
import { evaluate, polynomial, lagrange_coeffs_at_zero } from './shamir.js';

var MAX_NODES = 1024;
var MAX_DEPTH = 16;

function is_gate(n) { return n !== null && typeof n === 'object' && !Array.isArray(n); }

/**
 * The structure, checked and in one spelling: gates as { t, of }, leaves as
 * strings. ONE way to write a gate: AND is t = the number of children, OR is
 * t = 1 - no synonyms, so a policy reads the same wherever it is written.
 *
 * @return {object}
 */
export function canonical(policy) {
    var count = 0;
    function walk(n, depth) {
        if (++count > MAX_NODES) { throw new RangeError('access: more than ' + MAX_NODES + ' nodes'); }
        if (depth > MAX_DEPTH) { throw new RangeError('access: nested deeper than ' + MAX_DEPTH); }
        if (typeof n === 'string' || typeof n === 'number') {
            var name = String(n);
            if (name.length === 0 || name.length > 256) { throw new TypeError('access: a leaf is a name of 1 to 256 characters'); }
            return name;
        }
        if (!is_gate(n)) { throw new TypeError('access: a node is a name or { t, of }'); }
        for (var key in n) { if (key !== 't' && key !== 'of') { throw new TypeError('access: a gate is { t, of } and nothing else — not "' + key + '"'); } }
        var of = n.of, t = n.t;
        if (!Array.isArray(of) || of.length < 1) { throw new TypeError('access: a gate needs a non-empty list of children'); }
        if (!Number.isInteger(t) || t < 1 || t > of.length) {
            throw new RangeError('access: a gate\'s t must be between 1 and its ' + of.length + ' children');
        }
        if (of.length > 255) { throw new RangeError('access: a gate has at most 255 children'); }
        return { t: t, of: of.map(function (c) { return walk(c, depth + 1); }) };
    }
    var c = walk(policy, 0);
    if (!is_gate(c)) { throw new TypeError('access: the root must be a gate'); }
    return c;
}

/** Every leaf, depth first: [{ path, name }]. */
export function leaves(policy) {
    var out = [];
    (function walk(n, path) {
        if (!is_gate(n)) { out.push({ path: path, name: n }); return; }
        for (var i = 0; i < n.of.length; i++) { walk(n.of[i], path === '' ? String(i + 1) : path + '.' + (i + 1)); }
    }(canonical(policy), ''));
    return out;
}

/** The distinct names, sorted. */
export function names(policy) {
    var seen = {};
    leaves(policy).forEach(function (l) { seen[l.name] = true; });
    return Object.keys(seen).sort();
}

/**
 * sat(node): is this (canonical) node satisfied by the names in `set`? —
 * a leaf by being in it, a gate by t of its children. One definition for
 * authorized, select and coefficients, which must agree on it exactly.
 */
function satisfier(set) {
    var have = {};
    (set || []).forEach(function (s) { have[String(s)] = true; });
    return function sat(n) {
        if (!is_gate(n)) { return have[n] === true; }
        var k = 0;
        for (var i = 0; i < n.of.length; i++) { if (sat(n.of[i])) { k++; } }
        return k >= n.t;
    };
}

/** May these names, together, reconstruct? */
export function authorized(policy, set) {
    return satisfier(set)(canonical(policy));
}

/**
 * The leaves an authorized set recombines from — the same choice
 * `coefficients` makes — or null when the set is not authorized.
 *
 * @return {string[]|null} leaf paths
 */
export function select(policy, set) {
    var root = canonical(policy), sat = satisfier(set);
    if (!sat(root)) { return null; }
    var out = [];
    (function walk(n, path) {
        if (!is_gate(n)) { out.push(path); return; }
        var k = 0;
        for (var i = 0; i < n.of.length && k < n.t; i++) {
            if (sat(n.of[i])) { k++; walk(n.of[i], path === '' ? String(i + 1) : path + '.' + (i + 1)); }
        }
    }(root, ''));
    return out;
}

/**
 * The recombination coefficients for an authorized set: { path: c } over the
 * leaves it uses, with secret = sum c * share. Deterministic - at each gate
 * the FIRST t satisfied children - so every party computes the same ones.
 *
 * @return {object|null} null when the set is not authorized
 */
export function coefficients(policy, set, modulus) {
    var root = canonical(policy), sat = satisfier(set);
    if (!sat(root)) { return null; }
    var out = {};
    (function walk(n, path, c) {
        if (!is_gate(n)) { out[path] = c; return; }
        var chosen = [];
        for (var i = 0; i < n.of.length && chosen.length < n.t; i++) { if (sat(n.of[i])) { chosen.push(i + 1); } }
        var lam = lagrange_coeffs_at_zero(chosen.map(BigInt), modulus);
        for (var j = 0; j < chosen.length; j++) {
            var p = path === '' ? String(chosen[j]) : path + '.' + chosen[j];
            walk(n.of[chosen[j] - 1], p, mod(c * lam[j], modulus));
        }
    }(root, '', 1n));
    return out;
}

/**
 * Deal `secret` over the structure.
 *
 * @return {{ shares: { path: bigint }, polys: { gatePath: bigint[] } }}
 *         shares for every LEAF, the polynomial of every GATE (for Feldman)
 */
export function deal(policy, secret, rng, modulus) {
    rng = require_rng('access.deal', rng);
    var shares = {}, polys = {};
    (function walk(n, path, s) {
        if (!is_gate(n)) { shares[path] = mod(s, modulus); return; }
        var f = polynomial(s, n.t, rng, modulus);
        polys[path] = f;
        for (var i = 0; i < n.of.length; i++) {
            walk(n.of[i], path === '' ? String(i + 1) : path + '.' + (i + 1), evaluate(f, BigInt(i + 1), modulus));
        }
    }(canonical(policy), '', secret));
    return { shares: shares, polys: polys };
}

/** Feldman commitments: { gatePath: [a_0*G, a_1*G, ...] }. */
export function commit(G, polys) {
    var out = {};
    for (var p in polys) { out[p] = polys[p].map(function (a) { return G.base_mul(a); }); }
    return out;
}

/** sum_k x^k * C_k */
function eval_commitment(G, C, x) {
    var acc = G.IDENTITY, xp = 1n;
    for (var k = 0; k < C.length; k++) {
        acc = G.add(acc, G.mul_vartime ? G.mul_vartime(xp, C[k]) : G.mul(xp, C[k]));
        xp = mod(xp * x, G.ORDER);
    }
    return acc;
}

function parent_and_position(path) {
    var i = path.lastIndexOf('.');
    return i < 0 ? { parent: '', x: BigInt(path) } : { parent: path.slice(0, i), x: BigInt(path.slice(i + 1)) };
}

/**
 * Check a dealer's commitments for shape and consistency: one per gate, of
 * the gate's degree, and every child gate's constant term equal to its
 * parent's commitment at the child's position.
 *
 * @return {string|null} why not, or null
 */
export function check_commitments(G, policy, C) {
    var root = canonical(policy), why = null;
    (function walk(n, path) {
        if (why || !is_gate(n)) { return; }
        var c = C[path];
        if (!Array.isArray(c) || c.length !== n.t) { why = 'gate "' + path + '" needs ' + n.t + ' commitments'; return; }
        if (path !== '') {
            var pp = parent_and_position(path);
            if (!G.equals(c[0], eval_commitment(G, C[pp.parent], pp.x))) {
                why = 'gate "' + path + '" does not continue its parent'; return;
            }
        }
        for (var i = 0; i < n.of.length; i++) { walk(n.of[i], path === '' ? String(i + 1) : path + '.' + (i + 1)); }
    }(root, ''));
    if (!why) {
        for (var k in C) { if (!(k in gate_paths(root))) { why = 'a commitment for no gate: "' + k + '"'; break; } }
    }
    return why;
}

function gate_paths(root) {
    var out = {};
    (function walk(n, path) {
        if (!is_gate(n)) { return; }
        out[path] = true;
        for (var i = 0; i < n.of.length; i++) { walk(n.of[i], path === '' ? String(i + 1) : path + '.' + (i + 1)); }
    }(root, ''));
    return out;
}

/** The public point of a leaf share: its parent gate's commitment at its position. */
export function leaf_point(G, C, path) {
    var pp = parent_and_position(path);
    return eval_commitment(G, C[pp.parent], pp.x);
}

/**
 * Are these leaf points ONE sharing over the structure — every gate's
 * children on one polynomial of its degree — and of what? Checks every
 * child, not only the ones a recombination would pick: at each gate the
 * first t children fix the polynomial, and each further child is checked
 * through a window of the first t-1 and itself.
 *
 * @param {object} points  { leafPath: point }
 * @return {object|null}   the shared point (the root's value), or null
 */
export function check_points(G, policy, points) {
    var q = G.ORDER;
    function at_zero(xs, pts) {
        var lam = lagrange_coeffs_at_zero(xs, q), acc = G.IDENTITY;
        for (var i = 0; i < xs.length; i++) { acc = G.add(acc, G.mul_vartime ? G.mul_vartime(lam[i], pts[i]) : G.mul(lam[i], pts[i])); }
        return acc;
    }
    function value(n, path) {
        if (!is_gate(n)) { return points[path] == null ? null : points[path]; }
        var xs = [], vs = [];
        for (var i = 0; i < n.of.length; i++) {
            var v = value(n.of[i], path === '' ? String(i + 1) : path + '.' + (i + 1));
            if (v === null) { return null; }
            xs.push(BigInt(i + 1)); vs.push(v);
        }
        var root = at_zero(xs.slice(0, n.t), vs.slice(0, n.t));
        for (var j = n.t; j < xs.length; j++) {
            var wx = xs.slice(0, n.t - 1).concat([xs[j]]), wv = vs.slice(0, n.t - 1).concat([vs[j]]);
            if (!G.equals(at_zero(wx, wv), root)) { return null; }
        }
        return root;
    }
    return value(canonical(policy), '');
}

/** Does `value` match the dealer's commitments at this leaf? */
export function verify_leaf(G, C, path, value) {
    return G.equals(G.base_mul(mod(value, G.ORDER)), leaf_point(G, C, path));
}

/**
 * Every leaf share as a LINEAR FORM in the dealing's unknowns: the root's
 * secret, then each gate's coefficients a_1 .. a_{t-1} in walk order. A
 * child at position j of gate g holds  const_g + sum_k j^k * a_{g,k}.
 *
 * @return {{ forms: { path: bigint[] }, width: number }}
 */
function leaf_forms(policy, modulus) {
    var root = canonical(policy), width = 1;
    (function count(n) {
        if (!is_gate(n)) { return; }
        width += n.t - 1;
        n.of.forEach(count);
    }(root));
    var forms = {}, next = 1;
    (function walk(n, path, base) {
        if (!is_gate(n)) { forms[path] = base; return; }
        var vars = [];
        for (var k = 1; k < n.t; k++) { vars.push(next++); }
        for (var i = 0; i < n.of.length; i++) {
            var j = BigInt(i + 1), f = base.slice(), jp = 1n;
            for (var v = 0; v < vars.length; v++) { jp = mod(jp * j, modulus); f[vars[v]] = mod(f[vars[v]] + jp, modulus); }
            walk(n.of[i], path === '' ? String(i + 1) : path + '.' + (i + 1), f);
        }
    }(root, '', (function () { var e = new Array(width).fill(0n); e[0] = 1n; return e; }())));
    return { forms: forms, width: width };
}

/**
 * How to rebuild ONE LEAF from the leaves other names hold: coefficients
 * { path: mu } over the leaves of `from` with
 *
 *     share_target = sum mu * share_path
 *
 * for EVERY dealing over this structure - or null when `from` does not
 * determine that leaf. Gaussian elimination over the public structure
 * (leaf_forms); the free unknowns are set to zero, so every party computes
 * the same answer.
 *
 * This is what repairing a lost holder needs. A leaf can be determined by
 * names that are NOT an authorized set (its sibling under a one-of gate
 * holds the very same share), and an authorized set determines every leaf
 * (through the root and the leaf's own gate). The solver finds whichever
 * combination exists, without a rule per case.
 *
 * @return {object|null}
 */
export function repair_coefficients(policy, target, from, modulus) {
    var lf = leaf_forms(policy, modulus), forms = lf.forms, m = lf.width;
    if (!Object.prototype.hasOwnProperty.call(forms, target)) { throw new Error('access: no leaf at ' + target); }
    var have = {};
    (from || []).forEach(function (s) { have[String(s)] = true; });
    var cols = leaves(policy).filter(function (l) { return have[l.name] && l.path !== target; }).map(function (l) { return l.path; });
    // rows = unknowns, columns = the available leaves, then the target
    var A = [];
    for (var r = 0; r < m; r++) {
        var row = cols.map(function (p) { return forms[p][r]; });
        row.push(forms[target][r]);
        A.push(row);
    }
    var n = cols.length, pivots = [], lead = 0;
    for (var c = 0; c < n && lead < m; c++) {
        var piv = -1;
        for (var i = lead; i < m; i++) { if (A[i][c] !== 0n) { piv = i; break; } }
        if (piv < 0) { continue; }
        var tmp = A[piv]; A[piv] = A[lead]; A[lead] = tmp;
        var inv = mod_inverse(A[lead][c], modulus);
        for (var k = 0; k <= n; k++) { A[lead][k] = mod(A[lead][k] * inv, modulus); }
        for (var i2 = 0; i2 < m; i2++) {
            if (i2 === lead || A[i2][c] === 0n) { continue; }
            var f = A[i2][c];
            for (var k2 = 0; k2 <= n; k2++) { A[i2][k2] = mod(A[i2][k2] - f * A[lead][k2], modulus); }
        }
        pivots.push(c);
        lead++;
    }
    for (var z = lead; z < m; z++) { if (A[z][n] !== 0n) { return null; } }   // inconsistent: not determined
    var out = {};
    for (var q = 0; q < pivots.length; q++) {
        if (A[q][n] !== 0n) { out[cols[pivots[q]]] = A[q][n]; }
    }
    return out;
}

/**
 * Recombine leaf shares (or, with `points`, leaf points) for an authorized
 * set. For checking and tests; a protocol uses `coefficients` directly.
 */
export function combine(policy, set, values, modulus) {
    var c = coefficients(policy, set, modulus);
    if (c === null) { throw new Error('access: not an authorized set'); }
    var s = 0n;
    for (var p in c) {
        if (values[p] === undefined) { throw new Error('access: missing the share at leaf ' + p); }
        s = mod(s + c[p] * values[p], modulus);
    }
    return s;
}


/* ===================================================================== *
 *  OVER THE INTEGERS - for a group whose order is secret (RSA)
 * ===================================================================== */

/*
 * THE SAME TREE WITHOUT A MODULUS - linear integer secret sharing
 * (Damgard-Thorbek, PKC 2006) for Benaloh-Leichter. Lagrange coefficients
 * divide, and with the group order secret there is nothing to divide by,
 * so every gate scales:
 *
 *     gate g, m children, t:   D_g = m!   (1 when t = 1: no denominators)
 *     f_g integer, degree t-1, f_g(0) = D_g * value_g;  child j gets f_g(j)
 *     t children T recombine:  sum (D_g * lambda_j^T) * f_g(j) = D_g^2 * value_g
 *
 * D_g * lambda_j^T is an integer: its denominators are differences of
 * positions in 1..m, and they divide m!. And f_g(j) = f_g(0) = 0 (mod j)
 * since j | m!, so no child learns its parent's value modulo its position.
 *
 * A CONSTANT MULTIPLIER PER NODE. Children reach their gate scaled by their
 * own subtrees, so they are brought to one scale first:
 *
 *     M(leaf) = 1,   M(g) = D_g^2 * lcm over g's children of M(child)
 *
 * a child c multiplied by lcm / M(c). M depends on the structure alone - not
 * on which set recombines - so for every authorized set
 *
 *     sum over its chosen leaves of  c_leaf * share_leaf  =  M(root) * secret
 *
 * with integer c_leaf. The chosen leaves are `select`'s.
 */

function factorial(n) {
    var v = 1n;
    for (var i = 2n; i <= BigInt(n); i++) { v *= i; }
    return v;
}

function gcd_int(a, b) {
    a = a < 0n ? -a : a; b = b < 0n ? -b : b;
    while (b) { var t = a % b; a = b; b = t; }
    return a;
}

/** D_g for a gate: m!, or 1 for a one-of gate. */
export function integer_delta(gate) {
    if (!is_gate(gate)) { throw new TypeError('access: integer_delta takes a gate'); }
    return gate.t === 1 ? 1n : factorial(gate.of.length);
}

/** M(node) for the node at `path` ('' the root). */
export function integer_multiplier(policy, path) {
    var n = node_at(canonical(policy), path || '');
    return (function M(x) {
        if (!is_gate(x)) { return 1n; }
        var l = 1n;
        for (var i = 0; i < x.of.length; i++) { var m = M(x.of[i]); l = l / gcd_int(l, m) * m; }
        var d = integer_delta(x);
        return d * d * l;
    }(n));
}

function node_at(root, path) {
    if (path === '') { return root; }
    var n = root;
    path.split('.').forEach(function (k) {
        if (!is_gate(n)) { throw new Error('access: no node at ' + path); }
        n = n.of[Number(k) - 1];
        if (n === undefined) { throw new Error('access: no node at ' + path); }
    });
    return n;
}

/**
 * The integer recombination for an authorized set: { path: c } over the
 * leaves `select` chooses, with sum c * share = M(root) * secret - or null
 * when the set is not authorized.
 */
export function integer_coefficients(policy, set) {
    var root = canonical(policy);
    var chosen = select(root, set);
    if (chosen === null) { return null; }
    var mult = {};
    function M(x, path) {
        if (!is_gate(x)) { mult[path] = 1n; return 1n; }
        var l = 1n;
        for (var i = 0; i < x.of.length; i++) {
            var m = M(x.of[i], path === '' ? String(i + 1) : path + '.' + (i + 1));
            l = l / gcd_int(l, m) * m;
        }
        var d = integer_delta(x);
        mult[path] = d * d * l;
        return mult[path];
    }
    M(root, '');
    var used = {};
    chosen.forEach(function (p) {
        var parts = p.split('.');
        for (var k = 1; k <= parts.length; k++) { used[parts.slice(0, k).join('.')] = true; }
    });
    var out = {};
    (function walk(n, path, c) {
        if (!is_gate(n)) { out[path] = c; return; }
        var pos = [], paths = [];
        for (var i = 0; i < n.of.length; i++) {
            var p = path === '' ? String(i + 1) : path + '.' + (i + 1);
            if (used[p]) { pos.push(BigInt(i + 1)); paths.push(p); }
        }
        var d = integer_delta(n);
        var lcm = mult[path] / (d * d);
        for (var j = 0; j < pos.length; j++) {
            var num = d, den = 1n;
            for (var k = 0; k < pos.length; k++) {
                if (k === j) { continue; }
                num *= pos[k];
                den *= pos[k] - pos[j];
            }
            if (num % den !== 0n) { throw new Error('access: an integer Lagrange coefficient that is not an integer'); }
            walk(n.of[Number(pos[j]) - 1], paths[j], c * (num / den) * (lcm / mult[paths[j]]));
        }
    }(root, '', 1n));
    return out;
}

/**
 * Deal an integer `secret` over the structure. `sample(gatePath, k)` gives
 * the gate's k-th coefficient (k >= 1) - the caller picks the range, which
 * is what hides each value (statistically, Damgard-Thorbek); the constant
 * term is D_g times the gate's value.
 *
 * @return {{ shares: { path: bigint }, polys: { gatePath: bigint[] } }}
 */
export function integer_deal(policy, secret, sample) {
    if (typeof sample !== 'function') { throw new TypeError('access.integer_deal: sample(gatePath, k) gives the coefficients'); }
    if (typeof secret !== 'bigint') { throw new TypeError('access.integer_deal: the secret is a bigint'); }
    var shares = {}, polys = {};
    (function walk(n, path, s) {
        if (!is_gate(n)) { shares[path] = s; return; }
        var f = [integer_delta(n) * s];
        for (var k = 1; k < n.t; k++) { f.push(sample(path, k)); }
        polys[path] = f;
        for (var i = 0; i < n.of.length; i++) {
            var x = BigInt(i + 1), v = 0n, xp = 1n;
            for (var q = 0; q < f.length; q++) { v += f[q] * xp; xp *= x; }
            walk(n.of[i], path === '' ? String(i + 1) : path + '.' + (i + 1), v);
        }
    }(canonical(policy), '', secret));
    return { shares: shares, polys: polys };
}
