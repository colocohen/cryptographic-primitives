/**
 * Keccak-f[1600] as a circuit, for proofs (commons/voleith.js)
 *
 * A Keccak round is linear except for chi, whose every output bit is
 *
 *     out = b0 + (b1 + 1) * b2           (b the state after theta, rho, pi)
 *
 * so with the state after each round committed, a round is 1600 quadratic
 * constraints in those bits. chi's inverse is cubic, so a block of rounds -
 * some forward from one committed state, some back from the next - is 1600
 * constraints of higher degree with fewer states committed (four forward
 * and two back: six rounds at degree 16). This file gives the plain
 * round-by-round states (the witness) and those constraints over the proof
 * system's abstract ring.
 *
 * BIT ORDER: a state is 200 bytes in the standard Keccak order (lane x + 5y,
 * little-endian), and state bit i is bit i & 7 of byte i >> 3 - so lane
 * (x, y) bit z is bit 64 (x + 5y) + z.
 */

var RHO = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]
];   /* RHO[x][y] */
var M64 = (BigInt(1) << BigInt(64)) - BigInt(1);
var RC = /* @__PURE__ */ (function () {
    /* the round constants from the LFSR of FIPS 202 algorithm 5 */
    var out = [], R = 1;
    function rc_bit() { var b = R & 1; R = (R << 1) ^ ((R & 0x80) ? 0x171 : 0); R &= 0xff; return b; }
    for (var r = 0; r < 24; r++) {
        var c = BigInt(0);
        for (var j = 0; j < 7; j++) { if (rc_bit()) { c |= BigInt(1) << BigInt((1 << j) - 1); } }
        out.push(c);
    }
    return out;
}());

function rotl(v, n) { var s = BigInt(n); return n === 0 ? v : ((v << s) | (v >> BigInt(64 - n))) & M64; }

/** One plain round on 25 BigInt lanes. */
function round(A, r) {
    var C = [], D = [], B = new Array(25), x, y;
    for (x = 0; x < 5; x++) { C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20]; }
    for (x = 0; x < 5; x++) { D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1); }
    for (x = 0; x < 5; x++) { for (y = 0; y < 5; y++) { B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y] ^ D[x], RHO[x][y]); } }
    var out = new Array(25);
    for (x = 0; x < 5; x++) { for (y = 0; y < 5; y++) { out[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y] & M64) & B[(x + 2) % 5 + 5 * y]); } }
    out[0] ^= RC[r];
    return out;
}

function lanes(st) {
    var A = [];
    for (var i = 0; i < 25; i++) { var v = BigInt(0); for (var b = 7; b >= 0; b--) { v = (v << BigInt(8)) | BigInt(st[8 * i + b]); } A.push(v); }
    return A;
}
function bytes(A) {
    var out = new Uint8Array(200);
    for (var i = 0; i < 25; i++) { var v = A[i]; for (var b = 0; b < 8; b++) { out[8 * i + b] = Number(v & BigInt(255)); v >>= BigInt(8); } }
    return out;
}

/**
 * The states after each of the 24 rounds of Keccak-f[1600] on a 200-byte
 * state: [st_1, ..., st_24], each 200 bytes. st_24 is the permutation.
 */
export function keccak_round_states(st) {
    var A = lanes(st), out = [];
    for (var r = 0; r < 24; r++) { A = round(A, r); out.push(bytes(A)); }
    return out;
}

/* ---------------- the round in the proof system's ring ---------------- */

/*
 * A state in the ring is 25 lanes of 64 values, all of one degree d (the
 * homogeneous convention of commons/voleith.js: a constant 1 at degree d is
 * X^d, here shift(cbit(1), d - 1)).
 */

/* theta^-1 on the column parities: theta maps C to C + D(C), D[x][z] = C[x-1][z] + C[x+1][z-1]; THETA_INV[j] lists the C' bits summing to C_j */
var THETA_INV = /* @__PURE__ */ (function () {
    var N = 320, Wd = 10, rows = [], inv = [], i, j, t;
    for (i = 0; i < N; i++) { rows.push(new Uint32Array(Wd)); inv.push(new Uint32Array(Wd)); inv[i][i >> 5] |= 1 << (i & 31); }
    function set(row, b) { row[b >> 5] ^= 1 << (b & 31); }
    /* row (x, z) of I + M: C'[x][z] = C[x][z] + C[x-1][z] + C[x+1][z-1] */
    for (var x = 0; x < 5; x++) {
        for (var z = 0; z < 64; z++) {
            var r = rows[64 * x + z];
            set(r, 64 * x + z); set(r, 64 * ((x + 4) % 5) + z); set(r, 64 * ((x + 1) % 5) + (z + 63) % 64);
        }
    }
    function get(row, b) { return (row[b >> 5] >>> (b & 31)) & 1; }
    for (j = 0; j < N; j++) {
        for (i = j; i < N && !get(rows[i], j); i++) { /* find a pivot */ }
        if (i === N) { throw new Error('keccak_circuit: theta is singular'); }
        t = rows[i]; rows[i] = rows[j]; rows[j] = t; t = inv[i]; inv[i] = inv[j]; inv[j] = t;
        for (i = 0; i < N; i++) {
            if (i !== j && get(rows[i], j)) { for (t = 0; t < Wd; t++) { rows[i][t] ^= rows[j][t]; inv[i][t] ^= inv[j][t]; } }
        }
    }
    var out = [];
    for (i = 0; i < N; i++) { var l = []; for (j = 0; j < N; j++) { if (get(inv[i], j)) { l.push(j); } } out.push(l); }
    return out;
}());

function ring_ops(Rg) {
    var ones = [null, Rg.cbit(1)];
    function one(d) { while (ones.length <= d) { ones.push(Rg.shift(ones[1], ones.length - 1)); } return ones[d]; }
    function sh(v, n) { return n ? Rg.shift(v, n) : v; }
    function sum(vs) { var a = vs[0]; for (var q = 1; q < vs.length; q++) { a = Rg.add(a, vs[q]); } return a; }
    function load(f) {
        var A = [];
        for (var q = 0; q < 25; q++) { var l = []; for (var z = 0; z < 64; z++) { l.push(f(64 * q + z)); } A.push(l); }
        return A;
    }
    function parities(A) {
        var C = [];
        for (var x = 0; x < 5; x++) { for (var z = 0; z < 64; z++) { C.push(sum([A[x][z], A[x + 5][z], A[x + 10][z], A[x + 15][z], A[x + 20][z]])); } }
        return C;
    }
    /* A + D(C), D[x][z] = C[x-1][z] + C[x+1][z-1] */
    function add_d(A, C) {
        var out = [], x, y, z;
        for (y = 0; y < 5; y++) { for (x = 0; x < 5; x++) { out.push(null); } }
        for (x = 0; x < 5; x++) {
            var Dx = [];
            for (z = 0; z < 64; z++) { Dx.push(Rg.add(C[64 * ((x + 4) % 5) + z], C[64 * ((x + 1) % 5) + (z + 63) % 64])); }
            for (y = 0; y < 5; y++) { var l = []; for (z = 0; z < 64; z++) { l.push(Rg.add(A[x + 5 * y][z], Dx[z])); } out[x + 5 * y] = l; }
        }
        return out;
    }
    function theta(A) { return add_d(A, parities(A)); }
    function theta_inv(A) {
        var Cp = parities(A), C = [];
        for (var j = 0; j < 320; j++) { C.push(sum(THETA_INV[j].map(function (q) { return Cp[q]; }))); }
        return add_d(A, C);
    }
    /* rho and pi: B[y + 5 (2x + 3y)] = rot(A[x + 5y], RHO[x][y]) */
    function rho_pi(A) {
        var B = new Array(25);
        for (var x = 0; x < 5; x++) {
            for (var y = 0; y < 5; y++) {
                var src = A[x + 5 * y], rot = RHO[x][y], dst = new Array(64);
                for (var z = 0; z < 64; z++) { dst[(z + rot) % 64] = src[z]; }
                B[y + 5 * ((2 * x + 3 * y) % 5)] = dst;
            }
        }
        return B;
    }
    function rho_pi_inv(B) {
        var A = new Array(25);
        for (var x = 0; x < 5; x++) {
            for (var y = 0; y < 5; y++) {
                var src = B[y + 5 * ((2 * x + 3 * y) % 5)], rot = RHO[x][y], dst = new Array(64);
                for (var z = 0; z < 64; z++) { dst[z] = src[(z + rot) % 64]; }
                A[x + 5 * y] = dst;
            }
        }
        return A;
    }
    /* iota: the round constant into lane (0, 0), at degree d */
    function iota(A, d, r) {
        var l = A[0].slice(), rc = RC[r];
        for (var z = 0; z < 64; z++) { if ((rc >> BigInt(z)) & BigInt(1)) { l[z] = Rg.add(l[z], one(d)); } }
        var out = A.slice(); out[0] = l;
        return out;
    }
    /* chi: out_x = b_x + (b_x+1 + 1) b_x+2, degree d -> 2d */
    function chi(B, d) {
        var out = [];
        for (var y = 0; y < 5; y++) {
            for (var x = 0; x < 5; x++) {
                var b0 = B[x + 5 * y], b1 = B[(x + 1) % 5 + 5 * y], b2 = B[(x + 2) % 5 + 5 * y], l = [];
                for (var z = 0; z < 64; z++) { l.push(Rg.add(sh(b0[z], d), Rg.mul(Rg.add(b1[z], one(d)), b2[z]))); }
                out.push(l);
            }
        }
        return out;
    }
    /* chi^-1 on a 5-bit row: a_x = y_x + (y_x+1 + 1)(y_x+2 + (y_x+3 + 1) y_x+4), degree d -> 3d */
    function chi_inv(Y, d) {
        var out = [];
        for (var y = 0; y < 5; y++) {
            for (var x = 0; x < 5; x++) {
                var y0 = Y[x + 5 * y], y1 = Y[(x + 1) % 5 + 5 * y], y2 = Y[(x + 2) % 5 + 5 * y], y3 = Y[(x + 3) % 5 + 5 * y], y4 = Y[(x + 4) % 5 + 5 * y], l = [];
                for (var z = 0; z < 64; z++) {
                    var inner = Rg.add(sh(y2[z], d), Rg.mul(Rg.add(y3[z], one(d)), y4[z]));
                    l.push(Rg.add(sh(y0[z], 2 * d), Rg.mul(Rg.add(y1[z], one(d)), inner)));
                }
                out.push(l);
            }
        }
        return out;
    }
    return {
        load: load, sh: sh,
        forward: function (A, d, r) { return iota(chi(rho_pi(theta(A)), d), 2 * d, r); },
        backward: function (A, d, r) { return theta_inv(rho_pi_inv(chi_inv(iota(A, d, r), d))); }
    };
}

/**
 * The constraints "out = Round_{r0 + nf + nb - 1} o ... o Round_{r0}(in)": nf
 * rounds forward from in, nb rounds back from out, and the 1600 meeting
 * values equal - of degree max(2^nf, 3^nb), since chi is quadratic and its
 * inverse cubic. (1, 0) is one round at degree 2; (4, 2) six rounds at
 * degree 16, so committing every sixth state.
 *
 * @param {object}   Rg      the proof system's ring
 * @param {function} emit    emit(c, degree)
 * @param {function} inb     (i) -> the ring value of input bit i (degree 1)
 * @param {function} outb    (i) -> the ring value of output bit i (degree 1)
 * @param {number}   r0      the first round's index
 * @param {number}   nf, nb  the rounds forward and back
 */
export function keccak_block_constraints(Rg, emit, inb, outb, r0, nf, nb) {
    var K = ring_ops(Rg), A = K.load(inb), B = K.load(outb), d = 1, e = 1, j;
    for (j = 0; j < nf; j++) { A = K.forward(A, d, r0 + j); d *= 2; }
    for (j = 0; j < nb; j++) { B = K.backward(B, e, r0 + nf + nb - 1 - j); e *= 3; }
    var D = Math.max(d, e);
    for (var q = 0; q < 25; q++) { for (var z = 0; z < 64; z++) { emit(Rg.add(K.sh(A[q][z], D - d), K.sh(B[q][z], D - e)), D); } }
}

/** The 1600 quadratic constraints "out = Round_r(in)". */
export function keccak_round_constraints(Rg, emit, inb, outb, r) {
    keccak_block_constraints(Rg, emit, inb, outb, r, 1, 0);
}
