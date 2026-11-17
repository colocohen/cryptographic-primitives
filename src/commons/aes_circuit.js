/**
 * AES / Rijndael as a circuit, for proofs (commons/voleith.js)
 *
 * FAEST's statement, on its own: the extended witness of a Rijndael
 * encryption (the key, the key-schedule words that pass through the S-box,
 * and the state after every other round) and its constraints of degree 7
 * over GF(2^lambda) - each S-box checked through the conjugates of its input
 * and output byte, two rounds per committed state. faest.js proves one key's
 * encryptions with it; ring_aes.js proves encryptions under a key selected
 * from a ring.
 *
 * BLOCKS AS RING VALUES. An encryption is constrained between an input and
 * an output given as arrays of ring bits - constants (cbits of public bytes)
 * or committed witness bits alike - so a statement may hide which public
 * block it encrypts.
 *
 * aes_circuit(F, W, lambda, Nst):
 *   lambda          the key size: 128, 192 or 256 (also the field)
 *   Nst             the block's columns: 4 for AES, 6 / 8 for Rijndael-192/256
 *   LKE, LENC       witness bits of the key schedule and of one block
 *   key_witness(k)  -> bytes: k and the S-box key-schedule words
 *   block_witness(rk, x) -> bytes: the committed states of one encryption
 *   round_keys(k, nb), encrypt(rk, x)  the plain cipher
 *   cbits(Rg, bytes, n), wbits(Rg, off, n)  ring bit vectors
 *   key_schedule(Rg, emit, off) -> rk   witness key at off; emits its constraints
 *   block(Rg, emit, rk, input, output, off)  emits one encryption's constraints
 */

import { rijndael_key } from './rijndael.js';
import { AES_SBOX, gmul, POLY_AES } from './gf256.js';
import { from_hex as hex, concat } from './bytes.js';
import { bit_le as bit } from './bitpack.js';

/* theta, the image of x in GF(2^8) -> GF(2^lambda) (FAEST's byte embedding); every other constant follows from it */
var THETA = {
    128: '0dce6055ace83fa11c9a97a955853d05',
    192: '6397386fd5a3c8cceabd6e966cd765e662366b0e14c80b31',
    256: 'e7fede0b42889796674e47a0388dd6be6ae1f1f8459822df3358c920cfa8c904'
};
var RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a];
/* lambda -> the S-box key-schedule bytes of AES-lambda */
var SKE = { 128: 40, 192: 32, 256: 52 };

/* ---- Rijndael on bytes, with the round states the witness needs ---- */
function round_keys(key, nb) {
    var ks = rijndael_key(key, nb), b = new Uint8Array(ks.w.length * 4);
    for (var i = 0; i < ks.w.length; i++) { var v = ks.w[i]; b[4 * i] = v >>> 24; b[4 * i + 1] = (v >>> 16) & 0xff; b[4 * i + 2] = (v >>> 8) & 0xff; b[4 * i + 3] = v & 0xff; }
    return { b: b, nr: ks.nr };
}
function shift_src(Nst, c, r) { return 4 * ((c + (Nst === 8 && r >= 2 ? r + 1 : r)) % Nst) + r; }
/* encrypt one Nst-column block; on_state(round, state) after SubBytes+ShiftRows of rounds 1..nr-1 */
function rijndael_rounds(rk, nr, Nst, input, on_state) {
    var n = 4 * Nst, s = new Uint8Array(n), t = new Uint8Array(n), r, i, c;
    for (i = 0; i < n; i++) { s[i] = input[i] ^ rk[i]; }
    for (r = 1; r <= nr; r++) {
        for (c = 0; c < Nst; c++) { for (i = 0; i < 4; i++) { t[4 * c + i] = AES_SBOX[s[shift_src(Nst, c, i)]]; } }
        if (r < nr) {
            if (on_state) { on_state(r, t); }
            for (c = 0; c < Nst; c++) {
                var a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
                s[4 * c] = gmul(a0, 2, POLY_AES) ^ gmul(a1, 3, POLY_AES) ^ a2 ^ a3;
                s[4 * c + 1] = a0 ^ gmul(a1, 2, POLY_AES) ^ gmul(a2, 3, POLY_AES) ^ a3;
                s[4 * c + 2] = a0 ^ a1 ^ gmul(a2, 2, POLY_AES) ^ gmul(a3, 3, POLY_AES);
                s[4 * c + 3] = gmul(a0, 3, POLY_AES) ^ a1 ^ a2 ^ gmul(a3, 2, POLY_AES);
            }
        } else { s.set(t); }
        for (i = 0; i < n; i++) { s[i] ^= rk[r * n + i]; }
    }
    return s;
}

export function aes_circuit(F, W, lambda, Nst) {
    var NK = lambda / 32, R = { 128: 10, 192: 12, 256: 14 }[Math.max(lambda, 32 * Nst)], Ske = SKE[lambda];
    var blocksize = 32 * Nst, NB = 4 * Nst, LKE = lambda + 8 * Ske, LENC = blocksize * (R / 2 - 1);
    var C = constants();

    function constants() {
        var th = F.from_bytes(hex(THETA[lambda]), 0, 1), pw = new Uint32Array(8 * W), i;
        pw[0] = 1; F.copy(pw, W, th, 0);
        for (i = 2; i < 8; i++) { F.mul(pw, i * W, pw, (i - 1) * W, th, 0); }
        function phi(b) { var r = new Uint32Array(W); for (var q = 0; q < 8; q++) { if ((b >> q) & 1) { F.add(r, 0, r, 0, pw, q * W); } } return r; }
        /* the S-box's linear part as sum a_k y^(2^k), solved over GF(2^8) */
        function lin(x) { var y = 0; for (var q = 0; q < 8; q++) { y |= (((x >> q) ^ (x >> ((q + 4) % 8)) ^ (x >> ((q + 5) % 8)) ^ (x >> ((q + 6) % 8)) ^ (x >> ((q + 7) % 8))) & 1) << q; } return y; }
        function frob(x, n) { for (var q = 0; q < n; q++) { x = gmul(x, x, POLY_AES); } return x; }
        var M = [], rhs = [], c, r;
        for (r = 0; r < 8; r++) { M.push([0, 1, 2, 3, 4, 5, 6, 7].map(function (kk) { return frob(1 << r, kk); })); rhs.push(lin(1 << r)); }
        for (c = 0; c < 8; c++) {
            var p = c; while (!M[p][c]) { p++; }
            var tt = M[c]; M[c] = M[p]; M[p] = tt; tt = rhs[c]; rhs[c] = rhs[p]; rhs[p] = tt;
            var iv = 1; while (gmul(M[c][c], iv, POLY_AES) !== 1) { iv++; }
            M[c] = M[c].map(function (v) { return gmul(v, iv, POLY_AES); }); rhs[c] = gmul(rhs[c], iv, POLY_AES);
            for (r = 0; r < 8; r++) {
                if (r !== c && M[r][c]) { var f = M[r][c]; M[r] = M[r].map(function (v, kk) { return v ^ gmul(f, M[c][kk], POLY_AES); }); rhs[r] ^= gmul(f, rhs[c], POLY_AES); }
            }
        }
        var sq = [];
        for (i = 0; i < 8; i++) { sq.push(gmul(1 << i, 1 << i, POLY_AES)); }
        return { alpha: pw, c: rhs.map(phi).concat([phi(0x63)]), bc2: th, sq: sq };
    }

    /* ---- the witness ---- */
    function key_witness(key) {
        var kk = round_keys(key, 4), parts = [kk.b.subarray(0, lambda / 8)];
        for (var j = 0, ik = NK; j < Ske / 4; j++, ik += lambda === 192 ? 6 : 4) { parts.push(kk.b.subarray(4 * ik, 4 * ik + 4)); }
        return concat(parts);
    }
    function block_witness(rk, x) {
        var parts = [];
        rijndael_rounds(rk.b, rk.nr, Nst, x, function (r, s) { if (r % 2 === 0) { parts.push(s.slice()); } });
        return concat(parts);
    }

    /* ---- the constraints, over the proof system's ring ---- */
    function wbits(Rg, off, n) { var v = []; for (var q = 0; q < n; q++) { v.push(Rg.bit(off + q)); } return v; }
    function cbits(Rg, bytes, n) { var v = []; for (var q = 0; q < n; q++) { v.push(Rg.cbit(bit(bytes, q))); } return v; }

    function ops(Rg) {
        function addv(a, bb) { return a.map(function (x, q) { return Rg.add(x, bb[q]); }); }
        function combine(x) { var y = x[0]; for (var q = 1; q < 8; q++) { y = Rg.add(y, Rg.scale(x[q], C.alpha.subarray(q * W, (q + 1) * W))); } return y; }
        function sq_bits(x) {
            var o = [];
            for (var q = 0; q < 8; q++) {
                var acc = null;
                for (var s = 0; s < 8; s++) { if ((C.sq[s] >> q) & 1) { acc = acc ? Rg.add(acc, x[s]) : x[s]; } }
                o.push(acc);
            }
            return o;
        }
        function conj(x) { var y = [combine(x)], s = x; for (var q = 1; q < 8; q++) { s = sq_bits(s); y.push(combine(s)); } return y; }
        function inv_affine(x) {
            var y = [];
            for (var q = 0; q < 8; q++) {
                var v = Rg.add(Rg.add(x[(q + 7) % 8], x[(q + 5) % 8]), x[(q + 2) % 8]);
                y.push(q === 0 || q === 2 ? Rg.add(v, Rg.cbit(1)) : v);
            }
            return y;
        }
        return { addv: addv, combine: combine, sq_bits: sq_bits, conj: conj, inv_affine: inv_affine };
    }

    /* the key schedule, forward from the witness words and backward through the S-box */
    function key_schedule(Rg, emit, off) {
        var O = ops(Rg), i, j, r;
        var rk = wbits(Rg, off, lambda);
        for (j = NK, i = off + lambda; j < 4 * (R + 1); j++) {
            if (j % NK === 0 || (NK > 6 && j % NK === 4)) { rk = rk.concat(wbits(Rg, i, 32)); i += 32; }
            else { rk = rk.concat(O.addv(rk.slice(32 * (j - NK), 32 * (j - NK + 1)), rk.slice(32 * (j - 1), 32 * j))); }
        }
        var every = 4 * Math.floor(lambda / 128), inc = lambda === 192 ? 192 : 128, flat = [];
        for (j = 0, i = 0; j < Ske; j++) {
            var xt = O.addv(wbits(Rg, off + lambda + 8 * j, 8), rk.slice(i + (j % 4) * 8, i + (j % 4) * 8 + 8));
            if (j % every === 0) { xt = O.addv(xt, cbits(Rg, [RCON[j / every]], 8)); }
            flat = flat.concat(O.inv_affine(xt));
            if (j % 4 === 3) { i += inc; }
        }
        for (j = 0, i = 32 * (NK - 1); j < Ske; j += 4, i += inc) {
            for (r = 0; r < 4; r++) {
                var rp = lambda === 256 && j % 8 !== 0 ? r : (r + 1) % 4;
                var kb = rk.slice(i + 8 * rp, i + 8 * rp + 8), wb = flat.slice(8 * j + 8 * r, 8 * j + 8 * r + 8);
                var K = O.combine(kb), Ksq = O.combine(O.sq_bits(kb)), Wv = O.combine(wb), Wsq = O.combine(O.sq_bits(wb));
                emit(Rg.add(Rg.mul(Ksq, Wv), Rg.shift(K, 1)), 2);
                emit(Rg.add(Rg.mul(K, Wsq), Rg.shift(Wv, 1)), 2);
            }
        }
        return rk;
    }

    /* one encryption output = E_rk(input), the committed states at witness bit off */
    function block(Rg, emit, rk, input, output, off) {
        var O = ops(Rg), r, q, c;
        function sbox(x) {
            var cj = O.conj(x), p1 = [], f1 = [], p2 = [], f2 = [], k;
            for (k = 0; k < 4; k++) {
                p1.push(Rg.mul(cj[2 * k], cj[2 * k + 1]));
                f1.push(Rg.add(Rg.scale(cj[2 * k + 1], C.c[2 * k]), Rg.scale(cj[2 * k], C.c[2 * k + 1])));
            }
            for (k = 0; k < 2; k++) {
                p2.push(Rg.mul(p1[2 * k], p1[2 * k + 1]));
                f2.push(Rg.add(Rg.mul(f1[2 * k], p1[2 * k + 1]), Rg.mul(f1[2 * k + 1], p1[2 * k])));
            }
            return Rg.add(Rg.add(Rg.mul(f2[0], p2[1]), Rg.mul(f2[1], p2[0])), Rg.cfield(C.c[8], 7));
        }
        function inv_sbox(x) { var cj = O.conj(O.inv_affine(x)), y = cj[1]; for (var k = 2; k < 8; k++) { y = Rg.mul(y, cj[k]); } return y; }
        function rinv(cc, rr) { var s = Nst === 8 && rr >= 2 ? rr + 1 : rr; return 4 * ((cc + Nst - s) % Nst) + rr; }
        var st = O.addv(input, rk.slice(0, blocksize));
        for (r = 0; r < R / 2; r++) {
            var z = [], zz = [], z3 = [];
            for (q = 0; q < NB; q++) { z.push(sbox(st.slice(8 * q, 8 * q + 8))); }
            for (c = 0; c < Nst; c++) { for (q = 0; q < 4; q++) { zz[4 * c + q] = z[shift_src(Nst, c, q)]; } }
            for (c = 0; c < Nst; c++) {
                var a4 = zz.slice(4 * c, 4 * c + 4), sum = Rg.add(Rg.add(a4[0], a4[1]), Rg.add(a4[2], a4[3]));
                for (q = 0; q < 4; q++) { z3.push(Rg.add(Rg.add(a4[q], sum), Rg.scale(Rg.add(a4[q], a4[(q + 1) % 4]), C.bc2))); }
            }
            var kr = rk.slice((2 * r + 1) * blocksize, (2 * r + 2) * blocksize);
            for (q = 0; q < NB; q++) { z3[q] = Rg.add(z3[q], Rg.shift(O.combine(kr.slice(8 * q, 8 * q + 8)), 6)); }
            var last = r === R / 2 - 1;
            var stl = last ? O.addv(output, rk.slice(R * blocksize, (R + 1) * blocksize)) : wbits(Rg, off + blocksize * r, blocksize);
            for (c = 0; c < Nst; c++) {
                for (q = 0; q < 4; q++) {
                    var src = rinv(c, q), bb = inv_sbox(stl.slice(8 * src, 8 * src + 8));
                    emit(Rg.add(bb, z3[4 * c + q]), 7);
                }
            }
            if (!last) {
                var mixed = [];
                for (c = 0; c < Nst; c++) {
                    var av = stl.slice(32 * c, 32 * c + 32), bv = [];
                    for (q = 0; q < 4; q++) {
                        var a8 = av.slice(8 * q, 8 * q + 8);
                        bv.push(a8[7], Rg.add(a8[0], a8[7]), a8[1], Rg.add(a8[2], a8[7]), Rg.add(a8[3], a8[7]), a8[4], a8[5], a8[6]);
                    }
                    for (q = 0; q < 4; q++) {
                        for (var t = 0; t < 8; t++) {
                            var cs = Rg.add(Rg.add(av[t], av[8 + t]), Rg.add(av[16 + t], av[24 + t]));
                            mixed.push(Rg.add(Rg.add(Rg.add(av[8 * q + t], cs), bv[8 * q + t]), bv[8 * ((q + 1) % 4) + t]));
                        }
                    }
                }
                st = O.addv(mixed, rk.slice((2 * r + 2) * blocksize, (2 * r + 3) * blocksize));
            }
        }
    }

    return {
        lambda: lambda, Nst: Nst, R: R, BLOCK_BITS: blocksize, LKE: LKE, LENC: LENC,
        round_keys: round_keys, encrypt: function (rk, x) { return rijndael_rounds(rk.b, rk.nr, Nst, x); },
        key_witness: key_witness, block_witness: block_witness,
        wbits: wbits, cbits: cbits, key_schedule: key_schedule, block: block
    };
}

