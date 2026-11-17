/**
 * Post-quantum and hybrid PAKEs  -  draft-vos-cfrg-pqpake-03
 *
 * FOUR PROTOCOLS on one interface (section 5): each party inputs a password
 * (PRS, or a verifier of it), a public_context and a secret_context, and two
 * parties end with the same key exactly when all three match.
 *
 *   OQUAKE         symmetric, post-quantum: the initiator's KEM public key is
 *                  encrypted under the password by a two-round Feistel
 *                  network; the responder encapsulates to it (section 6)
 *   CPaceOQUAKE    hybrid: CPace (cpace.js) first, then OQUAKE keyed by
 *                  CPace's session key - as strong as the STRONGER of the two,
 *                  classical or post-quantum (section 7)
 *   OQUAKE+        augmented: the server stores a verifier, not the password,
 *   CPaceOQUAKE+   and the client proves it knows the password by decapsulating
 *                  a KEM challenge to a key only the password derives
 *                  (section 8)
 *
 * THE KEM INSIDE OQUAKE MUST LOOK RANDOM: every byte string must be a valid
 * public key (otherwise a wrong-password decryption is recognisable) and the
 * keys must be indistinguishable from uniform. ML-BUA-sKEM is ML-KEM with its
 * keys Kemeleon-encoded (kemeleon.js, t = 132), and SPLITTABLE: the last 32
 * bytes, rho, do not depend on the secret key and are sent in the clear.
 *
 * WHAT THE PROTOCOLS DO NOT SAY. OQUAKE and CPaceOQUAKE never report a
 * wrong password: the parties simply hold different keys (section 6.3). Only
 * the augmented protocols confirm the password and raise an error.
 *
 * THE CONFIGURATIONS are section 9's, by identifier, each with its own DST;
 * the appendix E vectors cover the first configuration of each protocol and
 * ML-BUA-sKEM-768 and -1024.
 *
 * RANDOMNESS. Every function that needs any takes an rng; each documents the
 * order in which it draws, which is the order appendix E lists its values.
 * An rng omitted or null draws fresh bytes from the platform.
 */

import { CPACE_X25519_SHA512, CPACE_P384_SHA384, CPACE_P256_SHA256, transcript_ir } from './cpace.js';
import { kemeleon } from './kemeleon.js';
import { ml_kem768, ml_kem1024 } from './ml_kem.js';
import * as xwing from './xwing.js';
import { mlkem1024_p384, mlkem768_p256 } from './hybrid_kem.js';
import { hkdf_extract, hkdf_expand } from './kdf.js';
import { sha256 } from './sha2.js';
import { scrypt } from './scrypt.js';
import { concat, ascii, be32, lp16, xor, from_hex } from './commons/bytes.js';
import { equal_bool, select_bytes, equal } from './commons/ct.js';
import { require_rng } from './commons/primes.js';

var EMPTY = new Uint8Array(0);

/* ==================== encodings (section 3.1, appendix C) ==================== */

/** A two-byte big-endian length, then the bytes. */
export var lv_encode = lp16;

/** The inverse of lv_encode at the start of buf: {value, rest}, or null when the length does not fit. */
export function lv_decode(buf) {
    if (!(buf instanceof Uint8Array) || buf.length < 2) { return null; }
    var n = (buf[0] << 8) | buf[1];
    if (buf.length < 2 + n) { return null; }
    return { value: buf.subarray(2, 2 + n), rest: buf.subarray(2 + n) };
}

/** EncodePublicContext (appendix C.1): sid, U and S with four-byte big-endian lengths. */
export function encode_public_context(sid, U, S) {
    var parts = [];
    [sid || EMPTY, U || EMPTY, S || EMPTY].forEach(function (f) { parts.push(be32(f.length), f); });
    return concat(parts);
}


function bytes_of(v, len, what) {
    if (!(v instanceof Uint8Array) || v.length !== len) { throw new Error('pqpake: ' + what + ' must be ' + len + ' bytes'); }
}

/* ==================== ML-BUA-sKEM (section 4.2.1) ==================== */

/**
 * ML-KEM with Kemeleon-encoded (t = 132) uniform public keys, split into ut
 * (secret-dependent) and rho (the matrix seed, the last 32 bytes).
 *
 * keygen(rng) draws the 64-byte ML-KEM seed d || z, then one Kemeleon m per
 * polynomial (M_BYTES each); encaps(upk, rng) draws ML-KEM's 32-byte m.
 */
export function ml_bua_skem(level) {
    var K = level === 768 ? ml_kem768 : level === 1024 ? ml_kem1024 : null;
    if (!K) { throw new Error('pqpake: ML-BUA-sKEM is defined for ML-KEM-768 and ML-KEM-1024'); }
    var E = kemeleon(level, 132);
    var Npk = E.EK_BYTES;
    return {
        name: 'ML-BUA-sKEM-' + level,
        Npk: Npk, Nt: Npk - 32, Nrho: 32, Nct: K.CT_BYTES, KEMELEON: E,
        keygen: function (rng) {
            rng = require_rng('ml_bua_skem.keygen', rng);
            var kp = K.keygen(rng(64));
            return { sk: kp.dk, pk: E.encode_ek(kp.ek, rng) };
        },
        split: function (upk) { bytes_of(upk, Npk, 'public key'); return { ut: upk.subarray(0, Npk - 32), rho: upk.subarray(Npk - 32) }; },
        combine: function (ut, rho) { return concat([ut, rho]); },
        /* every Npk-byte string decodes to a valid ML-KEM key, so this cannot fail */
        encaps: function (upk, rng) {
            rng = require_rng('ml_bua_skem.encaps', rng);
            bytes_of(upk, Npk, 'public key');
            var r = K.encaps(E.decode_ek(upk), rng(32));
            return { k: r.ss, ct: r.ct };
        },
        decaps: function (ct, sk) { return K.decaps(sk, ct); }
    };
}

/* ==================== the KEMs of password confirmation (section 4.1) ==================== */

/*
 * DeriveKeyPair takes the seed DIRECTLY (section 4.1): ML-KEM's
 * KeyGen_internal(seed[0:32], seed[32:64]), the hybrids'
 * GenerateKeyPairDerand(seed) - not the HPKE-style DeriveKeyPair(ikm).
 */
function mlkem_pc(K) {
    return {
        Nseed: 64, Npk: K.EK_BYTES, Nct: K.CT_BYTES,
        derive: function (seed) { var kp = K.keygen(seed); return { sk: kp.dk, pk: kp.ek }; },
        encaps: function (pk, rng) {
            rng = require_rng('pqpake.encaps', rng);
            var r = K.encaps(pk, rng(32));
            return { k: r.ss, ct: r.ct };
        },
        decaps: function (ct, sk) { return K.decaps(sk, ct); }
    };
}
function hybrid_pc(H) {
    return {
        Nseed: 32, Npk: H.PK_BYTES, Nct: H.CT_BYTES,
        derive: function (seed) { return H.keygen_derand(seed); },
        /* draws RAND_BYTES: ML-KEM's m, then the curve's ephemeral seed */
        encaps: function (pk, rng) { var r = H.encaps(pk, rng); return { k: r.ss, ct: r.ct }; },
        decaps: function (ct, sk) { return H.decaps(sk, ct); }
    };
}

export var PC_KEMS = {
    'ML-KEM-768': /* @__PURE__ */ mlkem_pc(ml_kem768),
    'ML-KEM-1024': /* @__PURE__ */ mlkem_pc(ml_kem1024),
    'X-Wing': /* @__PURE__ */ hybrid_pc(xwing),
    'MLKEM1024-P384': /* @__PURE__ */ hybrid_pc(mlkem1024_p384),
    'MLKEM768-P256': /* @__PURE__ */ hybrid_pc(mlkem768_p256)
};

/** scrypt(N = 32768, r = 8, p = 1), section 9's PC-KSF: Stretch(msg, salt, L). */
export function ksf_scrypt(o) {
    var opt = o || {};
    return function (msg, salt, L) { return scrypt(msg, salt, opt.N || 32768, opt.r || 8, opt.p || 1, L); };
}

/* ==================== configurations (section 9) ==================== */

var CONFIGS = {
    'oquake-mlbuaskem1024': { proto: 'oquake', bua: 1024, dst: '601ed384c5775ddd3021f51a4660fff24bf4eaa7845a958b2cade75289d184cd' },
    'oquake-mlbuaskem768': { proto: 'oquake', bua: 768, dst: 'ca45261d9fe329b856389ebbf7f37ffa76c0034d8fc356454e1291d7d23e2045' },
    'oquakeplus-mlbuaskem1024-mlkem1024': { proto: 'oquakeplus', bua: 1024, kem: 'ML-KEM-1024',
        dst: '284e89132c00ba4f49e66d0af9e63c4c8efa701ce4b66bb6fcf1ce9cc5c35be1' },
    'oquakeplus-mlbuaskem768-mlkem768': { proto: 'oquakeplus', bua: 768, kem: 'ML-KEM-768',
        dst: '2a1a96e307871d45a9739c7193eeb04d6f52d17c67a52f762e5aae17df1ee5e6' },
    'cpaceoquake-x25519-mlbuaskem1024': { proto: 'cpaceoquake', cpace: 'X25519', bua: 1024,
        dst: '443e3089985f0f8dddfb20cc5e8618f447bdcfe6dd39abb23911cd784c075120' },
    'cpaceoquake-x25519-mlbuaskem768': { proto: 'cpaceoquake', cpace: 'X25519', bua: 768,
        dst: 'c2ef9d7f73324735ec5614f331fa49c86c05be3430996c46816fca59d778380b' },
    'cpaceoquake-p384-mlbuaskem1024': { proto: 'cpaceoquake', cpace: 'P384', bua: 1024,
        dst: '1c8604e01071bc2bee8e4132399ded88a9f83c23ed8ab7130d2d2e0b597c0fb5' },
    'cpaceoquakeplus-x25519-mlbuaskem1024-xwing': { proto: 'cpaceoquakeplus', cpace: 'X25519', bua: 1024, kem: 'X-Wing',
        dst: '7de162c387ba1bad9c790e7e56bd245d6753d045185cbc3972eba34ddac1a9db' },
    'cpaceoquakeplus-p384-mlbuaskem1024-mlkem1024p384': { proto: 'cpaceoquakeplus', cpace: 'P384', bua: 1024, kem: 'MLKEM1024-P384',
        dst: 'd8fcdaf8c2c8c429a2ff93ff658d07050017487dc367d11cabb54f2a7dd2b5fd' },
    'cpaceoquakeplus-x25519-mlbuaskem768-xwing': { proto: 'cpaceoquakeplus', cpace: 'X25519', bua: 768, kem: 'X-Wing',
        dst: '07d746a69c979f51e46d0051f0878a05ac5ec457d93c72ec6b814f528aae46f2' },
    /* section 9.6's example: P-256 throughout; the draft gives it no identifier, this is the section's naming rule */
    'cpaceoquakeplus-p256-mlbuaskem768-mlkem768p256': { proto: 'cpaceoquakeplus', cpace: 'P256', bua: 768, kem: 'MLKEM768-P256',
        dst: '38a518ec4b20d388f06504e78d6307b000f11e82fa3e5ff575b526129cf70953' }
};
export var CONFIG_IDS = Object.keys(CONFIGS);
var CPACE = { X25519: CPACE_X25519_SHA512, P384: CPACE_P384_SHA384, P256: CPACE_P256_SHA256 };

/* section 9.1, common to all configurations */
var Nv = 32, Nkc = 32, Nr = 64, Nkey = 32;

/**
 * One configuration of section 9.
 *
 * @param {string} id   an identifier from CONFIG_IDS
 * @param {object} [o]  { ksf } to replace the PC-KSF (scrypt with section 9's
 *                      parameters) - e.g. for a cheaper one in tests
 * @return the protocol's functions; see each below
 */
export function pqpake(id, o) {
    var C = CONFIGS[id];
    if (!C) { throw new Error('pqpake: unknown configuration ' + id); }
    var DST = from_hex(C.dst);
    var BUA = ml_bua_skem(C.bua);
    var KEM = C.kem ? PC_KEMS[C.kem] : null;
    var KSF = (o && o.ksf) || ksf_scrypt();
    var CP = C.cpace ? CPACE[C.cpace] : null;

    /* ---------------- the KDF: HKDF-SHA-256 everywhere (section 4.3) ---------------- */
    function d(s) { return concat([DST, ascii(s)]); }
    function extract(salt, ikm) { return hkdf_extract(sha256, ikm, salt); }
    function expand(prk, info, L) { return hkdf_expand(sha256, prk, L, info); }
    function TH(label) {
        var f = [];
        for (var i = 1; i < arguments.length; i++) { f.push(lv_encode(arguments[i])); }
        return extract(d('TH-' + label), concat(f));
    }

    /* ==================== OQUAKE (section 6) ==================== */

    function effective_prs(PRS, pub, sec) {
        var prk = extract(PRS, concat([d('OQUAKE-context'), lv_encode(pub), lv_encode(sec)]));
        return expand(prk, d('effective_PRS'), Nkey);
    }
    function pads(ePRS, rho, r_or_T, label, L) {
        return expand(extract(ePRS, concat([d('OQUAKE'), rho, r_or_T])), d(label), L);
    }
    function session(ePRS, s, T, rho, pk, ct, k) {
        var prk = extract(ePRS, concat([d('OQUAKE'), s, T, rho, pk, ct, k]));
        return { h: expand(prk, d('confirm'), Nkc), key: expand(prk, d('key'), Nkey) };
    }
    var INIT_BYTES = Nr + BUA.Nt + BUA.Nrho, RESP_BYTES = BUA.Nct + Nkc;

    var OQUAKE = {
        /** Init. Draws: the BUA-sKEM key pair (see ml_bua_skem), then r (Nr bytes). @return {{state, msg}} */
        init: function (PRS, pub, sec, rng) {
            rng = require_rng('oquake.init', rng);
            var e = effective_prs(PRS, pub || EMPTY, sec || EMPTY);
            var kp = BUA.keygen(rng), sp = BUA.split(kp.pk);
            var r = rng(Nr);
            var T = xor(sp.ut, pads(e, sp.rho, r, 'T_pad', BUA.Nt));
            var s = xor(r, pads(e, sp.rho, T, 's_pad', Nr));
            return { state: { e: e, sk: kp.sk, pk: kp.pk, rho: sp.rho, s: s, T: T, pub: pub || EMPTY },
                     msg: concat([s, T, sp.rho]) };
        },
        /** Respond. Draws: the BUA-sKEM encapsulation. @return {{msg, key, th}} */
        respond: function (PRS, pub, sec, init_msg, rng) {
            rng = require_rng('oquake.respond', rng);
            bytes_of(init_msg, INIT_BYTES, 'OQUAKE initiator message');
            var s = init_msg.subarray(0, Nr), T = init_msg.subarray(Nr, Nr + BUA.Nt), rho = init_msg.subarray(Nr + BUA.Nt);
            var e = effective_prs(PRS, pub || EMPTY, sec || EMPTY);
            var r = xor(s, pads(e, rho, T, 's_pad', Nr));
            var pk = BUA.combine(xor(T, pads(e, rho, r, 'T_pad', BUA.Nt)), rho);
            var en = BUA.encaps(pk, rng);
            var x = session(e, s, T, rho, pk, en.ct, en.k);
            return { msg: concat([en.ct, x.h]), key: x.key, th: TH('OQUAKE', pub || EMPTY, s, T, rho, en.ct, x.h) };
        },
        /**
         * Finish. NEVER REPORTS A WRONG PASSWORD: a failed confirmation gives
         * a random key (section 6.3). Draws Nkey bytes for that key ALWAYS,
         * so that the rng's use does not say which branch was taken.
         *
         * @return {{key, th}}
         */
        finish: function (st, resp_msg, rng) {
            rng = require_rng('oquake.finish', rng);
            bytes_of(resp_msg, RESP_BYTES, 'OQUAKE responder message');
            var ct = resp_msg.subarray(0, BUA.Nct), h = resp_msg.subarray(BUA.Nct);
            var th = TH('OQUAKE', st.pub, st.s, st.T, st.rho, ct, h);
            var random_key = rng(Nkey);
            var x = session(st.e, st.s, st.T, st.rho, st.pk, ct, BUA.decaps(ct, st.sk));
            return { key: select_bytes(equal(h, x.h), x.key, random_key), th: th };
        },
        INIT_BYTES: INIT_BYTES, RESP_BYTES: RESP_BYTES
    };

    /* ==================== CPace, wrapped (appendix B) ==================== */

    /*
     * CPace's CI is the secret_context and its sid the public_context; no
     * associated data. A neutral-element K is CPaceError - thrown.
     */
    var CPW = CP && {
        init: function (PRS, pub, sec, rng) {
            rng = require_rng('cpace.init', rng);
            var g = CP.calculate_generator(PRS, sec, pub);
            var y = CP.sample_scalar(rng);
            var Y = CP.scalar_mult(y, g);
            return { state: { y: y, Y: Y }, Y: Y };
        },
        respond: function (PRS, pub, sec, Ya, rng) {
            rng = require_rng('cpace.respond', rng);
            var g = CP.calculate_generator(PRS, sec, pub);
            var yb = CP.sample_scalar(rng), Yb = CP.scalar_mult(yb, g);
            var K = CP.scalar_mult_vfy(yb, Ya);
            if (K === null) { throw new Error('pqpake: CPaceError - the peer share gives the neutral element'); }
            return { isk: CP.isk(pub, K, transcript_ir(Ya, EMPTY, Yb, EMPTY)), Y: Yb, th: TH('CPace', pub, Ya, Yb) };
        },
        finish: function (st, pub, Yb) {
            var K = CP.scalar_mult_vfy(st.y, Yb);
            if (K === null) { throw new Error('pqpake: CPaceError - the peer share gives the neutral element'); }
            return { isk: CP.isk(pub, K, transcript_ir(st.Y, EMPTY, Yb, EMPTY)), th: TH('CPace', pub, st.Y, Yb) };
        }
    };
    var Y_BYTES = CP && (CP.G.DST ? 2 * CP.G.field_size_bytes + 1 : CP.G.field_size_bytes);

    /* ==================== CPaceOQUAKE (section 7) ==================== */

    function combined_key(key2, th2, key1) {
        return expand(extract(key2, concat([d('CPaceOQUAKE'), th2, key1])), d('key'), Nkey);
    }
    function parse_ya(msg1) {
        var l = lv_decode(msg1);
        if (!l || l.rest.length !== 0 || l.value.length !== Y_BYTES) { throw new Error('pqpake: CPaceOQUAKE msg1 has the wrong length'); }
        return l.value;
    }

    var CPO = CP && {
        /** Init (client). Draws: the CPace scalar. @return {{state, msg}} */
        init: function (PRS, pub, sec, rng) {
            rng = require_rng('cpaceoquake.init', rng);
            var c = CPW.init(PRS, pub || EMPTY, sec || EMPTY, rng);
            return { state: { c: c.state, PRS: PRS, pub: pub || EMPTY, sec: sec || EMPTY }, msg: lv_encode(c.Y) };
        },
        /** Respond (server). Draws: the CPace scalar, then OQUAKE.init's. THROWS CPaceError. @return {{state, msg}} */
        respond: function (PRS, pub, sec, msg1, rng) {
            rng = require_rng('cpaceoquake.respond', rng);
            var c = CPW.respond(PRS, pub || EMPTY, sec || EMPTY, parse_ya(msg1), rng);
            var o = OQUAKE.init(PRS, c.th, c.isk, rng);
            return { state: { o: o.state, key1: c.isk }, msg: concat([lv_encode(c.Y), o.msg]) };
        },
        /** InitiatorFinish (client). Draws: OQUAKE.respond's. THROWS CPaceError. @return {{key, msg, th}} */
        initiator_finish: function (st, msg2, rng) {
            rng = require_rng('cpaceoquake.initiator_finish', rng);
            var l = lv_decode(msg2);
            if (!l || l.value.length !== Y_BYTES || l.rest.length !== INIT_BYTES) {
                throw new Error('pqpake: CPaceOQUAKE msg2 has the wrong length');
            }
            var c = CPW.finish(st.c, st.pub, l.value);
            var r = OQUAKE.respond(st.PRS, c.th, c.isk, l.rest, rng);
            return { key: combined_key(r.key, r.th, c.isk), msg: r.msg, th: r.th };
        },
        /** ResponderFinish (server). Draws: OQUAKE.finish's. @return {{key, th}} */
        responder_finish: function (st, msg3, rng) {
            var f = OQUAKE.finish(st.o, msg3, rng);
            return { key: combined_key(f.key, f.th, st.key1), th: f.th };
        }
    };

    /* ==================== the PAKE-to-aPAKE transformation (section 8.1) ==================== */

    function gen_verifier_material(PRS, salt, U, S) {
        var m = KSF(concat([DST, lv_encode(PRS), lv_encode(U || EMPTY), lv_encode(S || EMPTY)]), salt, Nv + KEM.Nseed);
        return { v: m.subarray(0, Nv), seed: m.subarray(Nv, Nv + KEM.Nseed) };
    }
    function kem_seed(seed, kem_blind) {
        return expand(extract(seed, concat([d('KEMSeed'), kem_blind])), d('kem_seed'), KEM.Nseed);
    }
    var ENC_C = KEM && KEM.Nct + 32, CHALLENGE_BYTES = KEM && ENC_C + Nkc;

    function pc_values(SK, th, enc_c, k) {
        var prk = extract(SK, concat([d('PC'), th, enc_c, k]));
        return { cc: expand(prk, d('client_confirm'), Nkc), sc: expand(prk, d('server_confirm'), Nkc), key: expand(prk, d('key'), Nkey) };
    }

    var PC = KEM && {
        /** Challenge (server). Draws: KEM.Encaps. The key in state is NOT to be used before verify. */
        challenge: function (SK, th, pk, kem_blind, rng) {
            /* resolved before the try below, which reports every throw as a bad key */
            rng = require_rng('pqpake.challenge', rng);
            bytes_of(kem_blind, 32, 'kem_blind');
            var en;
            try { en = KEM.encaps(pk, rng); } catch (e) { throw new Error('pqpake: EncapsError - the registered public key is invalid'); }
            var enc_c = xor(concat([en.ct, kem_blind]), expand(SK, d('OTP'), ENC_C));
            var x = pc_values(SK, th, enc_c, en.k);
            return { state: { sc: x.sc, key: x.key, th: TH('PC', th, enc_c, x.cc, x.sc) }, msg: concat([enc_c, x.cc]) };
        },
        /** Respond (client). THROWS AuthenticationError. @return {{key, msg, th}} */
        respond: function (SK, th, seed, challenge) {
            bytes_of(challenge, CHALLENGE_BYTES, 'password confirmation challenge');
            var enc_c = challenge.subarray(0, ENC_C), target = challenge.subarray(ENC_C);
            var cb = xor(enc_c, expand(SK, d('OTP'), ENC_C));
            var kp = KEM.derive(kem_seed(seed, cb.subarray(KEM.Nct)));
            var k;
            try { k = KEM.decaps(cb.subarray(0, KEM.Nct), kp.sk); } catch (e) { k = null; }
            var x = k && pc_values(SK, th, enc_c, k);
            if (!x || !equal_bool(x.cc, target)) { throw new Error('pqpake: AuthenticationError - password confirmation failed'); }
            return { key: x.key, msg: x.sc, th: TH('PC', th, enc_c, x.cc, x.sc) };
        },
        /** Verify (server). THROWS AuthenticationError; the key is released only here. @return {{key, th}} */
        verify: function (st, server_confirm) {
            if (!(server_confirm instanceof Uint8Array) || server_confirm.length !== Nkc || !equal_bool(server_confirm, st.sc)) {
                throw new Error('pqpake: AuthenticationError - password confirmation failed');
            }
            return { key: st.key, th: st.th };
        }
    };

    /* registration (sections 8.1.1, C.6) */
    var REG = KEM && {
        gen_verifier_material: gen_verifier_material,
        /** GenVerifier. Draws: kem_blind (32 bytes). @return {{v, pk, kem_blind}} */
        gen_verifier: function (PRS, salt, U, S, rng) {
            rng = require_rng('gen_verifier', rng);
            var m = gen_verifier_material(PRS, salt, U, S);
            var kem_blind = rng(32);
            return { v: m.v, pk: KEM.derive(kem_seed(m.seed, kem_blind)).pk, kem_blind: kem_blind };
        },
        /** The registration message: salt, v, pk, kem_blind, U, S. */
        encode_registration: function (r) {
            bytes_of(r.salt, 32, 'salt');
            return concat([r.salt, r.v, r.pk, r.kem_blind, lv_encode(r.U || EMPTY), lv_encode(r.S || EMPTY)]);
        },
        decode_registration: function (msg) {
            var head = 32 + Nv + KEM.Npk + 32;
            if (!(msg instanceof Uint8Array) || msg.length < head + 4) { throw new Error('pqpake: registration message too short'); }
            var u = lv_decode(msg.subarray(head)), s = u && lv_decode(u.rest);
            if (!s || s.rest.length !== 0) { throw new Error('pqpake: registration message framing is wrong'); }
            return { salt: msg.subarray(0, 32), v: msg.subarray(32, 32 + Nv), pk: msg.subarray(32 + Nv, 32 + Nv + KEM.Npk),
                     kem_blind: msg.subarray(32 + Nv + KEM.Npk, head), U: u.value, S: s.value };
        }
    };

    /* ==================== OQUAKE+ (section 8.2) ==================== */

    var OQP = KEM && {
        /** Init (client): the KSF, then OQUAKE.init over v. */
        init: function (PRS, salt, U, S, pub, sec, rng) {
            var m = gen_verifier_material(PRS, salt, U, S);
            var o = OQUAKE.init(m.v, pub, sec, rng);
            return { state: { o: o.state, seed: m.seed }, msg: o.msg };
        },
        /** Respond (server). Draws: OQUAKE.respond's, then the challenge's encapsulation. */
        respond: function (v, pub, sec, msg1, pk, kem_blind, rng) {
            var r = OQUAKE.respond(v, pub, sec, msg1, rng);
            var c = PC.challenge(r.key, r.th, pk, kem_blind, rng);
            return { state: c.state, msg: concat([r.msg, c.msg]) };
        },
        /** Finish (client). Draws: OQUAKE.finish's. THROWS AuthenticationError. @return {{key, msg, th}} */
        finish: function (st, msg2, rng) {
            bytes_of(msg2, RESP_BYTES + CHALLENGE_BYTES, 'OQUAKE+ responder message');
            var f = OQUAKE.finish(st.o, msg2.subarray(0, RESP_BYTES), rng);
            return PC.respond(f.key, f.th, st.seed, msg2.subarray(RESP_BYTES));
        },
        /** Verify (server). THROWS AuthenticationError. @return {{key, th}} */
        verify: function (st, msg3) { return PC.verify(st, msg3); }
    };

    /* ==================== CPaceOQUAKE+ (section 8.3) ==================== */

    var CPOP = KEM && CP && {
        init: function (PRS, salt, U, S, pub, sec, rng) {
            var m = gen_verifier_material(PRS, salt, U, S);
            var c = CPO.init(m.v, pub, sec, rng);
            return { state: { c: c.state, seed: m.seed }, msg: c.msg };
        },
        respond: function (v, pub, sec, msg1, rng) { return CPO.respond(v, pub, sec, msg1, rng); },
        /** InitiatorContinue: CPaceOQUAKE's key is SK for password confirmation only. */
        initiator_continue: function (st, msg2, rng) {
            var f = CPO.initiator_finish(st.c, msg2, rng);
            return { state: { SK: f.key, th: f.th, seed: st.seed }, msg: f.msg };
        },
        responder_continue: function (st, msg3, pk, kem_blind, rng) {
            var f = CPO.responder_finish(st, msg3, rng);
            return PC.challenge(f.key, f.th, pk, kem_blind, rng);
        },
        /** THROWS AuthenticationError. @return {{key, msg, th}} */
        initiator_finish: function (st, msg4) { return PC.respond(st.SK, st.th, st.seed, msg4); },
        /** THROWS AuthenticationError. @return {{key, th}} */
        responder_finish: function (st, msg5) { return PC.verify(st, msg5); }
    };

    var API = {
        id: id, DST: DST, BUA: BUA, KEM: KEM, CPACE: CP,
        sizes: { Nv: Nv, Nkc: Nkc, Nr: Nr, Nkey: Nkey },
        oquake: OQUAKE
    };
    if (C.proto === 'cpaceoquake' || C.proto === 'cpaceoquakeplus') { API.cpaceoquake = CPO; }
    if (C.proto === 'oquakeplus') { API.oquakeplus = OQP; }
    if (C.proto === 'cpaceoquakeplus') { API.cpaceoquakeplus = CPOP; }
    if (KEM) { API.registration = REG; API.password_confirmation = PC; }
    return API;
}
