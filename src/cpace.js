/**
 * CPace  -  draft-irtf-cfrg-cpace-21
 *
 * A BALANCED PAKE: two parties who share a password (PRS) agree on a key
 * (ISK) over an open channel, in one round, and an eavesdropper or an active
 * attacker learns nothing that lets it test passwords offline - each online
 * attempt tests one password.
 *
 * THE IDEA. Both sides hash the password, together with the channel
 * identifier CI and the session id sid, to a group element g whose discrete
 * log nobody knows. Then they run Diffie-Hellman with g as the base:
 *
 *     A: Ya = ya*g  ---------->
 *               <----------  B: Yb = yb*g
 *     K = ya*Yb = yb*Ya,   ISK = H(lv_cat(DSI||"_ISK", sid, K) || transcript)
 *
 * With the wrong password the two bases differ and the two K values are
 * unrelated; nothing in the transcript lets anyone check a guess without
 * running the protocol again.
 *
 * SEVEN CIPHER SUITES (section 5), over three kinds of group:
 *
 *   X25519, X448                    single-coordinate Montgomery ladders;
 *                                   the generator is Elligator 2 of a hash
 *   ristretto255, decaf448          prime-order abstractions; the generator
 *                                   is the element derivation of a hash
 *   P-256, P-384, P-521             short Weierstrass; the generator is
 *                                   encode_to_curve (SSWU, non-uniform)
 *
 * Every suite is pinned to the draft's appendix B vectors, including the
 * invalid and low-order inputs that MUST abort (section 9).
 *
 * WHAT THE APPLICATION OWNS (section 4.3): the party identifiers, folded into
 * CI or the associated data per section 10.1; a fresh sid where one is
 * available; key confirmation, when it needs it, on top of ISK.
 *
 * The string helpers below (prepend_len, lv_cat, o_cat, the transcripts) are
 * exported: the hybrid post-quantum PAKEs (pqpake.js) build on CPace and use
 * the same encodings.
 */

import { concat, ascii, bytes_to_bigint, bigint_to_bytes, bytes_to_bigint_le, bigint_to_bytes_le } from './commons/bytes.js';
import { map_to_curve_elligator2 } from './commons/h2c.js';
import { reject_zero } from './commons/montgomery.js';
import { field } from './commons/modp.js';
import { sha256, sha384, sha512 } from './sha2.js';
import { shake256 } from './sha3.js';
import { x25519 } from './x25519.js';
import { x448 } from './x448.js';
import * as r255 from './ristretto255.js';
import * as d448 from './decaf448.js';
import { p256, p384, p521, p256_h2c, p384_h2c, p521_h2c } from './nist.js';
import { require_rng } from './commons/primes.js';

/* ==================== string operations (section 6.3, appendix A) ==================== */

/** The LEB128 encoding of len(data), then data. */
export function prepend_len(data) {
    var len = data.length, pre = [];
    do {
        pre.push(len < 128 ? len : (len & 0x7f) | 0x80);
        len = Math.floor(len / 128);
    } while (len > 0);
    return concat([Uint8Array.from(pre), data]);
}

/** prepend_len of each argument, concatenated. */
export function lv_cat() {
    var parts = [];
    for (var i = 0; i < arguments.length; i++) { parts.push(prepend_len(arguments[i])); }
    return concat(parts);
}

/** bytes1 > bytes2 in lexicographic order, a longer string winning a tie on the common prefix. */
export function lexiographically_larger(a, b) {
    var n = Math.min(a.length, b.length);
    for (var i = 0; i < n; i++) {
        if (a[i] !== b[i]) { return a[i] > b[i]; }
    }
    return a.length > b.length;
}

var OC = /* @__PURE__ */ ascii('oc');

/** "oc", then the larger string, then the smaller - the same bytes whichever side computes it. */
export function o_cat(a, b) {
    return lexiographically_larger(a, b) ? concat([OC, a, b]) : concat([OC, b, a]);
}

/** The transcript when A initiates and B responds. */
export function transcript_ir(Ya, ADa, Yb, ADb) {
    return concat([lv_cat(Ya, ADa), lv_cat(Yb, ADb)]);
}

/** The transcript with no fixed roles: the same whichever party sent first. */
export function transcript_oc(Ya, ADa, Yb, ADb) {
    return o_cat(lv_cat(Ya, ADa), lv_cat(Yb, ADb));
}

/**
 * lv_cat(DSI, PRS, zero padding, CI, sid), the padding sized so that DSI and
 * PRS fill the hash's first input block (section 8.1): for a short password
 * the amount hashed does not depend on its length.
 */
export function generator_string(DSI, PRS, CI, sid, s_in_bytes) {
    var zpad = Math.max(0, s_in_bytes - 1 - prepend_len(PRS).length - prepend_len(DSI).length);
    return lv_cat(DSI, PRS, new Uint8Array(zpad), CI, sid);
}

/* ==================== hash functions (section 6.2) ==================== */

/*
 * hash(m, l) is the first l bytes of H(m), defaulting to b_in_bytes;
 * s_in_bytes is the input block size the generator string pads to.
 */
function fixed_hash(name, f, b, s) {
    return {
        name: name, b_in_bytes: b, bmax_in_bytes: b, s_in_bytes: s,
        hash: function (m, l) {
            var n = l === undefined ? b : l;
            if (n > b) { throw new Error('cpace: ' + name + ' gives at most ' + b + ' bytes'); }
            return f(m).subarray(0, n);
        }
    };
}
export var H_SHA256 = /* @__PURE__ */ fixed_hash('SHA-256', sha256, 32, 64);
export var H_SHA384 = /* @__PURE__ */ fixed_hash('SHA-384', sha384, 48, 128);
export var H_SHA512 = /* @__PURE__ */ fixed_hash('SHA-512', sha512, 64, 128);
export var H_SHAKE256 = {
    name: 'SHAKE-256', b_in_bytes: 64, bmax_in_bytes: Infinity, s_in_bytes: 136,
    hash: function (m, l) { return shake256(m, l === undefined ? 64 : l); }
};

/* ==================== group environments (section 8) ==================== */

/*
 * Each environment is
 *
 *   DSI                      domain separation identifier
 *   calculate_generator(H, PRS, CI, sid)  -> g, the environment's own form
 *   encode_generator(g)      -> bytes, as the vectors print it
 *   sample_scalar(rng)       -> scalar bytes, the environment's byte order;
 *                               rng omitted or null draws from the platform
 *   scalar_mult(y, g)        -> Y bytes
 *   scalar_mult_vfy(y, X)    -> K bytes, or NULL where the draft returns G.I
 *
 * NULL IS THE ABORT. Each kind of group has its own representation of the
 * neutral element - zero bytes, the identity's encoding, IEEE 1363's "error"
 * - and the protocol's one rule is "abort if K = G.I"; returning null for
 * all three states that rule once.
 */

/*
 * X25519 and X448 (section 8.2). The scalar is any field_size_bytes and the
 * DH function clamps it; the generator is Elligator 2 of the hashed generator
 * string, read as a u-coordinate with the unused top bits cleared (RFC 7748
 * decodeUCoordinate).
 */
function montgomery_env(DSI, bytes, bits, p, A, Z, dh) {
    var F = field(p), dsi = ascii(DSI);
    var mask = (1n << BigInt(bits)) - 1n;
    return {
        DSI: dsi, field_size_bytes: bytes, I: new Uint8Array(bytes),
        calculate_generator: function (H, PRS, CI, sid) {
            var h = H.hash(generator_string(dsi, PRS, CI, sid, H.s_in_bytes), bytes);
            var u = (bytes_to_bigint_le(h) & mask) % p;
            return bigint_to_bytes_le(map_to_curve_elligator2(F, A, Z, u).s, bytes);
        },
        encode_generator: function (g) { return g; },
        sample_scalar: function (rng) {
            rng = require_rng('cpace.sample_scalar', rng);
            return rng(bytes);
        },
        scalar_mult: function (y, g) { return dh(y, g); },
        scalar_mult_vfy: function (y, X) {
            if (!(X instanceof Uint8Array) || X.length !== bytes) { return null; }
            return reject_zero(dh(y, X));
        }
    };
}

export var G_X25519 = /* @__PURE__ */ montgomery_env('CPace255', 32, 255, (1n << 255n) - 19n, 486662n, 2n, x25519);
export var G_X448 = /* @__PURE__ */ montgomery_env('CPace448', 56, 448,
    (1n << 448n) - (1n << 224n) - 1n, 156326n, (1n << 448n) - (1n << 224n) - 2n, x448);

/*
 * ristretto255 and decaf448 (section 8.3). The generator is the element
 * derivation of 2 * field_size_bytes hashed bytes and stays a decoded
 * element; scalars are little-endian with the bits above group_size_bits
 * cleared, which keeps them below the order without a reduction.
 */
function abstraction_env(DSI, M, bytes, group_bits) {
    var top = (1n << BigInt(group_bits)) - 1n, dsi = ascii(DSI);
    function scalar(y) { return bytes_to_bigint_le(y) % M.ORDER; }
    return {
        DSI: dsi, field_size_bytes: bytes, I: new Uint8Array(bytes),
        calculate_generator: function (H, PRS, CI, sid) {
            var gen = generator_string(dsi, PRS, CI, sid, H.s_in_bytes);
            return M.from_uniform_bytes(H.hash(gen, 2 * bytes));
        },
        encode_generator: function (g) { return M.encode(g); },
        sample_scalar: function (rng) {
            rng = require_rng('cpace.sample_scalar', rng);
            return bigint_to_bytes_le(bytes_to_bigint_le(rng(bytes)) & top, bytes);
        },
        scalar_mult: function (y, g) { return M.encode(M.mul(scalar(y), g)); },
        scalar_mult_vfy: function (y, X) {
            var P = M.decode(X);
            if (P === null) { return null; }
            return reject_zero(M.encode(M.mul(scalar(y), P)));
        }
    };
}

export var G_RISTRETTO255 = /* @__PURE__ */ abstraction_env('CPaceRistretto255', r255, 32, 252);
export var G_DECAF448 = /* @__PURE__ */ abstraction_env('CPaceDecaf448', d448, 56, 445);

/*
 * Short Weierstrass curves (section 8.4). The generator is
 * encode_to_curve(gen_str, DSI || "_DST") with the curve's NU suite; shares
 * are SEC1 uncompressed; K is the x-coordinate of y*X, big-endian, after
 * IEEE 1363 A.16.10 validation of X - an invalid encoding, the point at
 * infinity and a product at infinity all abort.
 *
 * Scalars are big-endian, uniform in [1, n-1] by rejection.
 */
function weierstrass_env(suite, E, h2c) {
    var C = E.POINT, N = E.CURVE.n, NB = (N.toString(2).length + 7) >> 3;
    var BITS = N.toString(2).length;
    var DSI = ascii('CPace' + suite);
    var DST = concat([DSI, ascii('_DST')]);
    function sec1(P) {
        var A = C.to_affine(P);
        return E.encode_point(A.x, A.y, false);
    }
    return {
        DSI: DSI, DST: DST, field_size_bytes: E.BYTES,
        calculate_generator: function (H, PRS, CI, sid) {
            return h2c.encode_to_curve(generator_string(DSI, PRS, CI, sid, H.s_in_bytes), DST);
        },
        encode_generator: sec1,
        sample_scalar: function (rng) {
            rng = require_rng('cpace.sample_scalar', rng);
            var excess = BigInt(NB * 8 - BITS);
            for (var i = 0; i < 128; i++) {
                var k = bytes_to_bigint(rng(NB)) >> excess;
                if (k > 0n && k < N) { return bigint_to_bytes(k, NB); }
            }
            throw new Error('cpace: the rng returned no scalar in [1, n-1]');
        },
        scalar_mult: function (y, g) { return sec1(C.mul(bytes_to_bigint(y) % N, g, BITS)); },
        scalar_mult_vfy: function (y, X) {
            var A = (X instanceof Uint8Array) ? E.decode_point(X) : null;
            if (A === null) { return null; }
            var R = C.mul(bytes_to_bigint(y) % N, C.of(A.x, A.y), BITS);
            if (C.is_zero(R)) { return null; }
            return bigint_to_bytes(C.to_affine(R).x, E.BYTES);
        }
    };
}

export var G_P256 = /* @__PURE__ */ weierstrass_env('P256_XMD:SHA-256_SSWU_NU_', p256, p256_h2c);
export var G_P384 = /* @__PURE__ */ weierstrass_env('P384_XMD:SHA-384_SSWU_NU_', p384, p384_h2c);
export var G_P521 = /* @__PURE__ */ weierstrass_env('P521_XMD:SHA-512_SSWU_NU_', p521, p521_h2c);

/* ==================== the protocol (section 7) ==================== */

var ISK_SUFFIX = /* @__PURE__ */ ascii('_ISK');
var SID_OUTPUT = /* @__PURE__ */ ascii('CPaceSidOutput');
var EMPTY = new Uint8Array(0);

/**
 * A cipher suite: a group environment and a hash.
 *
 * Low level, as section 7 states it - the appendix B vectors run through
 * these - and one high-level call, `party`, that holds a session's state.
 *
 * @param {string} name  "CPACE-G-H"
 * @param {object} G     a group environment above
 * @param {object} H     a hash above
 */
export function cpace_suite(name, G, H) {
    var isk_dsi = concat([G.DSI, ISK_SUFFIX]);

    function isk(sid, K, transcript) {
        return H.hash(concat([lv_cat(isk_dsi, sid, K), transcript]));
    }
    function sid_output(transcript) {
        return H.hash(concat([SID_OUTPUT, transcript]));
    }

    return {
        name: name, G: G, H: H,
        calculate_generator: function (PRS, CI, sid) {
            return G.calculate_generator(H, PRS, CI || EMPTY, sid || EMPTY);
        },
        sample_scalar: G.sample_scalar,
        scalar_mult: G.scalar_mult,
        scalar_mult_vfy: G.scalar_mult_vfy,
        isk: isk,
        sid_output: sid_output,

        /**
         * One party's session.
         *
         * @param {object} o
         *   prs   {Uint8Array}  the password-related string
         *   ci    {Uint8Array}  channel identifier, never sent        [empty]
         *   sid   {Uint8Array}  session id, the same on both sides    [empty]
         *   ad    {Uint8Array}  associated data, sent with Y          [empty]
         *   role  {string}      'initiator', 'responder' or 'symmetric'
         *                       (no fixed order: transcript_oc)
         *   rng   {function}    (n) -> n random bytes; omitted or null draws
         *                       fresh ones from the platform
         *   y     {Uint8Array}  [a fixed scalar, for test vectors only]
         *
         * @return {{Y, ad, finish(Y_peer, ad_peer) -> {isk, sid_output}}}
         *   finish THROWS when K is the neutral element - an invalid or
         *   low-order share, which the draft requires to abort the session.
         */
        party: function (o) {
            var role = o.role || 'symmetric';
            if (role !== 'initiator' && role !== 'responder' && role !== 'symmetric') {
                throw new Error('cpace: role must be initiator, responder or symmetric');
            }
            if (!(o.prs instanceof Uint8Array)) { throw new Error('cpace: prs must be bytes'); }
            var sid = o.sid || EMPTY, ad = o.ad || EMPTY;
            var g = G.calculate_generator(H, o.prs, o.ci || EMPTY, sid);
            var y = o.y || G.sample_scalar(o.rng);
            var Y = G.scalar_mult(y, g);
            return {
                Y: Y, ad: ad,
                finish: function (Y_peer, ad_peer) {
                    var K = G.scalar_mult_vfy(y, Y_peer);
                    if (K === null) { throw new Error('cpace: abort - the peer share gives the neutral element'); }
                    var adp = ad_peer || EMPTY;
                    var t = role === 'initiator' ? transcript_ir(Y, ad, Y_peer, adp)
                          : role === 'responder' ? transcript_ir(Y_peer, adp, Y, ad)
                          : transcript_oc(Y, ad, Y_peer, adp);
                    return { isk: isk(sid, K, t), sid_output: sid_output(t) };
                }
            };
        }
    };
}

/* the recommended suites (section 5), and the two over group abstractions */
export var CPACE_X25519_SHA512 = /* @__PURE__ */ cpace_suite('CPACE-X25519-SHA512', G_X25519, H_SHA512);
export var CPACE_X448_SHAKE256 = /* @__PURE__ */ cpace_suite('CPACE-X448-SHAKE256', G_X448, H_SHAKE256);
export var CPACE_RISTR255_SHA512 = /* @__PURE__ */ cpace_suite('CPACE-RISTR255-SHA512', G_RISTRETTO255, H_SHA512);
export var CPACE_DECAF448_SHAKE256 = /* @__PURE__ */ cpace_suite('CPACE-DECAF448-SHAKE256', G_DECAF448, H_SHAKE256);
export var CPACE_P256_SHA256 = /* @__PURE__ */ cpace_suite('CPACE-P256_XMD:SHA-256_SSWU_NU_-SHA256', G_P256, H_SHA256);
export var CPACE_P384_SHA384 = /* @__PURE__ */ cpace_suite('CPACE-P384_XMD:SHA-384_SSWU_NU_-SHA384', G_P384, H_SHA384);
export var CPACE_P521_SHA512 = /* @__PURE__ */ cpace_suite('CPACE-P521_XMD:SHA-512_SSWU_NU_-SHA512', G_P521, H_SHA512);
