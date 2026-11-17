/**
 * OPAQUE  -  RFC 9807
 *
 * AN AUGMENTED PAKE: the client logs in with a password, and the server
 * stores nothing from which the password can be attacked offline after a
 * breach - no hash, no salt it hands out before authentication. A stolen
 * credential file still has to be attacked one online guess at a time
 * against the OPRF key, which the file does not contain.
 *
 * HOW. The password never leaves the client. It goes through an OPRF with a
 * per-client key the server derives from a global seed (RFC 9497,
 * oprf.js), then through a key stretching function, to give
 * randomized_password. From that the client derives:
 *
 *   - an Envelope (nonce, MAC tag) the server stores, which lets the client
 *     check that what it recovers is genuine;
 *   - its long-term AKE key pair, recomputed on every login, never stored;
 *   - masking_key, with which the server masks the Envelope on login so that
 *     an unregistered user and a registered one look the same;
 *   - export_key, an application key the server never sees.
 *
 * Login runs the OPRF and a 3DH key exchange in the same three messages:
 *
 *     KE1  client -> server   blinded password, nonce, ephemeral share
 *     KE2  server -> client   evaluation, masked envelope, nonce, share, MAC
 *     KE3  client -> server   MAC
 *
 * and both sides end with session_key, the client also with export_key.
 *
 * CONFIGURATIONS (section 7) are a tuple (OPRF, KDF, MAC, Hash, KSF, Group,
 * Context): `opaque_suite` takes the OPRF suite, the 3DH group and the KSF;
 * HKDF, HMAC and the hash follow from the OPRF suite. The appendix C vectors
 * cover ristretto255-SHA512 with the ristretto255 and Curve25519 groups and
 * P256-SHA256 with P-256, real and fake (unregistered-client) runs.
 *
 * THE KSF IS THE APPLICATION'S CHOICE and there is no default: section 7
 * recommends Argon2id with 2 GiB of memory (`ksf_argon2id`), or scrypt
 * (`ksf_scrypt`). `ksf_identity` is what the test vectors use - it is a
 * valid function and no protection against offline guessing.
 */

import { suite as oprf_suite, MODE_OPRF } from './oprf.js';
import { hkdf_extract, hkdf_expand } from './kdf.js';
import { hmac } from './hmac.js';
import { sha256, sha384, sha512 } from './sha2.js';
import { argon2id } from './argon2.js';
import { scrypt } from './scrypt.js';
import { x25519 } from './x25519.js';
import { concat, ascii, be16, lp16, xor } from './commons/bytes.js';
import { equal_bool } from './commons/ct.js';
import { reject_zero } from './commons/montgomery.js';
import { require_rng } from './commons/primes.js';

/* section 2: every nonce is Nn bytes and every seed Nseed */
var Nn = 32, Nseed = 32;
var EMPTY = new Uint8Array(0);

/* ==================== key stretching functions (sections 2.3, 7) ==================== */

/**
 * The identity function, Stretch(msg) = msg. The test vectors use it. It
 * provides NO resistance to offline guessing; a deployment needs one of the
 * two below or another memory-hard function.
 */
export function ksf_identity(msg) { return msg; }

/**
 * Argon2id with section 7's recommended parameters: S = 16 zero bytes,
 * p = 4, T = Nh, m = 2^21 KiB (2 GiB), t = 1. Each may be overridden.
 *
 * @return {function(Uint8Array, number): Uint8Array}
 */
export function ksf_argon2id(o) {
    var opt = o || {};
    return function (msg, Nh) {
        return argon2id({ password: msg, salt: opt.salt || new Uint8Array(16),
                          m: opt.m || (1 << 21), t: opt.t || 1, p: opt.p || 4, length: Nh });
    };
}

/** scrypt with section 7's recommended parameters: S = 16 zero bytes, N = 32768, r = 8, p = 1, dkLen = 32. */
export function ksf_scrypt(o) {
    var opt = o || {};
    return function (msg) {
        return scrypt(msg, opt.salt || new Uint8Array(16), opt.N || 32768, opt.r || 8, opt.p || 1, opt.length || 32);
    };
}

/* ==================== 3DH groups (section 6.4.1) ==================== */

/*
 * Each group is
 *
 *   Npk, Nsk          encoded public and private key sizes
 *   derive(seed)      DeriveDiffieHellmanKeyPair -> {sk, pk}, both bytes
 *   dh(sk, pk)        DiffieHellman -> bytes; THROWS on a public key that is
 *                     invalid, the identity, or (X25519) of low order
 */
var DH_INFO = /* @__PURE__ */ ascii('OPAQUE-DeriveDiffieHellmanKeyPair');

/* a prime-order group through its RFC 9497 suite: DeriveKeyPair, SerializeElement */
function oprf_group_dh(name, id) {
    var S = null;
    function s() { return S || (S = oprf_suite(id)); }
    return {
        name: name,
        get Npk() { return s().Ne; },
        get Nsk() { return s().Ns; },
        derive: function (seed) {
            var kp = s().derive_keypair(seed, DH_INFO, MODE_OPRF);
            return { sk: s().GROUP.scalar_bytes(kp.sk), pk: kp.pk };
        },
        dh: function (sk, pk) {
            var G = s().GROUP, P = G.decode(pk), k = G.scalar_from_bytes(sk);
            if (P === null) { throw new Error('opaque: invalid public key'); }
            if (k === null) { throw new Error('opaque: invalid private key'); }
            return G.encode(G.mul(k, P));
        }
    };
}

var NINE = /* @__PURE__ */ (function () { var b = new Uint8Array(32); b[0] = 9; return b; }());

export var DH_GROUPS = {
    'ristretto255': /* @__PURE__ */ oprf_group_dh('ristretto255', 'ristretto255-SHA512'),
    'decaf448': /* @__PURE__ */ oprf_group_dh('decaf448', 'decaf448-SHAKE256'),
    'P256': /* @__PURE__ */ oprf_group_dh('P256', 'P256-SHA256'),
    'P384': /* @__PURE__ */ oprf_group_dh('P384', 'P384-SHA384'),
    'P521': /* @__PURE__ */ oprf_group_dh('P521', 'P521-SHA512'),
    /* section 6.4.1.3: the seed IS the private key, X25519 clamps it */
    'curve25519': {
        name: 'curve25519', Npk: 32, Nsk: 32,
        derive: function (seed) { return { sk: new Uint8Array(seed), pk: x25519(seed, NINE) }; },
        dh: function (sk, pk) {
            if (!(pk instanceof Uint8Array) || pk.length !== 32) { throw new Error('opaque: invalid public key'); }
            var out = reject_zero(x25519(sk, pk));
            if (out === null) { throw new Error('opaque: low-order public key'); }
            return out;
        }
    }
};

/* the hash - and so HKDF and HMAC - of each OPRF suite (section 7) */
var SUITE_HASH = { 'ristretto255-SHA512': sha512, 'P256-SHA256': sha256, 'P384-SHA384': sha384, 'P521-SHA512': sha512 };

/* ==================== a configuration ==================== */

/**
 * @param {object} cfg
 *   oprf     {string}    RFC 9497 suite: 'ristretto255-SHA512', 'P256-SHA256', ...
 *   group    {string}    3DH group: a key of DH_GROUPS
 *   ksf      {function}  (msg, Nh) -> bytes; required (see above)
 *   context  {Uint8Array} shared context for the preamble [empty]
 *   hash     {function}  [the OPRF suite's hash; required for decaf448-SHAKE256,
 *                        whose SHAKE256 is not an HMAC hash]
 */
export function opaque_suite(cfg) {
    var S = oprf_suite(cfg.oprf);
    var H = cfg.hash || SUITE_HASH[cfg.oprf];
    if (!H) { throw new Error('opaque: ' + cfg.oprf + ' needs an explicit hash for HKDF and HMAC'); }
    var D = DH_GROUPS[cfg.group];
    if (!D) { throw new Error('opaque: unknown 3DH group ' + cfg.group); }
    if (typeof cfg.ksf !== 'function') {
        throw new Error('opaque: a key stretching function is required (ksf_argon2id, ksf_scrypt, ...)');
    }
    var KSF = cfg.ksf, CONTEXT = cfg.context || EMPTY;
    var Nh = H.DIGEST_SIZE, Nx = Nh, Nm = Nh, Noe = S.Ne, Nok = S.Ns, Npk = D.Npk;
    var ENV = Nn + Nm;

    function extract(ikm) { return hkdf_extract(H, ikm, EMPTY); }
    function expand(prk, info, L) { return hkdf_expand(H, prk, L, info); }
    function mac(k, m) { return hmac(H, k, m); }

    function split(buf, sizes, what) {
        var total = sizes.reduce(function (a, b) { return a + b; }, 0);
        if (!(buf instanceof Uint8Array) || buf.length !== total) {
            throw new Error('opaque: ' + what + ' must be ' + total + ' bytes');
        }
        var out = [], o = 0;
        for (var i = 0; i < sizes.length; i++) { out.push(buf.subarray(o, o + sizes[i])); o += sizes[i]; }
        return out;
    }

    function oprf_key(credential_identifier, oprf_seed) {
        var seed = expand(oprf_seed, concat([credential_identifier, ascii('OprfKey')]), Nok);
        return S.derive_keypair(seed, ascii('OPAQUE-DeriveKeyPair'), MODE_OPRF).sk;
    }

    function evaluate(blinded, credential_identifier, oprf_seed) {
        var ev = S.blind_evaluate(oprf_key(credential_identifier, oprf_seed), blinded);
        if (ev === null) { throw new Error('opaque: the blinded element does not deserialize'); }
        return ev;
    }

    function randomized_password(password, blind, evaluated) {
        var y = S.finalize(password, blind, evaluated);
        if (y === null) { throw new Error('opaque: the evaluated element does not deserialize'); }
        return extract(concat([y, KSF(y, Nh)]));
    }

    function blind(password, rng) { return S.blind(password, rng, MODE_OPRF); }

    /* ---------------- section 4: credentials and the envelope ---------------- */

    function cleartext(server_public_key, client_public_key, server_identity, client_identity) {
        return concat([server_public_key, lp16(server_identity || server_public_key),
                       lp16(client_identity || client_public_key)]);
    }

    function envelope_keys(rpw, nonce) {
        return {
            auth_key: expand(rpw, concat([nonce, ascii('AuthKey')]), Nh),
            export_key: expand(rpw, concat([nonce, ascii('ExportKey')]), Nh),
            keys: D.derive(expand(rpw, concat([nonce, ascii('PrivateKey')]), Nseed))
        };
    }

    function store(rpw, server_public_key, server_identity, client_identity, rng) {
        var nonce = rng(Nn);
        var k = envelope_keys(rpw, nonce);
        var cc = cleartext(server_public_key, k.keys.pk, server_identity, client_identity);
        return {
            envelope: concat([nonce, mac(k.auth_key, concat([nonce, cc]))]),
            client_public_key: k.keys.pk,
            masking_key: expand(rpw, ascii('MaskingKey'), Nh),
            export_key: k.export_key
        };
    }

    function recover(rpw, server_public_key, envelope, server_identity, client_identity) {
        var nonce = envelope.subarray(0, Nn), tag = envelope.subarray(Nn);
        var k = envelope_keys(rpw, nonce);
        var cc = cleartext(server_public_key, k.keys.pk, server_identity, client_identity);
        if (!equal_bool(tag, mac(k.auth_key, concat([nonce, cc])))) {
            throw new Error('opaque: envelope recovery failed - wrong password or tampered response');
        }
        return { client_private_key: k.keys.sk, cleartext: cc, server_public_key: server_public_key,
                 server_identity: server_identity || server_public_key,
                 client_identity: client_identity || k.keys.pk, export_key: k.export_key };
    }

    /* ---------------- section 6.4.2: the 3DH key schedule ---------------- */

    function expand_label(secret, label, ctx, L) {
        var full = concat([ascii('OPAQUE-'), ascii(label)]);
        return expand(secret, concat([be16(L), new Uint8Array([full.length]), full,
                                      new Uint8Array([ctx.length]), ctx]), L);
    }

    function preamble(client_identity, ke1, server_identity, credential_response, server_nonce, server_share) {
        return concat([ascii('OPAQUEv1-'), lp16(CONTEXT), lp16(client_identity), ke1, lp16(server_identity),
                       credential_response, server_nonce, server_share]);
    }

    function derive_keys(ikm, pre) {
        var prk = extract(ikm), th = H(pre);
        var hs = expand_label(prk, 'HandshakeSecret', th, Nx);
        return {
            session_key: expand_label(prk, 'SessionKey', th, Nx),
            km2: expand_label(hs, 'ServerMAC', EMPTY, Nx),
            km3: expand_label(hs, 'ClientMAC', EMPTY, Nx)
        };
    }

    /* ==================== the API ==================== */

    var API = {
        config: { oprf: cfg.oprf, group: cfg.group, Nh: Nh, Npk: Npk, Nsk: D.Nsk, Nm: Nm, Nx: Nx, Nok: Nok, Noe: Noe, Nn: Nn },

        /** A server's long-term AKE key pair, from Nseed random bytes. */
        generate_server_keypair: function (rng) {
            rng = require_rng('generate_server_keypair', rng);
            return D.derive(rng(Nseed));
        },
        derive_dh_keypair: function (seed) { return D.derive(seed); },

        /* ---------------- section 5: registration ---------------- */

        /** @return {{request: Uint8Array, blind: bigint}} */
        create_registration_request: function (password, rng) {
            rng = require_rng('create_registration_request', rng);
            var b = blind(password, rng);
            return { request: b.blinded, blind: b.blind };
        },

        /** @return {Uint8Array} RegistrationResponse */
        create_registration_response: function (request, server_public_key, credential_identifier, oprf_seed) {
            split(request, [Noe], 'RegistrationRequest');
            return concat([evaluate(request, credential_identifier, oprf_seed), server_public_key]);
        },

        /**
         * @param {object} [ids]  {server_identity, client_identity}, each
         *                        defaulting to the party's public key
         * @return {{record: Uint8Array, export_key: Uint8Array}}
         */
        finalize_registration_request: function (password, blind_scalar, response, ids, rng) {
            rng = require_rng('finalize_registration_request', rng);
            var r = split(response, [Noe, Npk], 'RegistrationResponse'), id = ids || {};
            var rpw = randomized_password(password, blind_scalar, r[0]);
            var st = store(rpw, r[1], id.server_identity, id.client_identity, rng);
            return { record: concat([st.client_public_key, st.masking_key, st.envelope]), export_key: st.export_key };
        },

        /**
         * A record for a client that does not exist (section 6.3.2.2), so that
         * a login attempt for it looks like one for a registered client.
         * Create it ONCE and store it with the real records.
         */
        fake_record: function (rng) {
            rng = require_rng('fake_record', rng);
            return concat([D.derive(rng(Nseed)).pk, rng(Nh), new Uint8Array(ENV)]);
        },

        /* ---------------- section 6: login ---------------- */

        /**
         * GenerateKE1. rng draws, in order: the OPRF blind, client_nonce,
         * client_keyshare_seed.
         *
         * @return {{ke1: Uint8Array, state: object}}  keep state for generate_ke3
         */
        generate_ke1: function (password, rng) {
            rng = require_rng('generate_ke1', rng);
            var b = blind(password, rng);
            var nonce = rng(Nn), eph = D.derive(rng(Nseed));
            var ke1 = concat([b.blinded, nonce, eph.pk]);
            return { ke1: ke1, state: { password: password, blind: b.blind, client_secret: eph.sk, ke1: ke1 } };
        },

        /**
         * GenerateKE2. rng draws, in order: masking_nonce, server_nonce,
         * server_keyshare_seed. For an unregistered client pass a fake_record.
         *
         * @param {object} o
         *   server_identity, server_private_key, server_public_key, record,
         *   credential_identifier, oprf_seed, ke1, client_identity
         * @return {{ke2: Uint8Array, state: object}}  keep state for server_finish
         */
        generate_ke2: function (o, rng) {
            rng = require_rng('generate_ke2', rng);
            var ke1 = split(o.ke1, [Noe, Nn, Npk], 'KE1');
            var rec = split(o.record, [Npk, Nh, ENV], 'RegistrationRecord');
            var client_public_key = rec[0];
            /* CreateCredentialResponse */
            var evaluated = evaluate(ke1[0], o.credential_identifier, o.oprf_seed);
            var masking_nonce = rng(Nn);
            var pad = expand(rec[1], concat([masking_nonce, ascii('CredentialResponsePad')]), Npk + ENV);
            var credential_response = concat([evaluated, masking_nonce, xor(pad, concat([o.server_public_key, rec[2]]))]);
            /* AuthServerRespond */
            var server_identity = o.server_identity || o.server_public_key;
            var client_identity = o.client_identity || client_public_key;
            var server_nonce = rng(Nn), eph = D.derive(rng(Nseed));
            var pre = preamble(client_identity, o.ke1, server_identity, credential_response, server_nonce, eph.pk);
            var ikm = concat([D.dh(eph.sk, ke1[2]), D.dh(o.server_private_key, ke1[2]), D.dh(eph.sk, client_public_key)]);
            var k = derive_keys(ikm, pre);
            var server_mac = mac(k.km2, H(pre));
            return {
                ke2: concat([credential_response, server_nonce, eph.pk, server_mac]),
                state: { expected_client_mac: mac(k.km3, H(concat([pre, server_mac]))), session_key: k.session_key }
            };
        },

        /**
         * GenerateKE3. THROWS when the envelope does not recover (wrong
         * password) or the server's MAC does not verify.
         *
         * @param {object} [ids]  {server_identity, client_identity}
         * @return {{ke3, session_key, export_key}}
         */
        generate_ke3: function (state, ke2, ids) {
            var id = ids || {};
            var p = split(ke2, [Noe, Nn, Npk + ENV, Nn, Npk, Nm], 'KE2');
            var credential_response = ke2.subarray(0, Noe + Nn + Npk + ENV);
            /* RecoverCredentials */
            var rpw = randomized_password(state.password, state.blind, p[0]);
            var masking_key = expand(rpw, ascii('MaskingKey'), Nh);
            var pad = expand(masking_key, concat([p[1], ascii('CredentialResponsePad')]), Npk + ENV);
            var un = xor(pad, p[2]);
            var c = recover(rpw, un.subarray(0, Npk), un.subarray(Npk), id.server_identity, id.client_identity);
            /* AuthClientFinalize */
            var ikm = concat([D.dh(state.client_secret, p[4]), D.dh(state.client_secret, c.server_public_key),
                              D.dh(c.client_private_key, p[4])]);
            var pre = preamble(c.client_identity, state.ke1, c.server_identity, credential_response, p[3], p[4]);
            var k = derive_keys(ikm, pre);
            var expected = mac(k.km2, H(pre));
            if (!equal_bool(p[5], expected)) { throw new Error('opaque: server authentication failed'); }
            return { ke3: mac(k.km3, H(concat([pre, expected]))), session_key: k.session_key, export_key: c.export_key };
        },

        /** ServerFinish. THROWS when the client's MAC does not verify; the session key is not released. */
        server_finish: function (state, ke3) {
            if (!(ke3 instanceof Uint8Array) || ke3.length !== Nm || !equal_bool(ke3, state.expected_client_mac)) {
                throw new Error('opaque: client authentication failed');
            }
            return state.session_key;
        }
    };
    return API;
}
