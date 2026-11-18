/**
 * Engine selection
 *
 * Every public operation comes in three forms - `name(..., cb)`,
 * `name_sync(...)` and, where it fits, `name_create()` - and this file is the
 * one place that decides what runs each of them:
 *
 *     the platform's own crypto (node:crypto, or WebCrypto in a browser)
 *     when it has the operation in that form, and otherwise
 *     the pure JavaScript in src/<module>.js.
 *
 * The algorithm files never import this, and never touch a platform API.
 * They stay plain synchronous JavaScript; an engine is laid over them.
 *
 * ==================== WHICH NATIVE ENGINE ====================
 *
 * `#native` is resolved by package.json's "imports" field: engines/node.js
 * under the `node` condition, engines/web.js everywhere else. A browser
 * bundle therefore never sees `node:crypto`.
 *
 * An engine is a table, one entry per operation, each holding the forms it
 * can run: { sha256: { sync, async, create, accepts } }. A missing form falls
 * back to pure JavaScript, so an engine only lists what it does natively.
 * `accepts(args)`, when present, says whether the native form takes these
 * particular arguments - node:crypto's BLAKE2 has no key and a fixed length,
 * so a keyed or shortened BLAKE2 runs in pure JavaScript. A future
 * WebAssembly engine is one more table of the same shape.
 *
 * ==================== BY SIZE ====================
 *
 * A native call has a fixed cost before its first byte, and on a short
 * input the pure JavaScript finishes sooner. An entry can say from which
 * size the native form is worth it:
 *
 *     from: { arg, bytes }   the one-shot forms: native when args[arg] has
 *                            at least `bytes` bytes
 *     call_from: bytes       a keyed context from create(): each encrypt or
 *                            decrypt goes native from a message this long,
 *                            and shorter ones run in a pure context, made
 *                            on the first such call
 *
 * The engine sets them from its own measurements (engines/node.js); the
 * result is the same either way, only the time differs.
 *
 * ==================== NOTHING ABOUT THE PLATFORM IS ASSUMED ====================
 *
 * The platform's crypto is whatever this runtime has - Node's OpenSSL, Bun's
 * BoringSSL, a browser's WebCrypto - and no two have the same algorithms,
 * or take the same options. So no entry runs natively until it has shown,
 * here, that it works. Each carries a check, run on the entry's first use
 * and remembered for the life of the process (works, below):
 *
 *     kat()        fixed arguments: the native result must be the pure
 *                  function's, value for value
 *     probe(pure)  for what is not deterministic - a key pair, a hedged
 *                  signature, a keyed context: runs the native form once,
 *                  checks it with the pure code, and answers true
 *
 * An entry with no check, one whose check throws, and one whose check gets
 * another answer, run in JavaScript - the same results, only slower. A
 * check that answers through a Promise (WebCrypto's) keeps its entry in
 * JavaScript until it has answered.
 *
 * ==================== THE CALLBACK FORM ====================
 *
 * `cb(err, result)` is always called on a later turn of the event loop,
 * never before the function returns, so a caller's code after the call
 * always runs first - whichever engine answered.
 */

import { ops as native } from '#native';
import { utf8, check_room } from '../commons/bytes.js';

var use_native = true;

/**
 * 'auto' (the default): the platform's crypto where it has the operation,
 * pure JavaScript elsewhere. 'js': pure JavaScript everywhere - for tests
 * that compare the two, and for a caller that wants one implementation on
 * every platform.
 */
export function set_engine(name) {
    if (name === 'js') { use_native = false; }
    else if (name === 'auto') { use_native = true; }
    else { throw new TypeError("set_engine: expected 'auto' or 'js', got " + String(name)); }
}

/**
 * Which engine runs `op` in `form` right now: 'native' or 'js'.
 *
 *     engine_of('sha256', 'sync')                  can it run natively at all
 *     engine_of('sha256', 'sync', [msg])           for this call
 *     engine_of('aes_gcm', 'call', [iv, pt, aad])  for this encrypt or decrypt
 *                                                  of a context from create()
 *     engine_of('aes_ecb', 'call', [data])         (the arguments of its method)
 *
 * @param {string} form  'sync', 'async', 'create' or 'call'
 * @param {Array} [args] the call's arguments, without the callback
 */
export function engine_of(op, form, args) {
    var n = native[op];
    if (form === 'call') {
        var message = context_kind[op] ? context_kind[op].message : 1;
        return n && takes(n, 'create') && (!args || n.call_from === undefined || long_enough(args[message], n.call_from)) ? 'native' : 'js';
    }
    return n && takes(n, form, args) ? 'native' : 'js';
}

/*
 * Does the engine entry `n` run `form` ('sync', 'async' or 'create') with
 * these arguments? Without arguments: does it run that form at all. A
 * one-shot form also needs an input long enough to be worth it (`from`).
 * define() routes every call through this, and engine_of() reports it.
 */
function takes(n, form, args) {
    if (!use_native || !n[form] || !works(n)) { return false; }
    if (!args) { return true; }
    if (n.accepts && !n.accepts(args)) { return false; }
    return form === 'create' || !n.from || long_enough(args[n.from.arg], n.from.bytes);
}

function long_enough(x, bytes) { return !!x && x.length >= bytes; }

/* argument i of up to five, without an array */
function nth(i, a, b, c, d, e) { return i === 0 ? a : i === 1 ? b : i === 2 ? c : i === 3 ? d : e; }

/*
 * A later turn of the event loop. setImmediate where it exists (Node, Bun,
 * Deno); elsewhere a MessageChannel message, which browsers deliver without
 * setTimeout's 4 ms clamp on nested calls; setTimeout as the last resort.
 */
export var later = /* @__PURE__ */ (function () {
    if (typeof setImmediate === 'function') { return setImmediate; }
    if (typeof MessageChannel === 'function') {
        var queue = [];
        var ch = new MessageChannel();
        ch.port1.onmessage = function () { var fn = queue.shift(); fn(); };
        return function (fn) { queue.push(fn); ch.port2.postMessage(0); };
    }
    return function (fn) { setTimeout(fn, 0); };
}());

/*
 * A message given as a string is its UTF-8 bytes; so is each string in a list
 * of messages (tuplehash's items, a batch of messages to verify).
 */
function bytes(x) {
    if (typeof x === 'string') { return utf8(x); }
    if (Array.isArray(x)) {
        var out = x;
        for (var i = 0; i < x.length; i++) {
            if (typeof x[i] === 'string') {
                if (out === x) { out = x.slice(); }
                out[i] = utf8(x[i]);
            }
        }
        return out;
    }
    return x;
}

/*
 * A call's arguments, in place, from `from` (0 when left out): the strings at
 * the positions in `text` become their UTF-8 bytes - positions counted from
 * `from`. A string at a position in `only_bytes` ({ position: name }) is a
 * mistake - a hex or base64 key, most often - and throws.
 *
 * `fields` ({ position: [names] }) does the same inside an options object
 * (Argon2's { password, salt, ... }): a copy with those string fields as
 * UTF-8, so the caller's object is never changed.
 *
 * ⭐ IN PLACE, IN THE ARRAY OF THE CALL'S OWN REST PARAMETER: every call of
 *   every operation passes here, and a new array per call would be garbage
 *   per call - work for the collector on a hot path (a packet's encryption).
 */
function convert(who, args, text, only_bytes, fields, from) {
    var skip = from || 0;
    for (var i = 0; i < args.length - skip; i++) {
        args[skip + i] = one(who, args[skip + i], i, text, only_bytes, fields);
    }
    return args;
}

/* one argument, at position i, as convert() describes - and as a context's method converts each of its own */
function one(who, x, i, text, only_bytes, fields) {
    if (typeof x === 'string' && only_bytes[i] !== undefined) {
        throw new TypeError(who + ': ' + only_bytes[i] + ' must be a Uint8Array, not a string' +
            ' (strings are taken as UTF-8 only for text such as a message or a password)');
    }
    /*
     * ⚠ A NODE BUFFER BECOMES A PLAIN Uint8Array OVER THE SAME BYTES.
     *   Buffer's slice() is a view, not a copy, so code that copies with
     *   slice() and then changes the copy would change the caller's key
     *   or message.
     */
    if (x instanceof Uint8Array && x.constructor !== Uint8Array) {
        x = new Uint8Array(x.buffer, x.byteOffset, x.length);
    }
    if (text.indexOf(i) >= 0) { x = bytes(x); }
    if (fields && fields[i] && x && typeof x === 'object' && !(x instanceof Uint8Array)) {
        var copy = {};
        for (var k in x) { copy[k] = fields[i].indexOf(k) >= 0 ? bytes(x[k]) : x[k]; }
        x = copy;
    }
    return x;
}

/*
 * ==================== SLICES ====================
 *
 * A long pure computation (PBKDF2, scrypt, Argon2, key generation) is a
 * task: step() does a bounded piece of work and says whether it finished.
 * The callback form runs steps until SLICE_MS have passed, hands the event
 * loop back, and continues on the next turn - so timers, I/O and rendering
 * keep running while it works. The _sync form runs the same steps without
 * stopping (commons/task.js), so the two cannot disagree.
 *
 * ⚠ A SLICE ENDS BETWEEN STEPS. A step that runs long holds the loop for as
 *   long as it runs; each task sizes its steps well under a millisecond.
 */
var SLICE_MS = 8;

var now = (typeof performance !== 'undefined' && performance && typeof performance.now === 'function')
    ? function () { return performance.now(); }
    : function () { return Date.now(); };

function run_sliced(make_task, cb) {
    var task = null;
    function tick() {
        var t0 = now(), finished = false, result;
        try {
            if (!task) { task = make_task(); }
            while (!(finished = task.step())) {
                if (now() - t0 >= SLICE_MS) { break; }
            }
            if (finished) { result = task.result(); }
        } catch (e) {
            cb(e);
            return;
        }
        if (finished) { cb(null, result); } else { later(tick); }
    }
    later(tick);
}

/*
 * Has engine entry `n` shown that it works here? Asked on every call, so
 * the answer is kept on the entry; the check itself runs once (above,
 * NOTHING ABOUT THE PLATFORM IS ASSUMED). Until define() has given the entry
 * its pure function there is nothing to check against: not yet, and not
 * remembered.
 */
function works(n) {
    if (n.works !== undefined) { return n.works; }
    if (!n.pure_sync && !n.pure_create) { return false; }
    n.works = false;              /* while it runs, and if it throws */
    try {
        var r;
        var args = n.kat ? n.kat() : null;     /* one set for both: neither engine may change its input */
        if (args && n.sync) {
            r = same(n.sync.apply(null, args), n.pure_sync.apply(null, pure_args(args.slice())));
        } else if (args && n.async) {
            r = new Promise(function (resolve) {
                n.async(args, function (err, out) {
                    try { resolve(!err && same(out, n.pure_sync.apply(null, pure_args(args.slice())))); } catch (e) { resolve(false); }
                });
            });
        } else if (n.probe) {
            r = n.probe(n.pure_sync || n.pure_create);
        }
        if (r && typeof r.then === 'function') {
            r.then(function (ok) { n.works = ok === true; }, function () { n.works = false; });
        } else {
            n.works = r === true;
        }
    } catch (e) {
        n.works = false;
    }
    return n.works;
}

/* the same value: bytes byte for byte, BigInts and numbers equal, objects field by field */
function same(a, b) {
    if (a instanceof Uint8Array || b instanceof Uint8Array) {
        if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) { return false; }
        for (var i = 0; i < a.length; i++) { if (a[i] !== b[i]) { return false; } }
        return true;
    }
    if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') { return a === b; }
    var ka = Object.keys(a), kb = Object.keys(b);
    if (ka.length !== kb.length) { return false; }
    for (var j = 0; j < ka.length; j++) { if (!same(a[ka[j]], b[ka[j]])) { return false; } }
    return true;
}

/**
 * The three forms of one operation.
 *
 * ==================== STRINGS ====================
 *
 * A string is accepted, as its UTF-8 bytes, where a person may write the
 * value as text: a message, associated data, a password, a salt, an info,
 * label, context or domain string, and a key of any length (HMAC, KMAC,
 * keyed BLAKE2). A value of fixed size - a cipher key, a nonce, a seed, a
 * secret or public key, a signature, a ciphertext - is bytes only: a string
 * there throws a TypeError naming it, in both forms, before any work.
 * `text` and `bytes` list the two kinds' positions; each API file sets them
 * per operation. Any other argument is passed as it is, so a function that
 * reads a string itself (ntlm's UTF-16, an option such as verify's mode, a
 * policy name) still does.
 *
 * @param {string} op       the operation's name in an engine table
 * @param {object} spec     { sync: pure function, create?: pure constructor,
 *                            kind?: what create() returns -
 *                              'hash' (the default): { update, copy, digest }
 *                              'stream': { update(data) -> data xor keystream, copy }
 *                              'aead', 'block': a keyed context { encrypt,
 *                                decrypt } (CONTEXT_KINDS below), given a
 *                                callback and a _sync form of each,
 *                            text?: the positions of the arguments that take
 *                            a string as UTF-8 (none when absent),
 *                            bytes?: the arguments that must not be strings,
 *                            { position: name } for the error,
 *                            create_text?, create_bytes?: the same for
 *                            create()'s arguments,
 *                            fields?: { position: [names] }, string fields
 *                            of an options object taken as UTF-8,
 *                            task?: the same computation as a task (commons/
 *                            task.js) - the callback form then runs it in
 *                            slices, yielding to the event loop between }
 * @return {{ async: function, sync: function, create: function|undefined }}
 */
export function define(op, spec) {
    var n = native[op] || {};
    var pure_sync = spec.sync;
    /* what the entry's check compares against (works) */
    if (native[op]) {
        if (spec.sync) { n.pure_sync = spec.sync; }
        if (spec.create) { n.pure_create = spec.create; }
    }
    var text = spec.text || [], only_bytes = spec.bytes || {};
    var create_text = spec.create_text || [], create_bytes = spec.create_bytes || {};
    var fields = spec.fields;

    var sync_label = op + '_sync';
    function sync(...args) {
        convert(sync_label, args, text, only_bytes, fields);
        return takes(n, 'sync', args) ? n.sync.apply(null, args) : pure_sync.apply(null, pure_args(args));
    }

    function async(...args) {
        var cb = args[args.length - 1];
        if (typeof cb !== 'function') {
            throw new TypeError(op + ': the last argument must be a callback (err, result); use ' + op + '_sync for a direct result');
        }
        args.pop();
        convert(op, args, text, only_bytes, fields);

        if (takes(n, 'async', args)) {
            n.async(args, function (err, result) {
                later(function () { cb(err, result); });
            });
            return;
        }
        if (spec.task && !takes(n, 'sync', args)) {
            run_sliced(function () { return spec.task.apply(null, pure_args(args)); }, cb);
            return;
        }
        later(function () {
            var result;
            try {
                result = takes(n, 'sync', args) ? n.sync.apply(null, args) : pure_sync.apply(null, pure_args(args));
            } catch (e) {
                cb(e);
                return;
            }
            cb(null, result);
        });
    }

    var create;
    var kind = CONTEXT_KINDS[spec.kind];
    if (kind) { context_kind[op] = kind; }
    if (spec.create) {
        var pure_create = spec.create;
        var create_label = /_create$/.test(op) ? op : op + '_create';
        create = function (...args) {
            convert(create_label, args, create_text, create_bytes);
            if (kind && n.call_from !== undefined && takes(n, 'create', args)) {
                /*
                 * ⚠ A COPY OF THE KEY, NOT THE CALLER'S ARRAY. The pure
                 *   context is made on the first short message, and by then
                 *   the caller may have zeroed their key - as they should.
                 *   The copy is zeroed once that context is made, or by wipe().
                 */
                var saved = args.map(function (x) { return x instanceof Uint8Array ? new Uint8Array(x) : x; });
                var forget = function () {
                    for (var i = 0; i < saved.length; i++) { if (saved[i] instanceof Uint8Array) { saved[i].fill(0); } }
                };
                return wrap_context(op, kind, n.create.apply(null, args), n.call_from, function () {
                    var small = pure_create.apply(null, pure_args(saved.slice()));
                    forget();
                    return small;
                }, forget);
            }
            var inner = takes(n, 'create', args) ? n.create.apply(null, args) : pure_create.apply(null, pure_args(args));
            return kind ? wrap_context(op, kind, inner)
                 : spec.kind === 'stream' ? wrap_stream(inner)
                 : wrap_incremental(inner);
        };
    }

    /*
     * Each public form remembers its operation and its pure function, so a
     * construction that takes a hash as an argument - hmac(sha256, ...) -
     * can be handed any of them and still find the pure hash (for the
     * JavaScript path) and the operation's name (for the native one).
     */
    var forms = [async, sync, create];
    for (var f = 0; f < forms.length; f++) {
        if (!forms[f]) { continue; }
        forms[f].op = op;
        forms[f].pure = pure_sync;
    }

    return { async: async, sync: sync, create: create };
}

/*
 * The arguments for a pure function: a public hash form given as an argument
 * (hmac(sha256, ...), hkdf(sha256, ...)) becomes the pure hash behind it.
 * An engine gets the arguments as they were, and reads .op off the hash.
 */
function pure_args(args) {
    for (var i = 0; i < args.length; i++) {
        if (typeof args[i] === 'function' && args[i].pure) { args[i] = args[i].pure; }
    }
    return args;
}

/**
 * The pure function behind a hash argument: a public form (sha256,
 * sha256_sync, sha256_create) or a pure function given directly.
 */
export function pure_of(fn) {
    return fn && fn.pure ? fn.pure : fn;
}

/*
 * update() takes strings too; everything else passes through - digest(n)
 * keeps its length, and an extendable-output function keeps read(n).
 */
function wrap_incremental(inner) {
    var self = {
        update: function (msg) { inner.update(bytes(msg)); return self; },
        copy: function () { return wrap_incremental(inner.copy()); },
        digest: function (out_len) { return inner.digest(out_len); }
    };
    if (typeof inner.read === 'function') {
        self.read = function (n) { return inner.read(n); };
    }
    return self;
}

/* A keystream cipher fed in pieces: update() returns the output. */
function wrap_stream(inner) {
    var self = {
        update: function (data) { return inner.update(bytes(data)); },
        copy: function () { return wrap_stream(inner.copy()); }
    };
    if (typeof inner.wipe === 'function') { self.wipe = function () { inner.wipe(); }; }
    return self;
}

/*
 * A keyed context: a key set once, then a method per message. The engine's
 * context answers when it has one; its methods are synchronous, so the
 * callback forms run them on a later turn, like every other callback here.
 * Each kind's methods, and which of their arguments may be strings:
 *
 *     'aead'   encrypt(nonce, plaintext, aad, ...), decrypt(nonce, sealed, aad, ...)
 *              the plaintext and the associated data may be strings; a
 *              failed authentication is a null result, in both forms
 *     'block'  encrypt(data), decrypt(data) - ECB under the key; the data
 *              to encrypt may be a string. No wipe(): neither engine has a
 *              key schedule it could zero (Node's is inside OpenSSL)
 *     'signer'    sign(msg) - one signing key, expanded once (Ed25519, Ed448)
 *     'ecdsa_signer'  sign(msg_hash, extra), sign_message(hash, msg, extra)
 *     'rsa_signer'    sign_pss, sign_pkcs1 and their _message forms
 *     'fips_signer'   sign, hash_sign, hash_sign_digest - ML-DSA, SLH-DSA
 *                 (every signer: the module's operations with the key taken
 *                 out of their arguments, and wipe())
 *     'verifier'  verify(msg, sig) -> true or false - one public key, decoded once
 *     'ecdsa_verifier'  verify(msg_hash, sig), verify_message(hash, msg, sig)
 *     'rsa_verifier'    verify_pss, verify_pkcs1 and their _message forms
 *                 (every verifier: the module's operations with the key taken
 *                 out of their arguments; a public key needs no wipe())
 *     'x25519', 'x448'  x25519(peer) / x448(peer) and the _checked form - one
 *              secret for many agreements; pk, its public key, as a field
 *     'ecdh'   ecdh(peer) - the same for a NIST curve; pk and pk_uncompressed
 *     'decaps' decaps(ct) - one ML-KEM decapsulation key; ek as a field
 *
 * `fields` are values the context carries, copied as they are.
 *
 * Each method of 'aead' and 'block' also has an _into form, which writes the result into the
 * caller's array instead of a new one, and returns its length:
 *
 *     encrypt_into(out, offset, ...the same arguments)   and _into_sync
 *     decrypt_into(out, offset, ...)    null when it fails, nothing written
 *
 * `out` may be the input's own memory: the output is written only once the
 * input has been read.
 *
 * ⚠ FOR SPEED, ENCRYPT WITH encrypt_into AND DECRYPT WITH decrypt. Sealing
 *   into a record's own buffer saves the new array and the copy into the
 *   record. Opening is the other way round: node:crypto cannot write into a
 *   given array, so decrypt returns its output as it is, and decrypt_into
 *   copies it - use it only when the plaintext must land in a given place.
 *   (Measured in lemon-tls, 16 KB records: encrypt_into + decrypt run as
 *   fast as node:crypto called directly.)
 *
 * `message` is the argument whose length routes a call by size (call_from).
 */
var CONTEXT_KINDS = {
    aead: { methods: ['encrypt', 'decrypt'], into: true, message: 1, text: { encrypt: [1, 2], decrypt: [2] },
            bytes: { encrypt: { 0: 'nonce' }, decrypt: { 0: 'nonce', 1: 'sealed' } } },
    block: { methods: ['encrypt', 'decrypt'], into: true, message: 0, text: { encrypt: [0], decrypt: [] },
             bytes: { encrypt: {}, decrypt: { 0: 'data' } }, no_wipe: true },
    signer: { methods: ['sign'], message: 0, text: { sign: [0] }, bytes: { sign: {} } },
    ecdsa_signer: { methods: ['sign', 'sign_message'], message: 0, text: { sign: [], sign_message: [1] },
                    bytes: { sign: { 0: 'msg_hash', 1: 'extra' }, sign_message: { 2: 'extra' } } },
    rsa_signer: { methods: ['sign_pss', 'sign_pkcs1', 'sign_pss_message', 'sign_pkcs1_message'], message: 0,
                  text: { sign_pss: [], sign_pkcs1: [], sign_pss_message: [0], sign_pkcs1_message: [0] },
                  bytes: { sign_pss: { 0: 'msg_hash' }, sign_pkcs1: { 0: 'msg_hash' }, sign_pss_message: {}, sign_pkcs1_message: {} } },
    fips_signer: { methods: ['sign', 'hash_sign', 'hash_sign_digest'], message: 0,
                   text: { sign: [0, 2], hash_sign: [0, 3], hash_sign_digest: [3] },
                   bytes: { sign: { 1: 'rnd' }, hash_sign: { 2: 'rnd' }, hash_sign_digest: { 0: 'digest', 2: 'rnd' } } },
    verifier: { methods: ['verify'], message: 0, text: { verify: [0] }, bytes: { verify: { 1: 'sig' } }, no_wipe: true },
    ecdsa_verifier: { methods: ['verify', 'verify_message'], message: 0, text: { verify: [], verify_message: [1] },
                      bytes: { verify: { 0: 'msg_hash', 1: 'sig' }, verify_message: { 2: 'sig' } }, no_wipe: true },
    rsa_verifier: { methods: ['verify_pss', 'verify_pkcs1', 'verify_pss_message', 'verify_pkcs1_message'], message: 0,
                    text: { verify_pss: [], verify_pkcs1: [], verify_pss_message: [0], verify_pkcs1_message: [0] },
                    bytes: { verify_pss: { 0: 'msg_hash', 1: 'sig' }, verify_pkcs1: { 0: 'msg_hash', 1: 'sig' },
                             verify_pss_message: { 1: 'sig' }, verify_pkcs1_message: { 1: 'sig' } }, no_wipe: true },
    x25519: { methods: ['x25519', 'x25519_checked'], message: 0, text: { x25519: [], x25519_checked: [] },
              bytes: { x25519: { 0: 'peer' }, x25519_checked: { 0: 'peer' } }, fields: ['pk'] },
    x448: { methods: ['x448', 'x448_checked'], message: 0, text: { x448: [], x448_checked: [] },
            bytes: { x448: { 0: 'peer' }, x448_checked: { 0: 'peer' } }, fields: ['pk'] },
    ecdh: { methods: ['ecdh'], message: 0, text: { ecdh: [] }, bytes: { ecdh: { 0: 'peer_public_key' } }, fields: ['pk', 'pk_uncompressed'] },
    decaps: { methods: ['decaps'], message: 0, text: { decaps: [] }, bytes: { decaps: { 0: 'ct' } }, fields: ['ek'] }
};
/* each defined context operation's kind, for engine_of's 'call' form */
var context_kind = {};

/*
 * `inner` is the context that runs every call - or, given `call_from` and
 * `make_small`, every call whose message has at least call_from bytes; a
 * shorter one runs in make_small()'s context, made once, on first use.
 * `forget` zeroes what make_small keeps for that (a copy of the key).
 */
function wrap_context(op, kind, inner, call_from, make_small, forget) {
    var small = null;
    /* the context for a call whose message (kind.message) is `message` */
    function choose(message) {
        if (make_small && !long_enough(message, call_from)) {
            if (!small) { small = make_small(); }
            return small;
        }
        return inner;
    }
    /*
     * ⭐ EVERY CALL OF A CONTEXT PASSES HERE - a QUIC packet's encrypt, a
     *   TLS record's - so the _sync forms allocate nothing of their own: the
     *   arguments are parameters, converted one by one, never an array. A
     *   rest parameter is a new array on every call (72 bytes for ECB's
     *   three arguments, 88 for an AEAD's five). Every method takes at most
     *   five arguments (an RSA signer's sign_pss), and the _into forms at most
     *   four after out and offset; a missing one is passed as undefined,
     *   which every method reads as left out.
     */
    function method(name, into) {
        var text = kind.text[name], only_bytes = kind.bytes[name], m = kind.message;
        var label = op + '.' + name + (into ? '_into' : ''), sync_label = label + '_sync', into_name = name + '_into';
        function arg(x, i) { return pure_of(one(sync_label, x, i, text, only_bytes, null)); }
        function call(a, b, c, d, e) {
            var ctx = choose(nth(m, a, b, c, d, e));
            return ctx[name](a, b, c, d, e);
        }
        /*
         * The _into form: the result written into out from `offset`, and its
         * length returned (null when a decryption fails, and then nothing is
         * written). An engine context with its own <name>_into writes there
         * directly; any other result is computed whole, then set into out.
         */
        function call_into(out, offset, a, b, c, d) {
            var ctx = choose(nth(m, a, b, c, d));
            if (typeof ctx[into_name] === 'function') { return ctx[into_name](out, offset, a, b, c, d); }
            var result = ctx[name](a, b, c, d);
            if (result === null) { return null; }
            check_room(label, out, offset, result.length);
            out.set(result, offset);
            return result.length;
        }
        function check_out(who, out, offset) {
            if (!(out instanceof Uint8Array) || !(offset >= 0 && offset % 1 === 0)) {
                throw new TypeError(who + ': the output must be a Uint8Array and the offset a whole number >= 0');
            }
        }
        var sync = into
            ? function (out, offset, a, b, c, d) {
                check_out(sync_label, out, offset);
                return call_into(out, offset, arg(a, 0), arg(b, 1), arg(c, 2), arg(d, 3));
            }
            : function (a, b, c, d, e) {
                return call(arg(a, 0), arg(b, 1), arg(c, 2), arg(d, 3), arg(e, 4));
            };
        /* the callback form makes a closure per call anyway; its arguments are converted before it returns */
        function async(...all) {
            var cb = all[all.length - 1];
            if (typeof cb !== 'function') {
                throw new TypeError(label + ': the last argument must be a callback (err, result); use ' + name + (into ? '_into' : '') + '_sync for a direct result');
            }
            all.pop();
            if (into) { check_out(label, all[0], all[1]); }
            pure_args(convert(label, all, text, only_bytes, null, into ? 2 : 0));
            later(function () {
                var result;
                try { result = (into ? call_into : call).apply(null, all); } catch (e) { cb(e); return; }
                cb(null, result);
            });
        }
        return { sync: sync, async: async };
    }
    var self = {};
    (kind.fields || []).forEach(function (f) { self[f] = inner[f]; });
    kind.methods.forEach(function (name) {
        var m = method(name);
        self[name] = m.async; self[name + '_sync'] = m.sync;
        if (kind.into) {
            var mi = method(name, true);
            self[name + '_into'] = mi.async; self[name + '_into_sync'] = mi.sync;
        }
    });
    if (!kind.no_wipe) {
        self.wipe = function () {
            if (typeof inner.wipe === 'function') { inner.wipe(); }
            if (small && typeof small.wipe === 'function') { small.wipe(); }
            if (forget) { forget(); }
        };
    }
    return self;
}

/**
 * A parameter set's operations, in both forms: for a scheme object such as
 * ml_kem768 = { keygen, encaps, decaps, ... }, the result has
 *
 *     keygen(..., cb)  and  keygen_sync(...)
 *
 * for every method, and every other property as it is. The operations are
 * named '<name>.<method>' for the engines, so ml_kem768's keygen can be
 * native where the platform has ML-KEM-768.
 *
 * @param {string} name  the export's name: 'ml_kem768'
 * @param {object} obj   the pure parameter set
 * @param {object} [args]  per method, define's `text` and `bytes`:
 *                         { sign: { text: [1], bytes: { 0: 'sk' } } };
 *                         with `kind`, the method makes a context
 *                         (CONTEXT_KINDS) and `bytes` are its arguments'
 */
export function scheme(name, obj, args) {
    var out = {};
    for (var k in obj) {
        if (typeof obj[k] !== 'function') { out[k] = obj[k]; continue; }
        var a = (args && args[k]) || {};
        if (a.kind) {
            /* a context, <op>_create: as it is, one form */
            out[k] = define(name + '.' + k, { create: obj[k].bind(obj), kind: a.kind, create_bytes: a.bytes }).create;
            continue;
        }
        var ops = define(name + '.' + k, { sync: obj[k].bind(obj), text: a.text, bytes: a.bytes });
        out[k] = ops.async;
        out[k + '_sync'] = ops.sync;
    }
    return out;
}
