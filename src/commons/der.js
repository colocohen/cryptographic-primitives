/**
 * commons/der.js - DER (X.690 Distinguished Encoding Rules), the subset key
 * and signature encodings use: SEQUENCE, INTEGER, OCTET STRING, BIT STRING,
 * OBJECT IDENTIFIER and context-specific tags.
 *
 * ⚠ STRICT ON PURPOSE, and in one place. DER is where encoding malleability
 *   lives: a length that disagrees with the content, a long-form length
 *   where the short form fits, a leading zero an INTEGER does not need (or a
 *   missing one before a high bit, which reads as negative), and bytes left
 *   over after the value. A lenient parser accepts two encodings of one
 *   value; Bitcoin's BIP 66 exists because ECDSA's DER was parsed that way.
 *   Every one of them is refused here - null, never a guess - and ECDSA's
 *   signatures (commons/ecdsa.js), RSA's keys (rsa.js) and EC private keys
 *   are all read through this one parser.
 */
import { concat, bytes_to_bigint } from './bytes.js';

export var SEQUENCE = 0x30, INTEGER = 0x02, BIT_STRING = 0x03, OCTET_STRING = 0x04, OID = 0x06;

/* ---------------- writing ---------------- */

function length_bytes(n) {
    if (n < 0x80) { return new Uint8Array([n]); }
    var b = [];
    while (n > 0) { b.unshift(n & 0xff); n = Math.floor(n / 256); }
    return new Uint8Array([0x80 | b.length].concat(b));
}

/** tag ‖ length ‖ content */
export function tlv(tag, content) { return concat([new Uint8Array([tag]), length_bytes(content.length), content]); }

export function seq(parts) { return tlv(SEQUENCE, concat(parts)); }

/** A non-negative INTEGER, in its minimal two's-complement form. */
export function int(v) {
    if (typeof v !== 'bigint') { v = BigInt(v); }
    if (v < 0n) { throw new RangeError('der: negative integers are not used here'); }
    var hex = v.toString(16);
    if (hex.length & 1) { hex = '0' + hex; }
    if (parseInt(hex.slice(0, 2), 16) & 0x80) { hex = '00' + hex; }
    var b = new Uint8Array(hex.length / 2);
    for (var i = 0; i < b.length; i++) { b[i] = parseInt(hex.substr(2 * i, 2), 16); }
    return tlv(INTEGER, b);
}

export function octets(b) { return tlv(OCTET_STRING, b); }

/** An OBJECT IDENTIFIER from its dotted form. */
export function oid(dotted) {
    var arcs = dotted.split('.').map(function (a) { return BigInt(a); });
    if (arcs.length < 2) { throw new Error('der: an OID has at least two arcs'); }
    var out = base128(arcs[0] * 40n + arcs[1]);
    for (var i = 2; i < arcs.length; i++) { out = out.concat(base128(arcs[i])); }
    return tlv(OID, new Uint8Array(out));
}
function base128(v) {
    var b = [Number(v & 0x7fn)];
    v >>= 7n;
    while (v > 0n) { b.unshift(Number(v & 0x7fn) | 0x80); v >>= 7n; }
    return b;
}

/* ---------------- reading ---------------- */

/**
 * The one TLV at `off`: { tag, content, end }, or null if it is not DER -
 * an indefinite or non-minimal length, or one that runs past the input.
 */
export function read(b, off) {
    off = off || 0;
    if (!(b instanceof Uint8Array) || off + 2 > b.length) { return null; }
    var tag = b[off], l = b[off + 1], p = off + 2;
    if (l & 0x80) {
        var nb = l & 0x7f;
        if (nb === 0 || nb > 4 || p + nb > b.length) { return null; }     /* indefinite, or absurd */
        if (b[p] === 0) { return null; }                                   /* a leading zero byte */
        l = 0;
        for (var i = 0; i < nb; i++) { l = l * 256 + b[p + i]; }
        if (l < 0x80) { return null; }                                     /* the short form fits */
        p += nb;
    }
    if (p + l > b.length) { return null; }
    return { tag: tag, content: b.subarray(p, p + l), end: p + l };
}

/** The whole of `b` as one TLV of `tag` - nothing before or after - or null. */
export function read_whole(b, tag) {
    var t = read(b, 0);
    return t && t.tag === tag && t.end === b.length ? t : null;
}

/** The children of a constructed value's content, or null. */
export function children(content) {
    var out = [], off = 0;
    while (off < content.length) {
        var t = read(content, off);
        if (!t) { return null; }
        out.push(t);
        off = t.end;
    }
    return out;
}

/** A SEQUENCE that is the whole of `b`, as its children - or null. */
export function read_seq(b) {
    var t = read_whole(b, SEQUENCE);
    return t ? children(t.content) : null;
}

/** A non-negative INTEGER's value, or null for a non-minimal or negative encoding. */
export function int_value(t) {
    if (!t || t.tag !== INTEGER || t.content.length === 0) { return null; }
    var c = t.content;
    if (c[0] === 0 && (c.length === 1 ? false : !(c[1] & 0x80))) { return null; }   /* an unneeded leading zero */
    if (c[0] & 0x80) { return null; }                                                /* negative */
    return bytes_to_bigint(c);
}

/** An OBJECT IDENTIFIER's dotted form, or null. */
export function oid_value(t) {
    if (!t || t.tag !== OID || t.content.length === 0) { return null; }
    var arcs = [], v = 0n, c = t.content;
    for (var i = 0; i < c.length; i++) {
        if (v === 0n && c[i] === 0x80) { return null; }                  /* a non-minimal arc */
        v = (v << 7n) | BigInt(c[i] & 0x7f);
        if (!(c[i] & 0x80)) { arcs.push(v); v = 0n; }
    }
    if (c[c.length - 1] & 0x80) { return null; }
    var first = arcs[0] < 80n ? [arcs[0] / 40n, arcs[0] % 40n] : [2n, arcs[0] - 80n];
    return first.concat(arcs.slice(1)).join('.');
}
