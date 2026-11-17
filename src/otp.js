/**
 * HOTP and TOTP  -  RFC 4226 and RFC 6238
 *
 * The six-digit codes in Google Authenticator, Authy, and every other
 * two-factor app. The entire construction is HMAC and a truncation:
 *
 *     HOTP(K, counter) = truncate(HMAC(K, counter)) mod 10^digits
 *     TOTP(K)          = HOTP(K, floor(unix_time / 30))
 *
 * IT IS THE OPERATIONAL DETAILS THAT MATTER, not the cryptography, and this
 * file spends its length on those.
 *
 * DYNAMIC TRUNCATION is the one clever part. The last nibble of the HMAC
 * selects a four-byte window, and the code comes from that window rather than
 * a fixed offset. Using the first four bytes would leak the same part of the
 * HMAC every time; letting the HMAC choose its own offset means an observer
 * of many codes learns four bytes from varying, unpredictable positions.
 *
 * SHA-1 IS THE DEFAULT AND THAT IS FINE HERE. HOTP was specified in 2005 and
 * every authenticator app speaks HMAC-SHA1; changing it breaks
 * interoperability. SHA-1's collision breaks do not touch HMAC, which needs
 * only that the compression function is a PRF - and the output is six digits
 * anyway, so the security is bounded by guessing, not by the hash.
 *
 * THE REAL RISKS ARE ELSEWHERE:
 *
 *   - THE SECRET IS SYMMETRIC. The server stores what the phone stores, so a
 *     server breach hands the attacker every user's second factor. WebAuthn
 *     exists partly because of this.
 *   - IT IS PHISHABLE. A code typed into a proxy works for the attacker, and
 *     nothing binds the code to the site. TOTP defends against password
 *     reuse and credential stuffing; it does not defend against a convincing
 *     login page.
 *   - COUNTER REUSE IS A REPLAY. HOTP counters must never go backwards, and
 *     a TOTP code must be marked used - otherwise an intercepted code works
 *     for the rest of its window.
 */

import { hmac } from './hmac.js';
import { sha1 } from './sha1.js';
import { equal } from './commons/ct.js';
import { bigint_to_bytes, utf8 } from './commons/bytes.js';

var POW10 = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000];

/* the 8-byte big-endian counter; values beyond 2^53 are not a concern */
function counter_bytes(n) { return bigint_to_bytes(BigInt(n), 8); }

/**
 * @param  {Uint8Array} key
 * @param  {number}     counter
 * @param  {number}     [digits=6]  6 to 8; more is unusual and less
 *                                  interoperable
 * @param  {function}   [hash=sha1]
 * @return {string}     zero-padded decimal
 */
export function hotp(key, counter, digits, hash) {
    var d = digits || 6;
    if (d < 1 || d > 9) { throw new Error('otp: digits must be 1 to 9'); }
    var mac = hmac(hash || sha1, key, counter_bytes(counter));

    /* dynamic truncation, RFC 4226 section 5.3 */
    var offset = mac[mac.length - 1] & 0x0f;
    var bin = ((mac[offset] & 0x7f) << 24) |
              ((mac[offset + 1] & 0xff) << 16) |
              ((mac[offset + 2] & 0xff) << 8) |
              (mac[offset + 3] & 0xff);

    var code = (bin >>> 0) % POW10[d];
    var s = String(code);
    while (s.length < d) { s = '0' + s; }
    return s;
}

/**
 * @param {Uint8Array} key
 * @param {number}     [time]    unix SECONDS, not milliseconds. Defaults to
 *                               now, which is the one place this file reads
 *                               the clock.
 * @param {object}     [opts]    {step, t0, digits, hash}
 */
export function totp(key, time, opts) {
    var o = opts || {};
    var step = o.step || 30;
    var t0 = o.t0 || 0;
    var now = time === undefined ? Math.floor(Date.now() / 1000) : time;
    return hotp(key, Math.floor((now - t0) / step), o.digits, o.hash);
}

/**
 * Verify a TOTP code, accepting a window of steps either side.
 *
 * THE WINDOW EXISTS BECAUSE CLOCKS DRIFT and because a user takes a few
 * seconds to type. One step either side - thirty seconds - is the usual
 * setting; wider multiplies the attacker's guessing chances by the same
 * factor, so it is a direct security-versus-usability dial.
 *
 * THE COMPARISON IS CONSTANT TIME. A naive string compare leaks how many
 * leading digits were right, and with a six-digit code that turns a 10^6
 * search into six searches of 10.
 *
 * @param  {number} [window=1]
 * @return {number|null} the matching step offset, or null. The offset is
 *                       returned rather than a boolean so that a caller can
 *                       record which step was used and refuse to accept it
 *                       twice - without that, an intercepted code stays valid
 *                       for the rest of its window.
 */
export function totp_verify(key, code, time, opts) {
    var o = opts || {};
    var win = o.window === undefined ? 1 : o.window;
    var step = o.step || 30;
    var t0 = o.t0 || 0;
    var now = time === undefined ? Math.floor(Date.now() / 1000) : time;
    var base = Math.floor((now - t0) / step);

    var expected = utf8(code);
    var found = null;
    for (var d = -win; d <= win; d++) {
        var candidate = utf8(hotp(key, base + d, o.digits, o.hash));
        /* every step is checked even after a match, so the time taken does
           not reveal which one matched */
        if (candidate.length === expected.length && equal(candidate, expected) === 1) {
            if (found === null) { found = d; }
        }
    }
    return found;
}

/**
 * Verify an HOTP code, searching forward from the stored counter.
 *
 * THE LOOK-AHEAD WINDOW handles a user who pressed the button on their token
 * a few times without submitting. The counter MUST then be advanced past the
 * match - the return value is the new counter, and storing it is not
 * optional. A counter that does not move forward turns HOTP into a static
 * password.
 *
 * @return {number|null} the counter value to store next, or null
 */
export function hotp_verify(key, code, counter, opts) {
    var o = opts || {};
    var look = o.look_ahead === undefined ? 10 : o.look_ahead;
    var expected = utf8(code);
    var found = null;
    for (var i = 0; i <= look; i++) {
        var candidate = utf8(hotp(key, counter + i, o.digits, o.hash));
        if (candidate.length === expected.length && equal(candidate, expected) === 1) {
            if (found === null) { found = counter + i + 1; }
        }
    }
    return found;
}

/* ---------------- base32, because that is how secrets travel ---------------- */

var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * RFC 4648 base32, which is what every authenticator app expects.
 *
 * Not cryptography, and here for one reason: a TOTP secret is useless if it
 * cannot be typed into a phone, and every QR code and manual-entry field in
 * the ecosystem uses this alphabet. Leaving it out would mean the module
 * cannot be used for the thing it is for.
 */
export function base32_encode(bytes, pad) {
    var out = '';
    var bits = 0, value = 0;
    for (var i = 0; i < bytes.length; i++) {
        value = (value << 8) | bytes[i];
        bits += 8;
        while (bits >= 5) {
            out += B32[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) { out += B32[(value << (5 - bits)) & 31]; }
    if (pad) { while (out.length % 8 !== 0) { out += '='; } }
    return out;
}

/** @return {Uint8Array|null} null on an invalid character */
export function base32_decode(s) {
    var clean = s.replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
    var bytes = [];
    var bits = 0, value = 0;
    for (var i = 0; i < clean.length; i++) {
        var idx = B32.indexOf(clean[i]);
        if (idx < 0) { return null; }
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            bytes.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return new Uint8Array(bytes);
}

/**
 * The otpauth:// URI that a QR code encodes.
 *
 * @param {object} opts  {issuer, account, secret, digits, step, algorithm}
 */
export function otpauth_uri(opts) {
    var label = encodeURIComponent((opts.issuer ? opts.issuer + ':' : '') + opts.account);
    var params = ['secret=' + base32_encode(opts.secret)];
    if (opts.issuer) { params.push('issuer=' + encodeURIComponent(opts.issuer)); }
    if (opts.digits && opts.digits !== 6) { params.push('digits=' + opts.digits); }
    if (opts.step && opts.step !== 30) { params.push('period=' + opts.step); }
    if (opts.algorithm && opts.algorithm !== 'SHA1') { params.push('algorithm=' + opts.algorithm); }
    return 'otpauth://totp/' + label + '?' + params.join('&');
}
