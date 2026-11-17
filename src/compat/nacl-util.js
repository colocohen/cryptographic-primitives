/**
 * tweetnacl-util compatibility
 *
 * Four encoding helpers, which is all tweetnacl-util ever was:
 *
 * import util from 'tweetnacl-util';
 *     import util from 'cryptographic-primitives/compat/nacl-util.js';
 *
 * It exists as a separate package because tweetnacl itself deliberately has
 * no opinion about strings - it takes and returns byte arrays - and callers
 * needed somewhere to put the conversions. The same split is kept here so
 * that an existing import maps one to one.
 *
 * NOTHING HERE IS CRYPTOGRAPHIC. These are string and base64 conversions, and
 * they are in compat/ rather than in the library proper because this library
 * does not otherwise offer them: a crypto library that starts converting
 * strings has to take a position on encodings, and taking one badly is how
 * inputs get mangled before they are ever hashed.
 */

/** UTF-8 string to bytes. Throws on a non-string, as tweetnacl-util does. */
import { to_base64, from_base64, utf8 } from '../commons/bytes.js';
export function decodeUTF8(s) {
    if (typeof s !== 'string') { throw new TypeError('expected string'); }
    return utf8(s);
}

/** Bytes to a UTF-8 string. */
export function encodeUTF8(arr) {
    return new TextDecoder().decode(arr);
}

/**
 * Bytes to standard base64, WITH padding.
 *
 * The standard alphabet and the trailing '=' - not the URL-safe variant, and
 * not unpadded. tweetnacl-util produces exactly this and code round-tripping
 * through it depends on the padding being present.
 */
export function encodeBase64(arr) {
    /*
     * ⚠ WAS btoa OR Buffer, DEPENDING ON THE HOST - so this shim, whose whole
     *   purpose is to work anywhere, did not. btoa is absent in older Node and
     *   Buffer is absent in a browser. commons/bytes.js has neither problem.
     */
    return to_base64(arr);
}

/** @throws on input that is not valid base64, as tweetnacl-util does */
export function decodeBase64(s) {
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) {
        throw new TypeError('invalid encoding');
    }
    var out = from_base64(s);
    if (out === null) { throw new TypeError('invalid encoding'); }
    return out;
}

export default {
    decodeUTF8: decodeUTF8,
    encodeUTF8: encodeUTF8,
    encodeBase64: encodeBase64,
    decodeBase64: decodeBase64
};
