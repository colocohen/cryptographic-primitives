/**
 * MGF1 - the mask generation function of PKCS #1 (RFC 8017, B.2.1): a hash
 * in counter mode, hash(seed ‖ I2OSP(counter, 4)) for counter = 0, 1, ...,
 * cut to `len` bytes.
 *
 * Shared by RSA's OAEP and PSS paddings and SLH-DSA's SHA-2 message digest
 * (FIPS 205, 11.2).
 *
 * @param {Uint8Array} seed
 * @param {number} len
 * @param {function} hash
 * @return {Uint8Array}
 */
import { concat, be32 } from './bytes.js';

export function mgf1(seed, len, hash) {
    var out = new Uint8Array(len);
    var produced = 0, counter = 0;
    while (produced < len) {
        var block = hash(concat([seed, be32(counter)]));
        for (var i = 0; i < block.length && produced < len; i++) {
            out[produced++] = block[i];
        }
        counter++;
    }
    return out;
}
