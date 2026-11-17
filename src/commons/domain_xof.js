/**
 * A domain-separated XOF: the module's tag, one domain byte, then each part
 * with a four-byte length prefix - so no two different lists of parts hash
 * the same input, whatever their lengths.
 *
 *     var H = domain_xof(shake256, ascii('cryptographic-primitives/x/v1'));
 *     H(DOM_KEY, [seed, be32(i)], 32)
 */

import { concat, lp32 } from './bytes.js';

export function domain_xof(xof, dst) {
    return function (dom, parts, len) { return xof(concat([dst, new Uint8Array([dom])].concat(parts.map(lp32))), len); };
}
