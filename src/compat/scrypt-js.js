/**
 * scrypt-js compatibility
 *
 *     import { scrypt, syncScrypt } from 'scrypt-js';
 *     import { scrypt, syncScrypt } from 'cryptographic-primitives/compat/scrypt-js.js';
 *
 * scrypt is scrypt - RFC 7914 fixes the output for a given (password, salt,
 * N, r, p), so there is no format to agree on and the results are identical
 * by construction. This is the thinnest shim in the directory and exists only
 * because the argument order and the promise shape differ from src/scrypt.js.
 *
 * WHERE scrypt-js IS USED: Ethereum keystore files (Web3 Secret Storage) and
 * the wallets built on them, which is why it still has real traffic despite
 * doing one thing.
 *
 * ==================== ON THE PROGRESS CALLBACK ====================
 *
 * scrypt-js reports progress and lets the callback abort by returning true.
 * That works because it yields to the event loop between blocks; this
 * computes straight through, so the callback is invoked once at 0 and once at
 * 1 and an abort request between them cannot be honoured.
 *
 * Making it genuinely incremental means a resumable ROMix, and the honest fix
 * for a browser is a Worker - which the caller controls. The signature is
 * kept so that existing code runs; what it cannot do is interrupt.
 */

import { scrypt as scrypt_raw } from '../scrypt.js';
import { text_or_bytes } from './_common.js';

/* scrypt-js also takes plain arrays of bytes, hence the conversion after */
function to_bytes(x) {
    var b = text_or_bytes(x);
    return b instanceof Uint8Array ? b : new Uint8Array(b);
}

/**
 * @param {Uint8Array|string} password
 * @param {Uint8Array|string} salt
 * @param {number} N   cost, a power of two
 * @param {number} r   block size
 * @param {number} p   parallelism
 * @param {number} dkLen
 * @return {Uint8Array}
 */
export function syncScrypt(password, salt, N, r, p, dkLen) {
    return scrypt_raw(to_bytes(password), to_bytes(salt), N, r, p, dkLen);
}

/** The promise form. Computed synchronously - see the note above. */
export function scrypt(password, salt, N, r, p, dkLen, progress) {
    return new Promise(function (resolve, reject) {
        try {
            if (progress) { progress(0); }
            var out = syncScrypt(password, salt, N, r, p, dkLen);
            if (progress) { progress(1); }
            resolve(out);
        } catch (err) { reject(err); }
    });
}

export default { scrypt: scrypt, syncScrypt: syncScrypt };
