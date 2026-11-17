/**
 * RC4  -  Rivest, 1987
 *
 * BROKEN. Do not use it for anything new, under any circumstances.
 *
 * The first bytes of its keystream are measurably biased, and the biases do
 * not stop after a few bytes - they persist for thousands. That turned into
 * practical plaintext recovery against TLS and against WEP, and RFC 7465
 * banned RC4 from TLS outright in 2015. WEP fell to a related-key attack on
 * RC4's key schedule and was replaced entirely.
 *
 * It is here because a great deal of old data and old protocol traffic is
 * encrypted with it and still has to be read: legacy Office documents, PDF
 * up to revision 3, old Kerberos suites, archived captures. Decrypting the
 * past is a legitimate need; encrypting the future with this is not.
 *
 * The algorithm itself is remarkable for its size - a 256-byte permutation,
 * two counters, and a swap - which is why it spread so far before its
 * weaknesses were understood.
 *
 * RC4-drop: discarding the first N bytes of keystream avoids the worst of
 * the early bias. It is a patch on a broken primitive, not a fix, and it is
 * offered only because some legacy formats specify it.
 */

/**
 * @param  {Uint8Array} key   1 to 256 bytes
 * @param  {Uint8Array} data
 * @param  {number}     [drop=0]  keystream bytes to discard first. 768 and
 *                                3072 are the values seen in the wild.
 * @return {Uint8Array}
 */
export function rc4(key, data, drop) {
    if (key.length < 1 || key.length > 256) {
        throw new Error('rc4: key must be 1 to 256 bytes');
    }
    var s = new Uint8Array(256);
    var i, j = 0, t;

    for (i = 0; i < 256; i++) { s[i] = i; }

    /*
     * The key schedule. Its weakness is that the first outputs correlate with
     * the key - the whole reason WEP fell, since WEP prepended a visible IV
     * to a fixed key and handed attackers thousands of related keys.
     */
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % key.length]) & 0xff;
        t = s[i]; s[i] = s[j]; s[j] = t;
    }

    var out = new Uint8Array(data.length);
    var x = 0, y = 0, n;

    for (n = 0; n < (drop || 0); n++) {
        x = (x + 1) & 0xff;
        y = (y + s[x]) & 0xff;
        t = s[x]; s[x] = s[y]; s[y] = t;
    }

    for (n = 0; n < data.length; n++) {
        x = (x + 1) & 0xff;
        y = (y + s[x]) & 0xff;
        t = s[x]; s[x] = s[y]; s[y] = t;
        out[n] = data[n] ^ s[(s[x] + s[y]) & 0xff];
    }

    for (i = 0; i < 256; i++) { s[i] = 0; }
    return out;
}
