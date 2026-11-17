/**
 * The fixed inputs of the engines' checks
 *
 * No engine entry runs natively until it has shown, on this platform, that
 * it gives the pure code's answer (select.js, works). These are the values
 * those checks run on: small, fixed, and the same in every engine, so a
 * check is a few microseconds the first time an operation is used.
 *
 * The expected outputs here were made by the pure code (aes.js, chacha.js,
 * argon2.js) and are checked against it in test/routing.test.mjs. RSA_KEY is
 * a 1024-bit key made for these checks alone - public, and good for nothing
 * else.
 */

export function hex(s) {
    var out = new Uint8Array(s.length >> 1);
    for (var i = 0; i < out.length; i++) { out[i] = parseInt(s.substr(2 * i, 2), 16); }
    return out;
}
/* n bytes, each different: (v + 7i) mod 256 */
export function fill(n, v) {
    var b = new Uint8Array(n);
    for (var i = 0; i < n; i++) { b[i] = (v + 7 * i) & 255; }
    return b;
}

export var MSG = fill(40, 1);
export var K16 = fill(16, 2);
export var K32 = fill(32, 3);
export var N12 = fill(12, 4);
export var AAD = fill(9, 5);
export var IV16 = fill(16, 6);

/* aes_gcm_encrypt(K16, N12, MSG, AAD) */
export var GCM_SEALED = hex(
        '60e81df72fbca7984403bfdf64ae489c00b720b2a71ede623da6b6fb8e5369cd78148094ad5bf1378f70bd260f9a82a7' +
        '91bb411e7d09ad2c');
/* chacha20poly1305_encrypt(K32, N12, MSG, AAD) */
export var CP_SEALED = hex(
        '71c1481dae9dcee409599aac36d58b48d429bcbc8e2fc8acb19cd62ea87de542a50f52618f3998e504a6e0f80d28bae0' +
        'ad39425c0813ba9b');
/* aes_cbc_encrypt(K16, IV16, MSG), PKCS#7 padded */
export var CBC_CT = hex(
        'dc51b7891209391e77c1cb972959c7c3cfc6e997214c4b41c227efd0ed7715a1c53ab2c69df40b809586e50a8fe256e1');
/* argon2id({ password: MSG, salt: K16, p: 1, t: 1, m: 8, length: 32 }) */
export var ARGON2ID_TAG = hex(
        '0f889cbb7047f6b1f171c9e8c970d54900f270c2c8b36e8d8b598205b0603f17');
export var ARGON2_OPTS = { password: MSG, salt: K16, p: 1, t: 1, m: 8, length: 32 };

function big(h) { return BigInt('0x' + h); }
export var RSA_KEY = {
    n: big(
        'eef75235961146c45137d74a044442df6a6fe868297def6e13088ceda96bf2e75fce40d914e0860bf1dbd17523cfab98' +
        '1677f0ddba7907bfd819e99248afcd376e0fec14c3af9595982e4792ba77f521fb3ca1e3dbfb12522799aad89c2dd2b3' +
        '2454c85044838d5ad9b235818d4704ebe109a45c97d8342ad92322c512e1be3d'),
    e: big(
        '010001'),
    d: big(
        'b6523884edf44c7be843a49cb258aa74ef2e66b16246d570b450e7c544683a31d1e4f99126de8f2779e66f0ee2bdc57c' +
        '0a58848b8784642738e7bc4f81e9afb5cb558ce5f5109aee0db5469d8290bec4b049092fcd7b8214be5d6486b0872f3a' +
        'f64ba350a9a952064460680daf9a4c10bf769d2ad5a7f100e0b9d36ed12749f9'),
    p: big(
        'fdd285eb340af3e28db445594620296216d7eb949fe93f2179f354535de511defd1f7329c85474a62ce4cff8bb6e6752' +
        '1bb4fccfa4a8235ee41ad4928e90655b'),
    q: big(
        'f1042b372e113119f9ec304f0dd008571306a22c97373b7fe3b6cf14bc4b1191304c4ab1b532b672e232c6cf61ead2c4' +
        'fe9a9e4e9b6b95c0eb9683177dd88647'),
    dp: big(
        '409ed163712b7cade81fc62c155368d5c5351190142a40dd57fbe0331d4b8d8234f545cf946614109e8b5e7b57d4a2cf' +
        '5fa87358b5f5ec93630585ab0e4aaad3'),
    dq: big(
        '0197a67571df793493bb24c290f3cbea4f5cdedb6e9055db4d74dabf675313a5a2ed0e1d48763250660031e212e28b4b' +
        'f3e6af9f1355cda27dabfbe7bed41c67'),
    qinv: big(
        'acdc25426ee543f23c92377df241873d55111cc50f7e5f3233cedf7c0873116d1ff5618592b075835e026fae8371fcc7' +
        'd7f05f866271d3ddd9328b8c55ab09be')
};
