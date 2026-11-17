/**
 * BLS12-381  -  pairing-friendly curve and BLS signatures
 *
 * The curve Ethereum's consensus layer runs on, and the one Zcash chose after
 * BN254's security estimate fell. Also used by Filecoin, Chia, Dfinity, and
 * most zk-SNARK tooling.
 *
 * THE POINT OF A PAIRING CURVE: signatures that AGGREGATE. A thousand
 * signatures over a thousand messages compress into ONE 96-byte signature
 * that a verifier checks with a fixed amount of work. Ethereum's beacon chain
 * exists in its current shape because of this - it aggregates hundreds of
 * thousands of validator signatures per epoch.
 *
 * Two groups, and they are not interchangeable:
 *
 *   G1   over Fp,  48-byte compressed points, cheap
 *   G2   over Fp2, 96-byte compressed points, several times more expensive
 *
 * A scheme must put signatures in one and public keys in the other, and the
 * choice is a real trade-off. This implementation follows the IETF draft's
 * MINIMAL-PUBKEY-SIZE variant: public keys in G1, signatures in G2, which is
 * what Ethereum uses because it stores far more keys than signatures.
 *
 * SECURITY: about 120 bits, revised down from the original 128 after the
 * 2016 advances in the number field sieve for extension fields - the same
 * work that dropped BN254 from 128 to around 100 and forced the migration
 * here. That history is why the curve has 381-bit coordinates for a
 * 255-bit-order group.
 */

import { field, BLS12_381_FR } from './commons/modp.js';
import { weierstrass } from './commons/weierstrass.js';
import { fp2_field, fp6_field, fp12_field } from './commons/fp_ext.js';
import { pairing } from './commons/pairing.js';
import { g2_group } from './commons/g2.js';
import { msm, msm_group } from './commons/fixed_window.js';
import { expand_message_xmd, hash_to_field, map_to_curve_sswu, horner, sgn0, h2c_suite } from './commons/h2c.js';
import { sha256 } from './sha2.js';
import { bigint_to_bytes, bytes_to_bigint, ascii } from './commons/bytes.js';
import * as shamir from './shamir.js';
import { random_below_biased, require_rng } from './commons/primes.js';
import { make_group, random_secret_below, key_from_seed } from './commons/group.js';

export var CURVE = {
    name: 'bls12-381',
    p: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
    /* the prime order of both G1 and G2 */
    r: BLS12_381_FR,
    /* the BLS parameter. It is NEGATIVE, which the Miller loop must account
       for, and it is sparse - only six bits set - which is exactly why this
       curve family is fast. */
    x: -0xd201000000010000n,
    G1: {
        b: 4n,
        Gx: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
        Gy: 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n
    },
    G2: {
        Gx: [0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
             0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en],
        Gy: [0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
             0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben]
    }
};

var Fp   = /* @__PURE__ */ field(CURVE.p);
var Fp2  = /* @__PURE__ */ fp2_field(Fp);
var Fp6  = /* @__PURE__ */ fp6_field(Fp2);
var Fp12 = /* @__PURE__ */ fp12_field(Fp6);

/* G1: y^2 = x^3 + 4 over Fp. The complete formulas in weierstrass.js apply. */
var C1 = /* @__PURE__ */ weierstrass(Fp, 0n, 4n);
var G1 = /* @__PURE__ */ C1.of(CURVE.G1.Gx, CURVE.G1.Gy);

/* G2: y^2 = x^3 + 4(u+1) over Fp2 - the sextic twist, which is what keeps
   G2 coordinates in Fp2 rather than in the full Fp12 they would otherwise
   need. Without the twist a pairing curve would be impractical. */
var B2 = [4n, 4n];

export var FIELD = Fp;
export var FIELD2 = Fp2;
export var FIELD12 = Fp12;
export var POINT1 = C1;
export var BASE1 = G1;

/* G2 over Fp2 - shared with the other pairing curve, see commons/g2.js */
var C2 = /* @__PURE__ */ g2_group(Fp2, B2);

export var POINT2 = C2;
export var BASE2 = /* @__PURE__ */ C2.of(CURVE.G2.Gx, CURVE.G2.Gy);

export var PAIRING = /* @__PURE__ */ pairing(Fp12, CURVE.x, true, CURVE.r);


/* ---------------- hash to curve, RFC 9380 ---------------- */
/*
 * Both groups need SSWU with an isogeny, for the same reason secp256k1 did:
 * their a coefficient is zero, and the simplified SWU map requires it
 * nonzero. So each maps onto an isogenous curve that does have one, then
 * carries the point back.
 *
 * G1 needs an ELEVEN-isogeny with fifty-three coefficients; G2 needs a
 * 3-isogeny with thirteen, each an Fp2 element. All of them were extracted
 * programmatically from RFC 9380 appendices E.2 and E.3.
 *
 * COFACTOR CLEARING IS MANDATORY HERE, and it is not the small multiplication
 * it was for Ed25519. BLS12-381's groups sit inside much larger curve groups:
 * G1's cofactor is 76 bits and G2's is over 500. A point that has not been
 * cleared is not in the prime-order subgroup, and a signature over such a
 * point is not a signature - this is the subgroup-check failure that has
 * produced real vulnerabilities in BLS deployments.
 */

/* The 11-isogeny from E1' to G1, RFC 9380 appendix E.2 */
var ISO1_K1 = [
    0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7n,
    0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bbn,
    0xd54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0n,
    0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861n,
    0xe99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9n,
    0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983n,
    0xd6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84n,
    0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88en,
    0x80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317n,
    0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9en,
    0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7bn,
    0x6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229n
];
var ISO1_K2 = [
    0x8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1cn,
    0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bffn,
    0xb2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19n,
    0x3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8n,
    0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21en,
    0xe7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5n,
    0x772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3an,
    0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5en,
    0xa10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641n,
    0x95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0an
];
var ISO1_K3 = [
    0x90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33n,
    0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696n,
    0xcc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6n,
    0x1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cbn,
    0x8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedbn,
    0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0n,
    0x4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2n,
    0x987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29n,
    0x9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587n,
    0xe1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30n,
    0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132n,
    0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8en,
    0xb182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8n,
    0x245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133n,
    0x5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224bn,
    0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604n
];
var ISO1_K4 = [
    0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1n,
    0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03dn,
    0x58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2n,
    0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416n,
    0xbe0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001dn,
    0x8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7acn,
    0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775cn,
    0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9n,
    0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4an,
    0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55n,
    0x4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8n,
    0xaccbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092n,
    0xad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345ccn,
    0x2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7n,
    0xe0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8fn
];

/* The 3-isogeny from E2' to G2, appendix E.3. Every coefficient is an Fp2
   element, written [real, imaginary]. */
var ISO2_K1 = [
    [0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n, 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n],
    [0x0n, 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an],
    [0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en, 0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn],
    [0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n, 0x0n]
];
var ISO2_K2 = [
    [0x0n, 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n],
    [0xcn, 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn]
];
var ISO2_K3 = [
    [0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n, 0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n],
    [0x0n, 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben],
    [0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn, 0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn],
    [0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n, 0x0n]
];
var ISO2_K4 = [
    [0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn, 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn],
    [0x0n, 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n],
    [0x12n, 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n]
];

var ISO1_A = 0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1dn;
var ISO1_B = 0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0n;
/* RFC 9380 section 8.8.1 gives Z = 11, POSITIVE. The secp256k1 suite uses
   -11, and copying that sign here produced points off the curve. */
var ISO1_Z = 11n;

var ISO2_A = [0n, 240n];
var ISO2_B = [1012n, 1012n];
var ISO2_Z = [Fp.neg(2n), Fp.neg(1n)];

/* h_eff, the cofactor each group is cleared by - RFC 9380 section 8.8 */
var H_EFF_1 = 0xd201000000010001n;
var H_EFF_2 = 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551n;

/**
 * Apply an isogeny given as four polynomials: x = xn/xd, y = y * yn/yd.
 *
 * The same function serves G1's 11-isogeny over Fp and G2's 3-isogeny over
 * Fp2 - only the field and the coefficient tables differ. They were two
 * copies until a review noticed.
 *
 * BOTH DENOMINATORS ARE MONIC and RFC 9380 does not store their leading
 * coefficient: x_den is x^10 + k_(2,9)x^9 + ... Feeding the stored list
 * straight into Horner's rule evaluates a polynomial one degree too low,
 * which produces points that are not on the curve at all. The `true` flags
 * below are that implied leading term.
 */
function iso_map(F, K1, K2, K3, K4, x, y) {
    var xn = horner(F, K1, x, false);
    var xd = horner(F, K2, x, true);
    var yn = horner(F, K3, x, false);
    var yd = horner(F, K4, x, true);

    /*
     * ⭐ ONE INVERSION, NOT TWO - Montgomery's trick.
     *
     *     1/xd = yd * (1/(xd*yd))     and     1/yd = xd * (1/(xd*yd))
     *
     *   so a single inverse plus three multiplications replaces two inverses.
     *   Measured on this field: an Fp2 inversion is 671 us against 0.8 for a
     *   multiplication, so the trade is overwhelming.
     *
     * ⚠ IT BREAKS IF EITHER DENOMINATOR IS ZERO, where two separate inverses
     *   would each return zero and carry on. Neither can be zero here: xd and
     *   yd are the isogeny's denominator polynomials evaluated at a point the
     *   SSWU map has already placed on the curve, and a zero there would mean
     *   the map produced a point at infinity - which it does not. Stated
     *   because the failure would be a silent wrong point rather than an
     *   error.
     */
    var both = F.inv(F.mul(xd, yd));
    return {
        x: F.mul(xn, F.mul(yd, both)),
        y: F.mul(y, F.mul(yn, F.mul(xd, both)))
    };
}

/**
 * sgn0 over Fp2 - the low bit of the real part, falling back to the
 * imaginary part when the real part is zero. A prime field needs no such
 * fallback, which is why the shared SSWU takes this as an argument.
 */
function sgn0_fp2(v) {
    return (v[0] === 0n) ? Number(v[1] & 1n) : Number(v[0] & 1n);
}

/**
 * Hash a message to G1. DST per the BLS signature draft.
 */
/*
 * BLS12381G1_XMD:SHA-256_SSWU_RO_ through commons/h2c.js's h2c_suite - the
 * same two field elements, map, add and h_eff clearing that this function
 * used to write out, which is what the suite is for. (G2 cannot follow: the
 * suite hashes to Fp, m = 1, and G2 needs Fp2 plus Budroni-Pintore.)
 */
var G1_H2C = /* @__PURE__ */ h2c_suite({
    F: Fp, C: C1, p: CURVE.p, L: 64, cofactor: H_EFF_1, order_bits: 64,
    expand: function (m, d, l) { return expand_message_xmd(m, d, l, sha256); },
    map: function (u) { return iso_map_g1_pt(map_to_curve_sswu(Fp, ISO1_A, ISO1_B, ISO1_Z, u, sgn0)); }
});

export function hash_to_g1(msg, dst) { return G1_H2C.hash_to_curve(msg, dst); }

/**
 * Hash a message to G2 - what BLS signatures actually sign.
 *
 * Two Fp2 elements, each mapped by SSWU onto the isogenous curve, added, then
 * carried back by the 3-isogeny and cleared by the 500-bit cofactor.
 */
/*
 * ==================== CLEARING G2's COFACTOR ====================
 *
 * ⛔ IT WAS ONE MULTIPLICATION BY A 636-BIT SCALAR, h_eff. Measured at 39 ms,
 *   which made hash_to_g2 56 ms and bls.sign 71 - against a pairing at 27.
 *
 * ⭐ BUDRONI-PINTORE replaces it with two multiplications by |x|, which is
 *   64 bits, plus the endomorphism psi:
 *
 *       Q = [x^2 - x - 1]P + [x - 1]psi(P) + psi^2(2P)
 *
 *   7.5 ms against 39 - and every constant below is DERIVED from the field,
 *   not transcribed.
 *
 * ⚠ x IS NEGATIVE, so [x]P is the negation of [|x|]P. The identity holds
 *   either way up to sign, so getting it wrong yields a point that is still
 *   on the curve and still in the subgroup - and only a comparison against
 *   [h_eff]P catches it. That comparison is in the tests.
 *
 * ⚠ AND psi2's y-coordinate IS A PLAIN NEGATION, because PSI2_Y works out to
 *   -1 for this curve. That is asserted at load rather than assumed: a curve
 *   where it did not hold would need the general multiplication and this
 *   code would silently compute something else.
 */
var PSI_BASE = /* @__PURE__ */ Fp2.inv([1n, 1n]);
var PSI_X = /* @__PURE__ */ Fp2.pow(PSI_BASE, (CURVE.p - 1n) / 3n);
var PSI_Y = /* @__PURE__ */ Fp2.pow(PSI_BASE, (CURVE.p - 1n) / 2n);
var PSI2_X = /* @__PURE__ */ Fp2.pow(PSI_BASE, (CURVE.p * CURVE.p - 1n) / 3n);

/* the precondition the fast psi2 rests on */
if (!Fp2.eq(Fp2.pow(PSI_BASE, (CURVE.p * CURVE.p - 1n) / 2n), Fp2.neg(Fp2.ONE))) {
    throw new Error('bls12_381: PSI2_Y is not -1 - psi2 below is wrong for this curve');
}

var ABS_X = 0xd201000000010000n;   /* |x|, and x itself is negative */

/*
 * ⭐ psi WITHOUT LEAVING PROJECTIVE COORDINATES.
 *
 *   It used to call to_affine first - one Fp2 inversion at 671 us, and
 *   clear_cofactor_g2 calls psi and psi2 once each, so every hash_to_g2 paid
 *   two of them.
 *
 *   The Frobenius is a field automorphism, so it commutes with the ratio:
 *
 *       psi(X/Z, Y/Z) = ( conj(X)/conj(Z) * PSI_X , conj(Y)/conj(Z) * PSI_Y )
 *                     ~ ( conj(X)*PSI_X : conj(Y)*PSI_Y : conj(Z) )
 *
 * ⚠ conj(Z) IS THE NEW Z, not Z. Leaving Z alone gives a point that is on
 *   the curve and wrong by a factor of conj(Z)/Z - which is 1 exactly when Z
 *   is in Fp, and Z IS in Fp for a freshly built point. So the bug would be
 *   invisible until the input had already been through another psi.
 */
function psi_g2(Q) {
    return { x: Fp2.mul(Fp2.conj(Q.x), PSI_X),
             y: Fp2.mul(Fp2.conj(Q.y), PSI_Y),
             z: Fp2.conj(Q.z) };
}

/* ⭐ same, and psi^2 needs no conjugation at all - see psi_g2 above */
function psi2_g2(Q) {
    return { x: Fp2.mul(Q.x, PSI2_X), y: Fp2.neg(Q.y), z: Q.z };
}

/** [x]Q, with x negative - so the negation of [|x|]Q. */
function mul_x_g2(Q) { return C2.neg(C2.mul(ABS_X, Q, 64)); }

/*
 * ⭐ EXPORTED SO THE ORACLE TEST CAN REACH IT.
 *
 *   The comment above promises a comparison against [h_eff]P, and that
 *   comparison needs this function by name - hash_to_g2 alone cannot provide
 *   it, because the pre-cofactor point it works on is internal and the
 *   subgroup checks that DO run would pass for a wrong coset too.
 *
 * ⚠ NOT PART OF THE PUBLIC SURFACE in any meaningful sense. It is here for
 *   the test, and a caller who needs it is doing something the rest of this
 *   module already does for them.
 */
export function _clear_cofactor_g2_for_tests(P) { return clear_cofactor_g2(P); }

/**
 * Is this G2 point in the prime-order subgroup?
 *
 * ⭐ psi(P) == [x]P IS THE CRITERION, and it is far cheaper than the direct
 *   test. [r]P on G2 measured 17 ms - a 255-bit scalar over Fp2 - while this
 *   is one 64-bit multiplication plus the endomorphism.
 *
 * ⛔ THE CHECK IS NOT OPTIONAL AND IT IS NOT A FORMALITY. A point on the
 *   curve but outside the prime-order subgroup breaks the security argument
 *   entirely, and every signature made with it still verifies - which is why
 *   this lives in one place now rather than being written out at each call
 *   site. Two copies of a mandatory check is one copy away from a version
 *   that omits it and passes every test.
 */
function in_subgroup_g2(P) {
    return eq_g2(psi_g2(P), mul_x_g2(P));
}

/** Same for G1, where the criterion is the same shape. */
function in_subgroup_g1(P) {
    return C1.is_zero(C1.mul(CURVE.r, P, 255)) === 1n;
}

/*
 * Projective equality, commons/g2.js's - four Fp2 multiplications. This used
 * to convert both sides to affine first, two Fp2 inversions at 671 us each on
 * every subgroup check, for the same answer (identity included).
 */
var eq_g2 = C2.eq;

function clear_cofactor_g2(P) {
    var t1 = mul_x_g2(P);
    var t2 = psi_g2(P);
    var t3 = psi2_g2(C2.dbl(P));
    t3 = C2.add(t3, C2.neg(t2));
    t2 = mul_x_g2(C2.add(t1, t2));
    t3 = C2.add(t3, t2);
    t3 = C2.add(t3, C2.neg(t1));
    return C2.add(t3, C2.neg(P));
}

export function hash_to_g2(msg, dst) {
    var u = hash_to_field(msg, 2, dst, CURVE.p, 2, 64, function (m, d, l) {
        return expand_message_xmd(m, d, l, sha256);
    });
    var q0 = iso_map_g2_pt(map_to_curve_sswu(Fp2, ISO2_A, ISO2_B, ISO2_Z, u[0], sgn0_fp2));
    var q1 = iso_map_g2_pt(map_to_curve_sswu(Fp2, ISO2_A, ISO2_B, ISO2_Z, u[1], sgn0_fp2));
    var P = C2.add(C2.of(q0.x, q0.y), C2.of(q1.x, q1.y));
    return clear_cofactor_g2(P);
}

function iso_map_g1_pt(q) { return iso_map(Fp,  ISO1_K1, ISO1_K2, ISO1_K3, ISO1_K4, q.x, q.y); }
function iso_map_g2_pt(q) { return iso_map(Fp2, ISO2_K1, ISO2_K2, ISO2_K3, ISO2_K4, q.x, q.y); }

/* ---------------- BLS signatures ---------------- */
/**
 * The IETF draft's MINIMAL-PUBKEY-SIZE variant: public keys in G1 (48 bytes),
 * signatures in G2 (96 bytes). Ethereum's choice, because a beacon chain
 * stores millions of validator keys and comparatively few signatures.
 *
 * AGGREGATION IS THE WHOLE POINT. Signatures add: the sum of signatures over
 * the SAME message verifies against the sum of the public keys, in one
 * verification. That is what lets Ethereum compress hundreds of thousands of
 * attestations per epoch into a handful of checks.
 *
 * THE ROGUE KEY ATTACK. Naive aggregation is broken: an attacker who
 * registers a public key of pk' = pk_target^-1 * (their own) can produce an
 * aggregate signature that verifies against the group without ever holding
 * the target's secret. Two defences are standard - requiring a proof of
 * possession for every registered key, or weighting each key by a hash of
 * itself. THIS IMPLEMENTATION PROVIDES NEITHER AUTOMATICALLY; a caller
 * aggregating keys from untrusted parties must verify proofs of possession
 * first. Ethereum does exactly that at deposit time.
 */

var DST_SIG = /* @__PURE__ */ ascii('BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_');

export var DST_POP = /* @__PURE__ */ ascii('BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_');

function scalar_of(secret) {
    var d = bytes_to_bigint(secret) % CURVE.r;
    if (d === 0n) { throw new Error('bls: invalid secret key'); }
    return d;
}

/** @return {Uint8Array} 48 bytes, compressed */
export function get_public_key(secret) {
    var A = C1.to_affine(C1.mul(scalar_of(secret), G1, 255));
    return compress_g1(A.x, A.y);
}

/**
 * A key pair: { sk: 32 bytes, pk: 48 bytes compressed G1 }, as sign, verify
 * and get_public_key take them (the minimal-pubkey-size variant; for the
 * _short one, get_public_key_short(kp.sk)).
 *
 * NOT the IETF draft's KeyGen(IKM), which this file does not implement: the
 * seed here IS the secret key, a big-endian scalar, checked as
 * get_public_key checks it. Omitted or null draws a fresh one from the
 * platform, uniform in [1, r).
 */
export function keygen(seed) {
    var sk = key_from_seed('bls12_381.keygen', seed, function () {
        return bigint_to_bytes(random_secret_below(CURVE.r, 'bls12_381.keygen'), 32);
    });
    return { sk: sk, pk: get_public_key(sk) };
}

/** @return {Uint8Array} 96 bytes, compressed */
export function sign(msg, secret, dst) {
    var H = hash_to_g2(msg, dst || DST_SIG);
    var S = C2.to_affine(C2.mul_ct(scalar_of(secret), H, 255));      /* the key: constant time (commons/g2.js) */
    return compress_g2(S.x, S.y);
}

/**
 * Verify with ONE final exponentiation, by checking
 * e(pk, H(m)) * e(-G1, sig) == 1 rather than comparing two pairings.
 */
export function verify(msg, sig, public_key, dst) {
    var PK = decompress_g1(public_key);
    var S = decompress_g2(sig);
    if (PK === null || S === null) { return false; }

    /* ⛔ mandatory - see in_subgroup_g2 */
    if (!in_subgroup_g1(C1.of(PK.x, PK.y))) { return false; }
    if (!in_subgroup_g2(C2.of(S.x, S.y))) { return false; }

    var H = C2.to_affine(hash_to_g2(msg, dst || DST_SIG));
    var negG1 = C1.to_affine(C1.neg(G1));
    var r = PAIRING.pair_product([[PK, H], [negG1, S]]);
    return Fp12.eq(r, Fp12.ONE);
}

/**
 * Add points in G1, or in G2.
 *
 * The four exported aggregate functions are these two under four names: a
 * public key in the long variant lives in G1 and a signature in the short
 * variant also lives in G1, so they are the same operation. Naming them
 * separately matches the IETF draft's vocabulary; implementing them
 * separately would have been four copies of ten lines.
 *
 * These were four copies until a review caught it - and the review nearly
 * missed it, because the copies differed only in their error strings and the
 * duplicate-detector normalised variable names but not string literals.
 */
/*
 * ⭐ AND THE TWO ARE ONE LOOP over the group's point codec. aggregate_g1 and
 *   aggregate_g2 were still the same ten lines with C1 / C2 and the G1 / G2
 *   codecs swapped - the four-into-two merge above stopped one step short.
 */
function aggregate_in(C, decompress, compress, items, what) {
    var acc = C.ZERO;
    for (var i = 0; i < items.length; i++) {
        /* the identity is a valid summand here, and the only place it is */
        var P = decompress(items[i], true);
        if (P === null) { throw new Error('bls: invalid ' + what + ' in aggregate'); }
        if (!P.inf) { acc = C.add(acc, C.of(P.x, P.y)); }
    }
    var A = C.to_affine(acc);
    if (A === null) {                                   /* the sum is infinity */
        var out = new Uint8Array(compress === compress_g1 ? 48 : 96);
        out[0] = 0xc0;
        return out;
    }
    return compress(A.x, A.y);
}

function aggregate_g1(items, what) { return aggregate_in(C1, decompress_g1, compress_g1, items, what); }
function aggregate_g2(items, what) { return aggregate_in(C2, decompress_g2, compress_g2, items, what); }

/**
 * Long variant: signatures are in G2, public keys in G1.
 * See the rogue-key warning above before aggregating untrusted keys.
 */
export function aggregate_signatures(sigs) { return aggregate_g2(sigs, 'signature'); }
export function aggregate_public_keys(keys) { return aggregate_g1(keys, 'public key'); }

/** Short variant: the groups are exchanged. */
export function aggregate_signatures_short(sigs) { return aggregate_g1(sigs, 'signature'); }
export function aggregate_public_keys_short(keys) { return aggregate_g2(keys, 'public key'); }



/*
 * ZCash-style point compression, which is what every BLS12-381 deployment
 * uses. The three top bits of the first byte are flags: compressed, infinity,
 * and the sign of y. Coordinates are 381 bits, so those three bits are free.
 */

/*
 * POINT COMPRESSION, EXPORTED FOR bbs.js.
 *
 * The four functions below are the ZCash serialisation that every BLS12-381
 * consumer uses: 48 bytes for G1, 96 for G2, with the top three bits carrying
 * the compression flag, the infinity flag and the sign of y. Anything built
 * on this curve needs them, and bbs.js taking them as parameters instead was
 * a worse interface than exporting them.
 */
export function compress_point_g1(x, y) { return compress_g1(x, y); }
export function decompress_point_g1(b, allow_infinity) { return decompress_g1(b, allow_infinity); }
export function compress_point_g2(x, y) { return compress_g2(x, y); }
export function decompress_point_g2(b, allow_infinity) { return decompress_g2(b, allow_infinity); }

/*
 * "The larger of the two roots": y > (p-1)/2, which for odd p is 2y >= p.
 * For Fp2 the imaginary part decides, and the real part only when the
 * imaginary part is zero. Both were written out at each of the four sites.
 */
function larger_fp(y) { return (y * 2n) / CURVE.p >= 1n; }
function larger_fp2(y) { return larger_fp(y[1]) || (y[1] === 0n && larger_fp(y[0])); }

function compress_g1(x, y) {
    var out = bigint_to_bytes(x, 48);
    out[0] |= 0x80;                                   /* compressed */
    if (larger_fp(y)) { out[0] |= 0x20; }               /* the larger of the two roots */
    return out;
}

/*
 * THE POINT AT INFINITY: ONE RULE FOR BOTH GROUPS.
 *
 * Its only encoding is 0xc0 followed by zeros (compressed + infinity, sign
 * bit clear, x zero). Anything else with the infinity bit set is malformed.
 * The point itself is refused unless the caller asks for it
 * (allow_infinity): a public key, a signature to verify, a BBS signature or
 * proof element must never be the identity, and aggregation is the one
 * operation where it is a legitimate value.
 *
 * ⛔ G1 USED TO ACCEPT ANY BYTES WITH THE INFINITY BIT ("e000..", "c010.."
 *   decoded alike, as {x: 0, y: 0} - not a point at all, and what verify and
 *   bbs then built a point from), while G2 refused infinity outright, so
 *   aggregating the infinity signature threw.
 */
function infinity_flag(b, allow) {
    for (var i = 1; i < b.length; i++) { if (b[i] !== 0) { return null; } }
    if (b[0] !== 0xc0) { return null; }
    return allow ? { inf: true } : null;
}

function decompress_g1(b, allow_infinity) {
    if (b.length !== 48 || !(b[0] & 0x80)) { return null; }
    if (b[0] & 0x40) { return infinity_flag(b, allow_infinity); }
    var greater = (b[0] & 0x20) !== 0;
    var bx = new Uint8Array(b);
    bx[0] &= 0x1f;
    var x = bytes_to_bigint(bx);
    if (x >= CURVE.p) { return null; }
    var y2 = Fp.add(Fp.mul(Fp.sqr(x), x), 4n);
    var y = Fp.sqrt(y2);
    if (y === null) { return null; }
    if (larger_fp(y) !== greater) { y = Fp.neg(y); }
    return { x: x, y: y };
}

function compress_g2(x, y) {
    var out = new Uint8Array(96);
    out.set(bigint_to_bytes(x[1], 48), 0);            /* imaginary part first */
    out.set(bigint_to_bytes(x[0], 48), 48);
    out[0] |= 0x80;
    if (larger_fp2(y)) { out[0] |= 0x20; }
    return out;
}

function decompress_g2(b, allow_infinity) {
    if (b.length !== 96 || !(b[0] & 0x80)) { return null; }
    if (b[0] & 0x40) { return infinity_flag(b, allow_infinity); }
    var greater = (b[0] & 0x20) !== 0;
    var bx = new Uint8Array(b);
    bx[0] &= 0x1f;
    var x1 = bytes_to_bigint(bx.subarray(0, 48));
    var x0 = bytes_to_bigint(bx.subarray(48));
    if (x0 >= CURVE.p || x1 >= CURVE.p) { return null; }
    var x = [x0, x1];
    var y2 = Fp2.add(Fp2.mul(Fp2.sqr(x), x), B2);
    var y = Fp2.sqrt(y2);
    if (y === null) { return null; }
    if (larger_fp2(y) !== greater) { y = Fp2.neg(y); }
    return { x: x, y: y };
}

/* ---------------- proof of possession, and safe aggregate verification ---------------- */
/**
 * A proof of possession: a signature over the public key itself, under a
 * SEPARATE domain tag.
 *
 * This is the defence against the rogue-key attack described above. An
 * attacker can register pk' = (target's key)^-1 * (their own) and forge an
 * aggregate, but they cannot produce a signature over pk' without its secret.
 * Requiring a proof at registration time closes the hole; Ethereum demands
 * one when a validator deposits.
 *
 * The distinct DST is what stops a proof from being replayed as an ordinary
 * signature over a message that happens to equal a public key.
 */
export function prove_possession(secret) {
    return sign(get_public_key(secret), secret, DST_POP);
}

export function verify_possession(public_key, proof) {
    return verify(public_key, proof, public_key, DST_POP);
}

/**
 * Verify one aggregate signature over DIFFERENT messages from different keys.
 *
 * Costs one Miller loop per signer plus a single final exponentiation - the
 * saving that makes aggregation worth doing at all.
 *
 * THE MESSAGES MUST BE DISTINCT. With repeated messages this is insecure even
 * with proofs of possession, because an attacker can cancel terms across the
 * product. The check below enforces it rather than trusting the caller; use
 * fast_aggregate_verify for the same-message case.
 */
export function aggregate_verify(msgs, sig, public_keys, dst) {
    if (msgs.length !== public_keys.length || msgs.length === 0) { return false; }

    var seen = {}, i;
    for (i = 0; i < msgs.length; i++) {
        var k = '';
        for (var j = 0; j < msgs[i].length; j++) { k += msgs[i][j].toString(16); }
        if (seen[k]) { return false; }
        seen[k] = 1;
    }

    var S = decompress_g2(sig);
    if (S === null) { return false; }
    /*
     * ⛔ THIS WAS STILL THE OLD [r]P TEST - the one `verify` was moved off in
     *   an earlier pass, and a copy that was missed. On G2 that is a 255-bit
     *   scalar over Fp2 at 17 ms; in_subgroup_g2 is one 64-bit multiply and
     *   the endomorphism.
     */
    if (!in_subgroup_g2(C2.of(S.x, S.y))) { return false; }

    /*
     * ⭐ THE HASHED MESSAGES ARE CONVERTED TO AFFINE IN ONE BATCH.
     *
     *   Each hash_to_g2 result needs one Fp2 inversion to go from projective
     *   to affine, and they are independent - so Montgomery's trick turns N
     *   inversions into one plus 3N multiplications. Measured: an Fp2
     *   inversion is 671 us against 0.8 for a multiply.
     *
     * ⚠ THE POINT AT INFINITY WOULD POISON THE WHOLE BATCH, since its Z is
     *   zero and the running product would be too - every output would come
     *   back zero rather than just that one. hash_to_g2 cannot return
     *   infinity (it clears the cofactor of a point the SSWU map placed on
     *   the curve), which is why this is safe here and would not be for
     *   arbitrary caller-supplied points.
     */
    var hashed = [], zs = [];
    for (i = 0; i < public_keys.length; i++) {
        var H = hash_to_g2(msgs[i], dst || DST_SIG);
        hashed.push(H);
        zs.push(H.z);
    }
    var zinv = Fp2.inv_batch(zs);

    var pairs = [];
    for (i = 0; i < public_keys.length; i++) {
        var PK = decompress_g1(public_keys[i]);
        if (PK === null) { return false; }
        if (!in_subgroup_g1(C1.of(PK.x, PK.y))) { return false; }
        pairs.push([PK, { x: Fp2.mul(hashed[i].x, zinv[i]),
                          y: Fp2.mul(hashed[i].y, zinv[i]) }]);
    }
    pairs.push([C1.to_affine(C1.neg(G1)), S]);

    return Fp12.eq(PAIRING.pair_product(pairs), Fp12.ONE);
}

/**
 * Verify one aggregate signature over the SAME message from many keys.
 *
 * The public keys are added first, so this costs TWO pairings regardless of
 * how many signers there are. That is the property Ethereum's beacon chain
 * runs on: hundreds of thousands of attestations over one block root collapse
 * into a fixed amount of verification work.
 *
 * REQUIRES PROOFS OF POSSESSION to have been checked for every key. Without
 * them the rogue-key attack applies directly here.
 */
/* dst: the ciphersuite, as for verify. fast aggregation is only sound under
   proofs of possession (the POP suite Ethereum uses) - see above */
export function fast_aggregate_verify(msg, sig, public_keys, dst) {
    if (public_keys.length === 0) { return false; }
    /* KeyValidate on EVERY key, as aggregate_verify does: an identity key
       dropped silently out of the sum and the rest still verified */
    for (var i = 0; i < public_keys.length; i++) {
        var K = decompress_g1(public_keys[i]);
        if (K === null || !in_subgroup_g1(C1.of(K.x, K.y))) { return false; }
    }
    return verify(msg, sig, aggregate_public_keys(public_keys), dst);
}

/* ---------------- threshold signatures ---------------- */
/**
 * t-of-n threshold BLS.
 *
 * A secret is split into n shares; any t of them reconstruct a signature that
 * verifies against the ORIGINAL public key. Fewer than t reveal nothing at
 * all - not a weaker key, nothing.
 *
 * WHY BLS MAKES THIS EASY AND ECDSA DOES NOT. A BLS signature is
 * sk * H(m) - LINEAR in the secret. So Lagrange interpolation, which
 * reconstructs a polynomial's value at zero from t points, works directly on
 * the signature shares. Each signer produces their share alone, offline, and
 * a coordinator combines them with no protocol at all.
 *
 * ECDSA needs k^-1 in its signing equation, which is not linear, so threshold
 * ECDSA requires multi-round MPC protocols that took the field twenty years
 * and are still delicate. Threshold Schnorr sits in between: linear, but the
 * nonce has to be agreed in a round of communication first.
 *
 * This is what drand's randomness beacon runs on, and what most
 * distributed-custody systems use.
 *
 * NOTE ON THE DEALER. split_secret below is a TRUSTED DEALER scheme: whoever
 * runs it sees the whole secret. Removing that requires distributed key
 * generation, where the parties jointly produce shares of a secret nobody
 * ever holds. DKG is a protocol rather than a function and is out of scope
 * here; a caller that needs it should not fake it with this.
 */

var Fr = /* @__PURE__ */ field(CURVE.r);

/**
 * Shamir split over the scalar field.
 *
 * A random polynomial of degree t-1 with the secret as its constant term;
 * each share is the polynomial at x = 1, 2, ... n. Any t points determine the
 * polynomial, and therefore the constant term; t-1 leave it uniformly random.
 *
 * @param  {Uint8Array} secret
 * @param  {number}     t       threshold
 * @param  {number}     n       shares to produce
 * @param  {function}   rng
 * @return {Array<{index: number, share: Uint8Array}>}
 */
export function split_secret(secret, t, n, rng) {
    if (t < 1 || t > n) { throw new Error('bls: need 1 <= t <= n'); }
    var s = scalar_of(secret);

    /* the polynomial, its evaluation and the unbiased coefficient draw are
       all in shamir.js - frost.js uses the same code over ristretto's
       order */
    return shamir.split(s, t, n, rng, CURVE.r).map(function (sh) {
        return { index: Number(sh.index), share: bigint_to_bytes(sh.value, 32) };
    });
}

/** The public key of a share, so a coordinator can verify shares individually. */
export function share_public_key(share) { return get_public_key(share.share); }

/** Sign with one share. The result is a partial signature, not a signature. */
export function threshold_sign(msg, share, dst) {
    return { index: share.index, sig: sign(msg, share.share, dst) };
}

/**
 * Combine t partial signatures into one that verifies against the original
 * public key.
 *
 * The coordinator needs no secret and learns none. Supplying MORE than t
 * partials is fine; supplying fewer produces a signature that simply fails
 * verification, which is why the caller should verify the result.
 */

/*
 * The group interfaces Pippenger expects. Defined once here because three
 * call sites below use them - threshold combination, the group public key,
 * and batch verification.
 *
 * EVERY ONE OF THOSE IS OVER PUBLIC SCALARS: Lagrange coefficients derived
 * from published indices, and the random weights a batch verifier draws for
 * itself. Pippenger's bucket pattern reveals its scalars, so a fourth call
 * site would need that checked again rather than assumed.
 */
var G1_MSM = /* @__PURE__ */ msm_group(C1);
var G2_MSM = /* @__PURE__ */ msm_group(C2);

export function threshold_combine(partials) {
    if (partials.length === 0) { throw new Error('bls: no partial signatures'); }
    var indices = partials.map(function (p) { return p.index; });

    var scalars = [], points = [];
    /* ⭐ one batched inversion for the whole set rather than one per signer -
       9x at 20 signers, 2x at 3. The coefficients depend only on the index
       set, so they are all computable before the loop. */
    var coeffs = shamir.lagrange_coeffs_at_zero(indices.map(BigInt), CURVE.r);
    for (var i = 0; i < partials.length; i++) {
        var S = decompress_g2(partials[i].sig);
        if (S === null) { throw new Error('bls: invalid partial signature'); }
        scalars.push(coeffs[i]);
        points.push(C2.of(S.x, S.y));
    }
    var A = C2.to_affine(msm(G2_MSM, scalars, points, 255));
    return compress_g2(A.x, A.y);
}

/**
 * Combine partial signatures with GIVEN coefficients: sum c_i * sig_i in G2.
 *
 * threshold_combine computes Lagrange coefficients from the indices; an
 * access structure (access.js) has its own, and this takes them as they are.
 * The scalars must be PUBLIC (they go through Pippenger, see G2_MSM above):
 * recombination coefficients are.
 *
 * @param sigs     compressed G2 signatures (96 bytes each)
 * @param scalars  bigints, one per signature
 * @return {Uint8Array} 96 bytes, compressed
 */
export function combine_weighted(sigs, scalars) {
    if (!Array.isArray(sigs) || sigs.length === 0 || !Array.isArray(scalars) || scalars.length !== sigs.length) {
        throw new Error('bls: combine_weighted needs as many scalars as signatures, at least one');
    }
    var points = [], ks = [];
    for (var i = 0; i < sigs.length; i++) {
        var S = decompress_g2(sigs[i]);
        if (S === null) { throw new Error('bls: invalid partial signature'); }
        var P = C2.of(S.x, S.y);
        if (!in_subgroup_g2(P)) { throw new Error('bls: partial signature outside the subgroup'); }
        points.push(P);
        ks.push(((scalars[i] % CURVE.r) + CURVE.r) % CURVE.r);
    }
    var A = C2.to_affine(msm(G2_MSM, ks, points, 255));
    if (A === null) { throw new Error('bls: the combination is the identity'); }
    return compress_g2(A.x, A.y);
}

/**
 * The group public key: what a combined signature verifies against.
 *
 * It is the public key of the ORIGINAL secret, and can be recovered from any
 * t share public keys by the same interpolation - which is how a system that
 * never held the secret still knows the key.
 */
export function threshold_public_key(share_pubkeys, indices) {
    var pk_scalars = [], pk_points = [];
    var pk_coeffs = shamir.lagrange_coeffs_at_zero(indices.map(BigInt), CURVE.r);
    for (var i = 0; i < share_pubkeys.length; i++) {
        var K = decompress_g1(share_pubkeys[i]);
        if (K === null) { throw new Error('bls: invalid share public key'); }
        pk_scalars.push(pk_coeffs[i]);
        pk_points.push(C1.of(K.x, K.y));
    }
    var A = C1.to_affine(msm(G1_MSM, pk_scalars, pk_points, 255));
    return compress_g1(A.x, A.y);
}

/* ---------------- the short-signature variant ---------------- */
/**
 * MINIMAL-SIGNATURE-SIZE: public keys in G2 (96 bytes), signatures in G1
 * (48 bytes) - the mirror image of everything above.
 *
 * The IETF draft defines both, and the choice is a genuine trade-off rather
 * than a preference:
 *
 *   minimal-pubkey-size   pk 48, sig 96   Ethereum. Millions of validator
 *                                         keys are stored; signatures are
 *                                         aggregated away.
 *   minimal-signature-size pk 96, sig 48  Chia, and anything writing a
 *                                         signature into every record while
 *                                         holding few keys.
 *
 * Signing is also cheaper here, because a scalar multiplication in G1 costs
 * roughly a third of one in G2 - the coordinates are Fp rather than Fp2.
 * Verification costs the same either way.
 *
 * THE TWO VARIANTS ARE NOT INTERCHANGEABLE. Their domain tags differ
 * (G1 versus G2 in the DST), so a signature from one will not verify under
 * the other even after swapping the groups - which is the point of putting
 * the group name in the tag.
 */

var DST_SIG_SHORT = /* @__PURE__ */ ascii('BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_');
export var DST_POP_SHORT = /* @__PURE__ */ ascii('BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_');

/** @return {Uint8Array} 96 bytes */
export function get_public_key_short(secret) {
    var A = C2.to_affine(C2.mul_ct(scalar_of(secret), BASE2, 255));
    return compress_g2(A.x, A.y);
}

/** @return {Uint8Array} 48 bytes */
export function sign_short(msg, secret, dst) {
    var H = hash_to_g1(msg, dst || DST_SIG_SHORT);
    var S = C1.to_affine(C1.mul(scalar_of(secret), H, 255));
    return compress_g1(S.x, S.y);
}

export function verify_short(msg, sig, public_key, dst) {
    var PK = decompress_g2(public_key);
    var S = decompress_g1(sig);
    if (PK === null || S === null) { return false; }

    /*
     * ⛔ mandatory - see in_subgroup_g2. These were the two checks written
     *   out inline, [r]P == O on each side; the G2 one is the 17 ms form
     *   `verify` and aggregate_verify had already been moved off. The psi
     *   criterion is the same test, so the answers are unchanged.
     */
    if (!in_subgroup_g2(C2.of(PK.x, PK.y))) { return false; }
    if (!in_subgroup_g1(C1.of(S.x, S.y))) { return false; }

    /* e(H(m), pk) * e(-sig, G2) == 1 */
    var H = C1.to_affine(hash_to_g1(msg, dst || DST_SIG_SHORT));
    var negS = { x: S.x, y: Fp.neg(S.y) };
    var r = PAIRING.pair_product([[H, PK], [negS, C2.to_affine(BASE2)]]);
    return Fp12.eq(r, Fp12.ONE);
}



export function prove_possession_short(secret) {
    return sign_short(get_public_key_short(secret), secret, DST_POP_SHORT);
}

export function verify_possession_short(public_key, proof) {
    return verify_short(public_key, proof, public_key, DST_POP_SHORT);
}

export function fast_aggregate_verify_short(msg, sig, public_keys, dst) {
    if (public_keys.length === 0) { return false; }
    for (var i = 0; i < public_keys.length; i++) {
        var K = decompress_g2(public_keys[i]);
        if (K === null || !in_subgroup_g2(C2.of(K.x, K.y))) { return false; }
    }
    return verify_short(msg, sig, aggregate_public_keys_short(public_keys), dst);
}

/* ---------------- batch verification ---------------- */
/**
 * Verify many INDEPENDENT (message, signature, key) triples at once.
 *
 * This is not aggregation - the signatures were never combined and stay
 * separate. It is a way to check n of them for the cost of n Miller loops and
 * ONE final exponentiation, which is roughly half the work of verifying them
 * individually.
 *
 * THE RANDOM COEFFICIENTS ARE NOT OPTIONAL. Checking
 * prod e(pk_i, H_i) * e(-G1, sum sig_i) == 1 without them is broken: an
 * attacker submits two invalid signatures whose errors cancel, and the batch
 * passes while neither signature is valid. Weighting each triple by a fresh
 * random scalar makes cancellation possible only with probability about 2^-128.
 *
 * A batch that fails says only that AT LEAST ONE triple is bad, not which.
 * Callers that need to identify the culprit must fall back to verifying
 * individually, or bisect.
 *
 * @param {function} [rng]  fresh randomness - reusing coefficients defeats
 *                          it; omitted or null draws fresh ones from the
 *                          platform (pass null to give a dst)
 */
export function batch_verify(msgs, sigs, public_keys, rng, dst) {
    rng = require_rng('bls12_381.batch_verify', rng);
    var n = msgs.length;
    if (n === 0 || sigs.length !== n || public_keys.length !== n) { return false; }

    var pairs = [];
    var acc = C2.ZERO;

    for (var i = 0; i < n; i++) {
        var PK = decompress_g1(public_keys[i]);
        var S = decompress_g2(sigs[i]);
        if (PK === null || S === null) { return false; }
        if (!in_subgroup_g1(C1.of(PK.x, PK.y))) { return false; }
        if (!in_subgroup_g2(C2.of(S.x, S.y))) { return false; }

        /* 128 bits of randomness is enough; full-width scalars would cost
           twice the multiplication time for no extra security */
        var r = bytes_to_bigint(rng(16));
        if (r === 0n) { r = 1n; }

        var wPK = C1.to_affine(C1.mul(r, C1.of(PK.x, PK.y), 255));
        pairs.push([wPK, C2.to_affine(hash_to_g2(msgs[i], dst || DST_SIG))]);
        acc = C2.add(acc, C2.mul(r, C2.of(S.x, S.y)));
    }

    pairs.push([C1.to_affine(C1.neg(G1)), C2.to_affine(acc)]);
    return Fp12.eq(PAIRING.pair_product(pairs), Fp12.ONE);
}

/* ---------------- verifiable secret sharing and distributed key generation ---------------- */
/**
 * Feldman VSS, and the cryptographic core of a distributed key generation.
 *
 * split_secret above is a TRUSTED DEALER scheme: the dealer sees the whole
 * secret, and a recipient has no way to tell a correct share from a corrupt
 * one until signing fails. Both problems are solved by the same idea.
 *
 * A dealer publishes COMMITMENTS to its polynomial's coefficients - the
 * public keys of a_0, a_1, ... a_(t-1). Anyone can then check a share against
 * them: g^f(x) must equal the product of C_k raised to x^k, because that is
 * what evaluating the polynomial in the exponent means. The commitments
 * reveal nothing about the coefficients, and a dealer that sends a wrong
 * share is caught immediately.
 *
 * A FULL DKG is n parties each running as a dealer at once. Every party
 * contributes a polynomial, sends each other party its evaluation, and
 * verifies what it receives. The final share is the sum of all received
 * shares, and the group key is the sum of all the constant-term commitments -
 * a secret that NO SINGLE PARTY EVER HELD.
 *
 * WHAT THIS FILE PROVIDES AND WHAT IT DOES NOT. Every cryptographic step is a
 * function below: dealing with commitments, verifying a received share,
 * combining shares, deriving the group key. What is missing is transport and
 * complaint handling - who sends what to whom, what happens when a party is
 * caught cheating, and how the honest set is agreed. Those are protocol
 * decisions that depend on the surrounding system, and no library can make
 * them. The same is true of every other primitive here: this file signs and
 * verifies, it does not run TLS.
 */

/**
 * Deal a secret with commitments.
 *
 * @param  {function}   [rng]     omitted or null draws fresh bytes from the
 *                                platform (pass null to give a secret)
 * @param  {Uint8Array} [secret]  omit to generate one - the DKG case, where
 *                                each party contributes randomness
 * @return {{shares: Array, commitments: Array<Uint8Array>, secret: Uint8Array}}
 */
export function vss_deal(t, n, rng, secret) {
    rng = require_rng('bls12_381.vss_deal', rng);
    if (t < 1 || t > n) { throw new Error('bls: need 1 <= t <= n'); }

    var coeffs = [];
    coeffs.push(secret == null ? random_below_biased(CURVE.r, rng)
                                     : scalar_of(secret));
    for (var i = 1; i < t; i++) {
        coeffs.push(random_below_biased(CURVE.r, rng));
    }

    /* one commitment per coefficient - these are public */
    var commitments = coeffs.map(function (a) {
        var A = C1.to_affine(C1.mul(a, G1, 255));
        return compress_g1(A.x, A.y);
    });

    var shares = [];
    for (var x = 1n; x <= BigInt(n); x++) {
        var y = shamir.evaluate(coeffs, x, CURVE.r);          /* Horner: shamir.js */
        shares.push({ index: Number(x), share: bigint_to_bytes(y, 32) });
    }

    return {
        shares: shares,
        commitments: commitments,
        secret: bigint_to_bytes(coeffs[0], 32)
    };
}

/**
 * Σ_k x^k·C_k in G1 — the commitments evaluated at x, as a projective point
 * (C1.ZERO when it is the identity); null when a commitment does not decode.
 *
 * Exported for DKGs, which need the value — each party's verification share
 * — and not only vss_verify_share's yes/no.
 */
export function vss_eval_g1(commitments, x) {
    var acc = C1.ZERO;
    var xk = 1n;
    for (var k = 0; k < commitments.length; k++) {
        var Ck = decompress_g1(commitments[k]);
        if (Ck === null) { return null; }
        acc = C1.add(acc, C1.mul(xk, C1.of(Ck.x, Ck.y), 255));
        xk = Fr.mul(xk, BigInt(x));
    }
    return acc;
}

/**
 * Check a received share against the dealer's commitments.
 *
 * This is the step that removes the need to trust the dealer. It verifies
 * that g^share equals the polynomial evaluated in the exponent, which holds
 * only if the share really is f(index) for the committed polynomial.
 *
 * @return {boolean}
 */
export function vss_verify_share(share, commitments) {
    var expected = vss_eval_g1(commitments, BigInt(share.index));
    if (expected === null) { return false; }

    var A = C1.to_affine(C1.mul(scalar_of(share.share), G1, 255));
    var E = C1.to_affine(expected);
    if (E === null) { return false; }
    return A.x === E.x && A.y === E.y;
}

/**
 * A party's final share after a DKG: the sum of everything it received.
 *
 * Summing the shares corresponds to summing the polynomials, so the result is
 * a share of the sum of every party's secret - which is the group secret, and
 * which nobody computed.
 */
export function dkg_combine_shares(received) {
    if (received.length === 0) { throw new Error('bls: no shares'); }
    var idx = received[0].index;
    var acc = 0n;
    for (var i = 0; i < received.length; i++) {
        if (received[i].index !== idx) {
            throw new Error('bls: shares belong to different parties');
        }
        acc = Fr.add(acc, scalar_of(received[i].share));
    }
    return { index: idx, share: bigint_to_bytes(acc, 32) };
}

/**
 * The group public key: the sum of every dealer's constant-term commitment.
 *
 * Available to everyone from public data alone, before any signing happens
 * and without anyone holding the secret.
 */
export function dkg_group_public_key(all_commitments) {
    var firsts = all_commitments.map(function (c) { return c[0]; });
    return aggregate_g1(firsts, 'commitment');
}


/* ---------------- G1 as a prime-order group ---------------- */
/**
 * G1 (where this library's public keys live) behind the same GROUP interface
 * every other curve here exports (commons/group.js): constant-time
 * multiplication (the ladder), 48-byte compressed encoding, and a decode that
 * refuses the identity and anything outside the prime-order subgroup.
 *
 * What it is for: protocols written once over "a group" - Feldman
 * commitments, Schnorr proofs, secret sharing over an access structure -
 * running on the BLS12-381 key group, so a BLS key can be dealt by them and
 * its signatures (in G2, with the pairing) checked against their points.
 */
function eq_g1(P, Q) {
    var F = Fp;
    return F.mul(P.X, Q.Z) === F.mul(Q.X, P.Z) && F.mul(P.Y, Q.Z) === F.mul(Q.Y, P.Z);
}
export var GROUP_G1 = /* @__PURE__ */ make_group({
    name: 'bls12_381',
    little_endian: false,
    scalar_bytes_length: 32,
    ORDER: CURVE.r,
    bits: 255,
    IDENTITY: C1.ZERO,
    GENERATOR: G1,
    encoded_length: 48,
    add: C1.add,
    neg: C1.neg,
    equals: eq_g1,
    mul_raw: function (k, P, bits) { return C1.mul(k, P, bits); },
    encode_raw: function (P) { var A = C1.to_affine(P); return compress_g1(A.x, A.y); },
    decode_raw: function (b) { var A = decompress_g1(b); return A === null ? null : C1.of(A.x, A.y); },
    in_subgroup: in_subgroup_g1
});
