/**
 * SQIsign  -  the round-3 submission to NIST's additional signatures
 *
 * An isogeny signature. The public key is a supersingular Montgomery curve
 * E_pk over GF(p^2), p = c * 2^e - 1; the signer knows the endomorphism ring
 * of E_pk (through a secret isogeny from the special curve E_0: y^2 = x^3 + x).
 * A signature proves that knowledge: the message hashes (with E_pk and a
 * commitment curve E_com) to a challenge isogeny E_pk -> E_chall of degree
 * 2^chall_bits, and the signer answers with a response isogeny E_com ->
 * E_chall of degree < 2^resp_bits, which it can only find through the
 * quaternion algebra behind End(E_pk).
 *
 * THE RESPONSE TRAVELS AS A 2-DIMENSIONAL ISOGENY. The signature gives an
 * auxiliary curve E_aux and a 2x2 matrix; the verifier rebuilds canonical
 * 2^f-torsion bases on E_chall and E_aux from one-byte hints, maps the first
 * through the matrix, and computes the (2^n, 2^n)-isogeny of E_chall x E_aux
 * whose kernel the two bases span, in theta coordinates: a gluing step, a
 * chain of 2-isogenies between products of theta structures, and a final
 * splitting. Its codomain is E_com x E', and the signature verifies when
 * hashing E_com gives back the challenge.
 *
 * The curve arithmetic - theta coordinates, canonical bases, pairings - is in
 * commons/isogeny.js.
 *
 * THE SIGNER WORKS IN THE QUATERNION ALGEBRA (commons/quaternion.js): the
 * secret key is an ideal of O_0 of prime norm, made small; the commitment is
 * another; the response is a short element of the product of the secret,
 * challenge and commitment ideals, completed by an auxiliary ideal to degree
 * 2^resp_bits so that it becomes the 2-dimensional isogeny above. Each ideal
 * becomes an isogeny through the qlapoty algorithm: a norm equation solved in
 * O_0, whose solution is a (2^e, 2^e)-isogeny out of E_0 x E_0 evaluated on
 * E_0's basis through the precomputed action of O_0 on it. The bases'
 * coordinates between hints are discrete logarithms of Tate pairings.
 *
 * LEVELS: p = 3 * 2^324 - 1 (level 1), 27 * 2^500 - 1 (level 3),
 * 17 * 2^664 - 1 (level 5). pk = A (in GF(p^2), little-endian re || im) ||
 * hint byte; sk = pk || the secret ideal (norm, x, y) || the matrix from the
 * canonical basis of E_pk to the image of E_0's; sig = A_aux || four matrix
 * entries || challenge || two hints.
 *
 * KEYGEN AND SIGN TAKE THE RANDOMNESS: keygen(seed) and sign(sk, msg, rnd),
 * each 48 bytes, the reference's PRNG seed (SHAKE256 streams for the domains
 * "key", "com", "res" and the default "def" are derived from it). Signing
 * fails only with negligible probability, by throwing.
 */

import { isogeny_tools } from './commons/isogeny.js';
import { shake256 } from './sha3.js';
import { bytes_to_bigint_le, bigint_to_bytes_le, concat, secure_random } from './commons/bytes.js';
import { quaternion_tools, prng_domain } from './commons/quaternion.js';
import { lazy_scheme } from './commons/lazy_scheme.js';

/*
 * [name, cofactor c, e (p = c*2^e - 1), challenge bits, response bits,
 *  E_0 basis x(P) re/im, x(Q) re/im (affine, the 2^e-torsion basis of E_0),
 *  integer limbs, bound of the equivalent-ideal coefficients, bits and hex of
 *  floor(sqrt p), the 2-power used by qlapoty, scalar words]
 */
var LEVELS = {
    1: ['SQIsign_lvl1', 3n, 324, 128, 196,
        '2f5794ac8c12fd0aa9eecce1ef59c845e644efb1d83bfe12d9d1144badb77c74f532d79d7af17bc4d3',
        '1f5213ad2a961e68b62dd1e7a52f8a3773a68fca0fd2de384700119ccad18f95397269898753ba602e',
        '17ff26f770aaa7aa48966aedb5ef8c28b0849e0672ca488a3484a008019f4bf11279512257b1a6385b',
        '1da20dc6de567fd2bf17e29fa4a4c8a42bef024ed5030c5fac90d216a62228926fcbee6d95945b36bb',
        30, 15, 163, '6ed9eba16132a9cec95d0b5c1e2e0ee249760d331', 322, 6],
    3: ['SQIsign_lvl3', 27n, 500, 192, 302,
        '9fafe5085fcb1f13d5e487f010c8026abe233871b01f4a3587f06737f9bc686ba009922e2d459ec8f149c4c4083604e7842a612b6fdf8180025cdeb187b4c0',
        'c42a516ef3cf80d3e2e7a2d88faba1e46785ddce14f150ff4d204a43d47ad8d01940b2eba9aaac28b7198e48ed9281128f5782cdd197f48cddfbffe867063d',
        'bce91be61859cd3ddcd3f8408657d1d43c6f2764437e66e96371e74bc4b725f0cb99b58b09a91e872afcebb4608219f68aa3572c70ef5e6e654099bfc8aa09',
        'a48c9987de3810adbf0813505a561e134f31d64466875f90e21dd7c6b44eb81bed0e58d70ebd39fd9443a7523049993bd75145d72ec8f52be58b7086fffbe8',
        40, 19, 253, '14c8dc2e42397fd6c5c1722145a8a2ca6dc6227993ee3b5b295587cb652b43d2', 498, 8],
    5: ['SQIsign_lvl5', 17n, 664, 256, 400,
        'b66b93a890673a0d7e33340c53b6b986c1bbb905054419c400e5458a8655c166345abc1e4d70516e0dfcd03f7cbca2a87da6ef003f9301aa1e3a662f2db25e00f57345faa348b8c78d403891c85677b4b8d62ce',
        '900d04c251411f3be86fc8bc618b7d4caefb2a31c23b1cd9f86fcfb8cb114bf6fe9e19bca9fdd6e150b8fcca7eb7c7b71dceea11abff9da7dbab00e5d6e1dbe6b449796c96b4f2f5a5bf4e3cb04973bc3fdb8c9',
        'f4f3311a4df85d112f2ec580f3f677f1d80c2105cf9e7dea9f8b06d3b412aa14a0e1d1ae2dbf8b5d8fca950f0d355fa25cd98e4e14d58df00ada18c8453d45702ad7b8188d55a8df97c0dc87782f17e9e99452c',
        '2b3e8126b1983e58e41e2ed4ef551b7f4617364b1c3f04f072d50e9d77e5ae2ecedf5d924fe21e881a085764064bc175daa0308f13d6a1b760378c23aa4c912fe365ce0d5673b4edf297440304f2c1415d2b502',
        55, 22, 335, '41f83d9abfb41bd6b23c4654c2a2175832842012131573f2aa59916aca3991fcaec1b7c06fd19d2561ec', 662, 11]
};

/*
 * The signer's constants (the reference's precomputation): the cofactor of
 * the norms represented by RepresentInteger, 2^challenge bits, the degrees of
 * the secret and commitment ideals, the 2^e-torsion basis of E_0 (P, Q, P - Q
 * projective) and the action of i, j, k and of the O_0 generators (i + j)/2,
 * (1 + k)/2 on it, as matrices modulo 2^e. Integers are [hex, bit bound].
 */
var DATA = {
    1: {
        cofactor: ['4000000000000000000000000000000000055', 148], two_chall: ['100000000000000000000000000000000', 130],
        sec_degree: ['2fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000009b', 583],
        com_degree: ['2fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000009b', 583],
        basis: [[['2f5794ac8c12fd0aa9eecce1ef59c845e644efb1d83bfe12d9d1144badb77c74f532d79d7af17bc4d3', '1f5213ad2a961e68b62dd1e7a52f8a3773a68fca0fd2de384700119ccad18f95397269898753ba602e'], ['1', '0']],
            [['17ff26f770aaa7aa48966aedb5ef8c28b0849e0672ca488a3484a008019f4bf11279512257b1a6385b', '1da20dc6de567fd2bf17e29fa4a4c8a42bef024ed5030c5fac90d216a62228926fcbee6d95945b36bb'], ['1', '0']],
            [['275c77d2683d4be786ffc592d13cc1598380dff1ea4c43a970566b6c0cc71baa89ed7b974c9fcbe0e6', '8bb9f6ef00d5a29d48266c7948f50f1d4ad6a02848ff466134678bc02ad9aedbb6514fbc5bef7a427'], ['1', '0']]],
        actions: {
            i: [[['aa13b93638dd194fd68b1539d6abf5d9b354d65dc452cb133526024d24f509054322beb5e60469e6d', 325], ['72880b5ef20ea83fdea5ca9028ef5f98c46323737ad5faaee70a53f7c91113c33ec69680df262c1ba', 324]],
                [['6f28bcabec2b4a7959ccb5ba67dfe600d895b73a5d9601a7872106a16d914e980822b261335eac3c7', 324], ['55ec46c9c722e6b02974eac629540a264cab29a23bad34eccad9fdb2db0af6fabcdd414a19fb96193', 324]]],
            j: [[['2a13b93638dd194fd68b1539d6abf5d9b354d65dc452cb133526024d24f509054322beb5e60469e6d', 323], ['63d020c6e13403648bee4dc2f68bf0fc512455097910ac33325a768893a1516f3f18550703c8adda8', 324]],
                [['ef28bcabec2b4a7959ccb5ba67dfe600d895b73a5d9601a7872106a16d914e980822b261335eac3c7', 325], ['d5ec46c9c722e6b02974eac629540a264cab29a23bad34eccad9fdb2db0af6fabcdd414a19fb96193', 325]]],
            k: [[['7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 324], ['2add57fbcfc3325dd08f3cce1d3cc98d0c50cd0df306419e5ba1f5269f4e166230655a8733764c856', 323]],
                [['0', 1], ['800000000000000000000000000000000000000000000000000000000000000000000000000000001', 325]]],
            gen2: [[['aa13b93638dd194fd68b1539d6abf5d9b354d65dc452cb133526024d24f509054322beb5e60469e6d', 325], ['72880b5ef20ea83fdea5ca9028ef5f98c46323737ad5faaee70a53f7c91113c33ec69680df262c1ba', 324]],
                [['6f28bcabec2b4a7959ccb5ba67dfe600d895b73a5d9601a7872106a16d914e980822b261335eac3c7', 324], ['55ec46c9c722e6b02974eac629540a264cab29a23bad34eccad9fdb2db0af6fabcdd414a19fb96193', 324]]],
            gen3: [[['6a13b93638dd194fd68b1539d6abf5d9b354d65dc452cb133526024d24f509054322beb5e60469e6d', 324], ['6b2c1612e9a155d2354a0c298fbda84a8ac3bc3e79f353710cb265402e5932993eef75c3f1776cfb1', 324]],
                [['2f28bcabec2b4a7959ccb5ba67dfe600d895b73a5d9601a7872106a16d914e980822b261335eac3c7', 323], ['95ec46c9c722e6b02974eac629540a264cab29a23bad34eccad9fdb2db0af6fabcdd414a19fb96193', 325]]],
            gen4: [[['400000000000000000000000000000000000000000000000000000000000000000000000000000000', 324], ['956eabfde7e1992ee8479e670e9e64c686286686f98320cf2dd0fa934fa70b311832ad4399bb2642b', 325]],
                [['800000000000000000000000000000000000000000000000000000000000000000000000000000000', 325], ['c00000000000000000000000000000000000000000000000000000000000000000000000000000001', 325]]]
        }
    },
    3: {
        cofactor: ['100000000000000000000000000000000000000000000000000000d9', 222], two_chall: ['1000000000000000000000000000000000000000000000000', 194],
        sec_degree: ['1afffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050f', 890],
        com_degree: ['1afffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050f', 890],
        basis: [[['9fafe5085fcb1f13d5e487f010c8026abe233871b01f4a3587f06737f9bc686ba009922e2d459ec8f149c4c4083604e7842a612b6fdf8180025cdeb187b4c0', 'c42a516ef3cf80d3e2e7a2d88faba1e46785ddce14f150ff4d204a43d47ad8d01940b2eba9aaac28b7198e48ed9281128f5782cdd197f48cddfbffe867063d'], ['1', '0']],
            [['bce91be61859cd3ddcd3f8408657d1d43c6f2764437e66e96371e74bc4b725f0cb99b58b09a91e872afcebb4608219f68aa3572c70ef5e6e654099bfc8aa09', 'a48c9987de3810adbf0813505a561e134f31d64466875f90e21dd7c6b44eb81bed0e58d70ebd39fd9443a7523049993bd75145d72ec8f52be58b7086fffbe8'], ['1', '0']],
            [['2a3165c5061348beca06a8b4316633e6fb8f64fc96a2354b8fa271a9f539a4d336ee88c0e0a5a22de6eb125da3ddc872cc0a91a5277c7aaf98ffc3d75e2d34', 'b27e86c1eff34ce8995a3b707f152e907a662ffec7e5df6ff23b36ef3329fb1ebd12f2b2bf3459806f7905d73a8287e41c04b3936734761950daca2d3b3b4f'], ['1', '0']]],
        actions: {
            i: [[['19df28f2d7c316d855ea0387774de81d709d04122bb6b5af370731324d939a71e8de3d5c3f3dcd5435decd5b34fd7df75c4974c8e9f38892f96a886b93337', 498], ['89c9cf0b50897b57bf5123c0373656bc39bab67872b0b2aa634d9ffe5b079a8fe17de4982bb45ebb9c041d980d025716c40df3b18e4122061e1c20cfd028e', 501]],
                [['7b5cb2bffd3cdad392e812fddb0ad3069068975a3bbad3a9d2d541657a4135bb87a7d28fb0a4bfbe40058ee7e771e81ba39cb86cd2f81d85637b2429e45b1', 500], ['e620d70d283ce927aa15fc7888b217e28f62fbedd4494a50c8f8cecdb26c658e1721c2a3c0c232abca2132a4cb028208a3b68b37160c776d069577946ccc9', 501]]],
            j: [[['58d841e5112e16dc4af3a4d7c67b81519fa83900d2cb575591be3670f9ea080a093925f3722e7f4eb9e8743c15015a6e3ecb4ff68b334eb4fc9a677e020f3', 500], ['d7bb8c542dac47a7a5e15defc65f3a2a762d65d385e06471c59e52c25335f1ef4e7a6720cbbc547bf7d2f7711365830ece5ebf0cf524f2fa66d21e4308e98', 501]],
                [['bdc284c10659797687eb53fb50eda14a4faad640119faecac9c4e481ab32798ac5706e9a9afe2608ebd6959fc4fdf08116ef6c4955b5f49e0ec61e4fe3249', 501], ['a727be1aeed1e923b50c5b2839847eae6057c6ff2d34a8aa6e41c98f0615f7f5f6c6da0c8dd180b146178bc3eafea591c134b00974ccb14b03659881fdf0d', 501]]],
            k: [[['7c99fc05e406e30f333393c9a875303e199a77fb35dce78ce54f366aa60c3c097c98a639555a88d12d51ff1e2e6aee7a297c48cbe10dd75f1d05088dbf3b3', 500], ['7d51f18e1261123d267a05bd0e1f9328058d061690f5458eadce94789abbf730d2e8a347366f84881fcf23d98ccd9bcb84b1a58a88d2ecae77bc01bf3bdde', 500]],
                [['c857345e8202c981b33e5a4bffe0dc552bdfcfd43d1aeff9a30f48b68692dbecd0d9a7fc09a76ae5ea9abf5947f028bb39f39a7aee6dbea02939de36fee54', 501], ['836603fa1bf91cf0cccc6c36578acfc1e6658804ca2318731ab0c99559f3c3f6836759c6aaa5772ed2ae00e1d1951185d683b7341ef228a0e2faf77240c4d', 501]]],
            gen2: [[['19df28f2d7c316d855ea0387774de81d709d04122bb6b5af370731324d939a71e8de3d5c3f3dcd5435decd5b34fd7df75c4974c8e9f38892f96a886b93337', 498], ['89c9cf0b50897b57bf5123c0373656bc39bab67872b0b2aa634d9ffe5b079a8fe17de4982bb45ebb9c041d980d025716c40df3b18e4122061e1c20cfd028e', 501]],
                [['7b5cb2bffd3cdad392e812fddb0ad3069068975a3bbad3a9d2d541657a4135bb87a7d28fb0a4bfbe40058ee7e771e81ba39cb86cd2f81d85637b2429e45b1', 500], ['e620d70d283ce927aa15fc7888b217e28f62fbedd4494a50c8f8cecdb26c658e1721c2a3c0c232abca2132a4cb028208a3b68b37160c776d069577946ccc9', 501]]],
            gen3: [[['b95bb56bf47896da506ed42f9ee4b4b788229e897f4106826462b3d1a3bed13df90bb1a7d8b6265177e3a0cba4ff6c32cd8a625fba936ba3fb0277f4caa15', 501], ['30c2adafbf1ae17fb29940d7fecac87357f40e25fc488b8e1475f960571ec63f97fc25dc7bb8599bc9eb8a849033ed12c936595f41b30a8042771f896c893', 499]],
                [['1c8f9bc081cb2a250d69b37c95fc3a287009b6cd26ad413a4e4d12f392b9d7a3268c209525d172e395ee1243d637ec4e5d46125b14570911b920a13ce3bfd', 498], ['46a44a940b876925af912bd0611b4b4877dd617680bef97d9b9d4c2e5c412ec206f44e582749d9ae881c5f345b0093cd32759da0456c945c04fd880b355eb', 500]]],
            gen4: [[['be4cfe02f20371879999c9e4d43a981f0ccd3bfd9aee73c672a79b3553061e04be4c531caaad446896a8ff8f1735773d14be2465f086ebaf8e828446df9da', 501], ['bea8f8c70930891e933d02de870fc99402c6830b487aa2c756e74a3c4d5dfb98697451a39b37c2440fe791ecc666cde5c258d2c5446976573bde00df9deef', 501]],
                [['e42b9a2f410164c0d99f2d25fff06e2a95efe7ea1e8d77fcd187a45b43496df6686cd3fe04d3b572f54d5faca3f8145d9cf9cd3d7736df50149cef1b7f72a', 501], ['41b301fd0dfc8e786666361b2bc567e0f332c40265118c398d5864caacf9e1fb41b3ace35552bb9769570070e8ca88c2eb41db9a0f791450717d7bb920627', 500]]]
        }
    },
    5: {
        cofactor: ['40000000000000000000000000000000000000000000000000000000000000000000002b', 288], two_chall: ['10000000000000000000000000000000000000000000000000000000000000000', 258],
        sec_degree: ['10ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000051', 1182],
        com_degree: ['10ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000051', 1182],
        basis: [[['b66b93a890673a0d7e33340c53b6b986c1bbb905054419c400e5458a8655c166345abc1e4d70516e0dfcd03f7cbca2a87da6ef003f9301aa1e3a662f2db25e00f57345faa348b8c78d403891c85677b4b8d62ce', '900d04c251411f3be86fc8bc618b7d4caefb2a31c23b1cd9f86fcfb8cb114bf6fe9e19bca9fdd6e150b8fcca7eb7c7b71dceea11abff9da7dbab00e5d6e1dbe6b449796c96b4f2f5a5bf4e3cb04973bc3fdb8c9'], ['1', '0']],
            [['f4f3311a4df85d112f2ec580f3f677f1d80c2105cf9e7dea9f8b06d3b412aa14a0e1d1ae2dbf8b5d8fca950f0d355fa25cd98e4e14d58df00ada18c8453d45702ad7b8188d55a8df97c0dc87782f17e9e99452c', '2b3e8126b1983e58e41e2ed4ef551b7f4617364b1c3f04f072d50e9d77e5ae2ecedf5d924fe21e881a085764064bc175daa0308f13d6a1b760378c23aa4c912fe365ce0d5673b4edf297440304f2c1415d2b502'], ['1', '0']],
            [['b7a63f245737a562b92dffd7dfbb01b2b26578a58c10599d2a038a3c1368d621a7a5a5114c1336c36fae4544fcc60c309f3aa7bd5ba91243c2867d9cc148d149cc30875f7135401845fdf094f0c56fbcaa884df', '8ea5a35b9423ca6607d04834431cb960256b15f473eacd2d1e116c8df428f29de9fbdb889dfbf41b4c8b8c88c5b79e2fa036ef0cc6ace710007ad97ea49709550e421ce5e15173570f007d672b77b1d4f027568'], ['1', '0']]],
        actions: {
            i: [[['5769e03941e3989403b9d6ad109a35c31a5a335d3957ad7bc3ca79ef308fc6eb7efa724a347ad3a37fb4a028cf17188c7a9b180f19d0db447cd0a61bb6007ad70e3931281d58f27b207c4173fe74599f4867ed', 664], ['92695c791320436b2dcc1165406ff9075e1aa388472b861b19eb864f692dc5f5d323747965a4972659f612d6588f31b2bf857b7f9677a33cf50fe64632fa69d33caf9013d86c994909f501a4c2fac05399d40a', 665]],
                [['2667f5883cc14096fbb5a4fd2581e2709f1f2b0c28e3758884e3d634c8fc74e1bb303a7ada0ed30be50ea61c28493978ddd7e3fa9c73b24e1729721541b48dd21c283968883e5013c8c0924846f7e4a6f8cd0f', 663], ['a8961fc6be1c676bfc462952ef65ca3ce5a5cca2c6a852843c358610cf70391481058db5cb852c5c804b5fd730e8e7738564e7f0e62f24bb832f59e449ff8528f1c6ced7e2a70d84df83be8c018ba660b79813', 665]]],
            j: [[['93c871382657204b206306bbd2acafcb324f51262175f22f9875cd29012b34a3b63c06786c739668764b4f8cc838a7903783c39d36a0f28d8b3c122c79dc5d01ca9fd5be993e6722130de6890f1cb99666c609', 665], ['2cac1987de4e397780bd65f989498f7136b9d5c22975cca7156287628645aae1e82e5127d5a7fa4b67e702a508ee0c4de1e148760f6c65989eea2a3e7fec7a204ea01fff66f986fb9d85356aea996a837631d0', 663]],
                [['9fad34c078c72ea2c9fa19b153239957a8daa2a8faa3430eb292e621b44e207ea8eb6ffec368cc8df3e0a219e8107750014f3254edf9167242dac4ed1081345b8c800b73c4413fecb05358824e9160f4554e37', 665], ['6c378ec7d9a8dfb4df9cf9442d535034cdb0aed9de8a0dd0678a32d6fed4cb5c49c3f987938c699789b4b07337c7586fc87c3c62c95f0d7274c3edd38623a2fe35602a4166c198ddecf21976f0e346699939f7', 664]]],
            k: [[['4124d62beb9a5986d38443c2929519e7a7febb8b69552892fcf84d5dcf6d386f815ada476f3bd913c818f8582e2fb784851afcc7eceb0a1d1cbf2d7eae1ad97aeff8cea992c76942620b4c3d375913a4548f7b', 664], ['1e1bf622f832d15c9e07ed13e814821263d5cc603ee26fc59d7fe577b650959910353de86bd4ceb659e1cf36a92d21613bb718931604a02aeb0e6935077f8901ff1c07afa54b1f71b5de1795347fd032929d36', 662]],
                [['bd65c3dd906d0a8a2175fa62ecc4d0552fe74915a740b115b399c6b130c5cc2397627a8abd2d62b28626bd225ba6643f64b4eac643bdf307467f535b69c4d962860d86931ccaf968ae6df1d559498c1d69459c', 665], ['bedb29d41465a6792c7bbc3d6d6ae6185801447496aad76d0307b2a23092c7907ea525b890c426ec37e707a7d1d0487b7ae503381314f5e2e340d28151e52685100731566d3896bd9df4b3c2c8a6ec5bab7085', 665]]],
            gen2: [[['5769e03941e3989403b9d6ad109a35c31a5a335d3957ad7bc3ca79ef308fc6eb7efa724a347ad3a37fb4a028cf17188c7a9b180f19d0db447cd0a61bb6007ad70e3931281d58f27b207c4173fe74599f4867ed', 664], ['92695c791320436b2dcc1165406ff9075e1aa388472b861b19eb864f692dc5f5d323747965a4972659f612d6588f31b2bf857b7f9677a33cf50fe64632fa69d33caf9013d86c994909f501a4c2fac05399d40a', 665]],
                [['2667f5883cc14096fbb5a4fd2581e2709f1f2b0c28e3758884e3d634c8fc74e1bb303a7ada0ed30be50ea61c28493978ddd7e3fa9c73b24e1729721541b48dd21c283968883e5013c8c0924846f7e4a6f8cd0f', 663], ['a8961fc6be1c676bfc462952ef65ca3ce5a5cca2c6a852843c358610cf70391481058db5cb852c5c804b5fd730e8e7738564e7f0e62f24bb832f59e449ff8528f1c6ced7e2a70d84df83be8c018ba660b79813', 665]]],
            gen3: [[['759928b8b41d5c6f920e6eb471a372c72654c241ad66cfd5ae20238c18dd7dc79a9b3c6150773505fafff7dacba7e00e590f6dd62838e6e904065c2417ee6bec6c6c83735b4bacce99c513fe86c8899ad796fb', 664], ['df8abb0078b73e715744bbaf64dcc43c4a6a3ca53850a96117a706d8f7b9b86bdda8e2d09da648b8e0ee8abdb0be9f0050b361fad2f2046ac9fd0842597371f9c5a7d8099fb3102253bd1b87d6ca156b8802ed', 665]],
                [['630a95245ac4379ce2d7df573c52bde423fce6da91c35c4b9bbb5e2b3ea54ab0320dd53ccebbcfccec77a41b082cd8646f938b27c53664602d021b81291ae116d454226e263fc8003c89f5654ac4a2cda70da3', 664], ['8a66d7474be2a3906df1914b8e5c8d38d9ab3dbe5299302a51dfdc73e72282386564c39eaf88cafa0500082534581ff1a6f09229d7c71916fbf9a3dbe811941393937c8ca4b45331663aec0179377665286905', 665]]],
            gen4: [[['20926b15f5cd2cc369c221e1494a8cf3d3ff5dc5b4aa94497e7c26aee7b69c37c0ad6d23b79dec89e40c7c2c1717dbc2428d7e63f675850e8e5f96bf570d6cbd77fc6754c963b4a13105a61e9bac89d22a47be', 663], ['f0dfb117c1968ae4f03f689f40a410931eae6301f7137e2cebff2bbdb284acc881a9ef435ea675b2cf0e79b549690b09ddb8c498b0250157587349a83bfc480ff8e03d7d2a58fb8daef0bca9a3fe819494e9b', 661]],
                [['deb2e1eec836854510bafd317662682a97f3a48ad3a0588ad9cce3589862e611cbb13d455e96b15943135e912dd3321fb25a756321def983a33fa9adb4e26cb14306c3498e657cb45736f8eaaca4c60eb4a2ce', 665], ['df6d94ea0a32d33c963dde1eb6b5730c2c00a23a4b556bb68183d951184963c83f5292dc486213761bf383d3e8e8243dbd72819c098a7af171a06940a8f29342880398ab369c4b5ecefa59e16453762dd5b843', 665]]]
        }
    },
};

var EXTRA = 2;     /* EC_EXTRA_TORSION = HD_EXTRA_TORSION */

function build(level) {
    var L = LEVELS[level];
    var COF = L[1], E2 = L[2], CHALL = L[3], RESP = L[4];
    var p = COF * (1n << BigInt(E2)) - 1n;
    var FPB = (p.toString(2).length + 7) >> 3, FP2B = 2 * FPB;
    var CHB = CHALL / 8, RSB = (RESP + EXTRA + 7) >> 3;
    var PK_BYTES = FP2B + 1, SIG_BYTES = FP2B + 4 * RSB + CHB + 2;
    var G = isogeny_tools(COF, E2, [[BigInt('0x' + L[5]), BigInt('0x' + L[6])], [BigInt('0x' + L[7]), BigInt('0x' + L[8])]]);
    var ZERO = G.ZERO, ONE = G.ONE, mul = G.mul, inv = G.inv, sqr = G.sqr, eq = G.eq, pt = G.pt, INF = G.INF, curve = G.curve, copy_curve = G.copy_curve, verify_A = G.verify_A, fp2_half = G.fp2_half, basis_from_hint = G.basis_from_hint, basis_to_hint = G.basis_to_hint, ladder3pt = G.ladder3pt, isogeny_2chain = G.isogeny_2chain, biscalar_mul_verif = G.biscalar_mul_verif, biscalar_mul = G.biscalar_mul, theta_chain = G.theta_chain, ec_mul = G.ec_mul, dbl_iter_basis = G.dbl_iter_basis, pairing_dlog = G.pairing_dlog;

    /* ---------------- encodings ---------------- */

    function fp2_encode(a) { return concat([bigint_to_bytes_le(a[0], FPB), bigint_to_bytes_le(a[1], FPB)]); }
    /* a non-canonical half decodes to zero, as in the reference */
    function fp_decode(b, off) {
        var v = bytes_to_bigint_le(b.subarray(off, off + FPB));
        return v < p ? v : 0n;
    }
    function fp2_decode(b, off) { return [fp_decode(b, off), fp_decode(b, off + FPB)]; }

    /* ---------------- quaternions to isogenies ---------------- */

    var DL = DATA[level], QP = {
        p: p, ibz_bits: 64 * L[9], security_bits: CHALL, p_bits: (p.toString(2)).length, sqrt_p_bits: L[11],
        sqrt_p: BigInt('0x' + L[12]), equiv_bound: L[10], qlapoty_power: L[13], prime_cofactor: [BigInt('0x' + DL.cofactor[0]), DL.cofactor[1]]
    };
    var Qt = quaternion_tools(QP), NWO = L[14];
    function Zc(c) { return Qt.Z(BigInt.asIntN(64 * Math.ceil(c[1] / 64), BigInt('0x' + c[0])), c[1]); }
    var ACT = {}, k_;
    for (k_ in DL.actions) { ACT[k_] = DL.actions[k_].map(function (r) { return r.map(Zc); }); }
    var SEC_DEGREE = Zc(DL.sec_degree), COM_DEGREE = Zc(DL.com_degree), TWO_CHALL = Zc(DL.two_chall);
    function fp2c(c) { return [BigInt('0x' + c[0]), BigInt('0x' + c[1])]; }
    var BASIS_EVEN = { P: pt(fp2c(DL.basis[0][0]), fp2c(DL.basis[0][1])), Q: pt(fp2c(DL.basis[1][0]), fp2c(DL.basis[1][1])),
        PmQ: pt(fp2c(DL.basis[2][0]), fp2c(DL.basis[2][1])) };
    function curve_E0() { return { A: ZERO, C: ONE, A24: pt(fp2_half([1n, 0n]), ONE), a24: true }; }

    function matrix_application(B, E, M, f, last) {
        var pw = Qt.mul2e(Qt.ONE, f);
        M = M.map(function (r) { return r.map(function (x) { return Qt.mod(x, pw); }); });
        var out = { P: biscalar_mul(M[0][0].v, M[1][0].v, f, B, E), Q: biscalar_mul(M[0][1].v, M[1][1].v, f, B, E), PmQ: B.PmQ };
        if (last) { out.PmQ = biscalar_mul(Qt.mod(Qt.sub(M[0][0], M[0][1]), pw).v, Qt.mod(Qt.sub(M[1][0], M[1][1]), pw).v, f, B, E); }
        return out;
    }
    /* the action of a quaternion of O_0 on a basis of E_0[2^f] */
    function endomorphism_application(B, E, theta, f, last) {
        var two_e = Qt.mul2e(Qt.ONE, f), mp = Qt.make_primitive(theta), co = mp[0].map(function (x) { return Qt.mod(x, two_e); });
        var content = Qt.mod(mp[1], two_e), M = [[Qt.set(0, 0), Qt.set(0, 0)], [Qt.set(0, 0), Qt.set(0, 0)]];
        for (var i = 0; i < 2; ++i) {
            M[i][i] = Qt.add(M[i][i], co[0]);
            for (var j = 0; j < 2; ++j) {
                M[i][j] = Qt.mod(Qt.add(M[i][j], Qt.mul(ACT.gen2[i][j], co[1])), two_e);
                M[i][j] = Qt.mod(Qt.add(M[i][j], Qt.mul(ACT.gen3[i][j], co[2])), two_e);
                M[i][j] = Qt.mod(Qt.add(M[i][j], Qt.mul(ACT.gen4[i][j], co[3])), two_e);
                M[i][j] = Qt.mod(Qt.mul(M[i][j], content), two_e);
            }
        }
        return matrix_application(B, E, M, f, last);
    }
    /* [curve, basis]: the codomain of the isogeny of the ideal and the image of E_0's basis */
    function ideal_to_isogeny(I, dom_default) {
        var q = Qt.qlapoty(I, dom_default);
        if (!q) { throw new Error('sqisign: qlapoty failed'); }
        var two_e = Qt.mul2e(Qt.ONE, E2), d1inv = Qt.invmod(q[1], two_e)[1];
        var bt = endomorphism_application(BASIS_EVEN, curve_E0(), Qt.qscalar(d1inv, q[2]), E2, false);
        var ker = { T1: { P1: bt.P, P2: BASIS_EVEN.P }, T2: { P1: bt.Q, P2: BASIS_EVEN.Q } };
        var bb = endomorphism_application(BASIS_EVEN, curve_E0(), Qt.qscalar(d1inv, q[0]), E2, true);
        var push = [{ P1: bb.P, P2: INF }, { P1: bb.Q, P2: INF }, { P1: bb.PmQ, P2: INF }];
        var out = theta_chain(QP.qlapoty_power, [curve_E0(), curve_E0()], ker, push, 2);
        if (!out) { return null; }
        return [out.E[1], { P: out.P[0].P2, Q: out.P[1].P2, PmQ: out.P[2].P2 }];
    }
    function change_of_basis(B1, B2, E, f) {
        var d = pairing_dlog(B2, B1, E, f), n = 64 * NWO + 1;
        return [[Qt.Z(d[0], n), Qt.Z(d[2], n)], [Qt.Z(d[1], n), Qt.Z(d[3], n)]];
    }
    function invmod_2e(a, e) {
        var x = Qt.ONE, prec = 1;
        while (prec < e) {
            var nx = Math.min(2 * prec, e);
            x = Qt.mod2e(Qt.mul(x, Qt.sub(Qt.TWO, Qt.mul(a, x))), nx);
            prec = nx;
        }
        return Qt.mod2e(x, e);
    }
    function change_of_basis_invert(B1, B2, E, f) {
        var d = pairing_dlog(B1, B2, E, f), n = Math.min(64 * NWO + 1, f + 1);
        var a = Qt.Z(d[0], n), b = Qt.Z(d[1], n), c = Qt.Z(d[2], n), dd = Qt.Z(d[3], n);
        var det = invmod_2e(Qt.sub(Qt.mul(a, dd), Qt.mul(b, c)), f);
        return [[Qt.mod2e(Qt.mul(dd, det), f), Qt.mod2e(Qt.mul(Qt.neg(c), det), f)],
            [Qt.mod2e(Qt.mul(Qt.neg(b), det), f), Qt.mod2e(Qt.mul(a, det), f)]];
    }

    /* ---------------- key generation ---------------- */

    var SK_BYTES = PK_BYTES + 3 * FPB + 4 * CHB;
    function ibz_bytes(x, n) { return bigint_to_bytes_le(x.v, n); }
    /* seed: 48 bytes; omitted or null draws fresh ones from the platform */
    function keygen(seed) {
        if (seed == null) { seed = secure_random(48); }
        if (!(seed instanceof Uint8Array) || seed.length !== 48) { throw new Error('sqisign: keygen takes a 48-byte seed'); }
        var dd = prng_domain(seed, 'def'), dk = prng_domain(seed, 'key'), I, r;
        for (;;) {
            I = Qt.random_ideal_prime_norm(SEC_DEGREE, dk, dd);
            I = Qt.small_equivalent_coprime(I, Qt.ZERO, dk, false)[1];
            if ((r = ideal_to_isogeny(I, dd))) { break; }
        }
        var E = r[0], tb = basis_to_hint(E, CHALL + EXTRA, 0);
        var M = change_of_basis(tb[0], r[1], E, CHALL + EXTRA);
        M = Qt.m2_normalize(M.map(function (row) { return row.map(function (x) { return Qt.mod2e(x, CHALL); }); }), CHALL);
        var pk = pk_bytes(mul(E.A, inv(E.C)), tb[1]);
        var sk = concat([pk, ibz_bytes(I.n, FPB), ibz_bytes(I.x, FPB), ibz_bytes(I.y, FPB),
            ibz_bytes(M[0][0], CHB), ibz_bytes(M[0][1], CHB), ibz_bytes(M[1][0], CHB), ibz_bytes(M[1][1], CHB)]);
        return { pk: pk, sk: sk };
    }

    /* ---------------- signing ---------------- */

    /* [ideal, split]: the 2^f-ideal of the isogeny with kernel [a]P + [b]Q on E_0 (vec = (a, b)) */
    function kernel_dlogs_to_ideal(vec2, f) {
        var two_pow = f === CHALL ? TWO_CHALL : Qt.mul2e(Qt.ONE, f), m = Qt.m2_eval;
        var vj = m(ACT.j, vec2), vg = m(ACT.gen4, vec2);
        var M = [[vec2[0], Qt.mod(Qt.add(vj[0], vg[0]), two_pow)], [vec2[1], Qt.mod(Qt.add(vj[1], vg[1]), two_pow)]];
        var inv = Qt.m2_inv_mod(M, two_pow)[1];
        var vec = m(inv, m(ACT.i, vec2)).map(function (x) { return Qt.mod(x, two_pow); });
        var gen = { d: Qt.set(2, 3), c: [Qt.add(Qt.add(vec[0], vec[0]), vec[1]), Qt.set(-2, 3), Qt.add(vec[1], vec[1]), vec[1]] };
        gen = { d: gen.d, c: gen.c.map(function (x) { return Qt.set_bound(x, f + 10); }) };
        var st = Qt.qmul(gen, Qt.qe(1, 1, 1, 0, 0)), n = Qt.make_primitive(st)[1], split;
        if (!Qt.odd(n)) {
            gen = { d: st.d, c: Qt.v4_div(st.c, n) };
            split = Qt.qe(1, 1, -1, 0, 0);
            two_pow = Qt.mul2e(Qt.ONE, f - 1);
        } else { split = Qt.qe(1, 1, 0, 0, 0); }
        return [Qt.create_O0_pow_two(gen, two_pow), split];
    }
    function ibz_from(b, off, nbytes) { return Qt.Z(bytes_to_bigint_le(b.subarray(off, off + nbytes)), 64 * Math.ceil(nbytes / 8) + 1); }
    function decode_sk(sk) {
        var o = PK_BYTES, I = { n: ibz_from(sk, o, FPB), x: ibz_from(sk, o + FPB, FPB), y: ibz_from(sk, o + 2 * FPB, FPB) };
        o += 3 * FPB;
        var M = [[ibz_from(sk, o, CHB), ibz_from(sk, o + CHB, CHB)], [ibz_from(sk, o + 2 * CHB, CHB), ibz_from(sk, o + 3 * CHB, CHB)]];
        return { pkA: fp2_decode(sk, 0), hint: sk[FP2B], ideal: I, mat: M };
    }
    /* rnd: 48 bytes; omitted or null draws fresh ones from the platform */
    function sign(sk, msg, rnd) {
        if (!(sk instanceof Uint8Array) || sk.length !== SK_BYTES) { throw new Error('sqisign: secret key must be ' + SK_BYTES + ' bytes'); }
        if (rnd == null) { rnd = secure_random(48); }
        if (!(rnd instanceof Uint8Array) || rnd.length !== 48) { throw new Error('sqisign: sign takes 48 random bytes'); }
        var K = decode_sk(sk), R = RESP + EXTRA, dd = prng_domain(rnd, 'def');
        /* the commitment: a random ideal of prime norm and the curve E_com it leads to */
        var dc = prng_domain(rnd, 'com');
        var Icom = Qt.random_ideal_prime_norm(COM_DEGREE, dc, dd);
        Icom = Qt.small_equivalent_coprime(Icom, Qt.TWO, dc, false)[1];
        var cm = ideal_to_isogeny(Icom, dd), Ecom = cm[0], B1 = cm[1];
        var chall = hash_to_challenge(K.pkA, K.hint, Ecom.A, msg);
        /* the challenge ideal, and the response: a small element of I_sk I_chall I_com */
        var vec = Qt.m2_eval(K.mat, [Qt.set(1, 2), Qt.Z(bytes_to_bigint_le(chall), 64 * NWO + 1)]);
        var ch = kernel_dlogs_to_ideal(vec, CHALL), dr = prng_domain(rnd, 'res');
        var re = Qt.response_element(K.ideal, ch[0], ch[1], Icom, dr, dd, RESP - 1);
        var Iskc = re[0], resp_quat = re[1], deg_odd = re[2];
        if (!Qt.is1(Qt.gcd(Iskc.n, Icom.n))) { throw new Error('sqisign: non-coprime response norms'); }
        var remain = Qt.mul2e(Qt.ONE, RESP), aux_norm = Qt.set_bound(Qt.sub(remain, deg_odd), RESP + 1);
        remain = Qt.mul2e(remain, EXTRA);
        /* an auxiliary ideal of the complementary degree, making the response a 2-dimensional isogeny */
        var ax = Qt.random_ideal_odd_norm(aux_norm, re[3], dr), Iaux = ax[0], aux_split = ax[1];
        if (!Qt.is1(Qt.gcd(Iaux.n, Iskc.n)) || !Qt.is1(Qt.gcd(Iaux.n, K.ideal.n))) { throw new Error('sqisign: non-coprime auxiliary norm'); }
        var ia = ideal_to_isogeny(Qt.intersect_O0(Iaux, Iskc, aux_split), dd), Eaux = ia[0], B2 = ia[1];
        var dinv = Qt.invmod(Iskc.n, remain)[1];
        aux_split = { d: aux_split.d, c: [Qt.mod(Qt.mul(aux_split.c[0], dinv), remain), Qt.mod(Qt.mul(aux_split.c[1], dinv), remain),
            Qt.set_bound(aux_split.c[2], remain.n), Qt.set_bound(aux_split.c[3], remain.n)] };
        B2 = endomorphism_application(B2, Eaux, Qt.qmul(aux_split, resp_quat), E2, false);
        B1 = dbl_iter_basis(B1, E2 - R, Ecom);
        B2 = dbl_iter_basis(B2, E2 - R, Eaux);
        /* the (2^n, 2^n)-isogeny from E_com x E_aux, its codomain E_aux2 x E_chall2 */
        dinv = Qt.invmod(deg_odd, remain)[1];
        var Ec = copy_curve(Ecom), Ea = copy_curve(Eaux);
        var ker = { T1: { P1: B1.P, P2: ec_mul(B2.P, dinv.v, R, Ea) }, T2: { P1: B1.Q, P2: ec_mul(B2.Q, dinv.v, R, Ea) } };
        var out = theta_chain(RESP, [Ec, Ea], ker, [{ P1: B1.P, P2: INF }, { P1: B1.Q, P2: INF }, { P1: B1.PmQ, P2: INF }], 0);
        if (!out) { throw new Error('sqisign: the response chain failed'); }
        var Eaux2 = out.E[1], Echall = out.E[0];
        var Baux2 = { P: out.P[0].P2, Q: out.P[1].P2, PmQ: out.P[2].P2 }, Bchall2 = { P: out.P[0].P1, Q: out.P[1].P1, PmQ: out.P[2].P1 };
        Eaux2.A = mul(Eaux2.A, inv(Eaux2.C)); Eaux2.C = ONE;
        /* the canonical bases from hints, and the matrix taking E_chall's to the response's */
        var hc = basis_to_hint(Echall, E2, R), ha = basis_to_hint(Eaux2, E2, R);
        var Minv = change_of_basis_invert(ha[0], Baux2, Eaux2, R);
        Bchall2 = matrix_application(Bchall2, Echall, Minv, R, true);
        var M = Qt.m2_normalize(change_of_basis(Bchall2, hc[0], Echall, R), R);
        return concat([fp2_encode(Eaux2.A), ibz_bytes(M[0][0], RSB), ibz_bytes(M[0][1], RSB), ibz_bytes(M[1][0], RSB),
            ibz_bytes(M[1][1], RSB), chall, new Uint8Array([ha[1], hc[1]])]);
    }

    /* ---------------- encodings and verification ---------------- */

    var MID = 1n << BigInt(RESP + EXTRA - 1), BOUND = MID << 1n;
    function canonical_matrix(m) {
        var normal = false;
        for (var k = 0; k < 4; k++) {
            if (m[k] >= BOUND) { return false; }
            if (normal) { continue; }
            if (m[k] > MID) { return false; }
            normal = m[k] < MID && m[k] !== 0n;
        }
        return true;
    }
    function pk_bytes(A, hint) { return concat([fp2_encode(A), new Uint8Array([hint])]); }
    function hash_to_challenge(pkA, hint, Acom, msg) {
        return shake256(concat([new TextEncoder().encode('SQI'), pk_bytes(pkA, hint), fp2_encode(Acom), msg]), CHB);
    }
    function decode_sig(sig) {
        var o = FP2B, m = [];
        for (var k = 0; k < 4; k++, o += RSB) { m.push(bytes_to_bigint_le(sig.subarray(o, o + RSB))); }
        return {
            A_aux: fp2_decode(sig, 0), mat: m,           /* [00, 01, 10, 11] */
            chall: sig.slice(o, o + CHB), hint_aux: sig[o + CHB], hint_chall: sig[o + CHB + 1]
        };
    }

    function verify(pk, msg, sig) {
        if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) { return false; }
        if (!(sig instanceof Uint8Array) || sig.length !== SIG_BYTES) { return false; }
        var s = decode_sig(sig), A = fp2_decode(pk, 0), hint_pk = pk[FP2B];
        if (!canonical_matrix(s.mat) || !verify_A(A) || !verify_A(s.A_aux)) { return false; }
        /* the challenge isogeny E_pk -> E_chall */
        var Epk = curve(A), f = CHALL + EXTRA;
        var B = basis_from_hint(Epk, f, hint_pk);
        var kernel = ladder3pt(bytes_to_bigint_le(s.chall), 8 * CHB, B.P, B.Q, B.PmQ, Epk);
        if (!kernel) { return false; }
        var Ech = copy_curve(Epk);
        if (!isogeny_2chain(Ech, kernel, f)) { return false; }
        /* the response's kernel: the matrix applied to the canonical basis of E_chall, beside E_aux's */
        var Eaux = curve(s.A_aux), fr = RESP + EXTRA;
        var Bch = basis_from_hint(Ech, fr, s.hint_chall), Baux = basis_from_hint(Eaux, fr, s.hint_aux);
        var P = biscalar_mul_verif(s.mat[0], s.mat[2], fr, Bch, Ech);
        var Q = P && biscalar_mul_verif(s.mat[1], s.mat[3], fr, Bch, Ech);
        if (!Q) { return false; }
        var out = theta_chain(RESP, [Ech, Eaux], { T1: { P1: P, P2: Baux.P }, T2: { P1: Q, P2: Baux.Q } }, [], -1);
        if (!out) { return false; }
        var c = hash_to_challenge(A, hint_pk, out.E[0].A, msg), d = 0;
        for (var k = 0; k < CHB; k++) { d |= c[k] ^ s.chall[k]; }
        return d === 0;
    }

    return {
        NAME: L[0], PK_BYTES: PK_BYTES, SK_BYTES: SK_BYTES, SIG_BYTES: SIG_BYTES, SEED_BYTES: 48,
        keygen: keygen, sign: sign, verify: verify
    };
}

function lazy(level) {
    return lazy_scheme(function () { return build(level); },
        ['NAME', 'PK_BYTES', 'SK_BYTES', 'SIG_BYTES', 'SEED_BYTES'],
        ['keygen', 'sign', 'verify']);
}

export var sqisign_lvl1 = /* @__PURE__ */ lazy(1);
export var sqisign_lvl3 = /* @__PURE__ */ lazy(3);
export var sqisign_lvl5 = /* @__PURE__ */ lazy(5);
