/**
 * xmss, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../xmss.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../xmss.js.
 */

import * as pure from '../xmss.js';
import { define, scheme } from '../engines/select.js';

var xmss_ops = define('xmss.xmss', { sync: pure.xmss });
var xmssmt_ops = define('xmss.xmssmt', { sync: pure.xmssmt });

export var xmss = xmss_ops.async;
export var xmss_sync = xmss_ops.sync;
export var xmss_sha2_10_192 = scheme('xmss_sha2_10_192', pure.xmss_sha2_10_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_sha2_10_256 = scheme('xmss_sha2_10_256', pure.xmss_sha2_10_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_sha2_10_512 = scheme('xmss_sha2_10_512', pure.xmss_sha2_10_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_sha2_16_192 = scheme('xmss_sha2_16_192', pure.xmss_sha2_16_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_sha2_16_256 = scheme('xmss_sha2_16_256', pure.xmss_sha2_16_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_sha2_16_512 = scheme('xmss_sha2_16_512', pure.xmss_sha2_16_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_sha2_20_192 = scheme('xmss_sha2_20_192', pure.xmss_sha2_20_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_sha2_20_256 = scheme('xmss_sha2_20_256', pure.xmss_sha2_20_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_sha2_20_512 = scheme('xmss_sha2_20_512', pure.xmss_sha2_20_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake256_10_192 = scheme('xmss_shake256_10_192', pure.xmss_shake256_10_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake256_10_256 = scheme('xmss_shake256_10_256', pure.xmss_shake256_10_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake256_16_192 = scheme('xmss_shake256_16_192', pure.xmss_shake256_16_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake256_16_256 = scheme('xmss_shake256_16_256', pure.xmss_shake256_16_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake256_20_192 = scheme('xmss_shake256_20_192', pure.xmss_shake256_20_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake256_20_256 = scheme('xmss_shake256_20_256', pure.xmss_shake256_20_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake_10_256 = scheme('xmss_shake_10_256', pure.xmss_shake_10_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake_10_512 = scheme('xmss_shake_10_512', pure.xmss_shake_10_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake_16_256 = scheme('xmss_shake_16_256', pure.xmss_shake_16_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake_16_512 = scheme('xmss_shake_16_512', pure.xmss_shake_16_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake_20_256 = scheme('xmss_shake_20_256', pure.xmss_shake_20_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmss_shake_20_512 = scheme('xmss_shake_20_512', pure.xmss_shake_20_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt = xmssmt_ops.async;
export var xmssmt_sync = xmssmt_ops.sync;
export var xmssmt_sha2_20_2_192 = scheme('xmssmt_sha2_20_2_192', pure.xmssmt_sha2_20_2_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_20_2_256 = scheme('xmssmt_sha2_20_2_256', pure.xmssmt_sha2_20_2_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_20_2_512 = scheme('xmssmt_sha2_20_2_512', pure.xmssmt_sha2_20_2_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_20_4_192 = scheme('xmssmt_sha2_20_4_192', pure.xmssmt_sha2_20_4_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_20_4_256 = scheme('xmssmt_sha2_20_4_256', pure.xmssmt_sha2_20_4_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_20_4_512 = scheme('xmssmt_sha2_20_4_512', pure.xmssmt_sha2_20_4_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_40_2_192 = scheme('xmssmt_sha2_40_2_192', pure.xmssmt_sha2_40_2_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_40_2_256 = scheme('xmssmt_sha2_40_2_256', pure.xmssmt_sha2_40_2_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_40_2_512 = scheme('xmssmt_sha2_40_2_512', pure.xmssmt_sha2_40_2_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_40_4_192 = scheme('xmssmt_sha2_40_4_192', pure.xmssmt_sha2_40_4_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_40_4_256 = scheme('xmssmt_sha2_40_4_256', pure.xmssmt_sha2_40_4_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_40_4_512 = scheme('xmssmt_sha2_40_4_512', pure.xmssmt_sha2_40_4_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_40_8_192 = scheme('xmssmt_sha2_40_8_192', pure.xmssmt_sha2_40_8_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_40_8_256 = scheme('xmssmt_sha2_40_8_256', pure.xmssmt_sha2_40_8_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_40_8_512 = scheme('xmssmt_sha2_40_8_512', pure.xmssmt_sha2_40_8_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_60_12_192 = scheme('xmssmt_sha2_60_12_192', pure.xmssmt_sha2_60_12_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_60_12_256 = scheme('xmssmt_sha2_60_12_256', pure.xmssmt_sha2_60_12_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_60_12_512 = scheme('xmssmt_sha2_60_12_512', pure.xmssmt_sha2_60_12_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_60_3_192 = scheme('xmssmt_sha2_60_3_192', pure.xmssmt_sha2_60_3_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_60_3_256 = scheme('xmssmt_sha2_60_3_256', pure.xmssmt_sha2_60_3_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_60_3_512 = scheme('xmssmt_sha2_60_3_512', pure.xmssmt_sha2_60_3_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_60_6_192 = scheme('xmssmt_sha2_60_6_192', pure.xmssmt_sha2_60_6_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_60_6_256 = scheme('xmssmt_sha2_60_6_256', pure.xmssmt_sha2_60_6_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_sha2_60_6_512 = scheme('xmssmt_sha2_60_6_512', pure.xmssmt_sha2_60_6_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_20_2_192 = scheme('xmssmt_shake256_20_2_192', pure.xmssmt_shake256_20_2_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_20_2_256 = scheme('xmssmt_shake256_20_2_256', pure.xmssmt_shake256_20_2_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_20_4_192 = scheme('xmssmt_shake256_20_4_192', pure.xmssmt_shake256_20_4_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_20_4_256 = scheme('xmssmt_shake256_20_4_256', pure.xmssmt_shake256_20_4_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_40_2_192 = scheme('xmssmt_shake256_40_2_192', pure.xmssmt_shake256_40_2_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_40_2_256 = scheme('xmssmt_shake256_40_2_256', pure.xmssmt_shake256_40_2_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_40_4_192 = scheme('xmssmt_shake256_40_4_192', pure.xmssmt_shake256_40_4_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_40_4_256 = scheme('xmssmt_shake256_40_4_256', pure.xmssmt_shake256_40_4_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_40_8_192 = scheme('xmssmt_shake256_40_8_192', pure.xmssmt_shake256_40_8_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_40_8_256 = scheme('xmssmt_shake256_40_8_256', pure.xmssmt_shake256_40_8_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_60_12_192 = scheme('xmssmt_shake256_60_12_192', pure.xmssmt_shake256_60_12_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_60_12_256 = scheme('xmssmt_shake256_60_12_256', pure.xmssmt_shake256_60_12_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_60_3_192 = scheme('xmssmt_shake256_60_3_192', pure.xmssmt_shake256_60_3_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_60_3_256 = scheme('xmssmt_shake256_60_3_256', pure.xmssmt_shake256_60_3_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_60_6_192 = scheme('xmssmt_shake256_60_6_192', pure.xmssmt_shake256_60_6_192, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake256_60_6_256 = scheme('xmssmt_shake256_60_6_256', pure.xmssmt_shake256_60_6_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_20_2_256 = scheme('xmssmt_shake_20_2_256', pure.xmssmt_shake_20_2_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_20_2_512 = scheme('xmssmt_shake_20_2_512', pure.xmssmt_shake_20_2_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_20_4_256 = scheme('xmssmt_shake_20_4_256', pure.xmssmt_shake_20_4_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_20_4_512 = scheme('xmssmt_shake_20_4_512', pure.xmssmt_shake_20_4_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_40_2_256 = scheme('xmssmt_shake_40_2_256', pure.xmssmt_shake_40_2_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_40_2_512 = scheme('xmssmt_shake_40_2_512', pure.xmssmt_shake_40_2_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_40_4_256 = scheme('xmssmt_shake_40_4_256', pure.xmssmt_shake_40_4_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_40_4_512 = scheme('xmssmt_shake_40_4_512', pure.xmssmt_shake_40_4_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_40_8_256 = scheme('xmssmt_shake_40_8_256', pure.xmssmt_shake_40_8_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_40_8_512 = scheme('xmssmt_shake_40_8_512', pure.xmssmt_shake_40_8_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_60_12_256 = scheme('xmssmt_shake_60_12_256', pure.xmssmt_shake_60_12_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_60_12_512 = scheme('xmssmt_shake_60_12_512', pure.xmssmt_shake_60_12_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_60_3_256 = scheme('xmssmt_shake_60_3_256', pure.xmssmt_shake_60_3_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_60_3_512 = scheme('xmssmt_shake_60_3_512', pure.xmssmt_shake_60_3_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_60_6_256 = scheme('xmssmt_shake_60_6_256', pure.xmssmt_shake_60_6_256, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
export var xmssmt_shake_60_6_512 = scheme('xmssmt_shake_60_6_512', pure.xmssmt_shake_60_6_512, {
    keygen_derand: { bytes: { 0: 'seed' } },
    sign: { text: [1], bytes: { 0: 'sk' } },
    verify: { text: [1], bytes: { 0: 'pk', 2: 'sig' } },
    vrf_eval: { bytes: { 0: 'sk' } },
    vrf_verify: { bytes: { 0: 'pk' } }
});
