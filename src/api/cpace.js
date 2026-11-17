/**
 * cpace, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../cpace.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../cpace.js.
 */

import * as pure from '../cpace.js';
import { define, scheme } from '../engines/select.js';

var cpace_suite_ops = define('cpace.cpace_suite', { sync: pure.cpace_suite });
var generator_string_ops = define('cpace.generator_string', { sync: pure.generator_string, text: [2, 3] });
var lexiographically_larger_ops = define('cpace.lexiographically_larger', { sync: pure.lexiographically_larger });
var lv_cat_ops = define('cpace.lv_cat', { sync: pure.lv_cat });
var o_cat_ops = define('cpace.o_cat', { sync: pure.o_cat });
var prepend_len_ops = define('cpace.prepend_len', { sync: pure.prepend_len, text: [0] });
var transcript_ir_ops = define('cpace.transcript_ir', { sync: pure.transcript_ir, text: [1, 3] });
var transcript_oc_ops = define('cpace.transcript_oc', { sync: pure.transcript_oc, text: [1, 3] });

export var CPACE_DECAF448_SHAKE256 = scheme('CPACE_DECAF448_SHAKE256', pure.CPACE_DECAF448_SHAKE256, {
    calculate_generator: { text: [1, 2] },
    isk: { text: [0] }
});
export var CPACE_P256_SHA256 = scheme('CPACE_P256_SHA256', pure.CPACE_P256_SHA256, {
    calculate_generator: { text: [1, 2] },
    isk: { text: [0] }
});
export var CPACE_P384_SHA384 = scheme('CPACE_P384_SHA384', pure.CPACE_P384_SHA384, {
    calculate_generator: { text: [1, 2] },
    isk: { text: [0] }
});
export var CPACE_P521_SHA512 = scheme('CPACE_P521_SHA512', pure.CPACE_P521_SHA512, {
    calculate_generator: { text: [1, 2] },
    isk: { text: [0] }
});
export var CPACE_RISTR255_SHA512 = scheme('CPACE_RISTR255_SHA512', pure.CPACE_RISTR255_SHA512, {
    calculate_generator: { text: [1, 2] },
    isk: { text: [0] }
});
export var CPACE_X25519_SHA512 = scheme('CPACE_X25519_SHA512', pure.CPACE_X25519_SHA512, {
    calculate_generator: { text: [1, 2] },
    isk: { text: [0] }
});
export var CPACE_X448_SHAKE256 = scheme('CPACE_X448_SHAKE256', pure.CPACE_X448_SHAKE256, {
    calculate_generator: { text: [1, 2] },
    isk: { text: [0] }
});
export var G_DECAF448 = scheme('G_DECAF448', pure.G_DECAF448, {
    calculate_generator: { text: [2, 3] }
});
export var G_P256 = scheme('G_P256', pure.G_P256, {
    calculate_generator: { text: [2, 3] }
});
export var G_P384 = scheme('G_P384', pure.G_P384, {
    calculate_generator: { text: [2, 3] }
});
export var G_P521 = scheme('G_P521', pure.G_P521, {
    calculate_generator: { text: [2, 3] }
});
export var G_RISTRETTO255 = scheme('G_RISTRETTO255', pure.G_RISTRETTO255, {
    calculate_generator: { text: [2, 3] }
});
export var G_X25519 = scheme('G_X25519', pure.G_X25519, {
    calculate_generator: { text: [2, 3] }
});
export var G_X448 = scheme('G_X448', pure.G_X448, {
    calculate_generator: { text: [2, 3] }
});
export var H_SHA256 = scheme('H_SHA256', pure.H_SHA256);
export var H_SHA384 = scheme('H_SHA384', pure.H_SHA384);
export var H_SHA512 = scheme('H_SHA512', pure.H_SHA512);
export var H_SHAKE256 = scheme('H_SHAKE256', pure.H_SHAKE256);
export var cpace_suite = cpace_suite_ops.async;
export var cpace_suite_sync = cpace_suite_ops.sync;
export var generator_string = generator_string_ops.async;
export var generator_string_sync = generator_string_ops.sync;
export var lexiographically_larger = lexiographically_larger_ops.async;
export var lexiographically_larger_sync = lexiographically_larger_ops.sync;
export var lv_cat = lv_cat_ops.async;
export var lv_cat_sync = lv_cat_ops.sync;
export var o_cat = o_cat_ops.async;
export var o_cat_sync = o_cat_ops.sync;
export var prepend_len = prepend_len_ops.async;
export var prepend_len_sync = prepend_len_ops.sync;
export var transcript_ir = transcript_ir_ops.async;
export var transcript_ir_sync = transcript_ir_ops.sync;
export var transcript_oc = transcript_oc_ops.async;
export var transcript_oc_sync = transcript_oc_ops.sync;
