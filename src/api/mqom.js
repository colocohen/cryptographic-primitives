/**
 * mqom, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../mqom.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../mqom.js.
 */

import * as pure from '../mqom.js';
import { scheme } from '../engines/select.js';

export var mqom3_cat1_gf16_fast_ct = scheme('mqom3_cat1_gf16_fast_ct', pure.mqom3_cat1_gf16_fast_ct);
export var mqom3_cat1_gf16_fast_ot = scheme('mqom3_cat1_gf16_fast_ot', pure.mqom3_cat1_gf16_fast_ot);
export var mqom3_cat1_gf16_short_ct = scheme('mqom3_cat1_gf16_short_ct', pure.mqom3_cat1_gf16_short_ct);
export var mqom3_cat1_gf16_short_ot = scheme('mqom3_cat1_gf16_short_ot', pure.mqom3_cat1_gf16_short_ot);
export var mqom3_cat1_gf2_shorter_ct = scheme('mqom3_cat1_gf2_shorter_ct', pure.mqom3_cat1_gf2_shorter_ct);
export var mqom3_cat1_gf2_shorter_ot = scheme('mqom3_cat1_gf2_shorter_ot', pure.mqom3_cat1_gf2_shorter_ot);
export var mqom3_cat3_gf16_fast_ct = scheme('mqom3_cat3_gf16_fast_ct', pure.mqom3_cat3_gf16_fast_ct);
export var mqom3_cat3_gf16_fast_ot = scheme('mqom3_cat3_gf16_fast_ot', pure.mqom3_cat3_gf16_fast_ot);
export var mqom3_cat3_gf16_short_ct = scheme('mqom3_cat3_gf16_short_ct', pure.mqom3_cat3_gf16_short_ct);
export var mqom3_cat3_gf16_short_ot = scheme('mqom3_cat3_gf16_short_ot', pure.mqom3_cat3_gf16_short_ot);
export var mqom3_cat3_gf2_shorter_ct = scheme('mqom3_cat3_gf2_shorter_ct', pure.mqom3_cat3_gf2_shorter_ct);
export var mqom3_cat3_gf2_shorter_ot = scheme('mqom3_cat3_gf2_shorter_ot', pure.mqom3_cat3_gf2_shorter_ot);
export var mqom3_cat5_gf16_fast_ct = scheme('mqom3_cat5_gf16_fast_ct', pure.mqom3_cat5_gf16_fast_ct);
export var mqom3_cat5_gf16_fast_ot = scheme('mqom3_cat5_gf16_fast_ot', pure.mqom3_cat5_gf16_fast_ot);
export var mqom3_cat5_gf16_short_ct = scheme('mqom3_cat5_gf16_short_ct', pure.mqom3_cat5_gf16_short_ct);
export var mqom3_cat5_gf16_short_ot = scheme('mqom3_cat5_gf16_short_ot', pure.mqom3_cat5_gf16_short_ot);
export var mqom3_cat5_gf2_shorter_ct = scheme('mqom3_cat5_gf2_shorter_ct', pure.mqom3_cat5_gf2_shorter_ct);
export var mqom3_cat5_gf2_shorter_ot = scheme('mqom3_cat5_gf2_shorter_ot', pure.mqom3_cat5_gf2_shorter_ot);
