/**
 * sdith, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../sdith.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../sdith.js.
 */

import * as pure from '../sdith.js';
import { scheme } from '../engines/select.js';

export var sdith_cat1_fast = scheme('sdith_cat1_fast', pure.sdith_cat1_fast);
export var sdith_cat1_fast_cipherpow = scheme('sdith_cat1_fast_cipherpow', pure.sdith_cat1_fast_cipherpow);
export var sdith_cat1_short = scheme('sdith_cat1_short', pure.sdith_cat1_short);
export var sdith_cat1_short_cipherpow = scheme('sdith_cat1_short_cipherpow', pure.sdith_cat1_short_cipherpow);
export var sdith_cat3_fast = scheme('sdith_cat3_fast', pure.sdith_cat3_fast);
export var sdith_cat3_fast_cipherpow = scheme('sdith_cat3_fast_cipherpow', pure.sdith_cat3_fast_cipherpow);
export var sdith_cat3_short = scheme('sdith_cat3_short', pure.sdith_cat3_short);
export var sdith_cat3_short_cipherpow = scheme('sdith_cat3_short_cipherpow', pure.sdith_cat3_short_cipherpow);
export var sdith_cat5_fast = scheme('sdith_cat5_fast', pure.sdith_cat5_fast);
export var sdith_cat5_fast_cipherpow = scheme('sdith_cat5_fast_cipherpow', pure.sdith_cat5_fast_cipherpow);
export var sdith_cat5_short = scheme('sdith_cat5_short', pure.sdith_cat5_short);
export var sdith_cat5_short_cipherpow = scheme('sdith_cat5_short_cipherpow', pure.sdith_cat5_short_cipherpow);
