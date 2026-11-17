/**
 * pomfrit, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../pomfrit.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../pomfrit.js.
 */

import * as pure from '../pomfrit.js';
import { scheme } from '../engines/select.js';

export var pomfrit_128f = scheme('pomfrit_128f', pure.pomfrit_128f);
export var pomfrit_128s = scheme('pomfrit_128s', pure.pomfrit_128s);
export var pomfrit_192f = scheme('pomfrit_192f', pure.pomfrit_192f);
export var pomfrit_192s = scheme('pomfrit_192s', pure.pomfrit_192s);
export var pomfrit_256f = scheme('pomfrit_256f', pure.pomfrit_256f);
export var pomfrit_256s = scheme('pomfrit_256s', pure.pomfrit_256s);
export var pomfrit_shake_128f = scheme('pomfrit_shake_128f', pure.pomfrit_shake_128f);
export var pomfrit_shake_128s = scheme('pomfrit_shake_128s', pure.pomfrit_shake_128s);
export var pomfrit_shake_192f = scheme('pomfrit_shake_192f', pure.pomfrit_shake_192f);
export var pomfrit_shake_192s = scheme('pomfrit_shake_192s', pure.pomfrit_shake_192s);
export var pomfrit_shake_256f = scheme('pomfrit_shake_256f', pure.pomfrit_shake_256f);
export var pomfrit_shake_256s = scheme('pomfrit_shake_256s', pure.pomfrit_shake_256s);
export var pomfrit_shake_d16_128f = scheme('pomfrit_shake_d16_128f', pure.pomfrit_shake_d16_128f);
export var pomfrit_shake_d16_128s = scheme('pomfrit_shake_d16_128s', pure.pomfrit_shake_d16_128s);
export var pomfrit_shake_d16_192f = scheme('pomfrit_shake_d16_192f', pure.pomfrit_shake_d16_192f);
export var pomfrit_shake_d16_192s = scheme('pomfrit_shake_d16_192s', pure.pomfrit_shake_d16_192s);
export var pomfrit_shake_d16_256f = scheme('pomfrit_shake_d16_256f', pure.pomfrit_shake_d16_256f);
export var pomfrit_shake_d16_256s = scheme('pomfrit_shake_d16_256s', pure.pomfrit_shake_d16_256s);
