/**
 * faest, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../faest.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../faest.js.
 */

import * as pure from '../faest.js';
import { scheme } from '../engines/select.js';

export var faest_128f = scheme('faest_128f', pure.faest_128f);
export var faest_128s = scheme('faest_128s', pure.faest_128s);
export var faest_192f = scheme('faest_192f', pure.faest_192f);
export var faest_192s = scheme('faest_192s', pure.faest_192s);
export var faest_256f = scheme('faest_256f', pure.faest_256f);
export var faest_256s = scheme('faest_256s', pure.faest_256s);
export var faest_em_128f = scheme('faest_em_128f', pure.faest_em_128f);
export var faest_em_128s = scheme('faest_em_128s', pure.faest_em_128s);
export var faest_em_192f = scheme('faest_em_192f', pure.faest_em_192f);
export var faest_em_192s = scheme('faest_em_192s', pure.faest_em_192s);
export var faest_em_256f = scheme('faest_em_256f', pure.faest_em_256f);
export var faest_em_256s = scheme('faest_em_256s', pure.faest_em_256s);
