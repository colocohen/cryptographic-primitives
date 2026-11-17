/**
 * ring_aes, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ring_aes.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ring_aes.js.
 */

import * as pure from '../ring_aes.js';
import { scheme } from '../engines/select.js';

export var lrs_aes_128f = scheme('lrs_aes_128f', pure.lrs_aes_128f);
export var lrs_aes_128s = scheme('lrs_aes_128s', pure.lrs_aes_128s);
export var lrs_aes_192f = scheme('lrs_aes_192f', pure.lrs_aes_192f);
export var lrs_aes_192s = scheme('lrs_aes_192s', pure.lrs_aes_192s);
export var lrs_aes_256f = scheme('lrs_aes_256f', pure.lrs_aes_256f);
export var lrs_aes_256s = scheme('lrs_aes_256s', pure.lrs_aes_256s);
export var ring_aes_128f = scheme('ring_aes_128f', pure.ring_aes_128f);
export var ring_aes_128s = scheme('ring_aes_128s', pure.ring_aes_128s);
export var ring_aes_192f = scheme('ring_aes_192f', pure.ring_aes_192f);
export var ring_aes_192s = scheme('ring_aes_192s', pure.ring_aes_192s);
export var ring_aes_256f = scheme('ring_aes_256f', pure.ring_aes_256f);
export var ring_aes_256s = scheme('ring_aes_256s', pure.ring_aes_256s);
