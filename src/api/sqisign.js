/**
 * sqisign, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../sqisign.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../sqisign.js.
 */

import * as pure from '../sqisign.js';
import { scheme } from '../engines/select.js';

export var sqisign_lvl1 = scheme('sqisign_lvl1', pure.sqisign_lvl1);
export var sqisign_lvl3 = scheme('sqisign_lvl3', pure.sqisign_lvl3);
export var sqisign_lvl5 = scheme('sqisign_lvl5', pure.sqisign_lvl5);
