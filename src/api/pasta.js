/**
 * pasta, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../pasta.js, where the operations are documented.
 * A parameter set (an object of operations) has both forms of each of its
 * operations: <set>.keygen(..., cb) and <set>.keygen_sync(...).
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../pasta.js.
 */

import * as pure from '../pasta.js';
import { scheme } from '../engines/select.js';

export var PALLAS = pure.PALLAS;
export var PALLAS_GROUP = pure.PALLAS_GROUP;
export var VESTA = pure.VESTA;
export var VESTA_GROUP = pure.VESTA_GROUP;
export var pallas = scheme('pallas', pure.pallas, {
    keygen: { bytes: { 0: 'seed' } }
});
export var vesta = scheme('vesta', pure.vesta, {
    keygen: { bytes: { 0: 'seed' } }
});
