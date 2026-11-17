/**
 * merlin, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../merlin.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../merlin.js.
 */

import * as pure from '../merlin.js';
import { define } from '../engines/select.js';

/*
 * Both are constructors: define() calls its function without `new`, which
 * left `this` null and threw - so each form constructs one.
 */
var Strobe128_ops = define('Strobe128', { sync: function (label) { return new pure.Strobe128(label); }, text: [0] });
var Transcript_ops = define('Transcript', { sync: function (label) { return new pure.Transcript(label); }, text: [0] });

export var Strobe128 = Strobe128_ops.async;
export var Strobe128_sync = Strobe128_ops.sync;
export var Transcript = Transcript_ops.async;
export var Transcript_sync = Transcript_ops.sync;
