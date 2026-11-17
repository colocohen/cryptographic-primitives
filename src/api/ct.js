/**
 * Constant-time comparison, in the forms every operation takes:
 *
 *     equal(a, b, function (err, same) {})   on a later turn of the event loop
 *     equal_sync(a, b)                       true or false, directly
 *
 * with the arguments of ../ct.js, where it is documented. Both arguments
 * are bytes: a string is refused, since the bytes it stands for are a guess.
 */

import * as pure from '../ct.js';
import { define } from '../engines/select.js';

var equal_ops = define('ct.equal', { sync: pure.equal, bytes: { 0: 'a', 1: 'b' } });

export var equal = equal_ops.async;
export var equal_sync = equal_ops.sync;
