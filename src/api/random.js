/**
 * Random bytes, in the forms every operation takes:
 *
 *     random_bytes(n, function (err, bytes) {})   on a later turn of the event loop
 *     random_bytes_sync(n)                        the bytes, directly
 *
 * with the arguments of ../random.js, where it is documented.
 */

import * as pure from '../random.js';
import { define } from '../engines/select.js';

var random_bytes_ops = define('random.random_bytes', { sync: pure.random_bytes });

export var random_bytes = random_bytes_ops.async;
export var random_bytes_sync = random_bytes_ops.sync;
