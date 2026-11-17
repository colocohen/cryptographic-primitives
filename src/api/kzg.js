/**
 * kzg, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../kzg.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../kzg.js.
 */

import * as pure from '../kzg.js';
import { define } from '../engines/select.js';

var commit_ops = define('kzg.commit', { sync: pure.commit });
var evaluate_ops = define('kzg.evaluate', { sync: pure.evaluate });
var interpolate_ops = define('kzg.interpolate', { sync: pure.interpolate });
var load_setup_ops = define('kzg.load_setup', { sync: pure.load_setup });
var open_ops = define('kzg.open', { sync: pure.open });
var scalar_bytes_ops = define('kzg.scalar_bytes', { sync: pure.scalar_bytes });
var scalar_from_bytes_ops = define('kzg.scalar_from_bytes', { sync: pure.scalar_from_bytes });
var setup_ops = define('kzg.setup', { sync: pure.setup });
var verify_ops = define('kzg.verify', { sync: pure.verify });

export var commit = commit_ops.async;
export var commit_sync = commit_ops.sync;
export var evaluate = evaluate_ops.async;
export var evaluate_sync = evaluate_ops.sync;
export var interpolate = interpolate_ops.async;
export var interpolate_sync = interpolate_ops.sync;
export var load_setup = load_setup_ops.async;
export var load_setup_sync = load_setup_ops.sync;
export var open = open_ops.async;
export var open_sync = open_ops.sync;
export var scalar_bytes = scalar_bytes_ops.async;
export var scalar_bytes_sync = scalar_bytes_ops.sync;
export var scalar_from_bytes = scalar_from_bytes_ops.async;
export var scalar_from_bytes_sync = scalar_from_bytes_ops.sync;
export var setup = setup_ops.async;
export var setup_sync = setup_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
