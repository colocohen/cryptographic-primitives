/**
 * ring, in the forms every operation takes:
 *
 *     <name>(..., function (err, result) {})   on a later turn of the event loop
 *     <name>_sync(...)                          the result, directly
 *
 * with the arguments of ../ring.js, where the operations are documented.
 * Bytes are Uint8Array. A message, password, salt, label or context (each
 * operation's `text` below) may also be a string, taken as its UTF-8 - see
 * engines/select.js. It runs the pure JavaScript
 * in ../ring.js.
 */

import * as pure from '../ring.js';
import { define } from '../engines/select.js';

var key_image_ops = define('ring.key_image', { sync: pure.key_image, bytes: { 1: 'public_key' } });
var linked_ops = define('ring.linked', { sync: pure.linked });
var sign_ops = define('ring.sign', { sync: pure.sign, text: [0] });
var sign_linkable_ops = define('ring.sign_linkable', { sync: pure.sign_linkable, text: [0] });
var signature_size_ops = define('ring.signature_size', { sync: pure.signature_size });
var verify_ops = define('ring.verify', { sync: pure.verify, text: [0], bytes: { 1: 'sig' } });
var verify_linkable_ops = define('ring.verify_linkable', { sync: pure.verify_linkable, text: [0], bytes: { 1: 'sig' } });

export var key_image = key_image_ops.async;
export var key_image_sync = key_image_ops.sync;
export var linked = linked_ops.async;
export var linked_sync = linked_ops.sync;
export var sign = sign_ops.async;
export var sign_sync = sign_ops.sync;
export var sign_linkable = sign_linkable_ops.async;
export var sign_linkable_sync = sign_linkable_ops.sync;
export var signature_size = signature_size_ops.async;
export var signature_size_sync = signature_size_ops.sync;
export var verify = verify_ops.async;
export var verify_sync = verify_ops.sync;
export var verify_linkable = verify_linkable_ops.async;
export var verify_linkable_sync = verify_linkable_ops.sync;
