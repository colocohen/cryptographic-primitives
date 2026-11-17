/**
 * Tasks: long computations cut into resumable pieces
 *
 * Its own module, with no imports, so any algorithm file can use it without
 * pulling in anything else.
 */
/**
 * Run a task to the end, synchronously.
 *
 * A task is a long computation cut into resumable pieces:
 *
 *     { step(): true once finished, result(): the output }
 *
 * The synchronous form of a heavy function is finish_task(its_task(...)),
 * and the callback form in api/ runs the same steps a few milliseconds at a
 * time (engines/select.js), so the two share one implementation. Nothing
 * here knows about time or the event loop.
 */
export function finish_task(task) {
    while (!task.step()) { /* each step does a bounded amount of work */ }
    return task.result();
}

/** A task whose result is fn(task's result): the same steps, a different answer. */
export function map_task(task, fn) {
    return {
        step: function () { return task.step(); },
        result: function () { return fn(task.result()); }
    };
}

/** A task already finished, for an input that needs no work (a malformed hash to verify). */
export function done_task(value) {
    return { step: function () { return true; }, result: function () { return value; } };
}

/**
 * Two tasks in a row: `first`, then the task next(first's result) returns -
 * yescrypt's pre-hash pass and the pass it feeds.
 */
export function then_task(first, next) {
    var second = null;
    return {
        step: function () {
            if (!second) {
                if (!first.step()) { return false; }
                second = next(first.result());
                return false;
            }
            return second.step();
        },
        result: function () { return second.result(); }
    };
}

/**
 * make() as a task, again and again until accept(its result) is true; the
 * result is that accepted value. With `limit`, after that many rejected
 * results `failure` is thrown. A second prime that must differ from the
 * first, a partner that must fit (ring_pedersen.js).
 */
export function repeat_task(make, accept, limit, failure) {
    var current = null, tries = 0, value, finished = false;
    return {
        step: function () {
            if (finished) { return true; }
            if (!current) {
                if (limit !== undefined && tries >= limit) { throw new Error(failure); }
                current = make();
            }
            if (!current.step()) { return false; }
            var v = current.result();
            current = null;
            tries++;
            if (accept(v)) { value = v; finished = true; }
            return finished;
        },
        result: function () { return value; }
    };
}
