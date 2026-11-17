/**
 * A parameter set that is built on first use
 *
 * Signature schemes with many parameter sets (MQOM's 18, FAEST's 12) export
 * one object per set; building each one up front (tables, key schedules,
 * constants) would make importing the module slow for every caller that uses
 * one set or none. The object returned here builds the set the first time a
 * property or method is reached and forwards to it from then on.
 */

/**
 * @param {function} make     () -> the built parameter set
 * @param {string[]} props    the constants to expose (NAME, PK_BYTES, ...)
 * @param {string[]} methods  the functions to expose (keygen, sign, verify)
 */
export function lazy_scheme(make, props, methods) {
    var s = null, o = {};
    function get() { return s || (s = make()); }
    props.forEach(function (k) { Object.defineProperty(o, k, { get: function () { return get()[k]; }, enumerable: true }); });
    methods.forEach(function (k) { o[k] = function () { var t = get(); return t[k].apply(t, arguments); }; });
    return o;
}
