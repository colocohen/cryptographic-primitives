/**
 * Merkle-Damgard framing
 *
 * Extracted after sha256, sha512, sha1 and md5 were each written in full,
 * and this block turned out to repeat in all four almost verbatim.
 *
 * Shared: block splitting, padding, length encoding, output writing.
 * Not shared: the compression function itself. It stays in each algorithm's
 * own file, and the four have no code in common there.
 *
 * Padding is exactly where bugs live (the edge cases around 55/56/63/64),
 * so one well-tested implementation beats four.
 */

/**
 * @param {object} p
 *   p.compress       function(H, buf, off, W) - compresses one block into H
 *   p.iv             Int32Array - initial hash values
 *   p.w_size         size of the working array W
 *   p.block_size     64 or 128
 *   p.len_field      length field size in bytes: 8 (SHA-1/256, MD5) or 16 (SHA-512)
 *   p.digest_size    output length in bytes
 *   p.little_endian  true for MD5 only
 * @param {Uint8Array} msg
 * @return {Uint8Array}
 */
export function md_hash(p, msg, state, prior) {
    /*
     * ⭐ `state` AND `prior` LET A CALLER RESUME. Passing a chaining state and
     *   the number of bytes already absorbed into it makes this finish a hash
     *   that someone else started - which is what HMAC needs, since its two
     *   pad blocks depend only on the key and can be compressed once.
     *
     * ⚠ prior MUST BE A WHOLE NUMBER OF BLOCKS. The padding and the length
     *   field are computed here on the assumption that `state` sits on a
     *   block boundary; a partial one would need the leftover bytes too, and
     *   nothing in this function could detect that they were missing.
     *
     * ⛔ AND prior GOES INTO THE LENGTH FIELD. Omitting it produces a digest
     *   that is stable, well distributed, and not the hash of the whole
     *   input - the failure every length-extension bug looks like.
     */
    var block_size = p.block_size;
    var len = msg.length;
    var before = prior || 0;
    var i;

    /*
     * ⭐ THE SCRATCH ARRAYS ARE CACHED ON THE PARAMETER OBJECT, not allocated
     *   per call. The message schedule is 64 or 80 words and the chaining
     *   state is 8; allocating both on every hash showed up as soon as
     *   anything hashed in a loop - pbkdf2 at 100k iterations does 200,000
     *   calls, and the allocations cost more than the compression.
     *
     *   Measured there: 284 ms with the allocations, 164 without.
     *
     * ⛔ THIS MAKES md_hash NON-REENTRANT. Two hashes cannot be in progress
     *   at once over the same parameter object. JavaScript is single
     *   threaded and this function contains no await and no callback, so
     *   nothing can interleave - but a future change that yielded in the
     *   middle would corrupt the other hash silently, and that is the one
     *   thing to keep in mind here.
     *
     * ⚠ NESTED CALLS ARE FINE because they do not overlap: hmac_fast calls
     *   md_hash(md_hash(...)), and the inner one has returned before the
     *   outer touches the buffers.
     */
    /*
     * ⚠ `p` IS A PLAIN PARAMS OBJECT built once per hash, and these two slots
     *   are added on its first use. That is a hidden-class transition, but it
     *   happens ONCE per hash function for the life of the process - unlike
     *   the field objects, where the same pattern cost 2x because the
     *   transition invalidated call sites reached millions of times.
     */
    var H = p._H || (p._H = new Int32Array(p.iv.length));
    /*
     * ⛔ Int32Array, AND Uint32Array WAS TRIED AND REVERTED.
     *
     *   Every operation in these schedules is unsigned, and an isolated
     *   benchmark of SHA-1's expansion showed 325 ns for Int32Array against
     *   220 for Uint32Array. It looked obvious.
     *
     *   ⚠ IN CONTEXT IT WAS A REGRESSION, and a large one: sha256 fell from
     *     0.93x of noble to 0.64, hmac from 0.93 to 0.67, pbkdf2 from 0.98 to
     *     0.72. Consistent across three runs.
     *
     *   ⭐ THE COMPRESSION FUNCTIONS HOLD THEIR STATE IN int32 LOCALS and
     *     write back with `| 0`. Reading an unsigned word into that chain
     *     forces a conversion at every use, and there are far more uses than
     *     there are schedule writes - so the 105 ns saved per block was paid
     *     back several times over inside the rounds.
     *
     *   sha512 alone preferred the unsigned form. It was not worth splitting
     *   the two for, and a per-hash choice here is a knob nobody would keep
     *   correct.
     *
     * OLD NOTE, kept for the reasoning it records:
     * ⭐ Uint32Array FOR THE MESSAGE SCHEDULE, not Int32Array.
     *
     *   Every operation in these schedules is unsigned - shifts, rotations,
     *   xors - and an Int32Array forces a sign fixup that Uint32Array does
     *   not. Measured on SHA-1's expansion: 325 ns against 220.
     *
     * ⚠ THE COMPRESSION FUNCTIONS MUST NOT DEPEND ON THE SIGN. They write
     *   back with `| 0`, which stores the same bits either way, and read with
     *   `>>>` or bit operations that ignore it. A compression function that
     *   compared a schedule word against a negative constant would change
     *   behaviour here - none does, and the vectors would catch it.
     */
    var W = p._W || (p._W = new Int32Array(p.w_size));
    var src = state || p.iv;
    for (i = 0; i < H.length; i++) { H[i] = src[i]; }

    /* Full blocks are read straight from the input, with no copy of the whole message */
    /*
     * ⭐ THE COMPRESSION FUNCTION IS HOISTED. `p.compress` inside the loop is
     *   a property lookup per block - 16,384 of them for a megabyte, on an
     *   object V8 has no reason to keep specialised.
     */
    var compress = p.compress;
    var full = (len / block_size) | 0;
    var boff = 0;
    for (i = 0; i < full; i++) { compress(H, msg, boff, W); boff += block_size; }

    /*
     * Tail + padding: 0x80, zeros, then the message length in bits.
     * If there is no room left for the length field, an extra block is needed.
     */
    var tail_off = full * block_size;
    var rem = len - tail_off;
    var tail_len = rem < block_size - p.len_field ? block_size : block_size * 2;
    /*
     * ⭐ THE TAIL BUFFER IS CACHED TOO, for a reason specific to V8: a typed
     *   array over 64 bytes is not allocated on the JS heap but gets its own
     *   backing store, which costs microseconds. Every SHA-512 tail (128 or
     *   256 bytes) and every two-block SHA-256 tail (a message of 56 to 63
     *   bytes mod 64) paid that. Measured: sha256 of 60 bytes 2.8 us before,
     *   0.8 after; SHA-512 compression 3.2 us before, 1.8 after.
     *   It is all zero between calls: the bytes used are wiped below.
     */
    var tail = p._T || (p._T = new Uint8Array(block_size * 2));
    for (i = 0; i < rem; i++) { tail[i] = msg[tail_off + i]; }
    tail[rem] = 0x80;

    /*
     * len*8 can exceed 2^32, so it is split into hi/lo by hand.
     * In SHA-512 the length field is 16 bytes, but the top 8 are always zero
     * at realistic sizes, so the write is identical in both cases.
     */
    var total = before + len;
    var bit_hi = Math.floor(total / 0x20000000) >>> 0;
    var bit_lo = (total << 3) >>> 0;
    var q = tail_len - 8;

    if (p.little_endian) {
        tail[q]     = bit_lo & 0xff;          tail[q + 1] = (bit_lo >>> 8)  & 0xff;
        tail[q + 2] = (bit_lo >>> 16) & 0xff; tail[q + 3] = (bit_lo >>> 24) & 0xff;
        tail[q + 4] = bit_hi & 0xff;          tail[q + 5] = (bit_hi >>> 8)  & 0xff;
        tail[q + 6] = (bit_hi >>> 16) & 0xff; tail[q + 7] = (bit_hi >>> 24) & 0xff;
    } else {
        tail[q]     = (bit_hi >>> 24) & 0xff; tail[q + 1] = (bit_hi >>> 16) & 0xff;
        tail[q + 2] = (bit_hi >>> 8)  & 0xff; tail[q + 3] = bit_hi & 0xff;
        tail[q + 4] = (bit_lo >>> 24) & 0xff; tail[q + 5] = (bit_lo >>> 16) & 0xff;
        tail[q + 6] = (bit_lo >>> 8)  & 0xff; tail[q + 7] = bit_lo & 0xff;
    }

    for (i = 0; i < tail_len; i += block_size) { compress(H, tail, i, W); }

    /* Output: the H words in the algorithm's byte order */
    var words = p.digest_size >>> 2;
    var out = new Uint8Array(p.digest_size);
    if (p.little_endian) {
        for (i = 0; i < words; i++) {
            out[i * 4]     = H[i] & 0xff;
            out[i * 4 + 1] = (H[i] >>> 8)  & 0xff;
            out[i * 4 + 2] = (H[i] >>> 16) & 0xff;
            out[i * 4 + 3] = (H[i] >>> 24) & 0xff;
        }
    } else {
        for (i = 0; i < words; i++) {
            out[i * 4]     = (H[i] >>> 24) & 0xff;
            out[i * 4 + 1] = (H[i] >>> 16) & 0xff;
            out[i * 4 + 2] = (H[i] >>> 8)  & 0xff;
            out[i * 4 + 3] = H[i] & 0xff;
        }
    }

    for (i = 0; i < tail_len; i++) { tail[i] = 0; }
    return out;
}

/**
 * hash(prefix ‖ ·), with the prefix compressed once.
 *
 * For a prefix of whole blocks that many hashes share: HMAC's pad blocks,
 * and SLH-DSA's SHA-2 family, which opens every one of its millions of hash
 * calls with PK.seed padded to a block. What is kept is the chaining state
 * after the prefix, not the prefix itself.
 *
 * @param {function} hash    a hash exposing PARAMS (sha256, sha512)
 * @param {Uint8Array} prefix  a whole number of blocks
 * @return {function(Uint8Array): Uint8Array}
 */
export function md_prefixed(hash, prefix) {
    var p = hash.PARAMS;
    if (!p) { throw new Error('md_prefixed: this hash does not expose its parameters'); }
    if (prefix.length % p.block_size !== 0) { throw new Error('md_prefixed: the prefix must be whole blocks'); }
    var S = new Int32Array(p.iv), W = new Int32Array(p.w_size);
    for (var off = 0; off < prefix.length; off += p.block_size) { p.compress(S, prefix, off, W); }
    var before = prefix.length;
    /* ⚠ `before` goes into the length field: the state already holds that many bytes */
    return function (msg) { return md_hash(p, msg, S, before); };
}

/**
 * An incremental hash over the same framing: update() any number of times,
 * then digest() once.
 *
 * ⭐ FULL BLOCKS ARE COMPRESSED AS THEY ARRIVE, straight from the caller's
 *   array; only the partial last block is buffered. digest() then hands that
 *   remainder to md_hash with the chaining state and the byte count so far -
 *   the resume path md_hash already has for HMAC - so the padding and the
 *   length field stay in one place.
 *
 * ⚠ EACH INSTANCE OWNS ITS STATE. md_hash's scratch arrays live on the
 *   parameter object (see the note there), which is safe only because one
 *   call never overlaps another. An incremental hash stays open across
 *   calls, so its chaining state, schedule and buffer are its own, and two
 *   of them can be in progress at once.
 *
 * @param {object} p  the same parameter object md_hash takes
 * @return {{update: function(Uint8Array): object, copy: function(): object, digest: function(): Uint8Array}}
 */
export function md_create(p) {
    return md_instance(p, new Int32Array(p.iv), new Uint8Array(p.block_size), 0, 0);
}

function md_instance(p, H, buf, buf_len, absorbed) {
    var block_size = p.block_size;
    var W = new Int32Array(p.w_size);
    var done = false;

    function check() {
        if (done) { throw new Error('hash: digest() was already called on this instance'); }
    }

    var self = {
        update: function (msg) {
            check();
            var len = msg.length;
            var off = 0;
            var i;
            if (buf_len > 0) {
                var take = Math.min(block_size - buf_len, len);
                for (i = 0; i < take; i++) { buf[buf_len + i] = msg[i]; }
                buf_len += take;
                off = take;
                if (buf_len < block_size) { return self; }
                p.compress(H, buf, 0, W);
                absorbed += block_size;
                buf_len = 0;
            }
            while (len - off >= block_size) {
                p.compress(H, msg, off, W);
                absorbed += block_size;
                off += block_size;
            }
            for (i = 0; off + i < len; i++) { buf[i] = msg[off + i]; }
            buf_len = len - off;
            return self;
        },
        copy: function () {
            check();
            return md_instance(p, new Int32Array(H), new Uint8Array(buf), buf_len, absorbed);
        },
        digest: function () {
            check();
            done = true;
            var out = md_hash(p, buf.subarray(0, buf_len), H, absorbed);
            H.fill(0);
            buf.fill(0);
            W.fill(0);
            return out;
        }
    };
    return self;
}
