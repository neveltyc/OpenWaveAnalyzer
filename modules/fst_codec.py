# ================================================================
# Part 2: FST Varint
# ================================================================






def read_varint(buf: bytes | bytearray | memoryview, off: int = 0) -> tuple[int, int]:
    """Read an unsigned varint. Returns (value, bytes_consumed).

    FST varint format: bytes are stored with continuation bit (bit 7) set
    for all but the last byte. The LAST byte (without continuation bit)
    contains the LEAST significant 7 bits. Reconstruction reads backwards
    from the last byte to the first.
    """
    start = off
    n = len(buf)
    while off < n and (buf[off] & 0x80):
        off += 1
    if off >= n:
        raise _FstFormatError("truncated varint")
    # off now points to the last byte (which has bit7=0)
    end = off  # last byte index
    off += 1   # skip past

    value = 0
    # Iterate backwards: from last byte to first
    for i in range(end, start - 1, -1):
        value = (value << 7) | (buf[i] & 0x7F)
    return value, off - start


def read_varint32(buf: bytes | bytearray | memoryview, off: int = 0) -> tuple[int, int]:
    """Read an unsigned 32-bit varint. Alias for read_varint."""
    return read_varint(buf, off)


# Optional numpy acceleration for the bulk time-table decode.  The tool is
# stdlib-only by design, so numpy is treated purely as an accelerator: if it is
# not importable we fall back to a pure-Python decoder that is itself several
# times faster than the per-call read_varint loop.
try:
    import numpy as _np
except Exception:  # pragma: no cover - numpy is optional
    _np = None


def decode_varint_deltas(ucdata: bytes, nitems: int) -> list[int]:
    """Decode ``nitems`` consecutive unsigned LEB128 varints and return their
    running (prefix) sum as a list of ints.

    This is the hot path for VCDATA time tables: every section stores its
    timestamps as delta-encoded varints, and a large trace can carry tens of
    millions of them.  The semantics are exactly::

        out, acc, off = [], 0, 0
        for _ in range(nitems):
            val, used = read_varint(ucdata, off)
            acc += val
            out.append(acc)
            off += used

    but the per-varint Python function call and the backward byte scan in
    read_varint dominate at that scale.  Two faster strategies are used, both
    producing bit-for-bit identical results to the loop above (verified against
    read_varint across fixtures and a 386 MB VCS trace):

    * numpy path: split the stream on continuation bits and reconstruct every
      varint with vectorized shifts.  Only used when no single varint exceeds
      9 payload bytes, which keeps every intermediate inside uint64 (9*7 = 63
      bits); FST time deltas never approach that.  Anything longer falls back.
    * pure-Python path: a tight forward LEB128 loop with locals bound up front,
      avoiding both the function-call-per-item overhead and read_varint's
      separate backward length scan.
    """
    if nitems <= 0:
        return []

    if _np is not None:
        out = _decode_varint_deltas_numpy(ucdata, nitems)
        if out is not None:
            return out

    return _decode_varint_deltas_py(ucdata, nitems)


def _decode_varint_deltas_py(ucdata: bytes, nitems: int) -> list[int]:
    """Pure-Python forward LEB128 prefix-sum decoder (no dependencies)."""
    times: list[int] = []
    ap = times.append
    acc = 0
    off = 0
    data = ucdata
    n = len(data)
    for _ in range(nitems):
        b = data[off]
        off += 1
        if b < 0x80:
            acc += b
            ap(acc)
            continue
        value = b & 0x7F
        shift = 7
        while True:
            if off >= n:
                raise _FstFormatError("truncated varint")
            b = data[off]
            off += 1
            value |= (b & 0x7F) << shift
            if b < 0x80:
                break
            shift += 7
        acc += value
        ap(acc)
    return times


def _decode_varint_deltas_numpy(ucdata: bytes, nitems: int):
    """Vectorized decode; returns None to signal "fall back to pure Python"."""
    if not ucdata:
        return None
    b = _np.frombuffer(ucdata, dtype=_np.uint8)
    is_last = (b & 0x80) == 0
    last_idx = _np.nonzero(is_last)[0]
    if last_idx.size < nitems:
        return None
    last_idx = last_idx[:nitems].astype(_np.int64)
    starts = _np.empty(nitems, dtype=_np.int64)
    starts[0] = 0
    if nitems > 1:
        starts[1:] = last_idx[:-1] + 1
    lengths = last_idx - starts + 1
    maxlen = int(lengths.max())
    if maxlen > 9:
        # A 10+ byte varint can overflow uint64 intermediates; let the robust
        # pure-Python path handle this (vanishingly rare for real time tables).
        return None
    payload = (b & 0x7F).astype(_np.uint64)
    deltas = _np.zeros(nitems, dtype=_np.uint64)
    for k in range(maxlen):
        mask = lengths > k
        if not mask.any():
            break
        idx = starts[mask] + k
        deltas[mask] += payload[idx] << _np.uint64(7 * k)
    return _np.cumsum(deltas).tolist()


def read_varint64(buf: bytes | bytearray | memoryview, off: int = 0) -> tuple[int, int]:
    """Read an unsigned 64-bit varint. Same encoding as read_varint."""
    return read_varint(buf, off)


def read_svarint(buf: bytes | bytearray | memoryview, off: int = 0) -> tuple[int, int]:
    """Read a signed varint (protobuf-style sign extension).

    This is the encoding used by DYN_ALIAS2 chain tables.
    Unlike zigzag, the MSB of the last 7-bit chunk determines sign.
    """
    value = 0
    shift = 0
    pos = off
    last = 0
    n = len(buf)
    while True:
        if pos >= n:
            raise _FstFormatError("truncated signed varint")
        last = buf[pos]
        pos += 1
        value |= (last & 0x7F) << shift
        shift += 7
        if not (last & 0x80):
            break
    if shift < 64 and last & 0x40:
        value |= -(1 << shift)
    return value, pos - off


def read_svarint64(buf: bytes | bytearray | memoryview, off: int = 0) -> tuple[int, int]:
    """Read a signed 64-bit varint."""
    return read_svarint(buf, off)


def peek_varint32(buf: bytes | bytearray | memoryview, off: int = 0) -> int:
    """Read a varint value without advancing the offset."""
    val, _ = read_varint(buf, off)
    return val


def write_varint(value: int) -> bytes:
    """Encode an unsigned integer as an FST varint.

    Matches C `fstCopyVarint64ToRight` exactly: emit LSB-first 7-bit groups,
    with continuation bit (0x80) set on every byte except the last (which
    carries the MSB).  Stays roundtrip-consistent with `read_varint`, which
    advances forward to find the byte without bit 7, then iterates backward
    to reconstruct the value.

    Previously this function emitted the bytes in reversed order and set the
    continuation bit on the wrong byte, so any value >= 128 wrote out
    something that read_varint (and the C reader) decoded to a different
    integer.  This only manifested once writer tests had VC chunks large
    enough to push chain deltas above 127.
    """
    if value < 0:
        raise ValueError("varint must be non-negative")
    result = bytearray()
    while True:
        nxt = value >> 7
        if nxt:
            result.append((value & 0x7F) | 0x80)
            value = nxt
        else:
            result.append(value & 0x7F)
            break
    return bytes(result)


def write_varint32(value: int) -> bytes:
    """Encode a 32-bit integer as FST varint bytes."""
    return write_varint(value)


def write_varint64(value: int) -> bytes:
    """Encode a 64-bit integer as FST varint bytes."""
    return write_varint(value)



# ================================================================
# Part 3: FST Compression
# ================================================================




import zlib



def lz4_decompress(src: bytes, expected_len: int | None = None) -> bytes:
    """Pure-Python LZ4 block decompressor.

    Matches the LZ4 block format used by libfst's hierarchy and VCDATA
    blocks. This is the raw block format, not framed .lz4.

    The match copy is the hot loop.  LZ4 matches are overwhelmingly
    non-overlapping (offset >= match_len), which can be satisfied with one
    C-level ``bytearray.extend`` of a slice instead of a Python-level
    byte-at-a-time append loop.  Overlapping matches (offset < match_len, the
    RLE-style back-reference) still need replication, but that is expressed as
    slice multiplication, again staying in C.  Output is identical to the
    naive loop (verified against it on real LZ4/LZ4DUO hierarchy blocks).
    """
    i = 0
    n = len(src)
    out = bytearray()
    ext = out.extend

    while i < n:
        token = src[i]
        i += 1

        # Literal length
        literal_len = token >> 4
        if literal_len == 15:
            while True:
                if i >= n:
                    raise _FstFormatError("truncated LZ4 literal length")
                b = src[i]
                i += 1
                literal_len += b
                if b != 255:
                    break

        if i + literal_len > n:
            raise _FstFormatError("truncated LZ4 literal payload")
        if literal_len:
            ext(src[i:i + literal_len])
            i += literal_len

        if i >= n:
            break

        # Match offset
        if i + 2 > n:
            raise _FstFormatError("truncated LZ4 offset")
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        cur = len(out)
        if offset == 0 or offset > cur:
            raise _FstFormatError(f"invalid LZ4 offset {offset}")

        # Match length
        match_len = token & 0x0F
        if match_len == 15:
            while True:
                if i >= n:
                    raise _FstFormatError("truncated LZ4 match length")
                b = src[i]
                i += 1
                match_len += b
                if b != 255:
                    break
        match_len += 4

        # Copy match.  start..cur is the back-reference window of length offset.
        start = cur - offset
        if offset >= match_len:
            # Non-overlapping (the common case): one slice copy.
            ext(out[start:start + match_len])
        elif offset == 1:
            # Single-byte run.
            ext(out[start:cur] * match_len)
        else:
            # Overlapping back-reference: replicate the offset-length window.
            window = out[start:cur]
            full, rem = divmod(match_len, offset)
            ext(window * full)
            if rem:
                ext(window[:rem])

    if expected_len is not None and len(out) != expected_len:
        raise _FstFormatError(
            f"LZ4 decompressed length mismatch: got {len(out)}, expected {expected_len}"
        )
    return bytes(out)


def fastlz_decompress(src: bytes, maxout: int) -> bytes:
    """Pure-Python FastLZ level 1 decompressor.

    Direct port of fastlz1_decompress() from fastlz.c:418-547 (level-1
    branches only; level-2 is not used by libfst). FastLZ is one of the
    compression options for FST VCDATA chunks (pack_type 'F').

    Format (level 1):
      byte 0: low 5 bits = first ctrl; high 3 bits = level marker (discard).
      Thereafter, each ctrl byte branches:
        ctrl >= 32  back-reference.  length = (ctrl>>5)-1 + 3 bytes.
                    offset = ((ctrl & 31) << 8) | next_byte.
                    Copy from out[op - offset - 1] byte-by-byte
                    (overlap-safe; do NOT use a slice).
        ctrl <  32  literal: copy next (ctrl + 1) bytes verbatim.
      After each event, read the next full byte as ctrl.  Exit when
      input is exhausted.
    """
    if not src:
        return b""
    out = bytearray()
    ip = 0
    ip_limit = len(src)
    ctrl = src[ip] & 0x1F
    ip += 1
    loop = True
    while loop:
        if ctrl >= 32:
            length = (ctrl >> 5) - 1
            ofs = (ctrl & 0x1F) << 8
            if length == 6:
                if ip >= ip_limit:
                    raise _FstFormatError("truncated FastLZ extended length")
                length += src[ip]
                ip += 1
            if ip >= ip_limit:
                raise _FstFormatError("truncated FastLZ offset low byte")
            ref = len(out) - ofs - src[ip] - 1
            ip += 1
            if ref < 0:
                raise _FstFormatError(
                    f"invalid FastLZ back-reference (ref={ref})"
                )
            if ip < ip_limit:
                ctrl = src[ip]
                ip += 1
            else:
                loop = False
            for _ in range(length + 3):
                out.append(out[ref])
                ref += 1
        else:
            count = ctrl + 1
            if ip + count > ip_limit:
                raise _FstFormatError("truncated FastLZ literal payload")
            out.extend(src[ip:ip + count])
            ip += count
            if ip < ip_limit:
                ctrl = src[ip]
                ip += 1
            else:
                loop = False
    if maxout > 0 and len(out) > maxout:
        return bytes(out[:maxout])
    return bytes(out)


def decompress_zlib(data: bytes, expected_len: int | None = None) -> bytes:
    """Decompress zlib data, optionally checking expected length."""
    result = zlib.decompress(data)
    if expected_len is not None and len(result) != expected_len:
        raise _FstFormatError(
            f"zlib decompressed length mismatch: got {len(result)}, expected {expected_len}"
        )
    return result


def decompress_block(data: bytes, pack_type: str,
                     expected_len: int | None = None) -> bytes:
    """Decompress according to FST pack type: 'Z'/'!'=zlib, '4'=LZ4, 'F'=FastLZ."""
    if pack_type in ('Z', '!'):
        return decompress_zlib(data, expected_len)
    elif pack_type == '4':
        return lz4_decompress(data, expected_len)
    elif pack_type == 'F':
        return fastlz_decompress(data, expected_len)
    else:
        raise _FstFormatError(f"unknown FST pack type: {pack_type!r}")



