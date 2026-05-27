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
    """
    i = 0
    n = len(src)
    out = bytearray()

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
        out.extend(src[i:i + literal_len])
        i += literal_len

        if i >= n:
            break

        # Match offset
        if i + 2 > n:
            raise _FstFormatError("truncated LZ4 offset")
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0 or offset > len(out):
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

        # Copy match
        start = len(out) - offset
        for j in range(match_len):
            out.append(out[start + j])

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



