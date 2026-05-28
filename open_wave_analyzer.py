#!/usr/bin/env python3
"""Unified VCD/FST waveform analyzer for Agent-based RTL debug.

Usage: open_wave_analyzer [--json] <command> <file> [options]
Supported formats: VCD (.vcd), FST (.fst) — auto-detected by extension or magic byte.

Commands:
  info       <file>                               File overview (timescale, signal count, time span, scopes)
  list       <file> [--filter K1,K2]               List signals with path and bit width
  dump       <file> [--begin T] [--end T] [--filter K1,K2]   Print signal value changes in time order
  summary    <file> [--begin T] [--end T] [--filter K1,K2]   Per-signal stats: change count, unique values, static detection
  snapshot   <file> --at T [--filter K1,K2]        Known signal values at a given time point
  compare    <file> --at T1,T2 [--filter K1,K2]    Diff signal values between two time points
  search     <file> --condition C [--show K1,K2] [--changed K] [--begin T] [--end T]
                                                        Conditional search and associated signal observation

Global options:
  --json       Output compact structured JSON instead of text (time fields include *_ticks)
  --limit N    Max rows/records to emit; default 200; 0 = unlimited.
               Streaming commands stop after detecting the first unshown result.
  --verbose    Show extra fields; if --limit is omitted, disables truncation

Argument formats:
  <file>          VCD (.vcd) or FST (.fst) waveform file path.
                  Extension is used for format detection; unknown extensions fall back
                  to first-byte magic (FST starts with 0x00).
  --filter K1,K2  Comma-separated patterns. Plain text uses case-insensitive substring match;
                  patterns containing * or ? use case-insensitive glob match.
                  e.g. --filter clk,rst   --filter '*_valid,*_ready,*_data'   --filter 'top.u_dma.*'
  --begin T       Start time with optional unit suffix: 0, 100ns, 17.5us, 1ms, 500ps, 200fs
  --end T         End time, same format as --begin. Omit for no upper bound
  --at T          Time point for snapshot. For compare: two points comma-separated: --at 17.5us,17.7us
  --condition C   Comma-separated AND conditions: SIG=VAL, SIG==VAL, SIG!=VAL.
                  Condition signal patterns must match exactly one signal.
                  SIG!=VAL does not match x/z/undef; use SIG=x to search unknown.
                  Values use numeric or 4-state matching: 5, 0x5, b0101, b1x0z.
  --show K1,K2    Optional associated signals to display while condition holds;
                  segment mode splits whenever shown values change.
  --changed K     Optional trigger signal; emit events only when this signal really changes.
                  For ordinary signals, first observed values are not treated as changes.
                  VCD event variables count each trigger; t=0 initialization is ignored.

Examples:
  python open_wave_analyzer.py info sim.vcd
  python open_wave_analyzer.py info design.fst
  python open_wave_analyzer.py list sim.vcd --filter tdata,tvalid,tready
  python open_wave_analyzer.py dump sim.fst --begin 17.5us --end 17.6us --filter clk,rst,state
  python open_wave_analyzer.py summary sim.vcd --filter dll_st,locked
  python open_wave_analyzer.py snapshot design.fst --at 17.55us --filter init_done,state
  python open_wave_analyzer.py compare sim.vcd --at 17.535us,17.56us --filter init_done,link_active,state
  python open_wave_analyzer.py search sim.fst --condition "state=5"
  python open_wave_analyzer.py search sim.vcd --condition "arvalid=1,arready=1" --show araddr,arlen,arid
  python open_wave_analyzer.py search sim.vcd --changed data_out --condition "valid=0" --show data_out,valid
  python open_wave_analyzer.py search sim.fst --condition "valid=x"
  python open_wave_analyzer.py --json summary sim.vcd --filter tvalid,tready

Notes:
  Both VCD and FST files go through the same 7 analysis commands with identical
  output structure. FST files are typically 10-20x smaller; info is faster on FST
  (header-only read) while dump/summary may be slightly slower (pure-Python
  decompression).

  search requires at least one observed value_change in the data section;
  empty waveforms are reported as an input/data issue rather than as a false
  "no match" result.
"""

__version__ = '2.0.1'

import sys, os, re, math, json, struct
import zlib as _zlib
import bisect, mmap, argparse, base64, fnmatch, heapq, warnings
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Iterator



# ================================================================
# Part 1: FST Common Types
# ================================================================




from dataclasses import dataclass, field
from enum import IntEnum


# ---------------------------------------------------------------------------
# Block type constants (section identifiers at top of each block)
# ---------------------------------------------------------------------------

class FstBlockType(IntEnum):
    HDR = 0
    VCDATA = 1
    BLACKOUT = 2
    GEOM = 3
    HIER = 4
    VCDATA_DYN_ALIAS = 5
    HIER_LZ4 = 6
    HIER_LZ4DUO = 7
    VCDATA_DYN_ALIAS2 = 8
    ZWRAPPER = 254
    SKIP = 255


# ---------------------------------------------------------------------------
# Scope types
# ---------------------------------------------------------------------------

class FstScopeType(IntEnum):
    VCD_MODULE = 0
    VCD_TASK = 1
    VCD_FUNCTION = 2
    VCD_BEGIN = 3
    VCD_FORK = 4
    VCD_GENERATE = 5
    VCD_STRUCT = 6
    VCD_UNION = 7
    VCD_CLASS = 8
    VCD_INTERFACE = 9
    VCD_PACKAGE = 10
    VCD_PROGRAM = 11
    VHDL_ARCHITECTURE = 12
    VHDL_PROCEDURE = 13
    VHDL_FUNCTION = 14
    VHDL_RECORD = 15
    VHDL_PROCESS = 16
    VHDL_BLOCK = 17
    VHDL_FOR_GENERATE = 18
    VHDL_IF_GENERATE = 19
    VHDL_GENERATE = 20
    VHDL_PACKAGE = 21


# ---------------------------------------------------------------------------
# Variable types
# ---------------------------------------------------------------------------

class FstVarType(IntEnum):
    VCD_EVENT = 0
    VCD_INTEGER = 1
    VCD_PARAMETER = 2
    VCD_REAL = 3
    VCD_REAL_PARAMETER = 4
    VCD_REG = 5
    VCD_SUPPLY0 = 6
    VCD_SUPPLY1 = 7
    VCD_TIME = 8
    VCD_TRI = 9
    VCD_TRIAND = 10
    VCD_TRIOR = 11
    VCD_TRIREG = 12
    VCD_TRI0 = 13
    VCD_TRI1 = 14
    VCD_WAND = 15
    VCD_WIRE = 16
    VCD_WOR = 17
    VCD_PORT = 18
    VCD_SPARRAY = 19
    VCD_REALTIME = 20
    GEN_STRING = 21
    SV_BIT = 22
    SV_LOGIC = 23
    SV_INT = 24
    SV_SHORTINT = 25
    SV_LONGINT = 26
    SV_BYTE = 27
    SV_ENUM = 28
    SV_SHORTREAL = 29


FST_VT_MAX = 29


# ---------------------------------------------------------------------------
# Variable direction
# ---------------------------------------------------------------------------

class FstVarDir(IntEnum):
    IMPLICIT = 0
    INPUT = 1
    OUTPUT = 2
    INOUT = 3
    BUFFER = 4
    LINKAGE = 5


# ---------------------------------------------------------------------------
# File type
# ---------------------------------------------------------------------------

class FstFileType(IntEnum):
    VERILOG = 0
    VHDL = 1
    VERILOG_VHDL = 2


# ---------------------------------------------------------------------------
# Writer pack type
# ---------------------------------------------------------------------------

class FstWriterPackType(IntEnum):
    ZLIB = 0
    FASTLZ = 1
    LZ4 = 2


# ---------------------------------------------------------------------------
# Hierarchy event types
# ---------------------------------------------------------------------------

class FstHierType(IntEnum):
    SCOPE = 0
    UPSCOPE = 1
    VAR = 2
    ATTRBEGIN = 3
    ATTREND = 4
    TREEBEGIN = 5
    TREEEND = 6


# ---------------------------------------------------------------------------
# Attribute types
# ---------------------------------------------------------------------------

class FstAttrType(IntEnum):
    MISC = 0
    ARRAY = 1
    ENUM = 2
    PACK = 3


# ---------------------------------------------------------------------------
# Misc attribute subtypes
# ---------------------------------------------------------------------------

class FstMiscType(IntEnum):
    COMMENT = 0
    ENVVAR = 1
    SUPVAR = 2
    PATHNAME = 3
    SOURCESTEM = 4
    SOURCEISTEM = 5
    VALUELIST = 6
    ENUMTABLE = 7
    UNKNOWN = 8


# ---------------------------------------------------------------------------
# Array types
# ---------------------------------------------------------------------------

class FstArrayType(IntEnum):
    NONE = 0
    UNPACKED = 1
    PACKED = 2
    SPARSE = 3


# ---------------------------------------------------------------------------
# Enum value types
# ---------------------------------------------------------------------------

class FstEnumValueType(IntEnum):
    SV_INTEGER = 0
    SV_BIT = 1
    SV_LOGIC = 2
    SV_INT = 3
    SV_SHORTINT = 4
    SV_LONGINT = 5
    SV_BYTE = 6
    SV_UNSIGNED_INTEGER = 7
    SV_UNSIGNED_BIT = 8
    SV_UNSIGNED_LOGIC = 9
    SV_UNSIGNED_INT = 10
    SV_UNSIGNED_SHORTINT = 11
    SV_UNSIGNED_LONGINT = 12
    SV_UNSIGNED_BYTE = 13
    REG = 14
    TIME = 15


# ---------------------------------------------------------------------------
# Pack types
# ---------------------------------------------------------------------------

class FstPackType(IntEnum):
    NONE = 0
    UNPACKED = 1
    PACKED = 2
    TAGGED_PACKED = 3


# ---------------------------------------------------------------------------
# Supplemental variable types (VHDL)
# ---------------------------------------------------------------------------

class FstSupplementalVarType(IntEnum):
    NONE = 0
    VHDL_SIGNAL = 1
    VHDL_VARIABLE = 2
    VHDL_CONSTANT = 3
    VHDL_FILE = 4
    VHDL_MEMORY = 5


# ---------------------------------------------------------------------------
# Supplemental data types (VHDL)
# ---------------------------------------------------------------------------

class FstSupplementalDataType(IntEnum):
    NONE = 0
    VHDL_BOOLEAN = 1
    VHDL_BIT = 2
    VHDL_BIT_VECTOR = 3
    VHDL_STD_ULOGIC = 4
    VHDL_STD_ULOGIC_VECTOR = 5
    VHDL_STD_LOGIC = 6
    VHDL_STD_LOGIC_VECTOR = 7
    VHDL_UNSIGNED = 8
    VHDL_SIGNED = 9
    VHDL_INTEGER = 10
    VHDL_REAL = 11
    VHDL_NATURAL = 12
    VHDL_POSITIVE = 13
    VHDL_TIME = 14
    VHDL_CHARACTER = 15
    VHDL_STRING = 16


# ---------------------------------------------------------------------------
# Hierarchy special tags
# ---------------------------------------------------------------------------

FST_ST_GEN_ATTRBEGIN = 252
FST_ST_GEN_ATTREND = 253
FST_ST_VCD_SCOPE = 254
FST_ST_VCD_UPSCOPE = 255

# Header field sizes
FST_HDR_SIM_VERSION_SIZE = 128
FST_HDR_DATE_SIZE = 119
FST_DOUBLE_ENDTEST = 2.7182818284590452354

# Multi-bit VCD value encoding table
FST_RCV_STR = b"xzhuwl-?"


# ---------------------------------------------------------------------------
# Python dataclass representations of parsed hierarchy entries
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FstBlock:
    offset: int
    block_type: int
    section_length: int
    payload: Any  # bytes-like view; memoryview for mmap-backed readers


@dataclass(frozen=True)
class FstHeader:
    start_time: int
    end_time: int
    double_endian_match: bool
    memory_used_by_writer: int
    scope_count: int
    var_count: int
    max_handle: int
    value_change_section_count: int
    timescale: int
    version: str
    date: str
    filetype: int
    timezero: int


@dataclass(frozen=True)
class FstScope:
    scope_type: int
    name: str
    component: str
    full_name: str


@dataclass(frozen=True)
class FstSignalMetadata:
    """Semantic metadata decoded from FST hierarchy attributes.

    libfst exposes attributes as hierarchy events.  This structure attaches
    common SystemVerilog/VHDL helper attributes to the variable that follows
    them, matching the way fstWriterCreateVar2(), fstWriterSetValueList(),
    fstWriterEmitEnumTableRef(), and source-stem helpers emit metadata.

    The raw attrbegin/attrend stream is still available via
    ``FstReader.hierarchy()`` and ``FstReader.attributes()``.  These fields are
    a structured convenience layer for reader/filter users; they do not imply
    that a VCD text exporter is enabled.
    """

    type_name: str = ""
    supplemental_var_type: int = 0
    supplemental_data_type: int = 0
    value_list: str = ""
    enum_table_handle: int = 0
    source_stem: tuple[str, int] | None = None
    source_instantiation_stem: tuple[str, int] | None = None
    active_attributes: tuple = field(default_factory=tuple)
    misc_attributes: tuple = field(default_factory=tuple)
    array_attributes: tuple = field(default_factory=tuple)
    enum_attributes: tuple = field(default_factory=tuple)
    pack_attributes: tuple = field(default_factory=tuple)
    all_attributes: tuple = field(default_factory=tuple)


@dataclass(frozen=True)
class FstVar:
    var_type: int
    direction: int
    name: str
    length: int
    handle: int
    is_alias: bool
    full_name: str
    supplemental_var_type: int = 0
    supplemental_data_type: int = 0
    supplemental_type_name: str = ""
    metadata: FstSignalMetadata = field(default_factory=FstSignalMetadata)


@dataclass(frozen=True)
class FstUpscope:
    pass


@dataclass(frozen=True)
class FstAttrBegin:
    attr_type: int
    subtype: int
    name: str
    arg: int
    arg_from_name: int = 0
    # Raw C-string bytes from the hierarchy attribute name/payload field.
    # ``name`` is a text convenience view; ``name_raw`` preserves arbitrary
    # third-party/vendor payload bytes for reporting or custom decoders.
    name_raw: bytes = b""


@dataclass(frozen=True)
class FstAttrEnd:
    pass


class _FstFormatError(RuntimeError):
    """Raised when FST file data is malformed or truncated."""
    pass


# Module-level aliases for block type constants (used by reader/writer)
FST_BL_HDR = FstBlockType.HDR
FST_BL_VCDATA = FstBlockType.VCDATA
FST_BL_BLACKOUT = FstBlockType.BLACKOUT
FST_BL_GEOM = FstBlockType.GEOM
FST_BL_HIER = FstBlockType.HIER
FST_BL_VCDATA_DYN_ALIAS = FstBlockType.VCDATA_DYN_ALIAS
FST_BL_HIER_LZ4 = FstBlockType.HIER_LZ4
FST_BL_HIER_LZ4DUO = FstBlockType.HIER_LZ4DUO
FST_BL_VCDATA_DYN_ALIAS2 = FstBlockType.VCDATA_DYN_ALIAS2
FST_BL_ZWRAPPER = FstBlockType.ZWRAPPER
FST_BL_SKIP = FstBlockType.SKIP

# Module-level aliases for scope types
FST_ST_VCD_MODULE = FstScopeType.VCD_MODULE
FST_ST_VCD_TASK = FstScopeType.VCD_TASK
FST_ST_VCD_FUNCTION = FstScopeType.VCD_FUNCTION
FST_ST_VCD_BEGIN = FstScopeType.VCD_BEGIN
FST_ST_VCD_SCOPE = 254
FST_ST_VCD_UPSCOPE = 255


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



# ================================================================
# Part 4: FST Reader
# ================================================================




from dataclasses import dataclass
from pathlib import Path
import struct
import zlib
import base64
import mmap
import bisect
import fnmatch
import re
import heapq



@dataclass
class _VcSection:
    """Parsed value-change section metadata."""
    block_offset: int
    block_type: int
    section_length: int
    beg_time: int
    end_time: int
    times: list = None
    frame_uclen: int = 0
    frame_clen: int = 0
    frame_maxhandle: int = 0
    frame_data: bytes = b""
    vc_maxhandle: int = 0
    vc_start: int = 0
    pack_type: str = ""
    chain_table: list = None
    chain_table_lengths: list = None
    indx_pos: int = 0
    indx_len: int = 0
    _payload: Any = None   # stored for lazy parsing of time_table/chain_table
    _parsed: bool = False  # True once time_table and chain_table are populated


class _FstReader:
    """Pure-Python reader for FST waveform files."""

    VCDATA_BLOCK_TYPES = {FST_BL_VCDATA, FST_BL_VCDATA_DYN_ALIAS, FST_BL_VCDATA_DYN_ALIAS2}
    REAL_VAR_TYPES = {
        FstVarType.VCD_REAL,
        FstVarType.VCD_REAL_PARAMETER,
        FstVarType.VCD_REALTIME,
        FstVarType.SV_SHORTREAL,
    }

    def __init__(self, path: str | Path, *, use_mmap: bool = True):
        self.path = Path(path)
        self._file = None
        self._mmap = None
        self._owns_data = False

        # Normal FST files are block based and do not need to be copied into a
        # giant bytes object.  Use mmap by default so block scanning and lazy
        # VCDATA reads are backed by the OS page cache.  ZWRAPPER is a
        # whole-file compressed container, so it necessarily has to be inflated
        # before normal block parsing can continue.
        if use_mmap:
            f = self.path.open("rb")
            size = self.path.stat().st_size
            if size == 0:
                f.close()
                raise _FstFormatError("empty FST file")
            first = f.read(1)
            f.seek(0)
            if first and first[0] == FST_BL_ZWRAPPER:
                raw = f.read()
                f.close()
                self._data = self._inflate_zwrapper(raw)
                self._owns_data = True
            else:
                self._file = f
                self._mmap = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                self._data = self._mmap
        else:
            raw = self.path.read_bytes()
            if not raw:
                raise _FstFormatError("empty FST file")
            self._data = self._inflate_zwrapper(raw) if raw[0] == FST_BL_ZWRAPPER else raw
            self._owns_data = True

        self._blocks = self._scan_blocks(self._data)
        self.header = self._parse_header()
        self._signal_lengths: list[int] = []
        self._signal_types: list[int] = []
        self._hierarchy_events: list = []
        self._vc_sections: list[_VcSection] = []
        self._handle_to_var: dict[int, 'FstVar'] = {}
        self._vars_by_handle: dict[int, list['FstVar']] = {}
        self._comments: list[str] = []
        self._env_vars: list[str] = []
        self._value_lists: list[str] = []
        self._enum_tables: dict[int, dict] = {}
        self._source_paths: dict[int, str] = {}
        self._attribute_events: list[FstAttrBegin] = []
        self._attributes_by_handle: dict[int, tuple[FstAttrBegin, ...]] = {}
        self._parse_geometry_and_hierarchy()
        self._build_handle_map()
        self._build_signal_index()
        self._parse_vc_sections()
        self._build_section_time_index()
        self._parse_blackouts()
        self._blackout_times = [t for t, _ in self._blackouts]
        self._blackout_states = [a for _, a in self._blackouts]


    @staticmethod
    def _inflate_zwrapper(raw: bytes | bytearray | memoryview) -> bytes:
        """Inflate a whole-file ZWRAPPER FST container."""
        if len(raw) < 17:
            raise _FstFormatError("truncated ZWRAPPER")
        uclen = int.from_bytes(raw[9:17], "big")
        comp = raw[17:]
        try:
            data = zlib.decompress(comp, 15 + 32)
        except zlib.error:
            data = zlib.decompress(comp, -15)
        if len(data) != uclen:
            raise _FstFormatError("ZWRAPPER decompressed length mismatch")
        return data

    def close(self) -> None:
        """Release mmap/file resources held by the reader.

        Existing parsed metadata remains usable, but lazy VCDATA iteration
        requires the underlying mmap/data to stay open.  Prefer using the
        reader as a context manager for large files.
        """
        if self._mmap is not None:
            try:
                self._mmap.close()
            except BufferError:
                # A caller may still hold a temporary memoryview obtained from a
                # block payload.  Leave the mmap attached so a later close() can
                # retry after that view is released.
                return
            self._mmap = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self) -> "_FstReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @staticmethod
    def _scan_blocks(data: bytes | bytearray | memoryview | mmap.mmap) -> list[FstBlock]:
        """Scan top-level FST blocks.

        libfst treats FST_BL_SKIP as an end marker.  Some files contain only a
        single trailing 0xff byte, so do not require a full 9-byte section
        header once the marker is seen.
        """
        blocks: list[FstBlock] = []
        view = memoryview(data)
        off = 0
        n = len(view)
        while off < n:
            block_type = view[off]
            if block_type == FST_BL_SKIP:
                break
            if off + 9 > n:
                raise _FstFormatError(f"truncated block header at offset {off}")
            section_length = _u64be(view, off + 1)
            end = off + 1 + section_length
            if section_length < 8 or end > n:
                raise _FstFormatError(
                    f"invalid section length {section_length} at offset {off}"
                )
            payload = _ByteView(data, off + 9, end)
            blocks.append(FstBlock(off, block_type, section_length, payload))
            off = end
        return blocks

    def _parse_header(self) -> FstHeader:
        header_blocks = [b for b in self._blocks if b.block_type == FST_BL_HDR]
        if not header_blocks:
            raise _FstFormatError("missing FST header block")
        b = header_blocks[0].payload
        if len(b) < 320:
            raise _FstFormatError("truncated FST header payload")
        off = 0
        start_time = _u64be(b, off); off += 8
        end_time = _u64be(b, off); off += 8
        dcheck_raw = b[off:off + 8]; off += 8
        d_le = struct.unpack("<d", dcheck_raw)[0]
        d_be = struct.unpack(">d", dcheck_raw)[0]
        double_endian_match = abs(d_le - FST_DOUBLE_ENDTEST) < 1e-15
        if not double_endian_match and abs(d_be - FST_DOUBLE_ENDTEST) >= 1e-15:
            raise _FstFormatError("invalid FST endian check double")
        memory_used_by_writer = _u64be(b, off); off += 8
        scope_count = _u64be(b, off); off += 8
        var_count = _u64be(b, off); off += 8
        max_handle = _u64be(b, off); off += 8
        vc_section_count = _u64be(b, off); off += 8
        timescale = _i8(b[off]); off += 1
        version = bytes(b[off:off + FST_HDR_SIM_VERSION_SIZE])
        version = version.split(b"\0", 1)[0].decode("utf-8", errors="replace")
        off += FST_HDR_SIM_VERSION_SIZE
        date = bytes(b[off:off + FST_HDR_DATE_SIZE])
        date = date.split(b"\0", 1)[0].decode("utf-8", errors="replace")
        off += FST_HDR_DATE_SIZE
        filetype = b[off] if off < len(b) else 0
        off += 1
        timezero = struct.unpack(">q", b[off:off + 8])[0] if off + 8 <= len(b) else 0
        return FstHeader(
            start_time=start_time, end_time=end_time,
            double_endian_match=double_endian_match,
            memory_used_by_writer=memory_used_by_writer,
            scope_count=scope_count, var_count=var_count,
            max_handle=max_handle,
            value_change_section_count=vc_section_count,
            timescale=timescale, version=version, date=date,
            filetype=filetype, timezero=timezero,
        )

    def _parse_geometry(self, block: FstBlock) -> tuple[list[int], list[int]]:
        body = block.payload
        if len(body) < 16:
            raise _FstFormatError("truncated geometry block")
        uclen = _u64be(body, 0)
        maxhandle = _u64be(body, 8)
        comp = body[16:]
        geom = comp if len(comp) == uclen else zlib.decompress(comp)
        if len(geom) != uclen:
            raise _FstFormatError("geometry length mismatch")
        signal_lens: list[int] = []
        signal_typs: list[int] = []
        off = 0
        for _ in range(int(maxhandle)):
            val, used = read_varint(geom, off)
            off += used
            if val and val != 0xFFFFFFFF:
                signal_lens.append(val)
                signal_typs.append(16)
            elif val == 0xFFFFFFFF:
                signal_lens.append(0)
                signal_typs.append(16)
            else:
                signal_lens.append(8)
                signal_typs.append(3)
        return signal_lens, signal_typs

    def _extract_hierarchy(self) -> bytes:
        geom_blocks = [b for b in self._blocks if b.block_type == FST_BL_GEOM]
        self._has_geometry = bool(geom_blocks)
        if geom_blocks:
            self._signal_lengths, self._signal_types = \
                self._parse_geometry(geom_blocks[0])
        hier_blocks = [
            b for b in self._blocks
            if b.block_type in {FST_BL_HIER, FST_BL_HIER_LZ4, FST_BL_HIER_LZ4DUO}
        ]
        if not hier_blocks:
            raise _FstFormatError("missing hierarchy block")
        block = hier_blocks[0]
        body = block.payload
        if len(body) < 8:
            raise _FstFormatError("truncated hierarchy block")
        uclen = _u64be(body, 0)
        comp = body[8:]
        if block.block_type == FST_BL_HIER:
            try:
                data = zlib.decompress(comp)
            except zlib.error:
                data = zlib.decompress(comp, 15 + 32)  # try gzip
        elif block.block_type == FST_BL_HIER_LZ4:
            data = lz4_decompress(comp, uclen)
        elif block.block_type == FST_BL_HIER_LZ4DUO:
            uclen2, used = read_varint(comp, 0)
            mid = lz4_decompress(comp[used:], uclen2)
            data = lz4_decompress(mid, uclen)
        else:
            raise AssertionError(block.block_type)
        if len(data) != uclen:
            raise _FstFormatError("hierarchy length mismatch")
        return data

    def _parse_hierarchy(self, data: bytes) -> list:
        """Parse hierarchy stream and attach common libfst metadata.

        libfst exposes ATTRBEGIN/ATTREND as hierarchy events.  Writer helper
        APIs such as fstWriterCreateVar2(), fstWriterSetValueList(),
        fstWriterEmitEnumTableRef(), and source-stem helpers emit MISC
        attributes immediately before the variable to which they apply.  This
        parser preserves the raw hierarchy events and also attaches those
        helper attributes to the next FstVar as FstSignalMetadata.
        """
        events: list = []
        scopes: list[str] = []
        cur_scope = ""
        current_handle = 0
        off = 0
        n = len(data)
        active_attrs: list[FstAttrBegin] = []
        pending_misc: list[FstAttrBegin] = []
        pending_metadata = FstSignalMetadata()

        def add_pending_misc(attr: FstAttrBegin) -> None:
            nonlocal pending_metadata
            if attr.attr_type != int(FstAttrType.MISC):
                return
            subtype = int(attr.subtype)
            if subtype == int(FstMiscType.COMMENT):
                self._comments.append(attr.name)
            elif subtype == int(FstMiscType.ENVVAR):
                self._env_vars.append(attr.name)
            elif subtype == int(FstMiscType.PATHNAME):
                self._source_paths[int(attr.arg)] = attr.name
            elif subtype == int(FstMiscType.VALUELIST):
                self._value_lists.append(attr.name)
                pending_misc.append(attr)
                pending_metadata = _metadata_replace(pending_metadata, value_list=attr.name)
            elif subtype == int(FstMiscType.SUPVAR):
                pending_misc.append(attr)
                svt = int(attr.arg) >> 10
                sdt = int(attr.arg) & 0x3FF
                pending_metadata = _metadata_replace(
                    pending_metadata,
                    type_name=attr.name,
                    supplemental_var_type=svt,
                    supplemental_data_type=sdt,
                )
            elif subtype == int(FstMiscType.ENUMTABLE):
                if attr.name:
                    self._enum_tables[int(attr.arg)] = _parse_enum_table_attr(attr.name)
                else:
                    pending_misc.append(attr)
                    pending_metadata = _metadata_replace(
                        pending_metadata, enum_table_handle=int(attr.arg)
                    )
            elif subtype in (int(FstMiscType.SOURCESTEM), int(FstMiscType.SOURCEISTEM)):
                pending_misc.append(attr)
                sidx = attr.arg_from_name or _parse_varint_from_attr_name(attr.name)
                stem = (self._source_paths.get(sidx, ""), int(attr.arg))
                if subtype == int(FstMiscType.SOURCESTEM):
                    pending_metadata = _metadata_replace(pending_metadata, source_stem=stem)
                else:
                    pending_metadata = _metadata_replace(
                        pending_metadata, source_instantiation_stem=stem
                    )
            else:
                # Preserve third-party/vendor MISC attrs and attach them to the
                # next variable.  No semantic interpretation is attempted; the
                # raw payload is exposed through describe_attribute().
                pending_misc.append(attr)

        while off < n:
            tag = data[off]
            off += 1
            if tag == FST_ST_VCD_SCOPE:
                if off >= n:
                    raise _FstFormatError("truncated scope")
                scope_type = data[off]; off += 1
                name, off = _read_cstr(data, off)
                component, off = _read_cstr(data, off)
                full = name if not cur_scope else cur_scope + "." + name
                scopes.append(cur_scope)
                cur_scope = full
                events.append(FstScope(scope_type, name, component, full))
            elif tag == FST_ST_VCD_UPSCOPE:
                events.append(FstUpscope())
                if scopes:
                    cur_scope = scopes.pop()
                else:
                    cur_scope = ""
            elif tag == FST_ST_GEN_ATTRBEGIN:
                if off + 2 > n:
                    raise _FstFormatError("truncated attrbegin")
                attr_type = data[off]; subtype = data[off + 1]; off += 2
                name_raw, off = _read_cstr_raw(data, off)
                arg, used = read_varint(data, off); off += used
                arg_from_name = 0
                if attr_type == int(FstAttrType.MISC) and subtype in (
                    int(FstMiscType.SOURCESTEM), int(FstMiscType.SOURCEISTEM)
                ):
                    try:
                        arg_from_name, _ = read_varint(name_raw, 0)
                    except Exception:
                        arg_from_name = 0
                name = _decode_attr_name(name_raw, attr_type, subtype)
                attr = FstAttrBegin(attr_type, subtype, name, arg, arg_from_name, name_raw)
                events.append(attr)
                self._attribute_events.append(attr)
                if attr_type == int(FstAttrType.MISC):
                    add_pending_misc(attr)
                else:
                    active_attrs.append(attr)
            elif tag == FST_ST_GEN_ATTREND:
                events.append(FstAttrEnd())
                if active_attrs:
                    active_attrs.pop()
            elif 0 <= tag <= FST_VT_MAX:
                direction = data[off]; off += 1
                name, off = _read_cstr(data, off)
                length, used = read_varint(data, off); off += used
                alias, used = read_varint(data, off); off += used
                if alias == 0:
                    current_handle += 1
                    handle = current_handle
                    is_alias = False
                else:
                    handle = alias
                    is_alias = True
                full = name if not cur_scope else cur_scope + "." + name
                active_tuple = tuple(active_attrs)
                misc_tuple = tuple(pending_misc)
                metadata = _metadata_replace(
                    pending_metadata,
                    active_attributes=active_tuple,
                    misc_attributes=misc_tuple,
                    array_attributes=tuple(
                        a for a in active_tuple if a.attr_type == int(FstAttrType.ARRAY)
                    ),
                    enum_attributes=tuple(
                        a for a in active_tuple if a.attr_type == int(FstAttrType.ENUM)
                    ),
                    pack_attributes=tuple(
                        a for a in active_tuple if a.attr_type == int(FstAttrType.PACK)
                    ),
                    all_attributes=active_tuple + misc_tuple,
                )
                self._attributes_by_handle[handle] = metadata.all_attributes
                events.append(FstVar(
                    tag, direction, name, length, handle, is_alias, full,
                    metadata.supplemental_var_type,
                    metadata.supplemental_data_type,
                    metadata.type_name,
                    metadata,
                ))
                pending_misc = []
                pending_metadata = FstSignalMetadata()
            elif tag == 0xFF and off == n:
                break
            else:
                raise _FstFormatError(
                    f"unknown hierarchy tag 0x{tag:02x} at offset {off - 1}"
                )
        return events

    def _parse_geometry_and_hierarchy(self) -> None:
        hier_data = self._extract_hierarchy()
        self._hierarchy_events = self._parse_hierarchy(hier_data)
        self._patch_signal_info_from_hierarchy()
        self._build_frame_prefix()

    def _patch_signal_info_from_hierarchy(self) -> None:
        """Fill or refine signal length/type arrays from hierarchy records.

        GEOM is authoritative for frame sizes when present, but it deliberately
        collapses most non-real types to "wire".  The hierarchy stream carries
        the real var_type, and older or utility-generated FSTs may omit GEOM.
        Mirror libfst's fallback: derive canonical handle lengths/types from
        hierarchy whenever GEOM is missing or incomplete, and use hierarchy to
        refine signal_types without changing GEOM-derived sizes.
        """
        max_handle = int(self.header.max_handle)
        if len(self._signal_lengths) < max_handle:
            self._signal_lengths.extend([1] * (max_handle - len(self._signal_lengths)))
        if len(self._signal_types) < max_handle:
            self._signal_types.extend([int(FstVarType.VCD_WIRE)] * (max_handle - len(self._signal_types)))

        for e in self._hierarchy_events:
            if not isinstance(e, FstVar) or e.is_alias:
                continue
            idx = e.handle - 1
            if idx < 0:
                continue
            while idx >= len(self._signal_lengths):
                self._signal_lengths.append(1)
                self._signal_types.append(int(FstVarType.VCD_WIRE))
            vt = int(e.var_type)
            self._signal_types[idx] = int(FstVarType.VCD_REAL) if vt in self.REAL_VAR_TYPES else vt
            # If GEOM was absent, derive the frame width from HIER.  If GEOM
            # exists, keep its frame sizes because they are the layout source
            # for VCDATA frame_data.
            if not getattr(self, "_has_geometry", False):
                if vt in self.REAL_VAR_TYPES:
                    self._signal_lengths[idx] = 8
                elif vt == int(FstVarType.GEN_STRING):
                    self._signal_lengths[idx] = 0
                else:
                    self._signal_lengths[idx] = int(e.length)

    def _build_frame_prefix(self) -> None:
        # Precompute frame data prefix offsets for O(1) get_initial_value.
        self._frame_prefix: list[int] = [0]
        for sl in self._signal_lengths:
            self._frame_prefix.append(self._frame_prefix[-1] + max(0, int(sl)))

    def _build_handle_map(self) -> None:
        """Build handle->FstVar lookup dict.

        The first (non-alias) var for each handle is canonical.
        Subsequent aliases are stored in _vars_by_handle.
        """
        for e in self._hierarchy_events:
            if isinstance(e, FstVar):
                if e.handle not in self._handle_to_var:
                    self._handle_to_var[e.handle] = e
                self._vars_by_handle.setdefault(e.handle, []).append(e)

    def _build_signal_index(self) -> None:
        """Build name/handle indexes for random-access signal lookup."""
        self._full_name_to_handles: dict[str, list[int]] = {}
        self._short_name_to_handles: dict[str, list[int]] = {}
        self._handle_to_full_names: dict[int, list[str]] = {}
        for var in self.vars():
            self._full_name_to_handles.setdefault(var.full_name, []).append(var.handle)
            self._short_name_to_handles.setdefault(var.name, []).append(var.handle)
            names = self._handle_to_full_names.setdefault(var.handle, [])
            if var.full_name not in names:
                names.append(var.full_name)

    @staticmethod
    def _is_vc_block(b: FstBlock) -> bool:
        return b.block_type in _FstReader.VCDATA_BLOCK_TYPES

    def _parse_vc_sections(self) -> None:
        """Parse VCDATA section headers only (beg_time, end_time, frame_data,
        vc_maxhandle, pack_type).  Time table and chain table are deferred to
        _ensure_section_parsed() — called lazily by iter_time_value_pairs /
        iter_value_changes on first access.  This makes info/list O(hierarchy)
        instead of O(hierarchy + all_sections × 223K_chain_entries).
        """
        vc_blocks = [b for b in self._blocks if self._is_vc_block(b)]
        if not vc_blocks:
            return
        for block in vc_blocks:
            sect = _VcSection(
                block_offset=block.offset,
                block_type=block.block_type,
                section_length=block.section_length,
                beg_time=0, end_time=0,
            )
            payload = block.payload
            off = 0
            if len(payload) < 24:
                raise _FstFormatError("truncated VCDATA header")
            sect.beg_time = _u64be(payload, off); off += 8
            sect.end_time = _u64be(payload, off); off += 8
            off += 8
            frame_uclen, used = read_varint64(payload, off); off += used
            frame_clen, used2 = read_varint64(payload, off); off += used2
            frame_maxhandle, used3 = read_varint64(payload, off); off += used3
            sect.frame_uclen = frame_uclen
            sect.frame_clen = frame_clen
            sect.frame_maxhandle = frame_maxhandle
            frame_raw = payload[off:off + frame_clen]
            off += frame_clen
            if frame_uclen == frame_clen:
                sect.frame_data = frame_raw
            else:
                sect.frame_data = zlib.decompress(frame_raw)
            sect.vc_maxhandle, used4 = read_varint64(payload, off); off += used4
            sect.vc_start = off  # position of pack_type byte
            if off >= len(payload):
                raise _FstFormatError("truncated VCDATA before pack type")
            sect.pack_type = chr(payload[off])
            off += 1
            sect._payload = payload
            self._vc_sections.append(sect)

    def _ensure_section_parsed(self, section_index: int) -> None:
        """Parse time_table and chain_table for a section on first access."""
        sect = self._vc_sections[section_index]
        if sect._parsed:
            return
        payload = sect._payload
        if payload is None:
            raise _FstFormatError("section payload not available for lazy parse")
        sect.times = self._parse_time_table(payload)
        self._parse_chain_table(sect, payload)
        sect._payload = None
        sect._parsed = True

    def _ensure_all_sections_parsed(self) -> None:
        """Bulk-parse all unparsed sections.

        Full-scan commands (summary, search, dump --limit 0) need every
        section.  When ≥4 sections are unparsed, uses multiprocessing to
        parallelize across CPU cores (varint decoding is CPU-bound).
        Falls back to sequential on any error (Windows/spawn, pickling, etc).
        """
        unparsed = [(i, s) for i, s in enumerate(self._vc_sections)
                    if not s._parsed and s._payload is not None]
        if not unparsed:
            return
        import os
        if len(unparsed) >= 4 and (os.cpu_count() or 1) >= 2:
            try:
                self._parallel_parse_sections(unparsed)
                return
            except Exception:
                pass  # fall back to sequential
        for i, sect in unparsed:
            if sect._parsed:
                continue
            self._ensure_section_parsed(i)

    def _parallel_parse_sections(self, unparsed) -> None:
        """Parse multiple sections in parallel using fork-based workers."""
        import os
        from concurrent.futures import ProcessPoolExecutor

        global _g_fst_reader
        _g_fst_reader = self

        n_workers = min(len(unparsed), os.cpu_count() or 4, 4)
        indices = [i for i, _ in unparsed]

        try:
            with ProcessPoolExecutor(max_workers=n_workers) as pool:
                results = list(pool.map(_parse_section_worker, indices))
        finally:
            _g_fst_reader = None

        for (idx, sect), (times, ct, ctl) in zip(unparsed, results):
            sect.times = times
            sect.chain_table = ct
            sect.chain_table_lengths = ctl
            sect._payload = None
            sect._parsed = True

    def _build_section_time_index(self) -> None:
        """Build section begin/end arrays for time-window queries."""
        self._section_beg_times: list[int] = [int(s.beg_time) for s in self._vc_sections]
        self._section_end_times: list[int] = [int(s.end_time) for s in self._vc_sections]

    def _parse_time_table(self, payload: bytes) -> list[int]:
        n = len(payload)
        if n < 24:
            raise _FstFormatError("truncated VCDATA time section")
        tsec_uclen = _u64be(payload, n - 24)
        tsec_clen = _u64be(payload, n - 16)
        tsec_nitems = _u64be(payload, n - 8)
        tsec_start = n - 24 - tsec_clen
        if tsec_start < 0:
            raise _FstFormatError("invalid VCDATA time section offset")
        compressed = payload[tsec_start:tsec_start + tsec_clen]
        if tsec_uclen == tsec_clen:
            ucdata = compressed
        else:
            ucdata = zlib.decompress(compressed)
        times: list[int] = []
        tpval = 0
        off = 0
        for _ in range(tsec_nitems):
            val, used = read_varint64(ucdata, off)
            tpval += val
            times.append(tpval)
            off += used
        # Build O(1) lookup for cumulative time indices
        self._time_to_index: dict[int, int] = {t: i for i, t in enumerate(times)}
        return times

    def _parse_chain_table(self, sect: _VcSection, payload: bytes) -> None:
        n = len(payload)
        tsec_clen = _u64be(payload, n - 16)
        indx_pntr = n - 24 - tsec_clen - 8
        if indx_pntr < 0:
            raise _FstFormatError("invalid chain table position")
        chain_clen = _u64be(payload, indx_pntr)
        indx_pos = indx_pntr - chain_clen
        if indx_pos < 0:
            raise _FstFormatError("invalid chain table offset")
        chain_data = payload[indx_pos:indx_pos + chain_clen]
        sect.indx_pos = indx_pos
        sect.indx_len = chain_clen
        vc_maxhandle = sect.vc_maxhandle
        chain_table: list[int] = [0] * (vc_maxhandle + 2)
        chain_table_lengths: list[int] = [0] * (vc_maxhandle + 2)
        pnt = 0
        idx = 0
        pval = 0
        pidx = -1
        if sect.block_type == FST_BL_VCDATA_DYN_ALIAS2:
            prev_alias = 0
            while pnt < chain_clen:
                if chain_data[pnt] & 0x01:
                    shval, skiplen = read_svarint64(chain_data, pnt)
                    shval >>= 1
                    if shval > 0:
                        pval += shval
                        chain_table[idx] = pval
                        if pidx >= 0:
                            chain_table_lengths[pidx] = pval - chain_table[pidx]
                        pidx = idx
                        idx += 1
                    elif shval < 0:
                        chain_table[idx] = 0
                        chain_table_lengths[idx] = shval
                        prev_alias = shval
                        idx += 1
                    else:
                        chain_table[idx] = 0
                        chain_table_lengths[idx] = prev_alias
                        idx += 1
                else:
                    val, skiplen = read_varint32(chain_data, pnt)
                    loopcnt = val >> 1
                    for _ in range(loopcnt):
                        chain_table[idx] = 0
                        idx += 1
                pnt += skiplen
        else:
            while pnt < chain_clen:
                val, skiplen = read_varint32(chain_data, pnt)
                if not val:
                    pnt += skiplen
                    val, skiplen = read_varint32(chain_data, pnt)
                    chain_table[idx] = 0
                    chain_table_lengths[idx] = -val
                    idx += 1
                elif val & 1:
                    pval += (val >> 1)
                    chain_table[idx] = pval
                    if pidx >= 0:
                        chain_table_lengths[pidx] = pval - chain_table[pidx]
                    pidx = idx
                    idx += 1
                else:
                    loopcnt = val >> 1
                    for _ in range(loopcnt):
                        chain_table[idx] = 0
                        idx += 1
                pnt += skiplen
        chain_table[idx] = indx_pos - sect.vc_start
        if pidx >= 0:
            chain_table_lengths[pidx] = chain_table[idx] - chain_table[pidx]
        for i in range(idx):
            v = chain_table_lengths[i]
            if v < 0 and chain_table[i] == 0:
                v = -v
                v -= 1
                if v < i:
                    chain_table[i] = chain_table[v]
                    chain_table_lengths[i] = chain_table_lengths[v]
        sect.chain_table = chain_table[:idx]
        sect.chain_table_lengths = chain_table_lengths[:idx]

    def _parse_blackouts(self) -> None:
        self._blackouts: list[tuple[int, bool]] = []
        for b in self._blocks:
            if b.block_type == FST_BL_BLACKOUT:
                p = b.payload
                if len(p) < 2:
                    continue
                num, used = read_varint(p, 0)
                off = used
                cur_time = 0
                for _ in range(num):
                    if off >= len(p):
                        break
                    active = p[off] != 0
                    off += 1
                    delta, used2 = read_varint64(p, off)
                    off += used2
                    cur_time += delta
                    self._blackouts.append((cur_time, active))

    @property
    def blackouts(self) -> list[tuple[int, bool]]:
        """Blackout transitions as ``(time, is_dump_active)``.

        This mirrors libfst's ``blackout_times`` / ``blackout_activity``
        arrays.  Event iterators keep raw VCDATA behavior by default; pass
        ``respect_blackout=True`` to suppress events while dump is inactive.
        """
        return list(self._blackouts)

    def is_dump_active_at(self, time: int) -> bool:
        """Return dump-active state after applying blackout transitions <= time.

        Uses a precomputed transition array, so per-event blackout checks are
        O(log N) rather than scanning every transition.
        """
        if not self._blackout_times:
            return True
        idx = bisect.bisect_right(self._blackout_times, int(time)) - 1
        return True if idx < 0 else bool(self._blackout_states[idx])

    def iter_blackout_intervals(
        self, start: int | None = None, end: int | None = None,
    ) -> Iterator[tuple[int, int | None, bool]]:
        """Yield dump-active intervals as ``(begin, end, active)``.

        ``end`` is exclusive and may be ``None`` for the final open interval.
        ``start``/``end`` trim the yielded intervals but do not mutate the
        underlying blackout transitions.
        """
        lo = self.header.start_time if start is None else int(start)
        hi = self.header.end_time if end is None else int(end)
        points = [(lo, self.is_dump_active_at(lo))]
        points.extend((t, a) for t, a in self._blackouts if lo < t < hi)
        for i, (t, active) in enumerate(points):
            nt = points[i + 1][0] if i + 1 < len(points) else hi
            if nt > t:
                yield (t, nt, active)

    @property
    def comments(self) -> list[str]:
        return list(self._comments)

    @property
    def env_vars(self) -> list[str]:
        return list(self._env_vars)

    @property
    def value_lists(self) -> list[str]:
        return list(self._value_lists)

    @property
    def enum_tables(self) -> dict[int, dict]:
        return dict(self._enum_tables)

    @property
    def source_paths(self) -> dict[int, str]:
        return dict(self._source_paths)

    def attributes(self, *, decoded: bool = False) -> list:
        """Return all parsed FST hierarchy attributes.

        ``decoded=False`` returns the raw ``FstAttrBegin`` records.
        ``decoded=True`` returns dictionaries with category/subtype names and
        decoded payloads where applicable.
        """
        if not decoded:
            return list(self._attribute_events)
        return [self.describe_attribute(a) for a in self._attribute_events]

    def attributes_for_handle(self, handle: int, *, decoded: bool = False) -> list:
        """Return attributes attached to a handle's hierarchy variable.

        This includes currently active ARRAY/ENUM/PACK attributes plus MISC
        helper attributes immediately preceding that variable.
        """
        attrs = list(self._attributes_by_handle.get(handle, ()))
        if not decoded:
            return attrs
        return [self.describe_attribute(a) for a in attrs]

    def describe_attribute(self, attr: FstAttrBegin) -> dict:
        """Decode one FST hierarchy attribute into a structured dictionary.

        Tool-specific/unknown payloads are not semantically guessed.  They are
        nevertheless reported losslessly through the ``payload`` field, which
        contains safe ASCII/escaped/hex/base64 views of the raw hierarchy
        attribute name/payload bytes.
        """
        return _describe_attribute(attr, self._source_paths, self._enum_tables)

    def attribute_payload(self, attr: FstAttrBegin) -> dict:
        """Return safe textual views of one attribute's raw payload bytes."""
        return _attribute_payload_report(attr)

    def attribute_report(self, *, decoded: bool = True) -> list[dict]:
        """Return a report-friendly list of all hierarchy attributes.

        ``decoded=True`` includes category/subtype names plus payload readouts.
        ``decoded=False`` returns a compact raw numeric report while still
        including the escaped payload text.
        """
        if decoded:
            return [self.describe_attribute(a) for a in self._attribute_events]
        return [
            {
                "attr_type": int(a.attr_type),
                "subtype": int(a.subtype),
                "arg": int(a.arg),
                "arg_from_name": int(a.arg_from_name),
                "payload": _attribute_payload_report(a),
            }
            for a in self._attribute_events
        ]

    def attribute_report_text(self) -> str:
        """Return a human-readable text report of all hierarchy attrs."""
        lines: list[str] = []
        for idx, attr in enumerate(self._attribute_events):
            desc = self.describe_attribute(attr)
            payload = desc["payload"]
            lines.append(
                f"[{idx}] {desc['attr_type_name']}/{desc['subtype_name']} "
                f"arg={desc['arg']} payload={payload['ascii_escaped']}"
            )
            if payload["hex"]:
                lines.append(f"    hex={payload['hex']}")
        return "\n".join(lines)

    def iter_vcd_extension_lines(self) -> Iterator[str]:
        """Yield libfst-style VCD extension lines for hierarchy attributes.

        This is not a full FST-to-VCD exporter.  It is a lossless textual view
        of the ATTRBEGIN/ATTREND/comment metadata already present in the FST
        hierarchy stream, following the formatting used by libfst when
        ``use_vcd_extensions`` is enabled.
        """
        for event in self._hierarchy_events:
            if isinstance(event, FstAttrBegin):
                yield from _format_attr_as_vcd_extension(event)
            elif isinstance(event, FstAttrEnd):
                yield "$attrend $end"

    def metadata_for_handle(self, handle: int) -> FstSignalMetadata | None:
        var = self._handle_to_var.get(handle)
        return var.metadata if var is not None else None

    @property
    def num_handles(self) -> int:
        return self.header.max_handle

    @property
    def signal_lengths(self) -> list[int]:
        return self._signal_lengths

    @property
    def signal_types(self) -> list[int]:
        return self._signal_types

    def is_string_handle(self, handle: int) -> bool:
        idx = handle - 1
        if idx < 0 or idx >= len(self._signal_lengths):
            return False
        return self._signal_lengths[idx] == 0

    def is_real_handle(self, handle: int) -> bool:
        idx = handle - 1
        if idx < 0 or idx >= len(self._signal_types):
            return False
        return self._signal_types[idx] == int(FstVarType.VCD_REAL)

    def decode_value(self, handle: int, value: bytes):
        """Decode a raw FST value into a convenient Python value.

        Fixed-width scalar/vector values are returned as ASCII strings.
        GEN_STRING values remain bytes so binary payloads are preserved.
        Real values are returned as Python float using the file's double
        endian marker, matching libfst's callback conversion mode.
        """
        if self.is_real_handle(handle):
            if len(value) < 8:
                raise _FstFormatError(f"real value for handle {handle} is shorter than 8 bytes")
            fmt = "<d" if self.header.double_endian_match else ">d"
            return struct.unpack(fmt, value[:8])[0]
        if self.is_string_handle(handle):
            return bytes(value)
        return bytes(value).decode("ascii", errors="replace")

    # ------------------------------------------------------------------
    # Stable file/structure information API
    # ------------------------------------------------------------------

    def get_version_string(self) -> str:
        """Return the simulator/writer version string from the FST header."""
        return self.header.version

    def get_date_string(self) -> str:
        """Return the date string from the FST header."""
        return self.header.date

    def get_file_type(self) -> int:
        """Return the libfst file type code from the FST header."""
        return int(self.header.filetype)

    def get_var_count(self) -> int:
        """Return the variable count reported by the FST header."""
        return int(self.header.var_count)

    def get_scope_count(self) -> int:
        """Return the scope count reported by the FST header."""
        return int(self.header.scope_count)

    def get_alias_count(self) -> int:
        """Return the number of alias variable declarations parsed from hierarchy."""
        return sum(1 for v in self.vars() if v.is_alias)

    def get_start_time(self) -> int:
        """Return the FST start time tick from the header."""
        return int(self.header.start_time)

    def get_end_time(self) -> int:
        """Return the FST end time tick from the header."""
        return int(self.header.end_time)

    def get_timescale(self) -> int:
        """Return the FST timescale exponent from the header."""
        return int(self.header.timescale)

    def get_timezero(self) -> int:
        """Return the signed FST timezero offset from the header."""
        return int(self.header.timezero)

    def get_value_change_section_count(self) -> int:
        """Return the value-change section count reported by the header."""
        return int(self.header.value_change_section_count)

    def get_max_handle(self) -> int:
        """Return the maximum canonical handle reported by the header."""
        return int(self.header.max_handle)

    def get_value_from_handle_at_time(
        self, handle: int | str, time: int, *, decoded: bool = False,
        respect_blackout: bool = False,
    ):
        """libfst-style wrapper around ``get_value_at()``."""
        return self.get_value_at(handle, time, decoded=decoded, respect_blackout=respect_blackout)

    def file_info(self) -> dict:
        """Return a stable, external-facing file overview.

        This replaces the old internal ``summary()`` helper.  The schema is
        intentionally compact and suitable for analyzer/list/info commands.
        """
        block_counts: dict[str, int] = {}
        for b in self._blocks:
            name = _enum_name(FstBlockType, b.block_type) or str(int(b.block_type))
            block_counts[name] = block_counts.get(name, 0) + 1
        try:
            size_bytes = self.path.stat().st_size
        except OSError:
            size_bytes = None
        return {
            "file": str(self.path),
            "size_bytes": size_bytes,
            "version": self.header.version,
            "date": self.header.date,
            "filetype": int(self.header.filetype),
            "filetype_name": _file_type_name(self.header.filetype),
            "timescale": int(self.header.timescale),
            "timezero": int(self.header.timezero),
            "start_time": int(self.header.start_time),
            "end_time": int(self.header.end_time),
            "var_count": int(self.header.var_count),
            "scope_count": int(self.header.scope_count),
            "alias_count": self.get_alias_count(),
            "max_handle": int(self.header.max_handle),
            "value_change_section_count": int(self.header.value_change_section_count),
            "parsed_value_change_section_count": len(self._vc_sections),
            "block_count": len(self._blocks),
            "block_types": block_counts,
            "blackout_count": len(self._blackouts),
            "comment_count": len(self._comments),
            "env_var_count": len(self._env_vars),
            "attribute_count": len(self._attribute_events),
            "mmap_backed": self._mmap is not None,
        }

    def block_table(self) -> list[dict]:
        """Return top-level FST block directory records."""
        return [
            {
                "index": i,
                "offset": int(b.offset),
                "block_type": int(b.block_type),
                "block_type_name": _enum_name(FstBlockType, b.block_type),
                "section_length": int(b.section_length),
                "payload_length": max(0, int(b.section_length) - 8),
            }
            for i, b in enumerate(self._blocks)
        ]

    def section_table(self) -> list[dict]:
        """Return parsed VCDATA section directory records."""
        return [
            {
                "index": i,
                "block_offset": int(s.block_offset),
                "block_type": int(s.block_type),
                "block_type_name": _enum_name(FstBlockType, s.block_type),
                "section_length": int(s.section_length),
                "begin_time": int(s.beg_time),
                "end_time": int(s.end_time),
                "time_count": len(s.times or []),
                "frame_uncompressed_length": int(s.frame_uclen),
                "frame_compressed_length": int(s.frame_clen),
                "frame_max_handle": int(s.frame_maxhandle),
                "vc_max_handle": int(s.vc_maxhandle),
                "pack_type": s.pack_type,
                "chain_count": len(s.chain_table or []),
            }
            for i, s in enumerate(self._vc_sections)
        ]

    def signal_table(self, *, include_aliases: bool = True) -> list[dict]:
        """Return one structured signal record per canonical handle."""
        return [
            self._signal_record(h, include_aliases=include_aliases)
            for h in sorted(self._handle_to_var)
        ]

    def signal_names(self, *, include_aliases: bool = True) -> list[str]:
        """Return full signal names known to the hierarchy index."""
        if include_aliases:
            return sorted(self._full_name_to_handles)
        return sorted(v.full_name for v in self._handle_to_var.values())

    def names_for_handle(self, handle: int) -> list[str]:
        """Return full hierarchy names associated with a handle."""
        return list(self._handle_to_full_names.get(int(handle), []))

    def find_handle(self, name: str, *, include_aliases: bool = True) -> int:
        """Return the first handle matching an exact full signal name.

        ``include_aliases=False`` restricts lookup to canonical handle names.
        Raises KeyError if the name is not present.  Use ``find_handles()`` for
        wildcard/regex matching or when multiple aliases should be preserved.
        """
        if include_aliases:
            handles = self._full_name_to_handles.get(str(name), [])
        else:
            handles = [h for h, v in self._handle_to_var.items() if v.full_name == str(name)]
        if not handles:
            raise KeyError(f"unknown signal name: {name}")
        return int(handles[0])

    def find_handles(
        self, pattern: str | None = None, *, regex: bool = False,
        include_aliases: bool = True, unique: bool = True,
    ) -> list[int]:
        """Find handles by full-name wildcard or regular expression.

        ``pattern=None`` returns all known handles.  Wildcards use
        ``fnmatchcase`` semantics; regex mode uses ``re.search``.  When
        ``unique=True`` aliases are collapsed to one handle value.
        """
        if include_aliases:
            items = self._full_name_to_handles.items()
        else:
            items = ((v.full_name, [h]) for h, v in self._handle_to_var.items())
        if pattern is None:
            out = [h for _, handles in items for h in handles]
        elif regex:
            rx = re.compile(pattern)
            out = [h for name, handles in items if rx.search(name) for h in handles]
        else:
            out = [h for name, handles in items if fnmatch.fnmatchcase(name, pattern) for h in handles]
        if unique:
            return sorted(set(int(h) for h in out))
        return [int(h) for h in out]

    def resolve_handle(
        self, query: int | str, *, regex: bool = False, include_aliases: bool = True
    ) -> int:
        """Resolve ``query`` to exactly one handle.

        This is the strict, script-friendly resolver.  Integer handles are
        returned unchanged.  String queries try exact full-name lookup first;
        if no exact match exists, wildcard or regex matching is used.  A
        missing query raises ``KeyError`` and an ambiguous query raises
        ``ValueError``.  CLI-style substring filtering is intentionally left to
        analyzer layers.
        """
        if not isinstance(query, str):
            return int(query)
        try:
            return self.find_handle(query, include_aliases=include_aliases)
        except KeyError:
            pass
        handles = self.find_handles(
            query, regex=regex, include_aliases=include_aliases, unique=True
        )
        if not handles:
            raise KeyError(f"unknown signal pattern: {query}")
        if len(handles) != 1:
            examples = []
            for h in handles[:5]:
                names = self.names_for_handle(h)
                examples.append(names[0] if names else str(h))
            raise ValueError(
                f"signal pattern {query!r} matches {len(handles)} handles"
                + (f": {', '.join(examples)}" if examples else "")
            )
        return int(handles[0])

    def _resolve_handle(self, handle_or_name: int | str) -> int:
        return self.resolve_handle(handle_or_name)

    def _signal_record(self, handle: int, *, include_aliases: bool = True) -> dict:
        h = int(handle)
        var = self._handle_to_var.get(h)
        names = self.names_for_handle(h)
        canonical = var.full_name if var is not None else (names[0] if names else "")
        width = self._signal_lengths[h - 1] if 0 < h <= len(self._signal_lengths) else None
        sig_type = self._signal_types[h - 1] if 0 < h <= len(self._signal_types) else (var.var_type if var else None)
        rec = {
            "handle": h,
            "name": canonical,
            "path": canonical,
            "width": width,
            "type": sig_type,
            "type_name": _enum_name(FstVarType, sig_type),
            "direction": var.direction if var is not None else None,
            "direction_name": _enum_name(FstVarDir, var.direction) if var is not None else "",
            "is_string": self.is_string_handle(h),
            "is_real": self.is_real_handle(h),
            "metadata": _metadata_summary(self.metadata_for_handle(h)),
        }
        if include_aliases:
            rec["aliases"] = names
        return rec

    def find_signal(self, name: str, *, include_aliases: bool = True) -> dict:
        """Return the signal record for an exact full signal name."""
        return self._signal_record(self.find_handle(name, include_aliases=include_aliases), include_aliases=include_aliases)

    def find_signals(
        self, pattern: str | None = None, *, regex: bool = False,
        include_aliases: bool = True, unique: bool = True,
    ) -> list[dict]:
        """Return signal records matching ``pattern``.

        This is the structured counterpart of ``find_handles()``.  Matching is
        exact-all when ``pattern`` is ``None``, regex when ``regex=True``, and
        shell-style wildcard otherwise.
        """
        return [
            self._signal_record(h, include_aliases=include_aliases)
            for h in self.find_handles(pattern, regex=regex, include_aliases=include_aliases, unique=unique)
        ]

    def sections_overlapping(self, start: int | None = None, end: int | None = None) -> list[int]:
        """Return VCDATA section indexes whose time range overlaps [start, end].

        This is the section-level time index used by random-access queries.
        It skips sections whose ``end_time < start`` or ``beg_time > end``.
        """
        if not self._vc_sections:
            return []
        lo = self.header.start_time if start is None else int(start)
        hi = self.header.end_time if end is None else int(end)
        if hi < lo:
            return []
        idx = bisect.bisect_left(self._section_end_times, lo)
        out: list[int] = []
        while idx < len(self._vc_sections) and self._section_beg_times[idx] <= hi:
            if self._section_end_times[idx] >= lo:
                out.append(idx)
            idx += 1
        return out

    def section_for_time(self, time: int) -> int | None:
        """Return the section whose frame should be used for ``time``.

        If ``time`` falls in a gap after a section, the preceding section is
        returned because signal values persist until changed.  If ``time`` is
        before the first section, section 0 is returned so callers can use the
        first frame snapshot.
        """
        if not self._vc_sections:
            return None
        t = int(time)
        idx = bisect.bisect_right(self._section_beg_times, t) - 1
        if idx < 0:
            return 0
        if idx >= len(self._vc_sections):
            return len(self._vc_sections) - 1
        return idx

    def section_at_time(self, time: int) -> int | None:
        """Alias for ``section_for_time()`` with a more direct name."""
        return self.section_for_time(time)

    def get_value_at(
        self, handle: int | str, time: int, *, decoded: bool = False,
        respect_blackout: bool = False,
    ):
        """Return a handle's value at ``time`` using section/frame indexing.

        Only the selected handle's chain in the relevant section is decoded.
        With ``respect_blackout=True``, ``None`` is returned when the queried
        time is in a dump-inactive interval.
        """
        h = self._resolve_handle(handle)
        t = int(time)
        if respect_blackout and not self.is_dump_active_at(t):
            return None
        section_index = self.section_for_time(t)
        if section_index is None:
            return None
        val = self.get_initial_value(h, section_index)
        for et, ev in self.iter_value_changes(h, section_index, respect_blackout=respect_blackout):
            if et > t:
                break
            val = ev
        return self.decode_value(h, val) if decoded else val

    def iter_value_changes_range(
        self, handle: int | str, start: int | None = None, end: int | None = None,
        *, include_initial: bool = False, respect_blackout: bool = False,
    ) -> Iterator[tuple[int, bytes]]:
        """Iterate one signal's changes within a time window.

        The reader first skips non-overlapping VCDATA sections, then decodes
        only this handle's chain in the remaining sections.  When
        ``include_initial=True``, a synthetic snapshot at ``start`` is emitted
        first and explicit changes at exactly ``start`` are suppressed because
        the snapshot already includes them.
        """
        h = self._resolve_handle(handle)
        lo = self.header.start_time if start is None else int(start)
        hi = self.header.end_time if end is None else int(end)
        if hi < lo:
            return
        if include_initial:
            init = self.get_value_at(h, lo, respect_blackout=respect_blackout)
            if init is not None:
                yield lo, init
        for section_index in self.sections_overlapping(lo, hi):
            for t, v in self.iter_value_changes(
                h, section_index, respect_blackout=respect_blackout,
                _include_section_initial=False,
            ):
                if t < lo or (include_initial and t <= lo):
                    continue
                if t > hi:
                    break
                yield t, v

    def iter_decoded_value_changes_range(
        self, handle: int | str, start: int | None = None, end: int | None = None,
        *, include_initial: bool = False, respect_blackout: bool = False,
    ) -> Iterator[tuple[int, object]]:
        h = self._resolve_handle(handle)
        for t, v in self.iter_value_changes_range(
            h, start, end, include_initial=include_initial, respect_blackout=respect_blackout
        ):
            yield t, self.decode_value(h, v)

    def iter_selected_changes(
        self, handles: list[int | str] | tuple[int | str, ...],
        start: int | None = None, end: int | None = None, *,
        include_initial: bool = False, decoded: bool = False,
        respect_blackout: bool = False,
    ) -> Iterator[tuple[int, list[tuple[int, object]]]]:
        """Iterate selected signal changes grouped by time.

        This is the API intended for wavecut/agent queries: it decodes only the
        requested handles, groups their events by timestamp, and skips
        non-overlapping sections.
        """
        resolved = [self._resolve_handle(h) for h in handles]
        heap: list[tuple[int, int, int, bytes, Iterator[tuple[int, bytes]]]] = []
        for seq, h in enumerate(resolved):
            it = self.iter_value_changes_range(
                h, start, end, include_initial=include_initial, respect_blackout=respect_blackout
            )
            try:
                t, v = next(it)
            except StopIteration:
                continue
            heapq.heappush(heap, (int(t), seq, h, v, it))

        while heap:
            t = heap[0][0]
            changes: list[tuple[int, object]] = []
            pending_next: list[tuple[int, int, int, bytes, Iterator[tuple[int, bytes]]]] = []
            while heap and heap[0][0] == t:
                _, seq, h, v, it = heapq.heappop(heap)
                changes.append((h, self.decode_value(h, v) if decoded else v))
                try:
                    nt, nv = next(it)
                except StopIteration:
                    continue
                pending_next.append((int(nt), seq, h, nv, it))
            for item in pending_next:
                heapq.heappush(heap, item)
            yield t, changes

    def iter_events(
        self, start: int | None = None, end: int | None = None,
        handles: list[int | str] | tuple[int | str, ...] | None = None,
        *, decoded: bool = False, include_initial: bool = False,
        respect_blackout: bool = False,
    ) -> Iterator[tuple[int, int, object]]:
        """Yield a flat selected event stream: ``(time, handle, value)``.

        This is the FST counterpart to a VCD parser's selected event iterator.
        It is a thin wrapper over ``iter_selected_changes()`` and decodes only
        requested handles.  ``handles=None`` means all canonical handles.
        """
        if handles is None:
            handles = sorted(self._handle_to_var)
        for t, changes in self.iter_selected_changes(
            handles, start=start, end=end, include_initial=include_initial,
            decoded=decoded, respect_blackout=respect_blackout,
        ):
            for h, value in changes:
                yield t, h, value

    def iter_event_groups(
        self, start: int | None = None, end: int | None = None,
        handles: list[int | str] | tuple[int | str, ...] | None = None,
        *, decoded: bool = False, include_initial: bool = False,
        respect_blackout: bool = False,
    ) -> Iterator[tuple[int, list[tuple[int, object]]]]:
        """Yield selected changes grouped by timestamp.

        This is the script-friendly name for ``iter_selected_changes()``.
        ``handles=None`` means all canonical handles.
        """
        if handles is None:
            handles = sorted(self._handle_to_var)
        yield from self.iter_selected_changes(
            handles, start=start, end=end, include_initial=include_initial,
            decoded=decoded, respect_blackout=respect_blackout,
        )

    def snapshot_at(
        self, time: int, handles: list[int | str] | tuple[int | str, ...] | None = None,
        *, decoded: bool = False, respect_blackout: bool = False,
    ) -> dict[int, object]:
        """Return selected signal values at ``time``.

        The implementation uses section frames and per-handle chains; it does
        not materialize a full-file event stream.  ``handles=None`` returns all
        canonical handles, which can be expensive for very large files.
        """
        if handles is None:
            resolved = sorted(self._handle_to_var)
        else:
            resolved = [self._resolve_handle(h) for h in handles]
        return {
            h: self.get_value_at(h, time, decoded=decoded, respect_blackout=respect_blackout)
            for h in resolved
        }

    def format_value(self, handle: int | str, value) -> str:
        """Return a human-readable representation for a raw or decoded value."""
        h = self._resolve_handle(handle)
        if value is None:
            return "(inactive)"
        if isinstance(value, bytes):
            if self.is_real_handle(h):
                return repr(self.decode_value(h, value))
            if self.is_string_handle(h):
                try:
                    return value.decode("utf-8")
                except UnicodeDecodeError:
                    return value.hex()
            text = value.decode("ascii", errors="replace")
        else:
            if isinstance(value, float):
                return repr(value)
            text = str(value)
        width = self._signal_lengths[h - 1] if 0 < h <= len(self._signal_lengths) else 0
        if width <= 1:
            return text
        if any(ch in text.lower() for ch in ("x", "z")):
            return "b" + text
        try:
            intval = int(text, 2)
        except ValueError:
            return text
        hex_width = max(1, (int(width) + 3) // 4)
        return f"{intval} (0x{intval:0{hex_width}x})"

    # More explicit alias for callers that prefer value-oriented naming.
    iter_selected_value_changes = iter_selected_changes

    def get_initial_value_decoded(self, handle: int, section_index: int = 0):
        return self.decode_value(handle, self.get_initial_value(handle, section_index))

    def iter_decoded_value_changes(
        self, handle: int, section_index: int = 0,
    ) -> Iterator[tuple[int, object]]:
        for t, v in self.iter_value_changes(handle, section_index):
            yield t, self.decode_value(handle, v)

    def iter_value_changes_all(
        self, handle: int, *, include_initial: bool = False, respect_blackout: bool = False,
    ) -> Iterator[tuple[int, bytes]]:
        """Iterate a handle's value changes across all VCDATA sections.

        include_initial=True emits each section's frame value before that
        section's explicit changes.  This is useful for waveform slicing,
        where a time-window boundary needs a correct starting snapshot.
        """
        for section_index, sect in enumerate(self._vc_sections):
            if include_initial and (not respect_blackout or self.is_dump_active_at(sect.beg_time)):
                yield sect.beg_time, self.get_initial_value(handle, section_index)
            yield from self.iter_value_changes(handle, section_index, respect_blackout=respect_blackout)

    def iter_decoded_value_changes_all(
        self, handle: int, *, include_initial: bool = False, respect_blackout: bool = False,
    ) -> Iterator[tuple[int, object]]:
        for t, v in self.iter_value_changes_all(handle, include_initial=include_initial, respect_blackout=respect_blackout):
            yield t, self.decode_value(handle, v)

    def vars(self) -> list[FstVar]:
        return [e for e in self._hierarchy_events if isinstance(e, FstVar)]

    @property
    def handle_to_var(self) -> dict[int, 'FstVar']:
        """Map signal handle (1-indexed) to canonical FstVar."""
        return self._handle_to_var

    def vars_by_handle(self, handle: int) -> list['FstVar']:
        """Return all FstVar entries (canonical + aliases) for a handle."""
        return self._vars_by_handle.get(handle, [])

    def scopes(self) -> list[FstScope]:
        return [e for e in self._hierarchy_events if isinstance(e, FstScope)]

    def hierarchy(self) -> list:
        return list(self._hierarchy_events)

    @property
    def vc_sections(self) -> list[_VcSection]:
        return self._vc_sections

    def get_initial_value(self, handle: int, section_index: int = 0) -> bytes:
        if section_index >= len(self._vc_sections):
            raise IndexError(f"section_index {section_index} out of range")
        sect = self._vc_sections[section_index]
        idx = handle - 1
        if idx < 0 or idx >= len(self._signal_lengths):
            raise IndexError(f"handle {handle} out of range")
        off = self._frame_prefix[idx]
        sig_len = self._signal_lengths[idx]
        return sect.frame_data[off:off + sig_len]

    def iter_value_changes(
        self, handle: int, section_index: int = 0, *, respect_blackout: bool = False,
        _include_section_initial: bool = True,
    ) -> Iterator[tuple[int, bytes]]:
        if section_index >= len(self._vc_sections):
            return
        self._ensure_section_parsed(section_index)
        sect = self._vc_sections[section_index]
        idx = handle - 1

        if idx >= len(sect.chain_table) or idx >= len(sect.chain_table_lengths):
            if _include_section_initial:
                initial = self.get_initial_value(handle, section_index)
                if not respect_blackout or self.is_dump_active_at(sect.beg_time):
                    yield (sect.beg_time, initial)
            return

        chain_off = sect.chain_table[idx]
        chain_len = sect.chain_table_lengths[idx]

        # Negative chain_len: dynamic alias, return only the initial value
        if chain_len < 0:
            if _include_section_initial and (not respect_blackout or self.is_dump_active_at(sect.beg_time)):
                yield (sect.beg_time, self.get_initial_value(handle, section_index))
            return

        if chain_off <= 0 or chain_len <= 0:
            if idx < len(self._signal_lengths) and not self._signal_lengths[idx]:
                return  # string with no data: emit nothing (C reader behavior)
            if _include_section_initial and (not respect_blackout or self.is_dump_active_at(sect.beg_time)):
                yield (sect.beg_time, self.get_initial_value(handle, section_index))
            return
        payload = self._data
        vc_data_start = sect.block_offset + 9 + sect.vc_start
        vc_data = payload[vc_data_start + chain_off:vc_data_start + chain_off + chain_len]
        sig_len = self._signal_lengths[idx]
        times = sect.times

        # First varint: compressed size (0 = uncompressed)
        comp_size, cskip = read_varint(vc_data, 0)
        if comp_size:
            # Compressed data follows
            comp_body = vc_data[cskip:cskip + chain_len]
            if not comp_body:
                return
            vc_data = decompress_block(comp_body, sect.pack_type, comp_size)
        else:
            # Uncompressed: skip the marker
            vc_data = vc_data[cskip:]
        off = 0
        n = len(vc_data)
        tidx = 0
        while off < n:
            vli, skiplen = read_varint(vc_data, off)
            off += skiplen
            if sig_len == 0:
                # variable-length string: (tdelta, length, bytes)
                if vli & 1:
                    break  # unknown encoding
                tidx += vli >> 1
                length, lskip = read_varint(vc_data, off)
                off += lskip
                val = bytes(vc_data[off:off + length])
                off += length
                if tidx >= len(times):
                    break
                if not respect_blackout or self.is_dump_active_at(times[tidx]):
                    yield (times[tidx], val)
                continue
            if sig_len <= 1:
                # Single-bit: value encoded in vli
                if not (vli & 1):
                    shamt = 2 << (vli & 1)
                    tidx += vli >> shamt
                    val_byte = ((vli >> 1) & 1) | 0x30
                else:
                    shamt = 2 << (vli & 1)
                    tidx += vli >> shamt
                    val_byte = FST_RCV_STR[((vli >> 1) & 7)]
                val = bytes([val_byte])
            else:
                tidx += vli >> 1
                if not (vli & 1):
                    byte_len = (sig_len + 7) // 8
                    raw = bytearray(sig_len)
                    for j in range(sig_len):
                        bp = j // 8
                        bit = 7 - (j & 7)
                        ch = ((vc_data[off + bp] >> bit) & 1) | 0x30
                        raw[j] = ch
                    val = bytes(raw)
                    off += byte_len
                else:
                    val = vc_data[off:off + sig_len]
                    off += sig_len
            if tidx >= len(times):
                break
            if not respect_blackout or self.is_dump_active_at(times[tidx]):
                yield (times[tidx], val)

    def iter_time_value_pairs(
        self, section_index: int = 0, *, respect_blackout: bool = False,
    ) -> Iterator[tuple[int, list[tuple[int, bytes]]]]:
        """Yield time-ordered changes for one VCDATA section.

        Empty frame-only sections are valid FST and yield the section snapshot
        at beg_time.  Dynamic-alias chain-table entries are already resolved in
        _parse_chain_table, matching libfst's chain reuse behavior.
        """
        if section_index >= len(self._vc_sections):
            return
        self._ensure_section_parsed(section_index)
        sect = self._vc_sections[section_index]
        times = sect.times or []
        max_handle = self.header.max_handle
        sig_lens = list(self._signal_lengths)
        sig_typs = list(self._signal_types)
        while len(sig_lens) < max_handle:
            sig_lens.append(1)
        while len(sig_typs) < max_handle:
            sig_typs.append(int(FstVarType.VCD_WIRE))

        initial_vals: list[tuple[int, bytes]] = []
        frame_off = 0
        for idx in range(max_handle):
            sl = max(0, sig_lens[idx])
            initial_vals.append((idx + 1, sect.frame_data[frame_off:frame_off + sl]))
            frame_off += sl

        if not times:
            if initial_vals and (not respect_blackout or self.is_dump_active_at(sect.beg_time)):
                yield (sect.beg_time, initial_vals)
            return

        tc_head: list[int] = [0] * len(times)
        scatterptr: list[int] = [0] * max_handle
        headptr: list[int] = [0] * max_handle
        length_remaining: list[int] = [0] * max_handle
        traversal_buf = bytearray()
        for idx in range(max_handle):
            if idx >= len(sect.chain_table):
                continue
            chain_off = sect.chain_table[idx]
            chain_len = sect.chain_table_lengths[idx]
            if chain_off <= 0 or chain_len <= 0:
                continue
            vc_data_start = sect.block_offset + 9 + sect.vc_start
            start = vc_data_start + chain_off
            raw_compressed = self._data[start:start + chain_len]
            try:
                first_val, skiplen = read_varint32(raw_compressed, 0)
            except _FstFormatError:
                continue
            dest_len = first_val
            if first_val:
                comp_data = raw_compressed[skiplen:]
                if not comp_data:
                    continue
                decompressed = decompress_block(comp_data, sect.pack_type, dest_len)
            else:
                dest_len = chain_len - skiplen
                decompressed = raw_compressed[skiplen:skiplen + dest_len]
            if not decompressed:
                continue
            hptr = len(traversal_buf)
            traversal_buf.extend(decompressed)
            headptr[idx] = hptr
            length_remaining[idx] = dest_len
            vli = peek_varint32(traversal_buf, hptr)
            if sig_lens[idx] == 1:
                shcnt = 2 << (vli & 1)
                tdelta = vli >> shcnt
            else:
                tdelta = vli >> 1
            if tdelta < len(times):
                scatterptr[idx] = tc_head[tdelta]
                tc_head[tdelta] = idx + 1

        if sect.beg_time != times[0] and (not respect_blackout or self.is_dump_active_at(sect.beg_time)):
            yield (sect.beg_time, initial_vals)
        for ti in range(len(times)):
            changes: list[tuple[int, bytes]] = []
            while tc_head[ti]:
                idx = tc_head[ti] - 1
                vli, skiplen = read_varint32(traversal_buf, headptr[idx])
                sig_len = sig_lens[idx]
                if sig_len <= 1:
                    if sig_len == 0:
                        # variable-length string: (tdelta, length, bytes)
                        if not (vli & 1):
                            strlen, lskip2 = read_varint32(traversal_buf, headptr[idx] + skiplen)
                            raw_val = bytes(traversal_buf[headptr[idx] + skiplen + lskip2:headptr[idx] + skiplen + lskip2 + strlen])
                            val = raw_val
                            consume = skiplen + lskip2 + strlen
                            headptr[idx] += consume
                            length_remaining[idx] -= consume
                            tc_head[ti] = scatterptr[idx]
                            scatterptr[idx] = 0
                            if length_remaining[idx] > 0:
                                nv = peek_varint32(traversal_buf, headptr[idx])
                                tdelta = nv >> 1
                                next_ti = ti + tdelta
                                if next_ti < len(times):
                                    scatterptr[idx] = tc_head[next_ti]
                                    tc_head[next_ti] = idx + 1
                            changes.append((idx + 1, val))
                        else:
                            headptr[idx] += skiplen
                            length_remaining[idx] -= skiplen
                            tc_head[ti] = scatterptr[idx]
                            scatterptr[idx] = 0
                        continue
                    if not (vli & 1):
                        val_byte = ((vli >> 1) & 1) | 0x30
                    else:
                        val_byte = FST_RCV_STR[((vli >> 1) & 7)]
                    val = bytes([val_byte])
                    headptr[idx] += skiplen
                    length_remaining[idx] -= skiplen
                    tc_head[ti] = scatterptr[idx]
                    scatterptr[idx] = 0
                    if length_remaining[idx] > 0:
                        nv = peek_varint32(traversal_buf, headptr[idx])
                        if sig_len == 1:
                            shamt = 2 << (nv & 1)
                            tdelta = nv >> shamt
                        else:
                            tdelta = nv >> 1
                        next_ti = ti + tdelta
                        if next_ti < len(times):
                            scatterptr[idx] = tc_head[next_ti]
                            tc_head[next_ti] = idx + 1
                else:
                    if not (vli & 1):
                        byte_len = (sig_len + 7) // 8
                        raw = bytearray(sig_len)
                        for j in range(sig_len):
                            bp = j // 8
                            bit = 7 - (j & 7)
                            ch = ((traversal_buf[headptr[idx] + skiplen + bp] >> bit) & 1) | 0x30
                            raw[j] = ch
                        val = bytes(raw)
                        consume = byte_len
                    else:
                        val = bytes(traversal_buf[headptr[idx] + skiplen:headptr[idx] + skiplen + sig_len])
                        consume = sig_len
                    headptr[idx] += skiplen + consume
                    length_remaining[idx] -= skiplen + consume
                    tc_head[ti] = scatterptr[idx]
                    scatterptr[idx] = 0
                    if length_remaining[idx] > 0:
                        nv = peek_varint32(traversal_buf, headptr[idx])
                        tdelta = nv >> 1
                        next_ti = ti + tdelta
                        if next_ti < len(times):
                            scatterptr[idx] = tc_head[next_ti]
                            tc_head[next_ti] = idx + 1
                changes.append((idx + 1, val))
            if changes and (not respect_blackout or self.is_dump_active_at(times[ti])):
                yield (times[ti], changes)

        # -- Integrity check: every signal chain should be fully consumed --
        unconsumed = []
        for idx in range(max_handle):
            rem = length_remaining[idx]
            if rem > 0:
                unconsumed.append((idx + 1, rem))  # handle is 1-based
        if unconsumed:
            total_bytes = sum(r for _, r in unconsumed)
            warnings.warn(
                'FST section {} integrity: {} of {} signal chain(s) had '
                'unconsumed data ({} bytes remaining); some value changes '
                'may be missing due to data corruption'.format(
                    section_index, len(unconsumed), max_handle, total_bytes),
                stacklevel=2,
            )

    def iter_time_value_pairs_all(self, *, respect_blackout: bool = False) -> Iterator[tuple[int, list[tuple[int, bytes]]]]:
        """Yield time/value batches from all VCDATA sections in file order."""
        for idx in range(len(self._vc_sections)):
            yield from self.iter_time_value_pairs(idx, respect_blackout=respect_blackout)


# -- Parallel section parsing support ----------------------------------------
# Worker function for ProcessPoolExecutor. Must be module-level for pickling.
# On Linux (fork start method), workers inherit the parent's mmap and module
# globals, so _g_fst_reader is accessible without serialization.
_g_fst_reader = None


def _parse_section_worker(section_index):
    """Parse time_table + chain_table for one VCDATA section.

    Called in a forked worker process.  Accesses the shared _FstReader
    instance via the module global _g_fst_reader (inherited from parent
    through fork).
    """
    reader = _g_fst_reader
    sect = reader._vc_sections[section_index]
    payload = sect._payload

    # _parse_time_table uses self._time_to_index (dead write, never read).
    # Provide a dummy self with a writable attribute.
    class _Ctx:
        _time_to_index = None
    ctx = _Ctx()
    times = _FstReader._parse_time_table(ctx, payload)

    # _parse_chain_table does not use self at all.
    _FstReader._parse_chain_table(None, sect, payload)
    return (times, sect.chain_table, sect.chain_table_lengths)


class _ByteView:
    """Lightweight non-owning slice over bytes/mmap data.

    Unlike ``memoryview(data)[start:end]``, storing this object does not keep an
    exported buffer alive, so mmap-backed readers can still be closed when no
    temporary view is in user code.  Slicing returns a temporary memoryview,
    which zlib/struct/varint code can consume without copying unless the callee
    explicitly materializes bytes.
    """

    __slots__ = ("_data", "_start", "_end")

    def __init__(self, data, start: int, end: int):
        self._data = data
        self._start = int(start)
        self._end = int(end)

    def __len__(self) -> int:
        return self._end - self._start

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
            if step != 1:
                return bytes(memoryview(self._data)[self._start:self._end][key])
            return memoryview(self._data)[self._start + start:self._start + stop]
        if key < 0:
            key += len(self)
        if key < 0 or key >= len(self):
            raise IndexError(key)
        return self._data[self._start + key]

    def __bytes__(self) -> bytes:
        return bytes(memoryview(self._data)[self._start:self._end])

    def tobytes(self) -> bytes:
        return bytes(self)


def _u64be(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off:off + 8], "big")


def _i8(byte: int) -> int:
    return byte - 256 if byte >= 128 else byte


def _enum_name(enum_cls, value) -> str:
    """Best-effort IntEnum name lookup for external tables."""
    if value is None:
        return ""
    try:
        return enum_cls(int(value)).name.lower()
    except Exception:
        return f"unknown_{int(value)}" if isinstance(value, int) else "unknown"


def _file_type_name(value) -> str:
    mapping = {0: "verilog", 1: "vhdl", 2: "verilog_vhdl"}
    try:
        return mapping.get(int(value), f"unknown_{int(value)}")
    except Exception:
        return "unknown"


def _read_cstr(buf: bytes | bytearray | memoryview, off: int) -> tuple[str, int]:
    end = off
    n = len(buf)
    while end < n and buf[end] != 0:
        end += 1
    if end >= n:
        raise _FstFormatError("unterminated C string")
    return bytes(buf[off:end]).decode("utf-8", errors="replace"), end + 1

def _read_cstr_raw(buf: bytes | bytearray | memoryview, off: int) -> tuple[bytes, int]:
    end = off
    n = len(buf)
    while end < n and buf[end] != 0:
        end += 1
    if end >= n:
        raise _FstFormatError("unterminated C string")
    return bytes(buf[off:end]), end + 1


def _decode_attr_name(raw: bytes, attr_type: int, subtype: int) -> str:
    # SOURCESTEM/SOURCEISTEM overload the name field with varint bytes.  Keep
    # those bytes reversible via latin-1; normal textual attributes are UTF-8.
    if attr_type == int(FstAttrType.MISC) and subtype in (
        int(FstMiscType.SOURCESTEM), int(FstMiscType.SOURCEISTEM)
    ):
        return raw.decode("latin1", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _parse_varint_from_attr_name(name: str) -> int:
    if not name:
        return 0
    try:
        val, _ = read_varint(name.encode("latin1"), 0)
        return int(val)
    except Exception:
        return 0




_ATTR_TYPE_NAMES = {
    int(FstAttrType.MISC): "misc",
    int(FstAttrType.ARRAY): "array",
    int(FstAttrType.ENUM): "enum",
    int(FstAttrType.PACK): "pack",
}
_MISC_SUBTYPE_NAMES = {
    int(FstMiscType.COMMENT): "comment",
    int(FstMiscType.ENVVAR): "envvar",
    int(FstMiscType.SUPVAR): "supvar",
    int(FstMiscType.PATHNAME): "pathname",
    int(FstMiscType.SOURCESTEM): "sourcestem",
    int(FstMiscType.SOURCEISTEM): "sourceistem",
    int(FstMiscType.VALUELIST): "valuelist",
    int(FstMiscType.ENUMTABLE): "enumtable",
    int(FstMiscType.UNKNOWN): "unknown",
}
_ARRAY_SUBTYPE_NAMES = {0: "none", 1: "unpacked", 2: "packed", 3: "sparse"}
_ENUM_SUBTYPE_NAMES = {
    0: "sv_integer",
    1: "sv_bit",
    2: "sv_logic",
    3: "sv_int",
    4: "sv_shortint",
    5: "sv_longint",
    6: "sv_byte",
    7: "sv_unsigned_integer",
    8: "sv_unsigned_bit",
    9: "sv_unsigned_logic",
    10: "sv_unsigned_int",
    11: "sv_unsigned_shortint",
    12: "sv_unsigned_longint",
    13: "sv_unsigned_byte",
    14: "reg",
    15: "time",
}
_PACK_SUBTYPE_NAMES = {0: "none", 1: "unpacked", 2: "packed", 3: "tagged_packed"}


def _attribute_subtype_name(attr_type: int, subtype: int) -> str:
    if attr_type == int(FstAttrType.MISC):
        return _MISC_SUBTYPE_NAMES.get(subtype, f"misc_{subtype}")
    if attr_type == int(FstAttrType.ARRAY):
        return _ARRAY_SUBTYPE_NAMES.get(subtype, f"array_{subtype}")
    if attr_type == int(FstAttrType.ENUM):
        return _ENUM_SUBTYPE_NAMES.get(subtype, f"enum_{subtype}")
    if attr_type == int(FstAttrType.PACK):
        return _PACK_SUBTYPE_NAMES.get(subtype, f"pack_{subtype}")
    return str(subtype)


def _fst_unescape(text: str) -> str:
    """Decode libfst enum-table escape sequences (fstUtilityEscToBin)."""
    out = bytearray()
    b = text.encode("latin1", errors="replace")
    i = 0
    while i < len(b):
        ch = b[i]
        if ch != 0x5C:  # backslash
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(b):
            out.append(0x5C)
            break
        esc = chr(b[i])
        i += 1
        mapping = {
            "a": 7,
            "b": 8,
            "f": 12,
            "n": 10,
            "r": 13,
            "t": 9,
            "v": 11,
            "'": ord("'"),
            '"': ord('"'),
            "\\": ord("\\"),
            "?": ord("?"),
        }
        if esc in mapping:
            out.append(mapping[esc])
        elif esc == "x" and i + 1 < len(b):
            try:
                out.append(int(bytes(b[i:i+2]).decode("ascii"), 16))
                i += 2
            except ValueError:
                out.append(ord("x"))
        elif esc in "01234567" and i + 1 < len(b):
            octal = bytes([ord(esc)]) + b[i:i+2]
            try:
                out.append(int(octal.decode("ascii"), 8))
                i += 2
            except ValueError:
                out.append(ord(esc))
        else:
            out.append(ord(esc))
    return out.decode("utf-8", errors="replace")



def _attr_payload_bytes(attr: FstAttrBegin) -> bytes:
    raw = getattr(attr, "name_raw", b"")
    if raw:
        return bytes(raw)
    # Compatibility for FstAttrBegin instances constructed by older tests/users.
    return str(attr.name).encode("utf-8", errors="replace")


def _is_printable_ascii_byte(b: int) -> bool:
    return 0x20 <= b <= 0x7E


def _escape_bytes_for_report(raw: bytes) -> str:
    """Return a reversible, report-friendly C-style escaped byte string."""
    out: list[str] = []
    for b in raw:
        if b == 0x5C:  # backslash
            out.append(r"\\")
        elif b == 0x0A:
            out.append(r"\n")
        elif b == 0x0D:
            out.append(r"\r")
        elif b == 0x09:
            out.append(r"\t")
        elif b == 0x00:
            out.append(r"\0")
        elif _is_printable_ascii_byte(b):
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def _attribute_payload_report(attr: FstAttrBegin) -> dict:
    raw = _attr_payload_bytes(attr)
    printable = all(_is_printable_ascii_byte(b) or b in (0x09, 0x0A, 0x0D) for b in raw)
    return {
        "length": len(raw),
        "ascii_escaped": _escape_bytes_for_report(raw),
        "utf8": raw.decode("utf-8", errors="replace"),
        "latin1": raw.decode("latin1", errors="replace"),
        "hex": raw.hex(),
        "base64": base64.b64encode(raw).decode("ascii"),
        "is_printable_ascii": bool(printable),
    }


def _describe_attribute(attr: FstAttrBegin, source_paths: dict[int, str], enum_tables: dict[int, dict]) -> dict:
    attr_type = int(attr.attr_type)
    subtype = int(attr.subtype)
    payload = _attribute_payload_report(attr)
    d = {
        "attr_type": attr_type,
        "attr_type_name": _ATTR_TYPE_NAMES.get(attr_type, f"attr_{attr_type}"),
        "subtype": subtype,
        "subtype_name": _attribute_subtype_name(attr_type, subtype),
        "name": attr.name,
        "arg": int(attr.arg),
        "arg_from_name": int(attr.arg_from_name),
        "payload": payload,
        "payload_ascii": payload["ascii_escaped"],
    }
    if attr_type == int(FstAttrType.MISC):
        if subtype == int(FstMiscType.SUPVAR):
            d["type_name"] = attr.name
            d["supplemental_var_type"] = int(attr.arg) >> 10
            d["supplemental_data_type"] = int(attr.arg) & 0x3FF
        elif subtype in (int(FstMiscType.SOURCESTEM), int(FstMiscType.SOURCEISTEM)):
            sidx = attr.arg_from_name or _parse_varint_from_attr_name(attr.name)
            d["source_index"] = int(sidx)
            d["path"] = source_paths.get(int(sidx), "")
            d["line"] = int(attr.arg)
        elif subtype == int(FstMiscType.ENUMTABLE):
            if attr.name:
                d["enum_table"] = _parse_enum_table_attr(attr.name)
            else:
                d["enum_table_handle"] = int(attr.arg)
                if int(attr.arg) in enum_tables:
                    d["enum_table"] = enum_tables[int(attr.arg)]
        elif subtype == int(FstMiscType.VALUELIST):
            d["value_list"] = attr.name
        elif subtype == int(FstMiscType.PATHNAME):
            d["source_index"] = int(attr.arg)
            d["path"] = attr.name
    elif attr_type == int(FstAttrType.ARRAY):
        d["array_kind"] = d["subtype_name"]
        d["element_count"] = int(attr.arg)
    elif attr_type == int(FstAttrType.ENUM):
        d["enum_value_type"] = d["subtype_name"]
        d["element_count"] = int(attr.arg)
    elif attr_type == int(FstAttrType.PACK):
        d["pack_kind"] = d["subtype_name"]
        d["member_count"] = int(attr.arg)
    return d

def _parse_enum_table_attr(text: str) -> dict:
    # Writer encodes: name count literals... values... .  This mirrors
    # fstUtilityExtractEnumTableFromString(): split by spaces, then apply
    # fstUtilityEscToBin to literal/value tokens.  The raw tokens are retained
    # because third-party writers may use noncanonical escaping.
    parts = text.split()
    if len(parts) < 2:
        return {
            "raw": text,
            "name": text,
            "count": 0,
            "literals": [],
            "values": [],
            "raw_literals": [],
            "raw_values": [],
        }
    name = parts[0]
    try:
        count = int(parts[1])
    except ValueError:
        count = 0
    raw_literals = parts[2:2 + count]
    raw_values = parts[2 + count:2 + 2 * count]
    literals = [_fst_unescape(x) for x in raw_literals]
    values = [_fst_unescape(x) for x in raw_values]
    return {
        "raw": text,
        "name": name,
        "count": count,
        "literals": literals,
        "values": values,
        "raw_literals": raw_literals,
        "raw_values": raw_values,
    }




def _quote_empty_attr_name(name: str) -> str:
    return name if name else '""'


def _format_attr_as_vcd_extension(attr: FstAttrBegin) -> Iterator[str]:
    """Format one attribute like libfst's VCD extension printer."""
    attr_type = int(attr.attr_type)
    subtype = int(attr.subtype)
    attr_name = _ATTR_TYPE_NAMES.get(attr_type, "misc")
    name = _quote_empty_attr_name(attr.name)
    if attr_type == int(FstAttrType.ARRAY):
        yield f"$attrbegin {attr_name} {_ARRAY_SUBTYPE_NAMES.get(subtype, 'none')} {name} {int(attr.arg)} $end"
    elif attr_type == int(FstAttrType.ENUM):
        yield f"$attrbegin {attr_name} {_ENUM_SUBTYPE_NAMES.get(subtype, 'sv_integer')} {name} {int(attr.arg)} $end"
    elif attr_type == int(FstAttrType.PACK):
        yield f"$attrbegin {attr_name} {_PACK_SUBTYPE_NAMES.get(subtype, 'none')} {name} {int(attr.arg)} $end"
    else:
        if subtype == int(FstMiscType.COMMENT):
            yield "$comment"
            yield f"\t{attr.name}"
            yield "$end"
        elif subtype in (int(FstMiscType.SOURCESTEM), int(FstMiscType.SOURCEISTEM)):
            sidx = attr.arg_from_name or _parse_varint_from_attr_name(attr.name)
            yield f"$attrbegin misc {subtype:02x} {int(sidx)} {int(attr.arg)} $end"
        else:
            yield f"$attrbegin misc {subtype:02x} {name} {int(attr.arg)} $end"

def _metadata_summary(meta: FstSignalMetadata | None) -> dict:
    """Return a JSON-friendly metadata summary for signal_table()."""
    if meta is None:
        return {}
    return {
        "type_name": meta.type_name,
        "supplemental_var_type": int(meta.supplemental_var_type),
        "supplemental_data_type": int(meta.supplemental_data_type),
        "value_list": meta.value_list,
        "enum_table_handle": int(meta.enum_table_handle),
        "source_stem": meta.source_stem,
        "source_instantiation_stem": meta.source_instantiation_stem,
        "attribute_count": len(meta.all_attributes),
        "misc_attribute_count": len(meta.misc_attributes),
        "array_attribute_count": len(meta.array_attributes),
        "enum_attribute_count": len(meta.enum_attributes),
        "pack_attribute_count": len(meta.pack_attributes),
    }


def _metadata_replace(meta: FstSignalMetadata, **kwargs) -> FstSignalMetadata:
    data = {
        "type_name": meta.type_name,
        "supplemental_var_type": meta.supplemental_var_type,
        "supplemental_data_type": meta.supplemental_data_type,
        "value_list": meta.value_list,
        "enum_table_handle": meta.enum_table_handle,
        "source_stem": meta.source_stem,
        "source_instantiation_stem": meta.source_instantiation_stem,
        "active_attributes": meta.active_attributes,
        "misc_attributes": meta.misc_attributes,
        "array_attributes": meta.array_attributes,
        "enum_attributes": meta.enum_attributes,
        "pack_attributes": meta.pack_attributes,
        "all_attributes": meta.all_attributes,
    }
    data.update(kwargs)
    return FstSignalMetadata(**data)# ================================================================
# Part 5: VCD Utilities
# ================================================================

class _WaveResourceError(RuntimeError):
    pass

_VCDResourceError = _WaveResourceError

# -- Time utilities ----------------------------------------------------------

_UNITS = {'fs': 1e-15, 'ps': 1e-12, 'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0}


# Resource limits — generous defaults that never trip on real engineering
# files but reject pathological/malicious inputs cleanly.
# Override per-process via environment variables, e.g.:
#   VCD_ANALYZER_MAX_VARS=2000000 vcd_analyzer info big.vcd
def _env_int(name, default):
    """Read a positive integer resource limit from the environment."""
    raw = os.environ.get(name)
    if raw is None or raw == '':
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


MAX_VARS = _env_int('VCD_ANALYZER_MAX_VARS', 1_000_000)
MAX_REASSEMBLE_BITS = _env_int('VCD_ANALYZER_MAX_REASSEMBLE_BITS', 65536)
MAX_TIME_ARG_LEN = 100         # CLI/programmatic time string length cap
MAX_TIME_TICKS = (1 << 63) - 1  # int64 max — keeps downstream arithmetic safe
MAX_FILTER_PATTERN_LEN = 256
MAX_FILTER_WILDCARDS = 16

# Additional header-section caps. Defaults are far above any legitimate
# engineering VCD but cleanly refuse pathological/malicious construction.
#
# Two failure modes are used:
#  - fail-fast (raise _VCDResourceError): for caps whose violation would
#    corrupt data correctness (lost value_changes, lost $var declarations,
#    deep scope that breaks path reconstruction).
#  - silent drop (truncate retained list): for metadata-only caps whose
#    violation only affects the cosmetic output of `info --verbose`. These
#    are noted inline where they apply.
MAX_INT_DIGITS = 100              # any int-from-string in header (width, bit idx, msb/lsb)
MAX_SIGNAL_WIDTH = MAX_REASSEMBLE_BITS  # max bits per single $var declaration
MAX_VALUE_ARG_LEN = MAX_SIGNAL_WIDTH + 2  # target value string, allows b<MAX_SIGNAL_WIDTH bits>
MAX_DECIMAL_VALUE_DIGITS = 100  # avoid Python 3.9 int() CPU DoS on --value decimal
MAX_HEX_VALUE_DIGITS = max(1, (MAX_SIGNAL_WIDTH + 3) // 4)
MAX_HEADER_BODY_TOKENS = 131072   # any $<kw>...$end section body length (metadata-only effect:
                                  # truncates $comment / $date / $version bodies; $var bodies
                                  # are never long enough to be affected in practice)
MAX_COMMENTS = 1024               # number of $comment sections retained (metadata-only)
MAX_SCOPE_DEPTH = 256             # $scope nesting depth (fail-fast: lost scope breaks path)
MAX_INITIAL_TOKENS = 131072       # tokens buffered from same line as $enddefinitions $end
                                  # (fail-fast: these are data tokens, dropping them
                                  # would silently corrupt waveforms)


# IEEE 1364-2005 18.2.2 real value_change is 'r' + real_number where
# real_number follows C99 printf("%g") shape: optional sign, integer and/or
# fractional digits, optional exponent. Used to reject garbage tokens like
# 'reset' that start with 'r' but aren't a numeric value_change.
#
# Pattern written to avoid backtracking (no alternation overlap):
#   sign?  ( digits  ( '.' digits? )?  |  '.' digits )  exponent?
# The two top-level alternatives are disjoint (start with digit vs '.'),
# so the engine never has to backtrack between them. Inputs are also
# length-bounded below; real_number tokens in VCD value_changes shouldn't
# exceed reasonable %g output width.
_REAL_RE = re.compile(
    r'^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$'
)
_REAL_MAX_LEN = 64  # Defensive cap: %.16g + sign + exponent fits well under this

# Extended VCD port state character → 4-state mapping (IEEE 1364-2005 18.4.3.1).
# Strengths (driver levels 0-7) are not exposed; for RTL debug the 4-state value
# is what matters. Conflict states (d/u/l/h) collapse to their logical level.
_PORT_STATE = {
    # Input (testfixture)
    'D': '0', 'U': '1', 'N': 'x', 'Z': 'z', 'd': '0', 'u': '1',
    # Output (DUT)
    'L': '0', 'H': '1', 'X': 'x', 'T': 'z', 'l': '0', 'h': '1',
    # Unknown direction (both input and output active)
    '0': '0', '1': '1', '?': 'x', 'F': 'z',
    'A': 'x', 'a': 'x', 'B': 'x', 'b': 'x', 'C': 'x', 'c': 'x', 'f': 'z',
}


def _parse_timescale(text):
    """Extract base time unit in seconds from $timescale line.

    IEEE 1364-2005 18.2.3.8 only allows 1, 10, or 100 as the number, but
    we accept any positive integer for lenience. A zero, missing, or
    pathologically long number falls back to 1e-12 (1 ps) — the standard's
    default — to avoid downstream division-by-zero in parse_time and CPU
    DoS from int() on huge digit strings (Python 3.9 is O(n^2)).
    """
    m = re.search(r'(\d+)\s*(fs|ps|ns|us|ms|s)', text)
    if not m:
        return 1e-12
    digits = m.group(1)
    # Length cap matches parse_time's MAX_TIME_ARG_LEN. The standard allows
    # only 1/10/100 (≤3 digits), so anything multi-line absurd is corruption.
    if len(digits) > MAX_TIME_ARG_LEN:
        return 1e-12
    n = int(digits)
    if n <= 0:
        return 1e-12
    return n * _UNITS[m.group(2)]


class _TimeParseError(ValueError):
    """Raised by parse_time on invalid input; caught in main() for friendly CLI errors."""


class _FilterParseError(argparse.ArgumentTypeError):
    """Raised when --filter contains an unsafe or unsupported pattern.
    argparse handles this automatically with a friendly message."""


class _ValueParseError(ValueError):
    """Raised when a target value is too large or malformed beyond tolerant matching."""


class _ConditionParseError(ValueError):
    """Raised when search --condition / --show / --changed is invalid."""


class _VCDResourceError(RuntimeError):
    """Raised when a VCD input exceeds configured resource limits.
    Surfaced in main() as a CLI error, no Python traceback."""


def _check_time_range(ticks, original):
    if ticks < 0:
        raise _TimeParseError('time must be non-negative; got {!r}'.format(original))
    if ticks > MAX_TIME_TICKS:
        raise _TimeParseError(
            'time value too large; got {!r}, max ticks is {}'.format(original, MAX_TIME_TICKS))
    return ticks


def _parse_vcd_timestamp_token(tok):
    """Parse a VCD '#<digits>' simulation_time token into an int.

    Returns int on success, None for malformed input (e.g. '#1.5' — digit
    prefix passed the isdigit() pre-check but int() rejects it). The
    None-path preserves the round-7 "tolerant reader" behavior: malformed
    timestamps are silently skipped, the rest of the stream continues.

    Raises _VCDResourceError for inputs that would cause CPU/memory DoS or
    exceed int64. Python 3.11+ has PEP 678 (int_max_str_digits) baked in,
    but we target 3.9 where int(s) is O(n^2) for huge n; even on 3.11+
    the PEP 678 ValueError would otherwise become an unhandled traceback.
    """
    digits = tok[1:]
    if len(digits) > MAX_TIME_ARG_LEN:
        raise _VCDResourceError(
            'VCD timestamp token too long: {} digits (max {}); '
            'file may be corrupt or malicious'.format(len(digits), MAX_TIME_ARG_LEN))
    try:
        v = int(digits)
    except ValueError:
        return None  # tolerated malformed (e.g. '#1.5')
    if v > MAX_TIME_TICKS:
        raise _VCDResourceError(
            'VCD timestamp too large: got {}, max ticks is {}'.format(v, MAX_TIME_TICKS))
    return v


def _safe_int_digits(s):
    """Parse a digit string from VCD header to int with bounded cost.

    Used wherever the header declares an integer in user-controlled
    position: $var width, [msb:lsb] range, [N] bit index. Returns int
    on success, None for empty / malformed / oversized inputs. Never
    raises — caller decides whether to skip the declaration or raise
    _VCDResourceError with richer context.

    Length cap MAX_INT_DIGITS=100 defends against the same Python 3.9
    O(n^2) decimal-int and Python 3.11+ PEP 678 ValueError issues as
    _parse_vcd_timestamp_token. 100 digits is far beyond any legitimate
    bit width or index (which fit in 4 digits comfortably).
    """
    if not s or len(s) > MAX_INT_DIGITS:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def parse_time(s, ts_sec):
    """Parse time string with optional unit suffix to internal VCD timestamp.

    VCD timestamps per IEEE 1364-2005 18.2.3.8 are non-negative integers.
    - With unit: any non-negative value, scaled to ticks (e.g. '17.5us', '.5ns')
    - Without unit: must be a non-negative integer tick count

    Bare '10.5' (no unit) is rejected to avoid silent int() truncation;
    use '10.5ns' to specify a fractional time. Whitespace between number
    and unit is NOT allowed ('5 ns' is rejected; standard unit literals
    are written as a single token).

    Hardened against:
    - ZeroDivisionError when ts_sec <= 0 (e.g. malformed $timescale)
    - Overflow / non-finite intermediate values
    - Overlong input strings (CPU DoS)
    - Tick counts exceeding int64
    """
    if s is None:
        return None
    if not isinstance(s, str):
        raise _TimeParseError(
            'time value must be a string; got {}'.format(type(s).__name__))
    if len(s) > MAX_TIME_ARG_LEN:
        raise _TimeParseError(
            'time value too long; max length is {}'.format(MAX_TIME_ARG_LEN))
    stripped = s.strip()
    # Anchored match — no \s* between value and unit ('5 ns' must be rejected).
    m = re.match(r'^([+-]?)(\d+\.\d*|\.\d+|\d+)(fs|ps|ns|us|ms|s)?$', stripped)
    if not m:
        # Fall back to bare integer ('100', '-5'); reject anything else.
        try:
            v = int(stripped)
        except (ValueError, TypeError):
            raise _TimeParseError(
                'invalid time value {!r}; expected integer ticks or value '
                'with fs/ps/ns/us/ms/s suffix'.format(s))
        return _check_time_range(v, s)
    sign, val_str, unit = m.group(1), m.group(2), m.group(3)
    if sign == '-' and val_str.strip('0.') != '':
        # Reject negative non-zero. '-0' / '-0.0' silently treated as 0.
        raise _TimeParseError(
            'time must be non-negative; got {!r}'.format(s))
    if unit is None:
        if '.' in val_str:
            raise _TimeParseError(
                'bare numeric time must be integer ticks; got {!r}. '
                'Use a unit suffix for fractional times, e.g. {}ns'.format(s, val_str))
        return _check_time_range(int(val_str), s)
    if ts_sec <= 0:
        raise _TimeParseError(
            'cannot convert time with unit because VCD $timescale is 0 or invalid')
    try:
        scaled = float(val_str) * _UNITS[unit] / ts_sec
    except (OverflowError, ValueError, ZeroDivisionError):
        raise _TimeParseError('invalid time value {!r}'.format(s))
    if not math.isfinite(scaled):
        raise _TimeParseError('time value {!r} is not finite'.format(s))
    return _check_time_range(int(round(scaled)), s)


def fmt_time(ts, ts_sec):
    """Format internal timestamp to human-readable string.

    Picks the smallest unit u where |scaled| < 1000, preferring natural
    boundaries. E.g. with timescale 1ns, #5 prints as '5ns' not '5000ps';
    #17534700 prints as '17.5347us'.

    Defensive: non-finite ts or ts_sec produces '?', not 'infs' / 'nans'.
    """
    if ts == 0:
        return '0s'
    # math.isfinite handles int, float, bool. inf/nan slip through arithmetic
    # otherwise and produce garbage like 'infs'.
    try:
        if not (math.isfinite(ts) and math.isfinite(ts_sec)):
            return '?'
    except TypeError:
        return '?'
    if ts_sec <= 0:
        return '?'
    sec = ts * ts_sec
    for u in ('fs', 'ps', 'ns', 'us', 'ms', 's'):
        scaled = sec / _UNITS[u]
        if abs(scaled) < 1000 or u == 's':
            return '{:g}{}'.format(scaled, u)
    return '{:g}s'.format(sec)


# -- Value formatting --------------------------------------------------------

def fmt_val(value, info):
    """Format signal value per IEEE 1364-2005 18.2.2.

    info: dict with 'width' (required) and 'type' (optional, default 'wire').

    Real/realtime values (18.2.2) carry the simulator's %.16g rendering as
    their literal value string and have no bit width — declared width (often
    64) is purely cosmetic and must not trigger vector left-extension.
    Multi-bit vectors are left-extended per Table 18-1: MSB X/Z extends
    with X/Z, else 0. Events (var_type 'event' per 18.2.3.7) display as
    'triggered' since the dumped value is just a marker.
    """
    vtype = info.get('type', 'wire')
    if vtype == 'event':
        return 'triggered'
    if vtype in ('real', 'realtime'):
        return value
    width = info['width']
    # Malformed VCD may dump more 4-state bits than the declared width
    # (for example an over-long extended-VCD port state). Do not truncate
    # to the LSBs: that silently fabricates a plausible numeric value.
    # Show explicit unknowns instead.
    if _is_4state_bits(value) and len(value) > width:
        value = 'x' * width
    if width == 1:
        return value
    # Left-extend short vectors. Writer drops redundant MSB bits when they
    # match the extension char of MSB (Table 18-2).
    if len(value) < width:
        msb = value[0]
        pad = msb if msb in ('x', 'z') else '0'
        value = pad * (width - len(value)) + value
    if 'x' in value or 'z' in value:
        return 'b' + value
    try:
        d = int(value, 2)
        hw = max((width + 3) // 4, 1)
        return '{} (0x{})'.format(d, format(d, 'x').zfill(hw))
    except ValueError:
        return 'b' + value


def val_to_int(value):
    """Try converting to int, None on x/z or pathologically long values.

    int(s, 2) is O(n) for base-2 (PEP 678 does not apply to power-of-two
    bases) so the worst case after MAX_SIGNAL_WIDTH=65536 is sub-ms — but
    we cap anyway as defense in depth, in case a future code path lets
    an unbounded value reach here.
    """
    if 'x' in value or 'z' in value:
        return None
    if len(value) > MAX_SIGNAL_WIDTH:
        return None
    try:
        return int(value, 2) if len(value) > 1 else int(value)
    except ValueError:
        return None




def _clamp_overwide_logic_value(value, info):
    """Preserve clean 4-state state while rejecting malformed over-wide dumps.

    Legal VCD writers may omit redundant MSB bits; fmt_val() and condition
    matching already left-extend short values. A value longer than the
    declared width is malformed. Do not truncate it to the LSBs: that would
    turn corrupt input into a plausible-looking numeric value. Instead,
    degrade to all-x at the declared width so downstream dump/snapshot/search
    sees an explicit unknown.
    """
    vtype = info.get('type', 'wire')
    if vtype in ('real', 'realtime', 'event'):
        return value
    width = info.get('width')
    if width is None:
        return value
    if _is_4state_bits(value) and len(value) > width:
        return 'x' * width
    return value

def _normalize_filter_patterns(value):
    """Normalize and bound user-supplied substring/glob patterns.

    Plain text remains substring matching. Only '*' and '?' trigger glob
    matching; '[' is literal because VCD bus ranges like data[7:0] are
    common signal names. Pattern length and wildcard count are bounded
    to keep Python 3.9's fnmatch/regex translation from becoming a CPU
    DoS surface ('a*a*a*...b' style inputs can be slow in older Python).
    Consecutive '*' are collapsed (matches glob semantics, reduces backtracking).

    Used by:
    - argparse type= on --filter (raises argparse-friendly error)
    - VCDParser.match() applied to internally-stored keyword lists
    """
    if value is None:
        return None
    if isinstance(value, str):
        raw_patterns = value.split(',')
    elif isinstance(value, (list, tuple, set)):
        raw_patterns = value
    else:
        raise _FilterParseError(
            'filter patterns must be a string or a sequence of strings; got {}'.format(
                type(value).__name__))
    out = []
    for raw in raw_patterns:
        pat = str(raw).strip()
        if not pat:
            continue
        if len(pat) > MAX_FILTER_PATTERN_LEN:
            raise _FilterParseError(
                'filter pattern too long; max length is {}'.format(MAX_FILTER_PATTERN_LEN))
        pat = re.sub(r'\*+', '*', pat)  # collapse `**` → `*`
        if pat.count('*') + pat.count('?') > MAX_FILTER_WILDCARDS:
            raise _FilterParseError(
                'too many wildcard characters in filter pattern; max is {}'.format(
                    MAX_FILTER_WILDCARDS))
        out.append(pat)
    return out


def _glob_lite_regex(pattern):
    """Translate the tool's minimal glob syntax to a compiled regex.

    Only '*' and '?' are special. Everything else — notably '[' and ']' in
    VCD bus ranges such as data[7:0] — is matched literally. This deliberately
    avoids fnmatch's character-class syntax so documented filters like
    '*data[7:0]' match the literal signal path 'tb.data[7:0]'.

    Pattern length and wildcard count are already bounded by
    _normalize_filter_patterns(), so the generated regex is small and safe.
    """
    parts = ['^']
    for ch in pattern:
        if ch == '*':
            parts.append('.*')
        elif ch == '?':
            parts.append('.')
        else:
            parts.append(re.escape(ch))
    parts.append('$')
    return re.compile(''.join(parts))


# -- VCD Parser with bit-exploded signal reassembly -------------------------

# IEEE 1364-2005 declaration keywords that introduce a $<kw> ... $end section.
_DECL_KEYWORDS = {'$timescale', '$scope', '$upscope', '$var',
                  '$comment', '$date', '$version', '$enddefinitions'}

# Simulation keywords that wrap value_changes until $end. The keyword and $end
# are pure markers — the wrapped value_changes are parsed normally.
# Four-state VCD (18.2.3.9-12) + extended VCD (18.4.1 BNF).
_SIM_KEYWORDS = {'$dumpall', '$dumpoff', '$dumpon', '$dumpvars',
                 '$dumpports', '$dumpportsoff', '$dumpportson', '$dumpportsall'}

# Sections that can appear in the data area whose body is NOT value_changes
# and must be skipped wholesale until $end. $comment (18.2.3.1) is in both
# header and data; $vcdclose (18.3.6.1) wraps a final simulation time token.
_DATA_SKIP_SECTIONS = {'$comment', '$vcdclose'}

# ================================================================
# Part 6: VCD Parser
# ================================================================

class VCDParser:
    """Streaming VCD parser. Token-based: handles single-line and multi-line
    sections, inline simulation keyword blocks, and multi-line port values
    per IEEE 1364-2005 Section 18.

    Auto-reassembles bit-exploded signals (QuestaSim writes 512-bit signals
    as 512 individual 1-bit $var entries with [N] suffix).

    Extended VCD ($dumpports) support level: port_state characters are
    lowered to 4-state values (0/1/x/z) for RTL debug. The strength0 and
    strength1 components are parsed but discarded — preserving them would
    rarely benefit RTL-level analysis and clutters the value display.
    """

    def __init__(self, path):
        self.path = path
        self.ts_str = ''
        self.ts_sec = 1e-12        # timescale in seconds
        self.signals = {}           # sig_id -> {path, width, type, aliases}
        self._data_offset = 0
        # Header metadata per IEEE 1364-2005 18.2.3:
        #   $date    - simulation date string (18.2.3.2)
        #   $version - simulator vendor/version (18.2.3.3)
        #   $comment - free-form, may appear multiple times (18.2.3.1)
        # Captured verbatim for provenance display; an agent inspecting an
        # unknown VCD benefits from knowing which simulator produced it
        # (QuestaSim 2023.1 vs Icarus Verilog vs VCS) and when, since
        # downstream debug heuristics may depend on simulator quirks.
        self.date = ''
        self.version = ''
        self.comments = []
        # If $enddefinitions $end is followed by data tokens on the same
        # line(s) buffered by readline, those tokens replay first in data.
        self._initial_tokens = []
        self._bit_map = {}          # sym -> (sig_id, bit_index)
        self._bit_state_template = {}  # sig_id -> initial bit list for replay-local reassembly
        self._parse_header()

    def _parse_header(self):
        """Token-based header parse. Sections may span multiple lines;
        $end is the only terminator (IEEE 1364-2005 18.2.1)."""
        scope = []
        raw_vars = []  # (sym, name, width, bit_idx_str, scope_path, vtype)
        current_kw = None
        body = []
        done = False

        with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
            while not done:
                line = f.readline()
                if not line:
                    break
                for tok in line.split():
                    if done:
                        # Buffer tokens that share the same line as
                        # `$enddefinitions $end`. These are data tokens
                        # (value_changes, timestamps), so they MUST NOT
                        # be silently dropped — that would corrupt the
                        # waveform without the user noticing. Fail-fast.
                        # Normal VCDs have at most a handful of tokens
                        # on this line; 131072 is comfortably above any
                        # legitimate use.
                        if len(self._initial_tokens) >= MAX_INITIAL_TOKENS:
                            raise _VCDResourceError(
                                'too many data tokens on the same line as '
                                '$enddefinitions $end (>{}); file may be '
                                'corrupt or malicious'.format(MAX_INITIAL_TOKENS))
                        self._initial_tokens.append(tok)
                        continue
                    if current_kw is None:
                        if tok in _DECL_KEYWORDS:
                            current_kw = tok
                            body = []
                        # else: stray token, ignore
                    elif tok == '$end':
                        # Section complete
                        if current_kw == '$timescale':
                            ts_body = ' '.join(body)
                            self.ts_str = '$timescale ' + ts_body + ' $end'
                            self.ts_sec = _parse_timescale(ts_body)
                        elif current_kw == '$scope' and len(body) >= 2:
                            # Cap nesting depth to defend against
                            # 1M-level $scope-without-$upscope construction.
                            if len(scope) >= MAX_SCOPE_DEPTH:
                                raise _VCDResourceError(
                                    '$scope nesting depth exceeds {}; '
                                    'file may be corrupt or malicious'.format(MAX_SCOPE_DEPTH))
                            scope.append(body[1])
                        elif current_kw == '$upscope':
                            if scope:
                                scope.pop()
                        elif current_kw == '$var' and len(body) >= 4:
                            vtype = body[0]

                            def _collect_bracket(tokens, i):
                                if i >= len(tokens) or not tokens[i].startswith('['):
                                    return None, i
                                parts = []
                                while i < len(tokens):
                                    parts.append(tokens[i])
                                    if ']' in tokens[i]:
                                        return ''.join(parts), i + 1
                                    i += 1
                                return None, i

                            size_expr, idx_after_size = _collect_bracket(body, 1)
                            if size_expr is not None:
                                m = re.match(r'\[(\d+):(\d+)\]$', size_expr)
                                if not m:
                                    current_kw = None
                                    continue
                                msb = _safe_int_digits(m.group(1))
                                lsb = _safe_int_digits(m.group(2))
                                if msb is None or lsb is None:
                                    # Overlong or malformed digits — skip
                                    # this $var rather than abort, since
                                    # the rest of the header may still be
                                    # useful.
                                    current_kw = None
                                    continue
                                w = abs(msb - lsb) + 1
                                idx = idx_after_size
                            else:
                                w = _safe_int_digits(body[1])
                                if w is None:
                                    current_kw = None
                                    continue
                                idx = 2
                            # Hazard 1 mitigation: refuse pathological widths
                            # before they reach fmt_val (which would try to
                            # allocate `pad * (width - len(value))` bytes).
                            # Real signals never approach MAX_SIGNAL_WIDTH.
                            if w <= 0 or w > MAX_SIGNAL_WIDTH:
                                raise _VCDResourceError(
                                    '$var width {} exceeds max {}; '
                                    'file may be corrupt or malicious'.format(
                                        w, MAX_SIGNAL_WIDTH))
                            if len(body) <= idx + 1:
                                current_kw = None
                                continue
                            sym, name = body[idx], body[idx + 1]

                            # Per IEEE 1364 free-format, the bracket reference
                            # range can be split into several tokens, e.g.
                            # 'data [7 : 0]' → ['data', '[7', ':', '0]'].
                            bit_str, _idx_after_ref = _collect_bracket(body, idx + 2)
                            # Per IEEE 1364-2005 18.2.3.7 reference syntax:
                            #   identifier [bit_select_index]      → single bit
                            #   identifier [msb_index : lsb_index] → range
                            # For multi-bit refs with a range, fold it into
                            # the name so the displayed path is 'data[7:0]'.
                            # For w==1 with [N], keep bit_str separate for
                            # the bit-explosion heuristic below.
                            if bit_str is not None and w > 1:
                                name = name + bit_str
                                bit_str = None
                            # Resource cap: refuse to allocate unbounded memory
                            # for malicious VCDs declaring millions of $var.
                            # Default 500k is ~25x larger than typical QuestaSim
                            # files; tune via VCD_ANALYZER_MAX_VARS env var.
                            if len(raw_vars) >= MAX_VARS:
                                raise _VCDResourceError(
                                    'too many $var declarations: more than {}. '
                                    'Set VCD_ANALYZER_MAX_VARS to raise the limit.'.format(MAX_VARS))
                            raw_vars.append((sym, name, w, bit_str, '.'.join(scope), vtype))
                        elif current_kw == '$enddefinitions':
                            done = True
                        elif current_kw == '$date':
                            # Tokens collapsed to single-spaced string;
                            # original used \t / multi-line for readability.
                            self.date = ' '.join(body)
                        elif current_kw == '$version':
                            self.version = ' '.join(body)
                        elif current_kw == '$comment':
                            # Per 18.2.3.1, $comment may appear multiple
                            # times. Silent drop after the cap is safe:
                            # comments are metadata, not data — losing
                            # the 1025th comment only affects what
                            # `info --verbose` prints, never the waveform.
                            if len(self.comments) < MAX_COMMENTS:
                                self.comments.append(' '.join(body))
                        current_kw = None
                    else:
                        # Bound section body. In practice this only
                        # truncates oversized $comment / $date / $version
                        # bodies — metadata. $var bodies are 4-8 tokens,
                        # $scope is 2, $timescale is 2; none come close
                        # to the cap. Silent drop is safe because:
                        #   - the $end token still closes the section
                        #     correctly (we still see it in the outer
                        #     loop, we just stop appending to body)
                        #   - dropped tokens never become part of any
                        #     value_change interpretation
                        if len(body) < MAX_HEADER_BODY_TOKENS:
                            body.append(tok)
            self._data_offset = f.tell()

        # Phase 2: detect and reassemble bit-exploded signals.
        # Bit-exploded heuristic per QuestaSim convention: each bit is a
        # 1-bit $var with [N] suffix. We auto-reassemble ONLY when the bit
        # indices form a complete 0..max_bit contiguous set. Standard-legal
        # partial dumps (e.g. only $var ... bus[4] ... emitted) must NOT be
        # synthesized as a bus[4:0] with phantom lower bits — they are kept
        # as individual bit-select references.
        bit_groups = defaultdict(dict)  # (scope, base_name) -> {bit_idx: sym}
        bit_types = {}                   # (scope, base_name) -> vtype
        duplicate_bit_groups = set()      # groups with duplicate bit indices; never reassemble
        standalone = []
        bit_select_singletons = []       # (sym, name, idx, sc, vtype)

        for sym, name, w, bit_str, sc, vtype in raw_vars:
            if w == 1 and bit_str is not None:
                m = re.match(r'\[(\d+)\]', bit_str)
                if m:
                    idx = _safe_int_digits(m.group(1))
                    if idx is None:
                        # Overlong/malformed bit index — treat the $var as
                        # a standalone signal (its bit_str folded back).
                        standalone.append((sym, name + bit_str, 1, sc, vtype))
                        continue
                    group_key = (sc, name)
                    group = bit_groups[group_key]
                    if idx in group:
                        # Illegal VCD: duplicate bit-select declaration for the
                        # same reconstructed bus bit.  Do not silently let the
                        # later symbol overwrite the earlier one; mark the group
                        # non-reassemblable so all raw bit-select declarations
                        # remain visible as standalone signals.
                        duplicate_bit_groups.add(group_key)
                    else:
                        group[idx] = sym
                    # Resource cap: refuse to allocate gigantic synthesized
                    # buses (per-call template copy cost scales linearly).
                    # Default 65536 is 128× typical QuestaSim bit-bus size;
                    # tune via VCD_ANALYZER_MAX_REASSEMBLE_BITS env var.
                    if len(group) > MAX_REASSEMBLE_BITS:
                        raise _VCDResourceError(
                            'bit-exploded group {}.{} has more than {} bits. '
                            'Set VCD_ANALYZER_MAX_REASSEMBLE_BITS to raise the limit.'.format(
                                sc or '<root>', name, MAX_REASSEMBLE_BITS))
                    bit_types[(sc, name)] = vtype
                    bit_select_singletons.append((sym, name, idx, sc, vtype))
                    continue
                # A 1-bit reference written as a range (for example
                # data[0:0]) is not a bit-exploded bus bit. Preserve the
                # reference suffix in the displayed path instead of silently
                # dropping it. Some simulators emit this non-canonical form.
                standalone.append((sym, name + bit_str, 1, sc, vtype))
                continue
            standalone.append((sym, name, w, sc, vtype))

        # Partition bit_groups: contiguous-from-0 with ≥2 bits → reassemble;
        # everything else → individual bit-select references. A single
        # '[0]' declaration alone is NOT a bus — it's a partial dump that
        # happens to use bit 0; synthesizing it as 'data[0:0]' would lie
        # about the file structure.
        #
        # DoS guard: do NOT compute set(range(max+1)) — a malicious VCD with
        # 'bus[0]' + 'bus[1000000000]' would force materialization of a
        # billion-element set (gigabytes of RAM). Indices [0..max] form a
        # contiguous run iff: count == max+1 AND 0 is present. Both checks
        # are O(1) on dict_keys.
        non_contiguous = set(duplicate_bit_groups)
        for key, bits in bit_groups.items():
            if key in non_contiguous:
                continue
            indices = bits.keys()
            n = len(indices)
            if n < 2:
                non_contiguous.add(key)
                continue
            max_idx = max(indices)
            if max_idx + 1 != n or 0 not in indices:
                non_contiguous.add(key)

        # Each non-contiguous bit-select becomes a standalone 'name[idx]' signal
        for sym, name, idx, sc, vtype in bit_select_singletons:
            if (sc, name) in non_contiguous:
                standalone.append((sym, '{}[{}]'.format(name, idx), 1, sc, vtype))

        # Register standalone signals. Per IEEE 1364-2005 18.2.3.7, the same
        # identifier_code can be referenced under multiple paths. First seen
        # type wins when aliases have different var_types.
        for sym, name, w, sc, vtype in standalone:
            path = '{}.{}'.format(sc, name) if sc else name
            if sym in self.signals:
                self.signals[sym]['aliases'].append(path)
                if sc and sc not in self.signals[sym].setdefault('scopes', []):
                    self.signals[sym]['scopes'].append(sc)
            else:
                self.signals[sym] = {
                    'path': path, 'width': w, 'type': vtype,
                    'aliases': [path], 'scope': sc, 'scopes': [sc] if sc else []
                }

        for (sc, name), bits in bit_groups.items():
            if not bits or (sc, name) in non_contiguous:
                continue
            max_bit = max(bits.keys())
            width = max_bit + 1
            path = '{}.{}[{}:0]'.format(sc, name, max_bit) if sc else '{}[{}:0]'.format(name, max_bit)
            sig_id = '__grp__{}__{}'.format(sc, name)
            self.signals[sig_id] = {
                'path': path, 'width': width,
                'type': bit_types.get((sc, name), 'wire'),
                'aliases': [path], 'scope': sc, 'scopes': [sc] if sc else [],
                'synthesized': True,    # bit-exploded reassembled bus
                'raw_bits': len(bits),  # number of $var declarations consumed
            }
            self._bit_state_template[sig_id] = ['x'] * width
            # Per IEEE 1364-2005 18.2.3.7, the same identifier_code can be
            # referenced under multiple paths. When two bit-exploded buses
            # share per-bit identifier codes (e.g. bus[0]/aliasbus[0] both
            # use '!'), each is a separate synthesized signal that must
            # update independently. _bit_map is therefore 1-to-many.
            for idx, sym in bits.items():
                self._bit_map.setdefault(sym, []).append((sig_id, idx))

        # Raw $var counts (transparent to IEEE 1364 spec) so 'info' can
        # report accurate metadata even when reassembly collapses many
        # declarations into a single synthesized bus. Distinct from
        # `signal_count` (post-reassembly view used by agent commands).
        self.raw_var_count = len(raw_vars)
        self.raw_type_counts = defaultdict(int)
        for _sym, _name, _w, _bit_str, _sc, vtype in raw_vars:
            self.raw_type_counts[vtype] += 1

    def match(self, keywords):
        """Return set of sig_ids matching any pattern, or None for all.

        Plain patterns use case-insensitive substring matching. Patterns
        containing '*' or '?' use the tool's minimal glob-lite matching:
        '*' matches any span, '?' matches one character, and all other
        characters are literal. This intentionally differs from fnmatch:
        '[' and ']' are NOT character-class delimiters because VCD bus ranges
        like data[7:0] are common signal names.

        Input is normalized through _normalize_filter_patterns to bound
        pattern length and wildcard count.
        """
        if not keywords:
            return None
        raw_pats = [k.lower() for k in _normalize_filter_patterns(keywords) or []]
        if not raw_pats:
            return None
        pats = []
        for pat in raw_pats:
            if any(ch in pat for ch in '*?'):
                pats.append(('glob', _glob_lite_regex(pat)))
            else:
                pats.append(('substr', pat))
        out = set()
        for sid, info in self.signals.items():
            for path in info['aliases']:
                pl = path.lower()
                hit = False
                for kind, pat in pats:
                    hit = pat.match(pl) is not None if kind == 'glob' else pat in pl
                    if hit:
                        out.add(sid)
                        break
                if hit:
                    break
        return out

    def _data_tokens(self):
        """Generator yielding all tokens from the data section."""
        for t in self._initial_tokens:
            yield t
        with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(self._data_offset)
            for line in f:
                for t in line.split():
                    yield t

    def _is_structural_token(self, tok):
        """Return True when tok is structural rather than an identifier_code.

        Only #<digits> has positional ambiguity: it can be a timestamp at
        top level, or a legal identifier_code after b/r/p. If such a token is
        declared as a normal signal or bit-exploded bit, it is the symbol;
        otherwise it is structural and must be pushed back so the outer loop
        can process it as a timestamp.
        """
        if tok is None:
            return True
        if tok.startswith('#') and len(tok) > 1 and tok[1].isdigit():
            return tok not in self.signals and tok not in self._bit_map
        return False

    def _consume_value_change(self, tok, next_token, pushback):
        """Parse one VCD value_change token sequence.

        Returns (identifier_code, value_str) on a valid value_change, or None
        when tok is malformed / not a value_change. This is the single shared
        validation path used by iter_events() and scan_time_range(), so info's
        reported time range stays aligned with dump/search parsing behavior.

        next_token is a zero-arg function over the same pushback-capable token
        stream as the caller. If a token consumed while validating b/r/p turns
        out to be structural, it is pushed back in the same order used by the
        old local parsers.
        """
        if not tok:
            return None
        first = tok[0]

        if first in '01xXzZ':
            sym = tok[1:]
            if not sym:
                return None
            return sym, first.lower()

        if first in 'bB':
            bits = tok[1:]
            if not bits or any(c not in '01xXzZ' for c in bits):
                return None
            sym = next_token()
            if self._is_structural_token(sym):
                if sym is not None:
                    pushback.append(sym)
                return None
            return sym, bits.lower()

        if first in 'rR':
            body = tok[1:]
            if len(body) > _REAL_MAX_LEN or not _REAL_RE.match(body):
                return None
            sym = next_token()
            if self._is_structural_token(sym):
                if sym is not None:
                    pushback.append(sym)
                return None
            return sym, body

        if first == 'p':
            # Extended VCD (18.4.3.1): p<state> <s0> <s1> <id>.
            # Keep this validation in one place so malformed port events are
            # treated identically by iter_events() and scan_time_range().
            state = tok[1:] if len(tok) > 1 else ''
            if not state or any(c not in _PORT_STATE for c in state):
                return None

            s0 = next_token()
            if s0 is None or len(s0) != 1 or s0 not in '01234567':
                if s0 is not None:
                    pushback.append(s0)
                return None

            s1 = next_token()
            if s1 is None or len(s1) != 1 or s1 not in '01234567':
                if s1 is not None:
                    pushback.append(s1)
                pushback.append(s0)
                return None

            sym = next_token()
            if self._is_structural_token(sym):
                if sym is not None:
                    pushback.append(sym)
                pushback.append(s1)
                pushback.append(s0)
                return None
            return sym, ''.join(_PORT_STATE[c] for c in state)

        return None

    def iter_events(self, t0=0, t1=None, sids=None):
        """Yield (time, sig_id, value_str) with bit reassembly.

        Token-based, context-sensitive. Section keywords ($comment/$vcdclose/
        $dumpvars/$dumpoff/$dumpon/$dumpall/$dumpports*) are only recognized
        when the parser is at a top-level position (expecting either a
        timestamp or a value_change opener). After 'b<bits>', 'r<num>', or
        'p<state> <s0> <s1>' the NEXT token is consumed as identifier_code
        even if it happens to be the string '$comment' (legal per
        IEEE 1364-2005 18.2.1: identifier_code is any printable ASCII).

        Initial value changes appearing before any '#T' timestamp are
        emitted at logical t=0 (typical case: $dumpvars block directly
        after $enddefinitions without a leading #0).
        """
        cur_t = 0
        pending = {}

        def _flush():
            if not pending:
                return []
            items = list(pending.items())
            pending.clear()
            return items

        # Pushback-capable token stream. Lets us peek the next token in
        # b/r value_change branches and refuse it if it looks structural
        # (timestamp or section keyword) — otherwise malformed inputs
        # like 'b1010\n#10\n1!' would silently consume #10 as the
        # identifier_code and corrupt the timeline.
        raw = self._data_tokens()
        pushback = []
        # Replay-local bit state. iter_events() must be pure with respect
        # to parser metadata: compare/search/summary/snapshot may replay
        # the same VCDParser multiple times and in non-monotonic order.
        # Object-level mutable state would leak future bit values into
        # earlier snapshots for bit-exploded buses.
        #
        # Laziness: when the caller selected a subset of signals (sids),
        # maintain only the synthesized bit-buses that can be emitted for
        # this query. This avoids touching large unrelated bit-exploded
        # buses during catch-up scans, while preserving exact behavior for
        # selected buses and for no-filter calls.
        if sids is None:
            bit_map = self._bit_map
            bit_state = {gid: bits[:] for gid, bits in self._bit_state_template.items()}
        else:
            bit_map = {}
            needed_gids = set()
            for sym0, refs in self._bit_map.items():
                kept = [(gid, idx) for gid, idx in refs if gid in sids]
                if kept:
                    bit_map[sym0] = kept
                    for gid, _idx in kept:
                        needed_gids.add(gid)
            bit_state = {gid: self._bit_state_template[gid][:] for gid in needed_gids}

        def _next():
            return pushback.pop() if pushback else next(raw, None)

        try:
            while True:
                tok = _next()
                if tok is None:
                    break
                # Top-level: any unknown $keyword starts a section ending at
                # $end. This is safer than passing the body through as value
                # changes — '$bogus 1! $end' must not pollute the waveform.
                # Known wrappers ($dumpvars etc) are pass-through (their body
                # IS value_changes per 18.2.3.9-12).
                if tok == '$end':
                    continue
                if tok in _SIM_KEYWORDS:
                    continue
                if tok.startswith('$'):
                    # $comment, $vcdclose, $bogus, ...: drop body to $end
                    for t in raw:
                        if t == '$end':
                            break
                    continue
    
                if tok.startswith('#') and len(tok) > 1 and tok[1].isdigit():
                    new_t = _parse_vcd_timestamp_token(tok)
                    if new_t is None:
                        # Malformed (e.g. '#1.5'); silently skip per round-7 policy.
                        continue
                    if cur_t >= t0:
                        for sid, val in _flush():
                            yield cur_t, sid, val
                    cur_t = new_t
                    if t1 is not None and cur_t > t1:
                        return
                    continue

                # ---- Fast-path filter: skip value changes for unneeded signals ----
                # Check the identifier_code BEFORE calling _consume_value_change().
                # For 1-bit VCs (90%+ of all tokens), the identifier is tok[1:].
                # For b/r multi-token VCs, peek the next token (the identifier).
                # This avoids the full parsing overhead for 99.99% of tokens when
                # --filter selects a handful of signals out of 200K+.
                if sids is not None:
                    c = tok[0]
                    if c in '01xzXZ' and len(tok) >= 2:
                        sym = tok[1:]
                        if sym not in sids and sym not in bit_map:
                            continue
                    elif c in 'bBrR':
                        sym_tok = _next()
                        if sym_tok is not None and not self._is_structural_token(sym_tok):
                            if sym_tok not in sids and sym_tok not in bit_map:
                                continue  # consume both tokens, skip
                            pushback.append(sym_tok)  # needed — put back for parser
                        elif sym_tok is not None:
                            pushback.append(sym_tok)
    
                # Shared value_change parser. Keeping b/r/p validation in one
                # helper prevents scan_time_range() and iter_events() from
                # drifting apart when malformed-token rules are adjusted.
                parsed = self._consume_value_change(tok, _next, pushback)
                if parsed is None:
                    continue
                sym, val = parsed
    
                # Catch-up before t0: update bit_state only, don't emit.
                # Standalone state is owned by callers (e.g. _build_snapshot
                # accumulates it from yielded events), so nothing to do here
                # for the standalone case — the continue is correct.
                if cur_t < t0:
                    if sym in bit_map:
                        bit_val = val if _is_4state_bits(val) and len(val) == 1 else 'x'
                        for gid, idx in bit_map[sym]:
                            bit_state[gid][idx] = bit_val
                    continue
    
                # Bit-exploded signal: aggregate into virtual bus value(s).
                # If the same identifier_code drives multiple synthesized buses
                # (via aliased parent declarations), each gets its own event.
                #
                # IMPORTANT: do NOT continue after this branch. Per IEEE 1364-2005
                # 18.2.3.7, the same identifier_code can be referenced by both a
                # standalone $var (e.g. clk) AND a bit-select $var (e.g.
                # data_bus[0]) when RTL assigns one to the other. If we continued,
                # the standalone alias would silently never emit events and the
                # agent would see clk as a flat line. Fall through to the
                # standalone block so both signals update on the same value_change.
                if sym in bit_map:
                    bit_val = val if _is_4state_bits(val) and len(val) == 1 else 'x'
                    for gid, idx in bit_map[sym]:
                        bit_state[gid][idx] = bit_val
                        if sids is None or gid in sids:
                            pending[gid] = ''.join(reversed(bit_state[gid]))
    
                # Standalone signal (may run after the bit-bus branch above when
                # the sym serves both roles).
                if sym not in self.signals:
                    continue
                if sids is not None and sym not in sids:
                    continue
                pending[sym] = _clamp_overwide_logic_value(val, self.signals[sym])
    
            # Final flush
            if cur_t >= t0:
                for sid, val in _flush():
                    yield cur_t, sid, val
        finally:
            close = getattr(raw, 'close', None)
            if close is not None:
                close()

    def scan_time_range(self):
        """Min/max timestamps in the file.

        Uses a bidirectional strategy for large files:
        - **t_min**: forward scan from ``_data_offset`` — stops at the first
          ``#T`` token (typically within the first few KB of data).  If value
          changes appear before any timestamp, *t_min* is 0.
        - **t_max**: backward scan from EOF — reads a 64 KB tail chunk and
          finds the last ``#<digits>`` token that begins a line.  The buffer
          doubles up to 4 MB on retry; for tiny files the forward scan already
          covers the whole data section.

        This avoids a full sequential scan of the data section, reducing
        ``info`` on a 500 MB VCD from ~90 s to < 0.1 s.
        """
        # -- t_min: forward scan --
        t_min = None
        saw_initial_data = False
        with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(self._data_offset)
            for line in f:
                for tok in line.split():
                    if tok == '$end' or tok in _SIM_KEYWORDS:
                        if tok == '$dumpvars':
                            saw_initial_data = True
                        continue
                    if tok.startswith('$'):
                        # skip to $end of this section
                        for t2 in f:
                            if '$end' in t2:
                                break
                        break
                    if tok.startswith('#') and len(tok) > 1:
                        try:
                            t_min = 0 if saw_initial_data else int(tok[1:])
                        except ValueError:
                            continue
                        break
                    # Value change before first timestamp
                    c = tok[0]
                    if c in '01xzXZbBrRpP' and len(tok) >= 2:
                        saw_initial_data = True
                if t_min is not None:
                    break

        if t_min is None and saw_initial_data:
            t_min = 0

        # -- t_max: backward scan from EOF --
        import os as _os
        file_size = _os.path.getsize(self.path)
        # _data_offset may be a text-mode tell() cookie (opaque, potentially
        # larger than file_size); clamp to a safe floor for binary seek.
        safe_data_offset = self._data_offset if self._data_offset < file_size else 0
        t_max = None
        buf_size = 65536
        while buf_size <= 4 * 1024 * 1024:
            offset = max(safe_data_offset, file_size - buf_size)
            with open(self.path, 'rb') as f:
                f.seek(offset)
                chunk = f.read().decode('ascii', errors='replace')
            # Match #<digits> at start of line to avoid false positives
            timestamps = re.findall(r'(?:^|\n)#(\d+)', chunk)
            if timestamps:
                t_max = max(int(t) for t in timestamps)
                break
            if offset <= safe_data_offset:
                break  # already read the whole data section
            buf_size *= 2

        if t_max is None:
            t_max = t_min
        if t_min is None:
            t_min = t_max
        return t_min, t_max



# -- Subcommands -------------------------------------------------------------

_DEFAULT_LIMIT = 200


def _json(obj):
    """Compact JSON for agent use."""
    print(json.dumps(obj, ensure_ascii=False, separators=(',', ':')))


def _limit(args, cmd):
    """Resolve global output limit. --verbose disables truncation unless an
    explicit --limit was supplied. --limit 0 always means unlimited."""
    val = getattr(args, 'limit', None)
    if val is None:
        return 0 if getattr(args, 'verbose', False) else _DEFAULT_LIMIT
    if val < 0:
        raise _TimeParseError('limit must be non-negative; got {}'.format(val))
    return val


def _clip(seq, limit):
    if limit == 0:
        return seq, False
    return seq[:limit], len(seq) > limit


def _trunc_line(shown, total, noun):
    return '... truncated: {}/{} {} shown.'.format(shown, total, noun)


def _trunc_line_lower_bound(shown, total, noun):
    """Truncation line when scanning stopped at the first unshown result.

    Used by streaming commands where --limit is an execution bound, not just
    an output bound. `total` is a lower bound (normally shown + 1),
    not the exact global result count.
    """
    return '... truncated: {}/{}+ {} shown.'.format(shown, total, noun)


def _total_json_fields(total, truncated):
    """Return JSON count fields for exact vs early-stopped result sets.

    When truncated is true, total is only a lower bound (usually limit+1).
    Keeping it numeric is convenient for agents, while total_is_exact prevents
    consumers from treating it as the real global count.
    """
    return {'total': total, 'total_is_exact': not truncated}


def _count_label(shown, total, truncated):
    """Human count label for result headers."""
    return '{}+'.format(total) if truncated else str(total)


def _selected_sids(vcd, sids):
    """Return an explicit set of selected signal ids."""
    return set(vcd.signals.keys()) if sids is None else set(sids)


def _fmt_maybe(value, info):
    return fmt_val(value, info) if value is not None else '(undef)'


def _time_pair(prefix, t, ts):
    """Return both integer ticks and human-readable time for JSON outputs."""
    return {prefix + '_ticks': t, prefix + '_h': fmt_time(t, ts) if t is not None else None}


def _build_snapshot(vcd, t_at, sids=None):
    """Replay from start through t_at, return known {sig_id: value} only."""
    state = {}
    for _t, sid, val in vcd.iter_events(0, t_at, sids):
        state[sid] = val
    return state


def _build_snapshot_before(vcd, t_at, sids=None):
    """Replay from start up to, but excluding, t_at.

    Used by search --changed. A value_change exactly at --begin must remain
    observable as a transition. Because VCD timestamps are integer ticks, the
    exclusive snapshot is simply the inclusive snapshot at t_at - 1. At t=0
    there is no prior state; initialization is handled explicitly by the
    changed-mode loop and is not reported as a real change.
    """
    if t_at <= 0:
        return {}
    return _build_snapshot(vcd, t_at - 1, sids)


def _build_snapshot_pair(vcd, ta, tb, sids=None):
    """Build snapshots at ta and tb in a single iter_events pass.

    Assumes ta <= tb. Returns (snapshot_a, snapshot_b) where each is
    {sid: value} at the corresponding boundary (last value at or before
    the given time, inclusive).
    """
    state = {}
    snapshot_a = None
    for t, sid, val in vcd.iter_events(0, tb, sids):
        if snapshot_a is None and t > ta:
            snapshot_a = dict(state)
        state[sid] = val
    if snapshot_a is None:
        snapshot_a = dict(state)
    return snapshot_a, dict(state)


def _parse_target_value(text):
    """Parse search/condition target once with bounded cost.

    Returns (target_raw, target_int):

      - Numeric targets (decimal, 0x..., 0b..., b...) get target_int and are
        matched only by numeric equality.
      - 4-state binary literals with x/z keep a raw bit-string target. Explicit
        binary prefixes are stripped because VCD stores vector values as
        ``1x0`` internally, not ``b1x0``.

    Invalid hex and negative decimal targets are rejected rather than silently
    producing no matches; VCD value_change text is unsigned, and x/z literals
    should be written in binary form (e.g. b1x0z).
    """
    if text is None:
        raise _ValueParseError('target value must not be empty')
    raw = str(text).lower().strip()
    if not raw:
        raise _ValueParseError('target value must not be empty')
    if len(raw) > MAX_VALUE_ARG_LEN:
        raise _ValueParseError(
            'target value too long; max length is {}'.format(MAX_VALUE_ARG_LEN))

    if raw.startswith('-'):
        raise _ValueParseError(
            'negative target values are not supported for VCD signal matching')

    if raw.startswith('0x'):
        body = raw[2:]
        if not body:
            raise _ValueParseError('hex target must contain at least one digit')
        if len(body) > MAX_HEX_VALUE_DIGITS:
            raise _ValueParseError(
                'hex target too wide; max hex digits is {}'.format(MAX_HEX_VALUE_DIGITS))
        try:
            return raw, int(raw, 16)
        except ValueError:
            raise _ValueParseError(
                'invalid hex target {!r}; x/z literals must use binary form like b1x0z'.format(text))

    if raw.startswith('0b'):
        body = raw[2:]
        if not body:
            raise _ValueParseError('binary target must contain at least one bit')
        if len(body) > MAX_SIGNAL_WIDTH:
            raise _ValueParseError(
                'binary target too wide; max bits is {}'.format(MAX_SIGNAL_WIDTH))
        try:
            return body, int(body, 2)
        except ValueError:
            if all(c in '01xz' for c in body):
                return body, None
            raise _ValueParseError(
                'invalid binary target {!r}; expected only 0/1/x/z'.format(text))

    if raw.startswith('b'):
        body = raw[1:]
        if not body:
            raise _ValueParseError('binary target must contain at least one bit')
        if len(body) > MAX_SIGNAL_WIDTH:
            raise _ValueParseError(
                'binary target too wide; max bits is {}'.format(MAX_SIGNAL_WIDTH))
        try:
            return body, int(body, 2)
        except ValueError:
            if all(c in '01xz' for c in body):
                return body, None
            raise _ValueParseError(
                'invalid binary target {!r}; expected only 0/1/x/z'.format(text))

    # Bare target: decimal numeric if possible, otherwise literal 4-state
    # string (e.g. ``1x0``). Cap pure decimal digit count before int().
    if raw.startswith('+'):
        raise _ValueParseError(
            'signed target values are not supported; write unsigned values')
    if raw.isdigit() and len(raw) > MAX_DECIMAL_VALUE_DIGITS:
        raise _ValueParseError(
            'decimal target too long; max digits is {}'.format(MAX_DECIMAL_VALUE_DIGITS))
    try:
        return raw, int(raw)
    except ValueError:
        if len(raw) > MAX_SIGNAL_WIDTH:
            raise _ValueParseError(
                'literal target too wide; max characters is {}'.format(MAX_SIGNAL_WIDTH))
        return raw, None


def _is_4state_bits(text):
    return text is not None and text != '' and all(c in '01xz' for c in text)


def _left_extend_bits(bits, width):
    """Apply VCD vector left-extension to a 4-state bit string.

    When a dumped vector is shorter than its declared width, IEEE VCD
    semantics extend the MSB leftward: x extends with x, z with z, and
    0/1 with 0. Use the same rule for user 4-state targets so a condition
    such as data=b1x0 can match an 8-bit stored value 000001x0 without
    asking the Agent to spell out every leading zero.
    """
    if width is None or len(bits) >= width:
        return bits
    msb = bits[0]
    pad = msb if msb in ('x', 'z') else '0'
    return pad * (width - len(bits)) + bits


def _value_matches(value, target_raw, target_int, width=None):
    """Match a recorded value against a parsed search target.

    Numeric targets (decimal/hex/binary without x/z) match only by numeric
    equality, avoiding the decimal/binary collision where target 10 would
    otherwise raw-match a 2-bit value "10".

    Non-numeric 4-state targets (for example b1x0 -> raw "1x0") match as
    bit patterns. If the signal width is known, both the dumped value and the
    target are left-extended to that width using VCD rules before comparison.
    This preserves exact x/z semantics while avoiding the need to write every
    leading zero for wide buses. Non-bit-string literals fall back to exact
    string equality.
    """
    if target_int is not None:
        iv = val_to_int(value)
        return iv is not None and iv == target_int
    if width is not None and _is_4state_bits(value) and _is_4state_bits(target_raw):
        if len(target_raw) > width:
            return False
        return _left_extend_bits(value, width) == _left_extend_bits(target_raw, width)
    return value == target_raw


_COND_RE = re.compile(r'^\s*(.+?)\s*(==|=|!=)\s*(.+?)\s*$')


def _has_unknown(value):
    """True when a VCD value is unknown/ambiguous for negative predicates."""
    return value is None or 'x' in value or 'z' in value


def _condition_match(value, op, target_raw, target_int, width=None):
    """Evaluate one resolved condition against a raw VCD value.

    Equality reuses the existing two-mode value matcher, so numeric targets
    are compared numerically and mixed x/z literals are compared as 4-state
    bit patterns, width-aware when the signal width is available.

    Inequality is deliberately stricter than `not _value_matches(...)`:
    x/z/undef do NOT satisfy `!=`. In RTL debug, unknown is not evidence that
    a signal is definitely different from a value. Users who want unknowns
    should ask for them explicitly, e.g. `valid=x`.
    """
    if value is None:
        return False
    if op in ('=', '=='):
        return _value_matches(value, target_raw, target_int, width)
    if op == '!=':
        if _has_unknown(value):
            return False
        return not _value_matches(value, target_raw, target_int, width)
    raise AssertionError('unsupported condition operator {}'.format(op))


def _parse_conditions(text):
    """Parse comma-separated AND conditions into unresolved condition dicts."""
    if text is None or not str(text).strip():
        raise _ConditionParseError('search requires --condition')
    conditions = []
    for item in str(text).split(','):
        item = item.strip()
        if not item:
            continue
        m = _COND_RE.match(item)
        if not m:
            raise _ConditionParseError(
                'invalid condition {!r}; expected SIG=VAL, SIG==VAL, or SIG!=VAL'.format(item))
        sig_pat = m.group(1).strip()
        op = m.group(2)
        val_text = m.group(3).strip()
        if not sig_pat or not val_text:
            raise _ConditionParseError(
                'invalid empty signal/value in condition {!r}'.format(item))
        target_raw, target_int = _parse_target_value(val_text)
        conditions.append({
            'pattern': sig_pat,
            'op': op,
            'target_raw': target_raw,
            'target_int': target_int,
            'original': item,
            'value_text': val_text,
        })
    if not conditions:
        raise _ConditionParseError('search requires at least one condition')
    return conditions


def _resolve_one_signal(vcd, pattern, role):
    """Resolve a condition/trigger pattern to exactly one signal id.

    Matching normally follows VCDParser.match(): substring unless '*' or '?'
    is present. For condition/trigger positions, however, an exact full path
    should win over substring matches. Otherwise a precise path like
    'tb.u.rd_valid' would be rejected merely because 'tb.u.rd_valid0' exists.
    """
    pat = str(pattern).strip()
    pl = pat.lower()
    exact = set()
    if '*' not in pat and '?' not in pat:
        for sid, info in vcd.signals.items():
            for path in info['aliases']:
                if path.lower() == pl:
                    exact.add(sid)
        if len(exact) == 1:
            return next(iter(exact))
        if len(exact) > 1:
            examples = [vcd.signals[s]['path']
                        for s in sorted(exact, key=lambda sid: vcd.signals[sid]['path'])[:5]]
            raise _ConditionParseError(
                '{} pattern {!r} exactly matches {} signals; use list to choose a more specific name, examples: {}'.format(
                    role, pattern, len(exact), ', '.join(examples)))

    sids = vcd.match([pattern])
    if not sids:
        raise _ConditionParseError('{} pattern {!r} matches no signals'.format(role, pattern))
    if len(sids) != 1:
        examples = [vcd.signals[s]['path']
                    for s in sorted(sids, key=lambda sid: vcd.signals[sid]['path'])[:5]]
        extra = ', examples: {}'.format(', '.join(examples)) if examples else ''
        raise _ConditionParseError(
            '{} pattern {!r} matches {} signals; use list to choose a more specific name{}'.format(
                role, pattern, len(sids), extra))
    return next(iter(sids))


def _resolve_conditions(vcd, text):
    """Parse and resolve condition signal patterns to signal ids."""
    resolved = []
    seen = set()
    for c in _parse_conditions(text):
        sid = _resolve_one_signal(vcd, c['pattern'], 'condition signal')
        key = (sid, c['op'], c['target_raw'], c['target_int'])
        if key in seen:
            continue
        seen.add(key)
        c = dict(c)
        c['sid'] = sid
        c['path'] = vcd.signals[sid]['path']
        c['width'] = vcd.signals[sid]['width']
        resolved.append(c)
    return resolved


def _resolve_show_sids(vcd, show_patterns):
    """Resolve --show patterns to one or more signal ids.

    Show positions are allowed to match multiple signals, but an exact full
    path still wins over substring matching for that specific pattern. This
    keeps `--show tb.data` from unexpectedly also selecting `tb.data_out`;
    users who want broad matching can still write `--show data` or use glob
    patterns such as `--show "*data*"`.
    """
    if not show_patterns:
        return []
    # Normalize even for list inputs.  argparse already does this for CLI
    # strings, but repeating the bounded, idempotent normalization keeps the
    # helper safe for programmatic callers as well.
    pats = _normalize_filter_patterns(show_patterns)
    if not pats:
        return []

    selected = set()
    missing = []
    for pat in pats:
        pat_text = str(pat).strip()
        exact = set()
        if '*' not in pat_text and '?' not in pat_text:
            pl = pat_text.lower()
            for sid, info in vcd.signals.items():
                for path in info['aliases']:
                    if path.lower() == pl:
                        exact.add(sid)
            if exact:
                selected.update(exact)
                continue

        matched = vcd.match([pat_text])
        if matched:
            selected.update(matched)
        else:
            missing.append(pat_text)

    if missing:
        raise _ConditionParseError(
            '--show matches no signals: {}'.format(', '.join(missing)))
    if not selected:
        raise _ConditionParseError('--show matches no signals')
    return sorted(selected, key=lambda sid: vcd.signals[sid]['path'])


def _conditions_hold(state, conditions):
    for c in conditions:
        if not _condition_match(
                state.get(c['sid']), c['op'], c['target_raw'],
                c['target_int'], c.get('width')):
            return False
    return True


def _condition_label(conditions):
    return ','.join(c['original'] for c in conditions)


def _condition_result_text(conditions):
    return ','.join('{}{}{}'.format(c['path'], c['op'], c['value_text']) for c in conditions)


def _show_values(vcd, state, show_sids, verbose=False):
    """Return (values, meta) for show signals in current state.

    The return shape is intentionally stable regardless of verbose. meta is
    None unless verbose=True. This avoids type-dependent unpacking in search.
    """
    values = {}
    meta = {} if verbose else None
    for sid in show_sids:
        info = vcd.signals[sid]
        path = info['path']
        raw = state.get(sid)
        values[path] = fmt_val(raw, info) if raw is not None else '(undef)'
        if verbose:
            meta[path] = {'raw': raw, 'width': info['width'], 'type': info.get('type', 'wire')}
    return values, meta


def _values_text(values):
    return ' '.join('{}={}'.format(k, v) for k, v in values.items())


def _search_end_time(vcd, t0, t1):
    if t1 is not None:
        return t1
    _mn, mx = vcd.scan_time_range()
    if mx is None:
        raise _ConditionParseError(
            'search cannot evaluate condition: VCD data section contains no value changes')
    return mx


def _event_groups(vcd, t0, t1, sids):
    """Yield (time, [(sid, val), ...]) groups in time order."""
    cur_t = None
    group = []
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        if cur_t is None:
            cur_t = t
        if t != cur_t:
            yield cur_t, group
            cur_t, group = t, []
        group.append((sid, val))
    if cur_t is not None:
        yield cur_t, group


def _summary_rows(vcd, t0, t1, sids):
    """Return (rows, counts) for window summary.

    Baseline captures state up to init_boundary: t=0 when the window starts
    at 0 (so $dumpvars initialization is part of the baseline, not counted
    as changes), or t0-1 when the window starts later (so value_changes
    exactly at --begin are counted as in-window events, fixing the boundary
    black-hole where transitions at the window edge were silently dropped).

    Static means known in baseline and no value changes inside the window.
    Undefined means selected but not known in baseline and no value changes
    inside the window. No unknown values are invented.

    For 1-bit signals, rise/fall counts are reported for clean 0->1 and 1->0
    transitions only. x/z-related transitions still count as changes, but not
    as rises/falls.
    """
    selected = _selected_sids(vcd, sids)
    init_boundary = 0 if t0 == 0 else t0 - 1

    # Baseline: {sid: val} — cheap str overwrites, same as _build_snapshot.
    # Stats dicts are created only once per signal, not on every baseline event.
    baseline = {}
    stats = {}

    def _make_stats(info, init_val):
        is_scalar = info['width'] == 1
        return {
            'changes': 0, 'first_at': None, 'last_at': None,
            'initial': init_val, 'last': init_val,
            'unique': {init_val} if init_val is not None else set(),
            'prev': init_val,
            'rise_count': 0 if is_scalar else None,
            'fall_count': 0 if is_scalar else None,
        }

    for t, sid, val in vcd.iter_events(0, t1, selected):
        if t <= init_boundary:
            baseline[sid] = val
            continue

        # First event in analysis window for this signal —
        # initialize stats from baseline snapshot (if any).
        if sid not in stats:
            init_val = baseline.pop(sid, None)
            stats[sid] = _make_stats(vcd.signals[sid], init_val)

        s = stats[sid]
        prev = s['prev']
        info = vcd.signals[sid]
        if info['width'] == 1:
            if prev == '0' and val == '1':
                s['rise_count'] += 1
            elif prev == '1' and val == '0':
                s['fall_count'] += 1
        s['changes'] += 1
        if s['first_at'] is None:
            s['first_at'] = t
        s['last_at'] = t
        s['last'] = val
        s['prev'] = val
        s['unique'].add(val)

    # Signals that were in baseline but had no in-window events (static).
    for sid, val in baseline.items():
        stats[sid] = _make_stats(vcd.signals[sid], val)

    rows = []
    for sid in sorted(stats, key=lambda x: vcd.signals[x]['path']):
        info = vcd.signals[sid]
        s = stats[sid]
        kind = 'active' if s['changes'] else 'static'
        row = {
            'kind': kind,
            'path': info['path'],
            'value': fmt_val(s['last'], info) if kind == 'static' else None,
            'changes': s['changes'],
            'rise_count': s['rise_count'],
            'fall_count': s['fall_count'],
            'init': _fmt_maybe(s['initial'], info),
            'last': _fmt_maybe(s['last'], info),
        }
        if s['first_at'] is not None:
            row['first_at_ticks'] = s['first_at']
            row['first_at'] = fmt_time(s['first_at'], vcd.ts_sec)
            row['first_at_h'] = row['first_at']
            row['last_at_ticks'] = s['last_at']
            row['last_at'] = fmt_time(s['last_at'], vcd.ts_sec)
            row['last_at_h'] = row['last_at']
        if s['unique']:
            row['unique'] = len(s['unique'])
        row['_width'] = info['width']
        row['_type'] = info.get('type', 'wire')
        rows.append(row)

    undefined = sorted(selected - set(stats), key=lambda x: vcd.signals[x]['path'])
    counts = {
        'selected': len(selected), 'defined': len(stats), 'undefined': len(undefined),
        'active': sum(1 for r in rows if r['kind'] == 'active'),
        'static': sum(1 for r in rows if r['kind'] == 'static'),
    }
    return rows, undefined, counts

def _public_row(row, verbose=False):
    r = dict(row)
    width = r.pop('_width', None)
    typ = r.pop('_type', None)
    if verbose:
        r['width'] = width
        r['type'] = typ
    return r# ================================================================
# Part 7: FST Parser Adapter
# ================================================================



# ==========================================================================
# FST Parser Adapter
# ==========================================================================

_FST_VAR_TYPE_NAMES = {
    0: 'event', 1: 'integer', 2: 'parameter', 3: 'real', 4: 'real',
    5: 'reg', 6: 'supply0', 7: 'supply1', 8: 'time', 9: 'tri',
    10: 'triand', 11: 'trior', 12: 'trireg', 13: 'tri0', 14: 'tri1',
    15: 'wand', 16: 'wire', 17: 'wor', 18: 'port', 19: 'sparray',
    20: 'realtime', 21: 'string',
}
for _sv in range(22, 30):
    _FST_VAR_TYPE_NAMES.setdefault(_sv, 'wire')


class FSTParser:
    def __init__(self, path):
        self.path = path
        self._reader = _FstReader(path)
        hdr = self._reader.header
        self.ts_sec = 10 ** hdr.timescale
        ts_unit = 's'
        for u, scale in sorted(_UNITS.items(), key=lambda x: -x[1]):
            if abs(self.ts_sec - scale) < 1e-12:
                ts_unit = u
                break
        self.ts_str = '$timescale 1{} $end'.format(ts_unit)
        self.date = hdr.date
        self.version = hdr.version
        self.comments = list(self._reader.comments)

        # --- Single-pass hierarchy traversal ---
        self.signals = {}
        self.raw_var_count = 0
        self.raw_type_counts = defaultdict(int)

        for ev in self._reader.hierarchy():
            if not isinstance(ev, FstVar):
                continue

            self.raw_var_count += 1
            h = ev.handle
            path = ev.full_name

            # Normalize "name [msb:lsb]" -> "name[msb:lsb]" (FST hierarchy
            # inserts a space before the bracket).  String ops instead of regex.
            bracket_pos = path.find(' [')
            if bracket_pos >= 0:
                path = path[:bracket_pos] + path[bracket_pos + 1:]

            vtype_name = _FST_VAR_TYPE_NAMES.get(ev.var_type, 'wire')
            self.raw_type_counts[vtype_name] += 1

            is_real = ev.var_type in (FstVarType.VCD_REAL, FstVarType.VCD_REAL_PARAMETER,
                                       FstVarType.VCD_REALTIME, FstVarType.SV_SHORTREAL)
            vtype = 'real' if is_real else vtype_name
            if ev.var_type == FstVarType.VCD_REALTIME:
                vtype = 'realtime'

            scope = ''
            dot_pos = path.rfind('.')
            if dot_pos >= 0:
                scope = path[:dot_pos]

            if h in self.signals:
                self.signals[h]['aliases'].append(path)
                if scope and scope not in self.signals[h]['scopes']:
                    self.signals[h]['scopes'].append(scope)
            else:
                width = ev.length if not is_real else 64
                if ev.var_type == FstVarType.VCD_EVENT:
                    width = 1
                self.signals[h] = {
                    'path': path, 'width': width, 'type': vtype,
                    'aliases': [path], 'scope': scope,
                    'scopes': [scope] if scope else [],
                }

    def match(self, keywords):
        if not keywords:
            return None
        raw_pats = [k.lower() for k in _normalize_filter_patterns(keywords) or []]
        if not raw_pats:
            return None
        pats = []
        for pat in raw_pats:
            if any(ch in pat for ch in '*?'):
                pats.append(('glob', _glob_lite_regex(pat)))
            else:
                pats.append(('substr', pat))
        out = set()
        for sid, info in self.signals.items():
            for path in info['aliases']:
                pl = path.lower()
                for kind, pat in pats:
                    if (kind == 'glob' and pat.match(pl)) or (kind == 'substr' and pat in pl):
                        out.add(sid)
                        break
        return out

    def _format_raw_value(self, handle, raw_val):
        """Convert raw FST bytes to display string for a single value."""
        if isinstance(raw_val, memoryview):
            raw_val = bytes(raw_val)
        var = self._reader._handle_to_var.get(handle)
        var_type = var.var_type if var else -1
        info = self.signals[handle]
        real_types = {FstVarType.VCD_REAL, FstVarType.VCD_REAL_PARAMETER,
                      FstVarType.VCD_REALTIME, FstVarType.SV_SHORTREAL}
        if var_type in real_types and len(raw_val) >= 8:
            try:
                fmt = '<d' if self._reader.header.double_endian_match else '>d'
                dval = struct.unpack(fmt, raw_val[:8])[0]
                return '{:.16g}'.format(dval)
            except Exception:
                return raw_val.decode('utf-8', errors='replace')
        elif info.get('type') == 'string' or info['width'] == 0:
            return raw_val.decode('utf-8', errors='replace')
        elif info['width'] == 1:
            val_str = raw_val.decode('ascii', errors='replace')
            return val_str if val_str in '01xz' else 'x'
        else:
            val_str = raw_val.decode('ascii', errors='replace')
            if not all(c in '01xz' for c in val_str):
                val_str = ''.join(c if c in '01xz' else 'x' for c in val_str)
            return val_str

    def iter_events(self, t0=0, t1=None, sids=None):
        sections = self._reader._vc_sections
        if not sections:
            return

        # Determine which sections overlap the query window.
        first_needed = 0
        last_needed = len(sections) - 1
        while first_needed < len(sections) and sections[first_needed].end_time < t0:
            first_needed += 1
        if t1 is not None:
            while last_needed >= first_needed and sections[last_needed].beg_time > t1:
                last_needed -= 1
        needed = last_needed - first_needed + 1

        # Bulk-parse when most sections will be touched.
        # Avoids per-section _ensure_section_parsed overhead inside generators.
        if needed > 1 and needed >= len(sections) // 2:
            self._reader._ensure_all_sections_parsed()

        for section_idx in range(first_needed, last_needed + 1):
            if sids is not None:
                yield from self._iter_events_filtered(
                    section_idx, t0, t1, sids)
            else:
                yield from self._iter_events_all(
                    section_idx, t0, t1)

    def _iter_events_filtered(self, section_idx, t0, t1, sids):
        """Selective path: decompress only the requested handles."""
        # Build per-handle iterators and merge in time order.
        # Each entry in the heap: (time, sequence_counter, handle, value_bytes)
        iterators = []
        for handle in sids:
            if handle not in self.signals:
                continue
            it = self._reader.iter_value_changes(handle, section_idx)
            iterators.append((it, handle))

        heap = []
        seq = 0
        for it, handle in iterators:
            val = next(it, None)
            if val is not None:
                fst_time, raw_val = val
                heapq.heappush(heap, (fst_time, seq, handle, raw_val, it))
                seq += 1

        while heap:
            fst_time, _, handle, raw_val, it = heapq.heappop(heap)
            if t1 is not None and fst_time > t1:
                return
            if fst_time >= t0:
                yield (fst_time, handle, self._format_raw_value(handle, raw_val))
            # Advance this handle's iterator
            val = next(it, None)
            if val is not None:
                next_time, next_raw = val
                heapq.heappush(heap, (next_time, seq, handle, next_raw, it))
                seq += 1

    def _iter_events_all(self, section_idx, t0, t1):
        """Bulk path: decompress all handles (original behavior)."""
        for fst_time, changes in self._reader.iter_time_value_pairs(section_idx):
            if fst_time < t0:
                continue
            if t1 is not None and fst_time > t1:
                return
            for handle, raw_val in changes:
                if handle not in self.signals:
                    continue
                yield (fst_time, handle,
                       self._format_raw_value(handle, raw_val))

    def scan_time_range(self):
        return self._reader.header.start_time, self._reader.header.end_time


_FST_MAGIC = bytes([FST_BL_HDR])


def wave_parser(path):
    path_lower = str(path).lower()
    if path_lower.endswith('.fst'):
        try:
            return FSTParser(path)
        except _FstFormatError as e:
            sys.exit('Error: invalid FST file: {}'.format(e))
        except Exception as e:
            sys.exit('Error: cannot open FST file: {}'.format(e))
    if path_lower.endswith('.vcd'):
        return VCDParser(path)
    try:
        with open(path, 'rb') as f:
            if f.read(1) == _FST_MAGIC:
                return FSTParser(path)
    except Exception:
        pass
    return VCDParser(path)# ================================================================
# Part 8: Commands + CLI
# ================================================================

def cmd_info(vcd, args):
    t_min, t_max = vcd.scan_time_range()
    ts = vcd.ts_sec
    synth = [s for s in vcd.signals.values() if s.get('synthesized')]
    r = {
        'file': vcd.path,
        'size_bytes': os.path.getsize(vcd.path),
        'timescale': vcd.ts_str.replace('$timescale', '').replace('$end', '').strip(),
        # Provenance metadata from VCD header (IEEE 1364-2005 18.2.3.1-3).
        # Tells the agent which simulator produced the file and when, so
        # downstream debug can apply tool-specific heuristics (e.g. QuestaSim
        # bit-explodes wide buses but iverilog doesn't).
        'date': vcd.date,
        'version': vcd.version,
        'comments': list(vcd.comments),
        'signal_count': len(vcd.signals),
        'reference_count': vcd.raw_var_count,
        'synthesized_buses': len(synth),
        'var_types': dict(sorted(vcd.raw_type_counts.items(), key=lambda x: -x[1])),
        'time_min': fmt_time(t_min, ts) if t_min is not None else None,
        'time_min_ticks': t_min,
        'time_min_h': fmt_time(t_min, ts) if t_min is not None else None,
        'time_max': fmt_time(t_max, ts) if t_max is not None else None,
        'time_max_ticks': t_max,
        'time_max_h': fmt_time(t_max, ts) if t_max is not None else None,
        'duration': fmt_time(t_max - t_min, ts) if t_min is not None and t_max is not None else None,
        'duration_ticks': (t_max - t_min) if t_min is not None and t_max is not None else None,
        'duration_h': fmt_time(t_max - t_min, ts) if t_min is not None and t_max is not None else None,
        # Use declaration-time scope metadata instead of splitting public
        # paths on '.'. Escaped identifiers may legally contain dots;
        # path.split('.') would invent fake hierarchy such as tb.\foo.
        'scopes': sorted(set(
            sc for v in vcd.signals.values() for sc in v.get('scopes', []) if sc
        )),
    }
    if args.json:
        _json(r)
    else:
        print('File      : {}'.format(r['file']))
        print('Size      : {:,} bytes'.format(r['size_bytes']))
        if r['date']:
            print('Date      : {}'.format(r['date']))
        if r['version']:
            print('Tool      : {}'.format(r['version']))
        print('Timescale : {}'.format(r['timescale']))
        if r['signal_count'] == r['reference_count']:
            print('Signals   : {}'.format(r['signal_count']))
        elif r['synthesized_buses']:
            print('Signals   : {} ({} $var decls, {} reassembled as bit-buses)'.format(
                r['signal_count'], r['reference_count'], r['synthesized_buses']))
        else:
            print('Signals   : {} unique ({} $var refs via aliases)'.format(
                r['signal_count'], r['reference_count']))
        print('Types     : {}'.format(', '.join('{}={}'.format(k, v) for k, v in r['var_types'].items())))
        print('Time      : {} ~ {} ({})'.format(r['time_min'], r['time_max'], r['duration']))
        for s in r['scopes']:
            print('  scope: {}'.format(s))
        if r['comments'] and getattr(args, 'verbose', False):
            # Comments verbose-only: typical files have boilerplate
            # ("Generated by ..."), worth showing only on demand.
            print('Comments  :')
            for c in r['comments']:
                print('  - {}'.format(c))


def cmd_list(vcd, args):
    limit = _limit(args, 'list')
    sids = vcd.match(args.filter)
    entries = []
    for sid, info in vcd.signals.items():
        if sids is not None and sid not in sids:
            continue
        vtype = info.get('type', 'wire')
        for path in info['aliases']:
            e = {'path': path, 'width': info['width'], 'type': vtype}
            if getattr(args, 'verbose', False):
                e['id'] = sid
                if info.get('synthesized'):
                    e['synthesized'] = True
                    e['raw_bits'] = info.get('raw_bits')
            entries.append(e)
    entries.sort(key=lambda e: e['path'])
    shown, trunc = _clip(entries, limit)
    if args.json:
        _json({'total': len(entries), 'shown': len(shown), 'truncated': trunc, 'signals': shown})
    else:
        print('Matched: {}/{}'.format(len(entries), len(vcd.signals)))
        for e in shown:
            print('  {:<60} {:>5}  {}'.format(e['path'], e['width'], e['type']))
        if trunc:
            print(_trunc_line(len(shown), len(entries), 'signals'))


def cmd_dump(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    if t1 is not None and t1 < t0:
        raise _TimeParseError('end time must be >= begin time')
    sids = vcd.match(args.filter)
    limit = _limit(args, 'dump')
    total = 0
    truncated = False
    events = []
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        total += 1
        if limit != 0 and len(events) >= limit:
            truncated = True
            break
        info = vcd.signals[sid]
        e = {'time': t, 'time_ticks': t, 'time_h': fmt_time(t, ts),
             'path': info['path'], 'value': fmt_val(val, info)}
        if getattr(args, 'verbose', False):
            e['width'] = info['width']
            e['type'] = info.get('type', 'wire')
        events.append(e)
    if args.json:
        obj = {'shown': len(events), 'truncated': truncated, 'events': events}
        obj.update(_total_json_fields(total, truncated))
        _json(obj)
        return
    if not events:
        print('(no changes in range)')
        return
    cur = None
    for e in events:
        if e['time'] != cur:
            cur = e['time']
            print('T={}'.format(e['time_h']))
        if getattr(args, 'verbose', False):
            print('  {:<55} w={} {} = {}'.format(e['path'], e.get('width'), e.get('type'), e['value']))
        else:
            print('  {:<55} = {}'.format(e['path'], e['value']))
    if truncated:
        print(_trunc_line_lower_bound(len(events), total, 'events'))


def cmd_summary(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    if t1 is not None and t1 < t0:
        raise _TimeParseError('end time must be >= begin time')
    sids = vcd.match(args.filter)
    selected = _selected_sids(vcd, sids)
    rows, undef_sids, counts = _summary_rows(vcd, t0, t1, selected)
    active = [r for r in rows if r['kind'] == 'active']
    static = [r for r in rows if r['kind'] == 'static']
    ordered = active + static
    if getattr(args, 'verbose', False):
        for sid in undef_sids:
            info = vcd.signals[sid]
            ordered.append({'kind': 'undefined', 'path': info['path'], 'value': None,
                            'changes': 0, 'rise_count': 0 if info['width'] == 1 else None,
                            'fall_count': 0 if info['width'] == 1 else None,
                            'init': '(undef)', 'last': '(undef)',
                            '_width': info['width'], '_type': info.get('type', 'wire')})
    limit = _limit(args, 'summary')
    shown, trunc = _clip(ordered, limit)
    begin_h = fmt_time(t0, ts)
    end_h = fmt_time(t1, ts) if t1 is not None else None
    if args.json:
        _json({'window': {'begin': begin_h, 'end': end_h,
                          'begin_ticks': t0, 'begin_h': begin_h,
                          'end_ticks': t1, 'end_h': end_h}, **counts,
               'shown': len(shown), 'truncated': trunc,
               'rows': [_public_row(r, getattr(args, 'verbose', False)) for r in shown]})
        return
    print('Window: {}..{}'.format(begin_h, end_h if end_h is not None else '(end)'))
    print('Selected: {}, Defined: {}, Undefined: {}'.format(
        counts['selected'], counts['defined'], counts['undefined']))
    print('Active: {}, Static: {}'.format(counts['active'], counts['static']))
    current = None
    for r in shown:
        if r['kind'] != current:
            current = r['kind']
            print('\n{}'.format(current.upper()))
        if r['kind'] == 'active':
            if getattr(args, 'verbose', False):
                edge = '' if r.get('rise_count') is None else ' r={} f={}'.format(
                    r.get('rise_count', 0), r.get('fall_count', 0))
                print('  {:<45} w={} {} chg={}{} init={} last={} first@{} last@{} uniq={}'.format(
                    r['path'], r['_width'], r['_type'], r['changes'], edge, r['init'], r['last'],
                    r.get('first_at', '-'), r.get('last_at', '-'), r.get('unique', 0)))
            else:
                edge = '' if r.get('rise_count') is None else ' r={} f={}'.format(
                    r.get('rise_count', 0), r.get('fall_count', 0))
                print('  {:<45} chg={}{} init={} last={}'.format(
                    r['path'], r['changes'], edge, r['init'], r['last']))
        elif r['kind'] == 'static':
            if getattr(args, 'verbose', False):
                print('  {:<45} w={} {} value={}'.format(r['path'], r['_width'], r['_type'], r['value']))
            else:
                print('  {:<45} value={}'.format(r['path'], r['value']))
        else:
            print('  {:<45} w={} {}'.format(r['path'], r['_width'], r['_type']))
    if not rows and not undef_sids:
        print('(no selected signals)')
    if trunc:
        print(_trunc_line(len(shown), len(ordered), 'rows'))


def cmd_snapshot(vcd, args):
    ts = vcd.ts_sec
    t_at = parse_time(args.at, ts)
    sids0 = vcd.match(args.filter)
    selected = _selected_sids(vcd, sids0)
    state = _build_snapshot(vcd, t_at, selected)
    rows = []
    for sid in sorted(state, key=lambda s: vcd.signals[s]['path']):
        info = vcd.signals[sid]
        r = {'path': info['path'], 'value': fmt_val(state[sid], info)}
        if getattr(args, 'verbose', False):
            r['width'] = info['width']
            r['type'] = info.get('type', 'wire')
        rows.append(r)
    undef = sorted(selected - set(state), key=lambda s: vcd.signals[s]['path'])
    if getattr(args, 'verbose', False):
        for sid in undef:
            info = vcd.signals[sid]
            rows.append({'path': info['path'], 'value': None, 'undefined': True,
                         'width': info['width'], 'type': info.get('type', 'wire')})
    limit = _limit(args, 'snapshot')
    shown, trunc = _clip(rows, limit)
    if args.json:
        _json({'at': fmt_time(t_at, ts), 'at_ticks': t_at, 'at_h': fmt_time(t_at, ts),
               'selected': len(selected), 'known': len(state),
               'undefined': len(undef), 'shown': len(shown), 'truncated': trunc,
               'signals': shown})
        return
    if not state:
        print('No known values at {}.'.format(fmt_time(t_at, ts)))
    else:
        print('Known snapshot @ {}'.format(fmt_time(t_at, ts)))
    if getattr(args, 'verbose', False):
        print('Selected: {}, Known: {}, Undefined: {}'.format(len(selected), len(state), len(undef)))
    for r in shown:
        if r.get('undefined'):
            print('  {:<55} = (undef)'.format(r['path']))
        elif getattr(args, 'verbose', False):
            print('  {:<55} w={} {} = {}'.format(r['path'], r.get('width'), r.get('type'), r['value']))
        else:
            print('  {:<55} = {}'.format(r['path'], r['value']))
    if trunc:
        print(_trunc_line(len(shown), len(rows), 'signals'))


def cmd_compare(vcd, args):
    ts = vcd.ts_sec
    parts = args.at.split(',')
    if len(parts) != 2:
        raise _TimeParseError(
            '--at needs two times separated by comma, e.g. --at 17.5us,17.7us')
    ta, tb = parse_time(parts[0].strip(), ts), parse_time(parts[1].strip(), ts)
    if tb < ta:
        raise _TimeParseError('second compare time must be >= first compare time')
    sids = vcd.match(args.filter)
    sa, sb = _build_snapshot_pair(vcd, ta, tb, sids)
    diffs = []
    for sid in sorted(set(sa) | set(sb), key=lambda s: vcd.signals[s]['path']):
        va, vb = sa.get(sid), sb.get(sid)
        if va != vb:
            info = vcd.signals[sid]
            d = {'path': info['path'],
                 'at_t1': fmt_val(va, info) if va is not None else '(undef)',
                 'at_t2': fmt_val(vb, info) if vb is not None else '(undef)'}
            if getattr(args, 'verbose', False):
                d['width'] = info['width']
                d['type'] = info.get('type', 'wire')
            diffs.append(d)
    limit = _limit(args, 'compare')
    shown, trunc = _clip(diffs, limit)
    if args.json:
        _json({'t1': fmt_time(ta, ts), 't1_ticks': ta, 't1_h': fmt_time(ta, ts),
               't2': fmt_time(tb, ts), 't2_ticks': tb, 't2_h': fmt_time(tb, ts),
               'total': len(diffs), 'shown': len(shown), 'truncated': trunc,
               'diffs': shown})
    else:
        print('Compare: {} vs {}'.format(fmt_time(ta, ts), fmt_time(tb, ts)))
        print('{} changed, {} unchanged'.format(len(diffs), len(set(sa) | set(sb)) - len(diffs)))
        for d in shown:
            print('  {:<48} {} -> {}'.format(d['path'], d['at_t1'], d['at_t2']))
        if trunc:
            print(_trunc_line(len(shown), len(diffs), 'diffs'))


def cmd_search(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1_raw = parse_time(args.end, ts) if args.end else None
    t1 = _search_end_time(vcd, t0, t1_raw)
    if t1 < t0:
        raise _TimeParseError('end time must be >= begin time')

    conditions = _resolve_conditions(vcd, args.condition)
    show_sids = _resolve_show_sids(vcd, args.show)
    changed_sid = _resolve_one_signal(vcd, args.changed, 'changed signal') if args.changed else None
    if changed_sid is not None and not show_sids:
        show_sids = [changed_sid]

    selected = set(c['sid'] for c in conditions)
    selected.update(show_sids)
    if changed_sid is not None:
        selected.add(changed_sid)

    limit = _limit(args, 'search')
    verbose = getattr(args, 'verbose', False)
    cond_label = _condition_label(conditions)
    cond_text = _condition_result_text(conditions)

    if changed_sid is not None:
        # Single-pass: build state < t0, then process events t0..t1.
        state = {}
        events = []
        total = 0
        truncated = False
        cur_t = None
        group = []

        for t, sid, val in vcd.iter_events(0, t1, selected):
            if t < t0:
                # Baseline: build state up to (but not including) t0.
                # Last-write-wins semantics, matching _build_snapshot_before.
                state[sid] = val
                continue

            # Event processing phase: group by timestamp, process each group
            # before updating state (so old_val reflects pre-step state).
            if cur_t is None:
                cur_t = t
            if t != cur_t:
                # Process completed group at cur_t
                changed = set()
                for gsid, gval in group:
                    old_val = state.get(gsid)
                    if cur_t == 0 and old_val is None:
                        pass
                    elif vcd.signals[gsid].get('type') == 'event':
                        changed.add(gsid)
                    elif old_val is None:
                        pass
                    elif old_val != gval:
                        changed.add(gsid)
                for gsid, gval in group:
                    state[gsid] = gval

                if changed_sid in changed and _conditions_hold(state, conditions):
                    values, meta = _show_values(vcd, state, show_sids, verbose)
                    event = {'time_ticks': cur_t, 'time_h': fmt_time(cur_t, ts),
                             'values': values}
                    if verbose:
                        event['meta'] = meta
                    total += 1
                    if limit != 0 and len(events) >= limit:
                        truncated = True
                        break
                    events.append(event)

                if truncated:
                    break
                cur_t = t
                group = []
            group.append((sid, val))

        # Process final pending group
        if group and not truncated:
            t = cur_t
            changed = set()
            for gsid, gval in group:
                old_val = state.get(gsid)
                if t == 0 and old_val is None:
                    pass
                elif vcd.signals[gsid].get('type') == 'event':
                    changed.add(gsid)
                elif old_val is None:
                    pass
                elif old_val != gval:
                    changed.add(gsid)
            for gsid, gval in group:
                state[gsid] = gval
            if changed_sid in changed and _conditions_hold(state, conditions):
                values, meta = _show_values(vcd, state, show_sids, verbose)
                event = {'time_ticks': t, 'time_h': fmt_time(t, ts),
                         'values': values}
                if verbose:
                    event['meta'] = meta
                total += 1
                if limit != 0 and len(events) >= limit:
                    truncated = True
                else:
                    events.append(event)

        if args.json:
            obj = {'mode': 'event', 'condition': cond_label,
                   'condition_resolved': cond_text,
                   'changed': vcd.signals[changed_sid]['path'],
                   'show': [vcd.signals[sid]['path'] for sid in show_sids],
                   'begin_ticks': t0, 'begin_h': fmt_time(t0, ts),
                   'end_ticks': t1, 'end_h': fmt_time(t1, ts),
                   'shown': len(events), 'truncated': truncated,
                   'events': events}
            obj.update(_total_json_fields(total, truncated))
            _json(obj)
            return
        if events:
            print('Found: {} event(s)'.format(_count_label(len(events), total, truncated)))
            for e in events:
                print('  T={:<12} {}'.format(e['time_h'], _values_text(e['values'])))
            if truncated:
                print(_trunc_line_lower_bound(len(events), total, 'events'))
        else:
            print('No event in {}..{} where {} changed and {}.'.format(
                fmt_time(t0, ts), fmt_time(t1, ts), vcd.signals[changed_sid]['path'], cond_text))
        return

    # Interval/segment mode. A segment is an interval further split whenever
    # the displayed show-value tuple changes while the condition remains true.
    has_show = bool(show_sids)
    # Single-pass: build state up to t0, then process intervals t0+..t1
    state = {}
    results = []
    total = 0
    truncated = False

    def emit_interval(a, b):
        return {'begin_ticks': a, 'begin_h': fmt_time(a, ts),
                'end_ticks': b, 'end_h': fmt_time(b, ts)}

    def append_result(row):
        nonlocal total, truncated
        total += 1
        if limit != 0 and len(results) >= limit:
            truncated = True
            return True
        results.append(row)
        return False

    cur_t = None
    group = []
    active = False
    seg_start = None
    seg_values = None
    seg_meta = None
    init_checks_done = False

    for t, sid, val in vcd.iter_events(0, t1, selected):
        if t <= t0:
            state[sid] = val
            continue

        if not init_checks_done:
            active = _conditions_hold(state, conditions)
            seg_start = t0 if active else None
            if active and has_show:
                seg_values, seg_meta = _show_values(vcd, state, show_sids, verbose)
            init_checks_done = True

        # Group by timestamp beyond t0
        if cur_t is None:
            cur_t = t
        if t != cur_t:
            # Apply accumulated group values to state before checking
            for gsid, gval in group:
                state[gsid] = gval
            # Process completed group at cur_t
            cond_ok = _conditions_hold(state, conditions)
            if not has_show:
                if cond_ok and not active:
                    active = True
                    seg_start = cur_t
                elif not cond_ok and active:
                    if append_result(emit_interval(seg_start, cur_t)):
                        break
                    active = False
                    seg_start = None
            else:
                if not cond_ok:
                    if active:
                        row = emit_interval(seg_start, cur_t)
                        row['values'] = seg_values
                        if verbose:
                            row['meta'] = seg_meta
                        if append_result(row):
                            break
                        active = False
                        seg_start = None
                        seg_values = None
                        seg_meta = None
                else:
                    new_values, new_meta = _show_values(vcd, state, show_sids, verbose)
                    if not active:
                        active = True
                        seg_start = cur_t
                        seg_values = new_values
                        seg_meta = new_meta
                    elif new_values != seg_values:
                        row = emit_interval(seg_start, cur_t)
                        row['values'] = seg_values
                        if verbose:
                            row['meta'] = seg_meta
                        if append_result(row):
                            break
                        seg_start = cur_t
                        seg_values = new_values
                        seg_meta = new_meta

            if truncated:
                break
            cur_t = t
            group = []
        group.append((sid, val))

    # Process final pending group
    if group and not truncated:
        for gsid, gval in group:
            state[gsid] = gval
        cond_ok = _conditions_hold(state, conditions)
        if not has_show:
            if cond_ok and not active:
                active = True
                seg_start = cur_t
            elif not cond_ok and active:
                if append_result(emit_interval(seg_start, cur_t)):
                    pass
                active = False
                seg_start = None
        else:
            if not cond_ok:
                if active:
                    row = emit_interval(seg_start, cur_t)
                    row['values'] = seg_values
                    if verbose:
                        row['meta'] = seg_meta
                    append_result(row)
                    active = False
                    seg_start = None
                    seg_values = None
                    seg_meta = None
            else:
                new_values, new_meta = _show_values(vcd, state, show_sids, verbose)
                if not active:
                    active = True
                    seg_start = cur_t
                    seg_values = new_values
                    seg_meta = new_meta
                elif new_values != seg_values:
                    row = emit_interval(seg_start, cur_t)
                    row['values'] = seg_values
                    if verbose:
                        row['meta'] = seg_meta
                    append_result(row)
                    seg_start = cur_t
                    seg_values = new_values
                    seg_meta = new_meta

    # Emit final interval if still active
    if active and not truncated:
        row = emit_interval(seg_start, t1)
        if has_show:
            row['values'] = seg_values
            if verbose:
                row['meta'] = seg_meta
        append_result(row)

    if args.json:
        key = 'segments' if has_show else 'intervals'
        obj = {'mode': 'segment' if has_show else 'interval',
               'condition': cond_label,
               'condition_resolved': cond_text,
               'show': [vcd.signals[sid]['path'] for sid in show_sids],
               'begin_ticks': t0, 'begin_h': fmt_time(t0, ts),
               'end_ticks': t1, 'end_h': fmt_time(t1, ts),
               'shown': len(results), 'truncated': truncated,
               key: results}
        obj.update(_total_json_fields(total, truncated))
        _json(obj)
        return

    noun = 'segment' if has_show else 'interval'
    if results:
        print('Found: {} {}(s)'.format(_count_label(len(results), total, truncated), noun))
        for r in results:
            if has_show:
                print('  {:<12}..{:<12} {}'.format(
                    r['begin_h'], r['end_h'], _values_text(r['values'])))
            else:
                print('  {:<12}..{:<12} {}'.format(r['begin_h'], r['end_h'], cond_text))
        if truncated:
            print(_trunc_line_lower_bound(len(results), total, noun + 's'))
    else:
        print('No {} in {}..{} where {}.'.format(
            noun, fmt_time(t0, ts), fmt_time(t1, ts), cond_text))

# -- CLI entry ---------------------------------------------------------------

def _add_time_args(sp):
    sp.add_argument('--begin', metavar='TIME',
                    help='start time, e.g. 0, 100ns, 17.5us (omit = from start)')
    sp.add_argument('--end', metavar='TIME',
                    help='end time, same format (omit = no upper bound)')


def _add_filter(sp):
    sp.add_argument('--filter', metavar='K1,K2,...',
                    type=_normalize_filter_patterns,
                    help='comma-separated substring/glob patterns, case-insensitive')


def _add_common(sp):
    # Also accept global-style output controls after the subcommand.
    # Defaults are SUPPRESS so values supplied before the subcommand survive.
    sp.add_argument('--json', action='store_true', default=argparse.SUPPRESS,
                    help='output compact structured JSON instead of text')
    sp.add_argument('--limit', type=int, default=argparse.SUPPRESS,
                    help='max rows/records to emit; default 200; 0 = unlimited; streaming commands stop after the first unshown result')
    sp.add_argument('--verbose', action='store_true', default=argparse.SUPPRESS,
                    help='show extra fields; if --limit is omitted, disables truncation')


def main():
    p = argparse.ArgumentParser(
        prog='open_wave_analyzer',
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--json', action='store_true',
                   help='output compact structured JSON instead of text')
    p.add_argument('--limit', type=int, default=None,
                   help='max rows/records to emit; default 200; 0 = unlimited; streaming commands stop after the first unshown result')
    p.add_argument('--verbose', action='store_true',
                   help='show extra fields; if --limit is omitted, disables truncation')
    p.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    sub = p.add_subparsers(dest='cmd', metavar='<command>')

    sp = sub.add_parser('info', help='file overview: timescale, signal count, time span, scopes')
    sp.add_argument('file', metavar='<file>', help='VCD file path'); _add_common(sp)

    sp = sub.add_parser('list', help='list signals with path and bit width')
    sp.add_argument('file', metavar='<file>'); _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('dump', help='print value-change events in time order')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('summary', help='window stats: active/static/undefined selected signals')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('snapshot', help='known signal values at a given time point')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--at', metavar='TIME', required=True, help='time point, e.g. 17.55us')
    _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('compare', help='diff known signal values between two time points')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--at', metavar='T1,T2', required=True, help='two time points comma-separated, e.g. 17.5us,17.7us')
    _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('search', help='conditional search and associated signal observation')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_common(sp)
    sp.add_argument('--condition', metavar='COND', required=True,
                    help='comma-separated AND conditions, e.g. "valid=1,ready=1"; != does not match x/z/undef')
    sp.add_argument('--show', metavar='PAT1,PAT2,...', type=_normalize_filter_patterns,
                    help='signals to display while the condition holds; output segments split when shown values change')
    sp.add_argument('--changed', metavar='PATTERN',
                    help='emit events only when this signal really changes; VCD event vars count each trigger; must match exactly one signal')

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)

    try:
        vcd = wave_parser(args.file)
        cmds = {'info': cmd_info, 'list': cmd_list, 'dump': cmd_dump, 'summary': cmd_summary,
                'snapshot': cmd_snapshot, 'compare': cmd_compare, 'search': cmd_search}
        cmds[args.cmd](vcd, args)
    except FileNotFoundError as e:
        sys.exit('Error: cannot open waveform file: {}'.format(e.filename or args.file))
    except IsADirectoryError as e:
        sys.exit('Error: not a file: {}'.format(e.filename or args.file))
    except PermissionError as e:
        sys.exit('Error: permission denied: {}'.format(e.filename or args.file))
    except _TimeParseError as e:
        sys.exit('Error: ' + str(e))
    except _ValueParseError as e:
        sys.exit('Error: ' + str(e))
    except _ConditionParseError as e:
        sys.exit('Error: ' + str(e))
    except _WaveResourceError as e:
        sys.exit('Error: ' + str(e))
    except _FilterParseError as e:
        # Reaches here only if raised from VCDParser.match() at runtime;
        # argparse handles the same error when raised from type=.
        sys.exit('Error: ' + str(e))


if __name__ == '__main__':
    import signal as _sig
    if hasattr(_sig, 'SIGPIPE'):
        _sig.signal(_sig.SIGPIPE, _sig.SIG_DFL)
    try:
        main()
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        sys.exit(0)