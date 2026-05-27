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


