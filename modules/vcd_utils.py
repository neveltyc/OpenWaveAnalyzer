# ================================================================
# Part 5: VCD Utilities
# ================================================================

class _WaveResourceError(RuntimeError):
    pass


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


class _VCDResourceError(_WaveResourceError):
    """Raised when a VCD input exceeds configured resource limits.
    Surfaced in main() as a CLI error (caught via _WaveResourceError), no
    Python traceback."""


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

# Bracketed size/reference range, e.g. '[7:0]'.  Anchored so '[a:b]' rejects.
_HEADER_RANGE_RE = re.compile(r'\[(\d+):(\d+)\]$')


def _collect_bracket_tokens(tokens, i):
    """Join a bracketed reference that free-format VCD may split across tokens.

    Per IEEE 1364 free-format, a reference range can be split, e.g.
    'data [7 : 0]' -> ['data', '[7', ':', '0]'].  Returns (joined, next_idx)
    when tokens[i] opens a '[', else (None, i).  Module-level so the one-line
    fast path and the generic token parser share one definition and cannot
    drift apart.
    """
    if i >= len(tokens) or not tokens[i].startswith('['):
        return None, i
    parts = []
    while i < len(tokens):
        parts.append(tokens[i])
        if ']' in tokens[i]:
            return ''.join(parts), i + 1
        i += 1
    return None, i


def _parse_var_tokens(body, scope_path):
    """Parse the token body of a $var declaration (tokens between '$var' and
    '$end').

    Returns (sym, name, width, bit_str, scope_path, vtype), or None for a
    malformed declaration that should be skipped.  Raises _VCDResourceError for
    hostile widths.  Shared by both the one-line header fast path and the
    generic multi-line token parser so var interpretation is defined once.
    """
    nbody = len(body)
    if nbody < 4:
        return None

    # Fast path for the two overwhelmingly common shapes emitted by VCS,
    # Verilator, Icarus, etc., where the size is a plain integer (not a split
    # '[ msb : lsb ]') and the reference is at most one trailing '[..]' token:
    #   4 tokens: vtype width sym name                  (scalar / packed bus)
    #   5 tokens: vtype width sym name [range-or-bit]   (bus or bit-select)
    # This avoids two _collect_bracket_tokens scans per variable on files that
    # declare hundreds of thousands of them.  Any shape that does not match
    # (bracketed size, split range, extra tokens) falls through to the general
    # parser below, so behavior is unchanged for those.
    if nbody <= 5:
        b1 = body[1]
        if not b1.startswith('['):
            w = _safe_int_digits(b1)
            if w is not None:
                if w <= 0 or w > MAX_SIGNAL_WIDTH:
                    raise _VCDResourceError(
                        '$var width {} exceeds max {}; '
                        'file may be corrupt or malicious'.format(w, MAX_SIGNAL_WIDTH))
                vtype = body[0]
                sym = body[2]
                name = body[3]
                if nbody == 4:
                    return sym, name, w, None, scope_path, vtype
                # nbody == 5: trailing reference token body[4].
                ref = body[4]
                if ref.startswith('[') and ref.endswith(']'):
                    if w > 1:
                        # Range folded into displayed name ('data[7:0]').
                        return sym, name + ref, w, None, scope_path, vtype
                    # 1-bit [N]: keep as bit_str for the bit-explosion heuristic.
                    return sym, name, w, ref, scope_path, vtype
                # Unexpected 5th token (e.g. split '[7 :'); fall through.

    vtype = body[0]
    size_expr, idx_after_size = _collect_bracket_tokens(body, 1)
    if size_expr is not None:
        m = _HEADER_RANGE_RE.match(size_expr)
        if not m:
            return None
        msb = _safe_int_digits(m.group(1))
        lsb = _safe_int_digits(m.group(2))
        if msb is None or lsb is None:
            return None
        w = abs(msb - lsb) + 1
        idx = idx_after_size
    else:
        w = _safe_int_digits(body[1])
        if w is None:
            return None
        idx = 2
    # Refuse pathological widths before they reach fmt_val (which would try to
    # allocate pad bytes proportional to width).  Real signals never approach
    # MAX_SIGNAL_WIDTH.
    if w <= 0 or w > MAX_SIGNAL_WIDTH:
        raise _VCDResourceError(
            '$var width {} exceeds max {}; '
            'file may be corrupt or malicious'.format(w, MAX_SIGNAL_WIDTH))
    if len(body) <= idx + 1:
        return None
    sym, name = body[idx], body[idx + 1]
    # A bracket after the name is a bit/range reference, possibly split across
    # tokens.  For multi-bit refs with a range, fold it into the displayed name
    # ('data[7:0]'); for a 1-bit ref with [N], keep bit_str for the
    # bit-explosion heuristic.
    bit_str, _idx_after_ref = _collect_bracket_tokens(body, idx + 2)
    if bit_str is not None and w > 1:
        name = name + bit_str
        bit_str = None
    return sym, name, w, bit_str, scope_path, vtype

# Simulation keywords that wrap value_changes until $end. The keyword and $end
# are pure markers — the wrapped value_changes are parsed normally.
# Four-state VCD (18.2.3.9-12) + extended VCD (18.4.1 BNF).
_SIM_KEYWORDS = {'$dumpall', '$dumpoff', '$dumpon', '$dumpvars',
                 '$dumpports', '$dumpportsoff', '$dumpportson', '$dumpportsall'}

# Sections that can appear in the data area whose body is NOT value_changes
# and must be skipped wholesale until $end. $comment (18.2.3.1) is in both
# header and data; $vcdclose (18.3.6.1) wraps a final simulation time token.
_DATA_SKIP_SECTIONS = {'$comment', '$vcdclose'}

