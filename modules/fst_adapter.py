# ================================================================
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

    def iter_events(self, t0=0, t1=None, sids=None, *, bulk_parse=True):
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

        # Bulk-parse all sections up front only when the caller will consume the
        # whole stream (summary, search, dump --limit 0): it parallelizes chain
        # decoding across cores. For a bounded consumer (dump --limit N) it is
        # pure waste — the early break means later sections are never read — so
        # bulk_parse=False lets iter_time_value_pairs lazily parse section-by-
        # section and stop after the first few. Filtered paths never bulk-parse.
        if needed > 1 and sids is None and bulk_parse:
            self._reader._ensure_all_sections_parsed()

        for section_idx in range(first_needed, last_needed + 1):
            if sids is not None:
                yield from self._iter_events_filtered(
                    section_idx, t0, t1, sids)
            else:
                yield from self._iter_events_all(
                    section_idx, t0, t1)

    def _iter_events_filtered(self, section_idx, t0, t1, sids):
        """Selective path: decompress only the requested handles.

        Uses _scan_chain_entries (targeted chain lookup) to avoid parsing the
        full 223K-entry chain table. _scan_chain_entries falls back to a full
        parse internally if it hits an alias to an unselected handle, so the
        result is always identical to the full path.
        """
        sect = self._reader._vc_sections[section_idx]
        valid_handles = [h for h in sids if h in self.signals]
        if not valid_handles:
            return

        chain_entries = self._reader._scan_chain_entries(section_idx, valid_handles)
        sig_lens = self._reader._signal_lengths

        # When the section's frame snapshot precedes its first recorded
        # timestamp, every signal carries its initial (frame) value at beg_time.
        # The all-signal path (iter_time_value_pairs) emits these; mirror that
        # here so filtered dumps don't silently drop the beg_time sample.
        self._reader._ensure_time_table_parsed(section_idx)
        times = sect.times or []
        emit_initial = bool(times) and sect.beg_time != times[0]

        def _prepend_initial(handle, inner):
            yield (sect.beg_time, self._reader.get_initial_value(handle, section_idx))
            yield from inner

        iterators = []
        for handle in valid_handles:
            entry = chain_entries.get(handle)
            if entry is not None:
                it = self._reader.iter_value_changes(
                    handle, section_idx, _chain_entry=entry)
                if emit_initial:
                    # Chain's first event is at times[k] >= times[0] > beg_time,
                    # so prepending the beg_time sample never duplicates a time.
                    it = _prepend_initial(handle, it)
            else:
                # No chain data for this handle in this section. Mirror the
                # no-data branch of iter_value_changes: a zero-length string
                # emits nothing; everything else emits its initial value.
                idx0 = handle - 1
                if idx0 < len(sig_lens) and not sig_lens[idx0]:
                    continue
                initial = self._reader.get_initial_value(handle, section_idx)
                it = iter([(sect.beg_time, initial)])
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
# GHW (GHDL's native dump) begins with this signature.  GHW is NOT supported;
# it is rejected at the entry point (see wave_parser) so it never reaches a
# reader that would mis-parse it.
_GHW_MAGIC = b'GHDLwave\n'


# ==========================================================================
# Optional pywellen backend (cross-platform VCD/FST accelerator)
# ==========================================================================
# pywellen is the Python binding over the Rust `wellen` waveform library (the
# multi-threaded reader behind the Surfer waveform viewer).  It is used as a
# HYBRID accelerator:
#
#   * the bundled pure-Python readers (VCDParser / FSTParser) parse the
#     *hierarchy* -- the cheap part: VCD reads only up to $enddefinitions, FST
#     walks only the hierarchy block.  This keeps the signal model identical to
#     running without pywellen: real declared bit ranges (e.g. data[15:8]),
#     split bus slices kept distinct, array elements, and aliases all survive.
#   * pywellen parses the *value-change body* -- the expensive part -- and
#     supplies all per-time value data.
#
# So we get the native readers' signal fidelity at pywellen's value-reading
# speed.  pywellen drops the [msb:lsb] range from names and merges sibling bus
# slices into one vector; pulling the hierarchy from the native reader is what
# lets us keep both.
#
# The pure-Python readers remain the zero-dependency default and the only thing
# that works on every platform/architecture (pywellen ships no Windows wheel).
# If pywellen is absent, the installed version differs from the pinned/tested
# version, or anything fails, the tool transparently uses the native reader.

# Pinned to the exact pywellen version this backend was written and validated
# against.  pywellen's Python API is pre-1.0 and has changed across releases;
# we do not assume cross-version compatibility.  A different installed version
# is treated as "unavailable" (native fallback) unless OWA_PYWELLEN_ALLOW_ANY
# is set to opt in at the user's own risk.
_PYWELLEN_PINNED_VERSION = '0.25.5'

_PYWELLEN = None
_PYWELLEN_PROBED = False


def _truthy_env(name):
    return os.environ.get(name, '').strip().lower() not in ('', '0', 'false', 'no', 'off')


def _pywellen_installed_version():
    try:
        import importlib.metadata as _md
        return _md.version('pywellen')
    except Exception:
        return None


def _pywellen_version_ok():
    if _truthy_env('OWA_PYWELLEN_ALLOW_ANY'):
        return True
    ver = _pywellen_installed_version()
    # If the version cannot be determined the import still succeeded; the pin
    # guards against *known-different* releases, so accept an unknown version.
    return ver is None or ver == _PYWELLEN_PINNED_VERSION


def _probe_pywellen():
    """Import pywellen once; cache the module or None.  Never raises."""
    global _PYWELLEN, _PYWELLEN_PROBED
    if _PYWELLEN_PROBED:
        return _PYWELLEN
    _PYWELLEN_PROBED = True
    try:
        import pywellen as _pw
        _ = _pw.Waveform          # touch the API surface we depend on
        _ = _pw.Signal
        _PYWELLEN = _pw if _pywellen_version_ok() else None
    except Exception:
        _PYWELLEN = None
    return _PYWELLEN


def _force_native():
    """True if the user pinned the native readers via env var."""
    return _truthy_env('OWA_FORCE_NATIVE')


def pywellen_available():
    """Public: is the pywellen backend usable right now (and not forced off)?"""
    return (not _force_native()) and (_probe_pywellen() is not None)


def _canon_pw_name(full_name):
    # pywellen scopes array elements as `parent.[idx]`; the native readers use
    # the flat `parent[idx]`.  Normalize so the two models line up by name.
    return full_name.replace('.[', '[')


def _pw_var_width(var):
    if getattr(var, 'is_real', False):
        return 64
    bw = var.bitwidth
    return 0 if bw is None else bw


def _split_bit_range(path):
    """'top.bus[15:8]' -> ('top.bus', (15, 8)); else (path, None).

    Only a trailing [msb:lsb] containing a colon is treated as a bit range; a
    trailing [idx] without a colon is an array index and stays on the name.
    """
    if not path.endswith(']'):
        return path, None
    open_idx = path.rfind('[')
    if open_idx < 0:
        return path, None
    inside = path[open_idx + 1:-1]
    if ':' not in inside:
        return path, None
    a, _, b = inside.partition(':')
    try:
        hi, lo = int(a), int(b)
    except ValueError:
        return path, None
    if lo > hi:
        hi, lo = lo, hi
    return path[:open_idx], (hi, lo)


def _resolve_source(info, pw_index):
    """Map a native signal to (pywellen Var, slice) or None.

    `slice` is None for a direct 1:1 mapping, or (lo, width, total) when the
    native signal is a sub-slice [lo : lo+width) of a wider pywellen-merged bus
    of `total` bits.
    """
    path = info['path']
    width = info['width']
    # 1) Exact name match: scalars, array elements, whole buses, and anything
    #    pywellen did not merge.
    hit = pw_index.get(_canon_pw_name(path))
    if hit is not None:
        return (hit[0], None)
    # 2) The native signal carries a [hi:lo] range; pywellen may have merged
    #    sibling slices into one wider bus under the bare base name.
    base, rng = _split_bit_range(path)
    if rng is None:
        return None
    hit = pw_index.get(_canon_pw_name(base))
    if hit is None:
        return None
    var, pw_width = hit
    hi, lo = rng
    if pw_width == width:
        return (var, None)                       # whole bus, no real slicing
    if pw_width > width and 0 <= lo <= hi < pw_width:
        return (var, (lo, width, pw_width))
    return None


def _format_pywellen_value(vtype, width, raw, sl):
    """pywellen value -> the native readers' raw value_str convention.

    The shared display layer (fmt_val) renders this downstream, so events
    become 'triggered', clean vectors become 'dec (0xhex)', etc.  The raw
    convention is: 1-bit -> '0'/'1'/'x'/'z'; vector -> lowercase MSB-first
    4-state bit string; real -> %.16g text; event -> a marker.
    """
    if vtype == 'event':
        return '1'                               # marker; fmt_val -> 'triggered'
    if vtype in ('real', 'realtime'):
        try:
            return '{:.16g}'.format(raw)
        except Exception:
            return str(raw)
    if sl is None:
        # Whole signal.  Clean vectors arrive as int, 4-state as a full-width
        # MSB-first string, scalars as int.
        if isinstance(raw, str):
            return raw
        if isinstance(raw, bool):
            raw = int(raw)
        if isinstance(raw, int):
            return ('1' if raw else '0') if width <= 1 else format(raw, '0{}b'.format(width))
        return str(raw)
    # Sub-slice [lo : lo+w) of a wider merged bus of `total` bits.
    lo, w, total = sl
    if isinstance(raw, str):
        # MSB-first, length == total; bit i sits at string index total-1-i.
        hi = lo + w - 1
        return raw[total - 1 - hi: total - lo]
    if isinstance(raw, bool):
        raw = int(raw)
    if isinstance(raw, int):
        piece = (raw >> lo) & ((1 << w) - 1)
        return ('1' if piece else '0') if w <= 1 else format(piece, '0{}b'.format(w))
    return str(raw)


class WellenParser:
    """Hybrid VCD/FST parser: native hierarchy model + pywellen value data.

    The signal model (signals, names with real bit ranges, widths, types,
    aliases, timescale, date/version/comments) is taken verbatim from an
    already-built native reader, so it is identical to running the tool without
    pywellen.  The per-time value data (iter_events / scan_time_range) comes
    from pywellen, which parses the value-change body far faster than the
    pure-Python reader.

    Exposes the exact public surface the CLI consumes from VCDParser/FSTParser
    -- attributes (path, signals, ts_sec, ts_str, date, version, comments,
    raw_var_count, raw_type_counts) and methods (match, iter_events,
    scan_time_range) -- and yields identical (time, handle, value_str) tuples,
    so the CLI cannot tell which backend produced a result.

    If any native signal cannot be resolved to a pywellen value source, the
    instance transparently delegates value queries back to the native reader,
    so a signal's data is never silently dropped.
    """

    def __init__(self, path, native):
        pw = _probe_pywellen()
        if pw is None:
            raise RuntimeError('pywellen not available')
        self.path = str(path)
        self._native = native
        self._wave = pw.Waveform(self.path)

        # Mirror the native model's metadata verbatim.
        self.signals = native.signals
        self.ts_sec = native.ts_sec
        self.ts_str = native.ts_str
        self.date = native.date
        self.version = native.version
        self.comments = native.comments
        self.raw_var_count = native.raw_var_count
        self.raw_type_counts = native.raw_type_counts

        # Bridge: native handle -> (pywellen Var, slice).  If incomplete, every
        # value query falls back to the native reader.
        self._sources = {}
        self._fallback = not self._build_sources()

    def match(self, keywords):
        # Identical signal set -> identical filter semantics.
        return self._native.match(keywords)

    def scan_time_range(self):
        # The native readers already derive the time range cheaply (VCD via a
        # bidirectional seek to the first/last "#T" token; FST straight from the
        # header).  That range -- the last *timestamp* in the file rather than
        # the last value *change* -- is the simulation duration users expect, so
        # reuse it verbatim for an identical `info` at no extra scan cost.
        return self._native.scan_time_range()

    def iter_events(self, t0=0, t1=None, sids=None, *, bulk_parse=True):
        if self._fallback:
            yield from self._native.iter_events(t0, t1, sids, bulk_parse=bulk_parse)
            return
        handles = self.signals.keys() if sids is None else sids
        streams = []
        for h in handles:
            src = self._sources.get(h)
            if src is not None:
                streams.append((h, src))
        if not streams:
            return
        if bulk_parse:
            # Full / large scans (the cli sets bulk_parse when no --limit caps the
            # output): extract every selected signal and sort once by time.  This
            # is ~2.4x faster than a lazy k-way heap merge over thousands of
            # per-signal generators -- and faster than the native body parse --
            # because the value extraction itself runs inside pywellen (Rust)
            # while only the ordering stays in Python.
            events = []
            extend = events.extend
            for h, src in streams:
                extend(self._signal_stream(h, src, t0, t1))
            events.sort(key=lambda e: e[0])
            yield from events
        else:
            # Limited / early-stopping scans: a lazy heap merge so --limit can
            # stop without first materializing every event.
            gens = [self._signal_stream(h, src, t0, t1) for h, src in streams]
            yield from heapq.merge(*gens, key=lambda e: e[0])

    def _build_sources(self):
        """Map every native signal to a pywellen value source.

        Returns True only if *every* signal resolved; otherwise the caller
        flips to native fallback so no signal's data is ever dropped.
        """
        pw_index = {}
        for var in self._wave.all_vars():
            cname = _canon_pw_name(var.full_name)
            # Aliases share a signal_ref; any var for a given name works.
            pw_index.setdefault(cname, (var, _pw_var_width(var)))

        for handle, info in self.signals.items():
            src = _resolve_source(info, pw_index)
            if src is None:
                return False
            self._sources[handle] = src
        return True

    def _signal_stream(self, handle, src, t0, t1):
        var, sl = src
        info = self.signals[handle]
        vtype = info.get('type', 'wire')
        width = info['width']
        sig = var.signal
        n = len(sig)
        if n == 0:
            return                              # pywellen rejects an empty slice
        changes = sig[:]                        # [(time, value), ...], ascending
        i = 0
        while i < n:
            t = changes[i][0]
            raw = changes[i][1]
            # Collapse multiple changes within a single timestamp to the settled
            # (last) value, matching the native readers' one-value-per-timestamp
            # model.  Without this a same-time glitch (e.g. z -> 0x80) would
            # surface as two events the native reader never emits.
            j = i + 1
            while j < n and changes[j][0] == t:
                raw = changes[j][1]
                j += 1
            i = j
            if t < t0:
                continue
            if t1 is not None and t > t1:
                break               # changes are time-ordered: safe to stop
            yield (t, handle, _format_pywellen_value(vtype, width, raw, sl))


def _sniff_format(path):
    """Return 'fst', 'vcd', or 'ghw' for an extensionless file via magic bytes."""
    try:
        with open(path, 'rb') as f:
            head = f.read(len(_GHW_MAGIC))
    except Exception:
        return 'vcd'
    if head.startswith(_GHW_MAGIC):
        return 'ghw'
    if head[:1] == _FST_MAGIC:
        return 'fst'
    return 'vcd'


def wave_parser(path):
    path_lower = str(path).lower()

    # GHW is not supported -- reject explicitly at the entry point.
    if path_lower.endswith('.ghw'):
        sys.exit('Error: GHW files are not supported.')

    if path_lower.endswith('.fst'):
        fmt = 'fst'
    elif path_lower.endswith('.vcd'):
        fmt = 'vcd'
    else:
        fmt = _sniff_format(path)
        if fmt == 'ghw':
            sys.exit('Error: GHW files are not supported.')

    # Build the native signal model (hierarchy only -- the cheap part).  This is
    # also the fallback reader when pywellen is unavailable.
    if fmt == 'fst':
        try:
            native = FSTParser(path)
        except _FstFormatError as e:
            sys.exit('Error: invalid FST file: {}'.format(e))
        except Exception as e:
            sys.exit('Error: cannot open FST file: {}'.format(e))
    else:
        native = VCDParser(path)

    # Prefer the pywellen hybrid when available; fall back to the native reader
    # on any failure so a quirky environment never breaks the tool.
    if pywellen_available():
        try:
            return WellenParser(path, native)
        except Exception:
            pass
    return native