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


# ==========================================================================
# Optional pylibfst backend
# ==========================================================================
# pylibfst is a cffi binding over GTKWave's reference fstapi (the same C reader
# behind fst2vcd).  When installed it is dramatically faster than the pure-
# Python reader on filtered, point, time-range, and hierarchy queries, and
# competitive-to-faster on full scans, while producing byte-identical output
# (validated against the native reader across all fixtures).  It is an OPTIONAL
# accelerator: the tool stays single-file and dependency-free, and the native
# reader remains the default when pylibfst is absent or when the user forces it
# off via OWA_FST_FORCE_NATIVE.

_PYLIBFST = None
_PYLIBFST_PROBED = False


def _probe_pylibfst():
    """Import pylibfst once; cache the module or None.  Never raises."""
    global _PYLIBFST, _PYLIBFST_PROBED
    if _PYLIBFST_PROBED:
        return _PYLIBFST
    _PYLIBFST_PROBED = True
    try:
        import pylibfst as _pl
        # Touch the bits we rely on so a half-broken install fails the probe.
        _ = _pl.lib.fstReaderOpen
        _ = _pl.fstReaderIterBlocks2
        _PYLIBFST = _pl
    except Exception:
        _PYLIBFST = None
    return _PYLIBFST


def _force_native():
    """True if the user pinned the native reader via env var."""
    val = os.environ.get('OWA_FST_FORCE_NATIVE', '')
    return val.strip().lower() not in ('', '0', 'false', 'no', 'off')


def pylibfst_available():
    """Public: is the pylibfst backend usable right now (and not force-disabled)?"""
    return (not _force_native()) and (_probe_pylibfst() is not None)


_PYLIBFST_REAL_TYPES = frozenset({
    int(FstVarType.VCD_REAL), int(FstVarType.VCD_REAL_PARAMETER),
    int(FstVarType.VCD_REALTIME), int(FstVarType.SV_SHORTREAL),
})


class PyLibFstParser:
    """FST parser backed by pylibfst (GTKWave fstapi).

    Exposes the exact same public surface as FSTParser — attributes
    (signals, ts_sec, ts_str, date, version, comments, raw_var_count,
    raw_type_counts) and methods (match, iter_events, scan_time_range,
    _format_raw_value) — and yields identical (time, handle, value) events, so
    the CLI cannot tell which backend produced a result.
    """

    # Reuse the native adapter's matching and value formatting verbatim so the
    # two backends can never drift on filter semantics or value rendering.
    match = FSTParser.match

    def __init__(self, path):
        pl = _probe_pylibfst()
        if pl is None:
            raise _FstFormatError('pylibfst not available')
        self._pl = pl
        self._ffi = pl.ffi
        self._lib = pl.lib
        self.path = path
        ctx = pl.lib.fstReaderOpen(str(path).encode('utf-8'))
        if ctx == pl.ffi.NULL:
            raise _FstFormatError('pylibfst could not open {}'.format(path))
        self._ctx = ctx

        lib = self._lib
        ts = lib.fstReaderGetTimescale(ctx)  # power-of-ten exponent, like native
        self.ts_sec = 10 ** ts
        ts_unit = 's'
        for u, scale in sorted(_UNITS.items(), key=lambda x: -x[1]):
            if abs(self.ts_sec - scale) < 1e-12:
                ts_unit = u
                break
        self.ts_str = '$timescale 1{} $end'.format(ts_unit)
        self.date = pl.string(lib.fstReaderGetDateString(ctx))
        self.version = pl.string(lib.fstReaderGetVersionString(ctx))
        # FST does not carry a VCD-style $comment list; native reports [] too.
        self.comments = []
        self._start_time = lib.fstReaderGetStartTime(ctx)
        self._end_time = lib.fstReaderGetEndTime(ctx)
        # Endianness for real (double) decoding, mirroring the native reader's
        # header.double_endian_match handling.
        self._double_le = True
        try:
            self._double_le = bool(lib.fstReaderGetDoubleEndianMatchState(ctx))
        except Exception:
            self._double_le = True

        self.signals = {}
        self.raw_var_count = 0
        self.raw_type_counts = defaultdict(int)
        self._handle_type = {}

        ffi = self._ffi
        lib.fstReaderIterateHierRewind(ctx)
        scope = []
        while True:
            h = lib.fstReaderIterateHier(ctx)
            if h == ffi.NULL:
                break
            htyp = h.htyp
            if htyp == lib.FST_HT_SCOPE:
                scope.append(pl.string(h.u.scope.name))
            elif htyp == lib.FST_HT_UPSCOPE:
                if scope:
                    scope.pop()
            elif htyp == lib.FST_HT_VAR:
                var = h.u.var
                handle = var.handle
                var_type = var.typ
                length = var.length
                name = pl.string(var.name)
                base = '.'.join(scope)
                path_full = (base + '.' + name) if base else name
                # Normalize "name [msb:lsb]" -> "name[msb:lsb]" exactly as the
                # native adapter does (fstapi emits a space before the bracket).
                bracket_pos = path_full.find(' [')
                if bracket_pos >= 0:
                    path_full = path_full[:bracket_pos] + path_full[bracket_pos + 1:]

                self.raw_var_count += 1
                vtype_name = _FST_VAR_TYPE_NAMES.get(var_type, 'wire')
                self.raw_type_counts[vtype_name] += 1
                is_real = var_type in _PYLIBFST_REAL_TYPES
                vtype = 'real' if is_real else vtype_name
                if var_type == int(FstVarType.VCD_REALTIME):
                    vtype = 'realtime'

                scope_str = ''
                dot_pos = path_full.rfind('.')
                if dot_pos >= 0:
                    scope_str = path_full[:dot_pos]

                self._handle_type[handle] = var_type
                existing = self.signals.get(handle)
                if existing is not None:
                    existing['aliases'].append(path_full)
                    if scope_str and scope_str not in existing['scopes']:
                        existing['scopes'].append(scope_str)
                else:
                    width = length if not is_real else 64
                    if var_type == int(FstVarType.VCD_EVENT):
                        width = 1
                    self.signals[handle] = {
                        'path': path_full, 'width': width, 'type': vtype,
                        'aliases': [path_full], 'scope': scope_str,
                        'scopes': [scope_str] if scope_str else [],
                    }

    def scan_time_range(self):
        return self._start_time, self._end_time

    def _format_raw_value(self, handle, raw_val):
        """Identical contract to FSTParser._format_raw_value."""
        if isinstance(raw_val, memoryview):
            raw_val = bytes(raw_val)
        var_type = self._handle_type.get(handle, -1)
        info = self.signals[handle]
        if var_type in _PYLIBFST_REAL_TYPES and len(raw_val) >= 8:
            try:
                fmt = '<d' if self._double_le else '>d'
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
        lib = self._lib
        ffi = self._ffi
        ctx = self._ctx

        # C-level signal filter: ask fstapi to skip unselected handles entirely.
        lib.fstReaderClrFacProcessMaskAll(ctx)
        if sids is None:
            lib.fstReaderSetFacProcessMaskAll(ctx)
        else:
            # Restrict to declared handles to match the native filtered path.
            any_valid = False
            for h in sids:
                if h in self.signals:
                    lib.fstReaderSetFacProcessMask(ctx, h)
                    any_valid = True
            if not any_valid:
                return

        # C-level time window when an upper bound is given.  fstapi's range is
        # inclusive on both ends; we still re-check t0/t1 below so semantics are
        # exactly the native reader's.
        if t1 is not None:
            lib.fstReaderSetLimitTimeRange(ctx, int(t0) if t0 else 0, int(t1))
        else:
            lib.fstReaderSetUnlimitedTimeRange(ctx)

        events = []
        ap = events.append
        # Logic values arrive as ascii bit-strings; variable-length (string /
        # real) values arrive via the varlen callback as raw bytes.
        def _vc(_user, time, facidx, value):
            ap((time, facidx, self._ffi.string(value)))

        def _vc_varlen(_user, time, facidx, value, length):
            ap((time, facidx, self._ffi.buffer(value, length)[:]))

        self._pl.fstReaderIterBlocks2(ctx, _vc, _vc_varlen, None, None)

        fmt = self._format_raw_value
        for time, facidx, raw in events:
            if time < t0:
                continue
            if t1 is not None and time > t1:
                continue
            if facidx not in self.signals:
                continue
            yield (time, facidx, fmt(facidx, raw))


def wave_parser(path):
    path_lower = str(path).lower()
    is_fst = path_lower.endswith('.fst')
    if not is_fst and not path_lower.endswith('.vcd'):
        # Sniff the magic byte for extensionless inputs.
        try:
            with open(path, 'rb') as f:
                if f.read(1) == _FST_MAGIC:
                    is_fst = True
        except Exception:
            pass

    if is_fst:
        # Prefer pylibfst when present (and not force-disabled); fall back to the
        # native reader on any failure so a quirky build never breaks the tool.
        if pylibfst_available():
            try:
                return PyLibFstParser(path)
            except Exception:
                pass
        try:
            return FSTParser(path)
        except _FstFormatError as e:
            sys.exit('Error: invalid FST file: {}'.format(e))
        except Exception as e:
            sys.exit('Error: cannot open FST file: {}'.format(e))

    return VCDParser(path)