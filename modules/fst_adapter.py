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
    return VCDParser(path)