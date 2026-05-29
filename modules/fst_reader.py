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
        if sect.times is None:
            sect.times = self._parse_time_table(payload)
        self._parse_chain_table(sect, payload)
        sect._payload = None
        sect._parsed = True

    def _ensure_time_table_parsed(self, section_index: int) -> None:
        """Parse only the time table (cheap). Leaves _payload for later full parse."""
        sect = self._vc_sections[section_index]
        if sect.times is not None:
            return
        payload = sect._payload
        if payload is None:
            if sect._parsed:
                return
            raise _FstFormatError("section payload not available for time table parse")
        sect.times = self._parse_time_table(payload)

    @staticmethod
    def _locate_chain_data(payload):
        """Locate the chain-table byte range within a section payload.

        Returns (chain_data_bytes, chain_clen, indx_pos). Shared by
        _parse_chain_table (full) and _scan_chain_entries (sparse) so the
        header-offset arithmetic lives in exactly one place.
        """
        n = len(payload)
        tsec_clen = _u64be(payload, n - 16)
        indx_pntr = n - 24 - tsec_clen - 8
        if indx_pntr < 0:
            raise _FstFormatError("invalid chain table position")
        chain_clen = _u64be(payload, indx_pntr)
        indx_pos = indx_pntr - chain_clen
        if indx_pos < 0:
            raise _FstFormatError("invalid chain table offset")
        return payload[indx_pos:indx_pos + chain_clen], chain_clen, indx_pos

    def _scan_chain_entries(self, section_index: int, handle_indices) -> dict:
        """Scan chain table for specific handles only — fast filtered path.

        Returns {handle_1based: (chain_off, chain_len)} for handles with real
        data. Stops after the last needed handle, avoiding the [0]*223K array
        allocation and full alias-resolution pass.

        CORRECTNESS: if any requested handle is an alias whose target is NOT in
        the requested set, the sparse scan cannot resolve it. In that case we
        fall back to a full _ensure_section_parsed and retry — guaranteeing the
        same result as the full path, at the cost of the speedup for that
        section. Non-aliased (or self-contained alias) queries keep the speedup.
        """
        sect = self._vc_sections[section_index]
        if sect._parsed:
            result = {}
            for h in handle_indices:
                idx = h - 1
                if 0 <= idx < len(sect.chain_table):
                    off = sect.chain_table[idx]
                    length = sect.chain_table_lengths[idx]
                    if off > 0 and length > 0:
                        result[h] = (off, length)
            return result

        payload = sect._payload
        if payload is None:
            return {}

        needed_0 = frozenset(h - 1 for h in handle_indices)
        if not needed_0:
            return {}
        max_needed = max(needed_0)

        try:
            chain_data, chain_clen, indx_pos = self._locate_chain_data(payload)
        except _FstFormatError:
            return {}

        def _fallback():
            # Sparse scan insufficient (alias to unselected/forward target).
            # Full parse always yields the correct result; the recursive call
            # then takes the fast sect._parsed branch above. Recursion depth ≤ 2.
            self._ensure_section_parsed(section_index)
            return self._scan_chain_entries(section_index, handle_indices)

        collected = {}        # idx -> (off, length_or_None)
        unresolved = 0        # count of collected entries whose length is None
        pnt = 0; idx = 0; pval = 0; pidx = -1

        if sect.block_type == FST_BL_VCDATA_DYN_ALIAS2:
            prev_alias = 0
            while pnt < chain_clen:
                if chain_data[pnt] & 0x01:
                    shval, skiplen = read_svarint64(chain_data, pnt)
                    shval >>= 1
                    if shval > 0:
                        pval += shval
                        if pidx >= 0 and pidx in collected and collected[pidx][1] is None:
                            collected[pidx] = (collected[pidx][0], pval - collected[pidx][0])
                            unresolved -= 1
                        if idx in needed_0:
                            collected[idx] = (pval, None)
                            unresolved += 1
                        pidx = idx
                        idx += 1
                    elif shval < 0:
                        if idx in needed_0:
                            # Alias target = (-shval)-1. If not also selected, the
                            # sparse scan can't resolve it — fall back immediately.
                            if ((-shval) - 1) not in needed_0:
                                return _fallback()
                            collected[idx] = (0, shval)
                        prev_alias = shval
                        idx += 1
                    else:
                        if idx in needed_0:
                            if ((-prev_alias) - 1) not in needed_0:
                                return _fallback()
                            collected[idx] = (0, prev_alias)
                        idx += 1
                else:
                    val, skiplen = read_varint32(chain_data, pnt)
                    idx += (val >> 1)
                pnt += skiplen
                if idx > max_needed and unresolved == 0:
                    break
        else:
            while pnt < chain_clen:
                val, skiplen = read_varint32(chain_data, pnt)
                if not val:
                    pnt += skiplen
                    val2, skiplen = read_varint32(chain_data, pnt)
                    if idx in needed_0:
                        if (val2 - 1) not in needed_0:
                            return _fallback()
                        collected[idx] = (0, -val2)
                    idx += 1
                elif val & 1:
                    pval += (val >> 1)
                    if pidx >= 0 and pidx in collected and collected[pidx][1] is None:
                        collected[pidx] = (collected[pidx][0], pval - collected[pidx][0])
                        unresolved -= 1
                    if idx in needed_0:
                        collected[idx] = (pval, None)
                        unresolved += 1
                    pidx = idx
                    idx += 1
                else:
                    idx += (val >> 1)
                pnt += skiplen
                if idx > max_needed and unresolved == 0:
                    break

        # Resolve the final data entry's length from the sentinel offset.
        if pidx >= 0 and pidx in collected and collected[pidx][1] is None:
            sentinel_off = indx_pos - sect.vc_start
            collected[pidx] = (collected[pidx][0], sentinel_off - collected[pidx][0])
            unresolved -= 1

        # Resolve alias entries. Mirrors _parse_chain_table's alias loop, which
        # only resolves backward references (target index < current). Anything
        # else (forward ref, target not collected, chained alias) falls back.
        for cidx in list(collected):
            off, length = collected[cidx]
            if length is not None and length < 0 and off == 0:
                src = (-length) - 1
                if (src < cidx and src in collected
                        and collected[src][1] is not None and collected[src][1] > 0):
                    collected[cidx] = collected[src]
                else:
                    return _fallback()

        result = {}
        for h in handle_indices:
            i0 = h - 1
            entry = collected.get(i0)
            if entry is not None:
                off, length = entry
                if off is not None and length is not None and off > 0 and length > 0:
                    result[h] = (off, length)
        return result

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
        # Time tables are delta-encoded varints and are one of the largest hot
        # spots on big traces (tens of millions of items).  decode_varint_deltas
        # is a drop-in replacement for the per-item read_varint64 prefix-sum
        # loop, producing identical output.
        times: list[int] = decode_varint_deltas(ucdata, tsec_nitems)
        # Build O(1) lookup for cumulative time indices
        self._time_to_index: dict[int, int] = {t: i for i, t in enumerate(times)}
        return times

    def _parse_chain_table(self, sect: _VcSection, payload: bytes) -> None:
        # NOTE: the chain-stream decode loop below is mirrored in
        # _scan_chain_entries (sparse variant). If you change the encoding
        # handling here, update that method too — test_scan_chain_parity
        # cross-checks the two against every fixture and will fail on drift.
        chain_data, chain_clen, indx_pos = self._locate_chain_data(payload)
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
        _chain_entry: tuple = None,
    ) -> Iterator[tuple[int, bytes]]:
        if section_index >= len(self._vc_sections):
            return
        sect = self._vc_sections[section_index]
        idx = handle - 1

        if _chain_entry is not None:
            # Filtered fast path: chain entry pre-resolved by _scan_chain_entries.
            self._ensure_time_table_parsed(section_index)
            chain_off, chain_len = _chain_entry
        else:
            self._ensure_section_parsed(section_index)
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
        # Build active handle list on demand — only iter_time_value_pairs
        # needs it; filtered paths (iter_value_changes) never pay this cost.
        ct = sect.chain_table
        ctl = sect.chain_table_lengths
        active = [i for i in range(min(max_handle, len(ct)))
                  if ct[i] > 0 and ctl[i] > 0]
        for idx in active:
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

    # Bind both helpers to the real reader inherited via fork. (Writes like
    # reader._time_to_index land in the child's copy and never reach the parent,
    # which is fine — the parent only consumes the returned tuple.)
    times = reader._parse_time_table(payload)
    reader._parse_chain_table(sect, payload)
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
    return FstSignalMetadata(**data)