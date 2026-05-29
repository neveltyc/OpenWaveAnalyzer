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
        """Yield every token of the data section, one at a time.

        Retained for callers (e.g. scan_time_range) that want a flat token
        stream.  Implemented on top of the chunked list tokenizer so both
        share one tokenization path.
        """
        for toks in self._data_token_lists():
            for t in toks:
                yield t

    def _data_token_lists(self):
        """Yield successive non-empty token *batches* from the data section.

        The buffered initial tokens (those that trailed ``$enddefinitions`` on
        the same read) are yielded first.  The data section is then read in
        large chunks and split in C, rather than iterated line by line: an
        FST-to-VCD converter can emit tens of millions of one-token lines, and
        per-line ``readline`` plus per-line ``.split()`` dominate tokenizer
        time on those.  A carry buffer holds any partial token spanning a chunk
        boundary, so the concatenation of the batches is byte-for-byte
        identical to the previous per-line ``.split()`` (verified against it
        across chunk sizes and adversarial whitespace).

        iter_events() reads each batch by index, so only batch boundaries pay a
        ``next()`` call instead of every token — removing the per-token
        generator resume that dominated tokenizer time on large traces.
        """
        if self._initial_tokens:
            yield list(self._initial_tokens)

        chunk_size = _env_int('VCD_ANALYZER_TOKEN_CHUNK_SIZE', 4 * 1024 * 1024)
        if chunk_size < 65536:
            chunk_size = 65536
        carry = ''
        with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(self._data_offset)
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                if carry:
                    chunk = carry + chunk
                    carry = ''
                # If the chunk does not end on whitespace its final token may be
                # truncated mid-token.  Cut at the last whitespace char, tokenize
                # the complete prefix, and carry the remainder.  rfind over the
                # six VCD whitespace characters stays in C.
                if not chunk[-1].isspace():
                    cut = max(chunk.rfind(' '), chunk.rfind('\n'), chunk.rfind('\t'),
                              chunk.rfind('\r'), chunk.rfind('\v'), chunk.rfind('\f'))
                    if cut < 0:
                        carry = chunk
                        continue
                    carry = chunk[cut + 1:]
                    chunk = chunk[:cut]
                toks = chunk.split()
                if toks:
                    yield toks
        if carry:
            tail = carry.split()
            if tail:
                yield tail

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

    def iter_events(self, t0=0, t1=None, sids=None, *, bulk_parse=True):
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

        # Flattened tokenizer. The data section is consumed as a sequence of
        # token *lists* (self._data_token_lists); the main loop reads the
        # current list by index, so only list boundaries pay a next() call —
        # the per-token generator resume that dominated tokenizer time on large
        # files is gone. Pushback is honored on every read, so the b/r/p
        # look-ahead and $-section skipping keep their exact prior semantics.
        list_iter = self._data_token_lists()
        pushback = []
        toks = ()
        ntoks = 0
        ti = 0
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
            nonlocal toks, ntoks, ti
            if pushback:
                return pushback.pop()
            while ti >= ntoks:
                nl = next(list_iter, None)
                if nl is None:
                    return None
                toks = nl
                ntoks = len(nl)
                ti = 0
            tok = toks[ti]
            ti += 1
            return tok

        try:
            while True:
                # Inline token fetch (hot path): a direct index read with no
                # function call for the common case; _next() is reserved for
                # the parser's b/r/p look-ahead and section skipping.
                if pushback:
                    tok = pushback.pop()
                elif ti < ntoks:
                    tok = toks[ti]
                    ti += 1
                else:
                    nl = next(list_iter, None)
                    if nl is None:
                        break
                    toks = nl
                    ntoks = len(nl)
                    tok = toks[0]
                    ti = 1

                c0 = tok[0]
                # Top-level $keyword. Known wrappers ($dumpvars etc) and a bare
                # $end are pass-through markers; any other $section's body is
                # dropped to its $end so '$bogus 1! $end' can't pollute the
                # waveform. Gating on the first character keeps non-$ tokens
                # (the overwhelming majority) out of these comparisons.
                if c0 == '$':
                    if tok == '$end' or tok in _SIM_KEYWORDS:
                        continue
                    while True:
                        t = _next()
                        if t is None or t == '$end':
                            break
                    continue

                if c0 == '#' and len(tok) > 1 and tok[1].isdigit():
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

                # ---- Value change ----
                # The 1-bit scalar form (a single leading 0/1/x/z/X/Z followed
                # by the identifier_code) is by far the most common token, so it
                # is parsed inline here without a helper call. b/r/p forms keep
                # going through _consume_value_change so the malformed-token
                # validation rules live in exactly one place.
                if c0 in '01xXzZ' and len(tok) > 1:
                    sym = tok[1:]
                    # Fast-path filter: drop unneeded signals before any work.
                    if sids is not None and sym not in sids and sym not in bit_map:
                        continue
                    val = c0 if c0 in '01xz' else c0.lower()
                elif c0 in 'bBrRp':
                    # Fast-path filter peek for b/r (identifier is the next
                    # token). p is left to the standalone-stage filter, matching
                    # prior behavior.
                    if sids is not None and c0 in 'bBrR':
                        sym_tok = _next()
                        if sym_tok is not None and not self._is_structural_token(sym_tok):
                            if sym_tok not in sids and sym_tok not in bit_map:
                                continue  # consume both tokens, skip
                            pushback.append(sym_tok)  # needed — put back for parser
                        elif sym_tok is not None:
                            pushback.append(sym_tok)
                    parsed = self._consume_value_change(tok, _next, pushback)
                    if parsed is None:
                        continue
                    sym, val = parsed
                else:
                    # Not a value_change opener (e.g. stray '#', bare 'b').
                    continue

                # Catch-up before t0: update bit_state only, don't emit.
                # Standalone state is owned by callers (e.g. _build_snapshot
                # accumulates it from yielded events), so nothing to do here
                # for the standalone case — the continue is correct.
                if cur_t < t0:
                    if sym in bit_map:
                        bit_val = val if len(val) == 1 and _is_4state_bits(val) else 'x'
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
                    bit_val = val if len(val) == 1 and _is_4state_bits(val) else 'x'
                    for gid, idx in bit_map[sym]:
                        bit_state[gid][idx] = bit_val
                        if sids is None or gid in sids:
                            pending[gid] = ''.join(reversed(bit_state[gid]))

                # Standalone signal (may run after the bit-bus branch above when
                # the sym serves both roles).
                info = self.signals.get(sym)
                if info is None:
                    continue
                if sids is not None and sym not in sids:
                    continue
                # Inline the over-wide clamp guard. A scalar value (len 1) can
                # never exceed a declared width >= 1, and on real dumps ~93% of
                # standalone values are scalars and over-wide values are absent
                # entirely — so calling _clamp_overwide_logic_value() for every
                # event is almost pure call/dict/len overhead across tens of
                # millions of events. Take the helper only when the value is
                # actually long enough to possibly need clamping; it remains the
                # single source of truth for that rare case.
                if len(val) == 1:
                    pending[sym] = val
                else:
                    w = info.get('width')
                    if w is None or len(val) <= w:
                        pending[sym] = val
                    else:
                        pending[sym] = _clamp_overwide_logic_value(val, info)

            # Final flush
            if cur_t >= t0:
                for sid, val in _flush():
                    yield cur_t, sid, val
        finally:
            close = getattr(list_iter, 'close', None)
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
    return r