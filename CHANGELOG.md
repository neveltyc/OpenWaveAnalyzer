# Changelog

All notable changes to open_wave_analyzer.


## [3.0.1] - 2026-05-29

### Fixed

- Restore Python 3.9 compatibility. The codebase uses PEP 604 union syntax
  (e.g. `tuple[str, int] | None`, `bytes | bytearray | memoryview`) in
  annotations, which raises `TypeError` at import time on Python 3.9 — most
  visibly on the `@dataclass` field `source_stem: tuple[str, int] | None`.
  Adding `from __future__ import annotations` (PEP 563) makes all annotations
  lazy strings so they are never evaluated at runtime, which 3.9 supports.
- Fix `verify/test_scan_correctness.py` so it remains compatible with the
  future-import. The test imports the assembled file under a synthetic module
  name via `spec_from_file_location` + `exec_module`. Under PEP 563,
  `@dataclass` resolves its string field annotations through
  `sys.modules[cls.__module__].__dict__` to detect `KW_ONLY`; a module built
  by `module_from_spec` is not auto-registered, so the lookup returned `None`
  and class creation failed. The loader now registers the module in
  `sys.modules` before `exec_module` (and pops it on failure).

Verified on CPython 3.9.19 and 3.12: the single file imports and runs, output
is byte-for-byte identical across versions, and the full test suite passes on
both. Minimum supported Python returns to 3.9; README badge reverted to 3.9+.


## [3.0.0] - 2026-05-29

### Changed

- Vectorized time-table varint decode: numpy-accelerated path for bulk
  VCDATA time tables, with pure-Python fast path fallback.
- Faster FST hierarchy parse: shared default metadata for attribute-free
  variables, LZ4 decompression optimized with C-level slice copy, dropped
  dead _time_to_index dict.
- VCD chunked tokenizer: data section read in 4MB chunks split in C,
  replacing per-line readline+split. List-based iter_events eliminates
  per-token generator resume.
- VCD one-line header fast path: common VCD declarations handled by
  direct line parsing, avoiding per-token state machine.
- FST C-level cstr scan: bytes.find-based null scan, deferred signal-name
  index (never built for analysis commands).
- Trim per-variable startup allocations: elided empty attributes dict
  entries, lazy vars_by_handle alias list.
- All previous Unreleased changes folded in (VCDATA lazy parsing,
  section time-window skip, multi-process parallel parse, filtered
  chain-table scan, bulk_parse for bounded dump, _summary_rows
  baseline optimization, active_handles lazy, alias fallback hardening).

### Added

- verify/test_scan_correctness.py (152 white-box tests)
- verify/test_commands_extended.py (276 extended cross-validation tests)

573 passed, 16 skipped.



### Changed

- Optimize _summary_rows baseline phase: defer full stats dict creation to
  first analysis-window event, using cheap baseline dict during preamble.
- Defer FST VCDATA time_table and chain_table parsing to first access
  (_ensure_section_parsed), making info/list O(hierarchy) instead of
  O(hierarchy + all sections).  Add section-level time-window skipping in
  FSTParser.iter_events to avoid sections outside [t0, t1].  Large FST
  header-only commands drop from ~24s to ~6s (-74%); time-range queries
  (snapshot, compare, --begin/--end) drop ~78-80%.
- Add batch pre-parse for full-scan paths in lazy VCDATA to avoid per-section
  _ensure_section_parsed overhead inside generator frames.  Uses a
  needed >= sections//2 heuristic; full-scan commands see modest improvement
  but filtered commands regress when the heuristic triggers unnecessarily.
  Time-window commands (snapshot, compare, --begin/--end) are unaffected.
- Multi-process parallel section parsing in _ensure_all_sections_parsed:
  when >=4 sections need parsing, distributes across ProcessPoolExecutor
  (max 4 workers).  On Linux, workers inherit parent mmap via fork; on
  Windows the sequential fallback applies.  Full-scan commands (summary,
  search) improve from ~38s to ~26s on large FST, slightly faster than
  the original eager parsing.  Filtered commands still regress vs pure
  lazy because the batch heuristic continues to trigger unnecessarily.
- Gate batch pre-parse on `sids is None` so only unfiltered full-scan
  commands trigger bulk+parallel parsing.  Filtered dumps that need
  single-handle data avoid parsing all chain tables, restoring 5-8s
  performance.  With this gate: summary/search/dump --limit 0 ~23-27s
  (-14-19% vs original eager), filtered dumps ~5-8s (-68-77%).

## [2.0.1] - 2026-05-28

### Changed

 
- Merge FSTParser.__init__ three hierarchy() passes into a single traversal,
  compute raw_var_count and raw_type_counts inline, and replace per-path
  re.match() with path.find(' [') + slice to eliminate ~275K regex calls.
- Replace double-scan VCD patterns in summary, compare, and search commands
  with single iter_events passes: _summary_rows builds both baseline
  snapshot and per-signal statistics in one scan; cmd_compare uses
  _build_snapshot_pair to capture two snapshots in one pass; cmd_search
  builds state and processes events in a single iteration for both changed
  and interval/segment modes.
- Speed up filtered FST iteration with single-handle fast path.
- Remove inline heapq import in FST adapter (heapq is imported at file
  level).

### Fixed

- Fix DYN_ALIAS2 chain table clobber in FST reader and add dump command
  defenses against malformed value-change data.
- Add missing comp_body guard in FST reader to prevent access on
  non-existent VC section compression bodies.

- Speed up filtered VCD scans by skipping unselected scalar, vector, and real
  value-change tokens before full value parsing.
- Align VCD tokenization with upstream VCD_ANALYZER by using Python's standard
  whitespace splitting in the VCD parser.

## [2.0.0] - 2026-05-28

### Changed

- Split monolithic open_wave_analyzer.py into 8 source modules under modules/,
  assembled by _make.py.  The single-file release artifact is produced by
  running python _make.py; python _make.py --check verifies byte-level
  consistency between modules/ and the assembled output.

### Added

- VCDATA section integrity check: after iterating all time points, warn if
  any signal chain has unconsumed data remaining, which would indicate
  silently dropped value changes due to corruption.

### Fixed

- Rename 41 stray references to FstFormatError that missed the _FstFormatError
  prefix applied during inlining.  These would raise NameError instead of the
  intended format error on malformed or truncated FST inputs.
- Restore full module docstring with command reference table, argument format
  descriptions, 12 usage examples, and format comparison notes.  Had been
  stripped to a 6-line stub during the build script assembly.

### Added (initial)

- FST waveform reading via inlined PurePyFstlib (v0.4.0) reader core:
  common types, varint encoding, LZ4/FastLZ decompression, _FstReader
  with correct VCDATA parsing including DYN_ALIAS2 chain resolution
- Full VCDParser retained from vcd_analyzer (v1.3.10) with
  bit-exploded signal reassembly
- FSTParser adapter exposing VCDParser-compatible interface
- wave_parser() factory for automatic format detection (extension
  and magic bytes)
- Seven analysis commands: info, list, dump, summary, snapshot,
  compare, search
- Bus range name normalization across formats
- Cross-validation test suite (verify/) with 19 waveform pairs,
  152 test cases (145 passed, 7 skipped, 0 failed)
