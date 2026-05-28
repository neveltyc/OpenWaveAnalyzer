# Changelog

All notable changes to open_wave_analyzer.


## [Unreleased]

### Changed

- Optimize _summary_rows baseline phase: defer full stats dict creation to
  first analysis-window event, using cheap baseline dict during preamble.

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
