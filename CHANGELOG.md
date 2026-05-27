# Changelog

All notable changes to wave_analyzer.

## [Unreleased]

### Fixed

- Rename 41 stray references to FstFormatError that missed the _FstFormatError
  prefix applied during inlining.  These would raise NameError instead of the
  intended format error on malformed or truncated FST inputs.

### Added

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
  152 test cases
