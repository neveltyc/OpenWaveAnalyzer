# Changelog

All notable changes to wave_analyzer.

## [Unreleased]

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
