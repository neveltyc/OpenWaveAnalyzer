#!/usr/bin/env python3
"""Unified VCD/FST waveform analyzer for Agent-based RTL debug.

Usage: open_wave_analyzer [--json] <command> <file> [options]
Supported formats: VCD (.vcd), FST (.fst) — auto-detected by extension or magic byte.

Commands:
  info       <file>                               File overview (timescale, signal count, time span, scopes)
  list       <file> [--filter K1,K2]               List signals with path and bit width
  dump       <file> [--begin T] [--end T] [--filter K1,K2]   Print signal value changes in time order
  summary    <file> [--begin T] [--end T] [--filter K1,K2]   Per-signal stats: change count, unique values, static detection
  snapshot   <file> --at T [--filter K1,K2]        Known signal values at a given time point
  compare    <file> --at T1,T2 [--filter K1,K2]    Diff signal values between two time points
  search     <file> --condition C [--show K1,K2] [--changed K] [--begin T] [--end T]
                                                        Conditional search and associated signal observation

Global options:
  --json       Output compact structured JSON instead of text (time fields include *_ticks)
  --limit N    Max rows/records to emit; default 200; 0 = unlimited.
               Streaming commands stop after detecting the first unshown result.
  --verbose    Show extra fields; if --limit is omitted, disables truncation

Argument formats:
  <file>          VCD (.vcd) or FST (.fst) waveform file path.
                  Extension is used for format detection; unknown extensions fall back
                  to first-byte magic (FST starts with 0x00).
  --filter K1,K2  Comma-separated patterns. Plain text uses case-insensitive substring match;
                  patterns containing * or ? use case-insensitive glob match.
                  e.g. --filter clk,rst   --filter '*_valid,*_ready,*_data'   --filter 'top.u_dma.*'
  --begin T       Start time with optional unit suffix: 0, 100ns, 17.5us, 1ms, 500ps, 200fs
  --end T         End time, same format as --begin. Omit for no upper bound
  --at T          Time point for snapshot. For compare: two points comma-separated: --at 17.5us,17.7us
  --condition C   Comma-separated AND conditions: SIG=VAL, SIG==VAL, SIG!=VAL.
                  Condition signal patterns must match exactly one signal.
                  SIG!=VAL does not match x/z/undef; use SIG=x to search unknown.
                  Values use numeric or 4-state matching: 5, 0x5, b0101, b1x0z.
  --show K1,K2    Optional associated signals to display while condition holds;
                  segment mode splits whenever shown values change.
  --changed K     Optional trigger signal; emit events only when this signal really changes.
                  For ordinary signals, first observed values are not treated as changes.
                  VCD event variables count each trigger; t=0 initialization is ignored.

Examples:
  python open_wave_analyzer.py info sim.vcd
  python open_wave_analyzer.py info design.fst
  python open_wave_analyzer.py list sim.vcd --filter tdata,tvalid,tready
  python open_wave_analyzer.py dump sim.fst --begin 17.5us --end 17.6us --filter clk,rst,state
  python open_wave_analyzer.py summary sim.vcd --filter dll_st,locked
  python open_wave_analyzer.py snapshot design.fst --at 17.55us --filter init_done,state
  python open_wave_analyzer.py compare sim.vcd --at 17.535us,17.56us --filter init_done,link_active,state
  python open_wave_analyzer.py search sim.fst --condition "state=5"
  python open_wave_analyzer.py search sim.vcd --condition "arvalid=1,arready=1" --show araddr,arlen,arid
  python open_wave_analyzer.py search sim.vcd --changed data_out --condition "valid=0" --show data_out,valid
  python open_wave_analyzer.py search sim.fst --condition "valid=x"
  python open_wave_analyzer.py --json summary sim.vcd --filter tvalid,tready

Notes:
  Both VCD and FST files go through the same 7 analysis commands with identical
  output structure. FST files are typically 10-20x smaller; info is faster on FST
  (header-only read) while dump/summary may be slightly slower (pure-Python
  decompression).

  search requires at least one observed value_change in the data section;
  empty waveforms are reported as an input/data issue rather than as a false
  "no match" result.
"""

# PEP 563: make all annotations lazy strings so the PEP 604 union syntax used
# throughout this file (e.g. ``bytes | bytearray | memoryview``,
# ``tuple[str, int] | None``) is never evaluated at runtime.  Without this the
# module fails to import on Python 3.9, where ``X | Y`` raises TypeError
# outside of a string annotation.  This must remain the first statement after
# the module docstring.  See verify/test_scan_correctness.py for the matching
# loader fix that lets @dataclass resolve these string annotations when the
# module is imported under a synthetic name.
from __future__ import annotations

__version__ = '3.1.0'

import sys, os, re, math, json, struct
import zlib as _zlib
import bisect, mmap, argparse, base64, fnmatch, heapq, warnings
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Iterator



