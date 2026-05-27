<p align="center">
  <h1 align="center">OpenWaveAnalyzer</h1>
  <p align="center">
    A fast, single-file CLI for inspecting <b>VCD</b> and <b>FST</b> waveforms &mdash;
    no conversion needed.  Built for RTL debug, agent workflows, and anyone
    who wants answers without opening a waveform viewer.
  </p>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-2.0.0-3366cc?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/python-3.9+-3366cc?style=flat-square&logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-3366cc?style=flat-square">
  <img alt="Tests" src="https://img.shields.io/badge/tests-145%20passed-22aa55?style=flat-square">
</p>

---

## Why OpenWaveAnalyzer?

**Open** means it supports both open waveform formats &mdash; VCD and FST &mdash;
natively, in a single tool.  No `fst2vcd` pre-conversion, no format lock-in.
Drop in a `.vcd` or `.fst` and the same seven commands just work.

You have a waveform dump from simulation &mdash; `.vcd` from Icarus, `.fst` from
commercial tools, or both &mdash; and you need to know what happened to
`state[3:0]` between 17.3 us and 17.6 us.  Opening a waveform viewer means
waiting for the GUI, clicking through the hierarchy, zooming, squinting at
values.  This tool gives you the answer in one command.

It is designed from the ground up for **agent-assisted workflows**: every
command has a `--json` mode that emits compact, machine-readable output so
LLM agents can inspect waveforms without a GUI.

```bash
python open_wave_analyzer.py search sim.fst --condition "state=5" --show data,valid --begin 17us
```

## Quick start

```bash
# What is in this file?
python open_wave_analyzer.py info sim.vcd
python open_wave_analyzer.py info sim.fst

# Show me the clock and reset
python open_wave_analyzer.py list sim.vcd --filter clk,rst

# What happened between 100 ns and 200 ns?
python open_wave_analyzer.py dump sim.fst --begin 100ns --end 200ns --filter state

# When was valid=1 AND ready=1 at the same time?
python open_wave_analyzer.py search sim.vcd --condition "valid=1,ready=1" --show data

# Give me a snapshot at exactly 17.55 us
python open_wave_analyzer.py snapshot sim.fst --at 17.55us --filter state,init_done

# Which signals are toggling, which are static?
python open_wave_analyzer.py summary sim.vcd --filter dll_*
```

## Install

Single file, no dependencies, Python 3.9+.

```bash
# Download the release artifact
curl -fsSL https://raw.githubusercontent.com/neveltyc/OpenWaveAnalyzer/main/open_wave_analyzer.py -o open_wave_analyzer.py

# Verify
python open_wave_analyzer.py --version
```

No pip, no venv, no PyPI.  Works anywhere curl and Python 3.9+ are available
&mdash; CI containers, EDA servers, Docker builds, agent toolchains.

## Supported formats

| Format | Extension | Detection |
|:-------|:----------|:----------|
| VCD (Value Change Dump) | `.vcd` | Extension or text header |
| FST (Fast Signal Trace) | `.fst` | Extension or magic byte (`0x00`) |

The same 7 commands work identically on both formats.  FST files are typically
10&ndash;20&times; smaller than equivalent VCD files.

## Commands

| Command | What it does |
|:--------|:-------------|
| `info` | Timescale, signal count, time span, scopes &mdash; the file at a glance |
| `list` | Enumerate signals with path, width, and type |
| `dump` | Print every value change in a time window, in order |
| `summary` | Per-signal stats: active/static, change count, rise/fall edges |
| `snapshot` | What are all known signal values at time T? |
| `compare` | What changed between T1 and T2? |
| `search` | Find intervals where conditions hold, optionally watching related signals |

All commands accept `--begin` / `--end` time windows with unit suffixes
(`fs`, `ps`, `ns`, `us`, `ms`, `s`), `--filter` with substring or glob
patterns, and `--json` for structured output.

Run `python open_wave_analyzer.py --help` for the full reference.

## Performance

Measured on a 12 MB VCD waveform and its FST equivalent (0.87 MB, 14&times;
smaller).  All tests run with a single-core Python 3.14 on Windows x64, no
warmup.

| Command | VCD (12 MB) | FST (0.87 MB) | Ratio |
|:--------|------------:|--------------:|:------|
| `info` | 1.63 s | 0.20 s | FST 8&times; faster |
| `summary` | 3.16 s | 4.80 s | FST 1.5&times; slower |
| `dump` | 8.48 s | 10.60 s | FST 1.25&times; slower |

`info` is near-instant on FST because the header does not require scanning the
value-change data.  `dump` and `summary` are slower on FST because the
pure-Python LZ4/FastLZ decompression path is not as fast as reading plain-text
VCD tokens.  The trade-off: **FST files are 14&times; smaller, at the cost of
~25% more parse time for full-scan commands.**

Future work (mmap-backed reading, optional C-extension decompression) can close
this gap.  For interactive use, the time difference is rarely the bottleneck
compared to opening a GUI viewer.

## JSON output

Every command emits compact structured JSON under `--json`.  Agents and scripts
get raw tick counts (`_ticks`) alongside human-readable times (`_h`).

```bash
python open_wave_analyzer.py --json info sim.fst
python open_wave_analyzer.py --json search sim.vcd --condition "state=5" --show data
```

## Project layout

```
open_wave_analyzer.py          Release artifact (single file, _make.py output)
_make.py                  Assembler: concatenate modules/ into open_wave_analyzer.py
modules/                  Source modules (edit here, _make.py builds the release)
  _preamble.py              Shebang, docstring, imports, version
  fst_types.py              Part 1: FST enums and dataclasses
  fst_codec.py              Part 2-3: FST varint + LZ4/FastLZ codec
  fst_reader.py             Part 4: _FstReader (syncs with PurePyFstlib upstream)
  vcd_utils.py              Part 5: Timescale, filter, value helpers
  vcd_parser.py             Part 6: VCDParser (syncs with VCD_ANALYZER upstream)
  fst_adapter.py            Part 7: FSTParser adapter
  cli.py                    Part 8: 7 commands + CLI entry
verify/                   Cross-validation test suite (152 cases, 19 waveform pairs)
CHANGELOG.md              Release notes
```

## Tests

```bash
# Generate waveform pairs (requires iverilog + vcd2fst in PATH)
python verify/gen_waveforms.py

# Run cross-validation suite (requires pytest)
python -m pytest verify/ -v
```

The test suite compiles 19 Verilog/SystemVerilog designs (custom + PurePyFstlib
fixtures + VCD_ANALYZER fixtures), simulates them with iverilog/vvp, converts
to FST via vcd2fst, then runs every command on both formats and compares the
JSON output.

**145 passed, 7 skipped, 0 failed.**  The 7 skipped are designs with zero time
range or no 1-bit signals, which are design limitations, not bugs.

## Development workflow

```
Edit FST reader    -> modules/fst_reader.py
Edit VCD parser    -> modules/vcd_parser.py
Edit other parts   -> corresponding module in modules/
Build              -> python _make.py
Check consistency  -> python _make.py --check
Run tests          -> pytest verify/
Sync PurePyFstlib  -> diff -> patch modules/fst_reader.py -> python _make.py
Sync VCD_ANALYZER  -> diff -> patch modules/vcd_parser.py -> python _make.py
Release            -> publish open_wave_analyzer.py (single file)
```

## License

MIT.