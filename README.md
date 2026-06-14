<p align="center">
  <h1 align="center">OpenWaveAnalyzer</h1>
  <p align="center">
    A fast, single-file CLI for inspecting <b>VCD</b> and <b>FST</b> waveforms &mdash;
    no conversion needed.  Built for RTL debug, agent workflows, and anyone
    who wants answers without opening a waveform viewer.
  </p>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-4.0.0-3366cc?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/python-3.9+-3366cc?style=flat-square&logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-3366cc?style=flat-square">
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

Single file, no required dependencies, Python 3.9+.  (An optional accelerator is
described under [Value backend](#value-backend).)

```bash
# Download the release artifact
curl -fsSL https://raw.githubusercontent.com/neveltyc/OpenWaveAnalyzer/main/open_wave_analyzer.py -o open_wave_analyzer.py

# Verify
python open_wave_analyzer.py --version
```

No pip, no venv, no PyPI.  Works anywhere curl and Python 3.9+ are available
&mdash; CI containers, EDA servers, Docker builds, agent toolchains.

`--version` also prints the active value backend.  The pure-Python reader is the
default and needs nothing installed; an optional accelerator is described in
[Value backend](#value-backend) below.

## Value backend

By default OpenWaveAnalyzer reads value data with its built-in pure-Python
reader &mdash; zero dependencies, every platform.  If the optional
[`pywellen`](https://pypi.org/project/pywellen/) package (the Python binding for
the Rust [`wellen`](https://github.com/ekiwi/wellen) waveform library) is
installed, the tool automatically switches to a **hybrid** backend:

- the **hierarchy** (scopes, signal names, bus ranges like `[15:8]`, split bus
  slices, arrays, aliases) is still parsed by the native reader, so paths and
  ranges are exactly what the file declares; and
- the **value body** is read through `pywellen`, which speeds up full dumps and
  makes time-windowed queries (`dump --begin/--end`, `snapshot`, `compare`)
  noticeably faster on large traces.

```bash
pip install pywellen      # optional; enables the hybrid backend
python open_wave_analyzer.py --version
#   open_wave_analyzer 4.0.0
#   value backend: pywellen 0.25.5 (hybrid -- native hierarchy + pywellen values)
```

The backend is transparent &mdash; the same seven commands and the same
`--json` shapes work either way. Control it with environment variables:

| Variable | Effect |
|:---------|:-------|
| `OWA_FORCE_NATIVE=1` | Always use the pure-Python reader, even if `pywellen` is installed |
| `OWA_PYWELLEN_ALLOW_ANY=1` | Accept any installed `pywellen` version (otherwise a pinned version is expected, and a mismatch falls back to native) |

If `pywellen` is missing, version-mismatched, or errors on a file, the tool
silently falls back to the native reader, so it always works.

**Notes on equivalence.** The two backends agree on the signal model and on
values, but a few differences are expected and intentional: `wellen` reports
only real value *transitions*, so redundant same-value writes present in a
source file are coalesced (this lowers change counts in `summary` and row
counts in `dump` for such files); multiple writes within a single timestamp are
reduced to the settled value; the relative order of events that share a
timestamp may differ; and `pywellen` can read enum / VHDL `U`/`X` style values
that the native reader does not. Use `OWA_FORCE_NATIVE=1` when you need the
native reader's every-record behavior.

> GHW (GHDL's native waveform format) is **not** supported by either backend and
> is rejected with a clear error; convert it to VCD or FST first.

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

Measured on a 17.1 MB VCD waveform and its FST equivalent (1.6 MB, 10.7&times;
smaller).  Python 3.14 on Windows x64, single-core, no warmup.

| Command | VCD (17 MB) | FST (1.6 MB) | Notes |
|:--------|------------:|--------------:|:------|
| `info` | 1.46 s | 3.30 s | header-only, FST hierarchy init dominates |
| `summary --filter <sig>` | 1.58 s | 2.99 s | single-signal full-window stats |
| `dump --filter <sig> --limit 3` | 1.57 s | 3.21 s | quick peek at a signal |
| `dump --filter <sig> --limit 0` | 1.57 s | 3.19 s | full filtered scan |
| `dump --limit 10` (no filter) | 1.82 s | 4.11 s | first 10 events, all signals |

On this 17 MB file, VCD finishes under 2 s for nearly every command.  FST
spends ~3 s in hierarchy initialisation, but the file is **10.7&times;
smaller** and the gap shrinks as traces grow: on a 368 MB FST, filtered
queries complete in 5&ndash;8 s while the equivalent VCD scan takes minutes.
For interactive use, either format is fast enough that the difference is
rarely the bottleneck compared to opening a GUI viewer.

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
  fst_adapter.py            Part 7: FSTParser adapter + pywellen hybrid backend
  cli.py                    Part 8: 7 commands + CLI entry
verify/                   Test suites:
  test_cross_validate.py      VCD vs FST parity checks
  test_scan_correctness.py    white-box filtered scan tests
  test_commands_extended.py   extended cross-validation
  test_pywellen_backend.py    pywellen hybrid backend (skips without pywellen)
CHANGELOG.md              Release notes
```

## Tests

```bash
# Generate waveform pairs (requires iverilog + vcd2fst in PATH)
python verify/gen_waveforms.py

# Run the full test suite
python _make.py && python -m pytest verify/ -q && python _make.py --check
```

The test suite compiles Verilog/SystemVerilog designs, simulates them with
iverilog/vvp, converts to FST via vcd2fst, then runs every command on both
formats and compares the JSON output.  Additional suites cover white-box
filtered-scan correctness and extended cross-validation under many option
combinations.

A separate `test_pywellen_backend.py` exercises the hybrid value backend: it
runs the CLI with the backend active and with `OWA_FORCE_NATIVE=1` and asserts
they agree on the model and values for clean fixtures, then covers the bus-slice
feature, IEEE 1364 value types (4-state `x`/`z`, mixed, real, event, signed),
same-timestamp coalescing, GHW rejection, error-handling parity, and VCD&harr;FST
consistency.  It skips automatically when `pywellen` is not installed.

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
