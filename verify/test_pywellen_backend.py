"""Tests for the pywellen hybrid value backend.

The hybrid backend (native hierarchy + pywellen value body) is only active when
``pywellen`` is importable; this whole module skips otherwise.  Tests drive the
CLI as a subprocess -- once with the backend active and once with
``OWA_FORCE_NATIVE=1`` -- and assert the two agree on the signal model and on
values for clean fixtures, then exercise the bus-slice feature, IEEE 1364 value
types, GHW rejection, error handling, and the env-var escapes.

Self-contained: every VCD fixture is written as text here, so no simulator or
bundled waveform is required.  Where ``vcd2fst`` (GTKWave) is on PATH the same
fixtures are converted to FST and the VCD/FST hybrid outputs are checked for
consistency; that part skips when the tool is missing.

Unlike ``conftest.run_analyzer`` (which runs ``python -S`` and so never sees
site-packages such as pywellen), this module's runner keeps the default import
path, so the hybrid path is genuinely exercised.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      'open_wave_analyzer.py')

# ---------------------------------------------------------------------------
# Skip the whole module unless pywellen can be imported.
# ---------------------------------------------------------------------------
pywellen = pytest.importorskip("pywellen", reason="pywellen not installed")

HAVE_VCD2FST = shutil.which("vcd2fst") is not None


def run(args, file=None, *, native=False, extra_env=None, timeout=60):
    """Run the analyzer (NOT with -S, so pywellen is importable).

    ``file`` may be passed separately or already included in ``args``.
    ``OWA_PYWELLEN_ALLOW_ANY`` is set for the hybrid path so the suite does not
    depend on the exact pinned pywellen version (a dedicated test covers the
    pin); ``OWA_FORCE_NATIVE`` selects the native reader.
    """
    env = dict(os.environ)
    env.pop("OWA_FORCE_NATIVE", None)
    env.pop("OWA_PYWELLEN_ALLOW_ANY", None)
    if native:
        env["OWA_FORCE_NATIVE"] = "1"
    else:
        env["OWA_PYWELLEN_ALLOW_ANY"] = "1"
    if extra_env:
        env.update(extra_env)
    argl = list(args)
    if file is not None:
        argl.append(file)
    cmd = [sys.executable, SCRIPT] + [str(a) for a in argl]
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)


def run_json(args, file=None, *, native=False, extra_env=None):
    r = run(["--json"] + list(args), file, native=native, extra_env=extra_env)
    assert r.returncode == 0, "command failed: {}\n{}".format(args, r.stderr or r.stdout)
    return json.loads(r.stdout.strip())


# ---------------------------------------------------------------------------
# Normalization (order-insensitive within a timestamp, matching the project's
# own dump normalization).
# ---------------------------------------------------------------------------

def norm_list(d):
    sig = [{"path": s["path"], "width": s["width"], "type": s["type"]}
           for s in d.get("signals", [])]
    sig.sort(key=lambda s: s["path"])
    return sig


def norm_dump(d):
    ev = [(e["time_ticks"], e["path"], e["value"]) for e in d.get("events", [])]
    ev.sort()
    return ev


def dump_values(d, path):
    vals = [(e["time_ticks"], e["value"]) for e in d.get("events", []) if e["path"] == path]
    vals.sort()
    return vals


# ---------------------------------------------------------------------------
# Fixtures (handcrafted VCD text -> files).  All transitions are deliberately
# clean (no redundant same-value writes, no cross-timestamp glitch-and-return)
# so the hybrid and native outputs are byte-identical after sorting.
# ---------------------------------------------------------------------------

SLICES_VCD = """\
$date Sat Jun 14 2026 $end
$version owa-test $end
$timescale 1ns $end
$scope module top $end
$var reg 8 # data [15:8] $end
$var reg 8 $ data [7:0] $end
$var reg 8 % mem [0] $end
$var reg 8 & mem [1] $end
$var reg 8 ( count [7:0] $end
$upscope $end
$enddefinitions $end
#0
$dumpvars
b00000001 #
b00000010 $
b00000011 %
b00000100 &
b00000101 (
$end
#5
b10101010 #
b01010101 $
b00001010 (
#10
b11111111 #
b00000000 $
"""

# IEEE 1364 value types: 0/1/x/z scalars, 4-state vectors (full & mixed),
# tri-state wire, real, event, signed (two's complement bits).
TYPES_VCD = """\
$date Sat Jun 14 2026 $end
$version owa-test $end
$timescale 1ns $end
$scope module top $end
$var wire 1 a sx $end
$var wire 1 b sz $end
$var reg 8 c vec8 [7:0] $end
$var reg 4 d nyb [3:0] $end
$var real 1 e realv $end
$var event 1 f ev $end
$var reg 8 g sgn [7:0] $end
$var reg 16 h vec16 [15:0] $end
$upscope $end
$enddefinitions $end
#0
$dumpvars
0a
0b
b00000000 c
b0000 d
r0 e
b00000000 g
b0000000000000000 h
$end
#10
1a
1b
b10101010 c
b1010 d
r3.14159 e
1f
b11111011 g
b1010101001010101 h
#20
xa
zb
bxxxxxxxx c
b10xz d
r-1.5 e
1f
bxxxxxxxxxxxxxxxx h
#30
za
xb
bzzzzzzzz c
bzzzz d
b1010xxxxzzzz0101 h
"""

# Same-timestamp glitch: vec goes z then a settled value at the same time.
# Both backends must report only the settled (last) value per timestamp.
GLITCH_VCD = """\
$timescale 1ns $end
$scope module top $end
$var reg 8 ! bus [7:0] $end
$var reg 1 # idle $end
$upscope $end
$enddefinitions $end
#0
$dumpvars
b00000000 !
0#
$end
#10
bzzzzzzzz !
b10000000 !
#20
b00000001 !
"""

# A signal that never changes after the initial dump (zero-change tail) plus a
# normal one -- exercises the empty-signal guard.
EMPTY_SIG_VCD = """\
$timescale 1ns $end
$scope module top $end
$var reg 8 ! constant [7:0] $end
$var reg 1 # toggling $end
$upscope $end
$enddefinitions $end
#0
$dumpvars
b00000000 !
0#
$end
#10
1#
#20
0#
"""


@pytest.fixture
def slices_vcd(tmp_path):
    p = tmp_path / "slices.vcd"
    p.write_text(SLICES_VCD)
    return str(p)


@pytest.fixture
def types_vcd(tmp_path):
    p = tmp_path / "types.vcd"
    p.write_text(TYPES_VCD)
    return str(p)


@pytest.fixture
def glitch_vcd(tmp_path):
    p = tmp_path / "glitch.vcd"
    p.write_text(GLITCH_VCD)
    return str(p)


@pytest.fixture
def empty_sig_vcd(tmp_path):
    p = tmp_path / "empty_sig.vcd"
    p.write_text(EMPTY_SIG_VCD)
    return str(p)


def to_fst(vcd_path):
    """Convert a VCD to FST with vcd2fst; skip the test if unavailable/failing."""
    if not HAVE_VCD2FST:
        pytest.skip("vcd2fst (GTKWave) not on PATH")
    fst_path = vcd_path[:-4] + ".fst" if vcd_path.endswith(".vcd") else vcd_path + ".fst"
    r = subprocess.run(["vcd2fst", vcd_path, fst_path], capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(fst_path):
        pytest.skip("vcd2fst failed: {}".format(r.stderr))
    return fst_path


# ===========================================================================
# Backend activation
# ===========================================================================

def test_hybrid_backend_is_active():
    r = run(["--version"])
    assert r.returncode == 0
    assert "pywellen" in r.stdout and "hybrid" in r.stdout, r.stdout


def test_force_native_disables_backend():
    r = run(["--version"], native=True)
    assert r.returncode == 0
    assert "native pure-Python" in r.stdout
    assert "hybrid" not in r.stdout


# ===========================================================================
# Signal model parity (the model always comes from the native reader)
# ===========================================================================

@pytest.mark.parametrize("fixture", ["slices_vcd", "types_vcd"])
def test_model_matches_native(fixture, request):
    f = request.getfixturevalue(fixture)
    assert norm_list(run_json(["list", "--limit", "0"], f)) == \
           norm_list(run_json(["list", "--limit", "0"], f, native=True))


def test_info_matches_native(types_vcd):
    assert run_json(["info"], types_vcd) == run_json(["info"], types_vcd, native=True)


# ===========================================================================
# Bus slice feature -- the core reason for the hybrid model
# ===========================================================================

def test_split_bus_slices_are_distinct(slices_vcd):
    paths = {s["path"] for s in run_json(["list", "--limit", "0"], slices_vcd)["signals"]}
    assert "top.data[15:8]" in paths
    assert "top.data[7:0]" in paths


def test_split_bus_slice_values(slices_vcd):
    d = run_json(["dump", "--limit", "0"], slices_vcd)
    # at t=5 the high byte is 0xAA and the low byte is 0x55
    assert (5, "170 (0xaa)") in dump_values(d, "top.data[15:8]")
    assert (5, "85 (0x55)") in dump_values(d, "top.data[7:0]")
    # and the slices are independent at t=10 (high 0xff, low 0x00)
    assert (10, "255 (0xff)") in dump_values(d, "top.data[15:8]")
    assert (10, "0 (0x00)") in dump_values(d, "top.data[7:0]")


def test_slices_dump_matches_native(slices_vcd):
    assert norm_dump(run_json(["dump", "--limit", "0"], slices_vcd)) == \
           norm_dump(run_json(["dump", "--limit", "0"], slices_vcd, native=True))


# ===========================================================================
# IEEE 1364 value-type fidelity
# ===========================================================================

def test_value_types_match_native(types_vcd):
    assert norm_dump(run_json(["dump", "--limit", "0"], types_vcd)) == \
           norm_dump(run_json(["dump", "--limit", "0"], types_vcd, native=True))


def test_four_state_rendering(types_vcd):
    d = run_json(["dump", "--limit", "0"], types_vcd)
    # scalar x / z
    assert (20, "x") in dump_values(d, "top.sx")
    assert (20, "z") in dump_values(d, "top.sz")
    # full-width x / z vectors
    assert (20, "bxxxxxxxx") in dump_values(d, "top.vec8[7:0]")
    assert (30, "bzzzzzzzz") in dump_values(d, "top.vec8[7:0]")
    # mixed 4-state within one vector
    assert (20, "b10xz") in dump_values(d, "top.nyb[3:0]")
    # partial x/z inside a wide vector
    assert (30, "b1010xxxxzzzz0101") in dump_values(d, "top.vec16[15:0]")


def test_real_event_signed_rendering(types_vcd):
    d = run_json(["dump", "--limit", "0"], types_vcd)
    assert (10, "3.14159") in dump_values(d, "top.realv")
    assert (20, "-1.5") in dump_values(d, "top.realv")
    assert (10, "triggered") in dump_values(d, "top.ev")
    # signed -5 dumps as two's-complement bits 0xfb
    assert (10, "251 (0xfb)") in dump_values(d, "top.sgn[7:0]")


# ===========================================================================
# Same-timestamp coalescing (settled value) and empty-signal guard
# ===========================================================================

def test_same_timestamp_glitch_coalesced(glitch_vcd):
    d = run_json(["dump", "--limit", "0"], glitch_vcd)
    bus = dump_values(d, "top.bus[7:0]")
    # only the settled value (0x80) survives at t=10, not the intermediate z
    assert (10, "128 (0x80)") in bus
    assert (10, "bzzzzzzzz") not in bus
    # and it matches the native reader
    assert norm_dump(d) == norm_dump(run_json(["dump", "--limit", "0"], glitch_vcd, native=True))


def test_empty_signal_no_crash(empty_sig_vcd):
    # a never-changing signal must not crash the value bridge
    r = run(["dump", "--limit", "0"], empty_sig_vcd)
    assert r.returncode == 0, r.stderr
    assert norm_dump(run_json(["dump", "--limit", "0"], empty_sig_vcd)) == \
           norm_dump(run_json(["dump", "--limit", "0"], empty_sig_vcd, native=True))


# ===========================================================================
# Bulk vs early-stop iteration paths both work
# ===========================================================================

def test_bulk_and_limited_paths_agree(types_vcd):
    full = run_json(["dump", "--limit", "0"], types_vcd)          # collect+sort path
    limited = run_json(["dump", "--limit", "5"], types_vcd)       # lazy heap-merge path
    full_ev = norm_dump(full)
    # every limited event is a prefix subset of the full (time-ordered) set
    assert len(limited["events"]) <= 5
    limited_ev = {(e["time_ticks"], e["path"], e["value"]) for e in limited["events"]}
    assert limited_ev.issubset(set(full_ev))


# ===========================================================================
# GHW rejection
# ===========================================================================

def test_ghw_rejected_by_extension(tmp_path):
    p = tmp_path / "wave.ghw"
    p.write_bytes(b"GHDLwave\nwhatever")
    r = run(["info", str(p)])
    assert r.returncode != 0
    assert "GHW" in (r.stdout + r.stderr)
    assert "Traceback" not in (r.stdout + r.stderr)


def test_ghw_rejected_by_magic(tmp_path):
    p = tmp_path / "noext_ghw.dump"     # no .ghw extension -> must sniff magic
    p.write_bytes(b"GHDLwave\n\x00\x01\x02 body")
    r = run(["info", str(p)])
    assert r.returncode != 0
    assert "GHW" in (r.stdout + r.stderr)


# ===========================================================================
# Error handling parity (clean messages, never a traceback)
# ===========================================================================

def test_missing_file_clean_error():
    for native in (False, True):
        r = run(["info", "/no/such/file.vcd"], native=native)
        assert r.returncode != 0
        assert "Traceback" not in (r.stdout + r.stderr)


def test_truncated_fst_clean_error(types_vcd):
    fst = to_fst(types_vcd)
    trunc = fst + ".trunc.fst"
    with open(fst, "rb") as fh:
        head = fh.read(200)
    with open(trunc, "wb") as fh:
        fh.write(head)
    for native in (False, True):
        r = run(["info", trunc], native=native)
        assert "Traceback" not in (r.stdout + r.stderr)


# ===========================================================================
# VCD <-> FST consistency (needs vcd2fst)
# ===========================================================================

def test_vcd_fst_model_consistent(types_vcd):
    fst = to_fst(types_vcd)
    vcd_model = norm_list(run_json(["list", "--limit", "0"], types_vcd))
    fst_model = norm_list(run_json(["list", "--limit", "0"], fst))
    # reals are declared 1-bit in VCD but 64-bit in FST -- a format convention,
    # so compare on path/type and only the width of non-real signals.
    def key(rows):
        return {(s["path"], s["type"]): (s["width"] if s["type"] != "real" else None)
                for s in rows}
    assert key(vcd_model) == key(fst_model)


def test_vcd_fst_values_consistent(types_vcd):
    fst = to_fst(types_vcd)
    assert norm_dump(run_json(["dump", "--limit", "0"], types_vcd)) == \
           norm_dump(run_json(["dump", "--limit", "0"], fst))


def test_vcd_fst_slices_consistent(slices_vcd):
    fst = to_fst(slices_vcd)
    assert norm_dump(run_json(["dump", "--limit", "0"], slices_vcd)) == \
           norm_dump(run_json(["dump", "--limit", "0"], fst))
