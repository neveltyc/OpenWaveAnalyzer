"""Backend-equivalence tests: the pylibfst FST reader must produce output that
is byte-for-byte identical to the pure-Python (native) reader.

The whole module is skipped when pylibfst is not installed, so it never breaks
environments that rely on the native reader (e.g. Windows without pylibfst).

Strategy: for every FST fixture and a battery of commands, run the analyzer
twice as a subprocess — once with OWA_FST_FORCE_NATIVE=1 (native) and once
without (pylibfst, the default when installed) — and assert stdout matches
exactly. Running as a subprocess is what the user actually experiences and
also pins the backend cleanly via the environment variable.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

VERIFY_DIR = Path(__file__).resolve().parent
SCRIPT = VERIFY_DIR.parent / 'open_wave_analyzer.py'
WAVEFORMS_DIR = VERIFY_DIR / 'waveforms'


def _pylibfst_installed():
    try:
        import pylibfst  # noqa: F401
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _pylibfst_installed(),
    reason='pylibfst not installed; backend-equivalence test is not applicable',
)


def _fst_fixtures():
    if not WAVEFORMS_DIR.exists():
        return []
    return sorted(WAVEFORMS_DIR.glob('*.fst'))


FST_FIXTURES = _fst_fixtures()
FST_IDS = [p.stem for p in FST_FIXTURES]

# Command argument lists exercised against each fixture. Cover header, listing,
# full dump, filtered dump, summary, point query, and two-point compare, in both
# text and JSON forms (JSON is the machine contract; text exercises grouping and
# within-timestamp ordering).
COMMAND_ARGSETS = [
    ['info'],
    ['--json', 'info'],
    ['list', '--limit', '0'],
    ['--json', 'list', '--limit', '0'],
    ['dump', '--limit', '0'],
    ['--json', 'dump', '--limit', '0'],
    ['dump', '--filter', 'clk', '--limit', '0'],
    ['--json', 'dump', '--filter', 'clk', '--limit', '0'],
    ['summary'],
    ['--json', 'summary'],
    ['snapshot', '--at', '50'],
    ['--json', 'snapshot', '--at', '50'],
    ['compare', '--at', '10,50'],
    ['--json', 'compare', '--at', '10,50'],
]


def _run(args, fst, force_native):
    env = dict(os.environ)
    if force_native:
        env['OWA_FST_FORCE_NATIVE'] = '1'
    else:
        env.pop('OWA_FST_FORCE_NATIVE', None)
    cmd = [sys.executable, '-S', str(SCRIPT)] + args + [str(fst)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)


@pytest.mark.skipif(not FST_FIXTURES, reason='no FST fixtures generated')
@pytest.mark.parametrize('fst', FST_FIXTURES, ids=FST_IDS)
@pytest.mark.parametrize('args', COMMAND_ARGSETS, ids=lambda a: '_'.join(a).replace('--', ''))
def test_pylibfst_matches_native(fst, args):
    native = _run(args, fst, force_native=True)
    pylib = _run(args, fst, force_native=False)
    # Both backends must succeed identically.
    assert native.returncode == pylib.returncode, (
        f'return codes differ: native={native.returncode} pylibfst={pylib.returncode}\n'
        f'native stderr: {native.stderr[:400]}\npylibfst stderr: {pylib.stderr[:400]}'
    )
    assert native.stdout == pylib.stdout, (
        f'stdout differs for args={args} fixture={fst.name}\n'
        f'--- native ---\n{native.stdout[:1000]}\n'
        f'--- pylibfst ---\n{pylib.stdout[:1000]}'
    )


def test_backend_selection_env():
    """OWA_FST_FORCE_NATIVE must actually flip the backend class."""
    import importlib.util

    spec = importlib.util.spec_from_file_location('owa_backend_probe', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    mod.__name__ = 'owa_backend_probe'
    sys.modules['owa_backend_probe'] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop('owa_backend_probe', None)
        raise

    if not FST_FIXTURES:
        pytest.skip('no FST fixtures generated')
    fst = str(FST_FIXTURES[0])

    saved = os.environ.pop('OWA_FST_FORCE_NATIVE', None)
    try:
        # Default: pylibfst is installed (module-level skip guarantees it).
        assert mod.pylibfst_available() is True
        p = mod.wave_parser(fst)
        assert type(p).__name__ == 'PyLibFstParser'

        # Forced native.
        os.environ['OWA_FST_FORCE_NATIVE'] = '1'
        assert mod.pylibfst_available() is False
        p = mod.wave_parser(fst)
        assert type(p).__name__ == 'FSTParser'
    finally:
        os.environ.pop('OWA_FST_FORCE_NATIVE', None)
        if saved is not None:
            os.environ['OWA_FST_FORCE_NATIVE'] = saved
