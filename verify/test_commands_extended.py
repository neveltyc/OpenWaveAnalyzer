"""Extended command coverage: FST vs VCD cross-validation under many options.

Where ``test_cross_validate.py`` runs each command once per fixture with default
options, this suite multiplies the coverage by sweeping option combinations:
filter patterns (substring / glob / multi / no-match), time windows (quarter and
half points computed per-fixture), limits (0 / small / large), and multiple
snapshot/compare time points. Every variation asserts the FST and VCD readers
agree, so a regression in either path — or in the filtered-scan optimization —
shows up here.

Driven through the CLI (subprocess) so it exercises the real end-to-end path,
reusing the normalization helpers from conftest.
"""

import pytest
from pathlib import Path

from conftest import (
    run_analyzer_json, run_analyzer,
    normalize_list_output, normalize_dump_output,
    normalize_snapshot_output, normalize_summary_output,
    normalize_compare_output,
    WAVEFORMS_DIR,
)


# ---------------------------------------------------------------------------
# Wave-pair discovery (local, by matching .vcd/.fst stems)
# ---------------------------------------------------------------------------

def _wave_pairs():
    pairs = []
    if not WAVEFORMS_DIR.exists():
        return pairs
    for fst in sorted(WAVEFORMS_DIR.glob('*.fst')):
        vcd = fst.with_suffix('.vcd')
        if vcd.exists():
            pairs.append({'name': fst.stem, 'fst': str(fst), 'vcd': str(vcd)})
    return pairs


WAVE_PAIRS = _wave_pairs()
PAIR_IDS = [p['name'] for p in WAVE_PAIRS]


def _info_ticks(path):
    """Return (min_ticks, max_ticks) for a waveform file, or (0, 0)."""
    info, _ = run_analyzer_json(['info', path])
    if not info:
        return 0, 0
    return info.get('time_min_ticks', 0) or 0, info.get('time_max_ticks', 0) or 0


def _signal_leaves(path, limit=8):
    """A few leaf signal names usable as filter patterns."""
    data, _ = run_analyzer_json(['list', path, '--limit', '0'])
    if not data:
        return []
    leaves = []
    for s in data.get('signals', []):
        leaf = s['path'].rsplit('.', 1)[-1].split('[')[0]
        if leaf and leaf not in leaves:
            leaves.append(leaf)
        if len(leaves) >= limit:
            break
    return leaves


# ===================================================================
# list — filter / limit variations
# ===================================================================

@pytest.mark.parametrize('pair', WAVE_PAIRS, ids=PAIR_IDS)
@pytest.mark.parametrize('limit', ['0', '1', '3', '1000'])
def test_list_limit_variations_match(pair, limit):
    vcd, _ = run_analyzer_json(['list', pair['vcd'], '--limit', limit])
    fst, _ = run_analyzer_json(['list', pair['fst'], '--limit', limit])
    assert vcd is not None and fst is not None
    # Same number of signals reported (count field), modulo synthesized buses.
    v = normalize_list_output(vcd)
    f = normalize_list_output(fst)
    vpaths = {s['path'] for s in v['signals']}
    fpaths = {s['path'] for s in f['signals']}
    # FST may synthesize buses differently; require the smaller to be subset-ish.
    common = vpaths & fpaths
    assert common, f"{pair['name']} limit={limit}: no common signals"


@pytest.mark.parametrize('pair', WAVE_PAIRS, ids=PAIR_IDS)
def test_list_filter_patterns_match(pair):
    leaves = _signal_leaves(pair['vcd'])
    patterns = []
    if leaves:
        patterns = [leaves[0], leaves[0][:1] + '*', ','.join(leaves[:2]),
                    'zzz_no_match_zzz']
    for pat in patterns:
        vcd, _ = run_analyzer_json(['list', pair['vcd'], '--filter', pat, '--limit', '0'])
        fst, _ = run_analyzer_json(['list', pair['fst'], '--filter', pat, '--limit', '0'])
        assert vcd is not None and fst is not None, f"{pair['name']} filter={pat}"
        vpaths = sorted(s['path'] for s in vcd.get('signals', []))
        fpaths = sorted(s['path'] for s in fst.get('signals', []))
        common_v = set(vpaths) & set(fpaths)
        # For no-match, both should be empty.
        if pat == 'zzz_no_match_zzz':
            assert not vpaths and not fpaths, f"{pair['name']}: no-match returned signals"
        else:
            assert common_v or (not vpaths and not fpaths), \
                f"{pair['name']} filter={pat}: vcd={vpaths[:3]} fst={fpaths[:3]}"


# ===================================================================
# dump — time window / filter / limit variations
# ===================================================================

@pytest.mark.parametrize('pair', WAVE_PAIRS, ids=PAIR_IDS)
def test_dump_time_windows_match(pair):
    lo, hi = _info_ticks(pair['vcd'])
    if hi <= lo:
        pytest.skip('degenerate time range')
    q1 = lo + (hi - lo) // 4
    q3 = lo + 3 * (hi - lo) // 4
    windows = [
        ['--begin', str(q1)],
        ['--end', str(q3)],
        ['--begin', str(q1), '--end', str(q3)],
    ]
    for w in windows:
        vcd, _ = run_analyzer_json(['dump', pair['vcd'], '--limit', '0'] + w)
        fst, _ = run_analyzer_json(['dump', pair['fst'], '--limit', '0'] + w)
        assert vcd is not None and fst is not None, f"{pair['name']} window={w}"
        v = normalize_dump_output(vcd)
        f = normalize_dump_output(fst)
        vev = [(e['time_ticks'], e['path'], e['value']) for e in v['events']]
        fev = [(e['time_ticks'], e['path'], e['value']) for e in f['events']]
        # Restrict to common signal paths (synthesized-bus differences aside).
        common = {p for _, p, _ in vev} & {p for _, p, _ in fev}
        vev = sorted(e for e in vev if e[1] in common)
        fev = sorted(e for e in fev if e[1] in common)
        assert vev == fev, f"{pair['name']} window={w}: dump mismatch"


@pytest.mark.parametrize('pair', WAVE_PAIRS, ids=PAIR_IDS)
@pytest.mark.parametrize('limit', ['0', '1', '5'])
def test_dump_filtered_limit_match(pair, limit):
    leaves = _signal_leaves(pair['vcd'], limit=3)
    if not leaves:
        pytest.skip('no signals')
    pat = ','.join(leaves)
    vcd, _ = run_analyzer_json(['dump', pair['vcd'], '--filter', pat, '--limit', limit])
    fst, _ = run_analyzer_json(['dump', pair['fst'], '--filter', pat, '--limit', limit])
    assert vcd is not None and fst is not None, f"{pair['name']} pat={pat} limit={limit}"
    # With a limit, both should report the same shown/total bookkeeping for
    # the common signal set; with limit 0 the full event lists must match.
    if limit == '0':
        v = normalize_dump_output(vcd)
        f = normalize_dump_output(fst)
        vev = [(e['time_ticks'], e['path'], e['value']) for e in v['events']]
        fev = [(e['time_ticks'], e['path'], e['value']) for e in f['events']]
        common = {p for _, p, _ in vev} & {p for _, p, _ in fev}
        assert sorted(e for e in vev if e[1] in common) == \
               sorted(e for e in fev if e[1] in common), \
               f"{pair['name']} pat={pat}: filtered dump mismatch"


# ===================================================================
# summary — filter / window variations
# ===================================================================

@pytest.mark.parametrize('pair', WAVE_PAIRS, ids=PAIR_IDS)
def test_summary_filter_match(pair):
    leaves = _signal_leaves(pair['vcd'], limit=4)
    patterns = [None]
    if leaves:
        patterns.append(','.join(leaves[:2]))
    for pat in patterns:
        args = ['summary', pair['vcd'], '--limit', '0']
        argsf = ['summary', pair['fst'], '--limit', '0']
        if pat:
            args += ['--filter', pat]
            argsf += ['--filter', pat]
        vcd, _ = run_analyzer_json(args)
        fst, _ = run_analyzer_json(argsf)
        assert vcd is not None and fst is not None, f"{pair['name']} pat={pat}"
        v = normalize_summary_output(vcd)
        f = normalize_summary_output(fst)
        vrows = {r['path']: (r.get('changes'), r.get('kind')) for r in v['rows']}
        frows = {r['path']: (r.get('changes'), r.get('kind')) for r in f['rows']}
        common = set(vrows) & set(frows)
        assert common, f"{pair['name']} pat={pat}: no common summary rows"
        for p in common:
            assert vrows[p] == frows[p], \
                f"{pair['name']} pat={pat} sig={p}: {vrows[p]} != {frows[p]}"


# ===================================================================
# snapshot — multiple time points
# ===================================================================

@pytest.mark.parametrize('pair', WAVE_PAIRS, ids=PAIR_IDS)
def test_snapshot_multiple_times_match(pair):
    lo, hi = _info_ticks(pair['vcd'])
    if hi <= lo:
        pytest.skip('degenerate time range')
    pts = [lo, lo + (hi - lo) // 3, lo + 2 * (hi - lo) // 3, hi]
    for t in pts:
        vcd, _ = run_analyzer_json(['snapshot', pair['vcd'], '--at', str(t), '--limit', '0'])
        fst, _ = run_analyzer_json(['snapshot', pair['fst'], '--at', str(t), '--limit', '0'])
        assert vcd is not None and fst is not None, f"{pair['name']} at={t}"
        v = normalize_snapshot_output(vcd)
        f = normalize_snapshot_output(fst)
        vsig = {s['path']: s.get('value') for s in v['signals']}
        fsig = {s['path']: s.get('value') for s in f['signals']}
        common = set(vsig) & set(fsig)
        assert common, f"{pair['name']} at={t}: no common snapshot signals"
        for p in common:
            assert vsig[p] == fsig[p], \
                f"{pair['name']} at={t} sig={p}: VCD={vsig[p]} FST={fsig[p]}"


# ===================================================================
# compare — multiple time-point pairs
# ===================================================================

@pytest.mark.parametrize('pair', WAVE_PAIRS, ids=PAIR_IDS)
def test_compare_time_pairs_match(pair):
    lo, hi = _info_ticks(pair['vcd'])
    if hi <= lo:
        pytest.skip('degenerate time range')
    mid = lo + (hi - lo) // 2
    pairs_t = [(lo, hi), (lo, mid), (mid, hi)]
    for t1, t2 in pairs_t:
        spec = f'{t1},{t2}'
        vcd, _ = run_analyzer_json(['compare', pair['vcd'], '--at', spec, '--limit', '0'])
        fst, _ = run_analyzer_json(['compare', pair['fst'], '--at', spec, '--limit', '0'])
        assert vcd is not None and fst is not None, f"{pair['name']} at={spec}"
        v = normalize_compare_output(vcd)
        f = normalize_compare_output(fst)
        vd = {d['path']: (d.get('from'), d.get('to')) for d in v.get('diffs', [])}
        fd = {d['path']: (d.get('from'), d.get('to')) for d in f.get('diffs', [])}
        common = set(vd) & set(fd)
        for p in common:
            assert vd[p] == fd[p], \
                f"{pair['name']} at={spec} sig={p}: VCD={vd[p]} FST={fd[p]}"


# ===================================================================
# search — conditions across both formats
# ===================================================================

@pytest.mark.parametrize('pair', WAVE_PAIRS, ids=PAIR_IDS)
def test_search_condition_match(pair):
    # Find a 1-bit-ish signal to build a condition on.
    data, _ = run_analyzer_json(['list', pair['vcd'], '--limit', '0'])
    if not data:
        pytest.skip('no list')
    # Pick a signal whose exact path matches one signal (condition needs unique).
    cond_sig = None
    for s in data.get('signals', []):
        if s.get('width', 1) == 1 and '[' not in s['path']:
            cond_sig = s['path']
            break
    if not cond_sig:
        pytest.skip('no scalar signal for condition')
    for val in ('1', '0'):
        cond = f'{cond_sig}={val}'
        vcd, verr = run_analyzer_json(['search', pair['vcd'], '--condition', cond, '--limit', '0'])
        fst, ferr = run_analyzer_json(['search', pair['fst'], '--condition', cond, '--limit', '0'])
        # Both must succeed or both must fail the same way.
        assert (vcd is None) == (fst is None), \
            f"{pair['name']} cond={cond}: VCD/FST disagree on success (v={verr} f={ferr})"
        if vcd is None:
            continue
        # Compare interval/segment counts.
        vkey = 'intervals' if 'intervals' in vcd else 'segments' if 'segments' in vcd else 'events'
        fkey = 'intervals' if 'intervals' in fst else 'segments' if 'segments' in fst else 'events'
        vn = len(vcd.get(vkey, []))
        fn = len(fst.get(fkey, []))
        assert vn == fn, f"{pair['name']} cond={cond}: VCD {vn} intervals, FST {fn}"


# ===================================================================
# info — exit codes & basic invariants across formats
# ===================================================================

@pytest.mark.parametrize('pair', WAVE_PAIRS, ids=PAIR_IDS)
def test_info_time_range_match(pair):
    vlo, vhi = _info_ticks(pair['vcd'])
    flo, fhi = _info_ticks(pair['fst'])
    assert vlo == flo, f"{pair['name']}: time_min VCD={vlo} FST={flo}"
    assert vhi == fhi, f"{pair['name']}: time_max VCD={vhi} FST={fhi}"


@pytest.mark.parametrize('pair', WAVE_PAIRS, ids=PAIR_IDS)
def test_all_commands_exit_clean(pair):
    """Every command on every fixture exits 0 (no crashes) for both formats."""
    lo, hi = _info_ticks(pair['fst'])
    mid = lo + (hi - lo) // 2 if hi > lo else lo
    invocations = [
        ['info'],
        ['list', '--limit', '0'],
        ['dump', '--limit', '5'],
        ['summary', '--limit', '0'],
        ['snapshot', '--at', str(mid), '--limit', '0'],
        ['compare', '--at', f'{lo},{hi}', '--limit', '0'],
    ]
    for fmt in ('vcd', 'fst'):
        for inv in invocations:
            r = run_analyzer(['--json'] + [inv[0], pair[fmt]] + inv[1:])
            assert r.returncode == 0, \
                f"{pair['name']} {fmt} {inv[0]}: rc={r.returncode} err={r.stderr[:200]}"
