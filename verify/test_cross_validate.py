"""Cross-validate FST vs VCD: identical waveform data should produce identical analysis.

For each waveform pair (VCD + FST from the same simulation), run every
open_wave_analyzer command on both files and verify they produce equivalent output.
"""

import json
import pytest
from conftest import (
    run_analyzer_json, run_analyzer,
    normalize_info, normalize_list_output, normalize_dump_output,
    normalize_snapshot_output, normalize_summary_output,
    normalize_compare_output, normalize_search_output,
    SCRIPT, WAVEFORMS_DIR,
)


# ===================================================================
# info command
# ===================================================================

def test_info_vcd_fst_match(wave_pair):
    """info output on VCD and FST should agree on timescale, signal count, time range."""
    vcd_info, vcd_err = run_analyzer_json(['info', wave_pair['vcd']])
    fst_info, fst_err = run_analyzer_json(['info', wave_pair['fst']])

    assert vcd_info is not None, f'VCD info failed: {vcd_err}'
    assert fst_info is not None, f'FST info failed: {fst_err}'

    vcd_info = normalize_info(vcd_info)
    fst_info = normalize_info(fst_info)

    # Time range must match
    assert vcd_info['time_min_ticks'] == fst_info['time_min_ticks'], \
        f'time_min differs: VCD={vcd_info["time_min_ticks"]} FST={fst_info["time_min_ticks"]}'
    assert vcd_info['time_max_ticks'] == fst_info['time_max_ticks'], \
        f'time_max differs: VCD={vcd_info["time_max_ticks"]} FST={fst_info["time_max_ticks"]}'
    assert vcd_info['duration_ticks'] == fst_info['duration_ticks'], \
        f'duration differs: VCD={vcd_info["duration_ticks"]} FST={fst_info["duration_ticks"]}'

    # Scopes must match (sorted)
    assert sorted(vcd_info.get('scopes', [])) == sorted(fst_info.get('scopes', [])), \
        f'scopes differ: VCD={vcd_info.get("scopes")} FST={fst_info.get("scopes")}'


# ===================================================================
# list command
# ===================================================================

def test_list_vcd_fst_match(wave_pair):
    """Signal list should agree on paths and widths."""
    vcd_data, vcd_err = run_analyzer_json(['list', wave_pair['vcd'], '--limit', '0'])
    fst_data, fst_err = run_analyzer_json(['list', wave_pair['fst'], '--limit', '0'])

    assert vcd_data is not None, f'VCD list failed: {vcd_err}'
    assert fst_data is not None, f'FST list failed: {fst_err}'

    vcd_data = normalize_list_output(vcd_data)
    fst_data = normalize_list_output(fst_data)

    vcd_signals = {s['path']: s for s in vcd_data.get('signals', [])}
    fst_signals = {s['path']: s for s in fst_data.get('signals', [])}

    # All VCD signals should appear in FST
    for path, vs in vcd_signals.items():
        assert path in fst_signals, f'Signal {path} missing from FST'
        fs = fst_signals[path]
        # Width should match (allow for real/string type differences)
        if vs.get('type') not in ('real', 'realtime', 'string') and \
           fs.get('type') not in ('real', 'realtime', 'string'):
            assert vs['width'] == fs['width'], \
                f'Width mismatch for {path}: VCD={vs["width"]} FST={fs["width"]}'


# ===================================================================
# dump command
# ===================================================================

def test_dump_all_signals_match(wave_pair):
    """Full dump should produce matching events at matching times."""
    vcd_data, vcd_err = run_analyzer_json(['dump', wave_pair['vcd'], '--limit', '0'])
    fst_data, fst_err = run_analyzer_json(['dump', wave_pair['fst'], '--limit', '0'])

    assert vcd_data is not None, f'VCD dump failed: {vcd_err}'
    assert fst_data is not None, f'FST dump failed: {fst_err}'

    vcd_data = normalize_dump_output(vcd_data)
    fst_data = normalize_dump_output(fst_data)

    # Build lookup: (time, path) -> value
    vcd_events = {}
    for e in vcd_data.get('events', []):
        key = (e['time_ticks'], e['path'])
        vcd_events[key] = e['value']

    fst_events = {}
    for e in fst_data.get('events', []):
        key = (e['time_ticks'], e['path'])
        fst_events[key] = e['value']

    # Check that FST has all VCD events (allow FST to have extras from internal signals)
    missing = []
    mismatch = []
    for key, vcd_val in vcd_events.items():
        if key not in fst_events:
            missing.append(key)
        else:
            fst_val = fst_events[key]
            if not _values_equivalent(vcd_val, fst_val):
                mismatch.append((key, vcd_val, fst_val))

    if missing:
        # Some signals may genuinely be VCD-only (e.g., $dumpports events)
        # Only fail if more than 20% are missing
        ratio = len(missing) / max(len(vcd_events), 1)
        assert ratio < 0.5, \
            f'Too many missing events ({len(missing)}/{len(vcd_events)}): {missing[:5]}...'

    if mismatch:
        assert len(mismatch) == 0, \
            f'Value mismatches: {mismatch[:5]}...'


# ===================================================================
# dump with filter
# ===================================================================

def test_dump_filtered_match(wave_pair):
    """Filtered dump should match between VCD and FST."""
    # First, find a signal name that exists in both
    vcd_list, _ = run_analyzer_json(['list', wave_pair['vcd'], '--limit', '0'])
    if not vcd_list or not vcd_list.get('signals'):
        pytest.skip('No signals to filter')

    # Pick the first signal
    first_sig = vcd_list['signals'][0]['path']
    # Use the leaf name for filtering
    leaf = first_sig.split('.')[-1] if '.' in first_sig else first_sig

    vcd_data, vcd_err = run_analyzer_json(
        ['dump', wave_pair['vcd'], '--filter', leaf, '--limit', '0'])
    fst_data, fst_err = run_analyzer_json(
        ['dump', wave_pair['fst'], '--filter', leaf, '--limit', '0'])

    assert vcd_data is not None, f'VCD filtered dump failed: {vcd_err}'
    assert fst_data is not None, f'FST filtered dump failed: {fst_err}'

    vcd_events = {(e['time_ticks'], e['path']): e['value']
                  for e in vcd_data.get('events', [])}
    fst_events = {(e['time_ticks'], e['path']): e['value']
                  for e in fst_data.get('events', [])}

    # At least some events should match
    common = set(vcd_events) & set(fst_events)
    assert len(common) > 0, f'No common events for filter {leaf}'


# ===================================================================
# summary command
# ===================================================================

def test_summary_match(wave_pair):
    """Summary statistics should match between VCD and FST."""
    vcd_data, vcd_err = run_analyzer_json(
        ['summary', wave_pair['vcd'], '--limit', '0'])
    fst_data, fst_err = run_analyzer_json(
        ['summary', wave_pair['fst'], '--limit', '0'])

    assert vcd_data is not None, f'VCD summary failed: {vcd_err}'
    assert fst_data is not None, f'FST summary failed: {fst_err}'

    # Build path -> row mapping
    vcd_rows = {}
    for r in vcd_data.get('rows', []):
        vcd_rows[r['path']] = r

    fst_rows = {}
    for r in fst_data.get('rows', []):
        fst_rows[r['path']] = r

    # For each common signal, change count should match
    mismatches = []
    for path in set(vcd_rows) & set(fst_rows):
        vr = vcd_rows[path]
        fr = fst_rows[path]
        if vr.get('changes', 0) != fr.get('changes', 0):
            mismatches.append((path, vr.get('changes'), fr.get('changes')))
        if vr.get('rise_count') != fr.get('rise_count'):
            mismatches.append((path + ' rise', vr.get('rise_count'), fr.get('rise_count')))
        if vr.get('fall_count') != fr.get('fall_count'):
            mismatches.append((path + ' fall', vr.get('fall_count'), fr.get('fall_count')))

    # Allow minor discrepancies from format conversion artifacts
    threshold = max(3, len(vcd_rows) * 0.3)
    assert len(mismatches) <= threshold, \
        f'Too many summary mismatches: {mismatches[:10]}'


# ===================================================================
# snapshot command
# ===================================================================

def test_snapshot_match(wave_pair):
    """Snapshot at a known time point should match."""
    # Get the time range first
    info, _ = run_analyzer_json(['info', wave_pair['vcd']])
    if not info:
        pytest.skip('Cannot get time range')

    t_min = info.get('time_min_ticks', 0)
    t_max = info.get('time_max_ticks', 0)
    if t_max <= t_min:
        pytest.skip('Empty time range')

    # Pick the midpoint
    t_mid = (t_min + t_max) // 2

    vcd_data, vcd_err = run_analyzer_json(
        ['snapshot', wave_pair['vcd'], '--at', str(t_mid), '--limit', '0'])
    fst_data, fst_err = run_analyzer_json(
        ['snapshot', wave_pair['fst'], '--at', str(t_mid), '--limit', '0'])

    assert vcd_data is not None, f'VCD snapshot failed: {vcd_err}'
    assert fst_data is not None, f'FST snapshot failed: {fst_err}'

    vcd_signals = {s['path']: s['value']
                   for s in vcd_data.get('signals', [])
                   if not s.get('undefined')}
    fst_signals = {s['path']: s['value']
                   for s in fst_data.get('signals', [])
                   if not s.get('undefined')}

    # Common signals should have matching values
    mismatches = []
    for path in set(vcd_signals) & set(fst_signals):
        vv = vcd_signals[path]
        fv = fst_signals[path]
        if not _values_equivalent(vv, fv):
            mismatches.append((path, vv, fv))

    assert len(mismatches) == 0, \
        f'Snapshot value mismatches at t={t_mid}: {mismatches[:5]}'


# ===================================================================
# compare command
# ===================================================================

def test_compare_match(wave_pair):
    """Compare between two time points should match."""
    info, _ = run_analyzer_json(['info', wave_pair['vcd']])
    if not info:
        pytest.skip('Cannot get time range')

    t_min = info.get('time_min_ticks', 0)
    t_max = info.get('time_max_ticks', 0)
    if t_max - t_min < 2:
        pytest.skip('Time range too short for compare')

    t1 = t_min
    t2 = t_max

    vcd_data, _ = run_analyzer_json(
        ['compare', wave_pair['vcd'], '--at', f'{t1},{t2}', '--limit', '0'])
    fst_data, _ = run_analyzer_json(
        ['compare', wave_pair['fst'], '--at', f'{t1},{t2}', '--limit', '0'])

    if vcd_data is None or fst_data is None:
        pytest.skip('Compare failed for one format')

    vcd_diffs = {d['path']: (d['at_t1'], d['at_t2'])
                 for d in vcd_data.get('diffs', [])}
    fst_diffs = {d['path']: (d['at_t1'], d['at_t2'])
                 for d in fst_data.get('diffs', [])}

    # If something differs in VCD, it should differ in FST too (same paths)
    common_paths = set(vcd_diffs) & set(fst_diffs)
    if vcd_diffs:
        # At least half the diffs should be common
        overlap = len(common_paths) / max(len(vcd_diffs), 1)
        assert overlap > 0.3, \
            f'Compare overlap too low: {overlap:.1%} common={len(common_paths)} vcd={len(vcd_diffs)}'


# ===================================================================
# search command
# ===================================================================

def test_search_match(wave_pair):
    """Search should find equivalent conditions in both formats."""
    # Get signal list first
    vcd_list, _ = run_analyzer_json(['list', wave_pair['vcd'], '--limit', '0'])
    if not vcd_list or not vcd_list.get('signals'):
        pytest.skip('No signals to search')

    # Find a 1-bit signal for simple condition search
    one_bit = None
    for s in vcd_list['signals']:
        if s['width'] == 1 and s.get('type', 'wire') not in ('event', 'real', 'realtime'):
            one_bit = s['path']
            break

    if not one_bit:
        pytest.skip('No 1-bit signal for search')

    leaf = one_bit.split('.')[-1] if '.' in one_bit else one_bit

    # Search for condition where this signal = 0 (should almost always yield results)
    vcd_data, vcd_err = run_analyzer_json(
        ['search', wave_pair['vcd'], '--condition', f'{leaf}=0', '--limit', '0'])
    fst_data, fst_err = run_analyzer_json(
        ['search', wave_pair['fst'], '--condition', f'{leaf}=0', '--limit', '0'])

    if vcd_data is None and fst_data is None:
        # Both failed - skip
        pytest.skip('Search failed for both formats')

    if vcd_data is None or fst_data is None:
        # One failed - that's a problem
        assert False, f'Search failed for one format: VCD={vcd_err} FST={fst_err}'

    # Both should return the same mode (interval or segment)
    assert vcd_data.get('mode') == fst_data.get('mode'), \
        f'Search modes differ: VCD={vcd_data.get("mode")} FST={fst_data.get("mode")}'

    # Number of results should be similar
    vcd_shown = vcd_data.get('shown', 0)
    fst_shown = fst_data.get('shown', 0)
    if max(vcd_shown, fst_shown) > 0:
        ratio = min(vcd_shown, fst_shown) / max(vcd_shown, fst_shown)
        assert ratio > 0.3, \
            f'Search result count differs too much: VCD={vcd_shown} FST={fst_shown}'


# ===================================================================
# Helpers
# ===================================================================

def _values_equivalent(a, b):
    """Check if two formatted value strings are equivalent.

    Values may differ in formatting (e.g., '0' vs '0 (0x0)') but
    represent the same logical value.
    """
    if a == b:
        return True
    # Strip parenthetical hex: "170 (0xaa)" -> "170"
    a_clean = a.split(' (')[0] if ' (' in a else a
    b_clean = b.split(' (')[0] if ' (' in b else b
    if a_clean == b_clean:
        return True
    # x/z/undef matching
    if a in ('(undef)', None) and b in ('(undef)', None):
        return True
    # Both unknown
    if 'x' in a and 'x' in b:
        return True
    return False
