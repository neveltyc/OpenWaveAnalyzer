"""White-box correctness tests for the FST filtered-scan optimization.

The filtered query path uses ``_FstReader._scan_chain_entries`` to extract only
the requested handles' chain-table entries instead of parsing the whole 223K-
entry table. That sparse scan re-implements part of ``_parse_chain_table``'s
varint-stream decode, so the two can silently drift apart on a future change.

``test_scan_chain_parity`` is the safety net: for every FST fixture, every
section, and a battery of handle subsets, it asserts the sparse scan returns
*exactly* what the full parse produced. If the two ever diverge — including the
alias / fallback edge cases — these tests fail loudly.

These tests import open_wave_analyzer.py directly (white-box) rather than shelling
out, so they can reach the private reader internals.
"""

import importlib.util
import random
from pathlib import Path

import pytest

VERIFY_DIR = Path(__file__).resolve().parent
SCRIPT = VERIFY_DIR.parent / 'open_wave_analyzer.py'
WAVEFORMS_DIR = VERIFY_DIR / 'waveforms'


# ---------------------------------------------------------------------------
# Module loading / fixture discovery
# ---------------------------------------------------------------------------

_wa_module = None


def _load_wa():
    """Import open_wave_analyzer.py as a module (cached)."""
    global _wa_module
    if _wa_module is None:
        spec = importlib.util.spec_from_file_location('wave_analyzer_under_test', SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        mod.__name__ = 'wave_analyzer_under_test'
        spec.loader.exec_module(mod)
        _wa_module = mod
    return _wa_module


def _fst_fixtures():
    """All .fst fixtures in the waveforms directory."""
    if not WAVEFORMS_DIR.exists():
        return []
    return sorted(p for p in WAVEFORMS_DIR.glob('*.fst'))


FST_FIXTURES = _fst_fixtures()
FST_IDS = [p.stem for p in FST_FIXTURES]


@pytest.fixture(scope='module')
def wa():
    return _load_wa()


def _full_chain(reader, sect_idx):
    """Force a full parse of one section and return (chain_table, lengths)."""
    reader._ensure_section_parsed(sect_idx)
    s = reader._vc_sections[sect_idx]
    return s.chain_table, s.chain_table_lengths


def _expected_entry(ct, ctl, handle):
    """What _scan_chain_entries should return for a handle (1-based), or None."""
    idx = handle - 1
    if 0 <= idx < len(ct):
        off, length = ct[idx], ctl[idx]
        if off > 0 and length > 0:
            return (off, length)
    return None


def _reset_section(sect, payload):
    """Restore a section to its unparsed state so the sparse path runs again."""
    sect._parsed = False
    sect._payload = payload
    sect.chain_table = None
    sect.chain_table_lengths = None
    sect.times = None


# ===================================================================
# Exhaustive scan-vs-full-parse parity (the maintenance safety net)
# ===================================================================

@pytest.mark.parametrize('fst_path', FST_FIXTURES, ids=FST_IDS)
def test_scan_chain_parity_every_handle(wa, fst_path):
    """For every section, scanning ALL handles must equal the full chain table.

    This is the strongest possible cross-check: it walks each section once via
    the sparse scanner asking for every handle, and compares entry-by-entry to
    the full parse. Any decode-logic drift between the two surfaces here.
    """
    truth = wa.FSTParser(str(fst_path))
    scan_fp = wa.FSTParser(str(fst_path))

    for sidx in range(len(truth._reader._vc_sections)):
        ct, ctl = _full_chain(truth._reader, sidx)
        n_handles = len(ct)
        if n_handles == 0:
            continue
        all_handles = list(range(1, n_handles + 1))

        sect = scan_fp._reader._vc_sections[sidx]
        payload = sect._payload
        _reset_section(sect, payload)
        scanned = scan_fp._reader._scan_chain_entries(sidx, all_handles)

        for h in all_handles:
            exp = _expected_entry(ct, ctl, h)
            got = scanned.get(h)
            assert got == exp, (
                f'{fst_path.stem} sect{sidx} handle{h}: scan={got} expected={exp}')


@pytest.mark.parametrize('fst_path', FST_FIXTURES, ids=FST_IDS)
def test_scan_chain_parity_random_subsets(wa, fst_path):
    """Random handle subsets of varied sizes must match the full table.

    Exercises the sparse path's early-stop and fallback logic on many different
    subset shapes (singletons, small clusters, large spreads).
    """
    truth = wa.FSTParser(str(fst_path))
    scan_fp = wa.FSTParser(str(fst_path))
    rng = random.Random(1234)

    for sidx in range(len(truth._reader._vc_sections)):
        ct, ctl = _full_chain(truth._reader, sidx)
        n = len(ct)
        if n == 0:
            continue
        sect = scan_fp._reader._vc_sections[sidx]
        payload = sect._payload

        for _ in range(15):
            k = rng.choice([1, 1, 2, 3, 8, 32, max(1, n // 4), n])
            k = min(k, n)
            subset = sorted(rng.sample(range(1, n + 1), k))
            _reset_section(sect, payload)
            scanned = scan_fp._reader._scan_chain_entries(sidx, subset)
            for h in subset:
                exp = _expected_entry(ct, ctl, h)
                got = scanned.get(h)
                assert got == exp, (
                    f'{fst_path.stem} sect{sidx} subset(k={k}) handle{h}: '
                    f'scan={got} expected={exp}')


@pytest.mark.parametrize('fst_path', FST_FIXTURES, ids=FST_IDS)
def test_scan_handles_with_data_individually(wa, fst_path):
    """Each handle that has real data, scanned alone, must resolve correctly.

    Scanning a single handle is the most fallback-prone case (an aliased handle
    asked for in isolation can't resolve its target and must fall back).
    """
    truth = wa.FSTParser(str(fst_path))
    scan_fp = wa.FSTParser(str(fst_path))

    for sidx in range(len(truth._reader._vc_sections)):
        ct, ctl = _full_chain(truth._reader, sidx)
        n = len(ct)
        if n == 0:
            continue
        data_handles = [i + 1 for i in range(n) if ct[i] > 0 and ctl[i] > 0]
        # Cap to keep runtime reasonable on huge fixtures.
        sample = data_handles[:200]
        sect = scan_fp._reader._vc_sections[sidx]
        payload = sect._payload
        for h in sample:
            _reset_section(sect, payload)
            scanned = scan_fp._reader._scan_chain_entries(sidx, [h])
            exp = _expected_entry(ct, ctl, h)
            assert scanned.get(h) == exp, (
                f'{fst_path.stem} sect{sidx} solo handle{h}: '
                f'scan={scanned.get(h)} expected={exp}')


# ===================================================================
# Edge cases for the sparse scanner
# ===================================================================

@pytest.mark.parametrize('fst_path', FST_FIXTURES, ids=FST_IDS)
def test_scan_empty_request(wa, fst_path):
    """Scanning an empty handle list returns an empty dict, no crash."""
    fp = wa.FSTParser(str(fst_path))
    for sidx in range(len(fp._reader._vc_sections)):
        assert fp._reader._scan_chain_entries(sidx, []) == {}


@pytest.mark.parametrize('fst_path', FST_FIXTURES, ids=FST_IDS)
def test_scan_out_of_range_handles(wa, fst_path):
    """Handles past the chain table return nothing (handled as no-data)."""
    truth = wa.FSTParser(str(fst_path))
    scan_fp = wa.FSTParser(str(fst_path))
    for sidx in range(len(truth._reader._vc_sections)):
        ct, _ = _full_chain(truth._reader, sidx)
        n = len(ct)
        bogus = [n + 1, n + 100, n + 9999]
        sect = scan_fp._reader._vc_sections[sidx]
        _reset_section(sect, sect._payload)
        scanned = scan_fp._reader._scan_chain_entries(sidx, bogus)
        for h in bogus:
            assert h not in scanned, f'{fst_path.stem}: out-of-range handle {h} returned data'


@pytest.mark.parametrize('fst_path', FST_FIXTURES, ids=FST_IDS)
def test_scan_idempotent_after_fallback(wa, fst_path):
    """A scan that falls back to full parse marks the section parsed, and a
    repeat scan via the fast path returns identical results."""
    truth = wa.FSTParser(str(fst_path))
    scan_fp = wa.FSTParser(str(fst_path))
    for sidx in range(len(truth._reader._vc_sections)):
        ct, ctl = _full_chain(truth._reader, sidx)
        n = len(ct)
        if n == 0:
            continue
        data_handles = [i + 1 for i in range(n) if ct[i] > 0 and ctl[i] > 0][:50]
        if not data_handles:
            continue
        sect = scan_fp._reader._vc_sections[sidx]
        _reset_section(sect, sect._payload)
        first = scan_fp._reader._scan_chain_entries(sidx, data_handles)
        # Second call (section may now be parsed) must agree.
        second = scan_fp._reader._scan_chain_entries(sidx, data_handles)
        assert first == second, f'{fst_path.stem} sect{sidx}: scan not idempotent'
        for h in data_handles:
            assert first.get(h) == _expected_entry(ct, ctl, h)


# ===================================================================
# End-to-end: filtered iter_events == full-parse ground truth
# ===================================================================

def _full_parse_events(fp, sids):
    """Ground-truth events for sids via the all-signal path, filtered to sids.

    iter_time_value_pairs is the canonical full-file event stream (it is what an
    unfiltered dump uses and what cross-validates against VCD). The filtered
    iter_events(sids) path must reproduce exactly this stream restricted to the
    selected handles — including each section's beg_time initial sample.
    """
    fp._reader._ensure_all_sections_parsed()
    sid_set = set(sids)
    events = []
    for sidx in range(len(fp._reader._vc_sections)):
        for t, changes in fp._reader.iter_time_value_pairs(sidx):
            for h, raw in changes:
                if h in sid_set:
                    events.append((t, h, fp._format_raw_value(h, raw)))
    return sorted(events)


def _filter_patterns_for(fp):
    """Build a handful of filter patterns that match real signals."""
    # Take a few signal leaf-names from the design.
    leaves = []
    for info in fp.signals.values():
        path = info['path']
        leaf = path.rsplit('.', 1)[-1]
        # strip bus subscript
        leaf = leaf.split('[')[0]
        if leaf and leaf not in leaves:
            leaves.append(leaf)
        if len(leaves) >= 6:
            break
    pats = list(leaves)
    if leaves:
        pats.append(leaves[0][:2] + '*')  # a glob
        pats.append(','.join(leaves[:2]))  # multi-pattern
    return pats


@pytest.mark.parametrize('fst_path', FST_FIXTURES, ids=FST_IDS)
def test_filtered_events_equal_full_parse(wa, fst_path):
    """iter_events(sids) (sparse scan path) must equal the full-parse events."""
    for pat in _filter_patterns_for(wa.FSTParser(str(fst_path))):
        scan_fp = wa.FSTParser(str(fst_path))
        sids = scan_fp.match([pat])
        if not sids:
            continue
        scan_events = sorted(scan_fp.iter_events(0, None, sids))

        truth_fp = wa.FSTParser(str(fst_path))
        truth_fp.match([pat])
        truth_events = _full_parse_events(truth_fp, sids)

        assert scan_events == truth_events, (
            f'{fst_path.stem} filter={pat!r}: '
            f'scan={len(scan_events)} events, full={len(truth_events)} events')


@pytest.mark.parametrize('fst_path', FST_FIXTURES, ids=FST_IDS)
def test_filtered_all_signals_equal_full(wa, fst_path):
    """Selecting *every* signal via the filtered path still matches full parse.

    With all handles selected, aliases resolve within the set, so fallback
    should mostly not trigger — this stresses the sparse alias resolution.
    """
    scan_fp = wa.FSTParser(str(fst_path))
    sids = set(scan_fp.signals.keys())
    if not sids:
        pytest.skip('no signals')
    scan_events = sorted(scan_fp.iter_events(0, None, sids))

    truth_fp = wa.FSTParser(str(fst_path))
    truth_events = _full_parse_events(truth_fp, sids)
    assert scan_events == truth_events, (
        f'{fst_path.stem}: all-signal scan={len(scan_events)} '
        f'full={len(truth_events)}')
