"""Generate VCD and FST waveform pairs from all available Verilog designs.

Uses iverilog/vvp for compilation and simulation, vcd2fst for FST conversion.
Output goes to verify/waveforms/ as <design>.vcd and <design>.fst pairs.
"""

import os
import subprocess
import shutil
import sys
from pathlib import Path

VERIFY_DIR = Path(__file__).resolve().parent
WAVEFORMS_DIR = VERIFY_DIR / 'waveforms'
BUILD_DIR = VERIFY_DIR / 'build'
FIXTURES_DIR = VERIFY_DIR / 'fixtures'

# Tool paths
IVERILOG = shutil.which('iverilog') or 'iverilog'
VVP = shutil.which('vvp') or 'vvp'
VCD2FST = shutil.which('vcd2fst') or 'vcd2fst'


def run(cmd, cwd=None, timeout=60):
    """Run a command, return (success, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, timeout=timeout
        )
        return r.returncode == 0, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return False, '', 'timeout'
    except FileNotFoundError:
        return False, '', f'command not found: {cmd[0]}'


def build_design(v_file, design_name):
    """Compile a Verilog design and run simulation to produce VCD."""
    v_path = Path(v_file)
    if not v_path.exists():
        print(f'  SKIP {design_name}: file not found ({v_path})')
        return None

    vvp_path = BUILD_DIR / f'{design_name}.vvp'
    vcd_path = WAVEFORMS_DIR / f'{design_name}.vcd'
    fst_path = WAVEFORMS_DIR / f'{design_name}.fst'

    # Compile
    ok, out, err = run([IVERILOG, '-o', str(vvp_path), str(v_path)], cwd=BUILD_DIR)
    if not ok:
        print(f'  FAIL {design_name}: iverilog compile error')
        if err:
            print(f'    {err.strip()[:200]}')
        return None

    # Simulate - vvp writes VCD to the filename specified in $dumpfile
    # The testbenches use $dumpfile("name.vcd"), so we run in BUILD_DIR
    ok, out, err = run([VVP, str(vvp_path.name)], cwd=BUILD_DIR)
    if not ok:
        print(f'  FAIL {design_name}: vvp simulation error')
        return None

    # Find the VCD file that vvp produced (in BUILD_DIR)
    vcd_files = list(BUILD_DIR.glob('*.vcd'))
    if not vcd_files:
        print(f'  FAIL {design_name}: no VCD produced')
        return None

    # Move the VCD to waveforms dir
    produced_vcd = vcd_files[0]
    shutil.move(str(produced_vcd), str(vcd_path))

    # Convert VCD to FST
    ok, out, err = run([VCD2FST, str(vcd_path), str(fst_path)])
    if not ok:
        print(f'  FAIL {design_name}: vcd2fst conversion error')
        if err:
            print(f'    {err.strip()[:200]}')
        return None

    return {'vcd': vcd_path, 'fst': fst_path, 'name': design_name}


def copy_vcd_fixtures():
    """Copy existing VCD fixtures from VCD_ANALYZER/verify/fixtures/ and convert to FST."""
    vcd_fixtures = VERIFY_DIR.parent / 'VCD_ANALYZER' / 'verify' / 'fixtures'
    results = []
    for vcd_file in sorted(vcd_fixtures.glob('*.vcd')):
        name = vcd_file.stem
        dest_vcd = WAVEFORMS_DIR / f'{name}.vcd'
        dest_fst = WAVEFORMS_DIR / f'{name}.fst'

        shutil.copy2(str(vcd_file), str(dest_vcd))

        # Convert to FST
        ok, out, err = run([VCD2FST, str(dest_vcd), str(dest_fst)])
        if ok:
            print(f'  OK {name} (existing VCD fixture)')
            results.append({'vcd': dest_vcd, 'fst': dest_fst, 'name': name})
        else:
            print(f'  FAIL {name}: vcd2fst conversion - {err.strip()[:200]}')
    return results


def main():
    os.makedirs(WAVEFORMS_DIR, exist_ok=True)
    os.makedirs(BUILD_DIR, exist_ok=True)

    print('=== Building Verilog designs and generating waveforms ===')
    print()

    results = []

    # ---- Our custom designs ----
    designs_dir = VERIFY_DIR / 'designs'
    print('-- Custom designs --')
    for vf in sorted(designs_dir.glob('*.v')):
        name = vf.stem
        r = build_design(str(vf), name)
        if r:
            print(f'  OK {name}')
            results.append(r)

    # ---- PurePyFstlib designs ----
    fstlib_designs = VERIFY_DIR.parent / 'PurePyFstlib' / 'verify' / 'fixtures'
    print()
    print('-- PurePyFstlib designs --')
    for vf in sorted(fstlib_designs.glob('*.v')):
        name = f'fstlib_{vf.stem}'
        # Adjust the $dumpfile path in the design to use a predictable name
        content = vf.read_text()
        content = content.replace('$dumpfile("', f'$dumpfile("{vf.stem}')
        adjusted = BUILD_DIR / f'{name}.v'
        adjusted.write_text(content)
        r = build_design(str(adjusted), name)
        if r:
            print(f'  OK {name}')
            results.append(r)

    # ---- Existing VCD fixtures ----
    print()
    print('-- Existing VCD fixtures --')
    fixture_results = copy_vcd_fixtures()
    results.extend(fixture_results)

    print()
    print(f'=== Generated {len(results)} waveform pairs ===')

    # Write manifest
    manifest = []
    for r in results:
        manifest.append({
            'name': r['name'],
            'vcd': str(r['vcd']),
            'fst': str(r['fst']),
        })
    import json
    manifest_path = WAVEFORMS_DIR / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f'Manifest written to {manifest_path}')


if __name__ == '__main__':
    main()
