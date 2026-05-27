#!/usr/bin/env python3
"""Assemble modules/ into a single-file open_wave_analyzer.py for release.

Usage:
    python _make.py          # build open_wave_analyzer.py
    python _make.py --check  # verify open_wave_analyzer.py matches modules/

The module order matches the Part numbering in the assembled file:
    _preamble.py   shebang, docstring, imports, version
    fst_types.py   Part 1:   FST Common Types
    fst_codec.py   Part 2-3: FST Varint + Compression
    fst_reader.py  Part 4:   FST Reader  (syncs with PurePyFstlib upstream)
    vcd_utils.py   Part 5:   VCD Utilities
    vcd_parser.py  Part 6:   VCD Parser  (syncs with VCD_ANALYZER upstream)
    fst_adapter.py Part 7:   FST Parser Adapter
    cli.py         Part 8:   Commands + CLI
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULES_DIR = HERE / 'modules'
OUTPUT = HERE / 'open_wave_analyzer.py'

# Assembly order — must match the Part sequence.
# Each file is concatenated as-is (including trailing blank lines that
# serve as spacing between Parts), so the assembled output is a byte-level
# exact reproduction of the original single-file layout.
MODULE_ORDER = [
    '_preamble.py',
    'fst_types.py',
    'fst_codec.py',
    'fst_reader.py',
    'vcd_utils.py',
    'vcd_parser.py',
    'fst_adapter.py',
    'cli.py',
]


def assemble() -> str:
    """Read all modules and concatenate into a single source string."""
    parts = []
    for name in MODULE_ORDER:
        path = MODULES_DIR / name
        if not path.exists():
            sys.exit(f'Error: missing module {path}')
        parts.append(path.read_text(encoding='utf-8'))
    return ''.join(parts)


def main():
    check_mode = '--check' in sys.argv

    assembled = assemble()

    if check_mode:
        if not OUTPUT.exists():
            sys.exit(f'Error: {OUTPUT} does not exist; run without --check first')
        current = OUTPUT.read_text(encoding='utf-8')
        # Normalize line endings for comparison
        current_norm = current.replace('\r\n', '\n')
        assembled_norm = assembled.replace('\r\n', '\n')
        if current_norm == assembled_norm:
            print(f'OK: {OUTPUT.name} matches modules/')
        else:
            cur_lines = current_norm.splitlines()
            asm_lines = assembled_norm.splitlines()
            for i, (a, b) in enumerate(zip(cur_lines, asm_lines)):
                if a != b:
                    print(f'MISMATCH at line {i+1}:')
                    print(f'  current:  {a[:120]}')
                    print(f'  modules:  {b[:120]}')
                    break
            else:
                diff = len(cur_lines) - len(asm_lines)
                print(f'MISMATCH: line count differs by {diff} '
                      f'(current={len(cur_lines)}, modules={len(asm_lines)})')
            sys.exit(1)
    else:
        OUTPUT.write_text(assembled, encoding='utf-8', newline='\n')
        line_count = assembled.count('\n')
        size_kb = len(assembled.encode()) / 1024
        print(f'Assembled {OUTPUT.name}: {line_count} lines, '
              f'{size_kb:.0f} KB from {len(MODULE_ORDER)} modules')


if __name__ == '__main__':
    main()
