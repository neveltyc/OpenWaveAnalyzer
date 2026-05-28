#!/usr/bin/env python3
"""Cross-platform performance runner for OpenWaveAnalyzer.

The benchmark matrix mirrors todo/bench_perf.sh, but avoids shell-specific
tools so it works on Windows and Unix. It can also run selected commands
through cProfile and append the hottest cumulative-time functions to the
Markdown report.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import os
import platform
import pstats
import re
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TODO = ROOT / "todo"
DEFAULT_TIMEOUT = float(os.environ.get("BENCH_TIMEOUT", "60"))


@dataclasses.dataclass(frozen=True)
class BenchCase:
    group: str
    label: str
    fmt: str
    file_key: str
    cmd: str
    args: tuple[str, ...] = ()
    profile_default: bool = False


@dataclasses.dataclass
class BenchResult:
    group: str
    label: str
    fmt: str
    command: str
    seconds: float | None
    status: str
    returncode: int | None
    stderr_tail: str = ""
    profile: list[dict[str, object]] | None = None
    profile_file: str | None = None


def default_analyzer() -> Path:
    current = ROOT / "open_wave_analyzer.py"
    legacy = ROOT / "wave_analyzer.py"
    return current if current.exists() else legacy


def file_size_h(path: Path) -> str:
    size = path.stat().st_size
    units = ("B", "KB", "MB", "GB")
    value = float(size)
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024
    return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"


def resolve_dataset(name: str) -> tuple[Path, Path]:
    fst = TODO / f"{name}_test.fst"
    vcd = TODO / f"{name}_test.vcd"
    if not fst.exists() or not vcd.exists():
        raise SystemExit(
            f"Missing dataset {name!r}: expected {fst} and {vcd}"
        )
    return fst, vcd


def analyzer_args(analyzer: Path, case: BenchCase, file_path: Path) -> list[str]:
    return [
        sys.executable,
        str(analyzer),
        "--json",
        case.cmd,
        str(file_path),
        *case.args,
    ]


def shellish_command(args: list[str]) -> str:
    out = []
    for item in args:
        if re.search(r"\s", item):
            out.append(json.dumps(item))
        else:
            out.append(item)
    return " ".join(out)


def display_path(path: str | Path) -> str:
    p = Path(path).resolve()
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def run_command(args: list[str], timeout: float) -> tuple[str, float | None, int | None, str]:
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            cwd=ROOT,
        )
        elapsed = time.perf_counter() - start
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr or ""
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return "TIMEOUT", None, None, tail(stderr)
    status = "OK" if completed.returncode == 0 else "FAIL"
    return status, elapsed, completed.returncode, tail(completed.stderr)


def tail(text: str, limit: int = 800) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[-limit:]


def choose_search_signal(analyzer: Path, fst: Path, timeout: float) -> str | None:
    args = [
        sys.executable,
        str(analyzer),
        "--json",
        "list",
        str(fst),
        "--limit",
        "0",
    ]
    try:
        completed = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(timeout, 120),
            cwd=ROOT,
        )
    except subprocess.TimeoutExpired:
        return None
    if completed.returncode != 0:
        return None
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    for sig in data.get("signals", []):
        if sig.get("width") == 1 and sig.get("type") in ("wire", "reg"):
            return sig.get("path")
    return None


def make_cases(search_signal: str | None) -> list[BenchCase]:
    cases = [
        BenchCase("1. Header-only", "info", "FST", "fst", "info", profile_default=True),
        BenchCase("1. Header-only", "info", "VCD", "vcd", "info"),
        BenchCase("1. Header-only", "list --limit 5", "FST", "fst", "list", ("--limit", "5")),
        BenchCase("1. Header-only", "list --limit 5", "VCD", "vcd", "list", ("--limit", "5")),
        BenchCase("1. Header-only", "list --filter clk_diff", "FST", "fst", "list", ("--filter", "clk_diff")),
        BenchCase("1. Header-only", "list --filter clk_diff", "VCD", "vcd", "list", ("--filter", "clk_diff")),
        BenchCase(
            "2. Filtered dump",
            "dump --filter clk_diff --limit 3",
            "FST",
            "fst",
            "dump",
            ("--filter", "clk_diff", "--limit", "3"),
            profile_default=True,
        ),
        BenchCase(
            "2. Filtered dump",
            "dump --filter clk_diff --limit 3",
            "VCD",
            "vcd",
            "dump",
            ("--filter", "clk_diff", "--limit", "3"),
        ),
        BenchCase(
            "2. Filtered dump",
            "dump --filter clk_diff --limit 0",
            "FST",
            "fst",
            "dump",
            ("--filter", "clk_diff", "--limit", "0"),
        ),
        BenchCase(
            "2. Filtered dump",
            "dump --filter clk_diff --limit 0",
            "VCD",
            "vcd",
            "dump",
            ("--filter", "clk_diff", "--limit", "0"),
            profile_default=True,
        ),
        BenchCase(
            "2. Filtered dump",
            "dump --filter cal_e --limit 10",
            "FST",
            "fst",
            "dump",
            ("--filter", "cal_e", "--limit", "10"),
        ),
        BenchCase(
            "2. Filtered dump",
            "dump --filter cal_e --limit 10",
            "VCD",
            "vcd",
            "dump",
            ("--filter", "cal_e", "--limit", "10"),
        ),
        BenchCase(
            "2. Filtered dump",
            "dump --filter '*clk*' --limit 5",
            "FST",
            "fst",
            "dump",
            ("--filter", "*clk*", "--limit", "5"),
        ),
        BenchCase(
            "2. Filtered dump",
            "dump --filter '*clk*' --limit 5",
            "VCD",
            "vcd",
            "dump",
            ("--filter", "*clk*", "--limit", "5"),
        ),
        BenchCase(
            "3. Summary",
            "summary --filter clk_diff",
            "FST",
            "fst",
            "summary",
            ("--filter", "clk_diff"),
            profile_default=True,
        ),
        BenchCase(
            "3. Summary",
            "summary --filter clk_diff",
            "VCD",
            "vcd",
            "summary",
            ("--filter", "clk_diff"),
            profile_default=True,
        ),
        BenchCase(
            "4. Snapshot/Compare",
            "snapshot --at 5us --filter clk_diff",
            "FST",
            "fst",
            "snapshot",
            ("--at", "5us", "--filter", "clk_diff"),
        ),
        BenchCase(
            "4. Snapshot/Compare",
            "snapshot --at 5us --filter clk_diff",
            "VCD",
            "vcd",
            "snapshot",
            ("--at", "5us", "--filter", "clk_diff"),
        ),
        BenchCase(
            "4. Snapshot/Compare",
            "compare --at 1us,5us --filter clk_diff",
            "FST",
            "fst",
            "compare",
            ("--at", "1us,5us", "--filter", "clk_diff"),
        ),
        BenchCase(
            "4. Snapshot/Compare",
            "compare --at 1us,5us --filter clk_diff",
            "VCD",
            "vcd",
            "compare",
            ("--at", "1us,5us", "--filter", "clk_diff"),
        ),
        BenchCase(
            "6. Time-range",
            "dump --filter clk_diff --begin 4us --end 5us",
            "FST",
            "fst",
            "dump",
            ("--filter", "clk_diff", "--begin", "4us", "--end", "5us", "--limit", "0"),
        ),
        BenchCase(
            "6. Time-range",
            "dump --filter clk_diff --begin 4us --end 5us",
            "VCD",
            "vcd",
            "dump",
            ("--filter", "clk_diff", "--begin", "4us", "--end", "5us", "--limit", "0"),
        ),
        BenchCase(
            "7. No filter",
            "dump --limit 10 (no filter)",
            "FST",
            "fst",
            "dump",
            ("--limit", "10"),
        ),
        BenchCase(
            "7. No filter",
            "dump --limit 10 (no filter)",
            "VCD",
            "vcd",
            "dump",
            ("--limit", "10"),
        ),
    ]
    if search_signal:
        search_args = ("--condition", f"{search_signal}=1", "--limit", "5")
        cases.extend(
            [
                BenchCase(
                    "5. Search",
                    "search --condition <1bit>=1 --limit 5",
                    "FST",
                    "fst",
                    "search",
                    search_args,
                ),
                BenchCase(
                    "5. Search",
                    "search --condition <1bit>=1 --limit 5",
                    "VCD",
                    "vcd",
                    "search",
                    search_args,
                ),
            ]
        )
    return sorted(cases, key=lambda c: c.group)


def should_run(case: BenchCase, only: list[str], skip: list[str]) -> bool:
    haystack = " ".join((case.group, case.label, case.fmt)).lower()
    if only and not any(item.lower() in haystack for item in only):
        return False
    if skip and any(item.lower() in haystack for item in skip):
        return False
    return True


def profile_case(
    analyzer: Path,
    case: BenchCase,
    file_path: Path,
    timeout: float,
    out_dir: Path,
    top: int,
) -> tuple[list[dict[str, object]], str | None]:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{case.fmt}_{case.label}")[:80]
    profile_path = out_dir / f"profile_{stem}.pstats"
    args = [
        sys.executable,
        "-m",
        "cProfile",
        "-o",
        str(profile_path),
        str(analyzer),
        "--json",
        case.cmd,
        str(file_path),
        *case.args,
    ]
    status, _elapsed, _rc, _stderr = run_command(args, timeout * 2)
    if status != "OK" or not profile_path.exists():
        return [], None
    stats = pstats.Stats(str(profile_path))
    rows = []
    for func, stat in sorted(stats.stats.items(), key=lambda item: item[1][3], reverse=True)[:top]:
        ccalls, ncalls, tottime, cumtime, _callers = stat
        filename, line, name = func
        try:
            rel = str(Path(filename).resolve().relative_to(ROOT))
        except Exception:
            rel = filename
        rows.append(
            {
                "function": f"{rel}:{line}:{name}",
                "calls": ncalls,
                "primitive_calls": ccalls,
                "self_seconds": round(tottime, 6),
                "cum_seconds": round(cumtime, 6),
            }
        )
    return rows, str(profile_path)


def markdown_report(
    *,
    dataset: str,
    analyzer: Path,
    fst: Path,
    vcd: Path,
    timeout: float,
    search_signal: str | None,
    results: list[BenchResult],
) -> str:
    now = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
    lines = [
        f"# Performance analysis report ({dataset})",
        "",
        f"- Generated: {now}",
        f"- Python: {platform.python_version()} ({platform.system()} {platform.release()})",
        f"- Analyzer: `{display_path(analyzer)}`",
        f"- Timeout: {timeout:g}s",
        f"- FST: `{display_path(fst)}` ({file_size_h(fst)})",
        f"- VCD: `{display_path(vcd)}` ({file_size_h(vcd)})",
    ]
    if search_signal:
        lines.append(f"- Search signal: `{search_signal}`")
    else:
        lines.append("- Search signal: not found")
    lines.extend(
        [
            "",
            "## Timings",
            "",
            "| Group | Command | Fmt | Time | Status |",
            "|---|---|---:|---:|---|",
        ]
    )
    for r in results:
        t = "TIMEOUT" if r.seconds is None else f"{r.seconds:.3f}s"
        lines.append(f"| {r.group} | `{r.label}` | {r.fmt} | {t} | {r.status} |")
    failures = [r for r in results if r.status not in ("OK", "TIMEOUT")]
    if failures:
        lines.extend(["", "## Failures", ""])
        for r in failures:
            lines.append(f"- `{r.label}` {r.fmt}: rc={r.returncode}; {r.stderr_tail}")
    profiled = [r for r in results if r.profile]
    if profiled:
        lines.extend(["", "## cProfile Hotspots", ""])
        for r in profiled:
            if r.profile_file:
                lines.append(f"### {r.label} [{r.fmt}]")
                lines.append("")
                lines.append(f"- Raw profile: `{display_path(r.profile_file)}`")
                lines.append("")
                lines.append("| Function | Calls | Self | Cum |")
                lines.append("|---|---:|---:|---:|")
                for row in r.profile or []:
                    lines.append(
                        "| `{}` | {} | {:.3f}s | {:.3f}s |".format(
                            row["function"],
                            row["calls"],
                            row["self_seconds"],
                            row["cum_seconds"],
                        )
                    )
                lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", default="medium", choices=("small", "medium", "large"))
    p.add_argument("--fst", type=Path, help="explicit FST path")
    p.add_argument("--vcd", type=Path, help="explicit VCD path")
    p.add_argument("--analyzer", type=Path, default=default_analyzer())
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--only", action="append", default=[], help="run cases matching text")
    p.add_argument("--skip", action="append", default=[], help="skip cases matching text")
    p.add_argument("--profile-defaults", action="store_true", help="profile default hotspot cases")
    p.add_argument("--profile-label", action="append", default=[], help="profile cases matching text")
    p.add_argument("--profile-top", type=int, default=12)
    p.add_argument("--out-dir", type=Path, default=TODO)
    p.add_argument("--report", type=Path, help="Markdown output path")
    p.add_argument("--json-out", type=Path, help="JSON output path")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    analyzer = args.analyzer.resolve()
    if not analyzer.exists():
        raise SystemExit(f"Analyzer not found: {analyzer}")

    if args.fst or args.vcd:
        if not (args.fst and args.vcd):
            raise SystemExit("--fst and --vcd must be supplied together")
        fst = args.fst.resolve()
        vcd = args.vcd.resolve()
    else:
        fst, vcd = resolve_dataset(args.dataset)
        fst = fst.resolve()
        vcd = vcd.resolve()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    report = args.report or args.out_dir / f"perf_report_{args.dataset}_{stamp}.md"
    json_out = args.json_out or args.out_dir / f"perf_report_{args.dataset}_{stamp}.json"

    print(f"Analyzer: {analyzer}")
    print(f"FST: {fst} ({file_size_h(fst)})")
    print(f"VCD: {vcd} ({file_size_h(vcd)})")
    print("Selecting search signal...")
    search_signal = choose_search_signal(analyzer, fst, args.timeout)
    print(f"Search signal: {search_signal or '(none)'}")

    files = {"fst": fst, "vcd": vcd}
    results: list[BenchResult] = []
    for case in make_cases(search_signal):
        if not should_run(case, args.only, args.skip):
            continue
        file_path = files.get(case.file_key, fst)
        cmd_args = analyzer_args(analyzer, case, file_path)
        print(f"[{case.fmt}] {case.label}")
        status, seconds, rc, stderr_tail = run_command(cmd_args, args.timeout)
        result = BenchResult(
            group=case.group,
            label=case.label,
            fmt=case.fmt,
            command=shellish_command(cmd_args),
            seconds=seconds,
            status=status,
            returncode=rc,
            stderr_tail=stderr_tail,
        )
        profile_match = any(
            text.lower() in f"{case.label} {case.fmt}".lower()
            for text in args.profile_label
        )
        if status == "OK" and (profile_match or (args.profile_defaults and case.profile_default)):
            print(f"  profiling {case.label} [{case.fmt}]")
            profile, profile_file = profile_case(
                analyzer, case, file_path, args.timeout, args.out_dir.resolve(), args.profile_top
            )
            result.profile = profile
            result.profile_file = profile_file
        results.append(result)

    md = markdown_report(
        dataset=args.dataset,
        analyzer=analyzer,
        fst=fst,
        vcd=vcd,
        timeout=args.timeout,
        search_signal=search_signal,
        results=results,
    )
    report.write_text(md, encoding="utf-8", newline="\n")
    json_out.write_text(
        json.dumps(
            {
                "dataset": args.dataset,
                "analyzer": str(analyzer),
                "fst": str(fst),
                "vcd": str(vcd),
                "timeout": args.timeout,
                "search_signal": search_signal,
                "results": [dataclasses.asdict(r) for r in results],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {report}")
    print(f"Wrote {json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
