"""Command line interface: scan, effective, rules, demo, explain."""

from __future__ import annotations

import argparse
import json
import sys

from .__about__ import __version__
from .demo import run_demo
from .render import render
from .resolve import assignment_pairs, effective_for
from .rules import REGISTRY, RULES_BY_ID
from .scanner import parse_file, scan_paths

FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "note", "none")


def _emit(report, args) -> int:
    fmt = getattr(args, "format", "text")
    quiet = getattr(args, "quiet", False)
    sys.stdout.write(render(report, fmt=fmt, quiet=quiet) + "\n")
    # 三态退出码：0 干净 / 1 命中门禁 / 2 没扫全。
    # 路径不存在、目录里没有匹配文件，都属于"没扫全"，不能退 0 ——
    # 否则 CI 里的 `sysctlvet scan /etc/sysctl.d` 在打错字时永远是绿的。
    if getattr(report, "missing", None):
        return 2
    return 1 if report.should_fail(getattr(args, "fail_on", "high")) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sysctlvet",
        description="Zero-dependency kernel parameter (sysctl) auditor: sysctl.conf and sysctl.d drop-ins.",
    )
    parser.add_argument("--version", action="version", version=f"sysctlvet {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan sysctl.conf / sysctl.d files or directories")
    scan.add_argument("paths", nargs="+", help="config file(s) or directory(ies)")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="high",
        help="exit 1 when a finding at or above this severity exists (default: high; 'none' disables the gate)",
    )
    scan.add_argument("--quiet", action="store_true", help="hide fix hints")

    eff = sub.add_parser("effective", help="show which line wins for one key (the precedence engine)")
    eff.add_argument("key", help="e.g. net.ipv4.ip_forward")
    eff.add_argument("paths", nargs="+", help="config file(s) or directory(ies)")
    eff.add_argument("--format", choices=("text", "json"), default="text")

    rules = sub.add_parser("rules", help="print the rulebook")
    rules.add_argument("--rule", default="", help="only this rule id")
    rules.add_argument("--format", choices=("text", "json"), default="text")

    demo = sub.add_parser("demo", help="run the embedded demo corpus (no arguments needed)")
    demo.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    demo.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="none")
    demo.add_argument("--quiet", action="store_true")

    explain = sub.add_parser("explain", help="explain one rule")
    explain.add_argument("rule_id", help="e.g. SYS301")
    return parser


def _print_rule(item) -> None:
    sys.stdout.write(f"{item.id}  {item.title}\n")
    sys.stdout.write(f"  severity: {item.severity} (score {item.score}/10)  pass: {item.stage}\n")
    sys.stdout.write(f"  why: {item.why}\n")
    sys.stdout.write(f"  fix: {item.fix}\n")


def _print_effective(key: str, args) -> int:
    from .resolve import resolve
    from .scanner import collect

    files, _missing = collect(list(args.paths))
    configs = [parse_file(path) for path in files]
    eff = resolve(configs)
    entry = effective_for(eff, key)
    if entry is None:
        sys.stderr.write(f"sysctlvet: key {key!r} is not set in any of the given files\n")
        return 2
    rows = [{"role": role, **assignment.to_dict()} for assignment, role in assignment_pairs(entry)]
    if getattr(args, "format", "text") == "json":
        sys.stdout.write(json.dumps({"key": entry.key, "assignments": rows}, indent=2) + "\n")
        return 0
    sys.stdout.write(f"{entry.key}  (load order: earlier loses, later wins)\n")
    for row in rows:
        marker = "WINS" if row["role"] == "winner" else "dead"
        sys.stdout.write(f"  [{marker}] {row['file']}:{row['line']}  {row['raw_key']} = {row['value']}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _emit(scan_paths(args.paths), args)
    if args.command == "demo":
        return _emit(run_demo(), args)
    if args.command == "effective":
        return _print_effective(args.key, args)
    if args.command == "rules":
        if args.format == "json":
            wanted = [RULES_BY_ID[args.rule]] if args.rule else REGISTRY
            sys.stdout.write(json.dumps([item.__dict__ for item in wanted], indent=2) + "\n")
            return 0
        if args.rule:
            item = RULES_BY_ID.get(args.rule.upper())
            if item is None:
                sys.stderr.write(f"sysctlvet: unknown rule {args.rule!r}\n")
                return 2
            _print_rule(item)
            return 0
        for item in sorted(REGISTRY, key=lambda i: i.id):
            sys.stdout.write(f"{item.id}  [{item.severity}] {item.title}\n")
        return 0
    if args.command == "explain":
        item = RULES_BY_ID.get(args.rule_id.upper())
        if item is None:
            sys.stderr.write(f"sysctlvet: unknown rule {args.rule_id!r}\n")
            return 2
        _print_rule(item)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
