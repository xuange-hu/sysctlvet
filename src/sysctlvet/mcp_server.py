"""MCP server: expose sysctlvet to Claude Code / Cursor / Cline.

The `mcp` package is imported lazily so the core stays importable (and the
zero-dependency claim testable) without the optional extra installed.
"""

from __future__ import annotations

import json


def tool_manifest() -> list[dict]:
    return [
        {
            "name": "sysctlvet_scan",
            "description": (
                "Scan sysctl.conf / sysctl.d files and return findings with line-level evidence, "
                "resolved with the real sysctl load order."
            ),
            "args": "paths (list[str]), fail_on (str, default 'none')",
        },
        {
            "name": "sysctlvet_effective",
            "description": (
                "Precedence engine: for one key, show every assignment across the files and which "
                "line actually wins (the rest are dead)."
            ),
            "args": "key (str), paths (list[str])",
        },
        {
            "name": "sysctlvet_demo",
            "description": (
                "Run the embedded demo corpus (a host configured by four different people) "
                "and return the findings summary."
            ),
            "args": "none",
        },
        {
            "name": "sysctlvet_rules",
            "description": "Return the full rulebook: id, title, severity, pass, why and fix for all rules.",
            "args": "none",
        },
        {
            "name": "sysctlvet_explain",
            "description": "Explain one rule by id (e.g. SYS301) including why it matters and how to fix it.",
            "args": "rule_id (str)",
        },
        {
            "name": "sysctlvet_parse",
            "description": (
                "Parse one sysctl file and return its normalized assignments (keys, values, "
                "lines, offsets) without running rules."
            ),
            "args": "path (str)",
        },
    ]


def _summary(report) -> str:
    payload = {
        "source": report.source,
        "counts": report.counts,
        "findings": [f.to_dict() for f in report.findings],
    }
    return json.dumps(payload, indent=2)


def build_server():
    from mcp.server.fastmcp import FastMCP

    from .demo import run_demo
    from .resolve import assignment_pairs, effective_for, resolve
    from .rules import RULES_BY_ID
    from .scanner import collect, parse_file, scan_paths

    mcp = FastMCP("sysctlvet")

    @mcp.tool(name="sysctlvet_scan")
    def sysctlvet_scan(paths: list[str], fail_on: str = "none") -> str:
        """Scan sysctl.conf / sysctl.d files or directories; returns findings with evidence."""
        report = scan_paths(paths)
        return _summary(report)

    @mcp.tool(name="sysctlvet_effective")
    def sysctlvet_effective(key: str, paths: list[str]) -> str:
        """Show which line wins for one key, and every dead line it overrode."""
        files, _missing = collect(list(paths))
        configs = [parse_file(path) for path in files]
        eff = resolve(configs)
        entry = effective_for(eff, key)
        if entry is None:
            return json.dumps({"error": f"key {key!r} is not set in any of the given files"})
        return json.dumps(
            {
                "key": entry.key,
                "winner": entry.winner.to_dict(),
                "assignments": [{"role": role, **a.to_dict()} for a, role in assignment_pairs(entry)],
            },
            indent=2,
        )

    @mcp.tool(name="sysctlvet_demo")
    def sysctlvet_demo() -> str:
        """Run the embedded demo corpus and return its findings."""
        return _summary(run_demo())

    @mcp.tool(name="sysctlvet_rules")
    def sysctlvet_rules() -> str:
        """Return the full rulebook as JSON."""
        return json.dumps([item.__dict__ for item in sorted(RULES_BY_ID.values(), key=lambda i: i.id)], indent=2)

    @mcp.tool(name="sysctlvet_explain")
    def sysctlvet_explain(rule_id: str) -> str:
        """Explain one rule by id."""
        item = RULES_BY_ID.get(rule_id.upper())
        if item is None:
            return json.dumps({"error": f"unknown rule {rule_id!r}"})
        return json.dumps(item.__dict__, indent=2)

    @mcp.tool(name="sysctlvet_parse")
    def sysctlvet_parse(path: str) -> str:
        """Parse one sysctl file and return its normalized assignments."""
        config = parse_file(path)
        return json.dumps(
            {
                "source": config.source,
                "assignments": [a.to_dict() for a in config.assignments],
                "warnings": [{"line": line, "offset": offset, "raw": raw} for line, offset, raw in config.warnings],
            },
            indent=2,
        )

    return mcp


def main() -> None:
    mcp = build_server()
    mcp.run()


if __name__ == "__main__":
    main()
