"""Renderers: human text, machine JSON and SARIF 2.1.0 for CI."""

from __future__ import annotations

import json

from .model import SEVERITY_ORDER, Report

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "note": "note"}


def render_text(report: Report, quiet: bool = False) -> str:
    out: list[str] = []
    for finding in sorted(report.findings, key=lambda f: f.sort_key()):
        out.append(f"{finding.severity.upper():8s} {finding.rule}  {finding.message}")
        out.append(f"         at {finding.where}:{finding.line} (offset {finding.offset}, len {finding.length})")
        out.append(f"         saw: {finding.saw}")
        if not quiet:
            out.append(f"         fix: {finding.fix}")
        out.append("")
    counts = report.counts
    parts = [f"{counts[name]} {name}" for name in SEVERITY_ORDER if counts.get(name)]
    summary = ", ".join(parts) if parts else "no findings"
    out.append(f"{len(report.findings)} finding(s) across {len(report.targets)} file(s): {summary}")
    return "\n".join(out)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def render_sarif(report: Report) -> str:
    rules = []
    seen: set[str] = set()
    for finding in report.findings:
        if finding.rule in seen:
            continue
        seen.add(finding.rule)
        rules.append(
            {
                "id": finding.rule,
                "shortDescription": {"text": finding.message},
                "help": {"text": finding.fix},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(finding.severity, "warning")},
            }
        )
    results = [
        {
            "ruleId": finding.rule,
            "level": _SARIF_LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.where.replace("\\", "/")},
                        "region": {
                            "startLine": max(1, finding.line),
                            "byteOffset": max(0, finding.offset),
                            "byteLength": max(1, finding.length),
                            "snippet": {"text": finding.saw},
                        },
                    }
                }
            ],
            "properties": {"severity": finding.severity, "score": finding.score},
        }
        for finding in report.findings
    ]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sysctlvet",
                        "informationUri": "https://github.com/xuange-hu/sysctlvet",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def render(report: Report, fmt: str = "text", quiet: bool = False) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    return render_text(report, quiet=quiet)
