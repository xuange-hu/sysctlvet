"""Object model: assignments, effective values, findings and the report.

Every assignment keeps its file, line, character offset and raw text, because
the only useful sysctl finding is the one that points at the exact line an
operator must edit — especially when that line is dead because a later-loaded
file overwrote it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "note": 4}

# Load tiers, ascending = loaded earlier = lower precedence.  Mirrors
# `sysctl --system`: /usr/lib/sysctl.d first, /etc/sysctl.conf last (wins).
TIER_USR_LIB = 0
TIER_USR_LOCAL = 1
TIER_RUN = 2
TIER_ETC_D = 3
TIER_ETC_CONF = 4


@dataclass
class Assignment:
    """One ``key = value`` line from one config file."""

    key: str  # normalized: separators unified to dots
    raw_key: str  # exactly as written in the file
    value: str
    line: int
    offset: int
    length: int
    raw: str
    file: str
    eq_form: str = "="  # "=" | "ws" | ""
    seq: int = 0  # global load-order index (later wins)

    @property
    def numeric(self) -> int | None:
        """Integer value as the kernel sees it, or None for strings."""
        text = self.value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            pass
        try:
            return int(text, 10)
        except ValueError:
            return None

    @property
    def saw(self) -> str:
        return " ".join(self.raw.split())[:160]

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "raw_key": self.raw_key,
            "value": self.value,
            "file": self.file,
            "line": self.line,
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "length": self.length,
            "numeric": self.numeric,
            "eq_form": self.eq_form,
        }


@dataclass
class ConfigFile:
    """One parsed sysctl source file."""

    source: str
    tier: int = TIER_ETC_D
    load_key: tuple = ()
    assignments: list[Assignment] = field(default_factory=list)
    warnings: list[tuple[int, int, str]] = field(default_factory=list)  # line, offset, raw

    @property
    def text(self) -> str:
        return "\n".join(a.raw for a in self.assignments)


@dataclass
class Effective:
    """The winning assignment for one key, plus everything it overrode."""

    key: str
    winner: Assignment
    losers: list[Assignment] = field(default_factory=list)

    @property
    def assignments(self) -> list[Assignment]:
        return [*self.losers, self.winner]


@dataclass
class Finding:
    """One rule conclusion, with the evidence that produced it."""

    rule: str
    severity: str
    message: str
    line: int
    offset: int
    length: int
    saw: str
    fix: str
    where: str
    score: int = 0

    def sort_key(self) -> tuple[int, str, int]:
        return (SEVERITY_ORDER.get(self.severity, 9), self.rule, self.offset)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "where": self.where,
            "line": self.line,
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "length": self.length,
            "saw": self.saw,
            "fix": self.fix,
        }


@dataclass
class Report:
    source: str
    targets: list[ConfigFile] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    rules_run: int = 0
    rule_ids: list[str] = field(default_factory=list)
    # 用户给出的路径里，压根不存在的那些。
    # 这个字段存在的唯一理由：让"什么都没扫到"无法伪装成"这里很安全"。
    missing: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {name: 0 for name in SEVERITY_ORDER}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def should_fail(self, threshold: str) -> bool:
        if threshold == "none":
            return False
        limit = SEVERITY_ORDER[threshold]
        return any(SEVERITY_ORDER.get(f.severity, 9) <= limit for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "findings": [f.to_dict() for f in self.findings],
            "counts": self.counts,
            "rules_run": self.rules_run,
            "missing": list(self.missing),
        }
