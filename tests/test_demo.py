"""Demo corpus contract: the embedded demo must exercise every rule."""

from sysctlvet.demo import DEMO_FILES, run_demo
from sysctlvet.rules import REGISTRY


def test_demo_covers_every_rule():
    report = run_demo()
    fired = {f.rule for f in report.findings}
    missing = sorted({item.id for item in REGISTRY} - fired)
    assert not missing, f"demo corpus never triggers: {missing}"


def test_demo_shape():
    report = run_demo()
    assert len(report.targets) == len(DEMO_FILES) == 4
    assert report.rules_run == len(REGISTRY) == 31
    assert report.counts["high"] >= 6
    assert report.counts["medium"] >= 10
    assert report.counts["low"] >= 5
    assert report.counts["note"] >= 1


def test_demo_summary_counts_add_up():
    report = run_demo()
    assert sum(report.counts.values()) == len(report.findings)


def test_demo_is_deterministic():
    first = run_demo()
    second = run_demo()
    assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]


def test_demo_file_names_are_realistic_paths():
    # The names drive the load order; if they stop looking like real sysctl
    # paths the precedence story in the README stops being true.
    assert "etc/sysctl.conf" in DEMO_FILES
    assert any(name.startswith("etc/sysctl.d/") for name in DEMO_FILES)
    assert any(name.startswith("usr/lib/sysctl.d/") for name in DEMO_FILES)
