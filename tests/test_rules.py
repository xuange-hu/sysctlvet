"""Pass 1 (settings): every key rule fires on the risky value, stays quiet on the safe one."""

import pytest

from sysctlvet.scanner import scan_paths

# rule id -> (key, value that must fire, value that must stay quiet)
KEY_TRIGGERS = {
    "SYS101": ("net.ipv4.ip_forward", "1", "0"),
    "SYS102": ("net.ipv4.conf.all.accept_redirects", "1", "0"),
    "SYS103": ("net.ipv4.conf.all.send_redirects", "1", "0"),
    "SYS104": ("net.ipv4.conf.all.accept_source_route", "1", "0"),
    "SYS105": ("net.ipv4.conf.all.rp_filter", "0", "1"),
    "SYS106": ("net.ipv4.tcp_syncookies", "0", "1"),
    "SYS107": ("net.ipv4.conf.all.log_martians", "0", "1"),
    "SYS108": ("net.ipv4.icmp_echo_ignore_broadcasts", "0", "1"),
    "SYS109": ("kernel.randomize_va_space", "1", "2"),
    "SYS110": ("kernel.kptr_restrict", "0", "1"),
    "SYS111": ("kernel.dmesg_restrict", "0", "1"),
    "SYS112": ("kernel.perf_event_paranoid", "1", "2"),
    "SYS113": ("kernel.yama.ptrace_scope", "0", "1"),
    "SYS114": ("kernel.unprivileged_bpf_disabled", "0", "1"),
    "SYS115": ("fs.suid_dumpable", "1", "2"),
    "SYS116": ("kernel.sysrq", "1", "176"),
    "SYS117": ("kernel.core_pattern", "|/usr/local/bin/crashpipe", "core"),
    "SYS118": ("fs.protected_symlinks", "0", "1"),
    "SYS119": ("net.ipv6.conf.all.accept_ra", "2", "1"),
    "SYS120": ("kernel.kexec_load_disabled", "0", "1"),
}


def _scan(tmp_path, text):
    path = tmp_path / "sysctl.conf"
    path.write_text(text, encoding="utf-8")
    return scan_paths([str(path)])


def _rules(report):
    return {f.rule for f in report.findings}


@pytest.mark.parametrize("rule_id", sorted(KEY_TRIGGERS))
def test_risky_value_fires(tmp_path, rule_id):
    key, bad, _good = KEY_TRIGGERS[rule_id]
    report = _scan(tmp_path, f"{key} = {bad}\n")
    assert rule_id in _rules(report)


@pytest.mark.parametrize("rule_id", sorted(KEY_TRIGGERS))
def test_safe_value_stays_quiet(tmp_path, rule_id):
    key, _bad, good = KEY_TRIGGERS[rule_id]
    report = _scan(tmp_path, f"{key} = {good}\n")
    assert rule_id not in _rules(report)


def test_every_catalog_rule_has_a_trigger():
    from sysctlvet.rules import KEY_RULES

    catalog_ids = {rule_id for rule_id, _, _, _ in KEY_RULES}
    assert catalog_ids == set(KEY_TRIGGERS)


def test_wildcard_matches_named_interface(tmp_path):
    report = _scan(tmp_path, "net/ipv4/conf/eth0/accept_redirects = 1\n")
    findings = [f for f in report.findings if f.rule == "SYS102"]
    assert findings and "eth0" in findings[0].message


def test_wildcard_matches_ipv6_family(tmp_path):
    report = _scan(tmp_path, "net.ipv6.conf.default.accept_source_route = 1\n")
    assert "SYS104" in _rules(report)


def test_aslr_zero_and_one_both_fire(tmp_path):
    for value in ("0", "1"):
        report = _scan(tmp_path, f"kernel.randomize_va_space = {value}\n")
        assert "SYS109" in _rules(report), value


def test_suid_dumpable_zero_and_two_both_safe(tmp_path):
    for value in ("0", "2"):
        report = _scan(tmp_path, f"fs.suid_dumpable = {value}\n")
        assert "SYS115" not in _rules(report), value


def test_sysrq_bitmask_not_flagged(tmp_path):
    report = _scan(tmp_path, "kernel.sysrq = 176\n")
    assert "SYS116" not in _rules(report)


def test_core_pattern_plain_file_safe(tmp_path):
    report = _scan(tmp_path, "kernel.core_pattern = core\n")
    assert "SYS117" not in _rules(report)


def test_malformed_line_fires_sys199(tmp_path):
    report = _scan(tmp_path, "this is not an assignment\n")
    assert "SYS199" in _rules(report)


def test_finding_carries_evidence(tmp_path):
    report = _scan(tmp_path, "net.ipv4.tcp_syncookies = 0\n")
    finding = next(f for f in report.findings if f.rule == "SYS106")
    assert finding.line == 1
    assert finding.offset == 0
    assert finding.length == len("net.ipv4.tcp_syncookies = 0")
    assert finding.saw == "net.ipv4.tcp_syncookies = 0"
    assert finding.where.endswith("sysctl.conf")
    assert finding.fix


def test_findings_sorted_by_severity(tmp_path):
    text = "net.ipv4.tcp_syncookies = 0\nkernel.randomize_va_space = 0\nkernel.kexec_load_disabled = 0\n"
    report = _scan(tmp_path, text)
    severities = [f.severity for f in report.findings]
    order = {"high": 0, "medium": 1, "low": 2, "note": 3}
    assert severities == sorted(severities, key=lambda s: order[s])


def test_evidence_points_at_winner_not_loser(tmp_path):
    path = tmp_path / "sysctl.conf"
    path.write_text("net.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_syncookies = 0\n", encoding="utf-8")
    report = scan_paths([str(path)])
    finding = next(f for f in report.findings if f.rule == "SYS106")
    assert finding.line == 2  # the winner, not the dead line
