"""Pass 3 (relations): dead settings, reverted hardening, duplicates across files."""

from sysctlvet.scanner import scan_paths


def _scan_files(tmp_path, files: dict[str, str]):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return scan_paths([str(tmp_path)])


def _rules(report):
    return {f.rule for f in report.findings}


# --- SYS301: hardening silently reverted -----------------------------------

def test_hardening_reverted_by_sysctl_conf(tmp_path):
    report = _scan_files(
        tmp_path,
        {
            "10-base.conf": "kernel.randomize_va_space = 2\n",
            "sysctl.conf": "kernel.randomize_va_space = 0\n",
        },
    )
    hits = [f for f in report.findings if f.rule == "SYS301"]
    assert len(hits) == 1
    assert hits[0].line == 1
    assert "10-base.conf" in hits[0].where or hits[0].where.endswith("10-base.conf")
    assert "sysctl.conf" in hits[0].message


def test_reverted_co_fires_dead_assignment(tmp_path):
    report = _scan_files(
        tmp_path,
        {
            "10-base.conf": "kernel.randomize_va_space = 2\n",
            "sysctl.conf": "kernel.randomize_va_space = 0\n",
        },
    )
    assert {"SYS301", "SYS302"} <= _rules(report)


def test_reverted_within_one_file(tmp_path):
    report = _scan_files(
        tmp_path,
        {"sysctl.conf": "net.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.all.rp_filter = 0\n"},
    )
    hits = [f for f in report.findings if f.rule == "SYS301"]
    assert len(hits) == 1 and hits[0].line == 1


def test_risky_loser_is_not_reverted(tmp_path):
    # loser risky, winner safe -> plain dead text, no hardening was reverted
    report = _scan_files(
        tmp_path,
        {
            "10-base.conf": "net.ipv4.tcp_syncookies = 0\n",
            "sysctl.conf": "net.ipv4.tcp_syncookies = 1\n",
        },
    )
    assert "SYS301" not in _rules(report)
    assert "SYS302" in _rules(report)


# --- SYS302: dead assignments ---------------------------------------------

def test_cross_file_dead_assignment(tmp_path):
    report = _scan_files(
        tmp_path,
        {
            "10-a.conf": "net.ipv4.tcp_syncookies = 0\n",
            "99-b.conf": "net.ipv4.tcp_syncookies = 1\n",
        },
    )
    hits = [f for f in report.findings if f.rule == "SYS302"]
    assert len(hits) == 1
    assert hits[0].line == 1  # evidence on the dead line


def test_within_file_dead_assignment(tmp_path):
    report = _scan_files(tmp_path, {"sysctl.conf": "net.ipv4.tcp_syncookies = 0\nnet.ipv4.tcp_syncookies = 1\n"})
    hits = [f for f in report.findings if f.rule == "SYS302"]
    assert len(hits) == 1 and hits[0].line == 1


def test_single_assignment_no_dead_text(tmp_path):
    report = _scan_files(tmp_path, {"sysctl.conf": "net.ipv4.tcp_syncookies = 1\n"})
    assert "SYS302" not in _rules(report)


# --- SYS303: separator duplicates ----------------------------------------

def test_separator_duplicate_detected(tmp_path):
    report = _scan_files(
        tmp_path,
        {
            "10-a.conf": "net/ipv4/ip_forward = 0\n",
            "sysctl.conf": "net.ipv4.ip_forward = 0\n",
        },
    )
    hits = [f for f in report.findings if f.rule == "SYS303"]
    assert len(hits) == 1
    assert "net/ipv4/ip_forward" in hits[0].message


def test_consistent_spelling_no_sys303(tmp_path):
    report = _scan_files(
        tmp_path,
        {
            "10-a.conf": "net.ipv4.ip_forward = 0\n",
            "sysctl.conf": "net.ipv4.ip_forward = 1\n",
        },
    )
    assert "SYS303" not in _rules(report)


# --- SYS304: type mismatch ------------------------------------------------

def test_string_value_on_numeric_key(tmp_path):
    report = _scan_files(tmp_path, {"sysctl.conf": "net.ipv4.ip_nonlocal_bind = yes\n"})
    hits = [f for f in report.findings if f.rule == "SYS304"]
    assert len(hits) == 1 and "not a number" in hits[0].message


def test_string_key_not_flagged_as_type_error(tmp_path):
    report = _scan_files(tmp_path, {"sysctl.conf": "kernel.core_pattern = core\n"})
    assert "SYS304" not in _rules(report)


def test_hex_value_is_numeric(tmp_path):
    report = _scan_files(tmp_path, {"sysctl.conf": "kernel.sysrq = 0x1f\n"})
    assert "SYS304" not in _rules(report)


# --- SYS305: interface weakens global -------------------------------------

def test_interface_weakens_global(tmp_path):
    report = _scan_files(
        tmp_path,
        {
            "sysctl.conf": "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.eth0.accept_redirects = 1\n",
        },
    )
    hits = [f for f in report.findings if f.rule == "SYS305"]
    assert len(hits) == 1
    assert "eth0" in hits[0].message and "conf.all" in hits[0].message


def test_interface_matches_global_no_sys305(tmp_path):
    report = _scan_files(
        tmp_path,
        {
            "sysctl.conf": "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.eth0.accept_redirects = 0\n",
        },
    )
    assert "SYS305" not in _rules(report)


def test_default_interface_is_not_a_named_interface(tmp_path):
    report = _scan_files(
        tmp_path,
        {
            "sysctl.conf": "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 1\n",
        },
    )
    assert "SYS305" not in _rules(report)


def test_global_absent_no_sys305(tmp_path):
    report = _scan_files(tmp_path, {"sysctl.conf": "net.ipv4.conf.eth0.accept_redirects = 1\n"})
    assert "SYS305" not in _rules(report)


def test_every_relation_rule_can_fire():
    # The relation rules are exercised by the demo corpus; this guards the list.
    from sysctlvet.demo import run_demo

    fired = {f.rule for f in run_demo().findings}
    assert {"SYS301", "SYS302", "SYS303", "SYS304", "SYS305"} <= fired
