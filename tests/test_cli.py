"""CLI contract: scan, effective, rules, demo, explain, exit codes."""

import json

from sysctlvet.cli import main


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_scan_text_reports_findings(tmp_path, capsys):
    path = _write(tmp_path, "sysctl.conf", "net.ipv4.tcp_syncookies = 0\n")
    assert main(["scan", path]) == 0
    out = capsys.readouterr().out
    assert "SYS106" in out and "fix:" in out


def test_scan_quiet_hides_fixes(tmp_path, capsys):
    path = _write(tmp_path, "sysctl.conf", "net.ipv4.tcp_syncookies = 0\n")
    main(["scan", path, "--quiet"])
    assert "fix:" not in capsys.readouterr().out


def test_scan_json_shape(tmp_path, capsys):
    path = _write(tmp_path, "sysctl.conf", "kernel.randomize_va_space = 0\n")
    main(["scan", path, "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["high"] == 1
    assert payload["findings"][0]["rule"] == "SYS109"
    assert payload["rules_run"] == 31


def test_scan_sarif_shape(tmp_path, capsys):
    path = _write(tmp_path, "sysctl.conf", "kernel.randomize_va_space = 0\n")
    main(["scan", path, "--format", "sarif"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "sysctlvet"


def test_fail_on_gate_both_directions(tmp_path, capsys):
    clean = _write(tmp_path, "clean.conf", "kernel.randomize_va_space = 2\n")
    bad = _write(tmp_path, "sysctl.conf", "kernel.randomize_va_space = 0\n")
    assert main(["scan", clean, "--fail-on", "high"]) == 0
    assert main(["scan", bad, "--fail-on", "high"]) == 1
    assert main(["scan", bad, "--fail-on", "none"]) == 0
    capsys.readouterr()


def test_fail_on_none_never_fails(tmp_path):
    path = _write(tmp_path, "sysctl.conf", "kernel.randomize_va_space = 0\n")
    assert main(["scan", path, "--fail-on", "none"]) == 0


def test_effective_shows_winner_and_dead_lines(tmp_path, capsys):
    _write(tmp_path, "10-a.conf", "net.ipv4.tcp_syncookies = 1\n")
    _write(tmp_path, "sysctl.conf", "net.ipv4.tcp_syncookies = 0\n")
    assert main(["effective", "net.ipv4.tcp_syncookies", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "[WINS]" in out and "[dead]" in out
    assert "sysctl.conf" in out and "10-a.conf" in out


def test_effective_json(tmp_path, capsys):
    _write(tmp_path, "sysctl.conf", "net.ipv4.ip_forward = 1\n")
    main(["effective", "net.ipv4.ip_forward", str(tmp_path), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["key"] == "net.ipv4.ip_forward"
    assert payload["assignments"][0]["role"] == "winner"


def test_effective_unknown_key_exits_2(tmp_path, capsys):
    _write(tmp_path, "sysctl.conf", "net.ipv4.ip_forward = 1\n")
    assert main(["effective", "net.ipv9.nope", str(tmp_path)]) == 2
    assert "not set" in capsys.readouterr().err


def test_rules_list(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert out.count("SYS") >= 31
    assert "SYS301" in out


def test_rules_json(capsys):
    main(["rules", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 31


def test_rules_one(capsys):
    assert main(["rules", "--rule", "sys301"]) == 0
    assert "hardening" in capsys.readouterr().out.lower()


def test_unknown_rule_exits_2(capsys):
    assert main(["explain", "SYS999"]) == 2
    assert "unknown rule" in capsys.readouterr().err


def test_explain_prints_why_and_fix(capsys):
    assert main(["explain", "SYS114"]) == 0
    out = capsys.readouterr().out
    assert "why:" in out and "fix:" in out


def test_demo_runs_without_arguments(capsys):
    assert main(["demo", "--quiet"]) == 0
    out = capsys.readouterr().out
    assert "finding(s)" in out


def test_no_command_prints_help(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().out.lower()
