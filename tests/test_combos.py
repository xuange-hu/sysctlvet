"""Pass 2 (combos): values that are dangerous together."""

from sysctlvet.scanner import scan_paths


def _scan(tmp_path, text):
    path = tmp_path / "sysctl.conf"
    path.write_text(text, encoding="utf-8")
    return scan_paths([str(path)])


def _rules(report):
    return {f.rule for f in report.findings}


def test_kaslr_trifecta(tmp_path):
    text = "kernel.kptr_restrict = 0\nkernel.dmesg_restrict = 0\nkernel.perf_event_paranoid = 1\n"
    assert "SYS201" in _rules(_scan(tmp_path, text))


def test_kaslr_trifecta_needs_all_three(tmp_path):
    text = "kernel.kptr_restrict = 0\nkernel.dmesg_restrict = 0\nkernel.perf_event_paranoid = 2\n"
    assert "SYS201" not in _rules(_scan(tmp_path, text))


def test_dump_chain_aslr_off_plus_suid(tmp_path):
    text = "kernel.randomize_va_space = 0\nfs.suid_dumpable = 1\n"
    assert "SYS202" in _rules(_scan(tmp_path, text))


def test_dump_chain_absent_without_suid_dumps(tmp_path):
    text = "kernel.randomize_va_space = 0\nfs.suid_dumpable = 2\n"
    assert "SYS202" not in _rules(_scan(tmp_path, text))


def test_root_crash_handler_chain(tmp_path):
    text = "kernel.core_pattern = |/usr/local/bin/pipe\nfs.suid_dumpable = 1\n"
    assert "SYS203" in _rules(_scan(tmp_path, text))


def test_root_crash_handler_safe_without_pipe(tmp_path):
    text = "kernel.core_pattern = core\nfs.suid_dumpable = 1\n"
    assert "SYS203" not in _rules(_scan(tmp_path, text))


def test_forwarding_plus_redirects(tmp_path):
    text = "net.ipv4.ip_forward = 1\nnet.ipv4.conf.eth0.accept_redirects = 1\n"
    assert "SYS204" in _rules(_scan(tmp_path, text))


def test_forwarding_plus_redirects_needs_both(tmp_path):
    text = "net.ipv4.ip_forward = 1\nnet.ipv4.conf.eth0.accept_redirects = 0\n"
    assert "SYS204" not in _rules(_scan(tmp_path, text))


def test_ptrace_dump_chain(tmp_path):
    text = "kernel.yama.ptrace_scope = 0\nfs.suid_dumpable = 1\n"
    assert "SYS205" in _rules(_scan(tmp_path, text))


def test_ptrace_dump_chain_absent_with_scope_one(tmp_path):
    text = "kernel.yama.ptrace_scope = 1\nfs.suid_dumpable = 1\n"
    assert "SYS205" not in _rules(_scan(tmp_path, text))


def test_combo_findings_carry_anchor_evidence(tmp_path):
    text = "kernel.kptr_restrict = 0\nkernel.dmesg_restrict = 0\nkernel.perf_event_paranoid = 1\n"
    report = _scan(tmp_path, text)
    finding = next(f for f in report.findings if f.rule == "SYS201")
    assert finding.line == 1
    assert "kptr_restrict" in finding.message
