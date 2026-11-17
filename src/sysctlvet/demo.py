"""The embedded demo corpus: a host configured by four different people.

The file names matter — they decide the load order, exactly like on a real
machine: the vendor baseline loses to the site policy, the site policy loses
to local tweaks, and /etc/sysctl.conf loses to nobody.  Every rule in the
rulebook fires at least once against these four files (there is a test).
"""

from __future__ import annotations

from .model import ConfigFile, Report
from .parsers import parse
from .resolve import load_key, resolve, tier_of
from .rules import REGISTRY, evaluate

VENDOR = """\
# /usr/lib/sysctl.d/50-default.conf -- vendor baseline, later files disagree.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.rp_filter = 1
kernel.randomize_va_space = 2
net.ipv4.tcp_syncookies = 1
"""

SITE = """\
# /etc/sysctl.d/10-network.conf -- site network policy.
net/ipv4/ip_forward = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.all.log_martians = 0
net.ipv6.conf.all.accept_ra = 2
fs.protected_symlinks = 0
fs.protected_hardlinks = 0
"""

LOCAL = """\
# /etc/sysctl.d/99-local.conf -- local tweaks, these win over 10-network.conf.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.rp_filter = 0
net/ipv4/conf/eth0/accept_redirects = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.ip_forward = 1
kernel.core_pattern = core
net.ipv4.ip_nonlocal_bind = yes
this line is not a sysctl assignment
"""

SYSCONF = """\
# /etc/sysctl.conf -- applied last by procps, and it shows.
kernel.randomize_va_space = 0
kernel.kptr_restrict = 0
kernel.dmesg_restrict = 0
kernel.perf_event_paranoid = 1
kernel.yama.ptrace_scope = 0
kernel.unprivileged_bpf_disabled = 0
fs.suid_dumpable = 1
kernel.sysrq = 1
kernel.core_pattern = |/usr/local/bin/crashpipe
kernel.kexec_load_disabled = 0
net.ipv4.tcp_syncookies = 0
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv4.conf.all.send_redirects = 1
"""

DEMO_FILES: dict[str, str] = {
    "usr/lib/sysctl.d/50-default.conf": VENDOR,
    "etc/sysctl.d/10-network.conf": SITE,
    "etc/sysctl.d/99-local.conf": LOCAL,
    "etc/sysctl.conf": SYSCONF,
}


def demo_targets() -> list[ConfigFile]:
    out = []
    for name, text in DEMO_FILES.items():
        config = parse(text, name)
        config.tier = tier_of(name)
        config.load_key = load_key(name)
        out.append(config)
    return out


def run_demo() -> Report:
    targets = demo_targets()
    eff = resolve(targets)
    findings = evaluate(targets, eff)
    return Report(
        source="sysctlvet demo (embedded corpus)",
        targets=targets,
        findings=findings,
        rules_run=len(REGISTRY),
        rule_ids=sorted(item.id for item in REGISTRY),
    )
