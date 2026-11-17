"""The rule engine: 31 rules in three passes.

``settings``  one effective value at a time — what does *this* setting expose?
``combos``    values that are dangerous together (dump chains, KASLR defeat).
``relations`` between files — dead settings, reverted hardening, duplicates.

Every conclusion is drawn from the **effective** value (the line that wins
the load order), never from a line that is already dead.  Rules may co-fire
on purpose: a dead hardening line is both dead text (SYS302) and, when the
winner is the risky value, a silent hardening revert (SYS301).
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Assignment, ConfigFile, Effective, Finding
from .resolve import resolve


@dataclass(frozen=True)
class RuleInfo:
    id: str
    title: str
    severity: str
    stage: str  # settings | combos | relations
    score: int
    why: str
    fix: str


REGISTRY: list[RuleInfo] = [
    RuleInfo(
        id="SYS101",
        title="IP forwarding enabled on a host",
        severity="medium",
        stage="settings",
        score=5,
        why=(
            "`net.ipv4.ip_forward = 1` turns the machine into a router: it forwards packets between "
            "interfaces and answers routing queries. On anything that is not meant to be a router or "
            "a container host this widens the attack surface and often leaks traffic between networks."
        ),
        fix="Set net.ipv4.ip_forward = 0 unless the host is a router, a firewall or a container host that needs it.",
    ),
    RuleInfo(
        id="SYS102",
        title="ICMP redirects accepted",
        severity="high",
        stage="settings",
        score=8,
        why=(
            "A host that honours ICMP redirects lets anyone who can send it one packet rewrite its routing "
            "table — the classic ICMP redirect MITM. The kernel default is to ignore redirects on hosts; "
            "enabling them is only correct on networks with a trusted router and no attacker on-link."
        ),
        fix="Set net.ipv4.conf.<iface>.accept_redirects = 0 (and the net.ipv6 equivalent) everywhere.",
    ),
    RuleInfo(
        id="SYS103",
        title="ICMP redirects sent by this host",
        severity="medium",
        stage="settings",
        score=5,
        why=(
            "`send_redirects = 1` makes the host act as a router for its neighbours, telling them to reroute "
            "traffic. On a plain host this is never needed and the redirect messages help an on-link attacker "
            "map and steer the local network."
        ),
        fix="Set net.ipv4.conf.all.send_redirects = 0 and net.ipv4.conf.default.send_redirects = 0.",
    ),
    RuleInfo(
        id="SYS104",
        title="Source routing accepted",
        severity="high",
        stage="settings",
        score=8,
        why=(
            "IP source routing lets the sender choose the path a packet takes — including a path straight "
            "through the target and back out. It has no legitimate use on modern networks and every major "
            "hardening baseline disables it."
        ),
        fix="Set net.ipv4.conf.all.accept_source_route = 0 (and net.ipv6.conf.all.accept_source_route = 0).",
    ),
    RuleInfo(
        id="SYS105",
        title="Reverse-path filtering disabled",
        severity="medium",
        stage="settings",
        score=5,
        why=(
            "`rp_filter = 0` turns off source-address validation: the host accepts packets whose source "
            "address could not have come from the interface they arrived on. That is exactly the condition "
            "IP spoofing and blind response-riding attacks need."
        ),
        fix="Set net.ipv4.conf.all.rp_filter = 1 (strict) or 2 (loose) unless asymmetric routing forces 0.",
    ),
    RuleInfo(
        id="SYS106",
        title="SYN cookies disabled",
        severity="medium",
        stage="settings",
        score=5,
        why=(
            "Without SYN cookies a full TCP queue falls over under a trivial SYN flood: every half-open "
            "connection occupies memory until it times out. SYN cookies cost nothing when the queue is not "
            "full and are the standard defence for exactly this case."
        ),
        fix="Set net.ipv4.tcp_syncookies = 1.",
    ),
    RuleInfo(
        id="SYS107",
        title="Martian packets not logged",
        severity="low",
        stage="settings",
        score=3,
        why=(
            "`log_martians = 0` silences the kernel's record of packets with impossible source addresses — "
            "the single clearest signal of spoofing or scanning activity on the segment. The log line is "
            "cheap; losing it blinds the host's own intrusion detection."
        ),
        fix="Set net.ipv4.conf.all.log_martians = 1 (and enable kernel logging).",
    ),
    RuleInfo(
        id="SYS108",
        title="Broadcast pings not ignored",
        severity="medium",
        stage="settings",
        score=5,
        why=(
            "A host that answers ICMP echo requests sent to the broadcast address takes part in a Smurf "
            "amplification attack: one spoofed packet in, hundreds of replies out, aimed at a victim."
        ),
        fix="Set net.ipv4.icmp_echo_ignore_broadcasts = 1.",
    ),
    RuleInfo(
        id="SYS109",
        title="ASLR weakened or disabled",
        severity="high",
        stage="settings",
        score=8,
        why=(
            "`kernel.randomize_va_space < 2` partially or fully disables address-space layout randomization. "
            "Every memory-corruption exploit becomes dramatically easier when addresses are fixed: ASLR is "
            "the difference between a crash and a reliable code-execution primitive."
        ),
        fix="Set kernel.randomize_va_space = 2.",
    ),
    RuleInfo(
        id="SYS110",
        title="Kernel pointers readable",
        severity="medium",
        stage="settings",
        score=4,
        why=(
            "`kptr_restrict = 0` lets unprivileged users read kernel addresses from /proc/kallsyms and dmesg "
            "— the raw material for defeating KASLR. With the addresses in hand, a kernel exploit only has "
            "to deal with the bug, not with randomization."
        ),
        fix="Set kernel.kptr_restrict = 1 (hide from unprivileged) or 2 (hide from everyone without CAP_SYSLOG).",
    ),
    RuleInfo(
        id="SYS111",
        title="dmesg readable by unprivileged users",
        severity="medium",
        stage="settings",
        score=4,
        why=(
            "With `kernel.dmesg_restrict = 0` any local user can read the kernel ring buffer, which routinely "
            "contains kernel pointers, driver state and details of past crashes — free reconnaissance for a "
            "local privilege-escalation attempt."
        ),
        fix="Set kernel.dmesg_restrict = 1.",
    ),
    RuleInfo(
        id="SYS112",
        title="perf available to unprivileged users",
        severity="medium",
        stage="settings",
        score=4,
        why=(
            "`kernel.perf_event_paranoid < 2` opens the perf subsystem to unprivileged users: kernel-level "
            "profiling data leaks addresses and execution details, and perf events have had their own "
            "share of kernel bugs."
        ),
        fix="Set kernel.perf_event_paranoid = 2 (or 3 where perf is not needed at all).",
    ),
    RuleInfo(
        id="SYS113",
        title="ptrace attach allowed across processes",
        severity="medium",
        stage="settings",
        score=4,
        why=(
            "`kernel.yama.ptrace_scope = 0` restores classic ptrace behaviour: any process may attach to any "
            "other process of the same user. Malware running as the user can read credentials out of the "
            "memory of an ssh-agent or browser; scope 1 confines ptrace to descendants."
        ),
        fix="Set kernel.yama.ptrace_scope = 1 (or 2 / 3 for stricter environments).",
    ),
    RuleInfo(
        id="SYS114",
        title="Unprivileged BPF enabled",
        severity="high",
        stage="settings",
        score=8,
        why=(
            "With `kernel.unprivileged_bpf_disabled = 0` any local user can load BPF programs — a subsystem "
            "that has produced a steady stream of local privilege-escalation bugs. Modern distributions ship "
            "this set to 1 or 2 for exactly that reason."
        ),
        fix="Set kernel.unprivileged_bpf_disabled = 1 (or 2 to lock the setting on).",
    ),
    RuleInfo(
        id="SYS115",
        title="SUID crash dumps enabled (debug mode)",
        severity="high",
        stage="settings",
        score=8,
        why=(
            "`fs.suid_dumpable = 1` is debug mode: SUID/SGID processes dump core like ordinary programs. "
            "A crash of a SUID binary then writes its full memory — including credentials — to a "
            "user-writable core file. Value 2 (suidsafe) is the safe alternative."
        ),
        fix="Set fs.suid_dumpable = 0 (or 2 if crash debugging of SUID binaries is required).",
    ),
    RuleInfo(
        id="SYS116",
        title="Magic SysRq fully enabled",
        severity="medium",
        stage="settings",
        score=4,
        why=(
            "`kernel.sysrq = 1` enables every Magic SysRq function, including remount-ro, kill-all and "
            "sync — physical console access then becomes a denial-of-service and data-destruction tool. "
            "The value is a bitmask; the usual compromise is 176 (sync + remount-ro + signalling)."
        ),
        fix="Set kernel.sysrq = 0 (or a minimal bitmask such as 176) instead of 1.",
    ),
    RuleInfo(
        id="SYS117",
        title="Core dumps piped to a program",
        severity="medium",
        stage="settings",
        score=6,
        why=(
            "A `kernel.core_pattern` beginning with `|` hands every crash dump to a userspace program. "
            "Combined with SUID dumps this is a privilege-escalation path (the handler runs as root on "
            "a root-owned crash); even alone, a handler in a writable directory is an overwrite target."
        ),
        fix="Use a plain file pattern (e.g. core) or ensure the pipe handler is root-owned, not writable, and ignores SUID crashes.",
    ),
    RuleInfo(
        id="SYS118",
        title="Symlink/hardlink protection disabled",
        severity="medium",
        stage="settings",
        score=5,
        why=(
            "`fs.protected_symlinks` / `fs.protected_hardlinks` = 0 restores classic link-following "
            "behaviour in sticky world-writable directories (/tmp): a user can trick a privileged service "
            "into following a planted symlink or hardlink, the root of countless /tmp races."
        ),
        fix="Set fs.protected_symlinks = 1 and fs.protected_hardlinks = 1.",
    ),
    RuleInfo(
        id="SYS119",
        title="IPv6 router advertisements accepted while forwarding",
        severity="medium",
        stage="settings",
        score=4,
        why=(
            "`net.ipv6.conf.<iface>.accept_ra = 2` accepts router advertisements even when the interface "
            "is forwarding. An on-link attacker can then inject routes into a machine that routes other "
            "people's traffic — a clean interception position."
        ),
        fix="Set net.ipv6.conf.<iface>.accept_ra = 0 on forwarding hosts (or 1 if the host is not forwarding).",
    ),
    RuleInfo(
        id="SYS120",
        title="kexec allowed",
        severity="low",
        stage="settings",
        score=2,
        why=(
            "`kernel.kexec_load_disabled = 0` allows loading a new kernel from userspace (kexec). With "
            "CAP_SYS_BOOT — held by many containers and by root — an attacker can boot an arbitrary "
            "kernel and own the machine below every security control."
        ),
        fix="Set kernel.kexec_load_disabled = 1 unless kexec-based boot is used operationally.",
    ),
    RuleInfo(
        id="SYS199",
        title="Line does not parse as a sysctl assignment",
        severity="note",
        stage="settings",
        score=1,
        why=(
            "A line the config parser cannot turn into `key = value` never reaches the kernel. It is a "
            "setting that only looks configured — a typo here is a silent no-op, the worst failure mode "
            "for a hardening file."
        ),
        fix="Fix the line to `key = value` syntax or delete it.",
    ),
    RuleInfo(
        id="SYS201",
        title="KASLR-defeat trifecta",
        severity="high",
        stage="combos",
        score=9,
        why=(
            "kptr_restrict = 0 and dmesg_restrict = 0 leak kernel addresses to any user, and "
            "perf_event_paranoid < 2 adds execution-level detail. Together they hand an attacker the "
            "exact layout of kernel memory — KASLR is defeated before any bug is exploited."
        ),
        fix="Set kernel.kptr_restrict = 1, kernel.dmesg_restrict = 1 and kernel.perf_event_paranoid = 2 together.",
    ),
    RuleInfo(
        id="SYS202",
        title="Crash-dump exploit chain (ASLR off + SUID dumps)",
        severity="high",
        stage="combos",
        score=9,
        why=(
            "With ASLR weakened and fs.suid_dumpable = 1, crashing a SUID binary produces a full memory "
            "image at predictable addresses. That is precisely the raw material a local exploit developer "
            "needs: stable addresses plus a dump of the privileged process."
        ),
        fix="Set kernel.randomize_va_space = 2 and fs.suid_dumpable = 0 (or 2).",
    ),
    RuleInfo(
        id="SYS203",
        title="Root crash-handler chain (pipe core_pattern + SUID dumps)",
        severity="high",
        stage="combos",
        score=9,
        why=(
            "A pipe core_pattern runs its handler as root every time something crashes; with "
            "fs.suid_dumpable = 1 the trigger can be a SUID binary the attacker runs themselves. "
            "The handler's argv includes attacker-influenced paths — a documented privilege-escalation shape."
        ),
        fix="Set fs.suid_dumpable = 0/2 and keep the pipe handler absolute, root-owned and non-writable.",
    ),
    RuleInfo(
        id="SYS204",
        title="Forwarding host accepts ICMP redirects",
        severity="high",
        stage="combos",
        score=8,
        why=(
            "A machine that both forwards packets and honours ICMP redirects can be steered like a router "
            "by anyone on the link: send a redirect, and the forwarded traffic follows the attacker's path. "
            "Redirects are only safe on non-forwarding hosts behind a trusted router."
        ),
        fix="Set accept_redirects = 0 on every interface of a forwarding host.",
    ),
    RuleInfo(
        id="SYS205",
        title="ptrace + SUID dump chain",
        severity="medium",
        stage="combos",
        score=6,
        why=(
            "ptrace_scope = 0 lets same-user processes inspect each other and suid_dumpable = 1 lets "
            "SUID binaries be crashed into core files; between the two, the memory of privileged and "
            "credential-holding processes is fully readable by ordinary user code."
        ),
        fix="Set kernel.yama.ptrace_scope = 1 and fs.suid_dumpable = 0 (or 2).",
    ),
    RuleInfo(
        id="SYS301",
        title="Hardening silently reverted by a later-loaded file",
        severity="medium",
        stage="relations",
        score=7,
        why=(
            "This line hardens the key, but a file later in the sysctl load order sets it back to the "
            "risky value — and the later file wins. The hardening is dead text: audits that read only "
            "this file report a secure host that is actually exposed."
        ),
        fix="Delete the losing line or change the winning file; one key must have one owner.",
    ),
    RuleInfo(
        id="SYS302",
        title="Dead assignment (overridden in the load order)",
        severity="low",
        stage="relations",
        score=3,
        why=(
            "A later assignment — in this file or a higher-precedence file — overwrites this one before "
            "the kernel ever sees it. Dead assignments are how two people's edits quietly cancel out and "
            "how a 'configured' setting turns out to be unconfigured."
        ),
        fix="Remove the dead line, or remove the line that overrides it. One key, one owner.",
    ),
    RuleInfo(
        id="SYS303",
        title="Same key written with different separators",
        severity="low",
        stage="relations",
        score=3,
        why=(
            "`net/ipv4/ip_forward` and `net.ipv4.ip_forward` are the same key — the kernel only knows "
            "slashes, the tools accept both — but humans diffing the config see two different settings. "
            "One of these lines is dead and the diff hides it."
        ),
        fix="Pick one spelling (dots are conventional) for every file that touches this key.",
    ),
    RuleInfo(
        id="SYS304",
        title="Non-numeric value on a numeric key",
        severity="medium",
        stage="relations",
        score=5,
        why=(
            "This key takes an integer; a value like `yes` is rejected by the kernel with 'invalid "
            "argument' when sysctl applies the file. Depending on the tooling the whole file stops at "
            "this line or the line is skipped — either way the settings below may never be applied."
        ),
        fix="Use the numeric spelling (0 / 1 / …) that the key documents.",
    ),
    RuleInfo(
        id="SYS305",
        title="Interface-level setting weakens the global one",
        severity="medium",
        stage="relations",
        score=5,
        why=(
            "The global (`conf.all`) value is hardened but one named interface carries the risky value. "
            "Per-interface settings are what that interface actually uses: the global hardening looks "
            "good in the config and does not protect the interface that matters."
        ),
        fix="Set the interface-level value to match the global one, or drop the interface-level override.",
    ),
]

RULES_BY_ID: dict[str, RuleInfo] = {item.id: item for item in REGISTRY}

# ---------------------------------------------------------------------------
# Pass 1 catalog: key patterns and the value predicate that marks them risky.
# A pattern segment of `*` matches exactly one key segment (e.g. an interface).
# ---------------------------------------------------------------------------


def _is(value: int | None, target: int) -> bool:
    return value == target


def _below(value: int | None, bound: int) -> bool:
    return value is not None and value < bound


KEY_RULES: list[tuple[str, list[str], object, str]] = [
    ("SYS101", ["net.ipv4.ip_forward"], lambda n, s: _is(n, 1), "{key} = {value} turns the host into a router"),
    (
        "SYS102",
        ["net.ipv4.conf.*.accept_redirects", "net.ipv6.conf.*.accept_redirects"],
        lambda n, s: _is(n, 1),
        "{key} = {value} accepts ICMP redirects (on-link MITM)",
    ),
    (
        "SYS103",
        ["net.ipv4.conf.*.send_redirects"],
        lambda n, s: _is(n, 1),
        "{key} = {value} makes the host send ICMP redirects",
    ),
    (
        "SYS104",
        ["net.ipv4.conf.*.accept_source_route", "net.ipv6.conf.*.accept_source_route"],
        lambda n, s: _is(n, 1),
        "{key} = {value} accepts source-routed packets",
    ),
    (
        "SYS105",
        ["net.ipv4.conf.*.rp_filter"],
        lambda n, s: _is(n, 0),
        "{key} = {value} disables reverse-path (source address) validation",
    ),
    ("SYS106", ["net.ipv4.tcp_syncookies"], lambda n, s: _is(n, 0), "{key} = {value} disables SYN cookies"),
    (
        "SYS107",
        ["net.ipv4.conf.*.log_martians"],
        lambda n, s: _is(n, 0),
        "{key} = {value} stops logging spoofed (martian) packets",
    ),
    (
        "SYS108",
        ["net.ipv4.icmp_echo_ignore_broadcasts"],
        lambda n, s: _is(n, 0),
        "{key} = {value} answers broadcast pings (Smurf amplifier)",
    ),
    (
        "SYS109",
        ["kernel.randomize_va_space"],
        lambda n, s: _below(n, 2),
        "{key} = {value} weakens or disables ASLR",
    ),
    ("SYS110", ["kernel.kptr_restrict"], lambda n, s: _is(n, 0), "{key} = {value} exposes kernel pointers to users"),
    ("SYS111", ["kernel.dmesg_restrict"], lambda n, s: _is(n, 0), "{key} = {value} lets unprivileged users read dmesg"),
    (
        "SYS112",
        ["kernel.perf_event_paranoid"],
        lambda n, s: _below(n, 2),
        "{key} = {value} opens perf to unprivileged users",
    ),
    (
        "SYS113",
        ["kernel.yama.ptrace_scope"],
        lambda n, s: _is(n, 0),
        "{key} = {value} allows ptrace attach between same-user processes",
    ),
    (
        "SYS114",
        ["kernel.unprivileged_bpf_disabled"],
        lambda n, s: _is(n, 0),
        "{key} = {value} allows unprivileged BPF program loading",
    ),
    (
        "SYS115",
        ["fs.suid_dumpable"],
        lambda n, s: _is(n, 1),
        "{key} = {value} enables crash dumps for SUID binaries (debug mode)",
    ),
    ("SYS116", ["kernel.sysrq"], lambda n, s: _is(n, 1), "{key} = {value} enables every Magic SysRq function"),
    (
        "SYS117",
        ["kernel.core_pattern"],
        lambda n, s: s.startswith("|"),
        "{key} = {value} pipes crash dumps to a userspace program",
    ),
    (
        "SYS118",
        ["fs.protected_symlinks", "fs.protected_hardlinks"],
        lambda n, s: _is(n, 0),
        "{key} = {value} disables link-following protection",
    ),
    (
        "SYS119",
        ["net.ipv6.conf.*.accept_ra"],
        lambda n, s: _is(n, 2),
        "{key} = {value} accepts router advertisements even while forwarding",
    ),
    (
        "SYS120",
        ["kernel.kexec_load_disabled"],
        lambda n, s: _is(n, 0),
        "{key} = {value} allows loading a new kernel via kexec",
    ),
]

# Keys known to take integer values.  Used by SYS304: assigning a string to
# one of these is rejected by the kernel when the file is applied.
EXTRA_NUMERIC_KEYS = {
    "net.ipv4.ip_nonlocal_bind",
    "net.ipv4.tcp_max_syn_backlog",
    "net.ipv4.tcp_fin_timeout",
    "net.core.somaxconn",
    "vm.swappiness",
    "fs.file-max",
    "kernel.threads-max",
}

STRING_KEYS = {"kernel.core_pattern", "kernel.modprobe", "kernel.hotplug", "kernel.hostname", "kernel.domainname"}


def _match(pattern: str, key: str) -> bool:
    parts = pattern.lower().split(".")
    actual = key.lower().split(".")
    if len(parts) != len(actual):
        return False
    return all(p == "*" or p == a for p, a in zip(parts, actual, strict=True))


def _known_numeric(key: str) -> bool:
    if key in STRING_KEYS or key in EXTRA_NUMERIC_KEYS:
        return key in EXTRA_NUMERIC_KEYS
    return any(_match(pattern, key) for _, patterns, _, _ in KEY_RULES for pattern in patterns)


def _finding(info: RuleInfo, where: str, line: int, offset: int, length: int, saw: str, message: str) -> Finding:
    return Finding(
        rule=info.id,
        severity=info.severity,
        message=message,
        line=line,
        offset=offset,
        length=length,
        saw=saw,
        fix=info.fix,
        where=where,
        score=info.score,
    )


def _num(eff: dict[str, Effective], key: str) -> int | None:
    entry = eff.get(key)
    return entry.winner.numeric if entry else None


def _str_value(eff: dict[str, Effective], key: str) -> str | None:
    entry = eff.get(key)
    return entry.winner.value if entry else None


def _pick(eff: dict[str, Effective], keys: list[str]) -> Assignment | None:
    for key in keys:
        entry = eff.get(key)
        if entry is not None:
            return entry.winner
    return None


# ---------------------------------------------------------------------------
# Passes
# ---------------------------------------------------------------------------


def pass_settings(files: list[ConfigFile], eff: dict[str, Effective]) -> list[Finding]:
    out: list[Finding] = []
    for key in sorted(eff):
        entry = eff[key]
        winner = entry.winner
        for rule_id, patterns, bad, template in KEY_RULES:
            if not any(_match(pattern, key) for pattern in patterns):
                continue
            if not bad(winner.numeric, winner.value):
                continue
            info = RULES_BY_ID[rule_id]
            out.append(
                _finding(
                    info,
                    winner.file,
                    winner.line,
                    winner.offset,
                    winner.length,
                    winner.saw,
                    template.format(key=key, value=winner.value),
                )
            )
    for config in files:
        for line, offset, raw in config.warnings:
            info = RULES_BY_ID["SYS199"]
            out.append(
                _finding(info, config.source, line, offset, len(raw), " ".join(raw.split())[:160], "line does not parse as key = value")
            )
    return out


def pass_combos(eff: dict[str, Effective]) -> list[Finding]:
    out: list[Finding] = []

    def emit(rule_id: str, keys: list[str], message: str) -> None:
        anchor = _pick(eff, keys)
        if anchor is None:
            return
        info = RULES_BY_ID[rule_id]
        out.append(_finding(info, anchor.file, anchor.line, anchor.offset, anchor.length, anchor.saw, message))

    kptr, dmesg, perf = "kernel.kptr_restrict", "kernel.dmesg_restrict", "kernel.perf_event_paranoid"
    if _num(eff, kptr) == 0 and _num(eff, dmesg) == 0 and (_num(eff, perf) is not None and _num(eff, perf) < 2):
        emit(
            "SYS201",
            [kptr, dmesg, perf],
            f"KASLR-defeat trifecta: {kptr} = {_str_value(eff, kptr)}, {dmesg} = {_str_value(eff, dmesg)}, "
            f"{perf} = {_str_value(eff, perf)}",
        )

    aslr, suid = "kernel.randomize_va_space", "fs.suid_dumpable"
    if (_num(eff, aslr) is not None and _num(eff, aslr) < 2) and _num(eff, suid) == 1:
        emit(
            "SYS202",
            [aslr, suid],
            f"crash-dump exploit chain: ASLR weakened ({aslr} = {_str_value(eff, aslr)}) "
            f"while SUID dumps are enabled ({suid} = {_str_value(eff, suid)})",
        )

    core = "kernel.core_pattern"
    core_value = _str_value(eff, core)
    if core_value and core_value.startswith("|") and _num(eff, suid) == 1:
        emit(
            "SYS203",
            [core, suid],
            f"root crash-handler chain: {core} = {core_value} runs a handler as root while "
            f"{suid} = {_str_value(eff, suid)} dumps SUID crashes",
        )

    ipf = "net.ipv4.ip_forward"
    redirect_keys = sorted(k for k in eff if _match("net.ipv4.conf.*.accept_redirects", k) or _match("net.ipv6.conf.*.accept_redirects", k))
    risky_redirects = [k for k in redirect_keys if eff[k].winner.numeric == 1]
    if _num(eff, ipf) == 1 and risky_redirects:
        first = risky_redirects[0]
        emit(
            "SYS204",
            [ipf, first],
            f"forwarding host accepts ICMP redirects: {ipf} = {_str_value(eff, ipf)} with {first} = {_str_value(eff, first)}",
        )

    ptrace = "kernel.yama.ptrace_scope"
    if _num(eff, ptrace) == 0 and _num(eff, suid) == 1:
        emit(
            "SYS205",
            [ptrace, suid],
            f"ptrace + dump chain: {ptrace} = {_str_value(eff, ptrace)} and {suid} = {_str_value(eff, suid)}",
        )

    return out


def pass_relations(files: list[ConfigFile], eff: dict[str, Effective]) -> list[Finding]:
    out: list[Finding] = []

    def bad_of(entry: Effective, assignment: Assignment) -> bool:
        for _rule_id, patterns, bad, _ in KEY_RULES:
            if any(_match(pattern, entry.key) for pattern in patterns):
                return bool(bad(assignment.numeric, assignment.value))
        return False

    # Dead assignments.  A reverted hardening line is both concerns at once:
    # dead text (SYS302) and a silent hardening revert (SYS301) — co-fire.
    for key in sorted(eff):
        entry = eff[key]
        winner = entry.winner
        for loser in entry.losers:
            reverted = bad_of(entry, loser) is False and bad_of(entry, winner) is True
            if reverted:
                info = RULES_BY_ID["SYS301"]
                message = (
                    f"hardening {key} = {loser.value} is silently reverted: "
                    f"{winner.file}:{winner.line} sets it back to {winner.value}"
                )
                out.append(_finding(info, loser.file, loser.line, loser.offset, loser.length, loser.saw, message))
            info = RULES_BY_ID["SYS302"]
            where = "later in the same file" if loser.file == winner.file else f"{winner.file}:{winner.line}"
            message = f"dead assignment: {key} = {loser.value} is overridden by {where} (= {winner.value})"
            out.append(_finding(info, loser.file, loser.line, loser.offset, loser.length, loser.saw, message))

    # Separator-style duplicates: same key, different spelling in the raw text.
    for key in sorted(eff):
        entry = eff[key]
        seen: dict[str, Assignment] = {}
        for assignment in entry.assignments:
            shape = "slash" if "/" in assignment.raw_key else "dot"
            other = seen.get("dot" if shape == "slash" else "slash")
            if other is not None:
                info = RULES_BY_ID["SYS303"]
                message = (
                    f"{assignment.raw_key} and {other.raw_key} are the same key ({key}) written with "
                    f"different separators; {other.file}:{other.line} uses the other spelling"
                )
                out.append(
                    _finding(info, assignment.file, assignment.line, assignment.offset, assignment.length, assignment.saw, message)
                )
                break  # one conclusion per key is enough
            seen[shape] = assignment

    # Numeric keys carrying a string value.
    for key in sorted(eff):
        entry = eff[key]
        winner = entry.winner
        if _known_numeric(key) and winner.numeric is None:
            info = RULES_BY_ID["SYS304"]
            message = f"{key} = {winner.value} is not a number; the kernel rejects this line when the file is applied"
            out.append(_finding(info, winner.file, winner.line, winner.offset, winner.length, winner.saw, message))

    # Interface-level settings weakening the global value.
    for key in sorted(eff):
        entry = eff[key]
        winner = entry.winner
        parts = key.split(".")
        # net.ipv4.conf.<iface>.<prop> — the rule fires when <iface> is named
        # and the conf.all twin for the same property is hardened.
        if len(parts) != 5 or parts[:3] not in (["net", "ipv4", "conf"], ["net", "ipv6", "conf"]):
            continue
        iface, prop = parts[3], parts[4]
        if iface in ("all", "default"):
            continue
        all_key = f"{parts[0]}.{parts[1]}.conf.all.{prop}"
        all_entry = eff.get(all_key)
        if all_entry is None:
            continue
        risky_here = bad_of(entry, winner)
        safe_there = not bad_of(all_entry, all_entry.winner)
        if risky_here and safe_there:
            info = RULES_BY_ID["SYS305"]
            message = (
                f"{key} = {winner.value} weakens the global {all_key} = {all_entry.winner.value}: "
                f"the interface uses its own value"
            )
            out.append(_finding(info, winner.file, winner.line, winner.offset, winner.length, winner.saw, message))

    return out


def evaluate(files: list[ConfigFile], eff: dict[str, Effective] | None = None) -> list[Finding]:
    """Run all three passes over parsed files (resolving precedence if needed)."""
    if eff is None:
        eff = resolve(files)
    findings = pass_settings(files, eff) + pass_combos(eff) + pass_relations(files, eff)
    return sorted(findings, key=lambda f: f.sort_key())
