# sysctlvet rules

31 rules (9 high, 17 medium, 4 low, 1 note), in three passes: `settings` reads one effective value at a time,
`combos` reads values that are dangerous together, `relations` reads the gaps between files.

## SYS101

**IP forwarding enabled on a host**

- severity: medium (score 5/10)
- pass: settings

`net.ipv4.ip_forward = 1` turns the machine into a router: it forwards packets between interfaces and answers routing queries. On anything that is not meant to be a router or a container host this widens the attack surface and often leaks traffic between networks.

**Fix:** Set net.ipv4.ip_forward = 0 unless the host is a router, a firewall or a container host that needs it.

## SYS102

**ICMP redirects accepted**

- severity: high (score 8/10)
- pass: settings

A host that honours ICMP redirects lets anyone who can send it one packet rewrite its routing table — the classic ICMP redirect MITM. The kernel default is to ignore redirects on hosts; enabling them is only correct on networks with a trusted router and no attacker on-link.

**Fix:** Set net.ipv4.conf.<iface>.accept_redirects = 0 (and the net.ipv6 equivalent) everywhere.

## SYS103

**ICMP redirects sent by this host**

- severity: medium (score 5/10)
- pass: settings

`send_redirects = 1` makes the host act as a router for its neighbours, telling them to reroute traffic. On a plain host this is never needed and the redirect messages help an on-link attacker map and steer the local network.

**Fix:** Set net.ipv4.conf.all.send_redirects = 0 and net.ipv4.conf.default.send_redirects = 0.

## SYS104

**Source routing accepted**

- severity: high (score 8/10)
- pass: settings

IP source routing lets the sender choose the path a packet takes — including a path straight through the target and back out. It has no legitimate use on modern networks and every major hardening baseline disables it.

**Fix:** Set net.ipv4.conf.all.accept_source_route = 0 (and net.ipv6.conf.all.accept_source_route = 0).

## SYS105

**Reverse-path filtering disabled**

- severity: medium (score 5/10)
- pass: settings

`rp_filter = 0` turns off source-address validation: the host accepts packets whose source address could not have come from the interface they arrived on. That is exactly the condition IP spoofing and blind response-riding attacks need.

**Fix:** Set net.ipv4.conf.all.rp_filter = 1 (strict) or 2 (loose) unless asymmetric routing forces 0.

## SYS106

**SYN cookies disabled**

- severity: medium (score 5/10)
- pass: settings

Without SYN cookies a full TCP queue falls over under a trivial SYN flood: every half-open connection occupies memory until it times out. SYN cookies cost nothing when the queue is not full and are the standard defence for exactly this case.

**Fix:** Set net.ipv4.tcp_syncookies = 1.

## SYS107

**Martian packets not logged**

- severity: low (score 3/10)
- pass: settings

`log_martians = 0` silences the kernel's record of packets with impossible source addresses — the single clearest signal of spoofing or scanning activity on the segment. The log line is cheap; losing it blinds the host's own intrusion detection.

**Fix:** Set net.ipv4.conf.all.log_martians = 1 (and enable kernel logging).

## SYS108

**Broadcast pings not ignored**

- severity: medium (score 5/10)
- pass: settings

A host that answers ICMP echo requests sent to the broadcast address takes part in a Smurf amplification attack: one spoofed packet in, hundreds of replies out, aimed at a victim.

**Fix:** Set net.ipv4.icmp_echo_ignore_broadcasts = 1.

## SYS109

**ASLR weakened or disabled**

- severity: high (score 8/10)
- pass: settings

`kernel.randomize_va_space < 2` partially or fully disables address-space layout randomization. Every memory-corruption exploit becomes dramatically easier when addresses are fixed: ASLR is the difference between a crash and a reliable code-execution primitive.

**Fix:** Set kernel.randomize_va_space = 2.

## SYS110

**Kernel pointers readable**

- severity: medium (score 4/10)
- pass: settings

`kptr_restrict = 0` lets unprivileged users read kernel addresses from /proc/kallsyms and dmesg — the raw material for defeating KASLR. With the addresses in hand, a kernel exploit only has to deal with the bug, not with randomization.

**Fix:** Set kernel.kptr_restrict = 1 (hide from unprivileged) or 2 (hide from everyone without CAP_SYSLOG).

## SYS111

**dmesg readable by unprivileged users**

- severity: medium (score 4/10)
- pass: settings

With `kernel.dmesg_restrict = 0` any local user can read the kernel ring buffer, which routinely contains kernel pointers, driver state and details of past crashes — free reconnaissance for a local privilege-escalation attempt.

**Fix:** Set kernel.dmesg_restrict = 1.

## SYS112

**perf available to unprivileged users**

- severity: medium (score 4/10)
- pass: settings

`kernel.perf_event_paranoid < 2` opens the perf subsystem to unprivileged users: kernel-level profiling data leaks addresses and execution details, and perf events have had their own share of kernel bugs.

**Fix:** Set kernel.perf_event_paranoid = 2 (or 3 where perf is not needed at all).

## SYS113

**ptrace attach allowed across processes**

- severity: medium (score 4/10)
- pass: settings

`kernel.yama.ptrace_scope = 0` restores classic ptrace behaviour: any process may attach to any other process of the same user. Malware running as the user can read credentials out of the memory of an ssh-agent or browser; scope 1 confines ptrace to descendants.

**Fix:** Set kernel.yama.ptrace_scope = 1 (or 2 / 3 for stricter environments).

## SYS114

**Unprivileged BPF enabled**

- severity: high (score 8/10)
- pass: settings

With `kernel.unprivileged_bpf_disabled = 0` any local user can load BPF programs — a subsystem that has produced a steady stream of local privilege-escalation bugs. Modern distributions ship this set to 1 or 2 for exactly that reason.

**Fix:** Set kernel.unprivileged_bpf_disabled = 1 (or 2 to lock the setting on).

## SYS115

**SUID crash dumps enabled (debug mode)**

- severity: high (score 8/10)
- pass: settings

`fs.suid_dumpable = 1` is debug mode: SUID/SGID processes dump core like ordinary programs. A crash of a SUID binary then writes its full memory — including credentials — to a user-writable core file. Value 2 (suidsafe) is the safe alternative.

**Fix:** Set fs.suid_dumpable = 0 (or 2 if crash debugging of SUID binaries is required).

## SYS116

**Magic SysRq fully enabled**

- severity: medium (score 4/10)
- pass: settings

`kernel.sysrq = 1` enables every Magic SysRq function, including remount-ro, kill-all and sync — physical console access then becomes a denial-of-service and data-destruction tool. The value is a bitmask; the usual compromise is 176 (sync + remount-ro + signalling).

**Fix:** Set kernel.sysrq = 0 (or a minimal bitmask such as 176) instead of 1.

## SYS117

**Core dumps piped to a program**

- severity: medium (score 6/10)
- pass: settings

A `kernel.core_pattern` beginning with `|` hands every crash dump to a userspace program. Combined with SUID dumps this is a privilege-escalation path (the handler runs as root on a root-owned crash); even alone, a handler in a writable directory is an overwrite target.

**Fix:** Use a plain file pattern (e.g. core) or ensure the pipe handler is root-owned, not writable, and ignores SUID crashes.

## SYS118

**Symlink/hardlink protection disabled**

- severity: medium (score 5/10)
- pass: settings

`fs.protected_symlinks` / `fs.protected_hardlinks` = 0 restores classic link-following behaviour in sticky world-writable directories (/tmp): a user can trick a privileged service into following a planted symlink or hardlink, the root of countless /tmp races.

**Fix:** Set fs.protected_symlinks = 1 and fs.protected_hardlinks = 1.

## SYS119

**IPv6 router advertisements accepted while forwarding**

- severity: medium (score 4/10)
- pass: settings

`net.ipv6.conf.<iface>.accept_ra = 2` accepts router advertisements even when the interface is forwarding. An on-link attacker can then inject routes into a machine that routes other people's traffic — a clean interception position.

**Fix:** Set net.ipv6.conf.<iface>.accept_ra = 0 on forwarding hosts (or 1 if the host is not forwarding).

## SYS120

**kexec allowed**

- severity: low (score 2/10)
- pass: settings

`kernel.kexec_load_disabled = 0` allows loading a new kernel from userspace (kexec). With CAP_SYS_BOOT — held by many containers and by root — an attacker can boot an arbitrary kernel and own the machine below every security control.

**Fix:** Set kernel.kexec_load_disabled = 1 unless kexec-based boot is used operationally.

## SYS199

**Line does not parse as a sysctl assignment**

- severity: note (score 1/10)
- pass: settings

A line the config parser cannot turn into `key = value` never reaches the kernel. It is a setting that only looks configured — a typo here is a silent no-op, the worst failure mode for a hardening file.

**Fix:** Fix the line to `key = value` syntax or delete it.

## SYS201

**KASLR-defeat trifecta**

- severity: high (score 9/10)
- pass: combos

kptr_restrict = 0 and dmesg_restrict = 0 leak kernel addresses to any user, and perf_event_paranoid < 2 adds execution-level detail. Together they hand an attacker the exact layout of kernel memory — KASLR is defeated before any bug is exploited.

**Fix:** Set kernel.kptr_restrict = 1, kernel.dmesg_restrict = 1 and kernel.perf_event_paranoid = 2 together.

## SYS202

**Crash-dump exploit chain (ASLR off + SUID dumps)**

- severity: high (score 9/10)
- pass: combos

With ASLR weakened and fs.suid_dumpable = 1, crashing a SUID binary produces a full memory image at predictable addresses. That is precisely the raw material a local exploit developer needs: stable addresses plus a dump of the privileged process.

**Fix:** Set kernel.randomize_va_space = 2 and fs.suid_dumpable = 0 (or 2).

## SYS203

**Root crash-handler chain (pipe core_pattern + SUID dumps)**

- severity: high (score 9/10)
- pass: combos

A pipe core_pattern runs its handler as root every time something crashes; with fs.suid_dumpable = 1 the trigger can be a SUID binary the attacker runs themselves. The handler's argv includes attacker-influenced paths — a documented privilege-escalation shape.

**Fix:** Set fs.suid_dumpable = 0/2 and keep the pipe handler absolute, root-owned and non-writable.

## SYS204

**Forwarding host accepts ICMP redirects**

- severity: high (score 8/10)
- pass: combos

A machine that both forwards packets and honours ICMP redirects can be steered like a router by anyone on the link: send a redirect, and the forwarded traffic follows the attacker's path. Redirects are only safe on non-forwarding hosts behind a trusted router.

**Fix:** Set accept_redirects = 0 on every interface of a forwarding host.

## SYS205

**ptrace + SUID dump chain**

- severity: medium (score 6/10)
- pass: combos

ptrace_scope = 0 lets same-user processes inspect each other and suid_dumpable = 1 lets SUID binaries be crashed into core files; between the two, the memory of privileged and credential-holding processes is fully readable by ordinary user code.

**Fix:** Set kernel.yama.ptrace_scope = 1 and fs.suid_dumpable = 0 (or 2).

## SYS301

**Hardening silently reverted by a later-loaded file**

- severity: medium (score 7/10)
- pass: relations

This line hardens the key, but a file later in the sysctl load order sets it back to the risky value — and the later file wins. The hardening is dead text: audits that read only this file report a secure host that is actually exposed.

**Fix:** Delete the losing line or change the winning file; one key must have one owner.

## SYS302

**Dead assignment (overridden in the load order)**

- severity: low (score 3/10)
- pass: relations

A later assignment — in this file or a higher-precedence file — overwrites this one before the kernel ever sees it. Dead assignments are how two people's edits quietly cancel out and how a 'configured' setting turns out to be unconfigured.

**Fix:** Remove the dead line, or remove the line that overrides it. One key, one owner.

## SYS303

**Same key written with different separators**

- severity: low (score 3/10)
- pass: relations

`net/ipv4/ip_forward` and `net.ipv4.ip_forward` are the same key — the kernel only knows slashes, the tools accept both — but humans diffing the config see two different settings. One of these lines is dead and the diff hides it.

**Fix:** Pick one spelling (dots are conventional) for every file that touches this key.

## SYS304

**Non-numeric value on a numeric key**

- severity: medium (score 5/10)
- pass: relations

This key takes an integer; a value like `yes` is rejected by the kernel with 'invalid argument' when sysctl applies the file. Depending on the tooling the whole file stops at this line or the line is skipped — either way the settings below may never be applied.

**Fix:** Use the numeric spelling (0 / 1 / …) that the key documents.

## SYS305

**Interface-level setting weakens the global one**

- severity: medium (score 5/10)
- pass: relations

The global (`conf.all`) value is hardened but one named interface carries the risky value. Per-interface settings are what that interface actually uses: the global hardening looks good in the config and does not protect the interface that matters.

**Fix:** Set the interface-level value to match the global one, or drop the interface-level override.
