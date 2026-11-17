# Promotion drafts (awaiting the author's sign-off — automation never posts)

Four channel drafts for sysctlvet. Do not post without xuange-hu's explicit
confirmation.

---

## Show HN

**Title:** Show HN: sysctlvet – audit which sysctl line actually wins

**Body:**

Every Linux box is "hardened" by four config files that quietly overwrite
each other. `/usr/lib/sysctl.d/50-default.conf` sets `randomize_va_space = 2`,
someone's `/etc/sysctl.conf` sets it back to 0, and every audit that reads one
file reports a secure machine.

sysctlvet is a zero-dependency Python auditor for sysctl.conf + sysctl.d that
models the real load order (`sysctl --system`: usr/lib loses to run loses to
etc/sysctl.d loses to /etc/sysctl.conf; lexicographic within a directory) and
tells you:

- which line wins for each key (and every dead line it overrode),
- when a hardening line is *silently reverted* by a later file (SYS301),
- dangerous combinations (KASLR-defeat trifecta, core_pattern + SUID dump
  chains), interface-level overrides that weaken the global value, and
  `net/ipv4/...` vs `net.ipv4...` separator duplicates that diffs hide.

31 rules, evidence-first (file/line/byte-offset/raw), SARIF + `--fail-on`
for CI, and 6 MCP tools so agents can ask "which line wins?" directly.

`pip install git+https://github.com/xuange-hu/sysctlvet` · 162 tests ·
demo corpus fires all 31 rules: `sysctlvet demo`

Curious whether other people's sysctl.d trees are as messy as mine — happy to
hear which rules you'd add (I deliberately do NOT flag absent keys).

---

## Reddit r/netsec / r/linuxadmin

**Title:** I got tired of sysctl.d files silently undoing each other, so I wrote an auditor that resolves the real load order

**Body:**

The scenario: a CIS hardening playbook sets `net.ipv4.conf.all.accept_redirects = 0`
in `/etc/sysctl.d/10-network.conf`, and a vendor package drops
`99-tuning.conf` that sets it back to 1. `sysctl --system` applies both,
silently, last one wins. Nothing complains — not systemd, not the audit tool
that only reads one file.

sysctlvet (MIT, zero dependencies, Python 3.10+) parses the whole tree and
resolves precedence the way procps actually loads it, then runs three passes:

1. settings — the risky values themselves (redirects, source routing, ASLR,
   unprivileged BPF, SUID dumps, …)
2. combos — values dangerous together: kptr_restrict=0 + dmesg_restrict=0 +
   perf_event_paranoid<2 hands an attacker the kernel layout; core_pattern
   pipe + suid_dumpable=1 is the classic root crash-handler chain
3. relations — dead assignments, hardening silently reverted (the money
   finding), slash-vs-dot duplicate keys, non-numeric values on numeric keys
   (rejected by the kernel when applied), interface values that weaken
   conf.all

Evidence-first: every finding carries file, line, byte offset and the raw
line. SARIF output + `--fail-on high` for CI, and an `effective` command that
answers "who wins for this key" with the dead lines listed.

Design decision I'd defend in review: absent keys are NOT findings — the
kernel defaults are sane on modern kernels and flagging absence drowns the
signal. Happy to be argued out of it.

https://github.com/xuange-hu/sysctlvet

---

## X (thread)

1/ My Linux hardening lesson of the week: the worst misconfiguration is the
one a later file silently undid. I audited my sysctl.d tree and found a
"hardened" ASLR setting that /etc/sysctl.conf had been setting back to 0
for months. Nobody notices — `sysctl --system` is silent by design.

2/ So I built sysctlvet: a zero-dependency auditor that resolves the real
sysctl load order first, then judges only the values that actually reach
the kernel. Dead lines get their own conclusion ("your hardening here is
dead") instead of a clean bill of health.

3/ The rule that keeps paying rent: SYS301 "hardening silently reverted" —
safe value in file A, risky value in file B that loads later. File A looks
perfect in review. Also: `net/ipv4/ip_forward` and `net.ipv4.ip_forward`
are the same key, and the diff won't tell you.

4/ 31 rules in 3 passes (settings / dangerous combos / relations between
files), evidence-first with byte offsets, SARIF for CI, and MCP tools so
your agent can ask "which line wins for this key?". 162 tests, MIT:
https://github.com/xuange-hu/sysctlvet

---

## Awesome-list submission blurb

> [sysctlvet](https://github.com/xuange-hu/sysctlvet) — Zero-dependency
> auditor for sysctl.conf / sysctl.d that resolves the real `sysctl --system`
> load order, flags hardening silently reverted by later drop-ins, and checks
> dangerous kernel-parameter combinations. Evidence-first, SARIF, CI gate,
> MCP server included. (Python, MIT)
