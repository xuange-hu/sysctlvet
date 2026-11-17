# Security policy

## Reporting a vulnerability

Open a private security advisory on GitHub (Security → Advisories → Report a
vulnerability), or email the maintainer through the address on the GitHub
profile. Please include:

- the version (or commit) you tested,
- a minimal sysctl file set that reproduces the problem,
- what sysctlvet concluded and what the correct conclusion should be.

You will get an acknowledgement within 72 hours.

## What counts as a security issue

sysctlvet reads sysctl config files and prints conclusions. The
security-relevant failure modes are:

- **False negatives on dangerous settings** — a config that clearly disables
  ASLR (or enables redirects, or exposes BPF) but produces no finding. This
  is the top priority class.
- **Wrong precedence resolution** — claiming a line wins when it does not
  (or vice versa) silently invalidates every relations conclusion.
- **Crashes on hostile input** — config files are attacker-influenced in
  incident-response scenarios; a crafted file must not execute code or read
  outside the file given.
- **Dependency confusion** — the package must stay dependency-free; any
  runtime dependency addition is treated as a security-relevant change.

False positives and rule-prose issues are regular bugs (open an issue).

## Scope

sysctlvet is an offline static auditor. It never reads live `/proc/sys`,
never needs root, and makes no network calls. It is meant for defensive
audit of systems you are authorised to assess.
