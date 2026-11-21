# sysctlvet

[![tests](https://img.shields.io/badge/tests-167-brightgreen)](https://github.com/xuange-hu/sysctlvet/actions)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![deps](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/xuange-hu/sysctlvet/blob/main/pyproject.toml)

**Zero-dependency kernel parameter (sysctl) auditor.**
It resolves which line actually wins the `sysctl.d` load order — and then
tells you about the hardening that a later file silently undid. Three passes
— settings, combos, relations — and every conclusion points at the exact
line that produced it.

```console
$ sysctlvet scan /etc/sysctl.conf /etc/sysctl.d/
MEDIUM   SYS301  hardening kernel.randomize_va_space = 2 is silently reverted: /etc/sysctl.conf:12 sets it back to 0
         at /usr/lib/sysctl.d/50-default.conf:3 (offset 96, len 29)
         saw: kernel.randomize_va_space = 2
         fix: Delete the losing line or change the winning file; one key must have one owner.
HIGH     SYS109  kernel.randomize_va_space = 0 weakens or disables ASLR
         at /etc/sysctl.conf:12 (offset 240, len 28)
         saw: kernel.randomize_va_space = 0
         fix: Set kernel.randomize_va_space = 2.
...
43 finding(s) across 4 file(s): 9 high, 22 medium, 11 low, 1 note
```

## Why another hardening tool?

Because the existing ones all audit the **live system**, and the failure mode
nobody catches is in the **files**:

| | what it is | why it is not enough |
|---|---|---|
| CIS benchmarks / `lynis` | audit a running host | needs the host; cannot review a repo, an image or a PR |
| `sysctl --system` | applies the files | applies them *silently*: the last file wins and nobody is told |
| config management (Ansible etc.) | converges values | convergence hides conflicts — two roles fight, one wins at random |

sysctlvet is a single Python package with **zero runtime dependencies** that
reads the config files themselves. It knows the load order —
`/usr/lib/sysctl.d` loses to `/run/sysctl.d` loses to `/etc/sysctl.d` loses
to `/etc/sysctl.conf`, and within a directory the filename sorts — so it can
prove which line reaches the kernel and which lines are decoration.

It runs in CI, on the host you just inherited, in an incident-response shell,
and inside your editor's agent.

## Quickstart

```console
# 1. get it (no dependencies to resolve)
pip install git+https://github.com/xuange-hu/sysctlvet

# 2. audit a machine's real config
sysctlvet scan /etc/sysctl.conf /etc/sysctl.d/

# 3. ask the precedence engine who wins for one key
sysctlvet effective kernel.randomize_va_space /etc/sysctl.conf /etc/sysctl.d/
kernel.randomize_va_space  (load order: earlier loses, later wins)
  [dead] /usr/lib/sysctl.d/50-default.conf:3  kernel.randomize_va_space = 2
  [WINS] /etc/sysctl.conf:12  kernel.randomize_va_space = 0
```

No machine at hand? `sysctlvet demo` runs the embedded corpus — a host
configured by four different people — and fires all 31 rules.

## What it checks

Three passes, 31 rules (full text in [docs/rules.md](docs/rules.md)):

| pass | rules | looks at |
|---|---|---|
| `settings` | SYS101–SYS120, SYS199 | the value of one effective setting: redirects, ASLR, BPF, dumps, links |
| `combos` | SYS201–SYS205 | values that are dangerous together: the KASLR-defeat trifecta, the dump chains |
| `relations` | SYS301–SYS305 | the gaps between files: dead settings, reverted hardening, separator duplicates, interface overrides |

Two things worth knowing about the rule set:

- **Only effective values are judged.** A dead line never triggers a
  settings finding — it triggers a *dead line* finding instead. An audit
  that reads one file in isolation reports a secure host that is exposed.
- **Absent settings are not findings.** Unlike sshd or sudoers, an unset
  sysctl key falls back to a kernel default that is sane on modern kernels;
  flagging absence would drown the real signal. (If you want a baseline that
  requires keys to be present, say so and it becomes a rule class.)

## The precedence engine

This is the part no other tool does:

```console
$ sysctlvet effective net/ipv4/ip_forward etc/ sys/
net.ipv4.ip_forward  (load order: earlier loses, later wins)
  [dead] etc/sysctl.d/10-network.conf:2  net/ipv4/ip_forward = 1
  [WINS] etc/sysctl.d/99-local.conf:6  net.ipv4.ip_forward = 1
```

`net/ipv4/ip_forward` and `net.ipv4.ip_forward` are the same key — the
kernel only knows slashes, the tools accept both — but humans diffing the
config see two different settings. sysctlvet merges them, and says so
(SYS303), because one of those lines is dead and the diff hides it.

## Evidence, not verdicts

Every finding carries `file`, `line`, `byte offset`, `length` and the raw
line. The SARIF output keeps the same fields, so code scanning shows the
snippet; `--fail-on high` gives you the CI gate:

```console
sysctlvet scan etc/ --format sarif --fail-on high > sysctlvet.sarif
```

## MCP server

sysctlvet ships six MCP tools for Claude Code / Cursor / Cline — scan,
effective (the precedence engine), parse, demo, rules, explain:

```console
uvx --from "git+https://github.com/xuange-hu/sysctlvet#egg=sysctlvet[mcp]" sysctlvet-mcp
```

Or in your MCP client config:

```json
{
  "mcpServers": {
    "sysctlvet": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/xuange-hu/sysctlvet#egg=sysctlvet[mcp]", "sysctlvet-mcp"]
    }
  }
}
```

`sysctlvet effective` is the tool an agent actually wants: give it a key and
the files, and it answers "which line wins, and what died" — the question
every config review eventually asks.

## Install notes

- Python 3.10+, no runtime dependencies (the mcp server is an optional extra
  and is imported lazily — the core package never touches it).
- A visitor's first `git clone && pip install . && pytest` works offline with
  base deps only; CI enforces this (`fresh-clone` job) along with a
  README-badge-vs-collection check.

## Related tools

Part of a family of zero-dependency auditors, one per config surface:
[vehsec](https://github.com/xuange-hu/vehsec) (vehicle security),
[sshdguard](https://github.com/xuange-hu/sshdguard) (sshd_config),
[sudolint](https://github.com/xuange-hu/sudolint) (sudoers),
[unitlint](https://github.com/xuange-hu/unitlint) (systemd units),
[cronlint](https://github.com/xuange-hu/cronlint) (crontab),
[firelint](https://github.com/xuange-hu/firelint) (firewall rules),
[hookvet](https://github.com/xuange-hu/hookvet) (git hooks).

## License

MIT. The rules are opinionated on purpose; every one of them argues its case
in [docs/rules.md](docs/rules.md) — open an issue if you disagree.
