# Changelog

## 0.1.0 — 2026-11-18

First release.

- Precedence engine: parses `/etc/sysctl.conf` and `sysctl.d` drop-ins,
  resolves the real `sysctl --system` load order (usr/lib → usr/local/lib →
  run → etc/sysctl.d → sysctl.conf; lexicographic within a directory) and
  reports which line wins — every other assignment is dead text.
- 31 rules in three passes: `settings` (SYS101–SYS120, SYS199),
  `combos` (SYS201–SYS205: KASLR-defeat trifecta, dump chains),
  `relations` (SYS301–SYS305: reverted hardening, dead assignments,
  separator duplicates, type mismatches, interface-level weakenings).
  Evidence-first findings with file, line, offset, length and raw text.
- Key normalization: `net/ipv4/ip_forward` and `net.ipv4.ip_forward` are
  one key (SYS303 says so when both spellings appear).
- Unparseable lines surface as SYS199 instead of being dropped.
- CLI: `sysctlvet scan|effective|rules|demo|explain`, text/json/sarif
  output, `--fail-on` exit-code gate (both directions tested with real files).
- MCP server (`sysctlvet-mcp`) with 6 tools for Claude Code / Cursor / Cline,
  pinned to `mcp>=1.2,<2`; `sysctlvet_effective` exposes the precedence
  engine directly.
- Embedded demo corpus (a host configured by four different people) that
  triggers all 31 rules (43 findings), pinned by the test suite.
- Zero runtime dependencies, Python 3.10+.
