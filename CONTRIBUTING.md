# Contributing

Thanks for considering a contribution. The project has three hard rules and
a handful of preferences.

## Hard rules

1. **Zero runtime dependencies.** The core package imports nothing outside
   the standard library. `tests/test_packaging.py` enforces this on the
   console-script modules (mcp must be imported lazily, inside a function);
   the CI import guard enforces it on the package. The only optional extra is
   `mcp` (pinned `>=1.2,<2`).
2. **Every rule needs evidence and prose.** A rule entry in
   `src/sysctlvet/rules.py` carries `why` and `fix` text; `docs/rules.md` is
   generated from it (run `python -c "from sysctlvet.rulebook import full_markdown;
   open('docs/rules.md','w',encoding='utf-8').write(full_markdown())"`) and a
   docs contract test compares the two.
3. **Every rule needs a trigger and a negative test.** A rule that only fires
   is half-tested: prove it stays quiet on the near-miss case too.

## Preferences

- Findings must be reproducible from the raw text: keep line/offset/length
  honest, never fabricate evidence.
- **Judgements are drawn from the effective value** (the winner of the load
  order), never from a line that is already dead. If a rule wants to look at
  losers, it belongs in the `relations` pass.
- The demo corpus (`src/sysctlvet/demo.py`) must trigger every rule —
  `tests/test_demo.py` fails otherwise. Extend the corpus when you add a rule.
- Load-order questions: follow what `sysctl --system` and `man sysctl.d`
  actually do (usr/lib loses to usr/local/lib loses to run loses to
  etc/sysctl.d loses to /etc/sysctl.conf; lexicographic within a directory).
  When procps and systemd disagree in the wild, document the choice in the
  rule's `why` instead of guessing.
- Run `pytest` and `ruff check .` before sending a PR; both must be clean.

## Adding a rule

1. Add the `RuleInfo` entry with id, title, severity, stage, score, why, fix.
2. For a settings rule, add a `(rule_id, patterns, bad, template)` row to
   `KEY_RULES` and a trigger/safe pair to `tests/test_rules.py::KEY_TRIGGERS`;
   for combo/relation rules, implement the check in `pass_combos` /
   `pass_relations`.
3. Add trigger + negative tests, extend the demo corpus, regenerate
   `docs/rules.md`.
4. Update the badge count in both READMEs to the new collection size
   (`python -m pytest --collect-only -q -o addopts=`).
