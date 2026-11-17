"""Docs contract: docs/rules.md is generated and must match the registry."""

import os

from sysctlvet.rulebook import full_markdown
from sysctlvet.rules import REGISTRY

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_rules_doc_matches_registry():
    path = os.path.join(ROOT, "docs", "rules.md")
    with open(path, encoding="utf-8") as handle:
        on_disk = handle.read()
    assert on_disk == full_markdown()


def test_every_rule_documented():
    text = full_markdown()
    for item in REGISTRY:
        assert f"## {item.id}" in text
        assert item.title in text


def test_rule_metadata_sane():
    for item in REGISTRY:
        assert item.severity in ("critical", "high", "medium", "low", "note")
        assert item.stage in ("settings", "combos", "relations")
        assert 0 <= item.score <= 10
        assert item.why and item.fix


def test_rule_ids_unique_and_prefixed():
    ids = [item.id for item in REGISTRY]
    assert len(ids) == len(set(ids))
    assert all(item_id.startswith("SYS") for item_id in ids)
