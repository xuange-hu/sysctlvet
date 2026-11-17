"""Collect files and produce a Report."""

from __future__ import annotations

import os

from .model import ConfigFile, Report
from .parsers import parse
from .resolve import load_key, resolve, tier_of
from .rules import REGISTRY, evaluate

MAX_FILE_BYTES = 5 * 1024 * 1024
NAME_SUFFIXES = (".conf", ".sysctl")


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        data = handle.read(MAX_FILE_BYTES)
    return data


def collect(paths: list[str]) -> tuple[list[str], list[str]]:
    """Expand files and directories into a sorted file list (plus missing paths)."""
    found: list[str] = []
    missing: list[str] = []
    for path in paths:
        if os.path.isfile(path):
            found.append(path)
        elif os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for name in sorted(names):
                    if name.endswith(NAME_SUFFIXES):
                        found.append(os.path.join(root, name))
        else:
            missing.append(path)
    seen: set[str] = set()
    out: list[str] = []
    for path in sorted(found):
        key = os.path.normcase(os.path.abspath(path))
        if key not in seen:
            seen.add(key)
            out.append(path)
    return out, missing


def parse_file(path: str) -> ConfigFile:
    config = parse(_read(path), path)
    config.tier = tier_of(path)
    config.load_key = load_key(path)
    return config


def scan_paths(paths: list[str] | str) -> Report:
    if isinstance(paths, str):
        paths = [paths]
    files, _missing = collect(list(paths))
    configs = [parse_file(path) for path in files]
    eff = resolve(configs)
    findings = evaluate(configs, eff)
    source = ", ".join(paths)
    return Report(
        source=source,
        targets=configs,
        findings=findings,
        rules_run=len(REGISTRY),
        rule_ids=sorted(item.id for item in REGISTRY),
    )
