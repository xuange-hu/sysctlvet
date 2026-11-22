"""Precedence resolution: which line actually wins.

The kernel keeps one value per key; every earlier assignment is dead text.
The load order is the one ``sysctl --system`` uses, in the words of
``man sysctl.d``: files in /etc/sysctl.d override /run/sysctl.d, which
override /usr/local/lib/sysctl.d, which override /usr/lib/sysctl.d — and
``/etc/sysctl.conf`` is applied last by procps, so it overrides everything.

Within one directory the filename decides: lexicographic order, later wins
(the ``10-`` … ``99-`` convention exists precisely because of this).

This module is the reason sysctlvet exists: a hardening line that a later
file silently undoes is indistinguishable from a working hardening line
unless somebody reconstructs this order by hand.
"""

from __future__ import annotations

import os

from .model import (
    TIER_ETC_CONF,
    TIER_ETC_D,
    TIER_RUN,
    TIER_USR_LIB,
    TIER_USR_LOCAL,
    Assignment,
    ConfigFile,
    Effective,
)


def tier_of(path: str) -> int:
    """Map a file path to its load tier.

    The tier is *not* the sort key. Per ``man sysctl.d`` the only thing a
    directory decides is **same-name replacement** ("Files in /etc/ override
    files with the same name in /run/, /usr/local/lib/ and /usr/lib/"); the
    application order itself is the lexicographic order of the *filename*,
    regardless of directory. ``/etc/sysctl.conf`` is a separate legacy channel
    that ``sysctl --system`` applies last, so it does win outright.
    """
    norm = path.replace("\\", "/").lower()
    name = os.path.basename(norm)
    if name == "sysctl.conf" and ("/etc/" in norm or norm.startswith("etc/")):
        return TIER_ETC_CONF
    # Anchor on the suffix rather than a bare substring: "/home/u/usr/lib/
    # sysctl.d/x.conf" is not a distribution directory.
    for marker, tier in (
        ("/etc/sysctl.d/", TIER_ETC_D),
        ("/run/sysctl.d/", TIER_RUN),
        ("/usr/local/lib/sysctl.d/", TIER_USR_LOCAL),
        ("/usr/lib/sysctl.d/", TIER_USR_LIB),
        ("/lib/sysctl.d/", TIER_USR_LIB),
    ):
        if marker in norm or norm.startswith(marker.lstrip("/")):
            return tier
    return TIER_ETC_D  # ad-hoc files: treated like site config


def load_key(path: str) -> tuple:
    """Sort key implementing the precedence order (later in sort = wins).

    Documented order (``man sysctl.d``): *filename* lexicographic, across all
    directories. ``/etc/sysctl.conf`` is applied last by ``sysctl --system``.
    The tier is folded in only as a tie-breaker for one identical filename,
    where the higher-priority directory must win.
    """
    tier = tier_of(path)
    name = os.path.basename(path.replace("\\", "/")).lower()
    if tier == TIER_ETC_CONF:
        return (1, "", "", name)
    return (0, name, tier, path.lower())


def resolve(files: list[ConfigFile]) -> dict[str, Effective]:
    """Fold every assignment into one effective value per key.

    Returns a dict keyed by normalized key; losers are kept in load order so
    findings can point at the dead line and name the line that killed it.
    """
    ordered = sorted(files, key=lambda f: f.load_key)
    seq = 0
    winners: dict[str, Effective] = {}
    for config in ordered:
        for assignment in config.assignments:
            assignment.seq = seq
            seq += 1
            entry = winners.get(assignment.key)
            if entry is None:
                winners[assignment.key] = Effective(key=assignment.key, winner=assignment)
            else:
                entry.losers.append(entry.winner)
                entry.winner = assignment
    return winners


def effective_for(eff: dict[str, Effective], key: str) -> Effective | None:
    """Look up one key with separator-insensitive spelling."""
    from .parsers import normalize_key

    return eff.get(normalize_key(key))


def load_order(files: list[ConfigFile]) -> list[ConfigFile]:
    return sorted(files, key=lambda f: f.load_key)


def assignment_pairs(entry: Effective) -> list[tuple[Assignment, str]]:
    """Every assignment of one key with its role: ``winner`` or ``dead``."""
    out = [(a, "dead") for a in entry.losers]
    out.append((entry.winner, "winner"))
    return out
