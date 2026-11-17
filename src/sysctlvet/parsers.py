"""Syntax parsing for sysctl.conf and sysctl.d files.

The accepted syntax is deliberately the union of what procps ``sysctl -p``
and ``systemd-sysctl`` consume:

* ``key = value`` — the only form procps ``sysctl -p`` and ``systemd-sysctl``
  accept.  Anything else on a non-comment line is a warning: a setting that
  only looks configured.
* ``/`` and ``.`` are both legal key separators — the kernel only knows ``/``,
  the tools accept both.  Keys are normalized to dots so
  ``net/ipv4/ip_forward`` and ``net.ipv4.ip_forward`` are one key, not two.
* ``#`` starts a comment at line start or after whitespace; ``;`` is a
  comment at line start (procps accepts both).

A line that cannot be parsed is returned as a warning, never silently
dropped: an unparseable line is a setting that never reaches the kernel.
"""

from __future__ import annotations

from .model import Assignment, ConfigFile


def normalize_key(raw: str) -> str:
    """Unify separators to dots and drop stray whitespace."""
    key = raw.strip().replace("/", ".")
    while ".." in key:
        key = key.replace("..", ".")
    return key.strip(".")


def _strip_comment(line: str) -> str:
    """Cut a trailing comment; the raw line is kept by the caller as evidence."""
    out = []
    for index, char in enumerate(line):
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            break
        out.append(char)
    return "".join(out).rstrip()


def parse_line(line: str) -> tuple[str, str, str] | None:
    """Return ``(raw_key, value, eq_form)`` or None for comments, blanks and junk."""
    stripped = _strip_comment(line)
    if not stripped.strip() or stripped.lstrip().startswith(";"):
        return None
    if "=" not in stripped:
        return None
    raw_key, _, value = stripped.partition("=")
    return raw_key.strip(), value.strip(), "="


def parse(text: str, source: str = "") -> ConfigFile:
    """Parse one file's text into assignments plus unparseable-line warnings."""
    out = ConfigFile(source=source)
    offset = 0
    for lineno, line in enumerate(text.splitlines(keepends=True), start=1):
        raw = line.rstrip("\r\n")
        parsed = parse_line(raw)
        if parsed is None:
            body = raw.strip()
            if body and not body.startswith("#") and not body.startswith(";"):
                out.warnings.append((lineno, offset, raw))
        else:
            raw_key, value, eq_form = parsed
            if not raw_key or not value:
                out.warnings.append((lineno, offset, raw))
            else:
                out.assignments.append(
                    Assignment(
                        key=normalize_key(raw_key),
                        raw_key=raw_key,
                        value=value,
                        line=lineno,
                        offset=offset,
                        length=len(raw),
                        raw=raw,
                        file=source,
                        eq_form=eq_form,
                    )
                )
        offset += len(line)
    return out
