"""Syntax parsing: separators, comments, strict `key = value`, evidence offsets."""

from sysctlvet.model import Assignment
from sysctlvet.parsers import normalize_key, parse, parse_line


def test_normalize_dots_unchanged():
    assert normalize_key("net.ipv4.ip_forward") == "net.ipv4.ip_forward"


def test_normalize_slash_to_dot():
    assert normalize_key("net/ipv4/ip_forward") == "net.ipv4.ip_forward"


def test_normalize_mixed_separators():
    assert normalize_key("net/ipv4/conf.all/accept_redirects") == "net.ipv4.conf.all.accept_redirects"


def test_normalize_strips_whitespace_and_stray_dots():
    assert normalize_key("  net..ipv4. ") == "net.ipv4"


def test_parse_plain_assignment():
    config = parse("net.ipv4.ip_forward = 1\n", "x.conf")
    assert len(config.assignments) == 1
    item = config.assignments[0]
    assert (item.key, item.value, item.eq_form) == ("net.ipv4.ip_forward", "1", "=")


def test_parse_whitespace_around_equals():
    config = parse("kernel.sysrq   =   176\n", "x.conf")
    assert config.assignments[0].value == "176"


def test_parse_value_with_spaces_kept():
    config = parse("kernel.core_pattern = |/usr/lib/systemd/systemd-coredump %P\n", "x.conf")
    assert config.assignments[0].value.startswith("|/usr/lib")


def test_strict_equals_required():
    # `key value` is not the sysctl.conf syntax; the line is a warning.
    config = parse("net.ipv4.ip_forward 1\n", "x.conf")
    assert not config.assignments
    assert len(config.warnings) == 1


def test_malformed_line_becomes_warning():
    config = parse("this line is not a sysctl assignment\n", "x.conf")
    assert not config.assignments
    assert config.warnings and config.warnings[0][0] == 1


def test_comment_lines_ignored():
    config = parse("# net.ipv4.ip_forward = 1\n; also a comment\n", "x.conf")
    assert not config.assignments and not config.warnings


def test_inline_comment_stripped():
    config = parse("net.ipv4.ip_forward = 1  # routing off\n", "x.conf")
    assert config.assignments[0].value == "1"


def test_hash_inside_value_preserved():
    config = parse("kernel.core_pattern = |/bin/pipe#2\n", "x.conf")
    assert config.assignments[0].value == "|/bin/pipe#2"


def test_empty_value_is_warning():
    config = parse("net.ipv4.ip_forward =\n", "x.conf")
    assert not config.assignments
    assert len(config.warnings) == 1


def test_blank_lines_are_neither():
    config = parse("\n   \n\n", "x.conf")
    assert not config.assignments and not config.warnings


def test_line_offsets_are_cumulative():
    text = "a = 1\nbb = 2\nccc = 3\n"
    config = parse(text, "x")
    offsets = [item.offset for item in config.assignments]
    assert offsets == [0, 6, 13]
    assert all(text[item.offset :].startswith(item.raw) for item in config.assignments)


def test_raw_key_preserved_for_separator_diffs():
    config = parse("net/ipv4/ip_forward = 1\n", "x.conf")
    assert config.assignments[0].raw_key == "net/ipv4/ip_forward"
    assert config.assignments[0].key == "net.ipv4.ip_forward"


def test_numeric_decimal_and_hex():
    config = parse("a = 31\nb = 0x1f\nc = -1\nd = yes\n", "x.conf")
    assert [item.numeric for item in config.assignments] == [31, 31, -1, None]


def test_saw_collapses_whitespace():
    item = Assignment(key="k", raw_key="k", value="v", line=1, offset=0, length=9, raw="k   =   v", file="x")
    assert item.saw == "k = v"


def test_parse_line_helper():
    assert parse_line("k = v") == ("k", "v", "=")
    assert parse_line("# k = v") is None
    assert parse_line("garbage without equals") is None
