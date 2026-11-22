"""Precedence resolution: tiers, load order, winners and losers."""

from sysctlvet.model import TIER_ETC_CONF, TIER_ETC_D, TIER_RUN, TIER_USR_LIB, TIER_USR_LOCAL
from sysctlvet.parsers import parse
from sysctlvet.resolve import assignment_pairs, effective_for, load_key, resolve, tier_of


def _file(text, source):
    config = parse(text, source)
    config.tier = tier_of(source)
    config.load_key = load_key(source)
    return config


def test_tier_sysctl_conf_is_highest():
    assert tier_of("/etc/sysctl.conf") == TIER_ETC_CONF
    assert tier_of("etc/sysctl.conf") == TIER_ETC_CONF


def test_tier_directories():
    assert tier_of("/etc/sysctl.d/10-a.conf") == TIER_ETC_D
    assert tier_of("/run/sysctl.d/10-a.conf") == TIER_RUN
    assert tier_of("/usr/local/lib/sysctl.d/10-a.conf") == TIER_USR_LOCAL
    assert tier_of("/usr/lib/sysctl.d/50-a.conf") == TIER_USR_LIB


def test_tier_unknown_is_site_config():
    assert tier_of("some/where/else.conf") == TIER_ETC_D


def test_tier_windows_separators():
    assert tier_of("C:\\etc\\sysctl.conf") == TIER_ETC_CONF


def test_load_key_orders_filename_then_tier():
    """``man sysctl.d``: sort by *filename*, regardless of directory.

    The directory only decides same-name replacement, so the tier rides along
    as a tie-breaker after the basename. ``/etc/sysctl.conf`` is the legacy
    channel ``sysctl --system`` applies last.
    """
    keys = [
        load_key("/etc/sysctl.conf"),
        load_key("/etc/sysctl.d/99-late.conf"),
        load_key("/etc/sysctl.d/10-early.conf"),
        load_key("/usr/lib/sysctl.d/50-vendor.conf"),
    ]
    assert sorted(keys) == [
        load_key("/etc/sysctl.d/10-early.conf"),
        load_key("/usr/lib/sysctl.d/50-vendor.conf"),
        load_key("/etc/sysctl.d/99-late.conf"),
        load_key("/etc/sysctl.conf"),
    ]


def test_later_filename_beats_higher_directory_tier():
    """A vendor file named later than a local one wins — not a blanket /etc/ win.

    This is the regression guard for the 2026-11-18 audit CRITICAL: the engine
    used to sort by directory tier first, so ``/etc/sysctl.d/10-hardening.conf``
    silently beat ``/usr/lib/sysctl.d/99-vendor.conf`` and the reported
    "effective" value (and every SYS301 "hardening reverted" conclusion built on
    it) was inverted.
    """
    files = [
        _file("net.ipv4.ip_forward = 0\n", "etc/sysctl.d/10-hardening.conf"),
        _file("net.ipv4.ip_forward = 1\n", "usr/lib/sysctl.d/99-vendor.conf"),
    ]
    eff = resolve(files)
    assert eff["net.ipv4.ip_forward"].winner.file.endswith("99-vendor.conf")
    assert eff["net.ipv4.ip_forward"].winner.value == "1"


def test_same_basename_higher_tier_still_wins():
    files = [
        _file("k = 1\n", "usr/lib/sysctl.d/50-default.conf"),
        _file("k = 0\n", "etc/sysctl.d/50-default.conf"),
    ]
    assert resolve(files)["k"].winner.value == "0"


def test_last_assignment_wins():
    files = [_file("k = 1\n", "etc/sysctl.d/10-a.conf"), _file("k = 2\n", "etc/sysctl.conf")]
    eff = resolve(files)
    assert eff["k"].winner.value == "2"  # sysctl.conf loads last and wins


def test_later_name_wins_within_dir():
    files = [_file("k = 1\n", "etc/sysctl.d/10-a.conf"), _file("k = 2\n", "etc/sysctl.d/99-b.conf")]
    eff = resolve(files)
    assert eff["k"].winner.value == "2"


def test_sysctl_conf_beats_dropins():
    files = [_file("k = dropin\n", "etc/sysctl.d/10-a.conf"), _file("k = conf\n", "etc/sysctl.conf")]
    eff = resolve(files)
    assert eff["k"].winner.value == "conf"


def test_losers_kept_in_load_order():
    files = [
        _file("k = 1\n", "usr/lib/sysctl.d/10-a.conf"),
        _file("k = 2\n", "etc/sysctl.d/10-b.conf"),
        _file("k = 3\n", "etc/sysctl.conf"),
    ]
    eff = resolve(files)
    assert [a.value for a in eff["k"].losers] == ["1", "2"]
    assert eff["k"].winner.value == "3"


def test_within_file_last_wins():
    files = [_file("k = 1\nk = 2\n", "etc/x.conf")]
    eff = resolve(files)
    assert eff["k"].winner.value == "2"
    assert [a.value for a in eff["k"].losers] == ["1"]


def test_separator_spelling_merges_into_one_key():
    files = [_file("net/ipv4/ip_forward = 1\n", "etc/a.conf"), _file("net.ipv4.ip_forward = 0\n", "etc/sysctl.conf")]
    eff = resolve(files)
    assert len(eff) == 1
    assert eff["net.ipv4.ip_forward"].winner.value == "0"


def test_assignment_pairs_marks_roles():
    files = [_file("k = 1\n", "etc/a.conf"), _file("k = 2\n", "etc/sysctl.conf")]
    eff = resolve(files)
    pairs = assignment_pairs(eff["k"])
    assert [role for _, role in pairs] == ["dead", "winner"]


def test_effective_for_normalizes_lookup():
    files = [_file("net/ipv4/ip_forward = 1\n", "etc/a.conf")]
    eff = resolve(files)
    assert effective_for(eff, "net.ipv4.ip_forward") is not None
    assert effective_for(eff, "net/ipv4/does_not_exist") is None


def test_seq_reflects_load_order():
    files = [_file("k = 1\n", "etc/sysctl.d/10-a.conf"), _file("k = 2\n", "etc/sysctl.conf")]
    eff = resolve(files)
    assert eff["k"].losers[0].seq < eff["k"].winner.seq
