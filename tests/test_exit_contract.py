"""退出码三态与默认门禁：这条契约决定 CI 里它是否还有意义。

旧行为有两处"绿灯型"失真：
  1. `--fail-on` 默认 `none` —— 扫出 9 个 high 也退 0，而 README 把
     "可进 CI" 当卖点；门禁参数存在但不生效，比没有更误导。
  2. `scan_paths()` 丢掉 `collect()` 返回的 `_missing` —— 路径写错、
     文件不存在时输出 "no findings"、退 0。对运维来说，"我什么都没
     扫到"和"内核参数很安全"被印成了同一行。
"""

from __future__ import annotations

import json

from sysctlvet.cli import main
from sysctlvet.scanner import scan_paths


def test_missing_path_is_recorded_not_dropped(tmp_path):
    report = scan_paths([str(tmp_path / "nope.conf")])
    assert report.missing, "不存在的路径必须被记录"
    assert not report.targets


def test_missing_path_exits_two(tmp_path, capsys):
    code = main(["scan", str(tmp_path / "nope.conf")])
    out = capsys.readouterr().out
    assert code == 2, "输入不存在不能退 0，否则 CI 打错字永远绿"
    assert "incomplete" in out
    assert "no findings" in out  # 事实陈述保留，但下一行说明为什么


def test_missing_path_is_visible_in_json(tmp_path, capsys):
    code = main(["scan", str(tmp_path / "nope.conf"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["missing"] == [str(tmp_path / "nope.conf")]


def test_default_gate_is_on(tmp_path, capsys):
    """默认值必须让门禁生效：high 级 finding 存在时退 1。"""
    path = tmp_path / "sysctl.conf"
    path.write_text("kernel.randomize_va_space = 0\n", encoding="utf-8")
    code = main(["scan", str(path)])
    capsys.readouterr()
    assert code == 1, "默认 --fail-on 必须生效，否则 CI 门禁是装饰"


def test_clean_file_still_exits_zero(tmp_path, capsys):
    path = tmp_path / "clean.conf"
    path.write_text("kernel.randomize_va_space = 2\n", encoding="utf-8")
    code = main(["scan", str(path)])
    capsys.readouterr()
    assert code == 0