"""Renderer contract: text, JSON and SARIF 2.1.0 shapes."""

import json

from sysctlvet.demo import run_demo
from sysctlvet.render import render, render_json, render_sarif, render_text


def test_text_ends_with_summary():
    out = render_text(run_demo())
    assert "finding(s) across 4 file(s)" in out


def test_text_shows_fix_by_default_and_hides_on_quiet():
    report = run_demo()
    assert "fix:" in render_text(report)
    assert "fix:" not in render_text(report, quiet=True)


def test_json_roundtrips():
    payload = json.loads(render_json(run_demo()))
    assert set(payload) == {"source", "findings", "counts", "rules_run", "missing"}
    assert payload["counts"] == run_demo().counts
    # missing 必须出现在机器可读输出里：CI 靠它区分"没扫到"和"很干净"
    assert payload["missing"] == []


def test_sarif_valid_envelope():
    payload = json.loads(render_sarif(run_demo()))
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "sysctlvet"
    assert run["results"]


def test_sarif_results_have_locations():
    payload = json.loads(render_sarif(run_demo()))
    for result in payload["runs"][0]["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert region["byteOffset"] >= 0
        assert region["snippet"]["text"]


def test_sarif_windows_paths_normalized():
    report = run_demo()
    report.findings[0].where = "C:\\etc\\sysctl.conf"
    payload = json.loads(render_sarif(report))
    uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri


def test_render_dispatch():
    report = run_demo()
    assert render(report, fmt="json").lstrip().startswith("{")
    assert render(report, fmt="sarif").lstrip().startswith("{")
    assert "SYS" in render(report, fmt="text")
