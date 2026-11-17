"""MCP server tests (skipped when the optional mcp extra is absent)."""

import asyncio
import json

import pytest

pytest.importorskip("mcp")

from sysctlvet.mcp_server import build_server, tool_manifest  # noqa: E402


def _call(name: str, arguments: dict):
    mcp = build_server()
    result = asyncio.run(mcp.call_tool(name, arguments))
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


def test_manifest_matches_registered_tools():
    tools = asyncio.run(build_server().list_tools())
    assert {t.name for t in tools} == {entry["name"] for entry in tool_manifest()}


def test_six_tools_with_descriptions():
    manifest = tool_manifest()
    assert len(manifest) == 6
    assert all(entry["description"] for entry in manifest)


def test_call_demo_tool():
    payload = _call("sysctlvet_demo", {})
    assert payload["counts"]["high"] >= 6
    assert payload["findings"]


def test_call_rules_tool():
    payload = _call("sysctlvet_rules", {})
    assert len(payload) == 31
    assert payload[0]["id"] == "SYS101"


def test_call_explain_tool():
    payload = _call("sysctlvet_explain", {"rule_id": "SYS301"})
    assert payload["severity"] == "medium"
    assert _call("sysctlvet_explain", {"rule_id": "SYS999"})["error"]


def test_call_effective_tool(tmp_path):
    (tmp_path / "10-a.conf").write_text("net.ipv4.tcp_syncookies = 1\n", encoding="utf-8")
    (tmp_path / "sysctl.conf").write_text("net.ipv4.tcp_syncookies = 0\n", encoding="utf-8")
    payload = _call("sysctlvet_effective", {"key": "net.ipv4.tcp_syncookies", "paths": [str(tmp_path)]})
    assert payload["winner"]["value"] == "0"
    roles = [row["role"] for row in payload["assignments"]]
    assert roles == ["dead", "winner"]


def test_call_effective_unknown_key(tmp_path):
    (tmp_path / "sysctl.conf").write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")
    payload = _call("sysctlvet_effective", {"key": "net.ipv9.nope", "paths": [str(tmp_path)]})
    assert payload["error"]


def test_call_parse_tool(tmp_path):
    path = tmp_path / "sysctl.conf"
    path.write_text("net.ipv4.ip_forward = 1\njunk line\n", encoding="utf-8")
    payload = _call("sysctlvet_parse", {"path": str(path)})
    assert payload["assignments"][0]["key"] == "net.ipv4.ip_forward"
    assert payload["warnings"][0]["line"] == 2


def test_call_scan_tool(tmp_path):
    path = tmp_path / "sysctl.conf"
    path.write_text("kernel.randomize_va_space = 0\n", encoding="utf-8")
    payload = _call("sysctlvet_scan", {"paths": [str(path)]})
    assert payload["counts"]["high"] == 1
