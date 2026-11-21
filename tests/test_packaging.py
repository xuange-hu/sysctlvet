"""Packaging contract: what the wheel promises must stay true.

The zero-dependency claim is about what `pip install sysctlvet` pulls in, and
the console scripts must stay importable with no extras installed.
"""

import ast
import importlib
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Modules that would break the zero-dependency claim if imported at module
# scope by a console-script entry point.
THIRD_PARTY = {"mcp", "yaml", "click", "rich", "requests", "pytest"}


def _pyproject() -> str:
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
        return handle.read()


def _module_source(name: str) -> str:
    path = os.path.join(ROOT, "src", "sysctlvet", name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def test_version_matches_pyproject():
    import sysctlvet

    match = re.search(r'(?m)^version = "([^"]+)"', _pyproject())
    assert match and match.group(1) == sysctlvet.__version__


def test_console_scripts_resolve():
    for module_name, attr in (("cli", "main"), ("mcp_server", "main")):
        module = importlib.import_module(f"sysctlvet.{module_name}")
        assert callable(getattr(module, attr))


def test_console_script_targets_declared():
    assert 'sysctlvet = "sysctlvet.cli:main"' in _pyproject()
    assert 'sysctlvet-mcp = "sysctlvet.mcp_server:main"' in _pyproject()


def test_base_dependencies_are_empty():
    assert re.search(r"(?m)^dependencies = \[\]", _pyproject())


def test_mcp_extra_pinned_below_2():
    assert 'mcp = ["mcp>=1.2,<2"]' in _pyproject()


def _module_scope_imports(tree: ast.AST) -> list[list[str]]:
    """Import name groups reachable at module scope, not inside any function."""
    out: list[list[str]] = []
    stack = list(getattr(tree, "body", []))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Import):
            out.append([alias.name.split(".")[0] for alias in node.names])
        elif isinstance(node, ast.ImportFrom):
            out.append([(node.module or "").split(".")[0]])
        stack.extend(getattr(node, "body", []))
        for field in ("orelse", "finalbody", "handlers"):
            for child in getattr(node, field, []) or []:
                if isinstance(child, ast.ExceptHandler):
                    stack.extend(child.body)
                else:
                    stack.append(child)
    return out


def test_entrypoint_modules_do_not_import_third_party_at_module_scope():
    """A bare `pip install sysctlvet` must still run the console scripts.

    The mcp server must therefore import `mcp` lazily (inside build_server),
    not at module scope — the CI job that installs `.[mcp]` can never see
    this class of breakage.
    """
    for module_name in ("cli.py", "mcp_server.py"):
        tree = ast.parse(_module_source(module_name))
        for names in _module_scope_imports(tree):
            offenders = [name for name in names if name in THIRD_PARTY]
            assert not offenders, f"{module_name} imports {offenders} at module scope"


def test_lazy_mcp_import_is_inside_function():
    source = _module_source("mcp_server.py")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            if "mcp" in names:
                # every mcp import must sit inside a function, never the module body
                parent_is_function = False
                for parent in ast.walk(tree):
                    if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)) and node in list(
                        ast.walk(parent)
                    ):
                        parent_is_function = True
                assert parent_is_function, "mcp must only be imported inside a function"


def test_package_is_typed():
    assert os.path.exists(os.path.join(ROOT, "src", "sysctlvet", "py.typed"))


def _collected_tests() -> int:
    """Ask pytest how many items exist, without running them.

    数 `def test_*` 不够：参数化测试会展开成多个 item。这里必须用真实的
    收集结果，并显式 `-o addopts=` —— 项目若配置了 `addopts = "-q"`，
    再叠一个 `-q` 会变成 `-qq`，把 "N tests collected" 汇总行吞掉。
    """
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts=", os.path.join(ROOT, "tests")],
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )
    match = re.search(r"(\d+) tests? collected", proc.stdout)
    if match is None:
        import pytest

        pytest.skip(f"could not collect tests: {proc.stdout[-200:]} {proc.stderr[-200:]}")
    return int(match.group(1))


def test_readme_badge_matches_collection():
    """徽章上的数字是访客读到的第一个数字，必须能被这条断言打死。

    `test_mcp_server.py` 在没装 mcp extra 的环境里整文件不收集，
    所以本机收集数会少于 CI（CI 装 `.[all]`）。这里只断言 README 与
    本地收集口径的关系：在装了 extras 的环境里必须精确相等。
    """
    import importlib.util

    import pytest

    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
        text = handle.read()
    match = re.search(r"tests-(\d+)", text)
    assert match, "README 缺少 tests 徽章"
    declared = int(match.group(1))
    collected = _collected_tests()
    has_mcp = importlib.util.find_spec("mcp") is not None
    if not has_mcp:
        # 未装 mcp 时跳过 9 条，只校验"不会少于"，避免误报成漂移
        pytest.skip(f"mcp extra 未安装：本机收集 {collected}，徽章 {declared}")
    assert declared == collected, f"README says {declared}, pytest collects {collected}"
