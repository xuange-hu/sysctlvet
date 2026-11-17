"""Fresh-clone contract: a bare checkout must collect without PYTHONPATH tricks."""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_collect_without_pythonpath(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", os.path.join(ROOT, "tests"), "--collect-only", "-q", "-o", "addopts="],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "tests collected" in result.stdout or "test" in result.stdout
