"""The ozenix welcome screen (update-motd script) renders and runs cleanly.

It runs as root on every SSH login, so a quoting mistake would print garbage
(or nothing) for every admin.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

TEMPLATE = Path(__file__).resolve().parents[2] / "ansible/roles/cli/templates/ozenix-motd.sh.j2"


def run(tmp_path: Path, coffee: str) -> str:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    text = env.from_string(TEMPLATE.read_text()).render(
        dp_motd_docs_url="https://ozenix.org", dp_motd_coffee_url=coffee
    )
    script = tmp_path / "05-ozenix"
    script.write_text(text)
    sh = shutil.which("sh")
    assert sh
    result = subprocess.run([sh, str(script)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and not result.stderr, result.stderr
    return result.stdout


def test_welcome_screen(tmp_path: Path) -> None:
    out = run(tmp_path, "https://buymeacoffee.com/example")
    assert "  \\___//___\\___|_| |_||_/_/\\_\\\n" in out  # backslashes intact
    assert r" | | | |_  / _ \ '_ \ | \ \/ /" + "\n" in out
    assert "\\n" not in out  # no escape printed literally
    assert "Documentation: https://ozenix.org" in out
    assert "buy me a coffee: https://buymeacoffee.com/example" in out
    assert "create --user john --key john.pub" in out and "site help" in out
    assert "Let's Encrypt" in out


def test_coffee_line_hidden_without_url(tmp_path: Path) -> None:
    assert "coffee" not in run(tmp_path, "")
