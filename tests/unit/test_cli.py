from __future__ import annotations

import argparse
import io
from pathlib import Path

import pytest
from conftest import FakeProbe, RunCli

from domainpilot import __version__
from domainpilot.cli import commands
from domainpilot.cli import main as cli_main
from domainpilot.cli.commands import CommandSpec
from domainpilot.cli.context import CommandResult, Context
from domainpilot.core.errors import ConfirmationRequired, ExitCode, UsageError
from domainpilot.core.locks import FileLock
from domainpilot.core.output import Output
from domainpilot.core.paths import Paths
from domainpilot.core.registry import Registry


def seed_site(paths: Paths, domain: str = "example.com") -> None:
    paths.create_runtime_dirs()
    reg = Registry.open(paths.registry)
    assert reg is not None
    t = reg.allocate_tenant()
    reg.set_tenant_status(t.id, "active")
    reg.add_site(domain, t.id, site_type="php", php_version="8.3")
    reg.close()


# --- help / version / grammar ------------------------------------------------


def test_no_args_prints_help_with_usage_code(run_cli: RunCli) -> None:
    r = run_cli()
    assert r.code == ExitCode.USAGE and "Usage:" in r.out


@pytest.mark.parametrize("argv", [["help"], ["--help"], ["-h"]])
def test_help(run_cli: RunCli, argv: list[str]) -> None:
    r = run_cli(*argv)
    assert r.code == 0 and "Ozenix site manager" in r.out


def test_version(run_cli: RunCli) -> None:
    r = run_cli("version")
    assert r.code == 0 and __version__ in r.out


def test_help_does_not_require_root(run_cli: RunCli) -> None:
    assert run_cli("example.com", "create", "--help", euid=1000).code == 0
    assert run_cli("system", "--help", euid=1000).code == 0


@pytest.fixture
def planned(monkeypatch: pytest.MonkeyPatch) -> None:
    """A not-yet-implemented command (every real one is implemented by Phase 9)."""
    spec = CommandSpec("site", ("future",), "R", 10, "Something for later")
    monkeypatch.setattr(commands, "COMMANDS", (*commands.COMMANDS, spec))


def test_scope_help_lists_commands_and_phases(run_cli: RunCli, planned: None) -> None:
    r = run_cli("example.com", "--help")
    assert r.code == 0
    assert "ssl status" in r.out and "isolation test" in r.out and "[Phase 10]" in r.out
    assert "status" in r.out


def test_command_help(run_cli: RunCli, planned: None) -> None:
    r = run_cli("example.com", "create", "--help")
    assert r.code == 0 and "--type" in r.out and "Planned" not in r.out
    r = run_cli("example.com", "future", "--help")
    assert r.code == 0 and "Planned for Phase 10" in r.out
    r = run_cli("system", "status", "--help")
    assert r.code == 0 and "Planned" not in r.out


def test_unknown_target_suggests(run_cli: RunCli) -> None:
    r = run_cli("sytem", "status")
    assert r.code == ExitCode.USAGE and "did you mean 'site system'" in r.err
    r = run_cli("nodot", "status")
    assert r.code == ExitCode.USAGE and "must contain a dot" in r.err


def test_unknown_verb_suggests(run_cli: RunCli) -> None:
    r = run_cli("example.com", "stauts")
    assert r.code == ExitCode.USAGE and "did you mean 'site example.com status'" in r.err
    r = run_cli("example.com", "zzzzzz")
    assert r.code == ExitCode.USAGE and "see: site example.com --help" in r.err


def test_missing_verb(run_cli: RunCli) -> None:
    r = run_cli("example.com")
    assert r.code == ExitCode.USAGE and "missing command" in r.err


def test_invalid_domain_is_validation_error(run_cli: RunCli) -> None:
    r = run_cli("exa_mple.com", "status")
    assert r.code == ExitCode.VALIDATION


def test_bad_command_arguments(run_cli: RunCli) -> None:
    r = run_cli("list", "--bogus")
    assert r.code == ExitCode.USAGE and "unrecognized arguments" in r.err
    r = run_cli("example.com", "create", "--type", "cgi", "--help")
    assert r.code == 0  # help wins
    r = run_cli("example.com", "create", "--type", "cgi")
    assert r.code == ExitCode.USAGE and "invalid choice" in r.err


def test_global_flag_errors(run_cli: RunCli) -> None:
    assert run_cli("list", "--confirm").code == ExitCode.USAGE
    assert run_cli("list", "-q", "-v").code == ExitCode.USAGE


def test_double_dash_passes_through(run_cli: RunCli) -> None:
    # After "--", "--json" is not a global flag, so `list` sees an extra argument.
    r = run_cli("list", "--", "--json")
    assert r.code == ExitCode.USAGE


def test_not_implemented_names_phase(run_cli: RunCli, planned: None) -> None:
    r = run_cli("example.com", "future")
    assert r.code == ExitCode.FAILED and "Phase 10" in r.err
    r = run_cli("--json", "example.com", "future")
    assert r.json()["errors"][0]["code"] == "not_implemented"


def test_requires_root(run_cli: RunCli) -> None:
    r = run_cli("list", euid=1000)
    assert r.code == ExitCode.PRECONDITION and "sudo site list" in r.err


# --- list / status ------------------------------------------------------------


def test_list_empty(run_cli: RunCli, paths: Paths) -> None:
    r = run_cli("list")
    assert r.code == 0 and "No sites yet" in r.out
    assert not paths.registry.exists()  # read-only commands never create state
    j = run_cli("list", "--json").json()
    assert j["ok"] and j["result"] == {"count": 0, "sites": []}


def test_list_with_sites(run_cli: RunCli, paths: Paths) -> None:
    seed_site(paths)
    r = run_cli("list")
    assert "example.com" in r.out and "t0001" in r.out
    assert run_cli("--json", "list").json()["result"]["count"] == 1


def test_site_status(run_cli: RunCli, paths: Paths) -> None:
    r = run_cli("example.com", "status")
    assert r.code == ExitCode.PRECONDITION and "sudo site example.com create" in r.err
    seed_site(paths)
    r = run_cli("EXAMPLE.com", "status")
    assert r.code == 0 and "t0001" in r.out and "PHP 8.3" in r.out
    j = run_cli("example.com", "status", "--json").json()
    assert j["result"]["site"]["domain"] == "example.com"
    assert j["result"]["tenant"]["uid"] == 20001


def test_site_status_warns_about_unfinished_ops(run_cli: RunCli, paths: Paths) -> None:
    seed_site(paths)
    reg = Registry.open(paths.registry)
    assert reg is not None
    reg.begin_operation(actor="a", command=["x"], target="example.com")
    reg.close()
    r = run_cli("example.com", "status")
    assert "repair" in r.err
    assert (
        run_cli("--json", "system", "status").json()["result"]["registry"]["unfinished_operations"]
        == 1
    )


def test_system_status(run_cli: RunCli, probe: FakeProbe, paths: Paths) -> None:
    r = run_cli("system", "status")
    assert r.code == 0 and "test-host" in r.out and "Firewall:  loaded" in r.out
    assert "warning" not in r.err

    probe.services = {"nginx": "failed", "ssh": "inactive"}
    probe.table_present = False
    probe.reboot = True
    paths.firewall_pending.parent.mkdir(parents=True)
    paths.firewall_pending.write_text("1")
    j = run_cli("system", "status", "--json").json()
    assert j["result"]["services"]["nginx"] == "failed"
    assert j["result"]["reboot_required"] is True
    warnings = " ".join(j["warnings"])
    for needle in ("nginx is failed", "ssh is inactive", "not loaded", "reboot", "confirmation"):
        assert needle in warnings


def test_internal_error_is_contained(
    run_cli: RunCli, probe: FakeProbe, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom() -> dict[str, object]:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(probe, "summary", boom)
    r = run_cli("system", "status")
    assert r.code == ExitCode.FAILED and "internal error" in r.err and "Traceback" not in r.err
    r = run_cli("system", "status", "--verbose")
    assert "Traceback" in r.err


def test_keyboard_interrupt(
    run_cli: RunCli, probe: FakeProbe, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt() -> dict[str, object]:
        raise KeyboardInterrupt

    monkeypatch.setattr(probe, "summary", interrupt)
    assert run_cli("system", "status").code == 130


# --- destructive confirmation & locking (via test-only commands) -------------


@pytest.fixture
def fake_commands(monkeypatch: pytest.MonkeyPatch, paths: Paths) -> list[str]:
    calls: list[str] = []

    def zap(ctx: Context, _ns: argparse.Namespace) -> CommandResult:
        calls.append(f"zap:{ctx.domain}:{ctx.dry_run}")
        return CommandResult({"zapped": True}, ["zapped"])

    def touch(ctx: Context, _ns: argparse.Namespace) -> CommandResult:
        with pytest.raises(Exception, match="another Ozenix operation"):
            FileLock(ctx.paths.global_lock, timeout=0.1).acquire()
        calls.append("touch")
        return CommandResult({})

    extra = (
        CommandSpec("site", ("zap",), "D", 3, "test destructive", zap),
        CommandSpec("system", ("touch",), "M", 3, "test mutating", touch),
    )
    monkeypatch.setattr(commands, "COMMANDS", commands.COMMANDS + extra)
    return calls


def test_destructive_requires_confirmation(run_cli: RunCli, fake_commands: list[str]) -> None:
    r = run_cli("example.com", "zap")  # stdin is not a TTY
    assert r.code == ExitCode.CONFIRMATION and "--confirm example.com" in r.err
    assert run_cli("example.com", "zap", "--yes").code == ExitCode.CONFIRMATION
    assert run_cli("example.com", "zap", "--confirm", "other.com").code == ExitCode.CONFIRMATION
    assert fake_commands == []
    assert run_cli("example.com", "zap", "--confirm=example.com").code == 0
    assert run_cli("--dry-run", "example.com", "zap").code == 0  # dry-run needs no confirmation
    assert fake_commands == ["zap:example.com:False", "zap:example.com:True"]


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_interactive_confirmation() -> None:
    spec = CommandSpec("site", ("zap",), "D", 3, "x")
    out = Output(stdout=io.StringIO(), stderr=io.StringIO())
    flags = cli_main.GlobalFlags()
    cli_main._confirm_destructive(spec, "example.com", flags, _TTY("example.com\n"), out)
    with pytest.raises(ConfirmationRequired):
        cli_main._confirm_destructive(spec, "example.com", flags, _TTY("nope\n"), out)
    flags.json = True
    with pytest.raises(ConfirmationRequired):
        cli_main._confirm_destructive(spec, "example.com", flags, _TTY("example.com\n"), out)


def test_mutating_commands_hold_global_lock(
    run_cli: RunCli, fake_commands: list[str], paths: Paths
) -> None:
    assert run_cli("system", "touch").code == 0
    assert fake_commands == ["touch"]
    with FileLock(paths.global_lock):
        paths_cfg = paths.config_file
        paths_cfg.write_text("[cli]\nlock_timeout = 1\n")
        r = run_cli("system", "touch")
    assert r.code == ExitCode.LOCK_BUSY


def test_bad_config_is_reported(run_cli: RunCli, paths: Paths) -> None:
    paths.config_file.write_text("[sites]\ntypo = 1\n")
    r = run_cli("list")
    assert r.code == ExitCode.VALIDATION and "unknown key sites.typo" in r.err


def test_split_globals() -> None:
    f = cli_main.split_globals(["example.com", "--json", "status", "-v", "--confirm", "x"])
    assert f.json and f.verbose and f.confirm == "x" and f.rest == ["example.com", "status"]


def test_parser_error_raises_usage() -> None:
    p = cli_main._Parser(prog="site x")
    with pytest.raises(UsageError):
        p.parse_args(["--nope"])


def test_every_spec_is_well_formed() -> None:
    seen = set()
    for spec in commands.COMMANDS:
        assert spec.kind in ("R", "M", "D")
        assert spec.scope in ("site", "system", "list")
        key = (spec.scope, spec.words)
        assert key not in seen, key
        seen.add(key)
        parser = cli_main._Parser(prog="t", add_help=False)
        if spec.configure:
            spec.configure(parser)


def test_package_entry_point_importable(tmp_path: Path) -> None:
    import importlib

    module = importlib.import_module("domainpilot.cli.main")
    assert callable(module.main)
