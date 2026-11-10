"""Entry point and dispatcher for `site`.

    site [GLOBAL-FLAGS] <domain|list|system|help|version> <verb> [sub-verb] [ARGS]

Global flags may appear anywhere. See docs/cli-spec.md.
"""

from __future__ import annotations

import argparse
import difflib
import os
import sys
import traceback
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import NoReturn, TextIO

from domainpilot import __version__, release
from domainpilot.cli import commands
from domainpilot.cli.commands import CommandSpec
from domainpilot.cli.context import CommandResult, Context
from domainpilot.core import config as config_mod
from domainpilot.core import validate
from domainpilot.core.errors import (
    ConfirmationRequired,
    DPError,
    ExitCode,
    NotImplementedYet,
    PreconditionFailed,
    UsageError,
)
from domainpilot.core.locks import FileLock
from domainpilot.core.output import Output
from domainpilot.core.paths import Paths
from domainpilot.core.sysinfo import SystemProbe

_BOOL_FLAGS = {
    "--json": "json",
    "--dry-run": "dry_run",
    "--yes": "yes",
    "--verbose": "verbose",
    "-v": "verbose",
    "--quiet": "quiet",
    "-q": "quiet",
    "--no-color": "no_color",
    "--help": "help",
    "-h": "help",
}


@dataclass
class GlobalFlags:
    json: bool = False
    dry_run: bool = False
    yes: bool = False
    verbose: bool = False
    quiet: bool = False
    no_color: bool = False
    help: bool = False
    confirm: str | None = None
    rest: list[str] = field(default_factory=list)


class _Parser(argparse.ArgumentParser):
    """argparse that raises UsageError instead of exiting the process."""

    def error(self, message: str) -> NoReturn:
        raise UsageError(f"{self.prog}: {message}", hint=f"see: {self.prog} --help")


def split_globals(argv: Sequence[str]) -> GlobalFlags:
    flags = GlobalFlags()
    items = list(argv)
    i = 0
    while i < len(items):
        arg = items[i]
        if arg == "--":
            flags.rest.extend(items[i + 1 :])
            break
        if arg in _BOOL_FLAGS:
            setattr(flags, _BOOL_FLAGS[arg], True)
        elif arg == "--confirm":
            if i + 1 >= len(items):
                raise UsageError("--confirm needs the domain name as its value")
            flags.confirm = items[i + 1]
            i += 1
        elif arg.startswith("--confirm="):
            flags.confirm = arg.split("=", 1)[1]
        else:
            flags.rest.append(arg)
        i += 1
    if flags.quiet and flags.verbose:
        raise UsageError("--quiet and --verbose are mutually exclusive")
    return flags


def _leading_words(tokens: list[str]) -> list[str]:
    words: list[str] = []
    for token in tokens:
        if token.startswith("-"):
            break
        words.append(token)
    return words


def _scope_help(scope: str, target: str) -> list[str]:
    lines = [f"Usage: site {target} <command> [options]", "", "Commands:"]
    for spec in commands.for_scope(scope):
        words = spec.usage_words or "(none)"
        state = "" if spec.handler else f"  [Phase {spec.phase}]"
        lines.append(f"  {words:<24} {spec.summary}{state}")
    return lines


TOP_HELP = f"""DomainPilot site manager {__version__}

Usage:
  sudo site <domain> <command> [options]     manage one site, e.g. sudo site example.com status
  sudo site list                             list sites
  sudo site system <command>                 server-wide commands
  site help | site version

Global options (anywhere on the line):
  --json          machine-readable output
  --dry-run       show the plan, change nothing
  --confirm NAME  confirm a destructive command non-interactively (must equal the target)
  --yes           accept non-destructive prompts (never confirms destruction)
  -v, --verbose / -q, --quiet / --no-color / -h, --help

Help for a scope:   site example.com --help    site system --help
Help for a command: site example.com create --help
Documentation: docs/cli-spec.md"""


def _confirm_destructive(
    spec: CommandSpec, target: str, flags: GlobalFlags, stdin: TextIO, out: Output
) -> None:
    if flags.confirm is not None:
        if flags.confirm != target:
            raise ConfirmationRequired(
                f"--confirm value {flags.confirm!r} does not match {target!r}; nothing changed"
            )
        return
    if flags.json or not stdin.isatty():
        raise ConfirmationRequired(
            f"'{spec.usage_words}' is destructive",
            hint=f"re-run with --confirm {target} (or interactively), or use --dry-run first",
        )
    out.info(f"'site {target} {spec.usage_words}' is destructive and cannot be undone.")
    print("Type the target name to confirm: ", end="", file=out.stdout, flush=True)
    answer = stdin.readline().strip()
    if answer != target:
        raise ConfirmationRequired("confirmation did not match; nothing changed")


def main(
    argv: Sequence[str] | None = None,
    *,
    paths: Paths | None = None,
    probe: SystemProbe | None = None,
    euid: int | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    use_syslog: bool = True,
) -> int:
    os.umask(0o027)
    args = list(sys.argv[1:] if argv is None else argv)
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    stdin = stdin or sys.stdin
    out = Output(stdout=stdout, stderr=stderr)
    command_echo = ["site", *args]
    ctx: Context | None = None
    try:
        flags = split_globals(args)
        out.json_mode = flags.json
        out.quiet = flags.quiet
        out.verbose = flags.verbose
        out.color = (not flags.no_color) and not flags.json and stdout.isatty()
        rest = flags.rest

        if not rest or rest[0] == "help":
            print(TOP_HELP, file=stdout)
            return int(ExitCode.OK if rest or flags.help else ExitCode.USAGE)
        if rest[0] == "version":
            print(f"site (DomainPilot) {__version__}", file=stdout)
            print(release.describe_installed(), file=stdout)
            return 0

        head = rest[0]
        if head == "list":
            scope, target, domain, remaining = "list", "list", None, rest[1:]
        elif head == "system":
            scope, target, domain, remaining = "system", "system", None, rest[1:]
        elif validate.looks_like_domain(head):
            domain = validate.domain(head)
            scope, target, remaining = "site", domain, rest[1:]
        else:
            suggestion = difflib.get_close_matches(head, ["list", "system", "help", "version"], 1)
            raise UsageError(
                f"unknown command {head!r}",
                hint=f"did you mean 'site {suggestion[0]}'?"
                if suggestion
                else "domains must contain a dot, e.g. 'site example.com status'",
            )

        words = _leading_words(remaining)
        spec = commands.match(scope, words)
        if spec is None:
            if flags.help or not words:
                if flags.help:
                    print("\n".join(_scope_help(scope, target)), file=stdout)
                    return 0
                raise UsageError(
                    f"missing command for {target!r}", hint=f"see: site {target} --help"
                )
            known = [c.usage_words for c in commands.for_scope(scope)]
            close = difflib.get_close_matches(" ".join(words), known, 1)
            raise UsageError(
                f"unknown command 'site {target} {' '.join(words)}'",
                hint=f"did you mean 'site {target} {close[0]}'?"
                if close
                else f"see: site {target} --help",
            )

        parser = _Parser(
            prog=f"site {target} {spec.usage_words}".strip(),
            description=spec.summary,
            add_help=False,
        )
        if spec.configure:
            spec.configure(parser)
        if flags.help:
            print(parser.format_help().rstrip(), file=stdout)
            if spec.handler is None:
                print(f"\n(Planned for Phase {spec.phase}; not available yet.)", file=stdout)
            return 0
        ns = parser.parse_args(remaining[len(spec.words) :])

        if spec.handler is None:
            raise NotImplementedYet(
                f"'site {target} {spec.usage_words}' is planned for Phase {spec.phase} "
                "and is not available in this version"
            )
        if (os.geteuid() if euid is None else euid) != 0:
            raise PreconditionFailed("site must be run as root", hint=f"sudo site {' '.join(args)}")

        pths = paths or Paths.default()
        ctx = Context(
            paths=pths,
            out=out,
            probe=probe or SystemProbe(),
            config=config_mod.load(pths.config_file),
            argv=command_echo,
            domain=domain,
            dry_run=flags.dry_run,
            use_syslog=use_syslog,
        )

        if spec.kind == "D" and not flags.dry_run:
            _confirm_destructive(spec, target, flags, stdin, out)

        result: CommandResult
        if spec.kind in ("M", "D") and not flags.dry_run:
            pths.create_runtime_dirs()
            job_lock = pths.run / ("job-" + "-".join(spec.words) + ".lock")
            lock = pths.global_lock if spec.lock else job_lock
            with FileLock(lock, timeout=ctx.config.lock_timeout if spec.lock else 5):
                result = spec.handler(ctx, ns)
        else:
            result = spec.handler(ctx, ns)

        out.result(command_echo, result.data, text=result.text, disclaimer=result.disclaimer)
        return result.exit_code
    except DPError as exc:
        out.error(command_echo, exc.code, exc.message, hint=exc.hint)
        return int(exc.exit_code)
    except KeyboardInterrupt:
        out.error(command_echo, "interrupted", "interrupted")
        return 130
    except Exception as exc:  # last-resort guard: never dump a traceback by default
        out.error(command_echo, "internal_error", f"internal error: {type(exc).__name__}: {exc}")
        if out.verbose:
            traceback.print_exc(file=stderr)
        return int(ExitCode.FAILED)
    finally:
        if ctx is not None:
            ctx.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
