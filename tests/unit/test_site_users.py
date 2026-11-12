"""Site users: each site has its own named Linux user that
logs in with an SSH key (SFTP + shell) and owns the site's code."""

from __future__ import annotations

import argparse
import io
import pwd
from pathlib import Path
from typing import Any

import pytest
from test_phase8 import ED25519, keygen_runner

from ozenix.cli import site_handlers
from ozenix.core import validate
from ozenix.core.errors import PreconditionFailed, UsageError, ValidationError
from ozenix.isolation.render import deploy_user_of
from ozenix.sftp import SftpManager
from ozenix.sites.lifecycle import CreateRequest


@pytest.mark.parametrize("name", ["john", "web_shop", "a1", "anna-maria"])
def test_valid_site_users(name: str) -> None:
    assert validate.site_user(name) == name


@pytest.mark.parametrize(
    "name", ["", "j", "John", "1john", "root", "www-data", "t0001", "t0001-deploy", "a b", "x" * 32]
)
def test_invalid_site_users(name: str) -> None:
    with pytest.raises(ValidationError):
        validate.site_user(name)


def _with_sftp(system: dict[str, Any]) -> Any:
    mgr = system["manager"]()
    calls: list[list[str]] = []
    original = mgr.run
    keygen = keygen_runner(calls)

    def run(argv: list[str], **kw: Any) -> Any:
        if argv[0].endswith("ssh-keygen"):
            return keygen(argv, **kw)
        return original(argv, **kw)

    mgr.sftp = SftpManager(
        audit=mgr.audit, argv=["site"], run=run, keys_dir=system["paths"].ssh_keys,
        hostname="srv.example.net",
    )  # fmt: skip
    system["paths"].ssh_keys.mkdir(parents=True, exist_ok=True)
    return mgr


def test_create_with_named_user_and_key(system: dict[str, Any]) -> None:
    mgr = _with_sftp(system)
    result = mgr.create(CreateRequest("example.com", site_user="john", site_key=ED25519))
    assert result["site_user"] == "john"
    useradds = [c for c in system["calls"] if c[0] == "/usr/sbin/useradd"]
    deploy = next(c for c in useradds if c[-1] == "john")
    assert deploy[deploy.index("--shell") + 1] == "/bin/bash"  # SFTP + shell
    runtime = next(c for c in useradds if c[-1] == result["tenant"])
    assert runtime[runtime.index("--shell") + 1].endswith("nologin")  # PHP user never logs in
    # In tests the uid lookup falls back to the automatic name; the key file is
    # written for whatever user the site has.
    assert result["login"] and result["login"].startswith("ssh ")
    keyfile = next(system["paths"].ssh_keys.iterdir())
    assert keyfile.read_text().startswith("restrict,pty ssh-ed25519 ")


def test_create_refuses_existing_or_bad_user(
    system: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    mgr = _with_sftp(system)
    with pytest.raises(ValidationError, match="reserved"):
        mgr.create(CreateRequest("a.example.com", site_user="root"))
    with pytest.raises(ValidationError):
        mgr.create(CreateRequest("a.example.com", site_user="x", site_key=ED25519))
    with pytest.raises(ValidationError):
        mgr.create(CreateRequest("a.example.com", site_user="john", site_key="not a key"))
    monkeypatch.setattr(
        pwd, "getpwnam", lambda n: pwd.struct_passwd((n, "x", 1000, 1000, "", "/home", "/bin/sh"))
    )
    with pytest.raises(PreconditionFailed, match="already exists"):
        mgr.create(CreateRequest("a.example.com", site_user="john"))
    assert system["registry"].get_site("a.example.com") is None


def test_deploy_user_lookup_by_uid(monkeypatch: pytest.MonkeyPatch) -> None:
    users = {"t0001": 20001}
    monkeypatch.setattr(
        pwd, "getpwnam", lambda n: pwd.struct_passwd((n, "x", users[n], 1, "", "", ""))
    )
    monkeypatch.setattr(
        pwd,
        "getpwuid",
        lambda uid: pwd.struct_passwd(("john", "x", uid, 1, "", "", ""))
        if uid == 30001
        else (_ for _ in ()).throw(KeyError(uid)),
    )
    assert deploy_user_of("t0001") == "john"
    users.clear()
    assert deploy_user_of("t0001") == "t0001-deploy"  # tenant gone: legacy name


def _ns(**kw: Any) -> argparse.Namespace:
    base = {"site_user": None, "site_key_file": None, "key_stdin": False}
    return argparse.Namespace(**(base | kw))


class _Ctx:
    def __init__(self, json_mode: bool = False) -> None:
        self.out = argparse.Namespace(json_mode=json_mode)
        self.dry_run = False


def test_cli_site_login(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx: Any = _Ctx()
    key = tmp_path / "john.pub"
    key.write_text(ED25519)
    assert site_handlers._site_login(ctx, _ns(site_user="john", site_key_file=str(key))) == (
        "john",
        ED25519,
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(ED25519))
    assert site_handlers._site_login(ctx, _ns(site_user="john", key_stdin=True))[1] == ED25519
    # Scripts (no terminal) may leave both out: automatic user, keys later.
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert site_handlers._site_login(ctx, _ns()) == (None, None)
    with pytest.raises(UsageError, match="needs --user"):
        site_handlers._site_login(ctx, _ns(site_key_file=str(key)))
    with pytest.raises(UsageError, match="not a public key file"):
        site_handlers._site_login(ctx, _ns(site_user="john", site_key_file=str(tmp_path / "x")))
    with pytest.raises(ValidationError):
        site_handlers._site_login(ctx, _ns(site_user="Root"))

    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", Tty(""))
    answers = iter(["anna", ED25519])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    assert site_handlers._site_login(ctx, _ns()) == ("anna", ED25519)
    answers = iter(["anna", ""])
    assert site_handlers._site_login(ctx, _ns()) == ("anna", None)  # key later
