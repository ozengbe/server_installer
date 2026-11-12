"""A real Laravel project on a real host, deployed by the site user over SSH.

Proves: code stays read-only for PHP (storage and caches go to data/), the
front controller is the only PHP that runs, the scheduler timer runs, the
queue worker starts, and the .env checks pass after `env protect`.
Runs only on a disposable test host (/etc/ozenix-test-vm); needs network
access to packagist.org.
"""

from __future__ import annotations

import http.client
import json
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.integration

SITE = "/usr/local/bin/site"
DOMAIN = "p13laravel.example.com"
USER = "p13dev"


def site_json(*args: str) -> dict[str, Any]:
    r = subprocess.run([SITE, "--json", *args], capture_output=True, text=True, timeout=900)
    data = json.loads(r.stdout or r.stderr)
    assert r.returncode in (0, 10, 11) and data["ok"], r.stdout + r.stderr  # 10/11: findings
    return dict(data["result"])


def as_site_user(key: Path, command: str, timeout: float = 900) -> subprocess.CompletedProcess[str]:
    """A login shell (reads ~/.profile: PHP alias, Laravel paths, umask)."""
    return subprocess.run(
        [
            "/usr/bin/ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            f"{USER}@127.0.0.1", f"bash -lc {json.dumps(command)}",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )  # fmt: skip


def http_get(path: str = "/") -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=30)
    try:
        conn.request("GET", path, headers={"Host": DOMAIN})
        resp = conn.getresponse()
        return resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()


@pytest.fixture(scope="module")
def laravel(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    assert Path("/etc/ozenix-test-vm").is_file(), "test host only"
    subprocess.run([SITE, DOMAIN, "delete", "--purge", "--confirm", DOMAIN], capture_output=True)
    key = tmp_path_factory.mktemp("key") / "id"
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True
    )
    made = site_json(
        DOMAIN, "create", "--type", "laravel", "--user", USER, "--key", f"{key}.pub", "--no-ssl"
    )
    tenant = made["tenant"]
    deploy = as_site_user(
        key,
        "cd ~/data && rm -rf src && composer create-project --no-interaction --prefer-dist "
        "--no-progress laravel/laravel src && rm -rf ~/app/public && cp -a src/. ~/app/ "
        "&& rm -rf src && cd ~/app && php artisan key:generate --force",
    )
    assert deploy.returncode == 0, deploy.stdout[-2000:] + deploy.stderr[-2000:]
    # The site's MariaDB database (created with the site), as the create output says.
    creds = site_json(DOMAIN, "db", "credentials", "--show-secret")
    env_lines = {
        "DB_CONNECTION": "mariadb",
        "DB_SOCKET": "/run/mysqld/mysqld.sock",
        "DB_DATABASE": f"{tenant}_app",
        "DB_USERNAME": creds["user"],
        "DB_PASSWORD": creds["password"],
    }
    script = "cd ~/app && " + " && ".join(
        f"(grep -q '^#* *{k}=' .env && sed -i 's|^#* *{k}=.*|{k}={v}|' .env"
        f" || echo '{k}={v}' >> .env)"
        for k, v in env_lines.items()
    )
    migrated = as_site_user(key, script + " && php artisan migrate --force")
    assert migrated.returncode == 0, migrated.stdout[-2000:] + migrated.stderr[-2000:]
    yield {"tenant": tenant, "key": key, "root": Path(f"/srv/tenants/{tenant}")}
    subprocess.run([SITE, DOMAIN, "delete", "--purge", "--confirm", DOMAIN], capture_output=True)


def test_laravel_answers_with_read_only_code(laravel: dict[str, Any]) -> None:
    root = laravel["root"]
    deadline = time.monotonic() + 60
    status, body = 0, ""
    while time.monotonic() < deadline:
        status, body = http_get()
        if status == 200 and "Laravel" in body:
            break
        time.sleep(2)
    assert status == 200 and "Laravel" in body, body[:500]
    # Compiled views and the package manifest went to data/, not into the code.
    views = list((root / "data/storage/framework/views").glob("*.php"))
    assert views, "Laravel did not write its compiled views to data/storage"
    assert not list((root / "app/storage/framework/views").glob("*.php"))
    # PHP cannot write the code: a probe as the runtime user fails.
    probe = subprocess.run(
        ["/usr/bin/setpriv", f"--reuid={laravel['tenant']}", f"--regid={laravel['tenant']}",
         "--clear-groups", "--", "/usr/bin/touch", str(root / "app/public/shell.php")],
        capture_output=True,
    )  # fmt: skip
    assert probe.returncode != 0


def test_only_the_front_controller_runs_php(laravel: dict[str, Any]) -> None:
    status, _ = http_get("/index.php")
    assert status == 200
    # Another .php file in public/ (e.g. a planted shell) is never executed.
    as_site_user(laravel["key"], "echo '<?php echo 7*6;' > ~/app/public/x.php")
    status, body = http_get("/x.php")
    assert status == 404 and "42" not in body
    # Uploads served from data/storage/app/public; PHP never runs there.
    upload = laravel["root"] / "data/storage/app/public"
    as_site_user(laravel["key"], "echo hello > ~/data/storage/app/public/hi.txt")
    as_site_user(laravel["key"], "echo '<?php echo 6*7;' > ~/data/storage/app/public/y.php")
    assert http_get("/storage/hi.txt") == (200, "hello\n")
    status, body = http_get("/storage/y.php")
    assert status == 404 and "42" not in body
    assert (upload / "hi.txt").exists()
    for path in ("/.env", "/artisan", "/composer.json", "/../.env"):
        assert http_get(path)[0] in (400, 404), path


def test_scheduler_and_queue(laravel: dict[str, Any]) -> None:
    t = laravel["tenant"]
    timer = subprocess.run(
        ["/usr/bin/systemctl", "is-active", f"dp-laravel-schedule@{t}.timer"],
        capture_output=True,
        text=True,
    )
    assert timer.stdout.strip() == "active"
    ran = subprocess.run(
        ["/usr/bin/systemctl", "start", f"dp-laravel-schedule@{t}.service"], capture_output=True
    )
    assert ran.returncode == 0, ran.stderr
    site_json(DOMAIN, "laravel", "queue", "on")
    time.sleep(3)
    worker = subprocess.run(
        ["/usr/bin/systemctl", "is-active", f"dp-laravel-queue@{t}.service"],
        capture_output=True,
        text=True,
    )
    assert worker.stdout.strip() == "active"
    site_json(DOMAIN, "laravel", "queue", "off")


def test_env_is_protected(laravel: dict[str, Any]) -> None:
    env = laravel["root"] / "app/.env"
    as_site_user(laravel["key"], "chmod 666 ~/app/.env")
    report = site_json(DOMAIN, "security")
    failing = {f["id"] for f in report["findings"] if f["severity"] in ("warn", "critical")}
    assert "ENV-PERMS" in failing and "ENV-DEBUG" in failing  # skeleton has APP_DEBUG=true
    site_json(DOMAIN, "env", "protect")
    assert env.stat().st_mode & 0o777 == 0o640
    as_site_user(
        laravel["key"],
        "sed -i 's/^APP_DEBUG=.*/APP_DEBUG=false/; s/^APP_ENV=.*/APP_ENV=production/' ~/app/.env",
    )
    report = site_json(DOMAIN, "security")
    failing = {f["id"] for f in report["findings"] if f["severity"] in ("warn", "critical")}
    assert not failing & {"ENV-PERMS", "ENV-DEBUG", "ENV-APP-ENV", "ENV-APP-KEY", "ENV-PUBLIC"}
