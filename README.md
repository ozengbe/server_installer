# ozenix Secure Server Management Platform

A secure-by-default web server manager for Ubuntu 24.04 and 26.04 LTS: Ansible-hardened hosts, strict per-tenant isolation, and a `site` CLI.

**Status: 0.10.0 preview.** All roadmap phases (0-10) are implemented and validated on a real host. Releases are labelled preview until an independent review of the root-run code (security gate 6). See [CHANGELOG.md](CHANGELOG.md).

## Documents
For administrators:
- [Install guide](docs/install.md): download, verify, install, first site
- [Command reference](docs/commands.md): every command, and how isolation works
- [Administrator guide](docs/admin-guide.md): day-to-day operation
- [Upgrade guide](docs/upgrade.md)
- Runbooks: [incident](docs/runbooks/incident.md), [restore](docs/runbooks/restore.md), [rollback](docs/runbooks/rollback.md), [key rotation](docs/runbooks/key-rotation.md)
- [Security validation report](docs/security-report.md): what is tested, residual risks

Design and development:
- [Architecture](docs/architecture.md): components, isolation model, privilege model, open decisions
- [Threat model](docs/threat-model.md)
- [Security baseline](docs/security-baseline.md)
- [CLI specification](docs/cli-spec.md)
- [Roadmap](docs/roadmap.md)
- [Making a release](docs/release.md)

## Development

| Task | Command (Git Bash on Windows, or Linux) |
|---|---|
| Lint, type-check, unit and security tests, security scans (Bandit, Semgrep, pip-audit, Gitleaks) | `bash tools/check-docker.sh` (Windows/macOS; `--no-security` skips the scans) or `bash tools/check.sh && bash tools/security-scan.sh` (Linux with `pip install -e .[dev]`) |
| Create a disposable Ubuntu 24.04 test VM | `bash tools/vm.sh up` (requires [Multipass](https://canonical.com/multipass/install)) |
| Run integration tests in the VM (as root) | `bash tools/vm.sh test` |
| Destroy the VM | `bash tools/vm.sh down` |
| Unsigned test build of a release tarball | `bash tools/release.sh --snapshot` |

CI (`.github/workflows/ci.yml`) runs the same checks, then the integration tests on a disposable `ubuntu-24.04` runner.
Integration tests refuse to run on any host without the `/etc/ozenix-test-vm` marker. **Never create that marker on a production server.**

Priorities: Security → Isolation → Reliability → Maintainability → Performance → Ease of use.

## The `site` CLI

Commands:

```bash
sudo site example.com create [--type php|static|proxy] [--alias www.example.com] [--upstream https://host]
sudo site example.com status | disable | enable | repair | logs [--error|--php] [--lines N]
sudo site example.com delete [--purge] --confirm example.com   # without --purge: archived, data kept
sudo site example.com db create [--name app] | db status | db credentials [--rotate]
sudo site example.com php status | php restart | isolation status
sudo site example.com ssl [--staging] | ssl status | ssl renew [--force] | ssl revoke --confirm example.com
sudo site example.com autossl on|off
sudo site example.com cloudflare status|dns [--apply]|ssl|security
sudo site example.com optimize [--apply|--rollback ID] | php 8.x
sudo site system optimize [--analyze|--apply|--profile P|--history|--rollback ID]
sudo site system health | update [--check|--security|--history] | cloudflare token add|list|remove
sudo site list | system status | system firewall status|confirm|rollback
sudo site example.com backup | backup list | db backup
sudo site example.com restore [--files|--db|--all] [--snapshot ID] [--to-staging] --confirm example.com
sudo site example.com sftp create --key id.pub [--name alice] | sftp list | sftp revoke alice --confirm example.com
sudo site system backup setup --repository s3:https://ENDPOINT/BUCKET[/prefix] --credentials-stdin
sudo site system backup [--status|--verify|--test-restore] | backup show-key | backup import-key
sudo site system backup rotate-key [--finish] | backup sites   # key rotation; disaster recovery
sudo site example.com create --tenant-id t0003                  # recreate a lost server's site
sudo site version
echo URL | sudo site system alerts setup --kind ntfy|slack|discord|telegram|webhook --url-stdin
sudo site system audit | system security | example.com security [--verbose-report]
sudo site example.com isolation audit | isolation test   # live escape attempts from inside the site
sudo site system alerts test|status | system monitor [--notify] | system logs [--audit|--errors] [-n N]
```

Every command takes `--json`, `--dry-run` (mutating commands) and `--help`. New sites get a certificate automatically (AutoSSL) as soon as their DNS points at the server; until then they are served over HTTP. Settings: `[ssl] email`, `staging`, `autossl` in `/etc/ozenix/ozenix.toml`. Commands from later phases are registered and say which phase adds them.

Layout on a server: the package lives in `/usr/lib/ozenix/releases/<version>/` (`current` points at the active one) and the wrapper at `/usr/local/bin/site` ([bin/site](bin/site)), which runs Python in isolated mode (`-I`). The runtime uses only the standard library. Core modules are in [ozenix/core/](ozenix/core/):

| Module | Role |
|---|---|
| `validate` | strict validators (`fullmatch`, IDNA, special-use names); fuzz-tested |
| `proc` | the only place subprocesses start: argv-only, absolute paths, scrubbed env, timeouts |
| `fsutil` | atomic writes and no-follow reads; refuses symlinks and group- or world-writable directories |
| `locks` | `flock`-based global/tenant locks |
| `registry` | SQLite source of truth with migrations; tenant IDs/UIDs never reused |
| `txn` | step transactions with reverse-order rollback and a crash journal |
| `audit` | append-only JSON audit log + journald, with secrets redacted |
