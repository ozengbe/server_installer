# DomainPilot Secure Server Management Platform

A secure-by-default Ubuntu 24.04 web server manager: Ansible-hardened hosts, strict per-tenant isolation, and a `site` CLI.

**Status: Phase 1 (architecture), proposed and awaiting approval. No implementation yet. Not for production use.**

## Documents
- [Architecture](docs/architecture.md): components, isolation model, privilege model, open decisions
- [Threat model](docs/threat-model.md)
- [Security baseline](docs/security-baseline.md)
- [CLI specification](docs/cli-spec.md)
- [Roadmap](docs/roadmap.md)

## Development

| Task | Command (Git Bash on Windows, or Linux) |
|---|---|
| Lint, type-check, unit and security tests | `bash tools/check-docker.sh` (Windows/macOS) or `bash tools/check.sh` (Linux with `pip install -e .[dev]`) |
| Create a disposable Ubuntu 24.04 test VM | `bash tools/vm.sh up` (requires [Multipass](https://canonical.com/multipass/install)) |
| Run integration tests in the VM (as root) | `bash tools/vm.sh test` |
| Destroy the VM | `bash tools/vm.sh down` |

CI (`.github/workflows/ci.yml`) runs the same checks, then the integration tests on a disposable `ubuntu-24.04` runner.
Integration tests refuse to run on any host without the `/etc/domainpilot-test-vm` marker. **Never create that marker on a production server.**

Priorities: Security → Isolation → Reliability → Maintainability → Performance → Ease of use.

## The `site` CLI (Phase 3 foundation)

Implemented so far: `site list`, `site <domain> status`, `site system status`, `site help` and `site version`, plus `--json`, `--dry-run`, `--confirm` and `--help` everywhere. Every other command in [docs/cli-spec.md](docs/cli-spec.md) is already registered. Running one says which phase adds it.

Layout on a server: the package lives in `/usr/lib/domainpilot/domainpilot/` and the wrapper at `/usr/local/bin/site` ([bin/site](bin/site)), which runs Python in isolated mode (`-I`). The runtime uses only the standard library. Core modules are in [domainpilot/core/](domainpilot/core/):

| Module | Role |
|---|---|
| `validate` | strict validators (`fullmatch`, IDNA, special-use names); fuzz-tested |
| `proc` | the only place subprocesses start: argv-only, absolute paths, scrubbed env, timeouts |
| `fsutil` | atomic writes and no-follow reads; refuses symlinks and group- or world-writable directories |
| `locks` | `flock`-based global/tenant locks |
| `registry` | SQLite source of truth with migrations; tenant IDs/UIDs never reused |
| `txn` | step transactions with reverse-order rollback and a crash journal |
| `audit` | append-only JSON audit log + journald, with secrets redacted |
