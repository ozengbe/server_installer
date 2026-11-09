# DomainPilot Secure Server Management Platform

A secure-by-default Ubuntu 24.04 web server manager: Ansible-hardened hosts, strict per-tenant isolation, and a `site` CLI.

**Status: Phase 2 (hardened host baseline + core services) implemented; tenant isolation (Phase 4) is next after the CLI foundation (Phase 3). Not for production use.**

## Documents
- [Architecture](docs/architecture.md): components, isolation model, privilege model, open decisions
- [Threat model](docs/threat-model.md)
- [Security baseline](docs/security-baseline.md)
- [CLI specification](docs/cli-spec.md)
- [Install guide](docs/install.md)
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

## The `site` CLI

Available now (Phases 3–5):

```bash
sudo site example.com create [--type php|static|proxy] [--alias www.example.com] [--upstream https://host]
sudo site example.com status | disable | enable | repair | logs [--error|--php] [--lines N]
sudo site example.com delete [--purge] --confirm example.com   # without --purge: archived, data kept
sudo site example.com db create [--name app] | db status | db credentials [--rotate]
sudo site example.com php status | php restart | isolation status
sudo site list | system status | system firewall status|confirm|rollback
```

Every command takes `--json`, `--dry-run` (mutating commands) and `--help`. Sites are HTTP-only until AutoSSL (Phase 6). Commands from later phases are registered and say which phase adds them.

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
