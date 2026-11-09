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
