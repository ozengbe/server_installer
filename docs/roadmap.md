# DomainPilot — Development Roadmap (Phase 1 draft)

Each milestone is a small, reviewable change with explicit acceptance criteria. Nothing moves to the next milestone until the current one is reviewed. "VM" means a disposable Ubuntu 24.04 VM. Destructive or security tests never run against production.

| Phase | Milestone | Deliverables | Acceptance criteria |
|---|---|---|---|
| **0** ✅ | Repo & test harness | git repo (outside OneDrive), `pyproject.toml` (dev tools only), ruff + mypy `--strict` + pytest, shellcheck, ansible-lint, CI workflow, VM harness (Multipass or cloud, script to create/destroy fresh 24.04 VMs) | CI green on an empty package; `make vm-up && make vm-test && make vm-down` works |
| **1** ✅ | Architecture | architecture, threat model, baseline, CLI spec, roadmap | **Approved by you**, open decisions D1–D8 resolved |
| **2a** ✅ merged; CI 24.04 + real 26.04 host | Installer: base + SSH + firewall | `installer/install.sh`, roles `base`, `ssh`, `firewall` (with anti-lockout), `apparmor`, sysctl | Idempotent (2nd run = 0 changes); lockout test passes (bad rule auto-reverts in 120 s); audit baseline items for host/SSH/firewall pass |
| **2b** ✅ merged; CI 24.04 + real 26.04 host | Installer: services | roles `nginx` (signed repo), `php`, `mariadb`, `redis`/`valkey`, `fail2ban`, `updates` | Idempotent; `ss -tlnpu` shows only 22/80/443 (+wg); MariaDB/Redis not on TCP; default vhost returns 444 |
| **3** ✅ merged | CLI foundation | `core/` (proc runner, validators, atomic fs, locks, txn journal, audit log, registry + migrations), argparse grammar, `--json`/`--dry-run`, `site list`, `site system status` | Unit coverage ≥ 90% on `core/`; injection/traversal fuzz tests on validators; lint test forbids `shell=True`/`os.system` |
| **4** ✅ impl (branch phase-4; real 26.04 host: 74/74, exposure ≤ 2.0; disk quota deferred) | Tenant isolation engine | identity allocation, directory layout, `dp-php@` sandbox unit, AppArmor profile generator, cgroup slices, nft tenant egress, per-tenant Redis, DB grants, disk quota | `systemd-analyze security dp-php@tX` ≤ 2.0; full isolation suite (FS, SOCK, PROC, NET-META, NET-LO, DB, RES, IPv6) passes between 3 test tenants |
| **5** ✅ impl (branch phase-5; crash-injected at all 16 creation steps, repaired) | Site lifecycle | `create/status/enable/disable/delete/repair`, nginx templates (php/static/proxy), rollback on failed `nginx -t` | Crash-injection tests (kill at every step) are recoverable via `repair`; delete retains data unless `--purge` |
| **6** | AutoSSL + Cloudflare | ACME backend (D5), HTTP-01 + DNS-01, renewal timer, expiry monitoring, Cloudflare read-only audits then `--apply` actions, origin protection, AOP | Issue/renew against **LE staging** in VM; failed validation never reloads nginx; tokens never appear in logs/argv |
| **7** | Optimization + updates | hardware/metrics analysis, profiles, diff/apply/rollback, unattended-upgrades policy, needrestart policy, health checks | Apply then rollback restores byte-identical configs; no auto-reboot; update history visible |
| **8** | SFTP, backups, monitoring | chrooted SFTP, restic per-tenant repos, DB dumps, restore-to-staging, exporters on wg/loopback, alert rules, bounded restarts | SFTP escape tests fail as expected; scheduled restore test succeeds; killing a service triggers bounded recovery and then an alert |
| **9** | Security validation | `system audit`, `system security`, per-site security, negative test suite (injection, traversal, symlink races, privilege escalation, chroot escape, metadata, cross-tenant), recovery drills | All checks pass in VM; findings report with residual risks; **external review of CLI root paths recommended** |
| **10** | Release | admin guide, runbooks (incident, restore, rollback, key rotation), upgrade path, signed release artifact (`.deb` or tarball + checksum + signature) | Fresh install from docs alone on a clean VM by someone other than the author |

## Security acceptance criteria (gate for calling it "enterprise-ready")

1. Every threat in threat-model §4 has at least one passing automated test.
2. The isolation suite passes for Tier S (and Tier C if enabled) on IPv4 **and** IPv6.
3. No tenant can reach metadata, loopback services, other tenants' sockets, files, processes, or DBs.
4. Install is idempotent; firewall and SSH changes cannot lock out admins (tested).
5. Backups restore successfully in an automated drill; backup deletion from the host is impossible.
6. Root-run code paths have been reviewed by someone other than the author.
7. Residual risks are documented and disclosed.

Until all seven are met, releases are labelled **preview**.

## Immediate next steps after approval

1. Resolve D1–D8 (architecture §8).
2. Phase 0: `git init` in a non-OneDrive path, scaffold the tooling, and stand up the VM harness.
3. Phase 2a as the first implementation PR.
