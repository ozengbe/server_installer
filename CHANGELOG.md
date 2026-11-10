# Changelog

Versions follow `MAJOR.MINOR.PATCH`. Releases are labelled **preview** until all seven security gates in [docs/roadmap.md](docs/roadmap.md) are met.

## 0.10.0 — 2026-11 (preview)

First packaged release. Supports Ubuntu 24.04 and 26.04 LTS.

### Added
- **Hardened host baseline:**
  - SSH: key-only, admins group;
  - nftables firewall with an anti-lockout rollback timer;
  - sysctl, AppArmor, fail2ban;
  - unattended security updates that never reboot.
- **Core services:** nginx from the signed nginx.org repository, PHP-FPM, MariaDB (unix socket only), and Redis or Valkey.
- **Tenant isolation.** Each site gets its own users, a systemd-sandboxed PHP-FPM and cache, an AppArmor profile, a cgroup slice, nftables egress rules and database grants.
- **Site lifecycle:** create, status, enable, disable, delete (archive or purge) and repair. Every create step is transactional.
- **TLS and Cloudflare:**
  - automatic Let's Encrypt certificates (AutoSSL), via HTTP-01 or Cloudflare DNS-01;
  - proxied DNS records;
  - read-only zone audits;
  - real client IPs;
  - an optional origin lock.
- **Optimization:** hardware-based profiles with diff, apply and rollback; update policy; health checks.
- **Operations:**
  - chrooted SFTP;
  - encrypted restic backups to an S3-compatible bucket;
  - restores through a verified staging copy;
  - a weekly restore drill;
  - bounded automatic restarts;
  - alerts via ntfy, Slack, Discord, Telegram or a webhook.
- **Security validation:** host and site audits, a live isolation self-test, a negative test suite, and a threat-to-test traceability gate.
- **Release and operations tooling (Phase 10):**
  - signed release tarball;
  - upgrade path: version check, pre-upgrade snapshot, versioned code directories, downgrade protection;
  - `site system backup rotate-key`;
  - `site system backup sites` and `site <domain> create --tenant-id` for disaster recovery onto a new server;
  - the admin guide and runbooks.

### Upgrade notes
- Hosts installed from a git checkout before 0.10.0 are treated as version 0.0.0 and upgraded. The CLI moves from `/usr/lib/domainpilot/domainpilot` to `/usr/lib/domainpilot/releases/0.10.0`.

### Known limits
See [docs/security-report.md](docs/security-report.md) §4. Most important:
- no per-site disk quota;
- the audit log is on the host only;
- backups are tamper-proof only with an Object Lock bucket;
- the root-run code has not yet had an independent review.
