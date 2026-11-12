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

### Changed (Cloudflare and HTTPS, the CloudPanel way)
- **ozenix no longer touches DNS by default.** Point the records at the server yourself, with the Cloudflare proxy on or off. Proxied DNS records are now opt-in: `create --cloudflare-dns`.
- **Every new site gets a self-signed placeholder certificate at once**, so HTTPS works immediately behind Cloudflare (SSL/TLS mode "Full"). Plain HTTP keeps working for direct visitors until Let's Encrypt issues a real certificate.
- **Names proxied through Cloudflare count as pointing at this server** when checking whether a certificate can be issued. The Let's Encrypt challenge passes through the proxy.
- **AutoSSL retries automatically.** The 5-minute self-check requests the certificate once DNS is ready, at most once an hour per site.
- `site help` lists the common tasks: sites, HTTPS, SFTP, database, backups. `--no-ssl` now works: it skips Let's Encrypt for that site.

### Added (CloudPanel-style sites)
- **Each site has its own named Linux user:** `create --user john --key john.pub`. It logs in with an SSH key, and gets SFTP and a shell in its own site. On a terminal, `create` asks for the name and key.
- **The server's own login is left as it is:** root, passwords, your accounts. The admin list (`dp_admins`) is optional.
- **PHP 8.2, 8.3, 8.4 and 8.5 side by side**, chosen per site (`--php`, `site <d> php <v>`). They come from ppa:ondrej/php, with its key pinned. On 26.04 only 8.5 is available until the PPA supports that release.
- **Node.js sites** (`--type nodejs`, Node.js 22/24/26 from signed official builds) and **Python sites** (`--type python`). Each runs as a sandboxed app service behind nginx, on a reserved local port only that site may use. Managed with `site <d> app status|restart|set`.

- **Laravel sites** (`--type laravel`):
  - code stays read-only for PHP; storage and caches live in `data/`;
  - only `public/index.php` runs PHP;
  - `/storage` URLs are served from `data/` with PHP never executed there;
  - a built-in scheduler timer, and an optional queue worker (`site <d> laravel queue on`).
- **.env protection** for all sites: `site <d> env protect` (owner = site user, mode 0640). `site <d> security` checks for a `.env` in web folders, its permissions, `APP_DEBUG`, `APP_ENV` and `APP_KEY`, without ever printing values. Site users' shells use `umask 027`.
- Composer is installed for site users.

### Upgrade notes
- Hosts installed from a git checkout before 0.10.0 are treated as version 0.0.0 and upgraded. The CLI moves from `/usr/lib/ozenix/ozenix` to `/usr/lib/ozenix/releases/0.10.0`.

### Known limits
See [docs/security-report.md](docs/security-report.md) §4. Most important:
- no per-site disk quota;
- the audit log is on the host only;
- backups are tamper-proof only with an Object Lock bucket;
- the root-run code has not yet had an independent review.
