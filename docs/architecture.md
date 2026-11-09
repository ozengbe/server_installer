# DomainPilot — System Architecture (Phase 1 draft)

Status: **PROPOSED — awaiting approval**. Nothing here is implemented yet.
Related: [threat-model.md](threat-model.md) · [security-baseline.md](security-baseline.md) · [cli-spec.md](cli-spec.md) · [roadmap.md](roadmap.md)

---

## 1. Starting point

| Item | Finding (2026-11-09) |
|---|---|
| Project directory | Empty. Greenfield project, no existing code, config or dependencies. |
| Version control | Not a git repository. Directory lives inside **OneDrive** (see §11 risk R-DEV-1). |
| Dev workstation | Windows 11 Pro; Docker Desktop running; no local Python; no Ubuntu WSL distro. |
| Target | Ubuntu Server 24.04 LTS (x86_64 first, arm64 later). |

Consequence: every runtime test has to run inside Ubuntu 24.04 VMs. Docker containers are good enough for unit tests and template rendering. They are **not** good enough for systemd, nftables, AppArmor, cgroup, or SFTP-chroot tests (see roadmap Phase 0).

---

## 2. Architectural overview

```text
                 Internet
                    │
            ┌───────▼────────┐   (optional) Cloudflare proxy: WAF, DDoS, AOP
            │  Cloudflare    │
            └───────┬────────┘
                    │ 80/443 only (CF ranges when proxied)
┌───────────────────▼──────────────────────────────────────────────────────┐
│ DomainPilot host (Ubuntu 24.04)                                           │
│                                                                           │
│  nftables (default deny, v4+v6)   fail2ban   AppArmor   auditd/journald   │
│                                                                           │
│  ┌──────────── nginx (user nginx, shared, trusted) ───────────┐          │
│  │ default vhost = 444 · per-site vhosts · TLS · rate limits    │          │
│  └──────┬──────────────────────┬──────────────────────┬────────┘          │
│         │ unix sock            │ unix sock            │ unix sock         │
│  ┌──────▼──────┐        ┌──────▼──────┐        ┌──────▼──────┐            │
│  │ tenant t0001│        │ tenant t0002│        │ tenant t0003│            │
│  │ dp-php@     │        │ dp-php@     │        │ podman      │  Tier C    │
│  │ (Tier S)    │        │ (Tier S)    │        │ (rootless)  │            │
│  │ own slice,  │        │ own slice,  │        │ own userns, │            │
│  │ mount ns,   │        │ mount ns,   │        │ slice,      │            │
│  │ seccomp, AA │        │ seccomp, AA │        │ seccomp, AA │            │
│  │ redis@t0001 │        │ redis@t0002 │        │ redis@t0003 │            │
│  └──────┬──────┘        └──────┬──────┘        └──────┬──────┘            │
│         └──── /run/mysqld/mysqld.sock (per-tenant DB user + grants) ──┘   │
│                                MariaDB (skip-networking)                   │
│                                                                           │
│  Root-only plane: `site` CLI · registry (SQLite) · secrets · ACME ·       │
│  restic · systemd timers · exporters (bound to WireGuard/loopback only)   │
└──────────────┬────────────────────────────────────────────┬───────────────┘
               │ SSH (admins, key-only, optional VPN-only)  │ WireGuard
               │ SFTP (tenants, chrooted, internal-sftp)     │ (monitoring, backups)
        Admin workstation                         Monitoring/backup host
                                                  (Prometheus, Grafana,
                                                   Alertmanager, rest-server)
```

**Design principles**

1. **Two planes.** The *control plane* is root-owned: the CLI, registry, secrets, templates, ACME, and backups. The *tenant plane* is everything that runs tenant code. Nothing in the tenant plane can write into the control plane.
2. **Ansible owns the host baseline. The CLI owns tenants.** Ansible installs and hardens the shared services (idempotent, re-runnable). The `site` CLI creates and removes per-tenant objects. Neither tool edits the other's files. Drift detection checks both.
3. **Every mutation is a transaction.** Each operation is a list of steps with a compensating undo for each step. Progress is journaled in the registry. A crash leaves a recoverable state that `site <domain> repair` can finish or roll back.
4. **Validate before reload.** Every generated config is checked with the service's own validator (`nginx -t`, `php-fpm -t`, `sshd -t`, `nft -c`, `apparmor_parser -Q`) before it goes live. On failure the previous version is restored.
5. **Fail closed.** If isolation can't be fully applied (for example, the firewall set update fails), the tenant isn't started.

---

## 3. Component selection

Versions are what the Ubuntu 24.04 archive and upstream offered as of the author's knowledge. **Every version gets re-verified and pinned at the start of Phase 2.** Ubuntu 26.04 LTS is out by now. The code should keep the distro version behind one abstraction so 26.04 support is a later milestone, not a rewrite.

| Component | Choice | Source | Rationale / notes |
|---|---|---|---|
| OS | Ubuntu 24.04 LTS | — | Mandated. systemd 255, kernel 6.8 (GA) / HWE, AppArmor 4, cgroups v2 by default. |
| Web server | nginx **stable** branch | nginx.org signed apt repo (key fingerprint pinned) | Mandated signed repo. QUIC/HTTP/3 compiled in. Ubuntu's own 1.24 is the fallback. |
| PHP | PHP 8.3 (default) | Ubuntu `main` | Canonical security support for the lifetime of 24.04. Other versions (8.4/8.5) require the Sury repo, which is an **opt-in third-party trust decision**. |
| Database | MariaDB 10.11 LTS | Ubuntu `main` | LTS, covered by unattended security updates. Upstream 11.4/11.8 LTS is possible later through the mariadb.org repo. |
| Cache | Redis 7.0 (Ubuntu `universe`) **or** Valkey | see decision D2 | One instance per tenant, unix socket only, `port 0`. |
| Firewall | **nftables native** (no UFW) | Ubuntu `main` | UFW can't express cgroup/UID egress matching. Running both causes rule-ordering bugs. |
| IPS | fail2ban (nftables backend) | Ubuntu `universe` | sshd, nginx-limit-req, and nginx-botsearch jails. |
| MAC | AppArmor 4 | Ubuntu `main` | Per-tenant generated profile for PHP-FPM; stock profiles for nginx/mariadb where available. |
| SSH/SFTP | OpenSSH 9.6 + `internal-sftp` | Ubuntu `main` | |
| ACME | certbot + `dns-cloudflare` plugin **or** lego | see decision D5 | Behind an `AcmeBackend` interface. Must support ARI and short-lived certificates (Let's Encrypt is shortening lifetimes and no longer sends expiry emails). |
| Updates | unattended-upgrades + needrestart | Ubuntu `main` | Security pocket only. No automatic reboot. |
| Backups | restic → rest-server `--append-only` (or S3 with Object Lock) | Ubuntu `universe` / upstream | One repository per tenant with its own key, plus a system repository. |
| Monitoring | node / nginx / mysqld / php-fpm / redis exporters | mixed | Bound to the WireGuard interface or loopback only. Prometheus + Grafana + Alertmanager on a **separate** monitoring host. |
| Admin network | WireGuard | Ubuntu `main` | Private path for monitoring, backups, and optional VPN-only SSH/SFTP. |
| Config mgmt | ansible-core 2.16 | Ubuntu `universe` | Bootstrap runs `ansible-playbook -c local`. Remote inventory later supports multi-server. |
| CLI | Python 3.12, **stdlib only** | Ubuntu `main` | No PyPI dependencies at runtime, so the root-run CLI has a minimal supply-chain surface. |
| Secrets | `systemd-creds` (host key, TPM2 when present) + root-only files | systemd 255 | Encrypted at rest. Services receive secrets via `LoadCredentialEncrypted=`. |

> **`universe` caveat.** Packages in `universe` (ansible, restic, redis, fail2ban, certbot) get security updates through **Ubuntu Pro / ESM-Apps**, not the standard security pocket. For commercial hosting, plan on Ubuntu Pro or replace these with upstream packages we track ourselves. This is decision D2/D6.

---

## 4. Tenant isolation model

### 4.1 Evaluation

| Option | Isolation strength | Ops reliability | Overhead | Verdict |
|---|---|---|---|---|
| A. PHP-FPM pools in one master | Weak: shared master, no mount ns, no per-pool seccomp; `open_basedir` is not a security boundary | High | Lowest | **Rejected.** The spec forbids it for untrusted code. |
| B. **Per-tenant systemd-sandboxed service** (own php-fpm master per tenant) | Separate UID, mount ns, PID view (`ProtectProc=invisible`), seccomp, AppArmor, cgroup v2 limits, per-cgroup eBPF IP filtering, `RestrictNamespaces` | High: native systemd, `systemctl` lifecycle, deterministic | ~15–30 MB per tenant | **Default (Tier S)** |
| C. **Rootless Podman per tenant** (quadlet units) | B plus user-namespace UID remapping and an image-defined rootfs | Medium: more moving parts (subuid, pasta networking, images) | ~50–150 MB per tenant | **Tier C**: custom runtimes (`--type proxy` apps), customers who need their own stack |
| D. microVM / dedicated VM (Firecracker, KVM, separate server) | Separate kernel | Lower on a single host | High | **Tier V**: documented, out of scope until multi-server (Phase 11+) |

**Why B as the default, not containers.** A rootless container and a well-sandboxed systemd service use the *same* kernel primitives: namespaces, seccomp, cgroups, and LSM. Both share the host kernel, and neither matches a VM. Tier S doesn't use user namespaces, so it can set `RestrictNamespaces=yes` and keep Ubuntu's `apparmor_restrict_unprivileged_userns=1` in force. Unprivileged user namespaces are a recurring source of kernel privilege-escalation bugs, so removing them **reduces** kernel attack surface. Tier C needs user namespaces, so it accepts that surface in exchange for running arbitrary images.

**Honest limit:** Tiers S and C both share a kernel. A kernel local privilege escalation in tenant code is a full host compromise. Tenants who are *known hostile* or regulated belong in Tier V. See residual risk RR-1 in the threat model.

### 4.2 Per-tenant objects

Tenants are identified internally by an opaque ID (`t0001`…). Domain names are aliases that point to that ID. Domains are too long for Linux usernames, and using them as usernames would leak them through `/etc/passwd`.

| Object | Value |
|---|---|
| Runtime user/group | `t0001` (UID/GID from the reserved range 20000–29999, never reused) |
| Deploy (SFTP) user | `t0001-deploy`, a separate UID in group `t0001` (see 4.3) |
| Home / chroot root | `/srv/tenants/t0001` (`root:t0001 0750`; meets the chroot ownership rules) |
| Code | `/srv/tenants/t0001/app` (owned by the deploy user, runtime has read access; docroot `app/public`) |
| Writable data | `/srv/tenants/t0001/data` (uploads/cache, runtime-writable, **`noexec` via bind mount**) |
| Temp | `/srv/tenants/t0001/tmp` (0700 runtime) plus systemd `PrivateTmp=yes` |
| Logs | `/var/log/domainpilot/tenants/t0001/` (root-written nginx logs; PHP log owned by runtime). Read-only bind into the chroot. |
| Runtime socket | `/run/domainpilot/t0001/php.sock` (dir `t0001:nginx 0750`, socket 0660; nginx.org packages run workers as `nginx`) |
| PHP-FPM | `dp-php@t0001.service` (one master per tenant; config `/etc/domainpilot/tenants/t0001/php-fpm.conf`) |
| Redis (optional) | `dp-redis@t0001.service`, unix socket only, `maxmemory` capped, ACL default user disabled |
| Database | DB `t0001_<name>`, user `t0001`@`localhost`, grants only on `t0001\_%`, `MAX_USER_CONNECTIONS` set |
| Secrets | `/etc/domainpilot/tenants/t0001/secrets/` (root:t0001 0750, files 0640). Exposed to the app through an env file or `LoadCredential=` |
| cgroup | `dp-t0001.slice` under `domainpilot-tenants.slice`: `CPUQuota`, `MemoryMax`, `MemoryHigh`, `TasksMax`, `IOWeight` |
| Firewall | Tenant cgroup path matched in nftables `output` (see 4.5) |

### 4.3 Runtime/deploy split (recommended default)

The PHP process runs as `t0001`. It can **read** `app/` but can **write** only `data/` and `tmp/`. Code is uploaded via SFTP as `t0001-deploy`. A compromised web app therefore can't persist a webshell into the code tree, and `data/` is `noexec`. Some applications update their own code (WordPress auto-updates, plugin installers), so `site <domain> create --writable-code` switches to a single-user model and the audit reports it as a weaker setting. *(Decision D3.)*

### 4.4 Tier S sandbox (`dp-php@.service`, abridged)

```ini
[Service]
User=%i
Group=%i
Slice=dp-%i.slice
ExecStart=/usr/sbin/php-fpm8.3 --nodaemonize --fpm-config /etc/domainpilot/tenants/%i/php-fpm.conf
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=no   # PHP JIT/PCRE-JIT need W^X exceptions; JIT disabled → can flip to yes (evaluate)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount @debug @cpu-emulation @obsolete
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0027
TemporaryFileSystem=/srv/tenants:ro /var/log/domainpilot:ro /run/domainpilot:ro
BindReadOnlyPaths=/srv/tenants/%i/app
BindPaths=/srv/tenants/%i/data /srv/tenants/%i/tmp /run/domainpilot/%i
InaccessiblePaths=/etc/domainpilot /var/lib/domainpilot /root /var/backups
IPAddressDeny=169.254.0.0/16 fe80::/10 fd00:ec2::254/128
AppArmorProfile=domainpilot-tenant-%i
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=300
StartLimitBurst=5
```

Each tenant's mount namespace contains **only its own** tree, so other tenants' paths aren't just denied, they don't exist from inside. Final directives are tuned per PHP version in Phase 4 and verified with `systemd-analyze security` (target score ≤ 2.0, "OK").

### 4.5 Network policy (default deny between tenants)

The only authorized flows:

| # | From | To | Transport | Purpose |
|---|---|---|---|---|
| N1 | Internet / Cloudflare | nginx | TCP 80, 443; UDP 443 (HTTP/3) | Public web |
| N2 | nginx | tenant runtime | unix socket `/run/domainpilot/<tid>/php.sock` | FastCGI / proxy |
| N3 | tenant runtime | MariaDB | unix socket `/run/mysqld/mysqld.sock` | DB (MariaDB `skip-networking`) |
| N4 | tenant runtime | its own Redis | unix socket `/run/domainpilot/<tid>/redis.sock` | Cache |
| N5 | tenant runtime | Internet | TCP 80/443 (+ 25/465/587 opt-in per tenant) | APIs, updates, mail |
| N6 | tenant runtime | local resolver | UDP/TCP 53 to `127.0.0.53` | DNS |
| N7 | admins | sshd | TCP 22 (allowlist or WireGuard) | Administration |
| N8 | tenants (deploy users) | sshd | TCP 22 | SFTP (chrooted) |
| N9 | monitoring host | exporters | TCP over WireGuard only | Metrics |
| N10 | host | backup target | HTTPS over WireGuard / Internet | restic |
| N11 | host | ACME, Cloudflare API, Ubuntu/nginx mirrors | HTTPS | Control plane only |

Enforcement:

- **nftables `output` chain**: packets from sockets in `domainpilot-tenants.slice` (`socket cgroupv2 level 2`) are restricted to N5/N6. **All loopback TCP/UDP is dropped** (blocks reaching exporters, other services, and any tenant that accidentally binds to localhost). RFC1918/ULA/link-local destinations are dropped, as are cloud metadata addresses (169.254.169.254, fd00:ec2::254).
- **systemd `IPAddressDeny=`** (cgroup eBPF) is a second, independent layer for metadata and link-local.
- **Unix-socket reachability** is limited by directory permissions *and* by the mount namespace, since other tenants' socket directories aren't mounted.
- **IPv4 and IPv6** rules are written once in an `inet` family table, so both protocols are always covered.
- `site <domain> isolation test` actively checks every rule from inside the tenant's sandbox (see roadmap Phase 9).

### 4.5a Implementation notes (Phase 4, verified on Ubuntu 26.04)

- **Sockets:** `/run/domainpilot/<tid>/php/php.sock` and `.../cache/cache.sock`. `/run/domainpilot` is 0711 (traversable, not listable). nginx reaches PHP because the `nginx` user is a member of each tenant group. Other tenants can't reach the sockets, because they aren't members and because the paths don't exist inside their namespace.
- **Units:** `dp-php@.service` and `dp-cache@.service` (installer) carry the whole sandbox. A per-tenant drop-in written by `site` only sets the binary and the slice `dptenants-<tid>.slice`, which holds the limits.
- **AppArmor:** one profile per tenant, `domainpilot-tenant-<tid>`. On 26.04 systemd attaches it as a stack (`<profile>//&unconfined`), which is just as restrictive; the profile allows signals to the tenant's own stacked label. Processes can only execute the PHP-FPM or cache binary, so `mail()` and any `exec` bypass of `disable_functions` fail by design. Applications must send mail over SMTP; ports 25/465/587 are opt-in per tenant (`tenant_smtp_uids`).
- **Egress:** nftables `meta skuid 20000-29999 jump tenant_egress` lets tenants reach only the DNS stub and outbound TCP 80/443. Loopback, RFC1918/CGNAT, link-local/metadata and multicast are dropped on IPv4 and IPv6. Matching on UID needs no per-tenant rules and can't fail at boot.
- **Database:** `<tid>@localhost`, `unix_socket OR mysql_native_password`, ``ALL ON `<tid>_%`.*`` only, `MAX_USER_CONNECTIONS 20`.
- **Code read-only for the runtime:** `app/` is owned by `<tid>-deploy` and mounted read-only in the PHP sandbox. Only `data/` and `tmp/` are writable.
- **Measured:** systemd exposure score is at or below 2.0 for both units. The isolation suite (`tests/integration/test_phase4_isolation.py`) runs a probe through each tenant's own PHP-FPM.
- **Deferred: per-tenant disk quotas.** ext4 project quotas need filesystem features (`project`, `quota`) that can't be enabled on a mounted root filesystem. That needs either an XFS/ext4 data volume for `/srv/tenants` prepared at install time, or provider-side volumes. Until then, disk use per tenant isn't capped (threat TH6 partially open).

### 4.6 Shared components and why they are trusted

| Shared component | Risk | Mitigation |
|---|---|---|
| nginx | One process reads all tenants' static files and talks to all sockets | No tenant-controlled nginx config (no `.htaccess`-style includes). Configs come only from templates. `disable_symlinks if_not_owner from=$document_root`. AppArmor profile. |
| MariaDB | One server, shared buffers | Grants per tenant, `skip-networking`, per-user connection limits. `local_infile=0`. `secure_file_priv` set to an empty dir. No `FILE`/`SUPER` grants. |
| Kernel | Shared by all tiers S/C | Patching, `RestrictNamespaces`, seccomp, AppArmor. Tier V for hostile tenants. |

---

## 5. Control plane and privilege separation

```text
admin ──ssh──► sudo (group dp-admins only, logged) ──► /usr/local/bin/site
                                                         │  python3 -I -E, stdlib only
                                                         ▼
                              ┌──────────── domainpilot (root) ────────────┐
                              │ validate input → acquire lock → plan steps │
                              │ → journal → execute (argv only, no shell)  │
                              │ → validate configs → reload → audit log    │
                              └───────┬───────────────────────┬────────────┘
                                      │ privileged ops         │ ops inside tenant trees
                                      ▼                        ▼
                               systemctl / nft / nginx    setpriv --reuid=tXXXX
                               mariadb (root socket)      (drop to tenant UID before
                                                           touching tenant-owned files)
```

Rules the code enforces:

1. **Root never follows tenant-controlled paths.** Any operation under `/srv/tenants/<tid>` either drops to the tenant UID first (`setpriv`) or uses `os.open(..., O_NOFOLLOW)` / `openat`-style walking with `dir_fd`. This applies to chmod/chown fixes, backups, restores, and deletes. Recursive operations never use `shutil.rmtree` without `dir_fd` support verified.
2. **No shell.** `subprocess.run([...], shell=False)` with absolute binary paths, a scrubbed environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`), a timeout, and captured output. A single `core.proc.run()` wrapper is the only allowed entry point, enforced by a lint test.
3. **Strict validation at the edge.** Domains are IDNA-normalized to A-labels, lowercased, and checked against RFC 1035 label rules. Single-label, IP-literal, and reserved names are rejected. Tenant IDs match `^t\d{4,6}$`. Usernames match `^t\d{4,6}(-[a-z]{1,8})?$`. PHP versions come from an allowlist. Every value that reaches a template has already passed a typed validator, and templates (`string.Template`) refuse unknown placeholders.
4. **Locking.** A global `flock` on `/run/domainpilot/global.lock` covers host-wide changes. A per-tenant lock covers tenant changes. Lock timeouts return exit code 4.
5. **Atomic writes.** Write to a temp file in the target directory, `fsync`, `rename`, `fsync` the dir. The previous version is kept in `/var/lib/domainpilot/history/` for rollback.
6. **Audit log.** One JSON event per privileged operation: `SUDO_USER`, argv (secrets redacted), plan, result, and duration. Events go to journald (`SYSLOG_IDENTIFIER=domainpilot-audit`) and to `/var/log/domainpilot/audit.jsonl`, which is append-only via `chattr +a` and shipped off-host by the monitoring pipeline.
7. **Who can run it.** sudoers grants `site` only to `%dp-admins`. The CLI refuses to run unless `euid == 0`, and records the invoking admin.

**State.** `/var/lib/domainpilot/registry.sqlite3` (root 0600, WAL mode) stores tenants, domains, aliases, TLS state, operation journal, and schema version with migrations. The registry is the source of truth. `site system audit` reports drift between the registry and the live system.

**Configuration.** `/etc/domainpilot/domainpilot.toml` (`tomllib` is stdlib in 3.12) holds host settings and the optimization profile. Secrets never go here.

---

## 6. Source tree (proposed)

```text
domainpilot-server/
├── domainpilot/                 # Python package (installed to /usr/lib/domainpilot)
│   ├── cli/                     # argparse grammar, output (text/json), exit codes
│   ├── core/                    # proc runner, validation, atomic fs, locks, txn, audit, registry
│   ├── isolation/               # tenant identity, sandbox units, AppArmor, cgroups, nft sets
│   ├── nginx/  php/  database/  redis/  ssl/  cloudflare/  sftp/
│   ├── optimization/  updates/  backups/  monitoring/  security/
│   └── templates/               # nginx, php-fpm, systemd, apparmor, nft (string.Template)
├── ansible/                     # site.yml + roles/ (base, ssh, firewall, apparmor, nginx, php,
│                                #   mariadb, redis, acme, fail2ban, updates, restic, monitoring, cli)
├── installer/install.sh         # bootstrap: verify OS → apt ansible-core → run playbook locally
├── tests/
│   ├── unit/                    # pure Python, runs anywhere (Docker on Windows)
│   ├── integration/             # runs inside disposable Ubuntu 24.04 VMs
│   └── security/                # negative tests: injection, traversal, symlink, escape, egress
├── docs/
└── README.md
```

The runtime is stdlib only. Development tooling (pytest, mypy `--strict`, ruff, ansible-lint, shellcheck) lives in a dev requirements file and **never ships to servers**.

---

## 7. Key cross-cutting designs (detail in later phases)

- **nginx changes:** render the candidate file, swap it in atomically, run `nginx -t`. On failure, restore the previous file and re-run `nginx -t`. Run `systemctl reload` only on success. The default server returns `444` and uses a self-signed cert with `ssl_reject_handshake on`.
- **Firewall changes (anti-lockout):** `nft -c -f candidate`, apply, then arm a `systemd-run --on-active=120s` rollback. The admin confirms with `site system firewall confirm` from a **new** SSH session, which disarms the rollback. Ansible uses the same mechanism.
- **SSH changes:** `sshd -t`, then reload (never restart). The existing session is preserved. The CLI refuses changes that would leave zero admin keys or zero `AllowGroups` members.
- **Optimization:** profile calculation is deterministic from hardware facts plus a 7-day metrics window, never instantaneous load. The output is a diff. `--apply` snapshots the current configs under an ID, and `site system optimize --rollback <id>` restores them.
- **Updates:** unattended-upgrades only on `${distro_id}:${distro_codename}-security` (+ ESM if Pro). No auto-reboot. needrestart in list mode, plus an allowlist of stateless services it may restart (nginx, php-fpm masters). MariaDB is never restarted automatically. A post-update health check runs, and update history comes from the apt history log plus our audit events.
- **Backups (Phase 8, implemented):** restic, one repository per tenant (`<base>/<tid>`) plus one for the server's own configuration (`<base>/system`: /etc/domainpilot, nginx, letsencrypt, mysql, php, ssh, AppArmor, nftables, and a consistent SQLite copy of the registry). Every repository password is derived from one 256-bit **master key** (HMAC-SHA256 per repository name). The key is shown once at `site system backup setup` and must be stored offline: the copy on the server is encrypted with that host's own key, so it is useless if the server is lost. Master key plus bucket credentials recover everything on a new server (`site system backup import-key`). DB dumps stream `mariadb-dump --single-transaction` → `restic backup --stdin` through a checked two-process pipe (restic 0.16 on 24.04 lacks `--stdin-from-command`). A dump that fails half-way gets its truncated snapshot forgotten. Restores always go to a root-only staging directory on the tenants' filesystem, are verified by restic, have setuid bits and device/fifo nodes stripped, and are only then swapped in by rename. The replaced tree is kept for manual rollback (pruned after 7 days). Databases get a `pre-restore` safety snapshot first, and a failed import puts it back. Nightly `dp-backup.timer`. Weekly `dp-backup-drill.timer` runs `restic check` (2% of the data re-read) plus a restore drill of every site, and the monitor alerts when it fails or is overdue. **Immutability (D7):** an S3-compatible bucket with versioning and Object Lock (default retention, e.g. 30 days), with a key that cannot delete object versions. A compromised server can only add delete markers; locked versions survive. See install.md.
- **SFTP (Phase 8):** an "SFTP account" is a labelled public key on the tenant's deploy user (`<tid>-deploy`, owns `app/`, runs no code). Keys live in root-owned `/etc/ssh/authorized_keys.d/<user>`, each line with `restrict`. sshd's `Match Group dp-sftp` forces `internal-sftp -d /app -u 0027`, chrooted at the tenant root (`%h`, root-owned 0750). Membership of `dp-sftp` comes with the first key and goes with the last; archiving or erasing a site revokes all keys. nginx `disable_symlinks if_not_owner` stops symlinks uploaded over SFTP from exposing files outside the site.
- **Monitoring (Phase 8):** no separate monitoring host (decided). `dp-monitor.timer` runs `site system monitor --notify` every 5 minutes: health checks, an HTTP probe of every enabled site, backup age and restore-drill result, and crash restarts recovered by systemd (`NRestarts`). It alerts only on change: new problem, resolved, a reminder for critical problems every N hours, crash events. Destinations are ntfy, Slack, Discord, Telegram or a generic webhook. The URL is a secret, given on stdin and stored encrypted. Bounded self-healing: nginx, MariaDB and fail2ban (drop-in) and the tenant units get `Restart=on-failure`, at most 5 starts in 10 minutes, then `OnFailure=dp-alert@%n` alerts at once. The Prometheus node exporter listens on loopback only.
- **Cloudflare:** one API token per zone, least privilege (`Zone:DNS:Edit` for DNS-01; `Zone:Read`/`Zone Settings:Read` for audits). Write actions (`--apply`) show a diff and require confirmation. When proxied: Full (strict), Authenticated Origin Pulls with a **per-zone** client certificate (the global CF cert would accept *any* Cloudflare customer), `set_real_ip_from` limited to the published CF ranges (refreshed by timer with sanity checks), and the origin firewall restricted to CF ranges.
- **Multi-server readiness:** the registry has a `host` column from day one, and the Ansible inventory is already remote-capable. A future control node calls the same CLI over SSH (no new daemon or API surface in v1).

---

## 8. Decisions

Architecture **approved 2026-11-09**. No specific answers were given for D1–D8, so the recommendations below are the working defaults. Any of them can still be revisited. D4 and D8 are partly done: tests run in Docker and Multipass VMs and the directory is under git, but the working copy hasn't moved out of OneDrive yet.

| ID | Decision | Recommendation (adopted default) |
|---|---|---|
| **D1** | Will tenants run **untrusted third-party code** (hosting customers), or code your team controls? | Assume untrusted. Tier S default, Tier C for custom runtimes, Tier V documented for hostile tenants. |
| **D2** | Redis (Ubuntu `universe`, 7.0) or Valkey (upstream, BSD license)? | Valkey if you won't have Ubuntu Pro. Redis 7.0 from the archive if you will. |
| **D3** | Runtime/deploy user split by default (read-only code)? | Yes, with `--writable-code` as an audited opt-out. |
| **D4** | Test infrastructure: Hyper-V/Multipass VMs on this PC, or cloud VMs? | Multipass on Hyper-V locally plus CI on cloud runners. Needs Python 3.12 locally or inside Docker. |
| **D5** | ACME client: certbot (apt) vs lego (pinned binary)? | **Decided (Phase 6): certbot from the Ubuntu archive** (4.0 on 26.04, plus python3-certbot-dns-cloudflare). Signed and security-maintained, ships a systemd renewal timer. The archive lego (4.9) is outdated. |
| **D6** | Ubuntu Pro available on production hosts? | Strongly recommended (`universe` security coverage, Livepatch for kernel fixes without reboots). |
| **D7** | Backup target: own rest-server, or S3-compatible with Object Lock? | **Decided (Phase 8): S3-compatible bucket with versioning + Object Lock** (B2, Wasabi, AWS S3, R2…). No extra server to run. Built and tested against a local restic repository until the bucket exists. |
| **D8** | Move the repo out of OneDrive into a git-tracked location? | Yes (see R-DEV-1). |

## 9. Architectural tradeoffs accepted

- **Per-tenant php-fpm masters cost memory** (~15–30 MB each). In exchange each tenant gets its own sandbox and limits. Plan density is roughly 100–150 tenants on a 16 GB host before tuning.
- **Per-tenant Redis** costs a few MB each, but avoids Redis ACL/keyspace sharing and noisy neighbours.
- **Shared nginx and MariaDB** are kept for density. They're treated as trusted components and hardened accordingly. Tenants never control their config.
- **No web panel** in v1, by design. All administration is SSH + CLI.
- **stdlib-only CLI.** It's more code to write (TOML read, templating, argparse), but nothing from PyPI runs as root.

## 10. Explicit non-goals for v1

Billing, a customer self-service portal, email hosting, DNS hosting other than via Cloudflare, Windows/other distros, Kubernetes, automatic major-version upgrades.

## 11. Development-environment risks

- **R-DEV-1 — OneDrive.** Sync can rewrite line endings, drop the executable bit, and create conflict copies (`file-PC.ext`). Shell scripts, templates, and SSH/nginx configs are sensitive to all three. Mitigations: git with `.gitattributes` (`* text=auto eol=lf`), which is already added, and ideally moving the working copy outside OneDrive.
- **R-DEV-2 — No Linux test host yet.** Phases 2+ can't be accepted without Ubuntu 24.04 VMs.
