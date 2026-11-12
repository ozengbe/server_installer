# ozenix — Security Baseline (Phase 1 draft)

This is the target state the Ansible installer enforces and `site system audit` checks. Each line becomes an audit check ID in Phase 9.

## Host
- Ubuntu 24.04 LTS, minimal install. Only the packages listed in architecture §3. Any unexpected listening socket is an audit failure.
- `/tmp` (tmpfs) and `/dev/shm` have `nodev,nosuid,noexec`. Host-wide `/proc` `hidepid` is **deferred**: it breaks polkit/logind on stock Ubuntu. Tenants get the same protection from `ProtectProc=invisible` inside their sandbox (Phase 4).
- sysctl: `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=1`, `kernel.yama.ptrace_scope=2`, `fs.protected_symlinks=1`, `fs.protected_hardlinks=1`, `fs.protected_fifos=2`, `fs.protected_regular=2`, `fs.suid_dumpable=0`, `net.ipv4.conf.all.rp_filter=1`, no IP forwarding (except WireGuard / Tier C as required), `kernel.apparmor_restrict_unprivileged_userns=1`.
- AppArmor enabled. Every shipped and generated profile is in enforce mode.
- Time sync via `systemd-timesyncd` or chrony (TLS and logs depend on correct time).
- auditd rules for: sudo, changes under `/etc/ozenix`, `/etc/ssh`, `/etc/nginx`, `/etc/sudoers*`, and nftables changes.

## SSH
- `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `AuthenticationMethods publickey`.
- `AllowGroups dp-admins dp-sftp`. `MaxAuthTries 3`, `LoginGraceTime 30`, `ClientAliveInterval 300`. Keys only from root-owned `/etc/ssh/authorized_keys.d/%u`. Port stays 22 (moving it adds little and complicates socket activation and firewall transitions).
- Modern algorithms only (curve25519/sntrup or mlkem hybrid KEX, chacha20-poly1305/aes-gcm, ed25519/sk-ed25519 host keys first).
- `Match Group dp-sftp`: `ChrootDirectory /srv/tenants/%u-root` (exact layout fixed in Phase 8), `ForceCommand internal-sftp -l INFO`, and all forwarding and TTY allocation disabled.

## Firewall (nftables, `inet` table)
- Input default **drop**. Allowed: established/related, loopback (non-tenant), ICMP/ICMPv6 essentials (rate-limited; ND/RA as required), TCP 80/443, UDP 443, SSH from the admin allowlist or `wg0`, WireGuard UDP port.
- Forward default **drop**.
- Output: open for the host. Tenant cgroups restricted per architecture §4.5.
- Ruleset is checked with `nft -c` and applied with an auto-rollback timer.

## nginx
- TLS 1.3 + TLS 1.2 (ECDHE + AEAD suites only). `ssl_prefer_server_ciphers off` (TLS 1.3 clients choose). Session tickets off or rotated. OCSP stapling not relied on (Let's Encrypt has ended OCSP).
- `server_tokens off`, `autoindex off`, `client_max_body_size` per site (default 64m), `client_body_timeout`/`client_header_timeout`/`send_timeout` 15–30s, `keepalive_timeout` 15s.
- Headers: `X-Content-Type-Options nosniff`, `Referrer-Policy strict-origin-when-cross-origin`, `X-Frame-Options SAMEORIGIN` (or CSP `frame-ancestors`), `Permissions-Policy` minimal. CSP per application template (report-only first). HSTS rolled out in stages: `max-age=300` → 1 week → 1 year; `preload` only on explicit request.
- Deny `/\.(?!well-known)`, VCS dirs, backup and editor files (`*.bak`, `*.swp`, `~`), `*.sql`, `*.env`, `composer.*`, PHP execution under upload directories.
- `limit_req_zone` / `limit_conn_zone` per IP (real IP when proxied), stricter on login endpoints in app templates.
- Default server: `return 444` and `ssl_reject_handshake on`.

## PHP (per tenant)
- `expose_php=Off`, `display_errors=Off`, `log_errors=On`, `allow_url_include=Off`, `session.cookie_httponly=1`, `session.cookie_secure=1`, `session.use_strict_mode=1`, `cgi.fix_pathinfo=0` (plus nginx `try_files $uri =404` before fastcgi).
- `disable_functions`: `exec`, `passthru`, `shell_exec`, `system`, `proc_open`, `popen`, `pcntl_*` by default. Overridable per site with an audit warning. (This is defense in depth only; the sandbox is the real boundary.)
- `upload_tmp_dir`, `session.save_path`, and `sys_temp_dir` point at the tenant's private paths.

## MariaDB
- `skip-networking`, `local_infile=0`, `secure_file_priv=/var/lib/mysql-files` (empty, root-only). `root@localhost` uses `unix_socket` auth only. Anonymous users and the test DB are removed.

## Redis / Valkey (per tenant)
- `port 0`, `unixsocket` under `/run/ozenix/<tid>/` with mode 0660. Default ACL user off; one ACL user per tenant. `rename-command`/ACL denies `CONFIG`, `DEBUG`, `MODULE`. `maxmemory` set with `allkeys-lru`. `protected-mode yes`.

## Secrets
- None in source, templates, logs, or `ps` output (secrets are passed by file descriptor, credential file, or stdin, never argv).
- Control-plane secrets are stored with `systemd-creds encrypt`. Tenant secrets are `root:<tid> 0640`.

## Updates
- unattended-upgrades runs daily from the security pocket only (+ ESM with Ubuntu Pro). `Automatic-Reboot "false"`. Reboot-required is reported by `site system health` and alerting.

## Logging
- journald persistent with size caps; logrotate for nginx and per-tenant logs; audit log append-only and shipped off-host.

## Secure coding (enforced in CI)
- Commands run only through `ozenix/core/proc.py`: argv lists, never a shell, a clean environment, mandatory timeouts. No other module may import `subprocess`; `os.system`, `os.popen`, `os.exec*`, `eval`, `exec`, `pickle`, `marshal` and `tempfile.mktemp` are forbidden (`tests/security/test_forbidden_calls.py`, `tools/semgrep/ozenix.yml`).
- Every outbound HTTP request checks its URL where it is made: the Cloudflare client only calls `https://api.cloudflare.com/client/v4/...`; alert webhooks must be `https://`, or `http://` to a loopback relay.
- SQL is built only from validated identifiers (tenant ids `t` + 4 digits, database names `[a-z0-9_]`) and passed on stdin.
- Files are written atomically, created with no-follow and exclusive flags under root-owned parents, and never world-writable.
- An accepted scanner finding carries an inline `# nosec <id>  # reason` (Bandit) or `# noqa: S<id>` (Ruff) next to the code it covers. No rule is switched off globally.

## Release gate (every phase)
A phase is complete only when all of these pass or have been reviewed, and `docs/audits/phase-<n>-audit.md` records the result:

| Check | Tool | Where | Fails the build |
|---|---|---|---|
| Lint, format, types | Ruff, MyPy (strict) | `tools/check.sh`, CI `checks` | yes |
| Unit, security and regression tests | pytest (90% coverage minimum) | `tools/check.sh`, CI `checks` | yes |
| Python security lint | Bandit | `tools/security-scan.sh`, CI `security` | yes, on any finding |
| Pattern rules | Semgrep: `tools/semgrep/ozenix.yml`, `p/python`, `p/secrets` | same | yes, on any finding |
| Dependency vulnerabilities | pip-audit (PyPI and OSV advisories) on the pinned dev and CI tools; ozenix itself has no runtime dependencies | same | yes |
| Secrets in the tree and history | Gitleaks (checksum-pinned release) | same | yes |
| Shell and Ansible | shellcheck, ansible-lint (production profile), playbook syntax | `tools/check.sh` | yes |
| Install, idempotence, integration | real Ubuntu host: install twice (second run `changed=0`), full integration suite | CI `integration`, test server | yes |
| Host hardening | `site system audit`, Lynis, `systemd-analyze security` on dp-* units | test server, reviewed | reviewed |
| TLS | testssl.sh or SSLyze against a test site | test server, reviewed | reviewed |
| Web | OWASP ZAP baseline against test sites | test server, reviewed | reviewed |

Safety is not used: its current CLI needs an account. pip-audit checks the same advisory data (PyPI, OSV).
