# DomainPilot — Security Validation Report (Phase 9)

Status: **preview**. Release gate #6 (a review of the root-run code paths by someone other than the author) is still open. Until it closes, this report is the author's own validation, not an independent assessment.

> Automated checks passed for the listed controls only. This is not a guarantee of security.

## 1. What was validated, and how

| Layer | How | Where |
|---|---|---|
| Host configuration | `site system audit`: about 40 read-only checks against the **running** state (sshd -T, nft, sysctl, MariaDB variables and accounts, file modes, nginx -T, timers), so drift after install is caught | `domainpilot/security/host_audit.py` |
| Site confinement (configured) | `site <d> isolation audit`: systemd sandbox properties as systemd applies them, exposure score ≤ 2.0, AppArmor mode, cgroup limits, directory owners and modes, database grants, account hygiene | `domainpilot/security/site_audit.py` |
| Site confinement (proven) | `site <d> isolation test`: escape attempts from **inside** the live site's PHP sandbox (other sites' files, sockets, processes and databases, host secrets, metadata, loopback, private networks, exec) | `domainpilot/security/isolation_test.py`, `isolation/probe.php` |
| Site hygiene | `site <d> security`: the above, plus world-writable files, setuid, secrets in the web root, symlinks leaving the site, PHP settings, certificate, SFTP keys, backups | same |
| DomainPilot itself | Negative tests: injection and traversal through the real binary, symlinks planted by tenants against root's backup, restore and purge, setuid uploads, privilege checks | `tests/integration/test_phase9_security.py`, `tests/security/` |
| Recovery | Firewall auto-rollback, crash-and-repair at every creation step, restore drill, crash → bounded restart → alert | phases 2a, 5 and 8 integration suites |

All suites run on a disposable Ubuntu 26.04 host (`/etc/domainpilot-test-vm`). CI runs 24.04.

## 2. Issues found and fixed during validation

| Found by | Issue | Fix |
|---|---|---|
| Phase 9 host audit (real server) | The Cloudflare token file was 0644. Its contents are encrypted with the host key, so the token was not exposed, but even ciphertext should be root-only | Installer enforces 0600 on every secret. The secret stores tighten the mode on every read |
| Phase 9 server run | The isolation test read NoNewPrivs, seccomp, capabilities and AppArmor from inside PHP, where open_basedir (on in production) hides them: false criticals | Read from the site's running PHP processes on the host side (cannot be influenced by the confined code) |
| Phase 9 server run | The database-grant check rejected a correct grant: `--batch` output escapes the backslash in `t0001_%` | Accept the escaped form |
| Phase 9 unit tests | The TLS-protocol check matched `TLSv1` inside `TLSv1.2`, a false critical | Token-exact parsing of `ssl_protocols` |
| Phase 9 review | The audit log was documented as `chattr +a`, but the installer never set it (TH19) | Installer sets and verifies the flag. The audit reports `AUDIT-APPEND-ONLY` |
| Phase 9 design | A probe on a live site must not be written by root into a tenant directory, or be reachable from the web | Written as the site's own owner (`setpriv`), random dot-name (nginx returns 404 for dot-files), called over the FastCGI socket, then deleted |
| Phase 8 server run | Rolling back tuning restored bytes but not the owner group (php-fpm.conf `root:<tenant>` became `root:root`): the site went down | Snapshots record and restore uid/gid. `atomic_write` also fixes an owner that differs when the bytes match |
| Phase 7 server run | `systemctl reload` of a tenant's PHP-FPM killed it: the AppArmor profile forbids exec, so php-fpm's re-exec fails | Tenant PHP is always restarted (Type=notify). The unit has no ExecReload |
| Phase 8 server run | Two restores in the same second collided on the staging directory | Random suffix |

## 3. Threat → test traceability (security gate #1)

Every threat in [threat-model.md](threat-model.md) §4 has at least one automated test. `tests/security/test_threat_coverage.py` fails the build if a threat is missing here or a listed test does not exist. "Partial" marks a control that is only partly testable today. The gap is listed in §4.

| Threat | Tests | Coverage |
|---|---|---|
| TH1 | `tests/integration/test_phase4_isolation.py::test_other_tenants_do_not_exist_in_namespace`, `tests/integration/test_phase4_isolation.py::test_code_is_read_only_for_runtime`, `tests/integration/test_phase9_security.py::test_isolation_test_from_inside_a_live_site` | full |
| TH2 | `tests/integration/test_phase4_isolation.py::test_other_tenants_do_not_exist_in_namespace`, `tests/integration/test_phase4_isolation.py::test_cache_isolation` | full |
| TH3 | `tests/integration/test_phase4_isolation.py::test_no_foreign_processes_visible` | full |
| TH4 | `tests/integration/test_phase4_isolation.py::test_network_egress_policy`, `tests/integration/test_phase9_security.py::test_isolation_test_from_inside_a_live_site` | full |
| TH5 | `tests/integration/test_phase4_isolation.py::test_network_egress_policy`, `tests/integration/test_phase2b_services.py::test_database_and_cache_not_on_network`, `tests/integration/test_phase2b_services.py::test_no_unexpected_public_tcp_listeners` | full |
| TH6 | `tests/integration/test_phase4_isolation.py::test_resource_limits_applied` | partial (no disk quota) |
| TH7 | `tests/integration/test_phase4_isolation.py::test_database_isolation`, `tests/integration/test_phase2b_services.py::test_mariadb_hardening` | full |
| TH8 | `tests/integration/test_phase9_security.py::test_tenant_symlinks_never_redirect_root`, `tests/integration/test_phase5_sites.py::test_symlink_to_host_file_is_not_served` | full |
| TH9 | `tests/security/test_cli_injection.py::test_hostile_targets_rejected_without_side_effects`, `tests/security/test_forbidden_calls.py::test_package_has_no_forbidden_constructs`, `tests/integration/test_phase9_security.py::test_hostile_domains_are_rejected`, `tests/integration/test_phase9_security.py::test_hostile_option_values_are_rejected` | full |
| TH10 | `tests/integration/test_phase9_security.py::test_hostile_option_values_are_rejected`, `tests/integration/test_phase9_security.py::test_hostile_domains_are_rejected` | full |
| TH11 | `tests/integration/test_phase2b_services.py::test_default_server_closes_unknown_http`, `tests/integration/test_phase2b_services.py::test_default_server_rejects_unknown_tls` | full |
| TH12 | `tests/unit/test_firewall_template.py::test_origin_lock_allows_web_ports_from_cloudflare_only` | partial (origin lock is opt-in; per-zone AOP not built) |
| TH13 | `tests/integration/test_phase6b_cloudflare.py::test_real_ip_trusts_cloudflare_only` | full |
| TH14 | `tests/integration/test_phase2a_baseline.py::test_sshd_effective_setting`, `tests/integration/test_phase2a_baseline.py::test_sshd_has_no_weak_algorithms`, `tests/integration/test_phase2b_services.py::test_fail2ban_jail_running` | full |
| TH15 | `tests/integration/test_phase8_ops.py::test_sftp_chroot_upload_and_escapes` | full |
| TH16 | `tests/unit/test_cloudflare.py::test_credential_store_roundtrip`, `tests/unit/test_cloudflare.py::test_certbot_dns01_argv` | full |
| TH17 | `tests/integration/test_phase2b_services.py::test_nginx_from_signed_nginx_org_repo`, `tests/integration/test_phase2b_services.py::test_unattended_upgrades_policy`, `tests/security/test_forbidden_calls.py::test_package_has_no_forbidden_constructs` | partial (universe packages need Ubuntu Pro for security updates) |
| TH18 | `tests/integration/test_phase8_ops.py::test_backup_and_restore_roundtrip`, `tests/integration/test_phase8_ops.py::test_verify_and_scheduled_restore_drill` | partial (immutability needs the Object Lock bucket) |
| TH19 | `tests/integration/test_phase9_security.py::test_system_audit_has_no_critical_findings` | partial (no off-host log shipping) |
| TH20 | `tests/integration/test_phase2a_baseline.py::test_firewall_auto_rollback_when_not_confirmed`, `tests/integration/test_phase2a_baseline.py::test_firewall_rejects_invalid_candidate` | full |
| TH21 | `tests/integration/test_phase5_sites.py::test_delete_requires_confirmation_then_archives_then_purges`, `tests/security/test_cli_injection.py::test_confirm_value_must_match_exactly` | full |
| TH22 | `tests/integration/test_phase6_ssl.py::test_status_and_key_protection`, `tests/integration/test_phase4_isolation.py::test_host_secrets_unreachable` | full |
| TH23 | `tests/integration/test_phase2b_services.py::test_nginx_sandboxed`, `tests/integration/test_phase2b_services.py::test_nginx_effective_config` | full |
| TH24 | `tests/integration/test_phase2b_services.py::test_nginx_effective_config` | partial (limits configured, not load-tested) |

## 4. Residual risks

Risks RR-1 to RR-6 from the threat model still stand. Phase 9 adds the open gaps behind every "partial" above:

| ID | Risk | Status / what closes it |
|---|---|---|
| RR-7 | **Backups are deletable until the bucket exists.** The local stand-in repository lives on the server it protects. | Configure the S3 bucket with versioning + Object Lock (install.md). `system audit` warns (`BKP-OFFSITE`) until then. |
| RR-8 | **Audit log only on the host.** Root can remove `chattr +a` and rewrite it; the flag only makes that deliberate and visible to the audit. | Ship the journal off-host (later phase). |
| RR-9 | **No per-tenant disk quota.** One site can fill `/srv`. | Monitor alerts at 90%. Project quotas need XFS/ext4 prjquota at mount time (deferred from Phase 4). |
| RR-10 | **Origin lock and AOP.** The firewall can restrict 80/443 to Cloudflare (`dp_cloudflare_origin_lock`), but it is off by default because not every site is proxied. Per-zone Authenticated Origin Pulls are not built. | Turn on the lock when all sites are proxied. AOP stays on the roadmap. |
| RR-11 | **L7 DoS.** Rate and connection limits are configured but not load-tested. A determined flood needs Cloudflare in front. | Accepted for v1. |
| RR-12 | **universe packages** (restic, Valkey/Redis, fail2ban, certbot) get security fixes only with Ubuntu Pro. | Decision D6: use Ubuntu Pro on production hosts. |

## 5. How to re-run

```bash
sudo site system audit                    # every host check, with fixes
sudo site system security                 # problems only, plus health
sudo site example.com isolation test      # live escape attempts from inside the site
sudo site example.com security --verbose-report
```

Exit codes: 0 all clear, 10 warnings, 11 critical findings.
