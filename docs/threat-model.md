# DomainPilot — Threat Model (Phase 1 draft)

Status: **PROPOSED**. Method: asset- and trust-boundary-based, with STRIDE applied at each boundary. This is revisited at the end of every phase.

## 1. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Host root / control plane (CLI, registry, `/etc/domainpilot`) | Root access means every tenant is compromised |
| A2 | Tenant code, uploads, databases | Customer data: confidentiality and integrity |
| A3 | TLS private keys | Impersonation of customer sites |
| A4 | Cloudflare API tokens | DNS hijack, origin exposure, certificate mis-issuance |
| A5 | Backup repositories and keys | Contain everything; also the recovery path |
| A6 | Admin SSH keys / sudo | Equivalent to A1 |
| A7 | Availability of all sites | Commercial SLA |
| A8 | Audit logs | Forensics; attackers will try to erase them |

## 2. Actors

| ID | Actor | Capability assumed |
|---|---|---|
| T1 | Internet attacker | Arbitrary HTTP(S)/SSH traffic, scanning, credential stuffing, L7 DoS |
| T2 | **Malicious tenant** | Arbitrary PHP/container code execution as their own UID; full SFTP write to their own tree |
| T3 | Compromised tenant app | Same as T2, triggered by T1 through a vulnerable CMS/plugin. *The most likely threat.* |
| T4 | Compromised admin workstation | Steals SSH keys and sudo |
| T5 | Supply chain | Malicious or compromised package, repo, image, or Ansible role |
| T6 | Cloud/provider-level | Metadata service abuse, snapshot access |
| T7 | Careless admin | Misconfiguration, destructive commands, lockout |

## 3. Trust boundaries

```text
 B1 Internet ─► nginx           B4 tenant ─► shared services (MariaDB, nginx sockets)
 B2 Internet ─► sshd            B5 tenant ─► host network / metadata / loopback
 B3 tenant  ─► tenant           B6 admin  ─► root (sudo site)
                                B7 host   ─► external APIs (ACME, Cloudflare, backup, mirrors)
```

## 4. Threats and mitigations

| ID | Boundary | Threat (STRIDE) | Mitigation | Verified by |
|---|---|---|---|---|
| TH1 | B3 | T2 reads/writes another tenant's files (I/T) | Unique UIDs, 0750 roots, per-tenant mount namespace (other trees not mounted), AppArmor profile per tenant, SFTP chroot | isolation test FS-* |
| TH2 | B3 | T2 connects to another tenant's PHP/Redis socket (E) | Socket dirs `tid:nginx 0750`; not mounted in other namespaces | isolation test SOCK-* |
| TH3 | B3 | T2 sees/kills other tenants' processes, reads `/proc/<pid>/environ` (I) | `ProtectProc=invisible`, `ProcSubset=pid`, separate UIDs, `hidepid` on host `/proc` | PROC-* |
| TH4 | B5 | T2 reaches cloud metadata and steals instance credentials (E) | nftables drop + `IPAddressDeny` (two independent layers), v4 and v6 | NET-META-* |
| TH5 | B5 | T2 reaches localhost services (exporters, MariaDB TCP, other tenants' accidental listeners) (E/I) | MariaDB `skip-networking`, Redis `port 0`, nft drops all tenant-cgroup loopback traffic | NET-LO-* |
| TH6 | B5/B3 | T2 resource exhaustion: fork bomb, memory, disk, inodes (D) | cgroup `TasksMax`/`MemoryMax`/`CPUQuota`/`IOWeight`; per-tenant disk quota (project quota on XFS/ext4, evaluated in Phase 4); PHP-FPM `pm.max_children` | RES-* |
| TH7 | B4 | T2 escalates through MariaDB (`FILE`, `LOAD DATA LOCAL`, other DBs) (E/I) | Grants scoped to `tid\_%` only, no global privileges, `local_infile=0`, `secure_file_priv` restricted | DB-* |
| TH8 | B4 | T2 plants a symlink and tricks root (backup/restore/chown/delete) into following it (E) | Root never follows tenant paths: drops to tenant UID or uses `O_NOFOLLOW`/`dir_fd`. nginx `disable_symlinks if_not_owner` | SEC-SYMLINK-* |
| TH9 | B6 | Command injection via domain/username/arguments (E) | Strict validators, argv-only subprocess, no shell, templates reject unknown placeholders | SEC-INJ-* (fuzzed) |
| TH10 | B6 | Path traversal via domain or restore paths (E/T) | Validators reject `/`, `..`, NUL; paths built from tenant ID, never from user strings; `realpath` containment checks | SEC-TRAV-* |
| TH11 | B1 | Host-header / unknown-vhost abuse, exposing a default site (I) | Default server returns 444 with `ssl_reject_handshake` | NGX-DEFAULT |
| TH12 | B1 | Direct-to-origin bypass of Cloudflare WAF (S/D) | Origin allowlist of CF ranges, per-zone Authenticated Origin Pulls, `real_ip` trusted only from CF | CF-ORIGIN-* |
| TH13 | B1 | Spoofed `X-Forwarded-For` / `CF-Connecting-IP` (S) | `set_real_ip_from` restricted to verified ranges; header ignored otherwise | NGX-REALIP |
| TH14 | B2 | SSH brute force / weak config (S/E) | Key-only auth, `AllowGroups`, modern KEX/ciphers, fail2ban, optional WireGuard-only | SSH-* |
| TH15 | B2 | SFTP user escapes chroot, gets a shell, or uses forwarding (E) | `ForceCommand internal-sftp`, root-owned chroot, `AllowTcpForwarding no`, `PermitTunnel no`, `X11Forwarding no`, `AllowAgentForwarding no` | SFTP-* |
| TH16 | B7 | Leaked Cloudflare token (E) | Per-zone least-privilege tokens, `systemd-creds` encryption, never logged, IP-restricted tokens where possible | SEC-SECRETS |
| TH17 | B7 | Malicious package/repo (T5) | Signed repos with pinned key fingerprints in `signed-by=`, apt pinning, stdlib-only CLI, no `curl \| bash`, checksum + signature on any binary download | SUPPLY-* |
| TH18 | A5 | Ransomware/attacker deletes backups after compromising the host (D/T) | Append-only rest-server, prune only from the backup host, per-tenant keys, regular restore tests | BKP-* |
| TH19 | A8 | Attacker erases audit logs (R) | `chattr +a`, off-host log shipping, journald forward-secure sealing (evaluate) | AUDIT-* |
| TH20 | T7 | Admin locks out SSH via a firewall or sshd change (D) | `nft -c`, `sshd -t`, auto-rollback timer, confirm from a new session | OPS-LOCKOUT |
| TH21 | T7 | Destructive command on the wrong site (D) | Typed confirmation (`--confirm <domain>`), `--dry-run`, pre-delete snapshot, tenant data retained for N days after delete unless `--purge` | OPS-DELETE |
| TH22 | A3 | TLS private key read by a tenant (I) | Keys root 0600, outside tenant namespaces; nginx reads them as root at startup | TLS-KEYS |
| TH23 | B4 | Attack on nginx (shared) from a malicious upstream response or crafted request (E) | nginx from the signed stable repo with timely patching, AppArmor, no third-party modules, response size/timeouts | NGX-* |
| TH24 | B1 | L7 DoS / slowloris (D) | `limit_req`, `limit_conn`, tight timeouts, Cloudflare in front where used | NGX-LIMITS |

## 5. Residual risks (accepted or deferred; must be disclosed to customers)

| ID | Risk | Status |
|---|---|---|
| RR-1 | **Shared kernel.** A kernel LPE from tenant code compromises the host and all tenants. Applies to Tier S and Tier C alike. | Reduced by patching, Livepatch (Ubuntu Pro), seccomp, `RestrictNamespaces`. Fully addressed only by Tier V (VMs). |
| RR-2 | Shared nginx and MariaDB processes: a 0-day in either crosses tenant boundaries. | Accepted for density; patch quickly. |
| RR-3 | CPU micro-architectural side channels between tenants. | Accepted; kernel mitigations stay at defaults (never `mitigations=off`). |
| RR-4 | A bug in the root-run CLI is a privilege-escalation path for whoever can feed it data (tenant file names, restored archives). | Mitigated by design rules (architecture §5) and negative tests; needs an external review before GA. |
| RR-5 | Compromised admin workstation (T4). | Out of DomainPilot's control. Recommend hardware-backed SSH keys (FIDO2 `sk-ed25519`) and WireGuard-only admin access. |
| RR-6 | Cloudflare account compromise. | Out of scope; recommend 2FA/SSO and token IP restrictions. |

## 6. Statement

Passing automated checks shows that the specific tested controls are present. **It does not show the system is secure.** Every report generated by `site ... audit` will say so.
