# Ozenix administrator guide

This guide is for the people who run an Ozenix server day to day. First-time setup is covered in [install.md](install.md). For emergencies, use the [runbooks](#runbooks).

## 1. What runs where

| Thing | Where | Notes |
|---|---|---|
| `site` command | `/usr/local/bin/site` → `/usr/lib/domainpilot/current` | Root-only tool. Every change is recorded in `/var/log/domainpilot/audit.jsonl`, which is append-only. |
| Settings | `/etc/domainpilot/install.yml` (installer), `/etc/domainpilot/domainpilot.toml` (CLI) | Change the installer settings, then re-run the installer. |
| Secrets | `/etc/domainpilot/secrets/` | Encrypted with this host's key. Useless on any other machine. |
| State | `/var/lib/domainpilot/` | Registry (sites and tenants), release record, backup state |
| Sites | `/srv/tenants/<tNNNN>/` | `app/` code (deploy user), `data/` uploads (PHP may write), `tmp/` scratch |
| Per-site services | `dp-php@<tNNNN>`, `dp-cache@<tNNNN>` | Sandboxed by systemd, AppArmor, cgroups and nftables. One set per site. |
| Timers | `dp-backup.timer` (nightly), `dp-backup-drill.timer` (Sunday), `dp-monitor.timer` (every 5 min), certificate renewal, unattended-upgrades | `systemctl list-timers 'dp-*'` |

Each site is a **tenant** with its own users:
- `tNNNN` runs PHP;
- `tNNNN-deploy` owns the code and is the SFTP login.

A tenant can't see other tenants' files, processes, sockets, databases or caches, and can't reach the server's own services or cloud metadata. `sudo site example.com isolation test` proves this live.

## 2. Daily and weekly checks

Alerts ([install.md § Alerts](install.md#alerts)) tell you when something changes, so there's no daily routine. Each week, spend two minutes on:

```bash
sudo site system status
sudo site system security
sudo site system backup --status
sudo site system update --check
```

`system security` exits with code 0 when all is clear, 10 for warnings, and 11 for critical findings. Run the full audit with its fixes after any manual change to the server: `sudo site system audit`.

## 3. Sites

```bash
sudo site example.com create --type php --alias www.example.com
sudo site example.com create --type static
sudo site example.com create --type proxy --upstream https://127.0.0.1:3000
sudo site example.com status
sudo site example.com logs --error --lines 100
sudo site example.com disable
sudo site example.com enable
sudo site example.com delete --confirm example.com           # archived: files and databases kept
sudo site example.com delete --purge --confirm example.com   # gone for good (backups remain)
```

**If a create was interrupted** (crash, power loss), run `sudo site example.com repair`. It finishes or cleans up the half-done steps.

**Databases:**

```bash
sudo site example.com db create --name app      # database t0001_app
sudo site example.com db credentials            # user and password for the app's config
```

**PHP:**

```bash
sudo site example.com php status
sudo site example.com php restart
sudo site example.com optimize                  # shows a recommendation; --apply to use it
```

**Uploads for the site owner (SFTP):**

```bash
sudo site example.com sftp create --key alice.pub --name alice
```

## 4. Certificates and Cloudflare

Every site gets HTTPS without any action:
1. **At creation:** a self-signed placeholder certificate. Visitors coming through Cloudflare with SSL/TLS mode **Full** see a valid certificate, because Cloudflare's own certificate is the one they see. Direct visitors still get plain HTTP: there's no redirect to the placeholder.
2. **When DNS points at the server**, directly or through the Cloudflare proxy: a Let's Encrypt certificate. HTTP then redirects to HTTPS. If DNS isn't ready, the self-check retries every hour.
3. **Renewal** runs on its own. An alert fires if a certificate gets within 14 days of expiry.

```bash
sudo site example.com ssl status       # self-signed placeholder or Let's Encrypt, expiry, what is missing
sudo site example.com ssl              # request Let's Encrypt now
sudo site example.com create --no-ssl  # only the placeholder, never Let's Encrypt
```

**Cloudflare without any setup on the server.** Create the DNS records in Cloudflare yourself, with the proxy on, and set SSL/TLS mode to **Full**. Switch to **Full (strict)** once `ssl status` shows Let's Encrypt. Ozenix never creates, changes or deletes DNS records unless you ask it to.

**Optional: let Ozenix manage the records.** With a stored API token, Ozenix can:
- create the proxied records itself (`create --cloudflare-dns`);
- validate certificates through DNS;
- review the zone's security settings read-only.

```bash
sudo site system cloudflare token add               # token is read from a hidden prompt
sudo site example.com create --cloudflare-dns
sudo site example.com cloudflare security           # read-only review of the zone's settings
```

The token needs `Zone - DNS - Edit` and `Zone - Zone Settings - Read`. Ozenix never changes zone settings, and it only deletes DNS records it created itself.

## 5. Backups

Configured once ([install.md § Backups](install.md#backups)). After that:

| When | What runs |
|---|---|
| Nightly | Every site (files plus each database) and the server's configuration |
| Sunday | Integrity check and restore drill |

```bash
sudo site system backup --status
sudo site example.com backup                    # now, for one site
sudo site example.com backup list
```

Restoring, and moving sites to a new server: [runbooks/restore.md](runbooks/restore.md).

**Store the master key offline.** `sudo site system backup show-key` prints it. Without it, the backups can't be read after the server is lost.

## 6. Updates

| What | How |
|---|---|
| Ubuntu security updates | Automatic, daily at `dp_updates_window_start`. Never reboots. |
| Everything else (nginx.org releases, PHP minor versions, kernel) | `sudo site system update --check`, then `sudo site system update` in a maintenance window |
| Reboot | When `site system health` reports `reboot-required`, in a window you choose |
| Ozenix itself | [upgrade.md](upgrade.md) |

```bash
sudo site system update --history
sudo site version
```

## 7. Performance

```bash
sudo site system optimize --analyze       # what the server has and uses
sudo site system optimize                 # proposed profile, as a diff
sudo site system optimize --apply
sudo site system optimize --history       # every applied change can be rolled back
```

## 8. Access

| Who | How they get in |
|---|---|
| Admins | SSH key only, listed in `dp_admins` in `/etc/domainpilot/install.yml`. Members of `dp-admins`, sudo. |
| Site owners | SFTP only, chrooted to their own site, no shell. Keys via `site <domain> sftp create`. |

Adding and removing admins: [install.md § Common changes](install.md#common-changes). Rotating keys: [runbooks/key-rotation.md](runbooks/key-rotation.md).

The firewall allows only 22, 80 and 443. Changes are applied with an automatic rollback timer, so a mistake cannot lock you out ([install.md](install.md#confirming-the-firewall-anti-lockout)).

## 9. Logs

```bash
sudo site system logs --audit -n 50       # who did what with Ozenix
sudo site system logs --errors            # warnings and errors from Ozenix's services
sudo site example.com logs --php          # one site's PHP errors
```

## Runbooks

| Situation | Runbook |
|---|---|
| A site or the server may be compromised | [runbooks/incident.md](runbooks/incident.md) |
| Data loss, or a move to a new server | [runbooks/restore.md](runbooks/restore.md) |
| A change or an upgrade went wrong | [runbooks/rollback.md](runbooks/rollback.md) |
| A key or credential must be replaced | [runbooks/key-rotation.md](runbooks/key-rotation.md) |

## Known limits

[security-report.md § 4](security-report.md#4-residual-risks) has the full list of residual risks:
- no per-site disk quota (an alert fires at 90%);
- the audit log stays on the server;
- backups are only tamper-proof once an Object Lock bucket is configured;
- rate limits are configured but have not been load-tested.

This release is a **preview**: the root-run code has not yet had an independent review.
