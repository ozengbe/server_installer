# Installing DomainPilot

> **Preview release.** Read [security-report.md](security-report.md) §4 for the known limits. Install on a server that hosts nothing else.

This guide takes you from a fresh server to the first site in about 30 minutes. Day-to-day operation is covered in [admin-guide.md](admin-guide.md), and later versions in [upgrade.md](upgrade.md).

## Before you start

- A fresh **Ubuntu 24.04 or 26.04 LTS** server, with the `universe` component enabled (needed for `ansible-core`, restic and fail2ban). At least 2 GB RAM and 20 GB disk.
- You log in over SSH **with a key**, as a normal user who can use sudo (not root).
- **Console access** through your provider, in case of a mistake with SSH or the firewall.
- For certificates: each site's DNS name pointing at the server, or its zone in Cloudflare (see [admin-guide.md § 4](admin-guide.md#4-certificates-and-cloudflare)).

## Download and verify

Download three files from the release page: `domainpilot-<version>.tar.gz`, `SHA256SUMS` and `SHA256SUMS.sig`. Then download the signing key list, `allowed_signers`. Take it from a source you trust **other than** the release page, and compare its fingerprint with the one published in [release.md](release.md#one-time-setup-the-signing-key).

Then, on the server:

```bash
# 1. The signature must say: Good "domainpilot-release" signature for release@domainpilot
ssh-keygen -Y verify -f allowed_signers -I release@domainpilot -n domainpilot-release \
  -s SHA256SUMS.sig < SHA256SUMS
# 2. The checksum must say: OK
sha256sum -c SHA256SUMS
# 3. Unpack (the installer re-checks every file against MANIFEST.sha256)
tar -xzf domainpilot-<version>.tar.gz
cd domainpilot-<version>
```

**Stop if either check fails.** Don't run anything from that download.

## Install

```bash
sudo installer/install.sh --check     # dry run: shows what would change
sudo installer/install.sh
```

The first run creates `/etc/domainpilot/install.yml`. Your account becomes the first admin, using the keys from your `~/.ssh/authorized_keys`. Review that file. Every setting is documented in [ansible/group_vars/all.yml](../ansible/group_vars/all.yml). Re-run the installer after any change.

When it finishes, the installer prints the installed version. You can show it again with `sudo site version`.

After hardening:
- SSH is key-only. Root login is disabled, and only members of `dp-admins` (admins) and `dp-sftp` (site owners) can log in.
- Keys are read **only** from `/etc/ssh/authorized_keys.d/<user>`, which is root-owned. Keys in `~/.ssh/authorized_keys` are ignored.
- Every inbound port is closed except 22, 80 and 443 (plus WireGuard if configured), on IPv4 and IPv6.

## First checks and first site

Do these right after the firewall is confirmed (next section):

```bash
sudo site system health
sudo site system security            # exit 0 = all clear, 10 = warnings, 11 = critical
sudo site example.com create --type php
sudo site example.com status
sudo site example.com isolation test
```

Next, set up [backups](#backups) and [alerts](#alerts). **Don't skip backups:** until a bucket is configured, nothing is backed up.

## Confirming the firewall (anti-lockout)

The firewall is applied with an automatic **rollback timer** (default 120 s):

1. Keep your current session open. Already-established connections are never cut.
2. Open a **new** SSH session to the server.
3. If it connects, run `sudo dp-firewall confirm`. The rules are persisted to `/etc/nftables.conf`.
4. If it does not connect, do nothing. The previous rules come back automatically. A reboot before confirmation also reverts, because nothing is persisted until you confirm.

Other commands: `sudo dp-firewall status`, `sudo dp-firewall rollback`.

For remote Ansible runs, set `dp_firewall_confirm_mode: remote`. Ansible then reconnects through the new rules and confirms only if that works.

## Common changes
| Task | How |
|---|---|
| Add an admin | Add to `dp_admins` in `/etc/domainpilot/install.yml`, re-run the installer |
| Revoke an admin | Move the name from `dp_admins` to `dp_admins_revoked`, re-run (key file removed, group membership dropped; account kept) |
| Restrict SSH to office/VPN IPs | Set `dp_ssh_allow_v4` / `dp_ssh_allow_v6`, re-run, confirm from a new session **from an allowed address** |
| Require a sudo password | `dp_admin_sudo_nopasswd: false`. Set a password for each admin **first**. |

## Rollback / recovery
- **Firewall:** `sudo dp-firewall rollback` while a change is pending. Otherwise re-run the installer with corrected vars. As a last resort from the provider console: `sudo nft delete table inet domainpilot` (opens the host).
- **SSH:** the installer validates with `sshd -t` and restores the previous drop-in if validation fails. To revert by hand from the console, delete `/etc/ssh/sshd_config.d/00-domainpilot.conf` and the `DomainPilot managed block` in `/etc/ssh/sshd_config`, then run `systemctl reload ssh`.
- **sysctl:** delete `/etc/sysctl.d/99-zz-domainpilot.conf` and reboot. Some settings, such as `kexec_load_disabled`, can't be undone without a reboot.
- **/tmp hardening:** `systemctl disable tmp.mount`, then reboot.

## Services installed

| Service | 24.04 / 26.04 | Source | State after install |
|---|---|---|---|
| nginx (stable) | same | nginx.org signed repository. The key is vendored in this repo and its fingerprints are pinned. | Running, sandboxed by systemd. Unknown hostnames get 444 and their TLS handshakes are rejected. |
| PHP-FPM | 8.3 / 8.5 | Ubuntu archive | **Shared service masked.** Each site gets its own sandboxed PHP master. |
| MariaDB | 10.11 / 11.8 | Ubuntu archive | Unix socket only (`skip-networking`), no `LOAD DATA LOCAL`, no anonymous users or test database |
| Cache | Redis 7.0 / Valkey | Ubuntu archive | **Shared instance masked.** Each site gets its own socket-only instance. |
| restic | 0.16 / 0.18 | Ubuntu archive (universe) | Backups, once configured |
| fail2ban | same | Ubuntu archive (universe) | Jails `sshd`, `nginx-limit-req` and `recidive`. Bans go in fail2ban's own nftables table, and admin allowlists are never banned. |
| unattended-upgrades | same | Ubuntu archive | Security pocket only, daily at `dp_updates_window_start`. **Never reboots.** |

Health check: `sudo dp-healthcheck` (or `--json`). It runs automatically after every unattended upgrade and logs failures to the journal at priority `err`. Exit code 10 means warnings only, such as a pending reboot.

**Updates that are deliberately not automatic:** nginx.org releases, PHP minor/major versions, MariaDB major versions, and kernel reboots. Run them in a maintenance window with `sudo site system update`. MariaDB is never restarted by needrestart.

**Rollback:** every service config change is validated (`nginx -t`, `fail2ban-client --test`, MariaDB start) and the previous file is restored if validation fails. To remove a service's DomainPilot config by hand, delete the file named in its "Managed by DomainPilot" header and restart the service.

## Locked out by fail2ban

Repeated failed SSH logins get the source IP banned for 1 h (longer for repeat offenders), on SSH only. Websites stay reachable. The installer exempts the IP it was run from (`dp_fail2ban_ignoreip` in `/etc/domainpilot/install.yml`); add any other admin addresses there and re-run the installer.

If you are banned, connect from another address or the provider console and run:

```bash
sudo fail2ban-client status sshd                   # list banned IPs
sudo fail2ban-client set sshd unbanip <your-ip>
sudo fail2ban-client set recidive unbanip <your-ip> # if banned repeatedly
```

## Backups

Backups go to an S3-compatible bucket (Backblaze B2, Wasabi, AWS S3, Cloudflare R2, …). Each site gets its own encrypted restic repository inside it, and the server configuration gets one more. Nothing is backed up until you configure a target.

1. **Create the bucket** in your provider's console:
   - **versioning ON** and **Object Lock ON**, with a default retention of, for example, 30 days (*compliance* mode if offered);
   - lifecycle rule: delete *non-current* versions after the retention period, so storage doesn't grow forever.
2. **Create an application key for this bucket only** that can list, read and write objects but **cannot delete object versions or change retention** (B2: no `deleteFiles`/`writeFileRetentions`; AWS: no `s3:DeleteObjectVersion`, `s3:PutObjectRetention`, `s3:BypassGovernanceRetention`). A compromised server can then only add delete markers; the locked versions survive.
3. **Connect the server.** The credentials go through stdin, never the command line:

   ```bash
   printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "<key id>" "<secret>" \
     | sudo site system backup setup --repository s3:https://s3.<region>.backblazeb2.com/<bucket>/<server-name> --credentials-stdin
   ```

   Run it in a terminal: it prints the **master key** once. **Store it offline** (password manager or paper). Without it the backups can't be read after the server is lost. Show it again with `sudo site system backup show-key`.
4. **Check it:** `sudo site system backup` (first full run), then `sudo site system backup --status` and `sudo site system backup --test-restore`.

Schedule: nightly at `dp_backup_time` (default 02:30 ± 30 min). Every Sunday at 05:00 an integrity check and a restore drill run. Retention defaults to 7 daily, 4 weekly and 6 monthly snapshots (`--keep-daily/--keep-weekly/--keep-monthly` at setup).

Restoring:

```bash
sudo site example.com backup list
sudo site example.com restore --all --to-staging --confirm example.com   # look first, nothing live changes
sudo site example.com restore --files --confirm example.com             # files only (previous copy is kept)
sudo site example.com restore --db --snapshot <id> --confirm example.com # one database (safety copy taken first)
```

**New server after a total loss:** follow [runbooks/restore.md](runbooks/restore.md#move-sites-to-a-new-server-total-loss-of-the-old-one). Sites are recreated with their old tenant IDs, so their backups match.

## Alerts

The server checks itself every 5 minutes. When something changes it sends an alert, for example:
- a site stops answering;
- a service crashes (it is restarted automatically, at most 5 times in 10 minutes);
- the disk fills up;
- a certificate is about to expire;
- a backup is overdue or a restore drill fails.

```bash
# phone push via ntfy (pick a long random topic name: it is the password)
echo 'https://ntfy.sh/<long-random-topic>' | sudo site system alerts setup --kind ntfy --url-stdin
# or Slack / Discord incoming webhook, or Telegram:
#   https://api.telegram.org/bot<token>/sendMessage?chat_id=<id>  (--kind telegram)
sudo site system alerts test
```

Options: `--min-severity warn|critical` and `--reminder-hours N` (how often a still-open critical problem is repeated). `sudo site system monitor` shows the current problems without sending anything.

## SFTP for site owners

```bash
sudo site example.com sftp create --key alice.pub --name alice
# alice connects with: sftp t0001-deploy@<server>   (lands in /app; web root is /app/public)
sudo site example.com sftp revoke alice --confirm example.com
```

Key-only (Ed25519 recommended; RSA must be at least 3072 bits). The account is chrooted to its own site, has no shell and no port forwarding, and uploads are readable by the web server and PHP but nobody else.
