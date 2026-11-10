# Ozenix command reference

Every command, grouped by task. Replace `example.com` with your domain.

**Conventions:**
- Every command takes `--help`.
- Commands that change something accept `--dry-run`, which shows the plan and changes nothing.
- `--json` gives machine-readable output.
- Destructive commands ask you to type the domain, or take `--confirm example.com`.

## Sites

```bash
# Create a PHP website (its own users, PHP, cache and sandbox; HTTPS at once)
sudo site example.com create

# Create a static HTML website
sudo site example.com create --type static

# Create a reverse proxy to an app (Node, Python, another server, ...)
sudo site example.com create --type proxy --upstream https://127.0.0.1:3000

# Extra names for the same site (www, parked domains)
sudo site example.com create --alias www.example.com --alias example.net

# A specific PHP version (if installed)
sudo site example.com create --php 8.3

# Information about a site (users, PHP, database, certificate, isolation)
sudo site example.com status
sudo site list

# Take a site offline (maintenance page, nothing deleted) and back online
sudo site example.com disable
sudo site example.com enable

# Delete: the site stops being served, files and databases are kept (archived)
sudo site example.com delete --confirm example.com

# Delete everything: files, databases, users (backups are kept)
sudo site example.com delete --purge --confirm example.com

# An interrupted create or delete (power loss, Ctrl-C): finish or clean it up
sudo site example.com repair

# Logs
sudo site example.com logs                 # access log
sudo site example.com logs --error
sudo site example.com logs --php --lines 200
```

## HTTPS (SSL)

New sites need nothing. They get a self-signed certificate at once, which is enough behind Cloudflare in SSL/TLS mode "Full". A Let's Encrypt certificate follows automatically as soon as DNS points at the server, directly or through the Cloudflare proxy. Renewal is automatic.

```bash
# Get the Let's Encrypt certificate now
sudo site example.com ssl

# Which certificate the site uses, expiry date, and what is missing
sudo site example.com ssl status

# Renew now (normally automatic)
sudo site example.com ssl renew
sudo site example.com ssl renew --force

# Automatic certificates on or off for this site
sudo site example.com autossl on
sudo site example.com autossl off

# Revoke the Let's Encrypt certificate (back to HTTP); only if its key leaked
sudo site example.com ssl revoke --confirm example.com

# Create a site without requesting Let's Encrypt (self-signed only)
sudo site example.com create --no-ssl
```

For a **reverse proxy** site, HTTPS works the same way: nginx terminates TLS and forwards to `--upstream`.

## Files (SFTP)

Every site has its own SFTP login, chrooted to the site, with no shell. Access uses keys only, no passwords.

```bash
# Give someone access with their SSH public key
sudo site example.com sftp create --key alice.pub --name alice
#   -> they connect with: sftp t0001-deploy@<server>   (website files go in app/public)

sudo site example.com sftp list
sudo site example.com sftp revoke alice --confirm example.com
```

## Database (MariaDB)

```bash
sudo site example.com db create                 # database t0001_app
sudo site example.com db create --name shop     # database t0001_shop
sudo site example.com db credentials            # user, password, socket for the app's config
sudo site example.com db credentials --rotate   # new password (update the app's config right away)
sudo site example.com db status
sudo site example.com db backup
sudo site example.com db restore --snapshot <id> --confirm example.com
```

## PHP and performance

```bash
sudo site example.com php status
sudo site example.com php restart
sudo site example.com php 8.3                   # switch PHP version
sudo site example.com php optimize              # recommendation; add --apply
sudo site example.com optimize --analyze
sudo site example.com optimize --apply
sudo site example.com optimize --history
sudo site example.com optimize --rollback <id>
```

## Backups and restore

```bash
# One-time setup (S3-compatible bucket; credentials on stdin)
printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "<key id>" "<secret>" \
  | sudo site system backup setup --repository s3:https://<endpoint>/<bucket>/<server> --credentials-stdin

sudo site example.com backup                    # now, one site
sudo site example.com backup list
sudo site example.com restore --all --to-staging --confirm example.com    # look first
sudo site example.com restore --files --confirm example.com
sudo site example.com restore --all --snapshot <id> --confirm example.com

sudo site system backup                         # all sites + server configuration
sudo site system backup --status
sudo site system backup --verify
sudo site system backup --test-restore
sudo site system backup show-key                # store it offline
sudo site system backup rotate-key
sudo site system backup rotate-key --finish
sudo site system backup sites                   # new server: what the old one hosted
sudo site system backup import-key
```

## Security and isolation

```bash
sudo site example.com isolation status          # the site's users, sandbox, limits
sudo site example.com isolation audit           # configuration checks
sudo site example.com isolation test            # live escape attempts from inside the site
sudo site example.com security --verbose-report
sudo site system security
sudo site system audit
```

## Cloudflare (optional)

Ozenix works behind Cloudflare without any token: you create the DNS records yourself. A token is needed only if Ozenix should create the records itself, validate certificates through DNS, or review the zone's settings.

```bash
sudo site system cloudflare token add           # token read from a hidden prompt
sudo site system cloudflare token list
sudo site system cloudflare token remove example.com --confirm system
sudo site example.com create --cloudflare-dns   # also create proxied DNS records
sudo site example.com cloudflare status         # read-only review
sudo site example.com cloudflare dns --apply    # (re)create this site's records
```

## Server

```bash
sudo site system status
sudo site system health
sudo site system update --check
sudo site system update                         # in a maintenance window
sudo site system update --history
sudo site system optimize --analyze
sudo site system optimize --apply
sudo site system monitor                        # current problems
echo 'https://ntfy.sh/<long-random-topic>' | sudo site system alerts setup --kind ntfy --url-stdin
sudo site system alerts test
sudo site system logs --audit -n 50             # who did what
sudo site system firewall status
sudo site version
```

## Installing the stack

There is no separate `stack` command. One installer sets up the whole hardened stack:
- nginx;
- PHP-FPM;
- MariaDB;
- Redis or Valkey;
- the firewall, fail2ban, backups and monitoring.

Re-run it to repair drift or to apply changed settings.

```bash
sudo installer/install.sh --check     # preview
sudo installer/install.sh             # install / re-apply / upgrade
```

PHP and MariaDB versions are the Ubuntu release's own, so they receive Canonical security updates:

| Ubuntu | PHP | MariaDB |
|---|---|---|
| 24.04 | 8.3 | 10.11 |
| 26.04 | 8.5 | 11.8 |

## How isolation works: each site is its own user

`create` makes the users itself. You are never asked for a name because the names are allocated and never reused. A user who had been deleted could otherwise come back with access to old files. Each site (a *tenant*, `t0001`, `t0002`, …) gets:

| Part | What it is | Why |
|---|---|---|
| `t0001` | Linux user that **runs** the site's PHP | PHP runs as this user only. It can read the code, write only to `data/` and `tmp/`. |
| `t0001-deploy` | Linux user that **owns the code** (`app/`), and the SFTP login | A hacked PHP script can't modify the code, so it can't plant a lasting web shell. |
| `/srv/tenants/t0001/` | The site's directory, readable only by its own users | Other sites can't even list it. |
| `dp-php@t0001` | Its own PHP-FPM service | Its own processes, its own sandbox. One site's crash or overload doesn't affect another. |
| `dp-cache@t0001` | Its own Redis or Valkey, on a private socket | No shared cache, so nothing leaks between sites. |
| `t0001_*` databases and user | Its own MariaDB user, allowed only its own databases | It can't see or touch other sites' data. |
| sandbox | systemd hardening (score ≤ 2.0), AppArmor profile, seccomp | It can't run programs, see other processes, or read host secrets. |
| limits | Its own cgroup (CPU, memory, processes) | One site can't starve the server. |
| network | Firewall rules per site | No access to the server's internal services, cloud metadata or private networks. |

`sudo site example.com status` shows which tenant a site is, and `sudo site example.com isolation test` proves the isolation live.

## Not available

| Feature found in some other panels | Status |
|---|---|
| Parked or extra domains | Use `create --alias` |
| Clone a site, forward or redirect a domain, FastCGI page cache, WordPress multisite conversion | Not built yet |
| phpMyAdmin | Deliberately not installed: a web login to every database is a common target. Use `db credentials` with a desktop client over an SSH tunnel. |
