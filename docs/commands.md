# ozenix command reference

Every command, grouped by task. Replace `example.com` with your domain.

**Conventions:**
- Every command takes `--help`.
- Commands that change something accept `--dry-run`, which shows the plan and changes nothing.
- `--json` gives machine-readable output.
- Destructive commands ask you to type the domain, or take `--confirm example.com`.

## Sites

```bash
# Create a PHP website with its own Linux user "john" (SSH key login: SFTP + shell).
# The site also gets its own PHP, cache and sandbox, and HTTPS at once.
# On a terminal, a missing --user or --key is asked for.
sudo site example.com create --user john --key john.pub

# Create a static HTML website
sudo site example.com create --type static

# Create a reverse proxy to an app (Node, Python, another server, ...)
sudo site example.com create --type proxy --upstream https://127.0.0.1:3000

# Extra names for the same site (www, parked domains)
sudo site example.com create --alias www.example.com --alias example.net

# A specific PHP version: 8.2, 8.3, 8.4 or 8.5 (see "PHP versions" below)
sudo site example.com create --user john --key john.pub --php 8.2

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

## Node.js and Python sites

A Node.js or Python site runs as an app with its own sandboxed service, `dp-app@<tNNNN>`:
- the app runs as the site's runtime user;
- it restarts automatically if it crashes;
- its log is in `/var/log/ozenix/tenants/<tNNNN>/app.log`;
- nginx (with HTTPS) forwards the site's traffic to it.

The app must listen on `127.0.0.1:$PORT`. `PORT` is set for it, and is 10000 plus the site number. Only this site's app may use that port: other sites and shell users get "permission denied".

```bash
# Node.js (22, 24 or 26; default 24). Starts with "npm start".
sudo site app.example.com create --type nodejs --user john --key john.pub
sudo site app.example.com create --type nodejs --node 22 --start "node dist/server.js"

# Python (the Ubuntu release's python3, with a virtualenv in app/.venv). Starts "python3 app.py".
sudo site api.example.com create --type python --user anna --key anna.pub \
  --start ".venv/bin/gunicorn -b 127.0.0.1:$PORT app:app"

# Manage the app
sudo site app.example.com app status            # running? restarts, port, log file
sudo site app.example.com app restart           # after deploying new code
sudo site app.example.com app set --start "npm run start:prod"
sudo site app.example.com app set --node 26     # switch Node.js version
sudo site app.example.com logs --error
```

**Deploying as the site user** (`ssh john@server`): the shell starts in `~/app`, with the site's Node.js version on `PATH` (or the virtualenv active for Python) and `PORT` set. Then:

```
git pull && npm ci && npm run build      # Node.js
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # Python (first time)
```

Then run `sudo site app.example.com app restart`. The app may write only to `~/data` and `~/tmp`; its code in `~/app` is read-only to it, as for PHP.

## Laravel sites

```bash
sudo site shop.example.com create --type laravel --user john --key john.pub --php 8.4
```

**Deploy as the site user** (`ssh john@server`). The shell starts in `~/app`, with the site's PHP version as `php`:

```
git clone https://github.com/you/shop.git ~/tmp/shop && cp -a ~/tmp/shop/. ~/app/   # or upload over SFTP
composer install --no-dev --optimize-autoloader
cp .env.example .env && php artisan key:generate
php artisan migrate --force && php artisan config:cache && php artisan route:cache
```

What ozenix does differently for Laravel, and why:

| Laravel normally... | On ozenix | Why |
|---|---|---|
| writes to `storage/` and `bootstrap/cache/` inside the code | writes to `~/data/storage` and `~/data/cache`. Laravel's own `LARAVEL_STORAGE_PATH` and `APP_*_CACHE` settings are set for PHP-FPM, the scheduler, the queue and your shell. | The code in `~/app` stays **read-only for PHP**, so a hacked app can't change its own code. |
| runs any `.php` file under `public/` | runs only `public/index.php`. Every other `.php` URL returns 404. | An uploaded or planted script is never executed. |
| `php artisan storage:link` | not needed: `/storage/...` URLs are served from `~/data/storage/app/public`, and PHP is never run there | User uploads can't become code. |
| cron `* * * * * php artisan schedule:run` | built in: `dp-laravel-schedule@<tNNNN>.timer` runs every minute, sandboxed | — |
| supervisor for `queue:work` | `sudo site shop.example.com laravel queue on` (or `off`) | It restarts automatically, and an alert fires if it keeps failing. |

Logs: `~/data/storage/logs/laravel.log`, and in `/var/log/ozenix/tenants/<tNNNN>/`: `laravel-schedule.log` and `laravel-queue.log`.

## Protecting `.env`

Secrets in `.env` (database password, `APP_KEY`, API keys) get several layers of protection, for every PHP, Laravel, Node.js and Python site:

- **Never served:** nginx returns 404 for every dot-file (`/.env`, `/.env.backup`, `/.git/…`) and for `composer.json`, `artisan` and similar files, on every site.
- **Outside the web root:** keep `.env` in `~/app`, never in `~/app/public`.
- **PHP can read it, never change it:** owner is the site user, the group is the site's PHP, mode `0640`. One command fixes this:
  ```bash
  sudo site shop.example.com env protect
  ```
  New files created by the site user get mode `0640` automatically (`umask 027` in its shell).
- **Checked:** `sudo site shop.example.com security` reports:
  - a `.env` file in a web folder (critical);
  - wrong owner or permissions;
  - `APP_DEBUG=true` (critical: debug pages show secrets);
  - `APP_ENV` other than `production`;
  - an empty `APP_KEY`.

  Values are never printed.
- **Backups** contain `.env` encrypted, like the rest of the site.

## PHP versions

PHP 8.2, 8.3, 8.4 and 8.5 are installed side by side, and each site picks its own:

```bash
sudo site example.com create --php 8.4
sudo site example.com php 8.2          # switch an existing site
sudo site example.com php status
```

On **Ubuntu 24.04** all four come from the PHP maintainer's repository (ppa:ondrej/php; its key is pinned by the installer). On **Ubuntu 26.04** that repository has no packages yet, so 26.04 offers PHP 8.5 only. Re-run `sudo installer/install.sh` once the repository supports 26.04, and the other versions appear.

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

Every site has its own Linux user (chosen at `create --user`). It logs in with SSH keys only (no passwords), and gets SFTP and a shell in its own site. It cannot read other sites. Each key has a label, so you can add several people or computers and revoke them one by one.

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

ozenix works behind Cloudflare without any token: you create the DNS records yourself. A token is needed only if ozenix should create the records itself, validate certificates through DNS, or review the zone's settings.

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

What the installer puts on the server:

| Component | Ubuntu 24.04 | Ubuntu 26.04 | Source |
|---|---|---|---|
| nginx | stable | stable | nginx.org (key pinned) |
| PHP-FPM | 8.2, 8.3, 8.4, 8.5 | 8.5 (more once ppa:ondrej/php supports 26.04) | Ubuntu, ppa:ondrej/php (key pinned) |
| MariaDB | 10.11 | 11.8 | Ubuntu |
| Redis / Valkey (one per site) | Redis 7 | Valkey | Ubuntu |
| Node.js | 22, 24, 26 | 22, 24, 26 | nodejs.org (signed checksums, keys vendored) |
| Python | 3.12 | 3.14 | Ubuntu |

## How isolation works: each site is its own user

`create --user john` makes the site's own Linux user, `john`. It also makes a second, internal user, `t0001`, which runs the site's PHP or app. Each site (a *tenant*, `t0001`, `t0002`, …) gets:

| Part | What it is | Why |
|---|---|---|
| `t0001` | Linux user that **runs** the site's PHP or app; it can never log in | It can read the code, and write only to `data/` and `tmp/`. |
| `john` (your choice; without `--user`: `t0001-deploy`) | Linux user that **owns the code** (`app/`): SSH key login, SFTP and a shell in its own site | A hacked PHP script or app can't modify the code, so it can't plant a lasting web shell. |
| `/srv/tenants/t0001/` | The site's directory, readable only by its own users | Other sites can't even list it. |
| `dp-php@t0001` / `dp-app@t0001` | Its own PHP-FPM, or its own Node.js/Python app service | Its own processes, its own sandbox. One site's crash or overload doesn't affect another. |
| `dp-cache@t0001` | Its own Redis or Valkey, on a private socket | No shared cache, so nothing leaks between sites. |
| `t0001_*` databases and user | Its own MariaDB user, allowed only its own databases | It can't see or touch other sites' data. |
| sandbox | systemd hardening, AppArmor (PHP), seccomp | It can't see other processes or read host secrets. PHP can't run programs. |
| limits | Its own cgroup (CPU, memory, processes) | One site can't starve the server. |
| network | Firewall rules per site; a reserved app port | No access to the server's internal services, cloud metadata or private networks. No other site can take over its port. |

`sudo site example.com status` shows which tenant a site is, and `sudo site example.com isolation test` proves the isolation live.

## Not available

| Feature found in some other panels | Status |
|---|---|
| Parked or extra domains | Use `create --alias` |
| PHP versions older than 8.2 | Not offered: they no longer get security updates. |
| Clone a site, forward or redirect a domain, FastCGI page cache, WordPress multisite conversion | Not built yet |
| Firewall rule commands, IP and bot blocker, Basic Auth | Not built yet (planned next) |
| MySQL instead of MariaDB, FTP, Varnish | Not offered |
| phpMyAdmin | Deliberately not installed: a web login to every database is a common target. Use `db credentials` with a desktop client over an SSH tunnel. |
