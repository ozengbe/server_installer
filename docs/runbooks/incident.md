# Runbook: security incident

Use this when an alert, a log line or a report suggests that a site or the server may be compromised.

**Order of work: contain → preserve evidence → find the scope → recover → rotate → review.**

Write down what you do and when, for example in a text file on your own machine. The server's own logs may be the thing under attack.

## 0. First five minutes

Find the scope. The questions below are in order of severity.

```bash
sudo site system security               # problems only; exit 11 = critical findings
sudo site system logs --errors -n 200
sudo site system logs --audit -n 100    # every privileged DomainPilot action, with who ran it
sudo site list
```

| Signal | Likely scope | Go to |
|---|---|---|
| One site defaced, spam sent from one site, webshell in one site's `data/` | **One site.** Isolation keeps it inside its own sandbox. | [§ 1](#1-one-site) |
| `isolation test` fails, unknown admin, unknown SSH key, changed binaries, audit-log flag removed (`AUDIT-APPEND-ONLY`) | **The server** | [§ 2](#2-the-server) |
| Leaked password, token or key, but no sign of use | **A credential** | [key-rotation.md](key-rotation.md) |

## 1. One site

1. **Contain.** Take the site offline. Its files and database are kept.
   ```bash
   sudo site example.com disable
   ```
   `disable` makes nginx serve a 503 maintenance page and stops the site's PHP and cache. Its SFTP keys stay valid, so if the SFTP account may be the entry point, revoke the keys too:
   ```bash
   sudo site example.com sftp list
   sudo site example.com sftp revoke alice --confirm example.com
   ```
2. **Preserve evidence** before you change anything else. This backup becomes your evidence snapshot.
   ```bash
   sudo site example.com backup
   sudo site example.com logs --lines 2000 > ~/incident-example.com-access.log
   sudo site example.com logs --php --lines 2000 > ~/incident-example.com-php.log
   ```
3. **Confirm the isolation held.** Each check should pass. If one fails, treat it as [§ 2](#2-the-server).
   ```bash
   sudo site example.com isolation test   # live escape attempts from inside the sandbox
   sudo site example.com security --verbose-report
   sudo site system security
   ```
4. **Find the way in.** Look for:
   - changed files: compare with a backup from before the incident, using `restore --to-staging`;
   - outdated plugins;
   - weak admin passwords in the application;
   - uploads that contain PHP.

   Code in `app/` can't be changed by PHP unless the site was created with writable code, so check `data/` first.
5. **Recover.** Restore files and database from the last backup **before** the compromise ([restore.md](restore.md)), then patch the hole.
   ```bash
   sudo site example.com restore --all --snapshot <id> --confirm example.com
   ```
6. **Rotate the site's secrets:**
   ```bash
   sudo site example.com db credentials --rotate
   ```
   Also rotate the site's SFTP keys and the application's own admin passwords and API keys.
7. **Bring it back:**
   ```bash
   sudo site example.com enable
   sudo site example.com security
   ```

## 2. The server

Assume root is compromised. Anything on this server, including DomainPilot's own reports, may be lying.

1. **Contain at the provider**, not on the host. Use its firewall to allow SSH only from your address, or take a snapshot and power the server off.
2. **Preserve evidence.** Take a provider disk snapshot **before** you change anything.
3. **Don't clean it. Replace it.** Build a new server with a verified release ([install.md](../install.md)) and restore the sites from backups made **before** the compromise ([restore.md](restore.md#move-sites-to-a-new-server-total-loss-of-the-old-one)). Object Lock on the bucket means an attacker on the old server could not delete or change locked backup versions.
4. **Rotate everything** in [key-rotation.md](key-rotation.md#host-compromise):
   - admin SSH keys;
   - Cloudflare tokens;
   - bucket credentials;
   - a **new** backup repository prefix;
   - database passwords;
   - SFTP keys;
   - alert URLs.
5. **Review.** Work out how the attacker got in, and record the residual risk ([security-report.md](../security-report.md)).

## 3. After any incident

- Add a test or audit check that would have caught it, if possible.
- Update the threat model ([threat-model.md](../threat-model.md)) if the attack path was not in it.
- Check the alert went out. If no alert fired, that is a finding too.
