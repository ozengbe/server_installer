# Runbook: rotate keys and credentials

Rotate on a schedule, when someone with access leaves, and **immediately** if a secret may have leaked.

**Ground rules:**
- Secrets go in through stdin or a hidden prompt, never on the command line.
- At rest they are encrypted with this host's key (systemd-creds).
- Every rotation is recorded in the audit log: `sudo site system logs --audit`.

| Secret | Suggested schedule | Section |
|---|---|---|
| Admin SSH keys | when people change | [Admin SSH keys](#admin-ssh-keys) |
| Site SFTP keys | when people change | [SFTP keys](#sftp-keys) |
| Site database passwords | yearly, or after a leak | [Database passwords](#database-passwords) |
| Cloudflare API tokens | yearly | [Cloudflare tokens](#cloudflare-tokens) |
| Backup bucket credentials | yearly | [Bucket credentials](#bucket-credentials) |
| Backup master key | after a suspected leak only | [Backup master key](#backup-master-key) |
| TLS certificate keys | automatic (new key on every renewal) | [TLS keys](#tls-keys) |
| Alert webhook URL | after a leak | [Alert URL](#alert-url) |
| Host credential key | never by hand | [Host compromise](#host-compromise) |

## Admin SSH keys

1. Edit `dp_admins` in `/etc/domainpilot/install.yml` and add the **new** key next to the old one.
2. Run `sudo installer/install.sh` from the current release directory.
3. Open a **new** session with the new key.
4. Only if that works, remove the old key from the file and run the installer again.

To remove a person completely, move them to `dp_admins_revoked`.

## SFTP keys

```bash
sudo site example.com sftp list
sudo site example.com sftp create --key new-key.pub --name alice-2026
sudo site example.com sftp revoke alice --confirm example.com
```

## Database passwords

```bash
sudo site example.com db credentials --rotate
```

The new password is printed once. Put it in the application's configuration (for example `wp-config.php`) **right away**: the old password stops working immediately.

## Cloudflare tokens

1. Create the new token in the Cloudflare dashboard, with the same permissions as the old one.
2. Store it under the **same label**. It replaces the old one, and the token is read from a hidden prompt:
   ```bash
   sudo site system cloudflare token list
   sudo site system cloudflare token add --label example.com
   ```
3. Check it: `sudo site example.com cloudflare status`.
4. Delete the old token in the Cloudflare dashboard.

## Bucket credentials

1. At the storage provider, create a new application key with the same restrictions: no deleting object versions, no changing retention (see [install.md](../install.md#backups)).
2. Re-run setup with the **same** repository. The master key is kept.
   ```bash
   printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "<new key id>" "<new secret>" \
     | sudo site system backup setup --repository s3:https://<endpoint>/<bucket>/<server> --credentials-stdin
   sudo site system backup
   ```
3. Once that backup succeeds, delete the old key at the provider.

## Backup master key

Every repository password is derived from the master key. Rotation takes two commands, so the old key never stops working before the new one is stored safely.

```bash
# 1. Add a key derived from a new master to every repository, and switch to it.
#    The new master key is printed: store it offline NOW, the same way as the old one.
sudo site system backup rotate-key
# 2. Back up once with the new key, then remove the old key from every repository.
sudo site system backup
sudo site system backup rotate-key --finish
```

**If a step fails** (network, bucket), run the same command again. Each step picks up where it stopped. Nothing is removed until `--finish`, and `--finish` keeps the old key in any repository the new key can't open.

**What rotation does not do.** restic wraps one data-encryption key per repository, and rotation replaces only the password that unlocks it. Someone who holds the **old** master key **and** can read the bucket can still use older versions of the key files that the bucket keeps (versioning and Object Lock are there to keep exactly those). If the master key leaked together with bucket access:
1. Revoke the bucket key.
2. Create a **new** repository prefix: `site system backup setup --repository …/<server>-2`.
3. Run a full backup.
4. Let the old prefix expire under its retention.

## TLS keys

Every renewal creates a new private key. To rotate now:

```bash
sudo site example.com ssl renew --force
```

If a key leaked, revoke the certificate, then issue a new one:

```bash
sudo site example.com ssl revoke --confirm example.com
sudo site example.com ssl
```

## Alert URL

The URL is the secret for ntfy topics and webhooks.
1. Create a new topic or webhook.
2. Point the server at it and test:
   ```bash
   echo 'https://ntfy.sh/<new-long-random-topic>' | sudo site system alerts setup --kind ntfy --url-stdin
   sudo site system alerts test
   ```
3. Delete the old webhook at its provider.

## Host compromise

The host credential key (`/var/lib/systemd/credential.secret`, or the TPM) encrypts every stored secret on this server. If root on this host may have been compromised, assume **every** secret above is known to the attacker. Don't try to clean the server:
1. Follow [incident.md](incident.md).
2. Build a new server.
3. Rotate every secret in this runbook from the new server or the providers' dashboards.
4. Restore the sites ([restore.md](restore.md#move-sites-to-a-new-server-total-loss-of-the-old-one)).
