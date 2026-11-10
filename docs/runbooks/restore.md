# Runbook: restore from backup

Restores never write straight into a live site. Each restore follows the same steps:
1. Files are restored into a root-only staging directory and verified by restic.
2. They are cleaned: setuid bits are stripped, and device and FIFO files are removed.
3. Only then are they swapped in.

The replaced copy is kept for 7 days. Before a database is replaced, a safety copy of its current state is taken. If the import fails, that safety copy is put back.

## 1. Find the backup

```bash
sudo site example.com backup list
sudo site system backup --status       # last backup, last verify, last restore drill
```

Each backup run has one `files` snapshot and one `db` snapshot per database, with the same run time. Pick a snapshot ID from the list. With no `--snapshot`, the newest run is used.

## 2. Look before you replace (recommended)

```bash
sudo site example.com restore --all --to-staging --confirm example.com
```

This prints a path under `/srv/tenants/.dp-restore/`. Inspect the files there, and the database dumps (`.sql`). Nothing live has changed.

## 3. Restore

```bash
sudo site example.com restore --files --confirm example.com                     # code + uploads
sudo site example.com restore --db --confirm example.com                        # every database of that run
sudo site example.com restore --db --snapshot <id> --confirm example.com        # one database snapshot
sudo site example.com restore --all --snapshot <id> --confirm example.com       # files + databases of one run
```

PHP is restarted after a files restore, so no cached code from the replaced version survives.

Then check the site:

```bash
sudo site example.com status
sudo site example.com security
```

## Undo a restore

**Files.** The previous `app/` and `data/` trees are in the staging directory that the restore printed, under `previous/`. To go back:

```bash
sudo site example.com disable
cd /srv/tenants/<tNNNN>
sudo mv app app.bad && sudo mv /srv/tenants/.dp-restore/<staging>/previous/app app
sudo mv data data.bad && sudo mv /srv/tenants/.dp-restore/<staging>/previous/data data
sudo site example.com enable
```

**Databases.** The restore printed a `safety_snapshot` ID. Restore it the same way as any other snapshot:

```bash
sudo site example.com restore --db --snapshot <safety id> --confirm example.com
```

## Move sites to a new server (total loss of the old one)

You need:
- the **master key**, stored offline at setup;
- the **bucket credentials**;
- the **repository URL**.

1. Install DomainPilot on the new server ([install.md](../install.md)).
2. Connect it to the same backups:
   ```bash
   sudo site system backup import-key                       # paste the master key
   printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "<key id>" "<secret>" \
     | sudo site system backup setup --repository s3:https://<endpoint>/<bucket>/<old-server-name> --credentials-stdin
   ```
3. List what the old server hosted, with each site's tenant ID:
   ```bash
   sudo site system backup sites
   ```
4. Recreate each **primary** domain **with its old tenant ID**, then restore it. The ID makes the backup repository, file owners and database names line up.
   ```bash
   sudo site example.com create --type php --tenant-id t0003
   sudo site example.com restore --all --confirm example.com
   ```
   Add aliases with `--alias` at create time, the way `backup sites` lists them.
5. The database user on the new server has a **new password**. Show it, then update the application's configuration (for example `wp-config.php`) in `app/`:
   ```bash
   sudo site example.com db credentials
   ```
6. Point DNS at the new server. Certificates are issued automatically once DNS resolves.
7. Run `sudo site system backup` and `sudo site system backup --test-restore`.

**A tenant ID is still in use on the new server.** `create --tenant-id` refuses an ID that already exists there. This happens when you created other sites before restoring. Restore onto a fresh server, or ask for help: files can be restored with `--to-staging` and copied by hand, but the database names will differ.

## Restore drill

A drill runs every Sunday at 05:00 and alerts on failure. To run one now:

```bash
sudo site system backup --test-restore
```
