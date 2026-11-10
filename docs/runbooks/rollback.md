# Runbook: roll back a change

Find the row that matches what went wrong. Start at the top: the cheapest fixes come first.

| What went wrong | Roll back with |
|---|---|
| A firewall change locked you out | Do nothing. It reverts by itself after 120 s unless confirmed. If it was already confirmed, use the provider console (see [§ Firewall](#firewall)). |
| `site <domain> optimize --apply` made a site slow or broken | `sudo site example.com optimize --rollback <ID>` (the ID was printed when you applied, or use `--history`) |
| `site system optimize --apply` | `sudo site system optimize --history`, then `sudo site system optimize --rollback <ID>` |
| A PHP version change broke the site | `sudo site example.com php <previous version>` |
| A bad restore | The replaced tree is kept next to the staging copy (see [restore.md](restore.md#undo-a-restore)) |
| An Ozenix upgrade broke something | [§ Upgrade](#upgrade) |

Every rollback is written to the audit log: `sudo site system logs --audit`.

## Firewall

Pending changes roll back automatically. To roll back right away, run `sudo dp-firewall rollback`.

If a **confirmed** change locks you out:
1. Log in through the provider console.
2. Run `sudo nft delete table inet domainpilot`. This removes Ozenix's firewall and leaves the host **open**.
3. Fix `/etc/domainpilot/install.yml`, then run `sudo installer/install.sh`.
4. Confirm from a new SSH session.

## Upgrade

1. **Find out what changed.**
   ```bash
   sudo site version
   sudo tail -n 3 /var/lib/domainpilot/release-history.jsonl
   sudo ls -1t /var/backups/domainpilot/
   ```
2. **Try a re-run of the new release first.** Most failures are an interrupted run, and the installer is idempotent: `sudo installer/install.sh`.
3. **If you must go back to the previous release:**
   1. Download and verify the previous release (see [install.md](../install.md)).
   2. Stop the timers so nothing writes state while you swap it:
      ```bash
      sudo systemctl stop dp-backup.timer dp-monitor.timer
      ```
   3. Restore the pre-upgrade snapshot. This replaces Ozenix's state with the copy taken just before the upgrade.
      ```bash
      SNAP=/var/backups/domainpilot/pre-upgrade-<from>-to-<to>-<time>.tar.gz
      sudo tar -tzf "$SNAP" | head          # look first
      sudo tar -xzf "$SNAP" -C / --exclude=registry.sqlite3 --exclude='./registry.sqlite3'
      sudo tar -xzf "$SNAP" -C /var/lib/domainpilot ./registry.sqlite3
      ```
   4. Install the previous release over the newer one:
      ```bash
      cd domainpilot-<previous-version>
      sudo installer/install.sh --allow-downgrade
      ```
   5. Check, then start the timers again:
      ```bash
      sudo site system health
      sudo site system security
      sudo site list
      sudo systemctl start dp-backup.timer dp-monitor.timer
      ```

**Sites created after the upgrade** are not in the old registry. Their files under `/srv/tenants` and their databases still exist. To bring them back after the rollback, back them up first, then recreate and restore them:

```bash
sudo site example.com backup
sudo site example.com create
sudo site example.com restore --all --confirm example.com
```

Do the backup **before** step 3 if you can.

## Configuration file by hand

Every file Ozenix writes has a `Managed by Ozenix` header. Your edits are overwritten by the next install. Put lasting changes in `/etc/domainpilot/install.yml`, then run `sudo installer/install.sh`.
