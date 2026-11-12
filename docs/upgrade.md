# Upgrading ozenix

An upgrade is the same installer run with a newer release. It is idempotent: it changes only what differs.

## What the installer does

1. **Checks the release files.** It verifies every file against `MANIFEST.sha256`, which the signed `SHA256SUMS` covers.
2. **Compares versions.** It compares the release with `/var/lib/ozenix/release.json`:

   | Situation | Result |
   |---|---|
   | Same version | Re-applied. Use this to repair drift. |
   | Newer version | Upgraded, after you confirm. |
   | Older version | **Refused.** A newer release may have migrated the registry or configuration. See [runbooks/rollback.md](runbooks/rollback.md). |

3. **Takes a pre-upgrade snapshot.** It writes `/var/backups/ozenix/pre-upgrade-<from>-to-<to>-<time>.tar.gz` (root 0600; the newest 5 are kept). The snapshot holds:
   - the registry, as a consistent SQLite copy;
   - `/etc/ozenix`, which includes the secrets. These are still encrypted with this host's key.
   - `/var/lib/ozenix`;
   - nginx, PHP and MariaDB configuration, SSH drop-ins, the ozenix AppArmor profiles and `nftables.conf`.

   Site files and databases are **not** in it. Your nightly backups cover those.
4. **Runs the playbook.** The new CLI is installed into `/usr/lib/ozenix/releases/<version>/`. It is test-imported there first, then `/usr/lib/ozenix/current` is switched to it in one atomic step, so old and new code never mix. The previous two releases stay on disk.
5. **Migrates the registry.** This happens on the first `site` command, inside a transaction. An older CLI refuses to open a newer registry rather than corrupt it.
6. **Records the release.** It writes `release.json` and appends to `release-history.jsonl`. `sudo site version` shows the result.

## Procedure

**Before you start:**
1. Read the release's `CHANGELOG.md` entry. It lists manual steps and any configuration that is reset.
2. Pick a maintenance window. nginx is reloaded and PHP workers are restarted, which interrupts sites for a moment. The server is never rebooted.
3. Make sure the last backup is good with `sudo site system backup --status`. If you're unsure, run `sudo site system backup` now.

**Run the upgrade:**

```bash
# 1. Get and verify the new release (same steps as docs/install.md, "Download and verify")
# 2. Preview, then apply:
cd ozenix-<new-version>
sudo installer/install.sh --check
sudo installer/install.sh
# 3. If the installer prints FIREWALL CHANGE PENDING: confirm from a NEW ssh session
sudo dp-firewall confirm
# 4. Check:
sudo site version
sudo site system health
sudo site system security
sudo site list
```

**If any check fails**, follow [runbooks/rollback.md](runbooks/rollback.md).

## Ubuntu release upgrades (24.04 → 26.04)

Don't run `do-release-upgrade` on an ozenix host. Major PHP, MariaDB and cache engine versions change underneath running sites. Instead:

1. Build a new 26.04 server with the current ozenix release.
2. Recreate the sites on it.
3. Restore them from backup ([runbooks/restore.md](runbooks/restore.md), "Move sites to a new server").
4. Switch DNS.
5. Retire the old server.
