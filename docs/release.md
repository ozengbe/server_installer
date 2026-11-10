# Making an Ozenix release (maintainers)

Administrators install only **signed release tarballs**. This page covers how one is made.

## What a release contains

| File | What it is |
|---|---|
| `domainpilot-<version>.tar.gz` | The tagged commit's `installer/`, `ansible/`, `bin/`, `domainpilot/`, `docs/`, `release/`, `README.md` and `CHANGELOG.md`, plus `RELEASE` (version and commit) and `MANIFEST.sha256` (every file). Reproducible: built twice from the same tag, the bytes are identical. |
| `SHA256SUMS` | Checksum of the tarball |
| `SHA256SUMS.sig` | SSH signature of `SHA256SUMS` (namespace `domainpilot-release`) |

The chain of trust:
1. The signature proves `SHA256SUMS`.
2. `SHA256SUMS` proves the tarball.
3. Inside the tarball, `MANIFEST.sha256` proves every file. The installer checks it on every run.

We use SSH signatures (`ssh-keygen -Y`) because every Ubuntu server already has the tool to verify them. No GPG keyring is involved.

## One-time setup: the signing key

1. Create a **dedicated** key. Use a hardware-backed one if possible:
   ```bash
   ssh-keygen -t ed25519-sk -C "domainpilot release" -f ~/.ssh/domainpilot-release   # security key
   # or: ssh-keygen -t ed25519 -C "domainpilot release" -f ~/.ssh/domainpilot-release
   ```
   Never use it for anything else, and keep it off servers.
2. Add the public key to `release/allowed_signers`:
   ```
   release@domainpilot namespaces="domainpilot-release" ssh-ed25519 AAAA... domainpilot release
   ```
3. Publish its fingerprint (`ssh-keygen -lf ~/.ssh/domainpilot-release.pub`) in the table below **and** somewhere that doesn't depend on this repository, such as the project website or a pinned issue. Administrators compare the two.

| Key | Fingerprint | Valid from | Valid until |
|---|---|---|---|
| *(not created yet)* | | | |

**Key rotation.** Add the new key to `allowed_signers` in a release signed with the **old** key. Remove the old key one release later. If a key is compromised, remove it at once, publish a notice, and re-sign the current release with the new key.

## Making a release

1. Make sure:
   - CI is green on `main`, including the integration job;
   - the integration suite passed on a real 26.04 host;
   - `docs/roadmap.md` and `docs/security-report.md` are up to date.
2. Set the version in `domainpilot/__init__.py` (`MAJOR.MINOR.PATCH`, `rcN` for candidates). Add a `## <version>` section to `CHANGELOG.md` with upgrade notes. Commit.
3. Tag and build:
   ```bash
   git tag -s v0.10.0 -m "Ozenix 0.10.0"
   bash tools/release.sh --key ~/.ssh/domainpilot-release
   ```
   The script refuses to build if:
   - the working tree is dirty;
   - the tag is missing or isn't HEAD;
   - the CHANGELOG has no section for this version;
   - the signature doesn't verify against `release/allowed_signers`.
4. **Acceptance test** (release gate): someone other than the author installs the tarball on a clean VM using only [install.md](install.md), then runs `sudo site system security` and creates a test site.
5. Publish the three files in `dist/` as a GitHub release for the tag, and push the tag.

A test build of the current HEAD, unsigned and named with the commit, can be made with:

```bash
bash tools/release.sh --snapshot
```

## Labels

A release is **preview** until all seven security gates in [roadmap.md](roadmap.md) are met. Gate 6 is an independent review of the root-run code. Say so in the GitHub release title.
