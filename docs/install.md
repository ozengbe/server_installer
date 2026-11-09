# Installing the DomainPilot host baseline (Phase 2a)

> **Preview.** Phase 2a hardens the base system, SSH and the firewall. Web services arrive in Phase 2b.
> Try it on a disposable VM first.

## Before you start
- Fresh **Ubuntu 24.04 LTS** server with the `universe` component enabled (needed for `ansible-core`).
- You are logged in over SSH **with a key** as a normal sudo-capable user (not root).
- Console access through your provider, in case something goes wrong.

## Install

```bash
git clone https://github.com/ozengbe/server_installer.git
cd server_installer
sudo installer/install.sh --check     # dry run: shows what would change
sudo installer/install.sh
```

On the first run the installer creates `/etc/domainpilot/install.yml`. Your account becomes the first admin, using the keys from your `~/.ssh/authorized_keys`. Review that file. All settings are documented in [ansible/group_vars/all.yml](../ansible/group_vars/all.yml).

After hardening:
- SSH is key-only. Root login is disabled, and only members of `dp-admins` (admins) and `dp-sftp` (tenants, from Phase 8) can log in.
- Keys are read **only** from `/etc/ssh/authorized_keys.d/<user>` (root-owned). Keys in `~/.ssh/authorized_keys` are ignored.
- Every inbound port is closed except 22, 80 and 443 (plus WireGuard if configured), on IPv4 and IPv6.

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
