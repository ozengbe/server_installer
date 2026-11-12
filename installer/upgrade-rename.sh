# shellcheck shell=bash
# One-time upgrade of servers installed before the project got its final name.
# Sourced by installer/install.sh. On a fresh server, and on any server that
# has already been upgraded, it does nothing. Delete this file (and its three
# calls in install.sh) once every server you run has been upgraded.
#
# Before the playbook (rename_move): directories are moved to their new names,
#   so the registry, secrets, site configs, certificates and logs carry over.
# During the playbook: the firewall replaces the old table atomically
#   (dp_legacy_nft_table); every role writes its files under the new names, and
#   `site system refresh` rewrites each site's configuration and restarts it.
# After the playbook (rename_cleanup): files left under the old name are
#   removed. Until then they duplicate the new ones (same settings), so there
#   is no window in which SSH, sudo, PHP or the firewall lose their settings.

RENAME_OLD="$(printf '%s' 'domain' 'pilot')"
RENAME_NEW=ozenix
RENAME_EXTRA=()  # used by install.sh
export RENAME_EXTRA

rename_move() {
  local o=$RENAME_OLD n=$RENAME_NEW pair src dst moved=0
  if nft list table inet "$o" >/dev/null 2>&1; then
    RENAME_EXTRA=(-e "dp_legacy_nft_table=$o")
  fi
  # Every step is independent and repeatable: an interrupted upgrade finishes
  # on the next run.
  for pair in "/etc/$o:/etc/$n" "/var/lib/$o:/var/lib/$n" "/var/log/$o:/var/log/$n" \
              "/var/log/nginx/$o:/var/log/nginx/$n" "/var/backups/$o:/var/backups/$n" \
              "/etc/nginx/$o:/etc/nginx/$n" "/etc/apparmor.d/$o:/etc/apparmor.d/$n" \
              "/var/lib/$o-acme:/var/lib/$n-acme" "/etc/$o-test-vm:/etc/$n-test-vm"; do
    src=${pair%%:*} dst=${pair#*:}
    [[ -e $src ]] || continue
    if (( moved == 0 )); then
      info "Upgrading a server installed under the previous name: moving its files to the new names"
      systemctl stop dp-backup.timer dp-backup-drill.timer dp-monitor.timer 2>/dev/null || true
      [[ -f /var/log/$o/audit.jsonl ]] && chattr -a "/var/log/$o/audit.jsonl" 2>/dev/null
      moved=1
    fi
    if [[ ! -e $dst ]]; then
      mv "$src" "$dst"
    elif [[ -d $src && -d $dst ]]; then
      # An interrupted run (or a role) already created the new directory:
      # merge, never overwriting anything that exists under the new name.
      local entry
      for entry in "$src"/* "$src"/.[!.]*; do
        [[ -e $entry && ! -e $dst/${entry##*/} ]] && mv "$entry" "$dst/"
      done
      rmdir "$src" 2>/dev/null || true
    fi
  done
  # Tuning chosen with `site system optimize` keeps its values under the new name.
  for src in /etc/mysql/mariadb.conf.d/98-"$o"-tuning.cnf /etc/php/*/fpm/conf.d/98-"$o"-tuning.ini; do
    [[ -f $src ]] && mv "$src" "${src//$o/$n}"
  done
  # Site vhosts and the nginx main config still point at the old paths: fix
  # them so `nginx -t` keeps passing until the roles rewrite them.
  if grep -rqsF "/$o" /etc/nginx/nginx.conf "/etc/nginx/$n"; then
    sed -i "s|/$o/|/$n/|g; s|/$o-acme|/$n-acme|g" /etc/nginx/nginx.conf /etc/nginx/"$n"/sites/*.conf \
      /etc/nginx/"$n"/*.conf /etc/nginx/"$n"/snippets/*.conf 2>/dev/null || true
  fi
  return 0
}

rename_cleanup() {
  local o=$RENAME_OLD f name
  # Anything named after the old name, or any file in /etc still mentioning it.
  [[ -n $(compgen -G "/etc/*/*$o*" 2>/dev/null; compgen -G "/etc/systemd/system/*/*$o*" 2>/dev/null) \
     || -e /run/$o || -e /usr/lib/$o ]] || grep -rqsIF "$o" /etc || return 0
  info "Removing configuration files left under the previous name"
  sed -i "/^# BEGIN $o managed block\$/I,/^# END $o managed block\$/Id" /etc/ssh/sshd_config
  for f in /etc/sysctl.d/*"$o"* /etc/ssh/sshd_config.d/*"$o"* /etc/sudoers.d/*"$o"* \
           /etc/fail2ban/jail.d/*"$o"* /etc/mysql/mariadb.conf.d/*"$o"* /etc/apt/apt.conf.d/*"$o"* \
           /etc/apt/preferences.d/*"$o"* /etc/audit/rules.d/*"$o"* /etc/needrestart/conf.d/*"$o"* \
           /etc/systemd/journald.conf.d/*"$o"* /etc/systemd/system/*.d/*"$o"* /etc/logrotate.d/*"$o"* \
           /etc/letsencrypt/renewal-hooks/*/*"$o"* /etc/tmpfiles.d/*"$o"* /etc/php/*/*/conf.d/*"$o"*; do
    [[ -e $f ]] && rm -f "$f"
  done
  # Certificate renewal settings point at the ACME webroot and hook paths.
  for f in /etc/letsencrypt/renewal/*.conf; do
    [[ -f $f ]] && grep -qF "$o" "$f" \
      && sed -i "s|/var/lib/$o-acme|/var/lib/$RENAME_NEW-acme|g; s|/run/$o/|/run/$RENAME_NEW/|g; s|/etc/$o/|/etc/$RENAME_NEW/|g" "$f"
  done
  # Generated audit rules: rebuild from rules.d (the old file was removed above).
  if command -v augenrules >/dev/null 2>&1; then augenrules --load >/dev/null 2>&1 || true; fi
  # augenrules keeps the previous generated file as audit.rules.prev.
  if grep -qsF "$o" /etc/audit/audit.rules.prev; then rm -f /etc/audit/audit.rules.prev; fi
  # Backup copies the installer made of files before changing them (name~).
  find /etc -xdev -type f -name '*~' 2>/dev/null \
    | while IFS= read -r f; do
        if grep -qF "$o" "$f" 2>/dev/null; then rm -f "$f"; fi
      done
  rm -rf "/run/$o"
  rm -rf "/usr/lib/$o" "/usr/local/lib/$o"  # the new CLI is installed by now
  rm -f "/etc/$RENAME_NEW/firewall/$o.nft"
  # Site AppArmor profiles of the old name: unused since `system refresh`.
  grep -o "$o-tenant-[a-z0-9-]*" /sys/kernel/security/apparmor/profiles 2>/dev/null | sort -u \
    | while IFS= read -r name; do
        printf 'profile %s {}\n' "$name" | apparmor_parser -R 2>/dev/null || true
      done
  systemctl daemon-reload
  if /usr/sbin/sshd -t; then systemctl reload ssh 2>/dev/null || true; fi
  systemctl reload fail2ban 2>/dev/null || true
  systemctl start dp-backup.timer dp-backup-drill.timer dp-monitor.timer 2>/dev/null || true
  return 0
}
