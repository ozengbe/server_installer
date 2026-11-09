#!/usr/bin/env bash
# After a failed integration run: collect what explains it and surface it as
# GitHub annotations (journals of tenant services, AppArmor denials, crashes).
set -uo pipefail

annotate() { # title, message
  local msg=$2
  [[ -z ${msg//[[:space:]]/} ]] && return 0
  msg=${msg//'%'/'%25'}; msg=${msg//$'\r'/'%0D'}; msg=${msg//$'\n'/'%0A'}
  echo "::error title=$1::$msg"
}

echo "== tenant service journals"
journal=$(journalctl -u 'dp-php@*' -u 'dp-cache@*' --no-pager -n 80 -o short-precise 2>&1)
echo "$journal"
annotate "diag: tenant service journal" "$(echo "$journal" | grep -viE 'Started|Starting|Stopping|Stopped|Deactivated|Consumed' | tail -n 25)"

echo "== AppArmor denials"
denials=$( { grep -h 'apparmor="DENIED"' /var/log/audit/audit.log 2>/dev/null; journalctl -k --no-pager 2>/dev/null | grep 'apparmor="DENIED"'; } )
summary=$(echo "$denials" | grep -oE 'operation="[^"]*"|profile="[^"]*"|name="[^"]*"|requested_mask="[^"]*"|peer="[^"]*"' \
  | paste -sd' ' | sed 's/ operation=/\noperation=/g' | sort | uniq -c | sort -rn | head -20)
echo "$summary"
annotate "diag: AppArmor denials" "$summary"

echo "== crashes, seccomp, OOM"
crashes=$( { journalctl --no-pager -n 3000 2>/dev/null; grep -h 'type=SECCOMP' /var/log/audit/audit.log 2>/dev/null; } \
  | grep -iE 'segfault|core-dump|dumped core|SIGSYS|type=SECCOMP|oom-kill|Out of memory|exited, code=|signal=' | tail -n 20)
echo "$crashes"
annotate "diag: crashes / seccomp / OOM" "$crashes"
exit 0
