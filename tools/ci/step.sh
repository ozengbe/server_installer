#!/usr/bin/env bash
# Run a CI step, keep its log, and on failure turn the important lines into
# GitHub annotations so the cause shows on the run's summary page.
#
#   tools/ci/step.sh TITLE MODE -- COMMAND...
#     MODE: install  - Ansible run; report fatal errors
#           idempotent - Ansible run that must report changed=0; report changed tasks
#           pytest   - report FAILED tests and assertion lines
#           plain    - report the last lines of output
set -uo pipefail

title=$1 mode=$2
shift 2
[[ ${1:-} == "--" ]] && shift

log="$(mktemp)"
"$@" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}

annotate() { # escape for workflow commands, then emit
  local msg=$1
  msg=${msg//'%'/'%25'}; msg=${msg//$'\r'/'%0D'}; msg=${msg//$'\n'/'%0A'}
  echo "::error title=${title}::${msg}"
}

report() {
  case "$mode" in
    install)
      # Loop tasks fail with "failed: [host] (item=...)" and no "fatal:" line.
      grep -E 'fatal:|^failed: |\[ERROR\]|ERROR!|FAILED!|install.sh: ERROR|release: ' "$log" \
        | cut -c1-600 | head -8 | while IFS= read -r line; do annotate "$line"; done
      # Which task failed (GitHub shows only the first line of an annotation).
      awk '/^TASK \[/ {task=$0} /^(fatal|failed): / {print task}' "$log" | sort -u | head -3 \
        | while IFS= read -r line; do annotate "failed task: $line"; done ;;
    idempotent)
      awk '/^TASK \[/ {task=$0} /^changed: / {print task}' "$log" | sort -u | head -15 \
        | while IFS= read -r line; do annotate "changed on second run: $line"; done
      grep -E 'fatal:|\[ERROR\]' "$log" | cut -c1-600 | head -5 \
        | while IFS= read -r line; do annotate "$line"; done ;;
    pytest)
      grep -E '^(FAILED|ERROR) ' "$log" | cut -c1-600 | head -15 \
        | while IFS= read -r line; do annotate "$line"; done
      grep -E '^E +' "$log" | cut -c1-400 | head -10 \
        | while IFS= read -r line; do annotate "$line"; done ;;
    *)
      annotate "$(tail -n 15 "$log")" ;;
  esac
}

if [[ $mode == idempotent && $rc -eq 0 ]]; then
  if ! grep -Eq 'localhost +: ok=[0-9]+ +changed=0 +unreachable=0 +failed=0' "$log"; then
    rc=1
  fi
fi
if [[ $rc -ne 0 ]]; then
  report
  # Always leave specific annotations: one per line, because GitHub's summary
  # shows only the first line of a multi-line annotation.
  annotate "step failed (exit $rc); the last lines follow"
  tail -n 8 "$log" | cut -c1-400 | while IFS= read -r line; do annotate "  $line"; done
fi
rm -f "$log"
exit "$rc"
