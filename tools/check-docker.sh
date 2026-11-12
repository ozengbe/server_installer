#!/usr/bin/env bash
# Run tools/check.sh inside a throwaway container (for Windows/macOS hosts).
# Works from Git Bash. The source tree is mounted read-only, then copied in,
# so caches never land in the (OneDrive-synced) working copy.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="$(pwd -W 2>/dev/null || pwd)"   # Windows path under Git Bash
IMAGE="python:3.12-slim"
# --no-security: skip tools/security-scan.sh (it needs network and takes a few minutes).
SCAN=1
[[ "${1:-}" == "--no-security" ]] && SCAN=0

MSYS_NO_PATHCONV=1 docker run --rm -e DEBIAN_FRONTEND=noninteractive -e SCAN="$SCAN" -v "${SRC}:/ro:ro" "$IMAGE" bash -c '
  set -euo pipefail
  apt-get update -qq >/dev/null && apt-get install -y -qq shellcheck git curl >/dev/null
  cp -a /ro /src && cd /src
  pip install --quiet --root-user-action=ignore --disable-pip-version-check -e ".[dev]" "ansible-lint==24.12.2" "ansible-core>=2.16,<2.17"
  # Run unprivileged, like the GitHub runner: tests that only pass as root
  # would otherwise go unnoticed until CI.
  useradd -m -u 1001 runner && chown -R runner /src
  su runner -c "cd /src && bash tools/check.sh"
  if [ "$SCAN" = 1 ]; then
    su runner -c "git config --global --add safe.directory /src && cd /src && bash tools/security-scan.sh"
  fi
'
