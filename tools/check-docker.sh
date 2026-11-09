#!/usr/bin/env bash
# Run tools/check.sh inside a throwaway container (for Windows/macOS hosts).
# Works from Git Bash. The source tree is mounted read-only, then copied in,
# so caches never land in the (OneDrive-synced) working copy.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="$(pwd -W 2>/dev/null || pwd)"   # Windows path under Git Bash
IMAGE="python:3.12-slim"

MSYS_NO_PATHCONV=1 docker run --rm -e DEBIAN_FRONTEND=noninteractive -v "${SRC}:/ro:ro" "$IMAGE" bash -c '
  set -euo pipefail
  apt-get update -qq >/dev/null && apt-get install -y -qq shellcheck >/dev/null
  cp -a /ro /src && cd /src
  pip install --quiet --root-user-action=ignore --disable-pip-version-check -e ".[dev]" "ansible-lint==24.12.2" "ansible-core>=2.16,<2.17"
  bash tools/check.sh
'
