#!/usr/bin/env bash
# Run all static checks and unit/security tests. Linux or CI.
# On Windows use tools/check-docker.sh (runs this inside a python:3.12 container).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== ruff";        ruff check .
echo "== ruff format"; ruff format --check .
echo "== mypy";        mypy
echo "== pytest";      pytest --cov=domainpilot --cov-report=term-missing

if command -v shellcheck >/dev/null 2>&1; then
  echo "== shellcheck"
  find . -name '*.sh' -not -path './.git/*' -print0 | xargs -0 shellcheck
else
  echo "== shellcheck: not installed, skipped (CI runs it)"
fi

if [ -d ansible/roles ] && command -v ansible-lint >/dev/null 2>&1; then
  echo "== ansible-lint"; ansible-lint ansible/
fi
echo "All checks passed."
