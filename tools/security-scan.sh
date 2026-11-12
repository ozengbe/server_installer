#!/usr/bin/env bash
# Security scans of the code base (release gate, docs/security-baseline.md):
#   Bandit     python security linter            any finding fails
#   Semgrep    ozenix rules + registry rule sets  any finding fails
#   pip-audit  known vulnerabilities in the pinned dev/CI dependencies
#              (ozenix itself has no runtime dependencies: stdlib only)
#   Gitleaks   secrets in the working tree and the whole git history
# Linux or CI, needs network. On Windows run it through tools/check-docker.sh.
# Each tool runs in its own throwaway venv, so the scanners' own packages are
# never part of the dependency audit.
set -euo pipefail
cd "$(dirname "$0")/.."

BANDIT="bandit==1.8.0"
SEMGREP="semgrep==1.99.0"
PIP_AUDIT="pip-audit==2.7.3"
GITLEAKS_VERSION="8.21.2"
GITLEAKS_SHA256="5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

venv() {  # venv <name> <packages...>: a private venv, prints its bin dir
  local dir="$WORK/$1"; shift
  python3 -m venv "$dir"
  "$dir/bin/pip" install --quiet --disable-pip-version-check "$@" >&2
  echo "$dir/bin"
}

echo "== bandit"
bin="$(venv bandit "$BANDIT")"
"$bin/bandit" -q -r ozenix -c pyproject.toml || fail=1

echo "== semgrep"
# setuptools: this semgrep release still imports pkg_resources.
bin="$(venv semgrep "$SEMGREP" "setuptools==75.8.0")"
"$bin/semgrep" scan --metrics=off --quiet --error --disable-version-check \
  --config tools/semgrep/ozenix.yml --config p/python --config p/secrets \
  ozenix installer tools || fail=1

echo "== pip-audit (pinned dev and CI dependencies)"
python3 - >"$WORK/requirements.txt" <<'EOF'
import re, tomllib
with open("pyproject.toml", "rb") as f:
    project = tomllib.load(f)["project"]
for req in [*project.get("dependencies", []), *project["optional-dependencies"]["dev"]]:
    print(req)
# CI-only tools (.github/workflows/ci.yml installs these next to the dev extra).
with open(".github/workflows/ci.yml", encoding="utf-8") as f:
    for pin in re.findall(r'"((?:ansible-lint|ansible-core)[^"]*)"', f.read()):
        print(pin)
EOF
bin="$(venv pip-audit "$PIP_AUDIT")"
"$bin/pip-audit" --progress-spinner off --strict -r "$WORK/requirements.txt" || fail=1

echo "== gitleaks"
tarball="$WORK/gitleaks.tar.gz"
curl -fsSL -o "$tarball" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
echo "${GITLEAKS_SHA256}  $tarball" | sha256sum -c --quiet -
tar -xzf "$tarball" -C "$WORK" gitleaks
"$WORK/gitleaks" git --no-banner --redact . || fail=1
"$WORK/gitleaks" dir --no-banner --redact . || fail=1

if [[ $fail -ne 0 ]]; then
  echo "Security scan FAILED" >&2
  exit 1
fi
echo "Security scan passed."
