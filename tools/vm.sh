#!/usr/bin/env bash
# Disposable Ubuntu 24.04 test VMs via Multipass (Linux, macOS, Windows/Git Bash).
#
#   tools/vm.sh up    [name]   create a fresh VM (default name: dp-test-1)
#   tools/vm.sh test  [name]   copy the working tree in and run integration tests as root
#   tools/vm.sh shell [name]   open a shell
#   tools/vm.sh down  [name]   delete and purge the VM
#   tools/vm.sh list           list ozenix test VMs
#
# Safety: only VMs whose name starts with "dp-test-" can be touched.
set -euo pipefail
cd "$(dirname "$0")/.."

PREFIX="dp-test-"
cmd="${1:-}"; name="${2:-${PREFIX}1}"

die() { echo "vm.sh: $*" >&2; exit 1; }

command -v multipass >/dev/null 2>&1 || die "multipass not found. Install: https://canonical.com/multipass/install (Windows: Hyper-V backend; 'winget install Canonical.Multipass')"
[[ "$name" =~ ^dp-test-[a-z0-9-]{1,20}$ ]] || die "VM name must match ${PREFIX}[a-z0-9-]{1,20}"

winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

case "$cmd" in
  up)
    multipass launch 24.04 --name "$name" --cpus 2 --memory 2G --disk 12G \
      --cloud-init "$(winpath "$PWD/tools/vm/cloud-init.yaml")" --timeout 900
    multipass exec "$name" -- cloud-init status --wait
    ;;
  test)
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    tar --exclude=.git --exclude='__pycache__' --exclude='.*_cache' -czf "$tmp/src.tgz" .
    multipass transfer "$(winpath "$tmp/src.tgz")" "$name:/tmp/dp-src.tgz"
    multipass exec "$name" -- sudo bash -c '
      set -euo pipefail
      rm -rf /opt/dp-src && mkdir -p /opt/dp-src
      tar -xzf /tmp/dp-src.tgz -C /opt/dp-src
      cd /opt/dp-src && python3 -m pytest -p no:cacheprovider -m integration tests/integration
    '
    ;;
  shell) multipass shell "$name" ;;
  down)  multipass delete --purge "$name" ;;
  list)  multipass list | awk -v p="$PREFIX" 'NR==1 || index($1,p)==1' ;;
  *)     sed -n '2,11p' "$0"; exit 2 ;;
esac
