#!/usr/bin/env bash
# Build an ozenix release (docs/release.md).
#
#   tools/release.sh --key ~/.ssh/ozenix-release [--out DIR]   from tag v<version>
#   tools/release.sh --snapshot [--out DIR]                         unsigned test build of HEAD
#
# Output in DIR (default dist/):
#   ozenix-<version>.tar.gz   git archive of the tag (reproducible: fixed
#                                  mtimes from the commit, gzip -n), with
#                                  RELEASE (version, commit) and MANIFEST.sha256
#                                  (every file; checked by installer/install.sh)
#   SHA256SUMS                     checksum of the tarball
#   SHA256SUMS.sig                 SSH signature, namespace "ozenix-release",
#                                  verifiable with release/allowed_signers
set -euo pipefail
export LC_ALL=C

die() { echo "release.sh: ERROR: $*" >&2; exit 1; }
info() { echo "release.sh: $*"; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist"
KEY=""
SNAPSHOT=0
NAMESPACE=ozenix-release
IDENTITY=release@ozenix
CONTENT=(installer ansible bin ozenix docs README.md CHANGELOG.md release)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key) KEY="${2:?--key needs a private key file}"; shift 2 ;;
    --out) OUT="${2:?--out needs a directory}"; shift 2 ;;
    --snapshot) SNAPSHOT=1; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

cd "$ROOT"
VERSION="$(sed -n 's/^__version__ = "\([0-9a-z.]*\)"$/\1/p' ozenix/__init__.py)"
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+((rc|\.dev)[0-9]+)?$ ]] || die "bad __version__: '$VERSION'"

if [[ $SNAPSHOT -eq 1 ]]; then
  REF=HEAD
  NAME="ozenix-$VERSION+$(git rev-parse --short=12 HEAD)"
else
  [[ -n $KEY ]] || die "--key is required for a release (or use --snapshot)"
  [[ -f $KEY ]] || die "no such key: $KEY"
  [[ -z "$(git status --porcelain)" ]] || die "working tree is not clean"
  REF="v$VERSION"
  git rev-parse -q --verify "refs/tags/$REF" >/dev/null || die "tag $REF does not exist (git tag -s $REF)"
  [[ "$(git rev-parse "$REF^{commit}")" == "$(git rev-parse HEAD)" ]] || die "HEAD is not $REF"
  grep -q "^## $VERSION\b" CHANGELOG.md || die "CHANGELOG.md has no '## $VERSION' section"
  NAME="ozenix-$VERSION"
fi
COMMIT="$(git rev-parse "$REF^{commit}")"

mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. Export exactly the tracked files of REF (nothing from the working tree).
git archive --format=tar --prefix="$NAME/" "$REF" -- "${CONTENT[@]}" | tar -x -C "$WORK"
find "$WORK/$NAME" -name '__pycache__' -prune -exec rm -rf {} +

# 2. Identity and manifest (the manifest lists every file except itself).
printf 'version=%s\ncommit=%s\n' "$VERSION" "$COMMIT" >"$WORK/$NAME/RELEASE"
(cd "$WORK/$NAME" && find . -type f -printf '%P\n' | sort | xargs -d '\n' sha256sum) \
  >"$WORK/manifest"
mv "$WORK/manifest" "$WORK/$NAME/MANIFEST.sha256"

# 3. Reproducible tarball: sorted names, commit time, root ownership, no gzip timestamp.
EPOCH="$(git log -1 --format=%ct "$REF")"
TARBALL="$OUT/$NAME.tar.gz"
tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' -C "$WORK" -cf - "$NAME" | gzip -9 -n >"$TARBALL"

(cd "$OUT" && sha256sum "$NAME.tar.gz" >SHA256SUMS)
info "built $TARBALL"
info "sha256 $(cut -d' ' -f1 "$OUT/SHA256SUMS")"

if [[ $SNAPSHOT -eq 1 ]]; then
  info "snapshot build: NOT signed, not for production"
  exit 0
fi

# 4. Sign the checksum file and prove the signature verifies with the published key.
rm -f "$OUT/SHA256SUMS.sig"
ssh-keygen -Y sign -q -f "$KEY" -n "$NAMESPACE" "$OUT/SHA256SUMS"
ssh-keygen -Y verify -f release/allowed_signers -I "$IDENTITY" -n "$NAMESPACE" \
  -s "$OUT/SHA256SUMS.sig" <"$OUT/SHA256SUMS" >/dev/null \
  || die "signature does not verify with release/allowed_signers (wrong key, or key not published)"
info "signed: $OUT/SHA256SUMS.sig"
info "publish: $NAME.tar.gz, SHA256SUMS, SHA256SUMS.sig"
