#!/bin/sh
# get.sh: download a stackward release, verify it, and put the binary in a
# directory you choose. Read it before you run it; it is short on purpose.
#
#   curl -fsSLO https://github.com/Shironex/stackward/releases/latest/download/get.sh
#   less get.sh
#   sh get.sh -d "$HOME/.local/bin"
#
# What it does:
#   1. detects your OS and CPU (linux or darwin, amd64 or arm64)
#   2. downloads the release archive and checksums.txt over HTTPS
#   3. checks the archive SHA-256 against checksums.txt
#   4. if cosign is installed, verifies the keyless signature of checksums.txt
#   5. extracts only the `stackward` file and copies it to the target directory
#
# What it never does: run the downloaded binary, use sudo, change anything
# outside the target directory and a private temp directory, or self update.
#
# Options:
#   -d DIR      install directory (default: current directory)
#   -v VERSION  release tag such as v0.1.0 (default: the latest release)
#   -h          show this help
#
# Environment:
#   STACKWARD_BASE_URL  repository URL to download from (default below);
#                       for mirrors and tests. Signature identity checks
#                       always expect the official repository workflow.

set -eu

REPO="Shironex/stackward"
BASE_URL="${STACKWARD_BASE_URL:-https://github.com/$REPO}"
SIGNER_ISSUER="https://token.actions.githubusercontent.com"

dest="."
version=""

say() { printf '%s\n' "$*"; }
die() { printf 'get.sh: error: %s\n' "$*" >&2; exit 1; }

usage() {
	sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//' >&2
	printf 'Usage: sh get.sh [-d DIR] [-v VERSION]\n' >&2
}

while getopts "d:v:h" opt; do
	case $opt in
	d) dest=$OPTARG ;;
	v) version=$OPTARG ;;
	h) usage; exit 0 ;;
	*) usage; exit 2 ;;
	esac
done

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

# OS and architecture
case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported OS $(uname -s); download the archive from $BASE_URL/releases by hand" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported CPU $(uname -m)" ;;
esac

# Version: an explicit tag, or whatever the latest release redirects to.
if [ -z "$version" ]; then
	final=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$BASE_URL/releases/latest") ||
		die "could not look up the latest release"
	version=${final##*/}
fi
case "$version" in
v[0-9]*) ;;
*) die "version must be a tag like v0.1.0, got '$version'" ;;
esac
case "$version" in
*[!0-9A-Za-z._-]*) die "version contains unexpected characters" ;;
esac
ver=${version#v}

archive="stackward_${ver}_${os}_${arch}.tar.gz"
asset_url="$BASE_URL/releases/download/$version"

# Private temp dir, removed on exit.
tmp=$(mktemp -d "${TMPDIR:-/tmp}/stackward-get.XXXXXX") || die "could not create a temp directory"
trap 'rm -rf "$tmp"' EXIT INT TERM HUP

say "stackward $version for $os/$arch"
say "downloading $archive and checksums.txt"
curl -fsSL -o "$tmp/$archive" "$asset_url/$archive" || die "download failed: $asset_url/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$asset_url/checksums.txt" || die "download failed: $asset_url/checksums.txt"

# SHA-256 of the archive against the checksums file (exact filename match).
if command -v sha256sum >/dev/null 2>&1; then
	actual=$(sha256sum "$tmp/$archive" | cut -d ' ' -f 1)
elif command -v shasum >/dev/null 2>&1; then
	actual=$(shasum -a 256 "$tmp/$archive" | cut -d ' ' -f 1)
else
	die "need sha256sum or shasum to verify the download"
fi
expected=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
[ -n "$expected" ] || die "$archive is not listed in checksums.txt"
[ "$actual" = "$expected" ] || die "SHA-256 mismatch for $archive (expected $expected, got $actual)"
say "sha256 ok: $actual"

# Signature of checksums.txt, only when cosign is available.
if command -v cosign >/dev/null 2>&1; then
	curl -fsSL -o "$tmp/checksums.txt.sigstore.json" "$asset_url/checksums.txt.sigstore.json" ||
		die "download failed: $asset_url/checksums.txt.sigstore.json"
	identity="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$version"
	cosign verify-blob \
		--bundle "$tmp/checksums.txt.sigstore.json" \
		--certificate-identity "$identity" \
		--certificate-oidc-issuer "$SIGNER_ISSUER" \
		"$tmp/checksums.txt" >/dev/null 2>&1 ||
		die "cosign could not verify the signature of checksums.txt; nothing was installed"
	say "cosign signature ok (signed by the $REPO release workflow)"
else
	say "cosign not found: signature NOT checked (only the SHA-256 above). Install cosign to check it."
fi

# Extract only the binary, then copy it into place.
tar -xzf "$tmp/$archive" -C "$tmp" stackward || die "the archive does not contain a stackward file"
if [ ! -f "$tmp/stackward" ] || [ -L "$tmp/stackward" ]; then
	die "unexpected archive content"
fi

mkdir -p "$dest" || die "cannot create $dest"
cp "$tmp/stackward" "$dest/.stackward.new.$$" || die "cannot write to $dest"
chmod 755 "$dest/.stackward.new.$$"
mv -f "$dest/.stackward.new.$$" "$dest/stackward"

say "installed $dest/stackward"
say "not executed. To check the build: $dest/stackward version"
say "then audit with: $dest/stackward audit  (sudo for full coverage)"
