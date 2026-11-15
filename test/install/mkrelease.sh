#!/bin/sh
# mkrelease.sh: build one fake release folder for test/install/run.sh.
#
#   mkrelease.sh ROOT VERSION [tamper]
#
# Writes ROOT/releases/download/vVERSION/ with a stub stackward (a shell
# script that prints a version line), the Linux or macOS archive for this
# machine, a .deb when dpkg-deb exists, install.sh, checksums.txt and a dummy
# signature bundle. With "tamper" the package files are changed after the
# checksums were written, so the SHA-256 check must fail.
set -eu

root=$1
ver=$2
tamper=${3:-}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) echo "mkrelease.sh: unsupported OS" >&2; exit 1 ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) echo "mkrelease.sh: unsupported CPU" >&2; exit 1 ;;
esac

dir="$root/releases/download/v$ver"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$dir" "$work/bin"

cat >"$work/bin/stackward" <<STUB
#!/bin/sh
echo "stackward $ver $os/$arch fake"
STUB
chmod 755 "$work/bin/stackward"

tar -czf "$dir/stackward_${ver}_${os}_${arch}.tar.gz" -C "$work/bin" stackward

if command -v dpkg-deb >/dev/null 2>&1; then
	pkg="$work/pkg"
	mkdir -p "$pkg/DEBIAN" "$pkg/usr/bin" "$pkg/usr/share/doc/stackward"
	cp "$work/bin/stackward" "$pkg/usr/bin/stackward"
	echo "fake license" >"$pkg/usr/share/doc/stackward/LICENSE"
	cat >"$pkg/DEBIAN/control" <<CONTROL
Package: stackward
Version: $ver
Architecture: $(dpkg --print-architecture)
Maintainer: test <test@example.com>
Description: fake stackward package for installer tests
CONTROL
	dpkg-deb --root-owner-group --build "$pkg" "$dir/stackward_${ver}_$(dpkg --print-architecture).deb" >/dev/null
fi

cp "$repo/scripts/install.sh" "$dir/install.sh"
echo '{}' >"$dir/checksums.txt.sigstore.json"

(
	cd "$dir"
	for f in stackward_* install.sh; do
		if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; else shasum -a 256 "$f"; fi
	done >"$work/checksums.txt"
)
cp "$work/checksums.txt" "$dir/checksums.txt"

if [ "$tamper" = tamper ]; then
	for f in "$dir"/stackward_*; do printf 'tampered' >>"$f"; done
fi
