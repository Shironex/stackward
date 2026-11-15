#!/bin/sh
# run.sh: scenarios for scripts/install.sh against a local fake release.
#
#   sh test/install/run.sh
#
# A python3 http server on 127.0.0.1 plays the repository's release URLs
# (STACKWARD_BASE_URL points at it). Every release holds a stub stackward, so
# nothing real is downloaded and nothing real is installed.
#
# The binary scenarios (--prefix) write only under a temp directory and run
# anywhere. The apt scenarios install and remove a fake `stackward` package on
# the machine, so they only run when STACKWARD_TEST_DEB=1 is set, which CI does
# on its disposable runner. Never set it on a machine you use.
#
# Set SAMPLE_OUT to a file to keep the raw recording of the terminal run.
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
INSTALL="$repo/scripts/install.sh"
T=$(mktemp -d "${TMPDIR:-/tmp}/stackward-install-test.XXXXXX")
fails=0
server_pid=""
ESC=$(printf '\033')

cleanup() {
	[ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null
	rm -rf "$T"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

pass() { printf 'ok   %s\n' "$1"; }
fail() {
	printf 'FAIL %s\n' "$1"
	[ ! -s "$T/out" ] || sed 's/^/     out: /' "$T/out"
	[ ! -s "$T/err" ] || sed 's/^/     err: /' "$T/err"
	fails=$((fails + 1))
}
check() { # name command...
	_n=$1
	shift
	if "$@"; then pass "$_n"; else fail "$_n"; fi
}

# inst ARGS...: run install.sh, output in $T/out and $T/err, status in $rc.
inst() {
	sh "$INSTALL" "$@" >"$T/out" 2>"$T/err" </dev/null
	rc=$?
}
exit_is() { [ "$rc" -eq "$1" ]; }
out_has() { grep -q -- "$1" "$T/out" "$T/err" 2>/dev/null; }
out_lacks() { ! out_has "$1"; }
gone() { [ ! -e "$1" ]; }
ver_is() { [ "$("$1" version 2>/dev/null)" = "stackward $2 $os/$arch fake" ]; }
log_path() { sed -n 's/^log: //p' "$T/out" | head -n 1; }

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) echo "unsupported OS"; exit 1 ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
*) arch=arm64 ;;
esac

if command -v cosign >/dev/null 2>&1; then
	echo "a real cosign is on PATH; it cannot verify the fake release. Remove it from PATH for this test." >&2
	exit 1
fi

# ---- fake release server
root="$T/site"
mkdir -p "$root"
for v in 0.0.1 0.0.2-rc.1 0.0.2; do sh "$here/mkrelease.sh" "$root" "$v"; done
sh "$here/mkrelease.sh" "$root" 0.0.3 tamper
echo v0.0.2 >"$root/latest.txt"
python3 "$here/server.py" "$root" "$T/port" &
server_pid=$!
i=0
while [ ! -s "$T/port" ] && [ "$i" -lt 50 ]; do
	sleep 0.1
	i=$((i + 1))
done
[ -s "$T/port" ] || { echo "server did not start"; exit 1; }
BASE="http://127.0.0.1:$(cat "$T/port")"
export STACKWARD_BASE_URL="$BASE"
unset NO_COLOR STACKWARD_VERSION STACKWARD_FETCHER

echo "== usage"
inst --version banana
check "bad version is a usage error" exit_is 2
inst frobnicate
check "unknown argument is a usage error" exit_is 2
inst --prefix relative/dir
check "relative prefix is refused" exit_is 2

echo "== binary install under --prefix"
P="$T/p1"
inst install --prefix "$P" --dry-run
check "dry run exits 0" exit_is 0
check "dry run says what it would do" out_has "would copy stackward"
check "dry run writes nothing" gone "$P"

inst install --prefix "$P" --version v0.0.3 --yes
check "tampered checksum fails" exit_is 1
check "tampered checksum names the mismatch" out_has "SHA-256 mismatch"
check "tampered checksum says nothing changed" out_has "Nothing was changed"
check "tampered checksum writes nothing" gone "$P"

# the one-line form: the script is piped into sh
curl -fsSL "$BASE/releases/latest/download/install.sh" | sh -s -- --prefix "$P" --yes >"$T/out" 2>"$T/err"
rc=$?
check "piped install exits 0" exit_is 0
check "piped install puts the binary in place" ver_is "$P/bin/stackward" 0.0.2
check "install writes the record" test -f "$P/share/stackward/install.json"
check "install says what it installed" out_has "stackward 0.0.2 installed"
check "summary names next steps" out_has "stackward audit"
check "summary says the signature was not checked" out_has "NOT checked"
check "plain output has no escape codes" out_lacks "$ESC"
check "plain output is printable ASCII" sh -c "! LC_ALL=C grep -q '[^[:print:]]' '$T/out'"
check "log file exists" test -s "$(log_path)"

inst install --prefix "$P" --yes
check "re-install exits 0" exit_is 0
check "re-install says already installed" out_has "already installed"
inst update --prefix "$P" --yes
check "update when current exits 0" exit_is 0
check "update when current says up to date" out_has "up to date"

inst uninstall --prefix "$P"
check "uninstall without --yes and no terminal is refused" exit_is 1
check "refused uninstall leaves the binary" test -x "$P/bin/stackward"
inst uninstall --prefix "$P" --yes --dry-run
check "uninstall dry run leaves the binary" test -x "$P/bin/stackward"
inst uninstall --prefix "$P" --yes
check "uninstall exits 0" exit_is 0
check "uninstall summary hints at the shell path cache" out_has 'hash -r'
check "uninstall leaves nothing, not even the prefix we created" gone "$P"
inst uninstall --prefix "$P" --yes
check "uninstall when absent exits 0" exit_is 0
check "uninstall when absent says so" out_has "nothing to remove"

echo "== update and downgrade"
P="$T/p2"
inst install --prefix "$P" --version v0.0.2-rc.1 --yes
check "install a pre-release when named" ver_is "$P/bin/stackward" 0.0.2-rc.1
inst update --prefix "$P" --yes
check "update from the pre-release installs the newer stable" ver_is "$P/bin/stackward" 0.0.2
check "update says update" out_has "update"
inst update --prefix "$P" --version v0.0.1 --yes
check "update never downgrades" out_has "up to date"
check "update kept 0.0.2" ver_is "$P/bin/stackward" 0.0.2
inst install --prefix "$P" --version v0.0.1 --yes
check "install can move to an older version when named" ver_is "$P/bin/stackward" 0.0.1
check "downgrade is labelled" out_has "downgrade"
touch "$P/bin/keep"
inst uninstall --prefix "$P" --yes
check "uninstall removes the binary" gone "$P/bin/stackward"
check "uninstall removes the record" gone "$P/share/stackward/install.json"
check "uninstall removes what it created" gone "$P/share"
check "uninstall keeps files it did not add" test -f "$P/bin/keep"

echo "== refusals"
P="$T/p3"
mkdir -p "$P/bin"
echo "mine" >"$P/bin/stackward"
inst install --prefix "$P" --yes
check "an unmanaged binary is not overwritten" exit_is 1
check "the unmanaged binary is untouched" test "$(cat "$P/bin/stackward")" = mine
inst update --prefix "$T/p-none" --yes
check "update without install fails" exit_is 1
if [ "$(id -u)" != 0 ]; then
	inst install --prefix /usr/stackward-nosudo-test --no-sudo --yes
	check "--no-sudo fails when root is needed" exit_is 1
	check "--no-sudo names the flag" out_has "no-sudo"
	check "--no-sudo writes nothing" gone /usr/stackward-nosudo-test
fi

echo "== quiet"
P="$T/p4"
inst install --prefix "$P" --yes --quiet
check "quiet install exits 0" exit_is 0
check "quiet prints one result line" test "$(wc -l <"$T/out" | tr -d ' ')" = 1
inst uninstall --prefix "$P" --yes --quiet
check "quiet uninstall exits 0" exit_is 0

echo "== cosign"
stubs="$T/stubs"
mkdir -p "$stubs"
printf '#!/bin/sh\necho "$@" >"%s/cosign.args"\nexit 0\n' "$T" >"$stubs/cosign"
chmod 755 "$stubs/cosign"
P="$T/p5"
PATH="$stubs:$PATH" inst install --prefix "$P" --yes
check "install with a passing cosign" exit_is 0
check "cosign result is reported" out_has "cosign signature ok"
check "cosign got the workflow identity" grep -q "release.yml@refs/tags/v0.0.2" "$T/cosign.args"
inst uninstall --prefix "$P" --yes
printf '#!/bin/sh\nexit 1\n' >"$stubs/cosign"
PATH="$stubs:$PATH" inst install --prefix "$P" --yes
check "a failing cosign stops the install" exit_is 1
check "a failing cosign writes nothing" gone "$P"
rm -rf "$stubs"

echo "== terminal output"
P="$T/p6"
if script --version 2>&1 | grep -q util-linux; then
	COLUMNS=200 TERM=xterm-256color LANG=C.UTF-8 script -qec "sh '$INSTALL' install --prefix '$P' --yes" /dev/null >"$T/tty.raw" 2>&1 </dev/null
else
	COLUMNS=200 TERM=xterm-256color LANG=en_US.UTF-8 script -q /dev/null sh "$INSTALL" install --prefix "$P" --yes >"$T/tty.raw" 2>&1 </dev/null
fi
check "terminal install worked" ver_is "$P/bin/stackward" 0.0.2
check "terminal output has colour" grep -q "$ESC\\[32m" "$T/tty.raw"
check "terminal output has a check mark" grep -q "✓" "$T/tty.raw"
check "terminal output has the summary box" grep -q "╭" "$T/tty.raw"
check "terminal output shows step numbers" grep -q "\\[5/5\\]" "$T/tty.raw"
[ -z "${SAMPLE_OUT:-}" ] || cp "$T/tty.raw" "$SAMPLE_OUT"
P="$T/p7"
NO_COLOR=1 inst install --prefix "$P" --yes
check "NO_COLOR gives plain output" out_lacks "$ESC"
rm -rf "$P"

# tty_ask ANSWERS...: run `install.sh install` on a terminal and type each
# answer after a short pause (script gives the run a pty, so confirm asks).
tty_ask() {
	_prefix=$1
	shift
	{
		for _a in "$@"; do
			sleep 1
			printf '%s\n' "$_a"
		done
		sleep 1
	} | if script --version 2>&1 | grep -q util-linux; then
		script -qec "sh '$INSTALL' install --prefix '$_prefix'" /dev/null >"$T/out" 2>"$T/err"
	else
		script -q /dev/null sh "$INSTALL" install --prefix "$_prefix" >"$T/out" 2>"$T/err"
	fi
	if [ -e "$_prefix/bin/stackward" ]; then rc=0; else rc=1; fi
}

echo "== prompt answers"
P="$T/p9"
tty_ask "$P" t y
check "an unknown answer is asked again, then yes installs" ver_is "$P/bin/stackward" 0.0.2
check "the unknown answer is not taken as yes" out_has "Please answer y or n"
inst uninstall --prefix "$P" --yes
P="$T/p10"
tty_ask "$P" t x "?"
check "three unknown answers install nothing" gone "$P"
check "three unknown answers say so" out_has "no answer understood; nothing was changed"
P="$T/p11"
tty_ask "$P" n
check "n declines" gone "$P"
check "n says cancelled" out_has "install cancelled"
P="$T/p12"
tty_ask "$P" ""
check "Enter takes the default yes" ver_is "$P/bin/stackward" 0.0.2

if command -v wget >/dev/null 2>&1; then
	echo "== wget"
	P="$T/p8"
	STACKWARD_FETCHER=wget inst install --prefix "$P" --yes
	check "install through wget" ver_is "$P/bin/stackward" 0.0.2
fi

if [ "${STACKWARD_TEST_DEB:-}" = 1 ] && [ "$os" = linux ] && command -v apt-get >/dev/null 2>&1; then
	echo "== apt (disposable machine only)"
	sudo -n true || { echo "passwordless sudo is needed for the apt scenarios"; exit 1; }
	installed() { dpkg-query -W -f='${Version}' stackward 2>/dev/null; }
	check "no stackward package at the start" test -z "$(installed)"

	inst install --dry-run
	check "dry run exits 0" exit_is 0
	check "dry run mentions apt-get" out_has "apt-get install"
	check "dry run installs nothing" test -z "$(installed)"
	if [ "$(id -u)" != 0 ]; then
		inst install --no-sudo --yes
		check "--no-sudo fails for the package" exit_is 1
		check "--no-sudo installs nothing" test -z "$(installed)"
	fi
	inst install --version v0.0.3 --yes
	check "tampered package fails" exit_is 1
	check "tampered package installs nothing" test -z "$(installed)"
	check "tampered package leaves no binary" gone /usr/bin/stackward

	inst install --version v0.0.1 --yes
	check "install exits 0" exit_is 0
	check "install put version 0.0.1 in place" test "$(installed)" = 0.0.1
	check "the binary runs" ver_is /usr/bin/stackward 0.0.1
	check "apt did not print the _apt notice" sh -c "! grep -qi 'unsandboxed\\|couldn.t be accessed by user' '$(log_path)'"
	check "log has the apt output" grep -q "apt-get install" "$(log_path)"

	inst install --version v0.0.1 --yes
	check "re-install exits 0" exit_is 0
	check "re-install says already installed" out_has "already installed"

	inst update --yes
	check "update installs the newer release" test "$(installed)" = 0.0.2
	inst update --yes
	check "update when current is a no-op" out_has "up to date"
	check "package still 0.0.2" test "$(installed)" = 0.0.2

	inst uninstall --yes
	check "uninstall exits 0" exit_is 0
	check "uninstall removes the package" test -z "$(installed)"
	check "uninstall removes the binary" gone /usr/bin/stackward
	check "uninstall removes the doc folder" gone /usr/share/doc/stackward

	# the real one-liner shape: piped into sudo sh, as root
	# shellcheck disable=SC2024 # the redirect belongs to the test user on purpose
	curl -fsSL "$BASE/releases/latest/download/install.sh" | sudo env STACKWARD_BASE_URL="$BASE" sh >"$T/out" 2>"$T/err"
	rc=$?
	check "one-liner as root exits 0" exit_is 0
	check "one-liner installed the latest" test "$(installed)" = 0.0.2
	# shellcheck disable=SC2024 # same
	sudo env STACKWARD_BASE_URL="$BASE" sh "$INSTALL" uninstall --yes >"$T/out" 2>"$T/err"
	rc=$?
	check "root uninstall exits 0" exit_is 0
	check "root uninstall leaves nothing" test -z "$(installed)"
else
	echo "== apt scenarios skipped (set STACKWARD_TEST_DEB=1 on a disposable Linux machine)"
fi

if [ "$fails" -gt 0 ]; then
	echo "$fails scenario check(s) failed"
	exit 1
fi
echo "all install scenarios passed"
