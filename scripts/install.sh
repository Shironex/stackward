#!/bin/sh
# install.sh: guided install, update and uninstall of stackward. Read it before
# you run it; it only touches the stackward package or binary.
#
#   curl -fsSLO https://github.com/Shironex/stackward/releases/latest/download/install.sh
#   less install.sh
#   sudo sh install.sh
#
# The one-line form does the same without the reading step:
#
#   curl -fsSL https://github.com/Shironex/stackward/releases/latest/download/install.sh | sudo sh
#
# To pass options through the pipe: ... | sudo sh -s -- --version v0.1.0
#
# Commands:
#   install     (default) install the latest stable release, or --version
#   update      install only when the latest stable release is newer
#   uninstall   remove exactly what install added
#
# What install does, in five steps:
#   1. detects OS, CPU, apt, sudo or root, curl or wget, cosign
#   2. finds the release (the latest stable one unless you name a tag) and
#      stops here when that version is already installed
#   3. downloads the package or archive and checksums.txt over HTTPS
#   4. checks the SHA-256 against checksums.txt, and the cosign signature of
#      checksums.txt when cosign is installed (it says so when it is not)
#   5. Debian and Ubuntu: installs the .deb with apt, so `apt remove` works too.
#      Elsewhere, or with --prefix: copies the binary to PREFIX/bin and writes
#      PREFIX/share/stackward/install.json listing what it added.
#
# A failed check stops the run before anything is written. The script never
# runs stackward except `stackward version` once after install, to confirm.
# `uninstall` removes the package with apt, or the files listed in install.json
# and nothing else.
#
# Options:
#   --version vX.Y.Z  release tag (default: the latest stable release; a
#                     pre-release is only installed when named)
#   --prefix DIR      install the binary under DIR (DIR/bin/stackward) instead
#                     of using the .deb; default prefix is /usr/local
#   -y, --yes         do not ask questions (needed to uninstall without a TTY)
#   --no-sudo         fail instead of calling sudo when root is needed
#   --dry-run         print the steps and what would change; change nothing
#   -q, --quiet       plain output, only the result line and errors
#   -h, --help        show this help
#
# Output: numbered steps with a spinner on a terminal. Plain lines (no spinner,
# no colour, ASCII only) when stdout is not a terminal, NO_COLOR is set, TERM
# is dumb or --quiet is given. Every command's output goes to a log file whose
# path is printed.
#
# Environment:
#   STACKWARD_VERSION   same as --version; the flag wins
#   STACKWARD_BASE_URL  repository URL to download from (default below); for
#                       mirrors and tests. Signature identity checks always
#                       expect the official repository workflow.
#   STACKWARD_FETCHER   curl or wget; for tests (default: curl, else wget)

# The step functions are called by name through run_step.
# shellcheck disable=SC2317,SC2329
set -u

REPO="Shironex/stackward"
BASE_URL="${STACKWARD_BASE_URL:-https://github.com/$REPO}"
SIGNER_ISSUER="https://token.actions.githubusercontent.com"
DEFAULT_PREFIX="/usr/local"

CMD=""
VERSION_ARG="${STACKWARD_VERSION:-}"
PREFIX=""
PREFIX_SET=0
YES=0
NO_SUDO=0
DRY=0
QUIET=0

# ---------------------------------------------------------------- helpers

usage() {
	cat <<'EOF'
Usage: sh install.sh [install|update|uninstall] [options]

Options:
  --version vX.Y.Z  release tag (default: latest stable)
  --prefix DIR      install the binary under DIR/bin instead of using the .deb
  -y, --yes         do not ask questions
  --no-sudo         fail instead of calling sudo
  --dry-run         print what would change, change nothing
  -q, --quiet       plain output, only the result and errors
  -h, --help        this help

Read the header of the script for what each command does.
EOF
}

usage_err() {
	printf 'install.sh: %s\n\n' "$*" >&2
	usage >&2
	exit 2
}

LOG=/dev/null

log() { printf '%s\n' "$*" >>"$LOG"; }

# run CMD...: run a command with its output in the log; stdin is closed so
# nothing can swallow the script when it is piped into sh.
run() {
	log "+ $*"
	"$@" >>"$LOG" 2>&1 </dev/null
}

# priv CMD...: run as root (through sudo when we are not root).
priv() {
	if [ -n "$SUDO" ]; then
		run sudo "$@"
	else
		run "$@"
	fi
}

bad() {
	ERR_REASON=$*
	log "error: $*"
	return 1
}

pad() { # text width
	_pt=$1
	_pl=${#_pt}
	printf '%s' "$_pt"
	while [ "$_pl" -lt "$2" ]; do
		printf ' '
		_pl=$((_pl + 1))
	done
}

fmt_dur() {
	if [ "$1" -lt 1 ]; then printf '<1s'; else printf '%ss' "$1"; fi
}

# ---------------------------------------------------------------- UI

init_ui() {
	FANCY=0
	if [ "$QUIET" = 0 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
		FANCY=1
	fi
	UTF8=0
	case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
	*[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) UTF8=1 ;;
	esac
	GREEN="" RED="" DIM="" BOLD="" RESET="" CLR="" HIDE="" SHOW=""
	if [ "$FANCY" = 1 ]; then
		_esc=$(printf '\033')
		GREEN="${_esc}[32m"
		RED="${_esc}[31m"
		DIM="${_esc}[2m"
		BOLD="${_esc}[1m"
		RESET="${_esc}[0m"
		CLR="${_esc}[K"
		HIDE="${_esc}[?25l"
		SHOW="${_esc}[?25h"
	fi
	if [ "$UTF8" = 1 ]; then
		SPIN_FRAMES="⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏"
		MARK_OK="✓"
		MARK_FAIL="✗"
		MARK_SKIP="-"
	else
		SPIN_FRAMES="| / - \\"
		MARK_OK="+"
		MARK_FAIL="x"
		MARK_SKIP="-"
	fi
	INDENT=""
	[ "$FANCY" = 1 ] && INDENT="  "
	SPIN_PID=""
	STEP_N=0
	STEP_TOTAL=0
	STEP_TITLE=""
	STEP_NOTE=""
	ERR_REASON=""
	CHANGED=0
}

say() { [ "$QUIET" = 1 ] || printf '%s\n' "$*"; }

spin_start() {
	[ "$FANCY" = 1 ] || return 0
	printf '%s' "$HIDE"
	(
		while :; do
			for _f in $SPIN_FRAMES; do
				printf '\r%s  %s%s%s %s[%s/%s]%s %s' "$CLR" "$BOLD" "$_f" "$RESET" "$DIM" "$STEP_N" "$STEP_TOTAL" "$RESET" "$STEP_TITLE"
				sleep 0.1
			done
		done
	) &
	SPIN_PID=$!
}

spin_stop() {
	if [ -n "$SPIN_PID" ]; then
		kill "$SPIN_PID" 2>/dev/null
		wait "$SPIN_PID" 2>/dev/null
		SPIN_PID=""
		printf '\r%s%s' "$CLR" "$SHOW"
	fi
}

print_ok() { # seconds
	[ "$QUIET" = 1 ] && return 0
	_d=$(fmt_dur "$1")
	if [ "$FANCY" = 1 ]; then
		printf '  %s%s%s %s[%s/%s]%s %s %s %s%s%s\n' "$GREEN" "$MARK_OK" "$RESET" "$DIM" "$STEP_N" "$STEP_TOTAL" "$RESET" "$(pad "$STEP_TITLE" 18)" "$(pad "$_d" 5)" "$DIM" "$STEP_NOTE" "$RESET"
	else
		printf '[%s/%s] %s ... ok (%s)%s\n' "$STEP_N" "$STEP_TOTAL" "$STEP_TITLE" "$_d" "${STEP_NOTE:+ $STEP_NOTE}"
	fi
}

print_skip() { # title reason
	STEP_N=$((STEP_N + 1))
	[ "$QUIET" = 1 ] && return 0
	if [ "$FANCY" = 1 ]; then
		printf '  %s%s [%s/%s] %s %s %s%s%s\n' "$DIM" "$MARK_SKIP" "$STEP_N" "$STEP_TOTAL" "$(pad "$1" 18)" "$(pad "" 5)" "" "$2" "$RESET"
	else
		printf '[%s/%s] %s ... skipped (%s)\n' "$STEP_N" "$STEP_TOTAL" "$1" "$2"
	fi
}

error_block() {
	{
		if [ "$FANCY" = 1 ]; then
			printf '\n  %sError%s  %s\n  %sStep%s   %s (%s of %s)\n  %sLog%s    %s\n' "$RED" "$RESET" "$ERR_REASON" "$RED" "$RESET" "$STEP_TITLE" "$STEP_N" "$STEP_TOTAL" "$RED" "$RESET" "$LOG_SHOWN"
		else
			printf 'error: %s\nstep: %s (%s of %s)\nlog: %s\n' "$ERR_REASON" "$STEP_TITLE" "$STEP_N" "$STEP_TOTAL" "$LOG_SHOWN"
		fi
		if [ "$CHANGED" = 0 ]; then
			printf '%sNothing was changed on this system.\n' "$INDENT"
		else
			printf '%sThe system may be partly changed; the log lists what ran.\n' "$INDENT"
		fi
	} >&2
}

print_fail() { # seconds
	if [ "$FANCY" = 1 ]; then
		printf '  %s%s%s %s[%s/%s]%s %s %s\n' "$RED" "$MARK_FAIL" "$RESET" "$DIM" "$STEP_N" "$STEP_TOTAL" "$RESET" "$(pad "$STEP_TITLE" 18)" "$(pad "$(fmt_dur "$1")" 5)"
	elif [ "$QUIET" = 0 ]; then
		printf '[%s/%s] %s ... FAILED (%s)\n' "$STEP_N" "$STEP_TOTAL" "$STEP_TITLE" "$(fmt_dur "$1")"
	fi
	error_block
}

run_step() { # title function
	STEP_N=$((STEP_N + 1))
	STEP_TITLE=$1
	STEP_NOTE=""
	ERR_REASON=""
	_t0=$(date +%s)
	log "== step $STEP_N/$STEP_TOTAL: $STEP_TITLE"
	spin_start
	"$2"
	_rc=$?
	spin_stop
	_dur=$(($(date +%s) - _t0))
	if [ "$_rc" -eq 0 ]; then
		print_ok "$_dur"
	else
		print_fail "$_dur"
		exit 1
	fi
}

# fail_now REASON: stop outside a step function (counts as the current step).
fail_now() {
	ERR_REASON=$*
	log "error: $*"
	print_fail 0
	exit 1
}

header() {
	if [ "$QUIET" = 1 ]; then return 0; fi
	if [ "$FANCY" = 1 ]; then
		printf '\n  %sstackward installer%s %s%s%s\n' "$BOLD" "$RESET" "$DIM" "$CMD" "$RESET"
		printf '  %slog: %s%s\n\n' "$DIM" "$LOG_SHOWN" "$RESET"
	else
		printf 'stackward installer: %s\n' "$CMD"
		printf 'log: %s\n' "$LOG_SHOWN"
	fi
}

# sum_add LINE: add a line to the summary.
SUM=""
sum_add() {
	SUM="${SUM}${1}
"
}

# summary_print COLOUR: the closing box (plain lines when not fancy).
summary_print() {
	[ "$QUIET" = 1 ] && return 0
	if [ "$FANCY" != 1 ]; then
		printf '\n%s' "$SUM"
		return 0
	fi
	SUM=${SUM%"
"}
	_w=0
	while IFS= read -r _l; do
		[ "${#_l}" -gt "$_w" ] && _w=${#_l}
	done <<EOF
$SUM
EOF
	_cols=${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}
	case $_cols in *[!0-9]* | "") _cols=80 ;; esac
	if [ $((_w + 6)) -gt "$_cols" ]; then
		# Too wide for a box (long paths): the same lines without borders.
		printf '\n'
		_first=1
		while IFS= read -r _l; do
			if [ "$_first" = 1 ]; then
				printf '  %s%s%s%s\n' "$BOLD" "$1" "$_l" "$RESET"
				_first=0
			else
				printf '  %s\n' "$_l"
			fi
		done <<EOF
$SUM
EOF
		printf '\n'
		return 0
	fi
	_hr=""
	_i=0
	while [ "$_i" -lt $((_w + 2)) ]; do
		_hr="${_hr}─"
		_i=$((_i + 1))
	done
	printf '\n  %s╭%s╮%s\n' "$DIM" "$_hr" "$RESET"
	_first=1
	while IFS= read -r _l; do
		if [ "$_first" = 1 ]; then
			printf '  %s│%s %s%s%s%s %s│%s\n' "$DIM" "$RESET" "$BOLD" "$1" "$(pad "$_l" "$_w")" "$RESET" "$DIM" "$RESET"
			_first=0
		else
			printf '  %s│%s %s %s│%s\n' "$DIM" "$RESET" "$(pad "$_l" "$_w")" "$DIM" "$RESET"
		fi
	done <<EOF
$SUM
EOF
	printf '  %s╰%s╯%s\n\n' "$DIM" "$_hr" "$RESET"
}

cleanup() {
	spin_stop
	[ -n "${FANCY:-}" ] && [ "$FANCY" = 1 ] && printf '%s' "$SHOW"
	if [ -n "${WORK:-}" ]; then rm -rf "$WORK"; fi
}

# ---------------------------------------------------------------- logic

# vercmp A B: print -1, 0 or 1 (semantic versions, pre-releases sort first).
vercmp() {
	awk -v a="$1" -v b="$2" '
	function split_ver(v, arr,   i) {
		i = index(v, "-")
		if (i) { arr["core"] = substr(v, 1, i - 1); arr["pre"] = substr(v, i + 1) }
		else { arr["core"] = v; arr["pre"] = "" }
	}
	BEGIN {
		split_ver(a, x); split_ver(b, y)
		n = split(x["core"], p, "."); m = split(y["core"], q, ".")
		k = (n > m) ? n : m
		for (i = 1; i <= k; i++) {
			if (p[i] + 0 < q[i] + 0) { print -1; exit }
			if (p[i] + 0 > q[i] + 0) { print 1; exit }
		}
		if (x["pre"] == y["pre"]) { print 0; exit }
		if (x["pre"] == "") { print 1; exit }
		if (y["pre"] == "") { print -1; exit }
		n = split(x["pre"], p, "."); m = split(y["pre"], q, ".")
		k = (n > m) ? n : m
		for (i = 1; i <= k; i++) {
			if (i > n) { print -1; exit }
			if (i > m) { print 1; exit }
			pn = (p[i] ~ /^[0-9]+$/); qn = (q[i] ~ /^[0-9]+$/)
			if (pn && qn) {
				if (p[i] + 0 < q[i] + 0) { print -1; exit }
				if (p[i] + 0 > q[i] + 0) { print 1; exit }
			} else if (pn) { print -1; exit }
			else if (qn) { print 1; exit }
			else {
				if (p[i] < q[i]) { print -1; exit }
				if (p[i] > q[i]) { print 1; exit }
			}
		}
		print 0
	}'
}

fetch() { # url dest
	log "+ fetch $1"
	if [ "$FETCHER" = curl ]; then
		curl -fsSL -o "$2" "$1" >>"$LOG" 2>&1 </dev/null
	else
		wget -q -O "$2" "$1" >>"$LOG" 2>&1 </dev/null
	fi
}

# final_url URL: print the URL after redirects.
final_url() {
	log "+ resolve $1"
	if [ "$FETCHER" = curl ]; then
		curl -fsSL -o /dev/null -w '%{url_effective}' "$1" 2>>"$LOG" </dev/null
	else
		wget -S -O /dev/null "$1" 2>&1 </dev/null | awk 'tolower($1) == "location:" { l = $2 } END { print l }'
	fi
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d ' ' -f 1
	else
		shasum -a 256 "$1" | cut -d ' ' -f 1
	fi
}

# nearest_writable DIR: succeed when DIR (or its nearest existing parent) is
# writable by the current user.
nearest_writable() {
	_a=$1
	while [ ! -e "$_a" ]; do _a=$(dirname "$_a"); done
	[ -w "$_a" ]
}

# state_get KEY: a string value from the install record.
state_get() {
	sed -n 's/^  "'"$1"'": "\(.*\)",\{0,1\}$/\1/p' "$STATE" | head -n 1
}

# state_list KEY: the entries of an array in the install record.
state_list() {
	awk -v k="\"$1\"" '
	index($0, "  " k ": [") == 1 { f = 1; next }
	f && /^  \]/ { f = 0 }
	f { s = $0; sub(/^    "/, "", s); sub(/",?$/, "", s); print s }' "$STATE"
}

# detect_installed: DEB_VER (apt package), BIN_VER (install record), UNMANAGED.
detect_installed() {
	DEB_VER=""
	BIN_VER=""
	UNMANAGED=0
	if command -v dpkg-query >/dev/null 2>&1; then
		# shellcheck disable=SC2016
		_st=$(dpkg-query -W -f='${db:Status-Abbrev}|${Version}' stackward 2>/dev/null) || _st=""
		case $_st in
		ii*) DEB_VER=$(printf '%s' "${_st#*|}" | tr '~' '-') ;;
		esac
	fi
	if [ -f "$STATE" ] && [ "$(state_get method)" = binary ]; then
		_sbin=$(state_get binary)
		if [ -n "$_sbin" ] && [ -f "$_sbin" ]; then BIN_VER=$(state_get version); fi
	fi
	if [ "$METHOD" = deb ]; then
		CUR=$DEB_VER
	else
		CUR=$BIN_VER
	fi
	if [ -z "$CUR" ] && [ -e "$BIN" ]; then UNMANAGED=1; fi
}

# setup_priv NEEDS_ROOT: choose sudo, or fail when root is needed and absent.
setup_priv() {
	SUDO=""
	[ "$1" = 1 ] || return 0
	[ "$(id -u)" = 0 ] && return 0
	if [ "$NO_SUDO" = 1 ]; then
		bad "root is needed and --no-sudo was given; re-run as root (sudo sh install.sh) or pick a writable --prefix"
		return 1
	fi
	if command -v sudo >/dev/null 2>&1; then
		SUDO=sudo
		return 0
	fi
	bad "root is needed but sudo is not installed; re-run as root or pick a writable --prefix"
	return 1
}

# ensure_sudo: ask for the sudo password up front, outside any spinner.
ensure_sudo() {
	[ -n "$SUDO" ] && [ "$DRY" = 0 ] || return 0
	sudo -n true >/dev/null 2>&1 </dev/null && return 0
	STEP_TITLE="Checking privileges"
	if [ -t 0 ]; then
		say "${INDENT}sudo needs your password to continue."
		sudo -v || fail_now "sudo did not authenticate"
	else
		fail_now "sudo needs a password but this run is not interactive; run as root (sudo sh install.sh)"
	fi
}

# confirm QUESTION DEFAULT(y|n): ask until the answer is understood, at most
# three times. Enter takes the default; y, yes mean yes; n, no mean no.
# Anything else asks again, then cancels without changing anything.
confirm() {
	[ "$YES" = 1 ] || [ "$DRY" = 1 ] && return 0
	[ -t 0 ] || return 0
	if [ "$2" = y ]; then _hint="[Y/n]"; else _hint="[y/N]"; fi
	_tries=0
	while [ "$_tries" -lt 3 ]; do
		printf '  %s %s ' "$1" "$_hint"
		read -r _ans || _ans=""
		_ans=$(printf '%s' "$_ans" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
		case $_ans in
		y | yes) return 0 ;;
		n | no) return 1 ;;
		"")
			[ "$2" = y ]
			return
			;;
		esac
		_tries=$((_tries + 1))
		[ "$_tries" -ge 3 ] || printf '  Please answer y or n.\n'
	done
	fail_now "no answer understood; nothing was changed"
}

mkdir_record() { # dir: make it (and parents), remembering what we created
	_todo=""
	_d=$1
	while [ ! -d "$_d" ]; do
		_todo="$_d
$_todo"
		_d=$(dirname "$_d")
	done
	[ -n "$_todo" ] || return 0
	priv mkdir -p "$1" || return 1
	CREATED_DIRS="${CREATED_DIRS}${_todo}"
}

write_state() {
	_tmp="$WORK/install.json"
	{
		printf '{\n  "schema": 1,\n  "version": "%s",\n  "method": "binary",\n  "prefix": "%s",\n  "binary": "%s",\n' "$VER" "$PREFIX" "$BIN"
		printf '  "files": [\n    "%s",\n    "%s"\n  ],\n' "$BIN" "$STATE"
		printf '  "dirs": [\n'
		printf '%s' "$CREATED_DIRS" | awk 'NF { l[++n] = $0 } END { for (i = 1; i <= n; i++) printf "    \"%s\"%s\n", l[i], (i < n ? "," : "") }'
		printf '  ]\n}\n'
	} >"$_tmp" || return 1
	chmod 644 "$_tmp"
	priv cp "$_tmp" "$STATE"
}

# ---------------------------------------------------------------- steps

step_detect() {
	case "$(uname -s)" in
	Linux) OS=linux ;;
	Darwin) OS=darwin ;;
	*)
		bad "unsupported OS $(uname -s); download an archive from $BASE_URL/releases by hand"
		return 1
		;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	*)
		bad "unsupported CPU $(uname -m)"
		return 1
		;;
	esac

	DISTRO=""
	LIKE=""
	if [ "$OS" = linux ] && [ -r /etc/os-release ]; then
		# shellcheck disable=SC1091
		DISTRO=$(. /etc/os-release 2>/dev/null; printf '%s %s' "${ID:-linux}" "${VERSION_ID:-}")
		# shellcheck disable=SC1091
		LIKE=$(. /etc/os-release 2>/dev/null; printf '%s %s' "${ID:-}" "${ID_LIKE:-}")
	fi
	[ -n "$DISTRO" ] || DISTRO=$OS

	METHOD=binary
	if [ "$PREFIX_SET" = 0 ] && [ "$OS" = linux ] && command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
		case " $LIKE " in
		*" debian "* | *" ubuntu "*) METHOD=deb ;;
		esac
	fi
	[ -n "$PREFIX" ] || PREFIX=$DEFAULT_PREFIX
	if [ "$METHOD" = deb ]; then BIN=/usr/bin/stackward; else BIN="$PREFIX/bin/stackward"; fi
	STATE="$PREFIX/share/stackward/install.json"

	if command -v curl >/dev/null 2>&1 && [ "${STACKWARD_FETCHER:-curl}" = curl ]; then
		FETCHER=curl
	elif command -v wget >/dev/null 2>&1 && [ "${STACKWARD_FETCHER:-wget}" = wget ]; then
		FETCHER=wget
	else
		bad "curl or wget is required"
		return 1
	fi
	command -v tar >/dev/null 2>&1 || { bad "tar is required"; return 1; }
	if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
		bad "sha256sum or shasum is required to verify the download"
		return 1
	fi
	COSIGN=0
	if command -v cosign >/dev/null 2>&1; then COSIGN=1; fi

	if [ "$CMD" != uninstall ]; then
		_need=0
		if [ "$METHOD" = deb ]; then
			_need=1
		elif ! nearest_writable "$PREFIX/bin" || ! nearest_writable "$PREFIX/share/stackward"; then
			_need=1
		fi
		setup_priv "$_need" || return 1
	fi
	detect_installed

	_who=root
	if [ "$(id -u)" != 0 ]; then _who=${SUDO:-user}; fi
	_via=apt
	[ "$METHOD" = deb ] || _via="binary install"
	_cos="cosign: no"
	[ "$COSIGN" = 0 ] || _cos="cosign: yes"
	STEP_NOTE="$DISTRO $ARCH, $_via, $_who, $FETCHER, $_cos"
	log "os=$OS arch=$ARCH method=$METHOD prefix=$PREFIX sudo=$SUDO fetcher=$FETCHER cosign=$COSIGN current=$CUR unmanaged=$UNMANAGED"
}

step_release() {
	TAG=$VERSION_ARG
	if [ -z "$TAG" ]; then
		_final=$(final_url "$BASE_URL/releases/latest") || _final=""
		TAG=${_final##*/}
		case "$TAG" in
		v[0-9]*) ;;
		*)
			bad "could not find a stable release at $BASE_URL/releases/latest; if only pre-releases exist, name a tag with --version v0.1.0"
			return 1
			;;
		esac
	fi
	VER=${TAG#v}
	ASSET_URL="$BASE_URL/releases/download/$TAG"
	if [ "$METHOD" = deb ]; then
		ASSET="stackward_${VER}_${ARCH}.deb"
	else
		ASSET="stackward_${VER}_${OS}_${ARCH}.tar.gz"
	fi

	DECISION=install
	if [ "$UNMANAGED" = 1 ]; then
		bad "$BIN exists but this installer did not put it there (for example get.sh); remove it first or choose another --prefix"
		return 1
	fi
	if [ -n "$CUR" ]; then
		_c=$(vercmp "$VER" "$CUR")
		if [ "$CMD" = update ]; then
			if [ "$_c" -le 0 ]; then
				DECISION=noop
				STEP_NOTE="$TAG, installed $CUR: up to date"
			else
				STEP_NOTE="$TAG, installed $CUR: update"
			fi
		elif [ "$_c" = 0 ]; then
			DECISION=noop
			STEP_NOTE="$TAG, installed $CUR: already installed"
		elif [ "$_c" -gt 0 ]; then
			STEP_NOTE="$TAG, installed $CUR: upgrade"
		else
			STEP_NOTE="$TAG, installed $CUR: downgrade"
		fi
	else
		if [ "$CMD" = update ]; then
			bad "stackward is not installed (no apt package and no install record in $PREFIX); run install first"
			return 1
		fi
		STEP_NOTE="$TAG"
	fi
}

step_download() {
	if [ "$DRY" = 1 ]; then
		STEP_NOTE="would download $ASSET and checksums.txt from $ASSET_URL"
		return 0
	fi
	WORK=$(mktemp -d "${TMPDIR:-/tmp}/stackward-install.XXXXXX") || { bad "could not create a temp directory"; return 1; }
	# Readable by everyone so apt's _apt user can read the .deb and does not
	# print its "unsandboxed" notice.
	chmod 755 "$WORK"
	fetch "$ASSET_URL/$ASSET" "$WORK/$ASSET" || { bad "download failed: $ASSET_URL/$ASSET"; return 1; }
	chmod 644 "$WORK/$ASSET"
	fetch "$ASSET_URL/checksums.txt" "$WORK/checksums.txt" || { bad "download failed: $ASSET_URL/checksums.txt"; return 1; }
	if [ "$COSIGN" = 1 ]; then
		fetch "$ASSET_URL/checksums.txt.sigstore.json" "$WORK/checksums.txt.sigstore.json" ||
			{ bad "download failed: $ASSET_URL/checksums.txt.sigstore.json"; return 1; }
	fi
	STEP_NOTE="$ASSET"
}

step_verify() {
	if [ "$DRY" = 1 ]; then
		STEP_NOTE="would check SHA-256 against checksums.txt"
		[ "$COSIGN" = 0 ] || STEP_NOTE="$STEP_NOTE and the cosign signature"
		return 0
	fi
	_actual=$(sha256_of "$WORK/$ASSET")
	_expected=$(awk -v f="$ASSET" '$2 == f || $2 == "*" f { print $1; exit }' "$WORK/checksums.txt")
	[ -n "$_expected" ] || { bad "$ASSET is not listed in checksums.txt; nothing was installed"; return 1; }
	if [ "$_actual" != "$_expected" ]; then
		bad "SHA-256 mismatch for $ASSET (expected $_expected, got $_actual); nothing was installed"
		return 1
	fi
	CHECKS="sha256 ok"
	if [ "$COSIGN" = 1 ]; then
		run cosign verify-blob \
			--bundle "$WORK/checksums.txt.sigstore.json" \
			--certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG" \
			--certificate-oidc-issuer "$SIGNER_ISSUER" \
			"$WORK/checksums.txt" ||
			{ bad "cosign could not verify the signature of checksums.txt; nothing was installed"; return 1; }
		CHECKS="sha256 ok, cosign signature ok"
		STEP_NOTE="sha256 ok, cosign signature ok"
	else
		CHECKS="sha256 ok, signature NOT checked (cosign is not installed)"
		STEP_NOTE="sha256 ok; cosign not installed, signature NOT checked"
	fi
}

confirm_version() { # path: run `stackward version` once and compare
	VERSION_LINE=$("$1" version 2>>"$LOG" </dev/null | head -n 1) || VERSION_LINE=""
	log "stackward version: $VERSION_LINE"
	case "$VERSION_LINE" in
	*"$VER"*) return 0 ;;
	esac
	bad "installed $1 but 'stackward version' did not report $VER (got: ${VERSION_LINE:-nothing})"
	return 1
}

step_install() {
	if [ "$METHOD" = deb ]; then
		if [ "$DRY" = 1 ]; then
			STEP_NOTE="would run: ${SUDO:+sudo }apt-get install -y --allow-downgrades <downloaded .deb>"
			return 0
		fi
		CHANGED=1
		priv env DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "$WORK/$ASSET" ||
			{ bad "apt-get could not install $ASSET"; return 1; }
		confirm_version /usr/bin/stackward || return 1
		STEP_NOTE="apt installed stackward $VER"
		return 0
	fi

	if [ "$DRY" = 1 ]; then
		STEP_NOTE="would copy stackward to $BIN and write $STATE"
		return 0
	fi
	mkdir -p "$WORK/x"
	run tar -xzf "$WORK/$ASSET" -C "$WORK/x" stackward || { bad "the archive does not contain a stackward file"; return 1; }
	if [ ! -f "$WORK/x/stackward" ] || [ -L "$WORK/x/stackward" ]; then
		bad "unexpected archive content"
		return 1
	fi
	CREATED_DIRS=""
	if [ -f "$STATE" ]; then CREATED_DIRS=$(state_list dirs | awk 'NF { printf "%s\n", $0 }'); fi
	[ -z "$CREATED_DIRS" ] || CREATED_DIRS="$CREATED_DIRS
"
	CHANGED=1
	mkdir_record "$PREFIX/bin" || { bad "cannot create $PREFIX/bin"; return 1; }
	mkdir_record "$PREFIX/share/stackward" || { bad "cannot create $PREFIX/share/stackward"; return 1; }
	_new="$PREFIX/bin/.stackward.new.$$"
	priv cp "$WORK/x/stackward" "$_new" || { bad "cannot write to $PREFIX/bin"; return 1; }
	priv chmod 755 "$_new" || return 1
	priv mv -f "$_new" "$BIN" || { bad "cannot move the binary into $PREFIX/bin"; return 1; }
	write_state || { bad "could not write $STATE"; return 1; }
	confirm_version "$BIN" || return 1
	STEP_NOTE="copied to $BIN"
}

step_check_installed() { # uninstall: what is there to remove
	TO_REMOVE=""
	NEED=0
	if [ -n "$DEB_VER" ]; then
		TO_REMOVE="deb"
		NEED=1
	fi
	if [ -n "$BIN_VER" ]; then
		TO_REMOVE="$TO_REMOVE bin"
		_sprefix=$(state_get prefix)
		case $_sprefix in
		/?*) ;;
		*)
			bad "the install record $STATE has no usable prefix; it was not touched"
			return 1
			;;
		esac
		if ! state_list files | awk -v p="$_sprefix/" 'index($0, p) != 1 { bad = 1 } END { exit bad }'; then
			bad "the install record lists files outside $_sprefix; nothing was removed"
			return 1
		fi
		_sbin=$(state_get binary)
		nearest_writable "$_sprefix" && [ -w "$(dirname "$_sbin")" ] || NEED=1
	fi
	if [ -z "$TO_REMOVE" ]; then
		DECISION=noop
		if [ -e "$BIN" ]; then
			STEP_NOTE="nothing to remove ($BIN was not installed by this script and is left alone)"
		else
			STEP_NOTE="nothing to remove"
		fi
		return 0
	fi
	DECISION=remove
	setup_priv "$NEED" || return 1
	STEP_NOTE=""
	case $TO_REMOVE in *deb*) STEP_NOTE="apt package stackward $DEB_VER" ;; esac
	case $TO_REMOVE in *bin*) STEP_NOTE="${STEP_NOTE:+$STEP_NOTE, }binary $BIN $BIN_VER" ;; esac
}

step_remove() {
	if [ "$DRY" = 1 ]; then
		case $TO_REMOVE in *deb*) STEP_NOTE="would run: ${SUDO:+sudo }apt-get remove -y stackward" ;; esac
		case $TO_REMOVE in *bin*) STEP_NOTE="${STEP_NOTE:+$STEP_NOTE; }would remove the files listed in $STATE" ;; esac
		return 0
	fi
	CHANGED=1
	REMOVED=""
	case $TO_REMOVE in
	*deb*)
		priv env DEBIAN_FRONTEND=noninteractive apt-get remove -y stackward || { bad "apt-get could not remove stackward"; return 1; }
		REMOVED="apt package stackward"
		;;
	esac
	case $TO_REMOVE in
	*bin*)
		_sprefix=$(state_get prefix)
		_files=$(state_list files)
		_dirs=$(state_list dirs | awk '{ l[NR] = $0 } END { for (i = NR; i >= 1; i--) print l[i] }')
		_oldifs=$IFS
		IFS='
'
		for _f in $_files; do
			case $_f in
			"$_sprefix"/*) ;;
			*) IFS=$_oldifs; bad "refusing to remove $_f"; return 1 ;;
			esac
			[ "$_f" = "$STATE" ] && continue
			priv rm -f "$_f" || { IFS=$_oldifs; bad "could not remove $_f"; return 1; }
			REMOVED="${REMOVED:+$REMOVED, }$_f"
		done
		priv rm -f "$STATE" || { IFS=$_oldifs; bad "could not remove $STATE"; return 1; }
		REMOVED="${REMOVED:+$REMOVED, }$STATE"
		for _d in $_dirs; do
			case $_d in
			"$_sprefix"/* | "$_sprefix") ;;
			*) continue ;;
			esac
			priv rmdir "$_d" 2>/dev/null
		done
		IFS=$_oldifs
		;;
	esac
	STEP_NOTE="removed"
}

# ---------------------------------------------------------------- main

while [ $# -gt 0 ]; do
	case $1 in
	install | update | uninstall)
		[ -z "$CMD" ] || usage_err "only one command allowed ($CMD and $1)"
		CMD=$1
		;;
	--version)
		[ $# -ge 2 ] || usage_err "--version needs a value"
		VERSION_ARG=$2
		shift
		;;
	--version=*) VERSION_ARG=${1#--version=} ;;
	--prefix)
		[ $# -ge 2 ] || usage_err "--prefix needs a directory"
		PREFIX=$2
		PREFIX_SET=1
		shift
		;;
	--prefix=*)
		PREFIX=${1#--prefix=}
		PREFIX_SET=1
		;;
	-y | --yes) YES=1 ;;
	--no-sudo) NO_SUDO=1 ;;
	--dry-run) DRY=1 ;;
	-q | --quiet) QUIET=1 ;;
	-h | --help)
		usage
		exit 0
		;;
	*) usage_err "unknown argument '$1'" ;;
	esac
	shift
done
[ -n "$CMD" ] || CMD=install

if [ -n "$VERSION_ARG" ]; then
	case "$VERSION_ARG" in
	[0-9]*) VERSION_ARG="v$VERSION_ARG" ;;
	esac
	case "$VERSION_ARG" in
	v[0-9]*) ;;
	*) usage_err "version must be a tag like v0.1.0, got '$VERSION_ARG'" ;;
	esac
	case "$VERSION_ARG" in
	*[!0-9A-Za-z._-]*) usage_err "version contains unexpected characters" ;;
	esac
fi
if [ "$PREFIX_SET" = 1 ]; then
	case "$PREFIX" in
	/*) ;;
	*) usage_err "--prefix must be an absolute path, got '$PREFIX'" ;;
	esac
	while [ "${#PREFIX}" -gt 1 ] && [ "${PREFIX%/}" != "$PREFIX" ]; do PREFIX=${PREFIX%/}; done
	[ "$PREFIX" != / ] || usage_err "--prefix cannot be /"
	case "$PREFIX" in
	*[\"\\]* | *'
'*) usage_err "--prefix contains a quote, backslash or newline" ;;
	esac
fi
SUDO=""
WORK=""

init_ui
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

if [ "$DRY" = 1 ]; then
	LOG_SHOWN="none (dry run)"
else
	LOG=$(mktemp "${TMPDIR:-/tmp}/stackward-install.XXXXXX") || { printf 'install.sh: error: cannot create a log file\n' >&2; exit 1; }
	LOG_SHOWN=$LOG
fi
log "install.sh $CMD version=${VERSION_ARG:-latest} prefix=${PREFIX:-default} yes=$YES no_sudo=$NO_SUDO dry=$DRY"

header
[ "$DRY" = 0 ] || say "${INDENT}dry run: nothing will be changed"

case $CMD in
uninstall)
	STEP_TOTAL=3
	run_step "Detecting system" step_detect
	run_step "Checking install" step_check_installed
	if [ "$DECISION" = noop ]; then
		print_skip "Removing" "nothing to remove"
		sum_add "Nothing to remove"
		sum_add ""
		sum_add "Log   $LOG_SHOWN"
		summary_print "$GREEN"
		[ "$QUIET" = 0 ] || printf 'nothing to remove\n'
		exit 0
	fi
	if [ "$YES" = 0 ] && [ "$DRY" = 0 ] && [ ! -t 0 ]; then
		fail_now "refusing to uninstall without a terminal to ask; pass --yes to confirm"
	fi
	confirm "Remove stackward ($STEP_NOTE)?" n || fail_now "uninstall cancelled"
	ensure_sudo
	run_step "Removing" step_remove
	if [ "$DRY" = 1 ]; then
		sum_add "Dry run: nothing was changed"
		sum_add ""
		sum_add "Would    remove: $STEP_NOTE"
	else
		sum_add "stackward removed"
		sum_add ""
		sum_add "Removed  $REMOVED"
		sum_add ""
		sum_add 'Your shell may remember the old path:'
		sum_add "run \`hash -r\` (bash) or open a new shell."
	fi
	sum_add "Log      $LOG_SHOWN"
	summary_print "$GREEN"
	[ "$QUIET" = 0 ] || printf 'stackward removed\n'
	;;
*)
	STEP_TOTAL=5
	run_step "Detecting system" step_detect
	run_step "Finding release" step_release
	if [ "$DECISION" = noop ]; then
		print_skip "Downloading" "not needed"
		print_skip "Verifying" "not needed"
		print_skip "Installing" "not needed"
		if [ "$CMD" = update ]; then
			sum_add "stackward $CUR is up to date"
		else
			sum_add "stackward $CUR is already installed"
		fi
		sum_add ""
		sum_add "Binary   $BIN"
		sum_add "Log      $LOG_SHOWN"
		summary_print "$GREEN"
		if [ "$QUIET" = 1 ]; then printf 'stackward %s is already installed (%s)\n' "$CUR" "$BIN"; fi
		exit 0
	fi
	if [ "$METHOD" = deb ]; then _what="the .deb with apt"; else _what="the binary to $BIN"; fi
	confirm "Install stackward $TAG ($_what)?" y || fail_now "install cancelled"
	ensure_sudo
	CHECKS=""
	run_step "Downloading" step_download
	run_step "Verifying" step_verify
	run_step "Installing" step_install

	_audit="stackward"
	[ "$METHOD" = deb ] || case ":$PATH:" in *":$PREFIX/bin:"*) ;; *) _audit=$BIN ;; esac
	if [ "$DRY" = 1 ]; then
		sum_add "Dry run: nothing was changed"
		sum_add ""
		sum_add "Would    install stackward $VER ($METHOD)"
		sum_add "Binary   $BIN"
	else
		sum_add "stackward $VER installed"
		sum_add ""
		if [ "$METHOD" = deb ]; then
			sum_add "Package  stackward $VER ($ASSET, apt)"
		else
			sum_add "Record   $STATE"
		fi
		sum_add "Binary   $BIN"
		sum_add "Version  $VERSION_LINE"
		sum_add "Checks   $CHECKS"
	fi
	sum_add "Log      $LOG_SHOWN"
	if [ "$DRY" = 0 ]; then
		sum_add ""
		sum_add "Next"
		sum_add "  sudo $_audit audit"
		# plan (and apply) came with 0.2; 0.1 only audits.
		if [ "$(vercmp "$VER" 0.2.0-0)" -ge 0 ]; then sum_add "  sudo $_audit plan"; fi
		sum_add "  sudo $_audit tui"
	fi
	summary_print "$GREEN"
	if [ "$QUIET" = 1 ] && [ "$DRY" = 0 ]; then printf 'stackward %s installed (%s)\n' "$VER" "$BIN"; fi
	;;
esac
exit 0
