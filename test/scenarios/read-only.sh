# shellcheck shell=bash
# read-only: the audit writes nothing but the report it was asked for.
#
# The host gets real state first (the bad-docker containers and UFW active,
# so the Docker, firewall and UFW code paths all run). Then:
#
# 1. A snapshot of everything the audit could plausibly write (snapshot.sh)
#    is taken before and after two audits, one with the sandbox and one
#    with --no-sandbox; any difference fails.
# 2. Both audits run under strace, following every child process. Any
#    open with a write flag (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND,
#    O_TMPFILE) outside the --out file and /dev/null, and any call that
#    creates, removes, renames or changes the mode, owner or times of a
#    file, fails, whether it succeeded or the sandbox refused it. The
#    --no-sandbox run matters most: it is what happens on kernels without
#    Landlock, where nothing else stops a write.
#
# strace works under sudo with Landlock: the tracer is not sandboxed, and a
# sandboxed tracee may be traced by a less restricted tracer. strace writes
# its own output file, outside the sandboxed process.

# shellcheck source=test/scenarios/bad-docker.sh
. "$SCENARIOS_DIR/bad-docker.sh"
# shellcheck source=test/scenarios/ufw.sh
. "$SCENARIOS_DIR/ufw.sh"

# Syscalls that create, remove, rename or change a file. open, openat and
# openat2 are filtered by their flags below.
WRITE_SYSCALLS="creat,truncate,ftruncate,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,link,linkat,symlink,symlinkat,mknod,mknodat,chmod,fchmod,fchmodat,chown,fchown,lchown,fchownat,utimes,utimensat,futimesat"

scenario_setup() {
	require_docker
	if ! command -v strace >/dev/null; then
		sudo apt-get install -y -qq strace >/dev/null 2>&1 ||
			{ sudo apt-get update -qq && sudo apt-get install -y -qq strace >/dev/null; }
	fi
	bad_docker_up
	ufw_up >/dev/null
	# Let container start up writes (redis, dockerd) settle before the
	# first snapshot.
	sleep 5
}

# traced_audit NAME [ARGS...]: run the audit as root under strace with
# --out, and leave the trace next to the report.
traced_audit() {
	local name="$1"
	shift
	local report="$OUT/$name.json" trace="$OUT/$name.strace" code=0
	rm -f "$report" "$trace"
	log "strace stackward audit --json --out $report $*"
	sudo strace -f -qq -y -s 256 -o "$trace" \
		-e trace=execve,open,openat,openat2,"$WRITE_SYSCALLS" \
		"$STACKWARD" audit --json --out "$report" "$@" || code=$?
	sudo chown "$(id -u):$(id -g)" "$report" "$trace"
	check_exit "$name" "$code"
	check_trace "$name" "$trace" "$report"
	REPORT="$report"
}

# TRANSIENT_TEMP is the one write the read-only check tolerates, and only
# from apt-get: apt 2.4 (Ubuntu 22.04) splits each signed InRelease file
# into an unnamed O_TMPFILE or a /tmp/clearsigned.message.* file it removes
# at once, even when its caches are current. Under the sandbox the attempt
# is refused and apt carries on with the same answer (the updates
# collector stays ok, and the sandboxed and unsandboxed reports agree);
# without the sandbox it is a short lived file in /tmp. apt 2.7 (Ubuntu
# 24.04) does not do it. docs/safety.md lists it with the command.
TRANSIENT_TEMP='^\[[^]]*apt-get[^]]*\] (openat\(AT_FDCWD<[^>]*>, "/tmp", O_RDWR\|O_EXCL\|O_CLOEXEC\|O_TMPFILE|openat\(AT_FDCWD<[^>]*>, "/tmp/clearsigned\.message\.[A-Za-z0-9]+", O_RDWR\|O_CREAT\|O_EXCL|unlink\("/tmp/clearsigned\.message\.[A-Za-z0-9]+"\))'

# check_trace NAME TRACE REPORT: fail on write attempts outside REPORT.
check_trace() {
	local name="$1" trace="$2" report="$3"
	local raw="$OUT/$name.writes.raw" all="$OUT/$name.writes.all" bad="$OUT/$name.writes.txt"
	# Write opens, minus the report and /dev/null; then every other write
	# syscall. -y prints paths in angle brackets for file descriptors.
	{
		grep -E '^[0-9]+ +open(at|at2)?\(' "$trace" |
			grep -E 'O_(WRONLY|RDWR|CREAT|TRUNC|APPEND|TMPFILE)' |
			grep -vF "\"$report\"" | grep -vF '"/dev/null"' || true
		grep -E "^[0-9]+ +($(echo "$WRITE_SYSCALLS" | tr , '|'))\(" "$trace" |
			grep -vF "<$report>" || true
	} >"$raw"
	# Name the program behind each pid from its execve: [argv] syscall.
	local pid line cmd
	while IFS= read -r line; do
		pid="${line%% *}"
		cmd="$(grep -E "^$pid +execve\(" "$trace" | tail -1 | sed -E 's/^[0-9]+ +execve\("[^"]*", \[([^]]*)\].*/\1/')"
		printf '[%s] %s\n' "${cmd:-stackward}" "${line#* }" | sed -E 's/ {2,}/ /'
	done <"$raw" >"$all"
	grep -vE "$TRANSIENT_TEMP" "$all" >"$bad" || true
	local tolerated
	tolerated="$(grep -cE "$TRANSIENT_TEMP" "$all" || true)"
	if [ ! -s "$bad" ]; then
		note yes "writes outside --out ($name)" none "none (${tolerated} transient apt temp files)"
		return
	fi
	note no "writes outside --out ($name)" none "$(wc -l <"$bad" | tr -d ' ') write attempts" "see $name.writes.txt"
	head -40 "$bad" | sed 's/^/     /'
}

# snapshot FILE: snapshot.sh as root, written by this shell as the caller.
snapshot() {
	# shellcheck disable=SC2024
	sudo "$SCENARIOS_DIR/snapshot.sh" >"$1"
}

scenario_verify() {
	local snaps
	snaps="$(mktemp -d)"
	# Snapshots stay out of $OUT: they hold hashes of /etc/shadow and other
	# private files, and $OUT is uploaded when a scenario fails.
	snapshot "$snaps/before"

	traced_audit read-only-sandbox
	expect collector "$REPORT" docker ok
	expect collector "$REPORT" firewall ok
	snapshot "$snaps/after-sandbox"

	traced_audit read-only-no-sandbox --no-sandbox
	snapshot "$snaps/after-no-sandbox"

	local run diff
	for run in after-sandbox after-no-sandbox; do
		# Paths only in the diff that is shown and uploaded: no hashes.
		diff="$(diff "$snaps/before" "$snaps/$run" | grep -E '^[<>]' | sed -E 's/^([<>]) sha256 [0-9a-f]+ /\1 content of /' || true)"
		if [ -z "$diff" ]; then
			note yes "host unchanged ($run)" "no change" "no change"
		else
			printf '%s\n' "$diff" >"$OUT/read-only-$run.diff"
			note no "host unchanged ($run)" "no change" \
				"$(printf '%s\n' "$diff" | wc -l | tr -d ' ') changed lines" "see read-only-$run.diff"
			printf '%s\n' "$diff" | head -40 | sed 's/^/     /'
		fi
	done
	sudo rm -rf "$snaps"
}

scenario_cleanup() {
	ufw_down
	docker_cleanup
}
