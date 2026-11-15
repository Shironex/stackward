#!/usr/bin/env bash
# Assertions over a stackward report.v1 JSON file.
#
#   assert.sh check     REPORT ID SUBJECT LEVELS
#   assert.sh collector REPORT NAME STATUSES
#   assert.sh sandbox   REPORT STATE
#   assert.sh none      REPORT LEVELS ID...
#   assert.sh field     REPORT JQ_FILTER EXPECTED
#
# SUBJECT is an extended regular expression matched against the whole
# subject (container:sw-redis, host, container:swa/.*). Every result of ID
# whose subject matches must have a level in LEVELS, and at least one must
# exist. LEVELS and STATUSES are lists separated by "|" (fail, pass|info),
# or "!" plus a list to forbid levels (!unknown, !pass|unknown).
#
# none fails when any result of the listed ids has a level in LEVELS.
# field compares the raw output of a jq filter over the report (jq -r)
# with EXPECTED, for example `.coverage.root` and false.
#
# Each assertion prints one line, PASS or FAIL with actual against
# expected, and appends a row to $ASSERT_LOG (tab separated) when set, so
# run.sh can print a summary of every assertion. The exit status is 1 when
# the assertion fails, 2 when it cannot be evaluated.
set -euo pipefail

usage() {
	sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' >&2
	exit 2
}

[ $# -ge 1 ] || usage
kind="$1"
shift

# record KIND WHAT EXPECTED ACTUAL OK DETAIL
record() {
	local what="$2" expected="$3" actual="$4" ok="$5" detail="$6"
	if [ "$ok" = yes ]; then
		printf 'PASS %s: %s (expected %s)\n' "$what" "$actual" "$expected"
	else
		printf 'FAIL %s: expected %s, got %s\n' "$what" "$expected" "$actual"
		[ -n "$detail" ] && printf '     %s\n' "$detail"
	fi
	if [ -n "${ASSERT_LOG:-}" ]; then
		# Tabs and newlines would break the log format.
		detail="$(printf '%s' "$detail" | tr '\t\n' '  ')"
		printf '%s\t%s\t%s\t%s\t%s\n' "$ok" "$what" "$expected" "$actual" "$detail" >>"$ASSERT_LOG"
	fi
	[ "$ok" = yes ]
}

# matches VALUE SPEC: SPEC is a|b|c or !a|b|c.
matches() {
	local value="$1" spec="$2" negate=no
	if [ "${spec#!}" != "$spec" ]; then
		negate=yes
		spec="${spec#!}"
	fi
	local hit=no item
	IFS='|' read -r -a items <<<"$spec"
	for item in "${items[@]}"; do
		[ "$item" = "$value" ] && hit=yes
	done
	if [ "$negate" = yes ]; then
		[ "$hit" = no ]
	else
		[ "$hit" = yes ]
	fi
}

need_report() {
	if [ ! -s "$1" ]; then
		echo "assert.sh: report $1 is missing or empty" >&2
		exit 2
	fi
	jq -e '.schema == "stackward.report.v1"' "$1" >/dev/null || {
		echo "assert.sh: $1 is not a stackward report.v1" >&2
		exit 2
	}
}

case "$kind" in
check)
	[ $# -eq 4 ] || usage
	report="$1" id="$2" subject="$3" levels="$4"
	need_report "$report"
	what="$id $subject"
	rows="$(jq -r --arg id "$id" --arg pat "$subject" '
		.results[] | select(.id == $id and (.subject | test("^(" + $pat + ")$")))
		| [.subject, .level, .message] | @tsv' "$report")"
	if [ -z "$rows" ]; then
		present="$(jq -r --arg id "$id" '[.results[] | select(.id == $id) | "\(.subject)=\(.level)"] | join(", ")' "$report")"
		record check "$what" "$levels" "no result" no "results of $id: ${present:-none}"
		exit 1
	fi
	status=0
	while IFS=$'\t' read -r subj level msg; do
		if matches "$level" "$levels"; then
			record check "$id $subj" "$levels" "$level" yes "" || true
		else
			record check "$id $subj" "$levels" "$level" no "$msg" || status=1
		fi
	done <<<"$rows"
	exit "$status"
	;;
collector)
	[ $# -eq 3 ] || usage
	report="$1" name="$2" statuses="$3"
	need_report "$report"
	row="$(jq -r --arg n "$name" '.coverage.collectors[] | select(.name == $n) | [.status, (.error // "")] | @tsv' "$report")"
	if [ -z "$row" ]; then
		record collector "collector $name" "$statuses" "missing" no "the report lists no collector named $name"
		exit 1
	fi
	IFS=$'\t' read -r status err <<<"$row"
	if matches "$status" "$statuses"; then
		record collector "collector $name" "$statuses" "$status" yes ""
	else
		record collector "collector $name" "$statuses" "$status" no "$err"
	fi
	;;
sandbox)
	[ $# -eq 2 ] || usage
	report="$1" want="$2"
	need_report "$report"
	row="$(jq -r '[.coverage.sandbox.state, (.coverage.sandbox.reason // "")] | @tsv' "$report")"
	IFS=$'\t' read -r state reason <<<"$row"
	if matches "$state" "$want"; then
		record sandbox "sandbox" "$want" "$state" yes ""
	else
		record sandbox "sandbox" "$want" "$state" no "$reason"
	fi
	;;
none)
	[ $# -ge 3 ] || usage
	report="$1" levels="$2"
	shift 2
	need_report "$report"
	ids="$(printf '%s\n' "$@" | jq -R . | jq -s .)"
	hits="$(jq -r --argjson ids "$ids" --arg levels "$levels" '
		($levels | split("|")) as $ls
		| [.results[] | select(.id as $i | $ids | index($i)) | select(.level as $l | $ls | index($l))
		   | "\(.id) \(.subject)=\(.level)"] | join(", ")' "$report")"
	what="none of $# checks at $levels"
	if [ -z "$hits" ]; then
		record none "$what" "none" "none" yes ""
	else
		record none "$what" "none" "$hits" no "results that must not be $levels: $hits"
	fi
	;;
field)
	[ $# -eq 3 ] || usage
	report="$1" filter="$2" want="$3"
	need_report "$report"
	got="$(jq -r "$filter" "$report")"
	if [ "$got" = "$want" ]; then
		record field "$filter" "$want" "$got" yes ""
	else
		record field "$filter" "$want" "$got" no ""
	fi
	;;
*)
	usage
	;;
esac
