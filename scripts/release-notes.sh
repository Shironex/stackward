#!/bin/sh
# release-notes.sh: print the CHANGELOG.md section for one release.
#
#   sh scripts/release-notes.sh v0.1.0 [CHANGELOG.md]
#
# Prints the body under the heading "## <version> (<date>)", without the
# heading, up to the next "## " heading. Fails when the section is missing or
# empty, so a release cannot go out without notes.

set -eu

tag=${1:?usage: release-notes.sh TAG [CHANGELOG.md]}
file=${2:-CHANGELOG.md}
ver=${tag#v}

[ -f "$file" ] || { printf 'release-notes.sh: %s not found\n' "$file" >&2; exit 1; }

notes=$(awk -v ver="$ver" '
	/^## / {
		if (on) exit
		split($0, h, " ")
		if (h[2] == ver) { on = 1; next }
	}
	on { print }
' "$file")

if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
	printf 'release-notes.sh: no section "## %s" in %s\n' "$ver" "$file" >&2
	exit 1
fi
printf '%s\n' "$notes"
