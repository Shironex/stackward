# shellcheck shell=bash
# shellcheck disable=SC2024 # outputs are written by this shell, as the caller, so they stay readable
# paas-env: the opt in paas-env-perms step on a real host (the disposable
# GitHub runner VM) with real systemd. Like apply, it lets stackward change
# the machine.
#
# Setup: a Coolify layout without Coolify itself, as its installer leaves
# it (/data/coolify owned by 9999:root, folders 0700): an app .env and a
# service .env at 0644, the main .env at 0644, all owned by uid 9999; an
# app .env.production owned by uid 1000 at 0644 (an owner the platform does
# not write as) and a .env.example at 0644 (a template). Then:
#
# 1. plan holds paas-env-perms, opt in, fixing SEC-001 and SEC-002.
# 2. apply --step paas-env-perms: the three units hold the planned content,
#    systemd-analyze verify accepts them, the timer is active, the service ran once: the app and service .env
#    are 0600, the main .env 0640, the uid 1000 file and the template stay
#    0644, every owner and every byte of content is unchanged.
# 3. A "deploy" opens the app .env again (0644) and writes a new app .env
#    at 0644: within 100 seconds the timer, not apply, closes both.
# 4. A second apply says nothing to do; a new audit passes SEC-002.
# 5. undo --run: the timer is gone (not loaded), the three unit files are
#    gone, every file under /etc is byte for byte as before, and the modes
#    the timer set stay set.

PE_SAVE=""
PE_UNIT=stackward-paas-env-perms
PE_SERVICE=/etc/systemd/system/$PE_UNIT.service
PE_TIMER=/etc/systemd/system/$PE_UNIT.timer
PE_DROPIN=/etc/systemd/system/timers.target.d/90-$PE_UNIT.conf
APP_ENV=/data/coolify/applications/a1/.env
SVC_ENV=/data/coolify/services/s1/.env
MAIN_ENV=/data/coolify/source/.env
OTHER_ENV=/data/coolify/applications/a1/.env.production
TEMPLATE_ENV=/data/coolify/applications/a1/.env.example
NEW_ENV=/data/coolify/applications/a2/.env

scenario_setup() {
	sudo test -e /data/coolify && die "/data/coolify exists; this scenario creates its own"
	PE_SAVE="$OUT/paas-env-saved"
	mkdir -p "$PE_SAVE"
	sudo mkdir -p /data/coolify/source /data/coolify/applications/a1 /data/coolify/services/s1
	printf 'APP_KEY=base64:scenario-only\n' | sudo tee "$MAIN_ENV" >/dev/null
	printf 'DB_URL=postgres://scenario-only\n' | sudo tee "$APP_ENV" >/dev/null
	printf 'REDIS_URL=redis://scenario-only\n' | sudo tee "$SVC_ENV" >/dev/null
	printf 'STAGE=production\n' | sudo tee "$OTHER_ENV" >/dev/null
	printf 'EXAMPLE=\n' | sudo tee "$TEMPLATE_ENV" >/dev/null
	sudo chown -R 9999:0 /data/coolify
	sudo chmod -R 700 /data/coolify
	sudo chown 1000:1000 "$OTHER_ENV"
	sudo chmod 0644 "$MAIN_ENV" "$APP_ENV" "$SVC_ENV" "$OTHER_ENV" "$TEMPLATE_ENV"
}

etc_hashes() {
	sudo find /etc -xdev -type f -print0 | sudo xargs -0 -r sha256sum | LC_ALL=C sort -k2
}

env_hashes() {
	sudo find /data/coolify -type f -name '.env*' -print0 | sudo xargs -0 -r sha256sum | LC_ALL=C sort -k2
}

mode_of() { sudo stat -c '%a' "$1"; }
owner_of() { sudo stat -c '%u:%g' "$1"; }

planned_new() {
	sudo jq -r --arg p "$1" ".steps[].edits[] | select(.path == \$p) | .new_sha256" "$OUT/plan.json"
}

file_sha() { sudo sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

yn() {
	if "$@"; then echo yes; else echo no; fi
}

run_apply() {
	local name="$1"
	shift
	CODE=0
	log "sudo stackward apply $*"
	sudo "$STACKWARD" apply "$@" "$OUT/plan.json" >"$OUT/$name.txt" 2>&1 || CODE=$?
	cat "$OUT/$name.txt"
}

expect_mode() {
	local p="$1" want="$2" what="$3"
	note "$(yn [ "$(mode_of "$p")" = "$want" ])" "$what" "$want" "$(mode_of "$p")"
}

scenario_verify() {
	local plan="$OUT/plan.json" step
	log "sudo stackward plan --out $plan"
	sudo "$STACKWARD" plan --out "$plan" >"$OUT/plan.txt"
	sudo chmod 0644 "$plan"
	cat "$OUT/plan.txt"
	step="$(jq -c '.steps[] | select(.id == "paas-env-perms") | {opt_in, fixes}' "$plan")"
	note "$(yn [ "$step" = '{"opt_in":true,"fixes":["SEC-001","SEC-002"]}' ])" "plan holds paas-env-perms, opt in" '{"opt_in":true,"fixes":["SEC-001","SEC-002"]}' "$step"

	etc_hashes >"$OUT/etc.before"
	env_hashes >"$OUT/env.before"
	verify_apply
	verify_timer
	verify_undo
}

verify_apply() {
	local p
	run_apply pe-1 --step paas-env-perms --yes
	note "$(yn [ "$CODE" -eq 0 ])" "apply exit code" 0 "$CODE"
	PE_RUN="$(sed -n 's/^run: *\([0-9TZ]*-[0-9a-f]*\) .*/\1/p' "$OUT/pe-1.txt")"
	for p in "$PE_SERVICE" "$PE_TIMER" "$PE_DROPIN"; do
		note "$(yn [ "$(file_sha "$p")" = "$(planned_new "$p")" ])" "$p holds the planned content" "$(planned_new "$p" | cut -c1-12)" "$(file_sha "$p" | cut -c1-12)"
	done
	local code=0
	sudo systemd-analyze verify "$PE_SERVICE" "$PE_TIMER" >"$OUT/pe-verify.txt" 2>&1 || code=$?
	note "$(yn [ "$code" -eq 0 ])" "systemd-analyze verify accepts the units" 0 "$code" "$(head -2 "$OUT/pe-verify.txt" | tr '\n' ' ')"
	note "$(yn [ "$(systemctl is-active "$PE_UNIT.timer" 2>/dev/null || true)" = active ])" "the timer is active" active "$(systemctl is-active "$PE_UNIT.timer" 2>/dev/null || true)"
	note "$(yn [ "$(systemctl show -p Result --value "$PE_UNIT.service")" = success ])" "the service ran and succeeded" success "$(systemctl show -p Result --value "$PE_UNIT.service")"
	expect_mode "$APP_ENV" 600 "the app .env is closed"
	expect_mode "$SVC_ENV" 600 "the service .env is closed"
	expect_mode "$MAIN_ENV" 640 "the main .env keeps the owner's and group's read bits"
	expect_mode "$OTHER_ENV" 644 "an .env of another owner is left alone"
	expect_mode "$TEMPLATE_ENV" 644 "a template is left alone"
	for p in "$APP_ENV" "$SVC_ENV" "$MAIN_ENV"; do
		note "$(yn [ "$(owner_of "$p")" = 9999:0 ])" "$p keeps its owner" 9999:0 "$(owner_of "$p")"
	done
	note "$(yn [ "$(owner_of "$OTHER_ENV")" = 1000:1000 ])" "the other owner's file keeps its owner" 1000:1000 "$(owner_of "$OTHER_ENV")"
	env_hashes >"$OUT/env.applied"
	note "$(yn cmp -s "$OUT/env.before" "$OUT/env.applied")" "no .env content changed" "no diff" "$(diff "$OUT/env.before" "$OUT/env.applied" | head -2 | tr '\n' ' ')"
}

verify_timer() {
	local i
	# A deploy rewrites an .env loose and adds a new app.
	sudo chmod 0644 "$APP_ENV"
	sudo mkdir -p /data/coolify/applications/a2
	printf 'NEW=scenario-only\n' | sudo tee "$NEW_ENV" >/dev/null
	sudo chown -R 9999:0 /data/coolify/applications/a2
	sudo chmod 0644 "$NEW_ENV"
	log "waiting for the timer to close $APP_ENV and $NEW_ENV"
	for i in $(seq 1 50); do
		if [ "$(mode_of "$APP_ENV")" = 600 ] && [ "$(mode_of "$NEW_ENV")" = 600 ]; then
			break
		fi
		sleep 2
	done
	systemctl list-timers "$PE_UNIT.timer" --all --no-pager || true
	expect_mode "$APP_ENV" 600 "the timer closes a reopened .env (after ${i}x2s)"
	expect_mode "$NEW_ENV" 600 "the timer closes a new app's .env"

	run_apply pe-2 --step paas-env-perms --yes
	note "$(yn grep -q 'nothing to do' "$OUT/pe-2.txt")" "second apply says nothing to do" "nothing to do" "$(tail -1 "$OUT/pe-2.txt")"

	audit pe-after
	expect check "$REPORT" SEC-002 host pass
	expect check "$REPORT" SEC-001 "file:$OTHER_ENV" fail

	sudo journalctl -u "$PE_UNIT.service" --no-pager -o cat >"$OUT/pe-journal.txt" 2>&1 || true
	note "$(if grep -q scenario-only "$OUT/pe-journal.txt"; then echo no; else echo yes; fi)" "the journal holds no .env value" "no value" "$(grep -c scenario-only "$OUT/pe-journal.txt" || true) lines"
}

verify_undo() {
	local code=0 p
	log "sudo stackward undo --run $PE_RUN --yes"
	sudo "$STACKWARD" undo --run "$PE_RUN" --yes >"$OUT/pe-undo.txt" 2>&1 || code=$?
	cat "$OUT/pe-undo.txt"
	note "$(yn [ "$code" -eq 0 ])" "undo exit code" 0 "$code"
	for p in "$PE_SERVICE" "$PE_TIMER" "$PE_DROPIN"; do
		note "$(yn sudo test ! -e "$p")" "undo removes $p" gone "$(sudo test -e "$p" && echo present || echo gone)"
	done
	local load
	load="$(systemctl show -p LoadState --value "$PE_UNIT.timer")"
	note "$(yn [ "$load" = not-found ])" "systemd no longer knows the timer" not-found "$load"
	etc_hashes >"$OUT/etc.undone"
	note "$(yn cmp -s "$OUT/etc.before" "$OUT/etc.undone")" "undo restores every file under /etc" "no diff" "$(diff "$OUT/etc.before" "$OUT/etc.undone" | head -3 | tr '\n' ' ')"
	expect_mode "$APP_ENV" 600 "undo leaves the closed modes closed"
}

scenario_cleanup() {
	[ -n "$PE_SAVE" ] || return 0
	sudo systemctl stop "$PE_UNIT.timer" "$PE_UNIT.service" >/dev/null 2>&1 || true
	sudo rm -f "$PE_SERVICE" "$PE_TIMER" "$PE_DROPIN"
	sudo systemctl daemon-reload || true
	sudo rm -rf /data/coolify
}
