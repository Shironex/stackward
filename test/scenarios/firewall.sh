# shellcheck shell=bash
# shellcheck disable=SC2024 # outputs are written by this shell, as the caller, so they stay readable
# firewall: the firewall steps on a real host (the disposable GitHub runner
# VM). Like apply, it lets stackward change the machine.
#
# Setup: UFW installed, reset to its stock files and off; the runner's own
# sshd on 22; a host service listening on 0.0.0.0:8090; a container
# publishing 8080. A network namespace joined by a veth pair stands in for
# a client on the internet (198.51.100.2, the host is 198.51.100.1), so
# reachability is tested from outside without touching the runner's own
# network. The runner talks to GitHub over connections it opens itself,
# which UFW's default deny incoming leaves alone (established traffic is
# accepted), as the ufw scenarios already show. Then:
#
# 1. plan --profile tunnel holds ufw-policy; ufw-docker waits for UFW.
# 2. apply --step ufw-policy runs as a transaction with no SSH session:
#    UFW is active with a default deny, SSH stays reachable from the
#    client, 8090 is closed, the published 8080 is still reachable (Docker
#    forwards past UFW's input rules, as the step says). confirm --console
#    keeps it. A second apply says nothing to do. NET-001 passes.
# 3. plan again: ufw-docker. apply --step ufw-docker: after.rules holds the
#    block, DOCKER-USER sends new connections to ufw-docker's logging
#    chain, 8080 is closed from the client and SSH still reachable. A
#    second apply says nothing to do. DKR-001 passes.
# 4. undo ufw-docker: 8080 reachable again, DOCKER-USER as Docker had it,
#    the logging chain gone. undo ufw-policy: UFW off, 8090 reachable,
#    every UFW file byte for byte as before.

FW_SAVE=""
NS=swfw
HOST_IP=198.51.100.1
CLIENT_IP=198.51.100.2
TXN_STATE=/var/lib/stackward/transaction.json

scenario_setup() {
	require_docker
	FW_SAVE="$OUT/firewall-saved"
	mkdir -p "$FW_SAVE"
	command -v ufw >/dev/null || sudo apt-get install -y -qq ufw >/dev/null
	docker_cleanup
	# reset puts the stock files back and leaves UFW off.
	sudo ufw --force reset >/dev/null
	sudo systemctl start ssh.service
	sudo docker run -d --name sw-web --user 65534:65534 -p 8080:8080 \
		"$ALPINE_IMAGE" sh -c 'while true; do nc -l -p 8080 </dev/null >/dev/null 2>&1; done' >/dev/null
	wait_running sw-web
	setsid python3 -m http.server 8090 --bind 0.0.0.0 >/dev/null 2>&1 &
	echo $! >"$FW_SAVE/http.pid"
	sudo ip netns add "$NS"
	sudo ip link add sw-fw-h type veth peer name sw-fw-n
	sudo ip link set sw-fw-n netns "$NS"
	sudo ip addr add "$HOST_IP/24" dev sw-fw-h
	sudo ip link set sw-fw-h up
	sudo ip netns exec "$NS" ip addr add "$CLIENT_IP/24" dev sw-fw-n
	sudo ip netns exec "$NS" ip link set sw-fw-n up
	sudo ip netns exec "$NS" ip link set lo up
	sleep 1
	sudo iptables -S DOCKER-USER >"$FW_SAVE/docker-user.before" 2>&1 || true
	ufw_hashes >"$FW_SAVE/ufw.before"
}

ufw_hashes() {
	sudo find /etc/ufw /etc/default/ufw -xdev -type f ! -name "*.orig" -print0 | sudo xargs -0 -r sha256sum | LC_ALL=C sort -k2
}

# reach PORT: yes when the client namespace can open a TCP connection to
# the host's veth address on PORT (three tries), no otherwise.
reach() {
	local _
	for _ in 1 2 3; do
		if sudo ip netns exec "$NS" timeout 3 bash -c "exec 3<>/dev/tcp/$HOST_IP/$1" 2>/dev/null; then
			echo yes
			return
		fi
		sleep 1
	done
	echo no
}

expect_reach() {
	local port="$1" want="$2" what="$3" got
	got="$(reach "$port")"
	note "$(yn [ "$got" = "$want" ])" "$what" "reachable=$want" "reachable=$got" "tcp/$port from $CLIENT_IP"
}

yn() {
	if "$@"; then echo yes; else echo no; fi
}

planned_new() {
	sudo jq -r --arg p "$2" ".steps[].edits[] | select(.path == \$p) | .new_sha256" "$1"
}

file_sha() { sudo sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# make_plan NAME: plan with the tunnel profile (nothing public by design)
# into $OUT/NAME.json.
make_plan() {
	log "sudo stackward plan --profile tunnel --out $OUT/$1.json"
	sudo "$STACKWARD" plan --profile tunnel --out "$OUT/$1.json" >"$OUT/$1.txt"
	sudo chmod 0644 "$OUT/$1.json"
	cat "$OUT/$1.txt"
}

# run_apply NAME PLAN ARGS...: apply PLAN, output to $OUT/NAME.txt; sets CODE.
run_apply() {
	local name="$1" plan="$2"
	shift 2
	CODE=0
	log "sudo stackward apply $*"
	sudo "$STACKWARD" apply "$@" "$plan" >"$OUT/$name.txt" 2>&1 || CODE=$?
	cat "$OUT/$name.txt"
}

# transaction NAME PLAN STEP: apply STEP as a transaction and confirm it
# from the console; sets TXN_ID.
transaction() {
	local name="$1" plan="$2" step="$3" code
	run_apply "$name" "$plan" --step "$step" --confirm-within 5m --yes
	note "$(yn [ "$CODE" -eq 0 ])" "$step transaction exit code" 0 "$CODE"
	TXN_ID="$(sudo jq -r '.id // empty' "$TXN_STATE" 2>/dev/null)"
	code=0
	sudo "$STACKWARD" confirm --console "$TXN_ID" >"$OUT/$name-confirm.txt" 2>&1 || code=$?
	cat "$OUT/$name-confirm.txt"
	note "$(yn [ "$code" -eq 0 ])" "$step confirm --console exit code" 0 "$code"
}

undo_run() {
	local name="$1" id="$2" code=0
	log "sudo stackward undo --run $id --yes"
	sudo "$STACKWARD" undo --run "$id" --yes >"$OUT/$name.txt" 2>&1 || code=$?
	cat "$OUT/$name.txt"
	note "$(yn [ "$code" -eq 0 ])" "$name exit code" 0 "$code"
}

scenario_verify() {
	expect_reach 22 yes "before: SSH reachable"
	expect_reach 8090 yes "before: the host service reachable"
	expect_reach 8080 yes "before: the published port reachable"

	make_plan plan
	local steps
	steps="$(jq -r '[.steps[].id] | join(",")' "$OUT/plan.json")"
	note "$(yn grep -Eq '(^|,)ufw-policy(,|$)' <<<"$steps")" "plan holds ufw-policy" yes "$steps"
	note "$(yn [ "$(jq -r '.skipped[] | select(.id == "ufw-docker") | .kind' "$OUT/plan.json")" = manual ])" \
		"ufw-docker waits for UFW" manual "$(jq -r '.skipped[] | select(.id == "ufw-docker") | .reason' "$OUT/plan.json")"

	verify_policy
	verify_docker

	undo_run undo-docker "$DOCKER_ID"
	expect_reach 8080 yes "after undo of ufw-docker: the published port reachable"
	sudo iptables -S DOCKER-USER >"$OUT/docker-user.undone" 2>&1 || true
	note "$(yn cmp -s "$FW_SAVE/docker-user.before" "$OUT/docker-user.undone")" "DOCKER-USER as Docker had it" "no diff" \
		"$(diff "$FW_SAVE/docker-user.before" "$OUT/docker-user.undone" | head -4 | tr '\n' ' ')"
	note "$(yn sudo sh -c '! iptables -S ufw-docker-logging-deny >/dev/null 2>&1')" "the logging chain is gone" gone ""

	undo_run undo-policy "$POLICY_ID"
	local status
	status="$(sudo ufw status | head -1)"
	note "$(yn [ "$status" = "Status: inactive" ])" "UFW is off again" "Status: inactive" "$status"
	expect_reach 8090 yes "after undo of ufw-policy: the host service reachable"
	ufw_hashes >"$OUT/ufw.undone"
	note "$(yn cmp -s "$FW_SAVE/ufw.before" "$OUT/ufw.undone")" "undo restores every UFW file" "no diff" \
		"$(diff "$FW_SAVE/ufw.before" "$OUT/ufw.undone" | head -4 | tr '\n' ' ')"
}

verify_policy() {
	local p status
	transaction pol-1 "$OUT/plan.json" ufw-policy
	POLICY_ID="$TXN_ID"
	for p in /etc/ufw/user.rules /etc/ufw/user6.rules /etc/ufw/ufw.conf; do
		note "$(yn [ "$(file_sha "$p")" = "$(planned_new "$OUT/plan.json" "$p")" ])" "$p holds the planned content" \
			"$(planned_new "$OUT/plan.json" "$p" | cut -c1-12)" "$(file_sha "$p" | cut -c1-12)"
	done
	sudo ufw status verbose | tee "$OUT/ufw-status.txt"
	status="$(head -1 "$OUT/ufw-status.txt")"
	note "$(yn [ "$status" = "Status: active" ])" "UFW is active" "Status: active" "$status"
	note "$(yn grep -q 'Default: deny (incoming)' "$OUT/ufw-status.txt")" "the default is deny incoming" "deny (incoming)" "$(grep '^Default' "$OUT/ufw-status.txt")"
	note "$(yn sudo sh -c 'iptables -S ufw-user-input | grep -q -- "--dport 22 -j ACCEPT"')" "UFW lets 22 in" "--dport 22 -j ACCEPT" "$(sudo iptables -S ufw-user-input | tr '\n' ' ')"
	expect_reach 22 yes "after ufw-policy: SSH reachable"
	expect_reach 8090 no "after ufw-policy: the host service closed"
	expect_reach 8080 yes "after ufw-policy: the published port still reachable (Docker forwards past UFW)"

	run_apply pol-2 "$OUT/plan.json" --step ufw-policy --yes
	note "$(yn grep -q 'nothing to do' "$OUT/pol-2.txt")" "second ufw-policy apply says nothing to do" "nothing to do" "$(tail -1 "$OUT/pol-2.txt")"

	audit pol-after --profile tunnel
	expect check "$REPORT" NET-001 host pass
}

verify_docker() {
	local after
	make_plan plan2
	note "$(yn [ "$(jq -r '.steps[] | select(.id == "ufw-docker") | .opt_in' "$OUT/plan2.json")" = true ])" \
		"plan holds the opt in ufw-docker" true "$(jq -r '[.steps[].id] | join(",")' "$OUT/plan2.json")"
	note "$(yn grep -q 'become filtered' "$OUT/plan2.txt")" "the plan says published ports become filtered" "become filtered" ""
	transaction dk-1 "$OUT/plan2.json" ufw-docker
	DOCKER_ID="$TXN_ID"
	after=/etc/ufw/after.rules
	note "$(yn [ "$(file_sha "$after")" = "$(planned_new "$OUT/plan2.json" "$after")" ])" "after.rules holds the planned content" \
		"$(planned_new "$OUT/plan2.json" "$after" | cut -c1-12)" "$(file_sha "$after" | cut -c1-12)"
	sudo iptables -S DOCKER-USER | tee "$OUT/docker-user.applied"
	note "$(yn grep -q 'ufw-docker-logging-deny' "$OUT/docker-user.applied")" "DOCKER-USER sends new connections to ufw-docker" "ufw-docker-logging-deny" ""
	expect_reach 8080 no "after ufw-docker: the published port closed"
	expect_reach 22 yes "after ufw-docker: SSH reachable"

	run_apply dk-2 "$OUT/plan2.json" --step ufw-docker --yes
	note "$(yn grep -q 'nothing to do' "$OUT/dk-2.txt")" "second ufw-docker apply says nothing to do" "nothing to do" "$(tail -1 "$OUT/dk-2.txt")"

	audit dk-after --profile tunnel
	expect check "$REPORT" DKR-001 container:sw-web pass
}

scenario_cleanup() {
	[ -n "$FW_SAVE" ] || return 0
	sudo systemctl stop 'stackward-rollback-*' >/dev/null 2>&1 || true
	if [ -f "$FW_SAVE/http.pid" ]; then
		kill "$(cat "$FW_SAVE/http.pid")" >/dev/null 2>&1 || true
	fi
	sudo ip netns del "$NS" >/dev/null 2>&1 || true
	sudo ip link del sw-fw-h >/dev/null 2>&1 || true
	if command -v ufw >/dev/null; then
		sudo ufw --force disable >/dev/null 2>&1 || true
		sudo ufw --force reset >/dev/null 2>&1 || true
	fi
	sudo iptables -F ufw-docker-logging-deny >/dev/null 2>&1 || true
	sudo iptables -F DOCKER-USER >/dev/null 2>&1 || true
	if grep -q -- '-A DOCKER-USER -j RETURN' "$FW_SAVE/docker-user.before" 2>/dev/null; then
		sudo iptables -A DOCKER-USER -j RETURN >/dev/null 2>&1 || true
	fi
	sudo iptables -X ufw-docker-logging-deny >/dev/null 2>&1 || true
	docker_cleanup
}
