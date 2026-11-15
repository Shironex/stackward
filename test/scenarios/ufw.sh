# shellcheck shell=bash
# ufw: UFW active with deny by default and SSH allowed only from a
# documentation range, plus a container that publishes 8080 with nothing in
# DOCKER-USER.
#
# stackward never runs ufw (even `ufw status` opens /run/ufw.lock for
# writing and dies under the sandbox); it reads UFW's files and the loaded
# ruleset. Under the sandbox the firewall collector must end ok and the NET
# checks must be judged, not unknown. UFW's input rules do not see Docker's
# forwarded traffic, so the published port still bypasses the firewall
# (DKR-001 fail).

scenario_setup() {
	require_docker
	command -v ufw >/dev/null || sudo apt-get install -y -qq ufw >/dev/null
	docker_cleanup
	sudo docker run -d --name sw-web --user 65534:65534 -p 0.0.0.0:8080:8080 \
		"$ALPINE_IMAGE" sleep infinity >/dev/null
	wait_running sw-web
	ufw_up
}

# ufw_up enables UFW with deny incoming and SSH from 192.0.2.0/24 only.
# Outgoing traffic stays allowed, so the runner keeps its connection.
ufw_up() {
	sudo ufw --force reset >/dev/null
	sudo ufw default deny incoming >/dev/null
	sudo ufw default allow outgoing >/dev/null
	sudo ufw allow from 192.0.2.0/24 to any port 22 proto tcp >/dev/null
	sudo ufw --force enable >/dev/null
	sudo ufw status verbose
}

ufw_down() {
	if command -v ufw >/dev/null; then
		sudo ufw --force disable >/dev/null 2>&1 || true
		sudo ufw --force reset >/dev/null 2>&1 || true
	fi
}

scenario_verify() {
	audit ufw
	expect collector "$REPORT" firewall ok
	expect collector "$REPORT" listeners ok
	expect check "$REPORT" NET-001 host pass
	local id
	# Left out: NET-005 judges 80/443 rules against the ingress profile,
	# which a runner with no tunnel, tailnet or web server cannot be
	# inferred to have (unknown, correctly), and NET-009 is the provider
	# firewall, which only a probe from outside can see.
	for id in NET-002 NET-003 NET-004 NET-006 NET-007 NET-008; do
		expect check "$REPORT" "$id" '.*' '!unknown'
	done
	expect check "$REPORT" NET-004 port:tcp/22 pass
	expect check "$REPORT" NET-004 port:tcp/8080 warn
	expect check "$REPORT" DKR-001 container:sw-web fail
}

scenario_cleanup() {
	ufw_down
	docker_cleanup
}
