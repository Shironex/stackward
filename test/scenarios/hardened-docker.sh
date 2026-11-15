# shellcheck shell=bash
# hardened-docker: the same services as bad-docker, set up the way the
# fixes say.
#
# - sw-redis publishes on 127.0.0.1 and runs as the redis user;
# - sw-app publishes on 0.0.0.0, but a DOCKER-USER rule drops new
#   connections to that port from any source, so DKR-001 passes on the
#   filter, not on the bind address;
# - nothing mounts the Docker socket, nothing is privileged or adds a
#   capability, every container sets a non-root user;
# - compose projects swa and swb each keep their own network.

# DOCKER_USER_DROP is the hardened DOCKER-USER rule, without the chain.
# --ctorigdstport matches the host port before DNAT.
DOCKER_USER_DROP="-p tcp -m conntrack --ctstate NEW --ctorigdstport 6380 -m comment --comment stackward-scenario -j DROP"

scenario_setup() {
	require_docker
	docker_cleanup
	sudo docker run -d --name sw-redis --user 999:999 -p 127.0.0.1:6379:6379 "$REDIS_IMAGE" >/dev/null
	sudo docker run -d --name sw-app --user 65534:65534 -p 0.0.0.0:6380:6380 \
		"$ALPINE_IMAGE" sleep infinity >/dev/null
	compose_up swa own-app.yml
	compose_up swb own-db.yml
	wait_running sw-redis sw-app swa-app-1 swb-db-1
	# shellcheck disable=SC2086 # the rule is split into iptables words
	sudo iptables -I DOCKER-USER $DOCKER_USER_DROP
}

scenario_verify() {
	audit hardened-docker
	expect collector "$REPORT" docker ok
	expect collector "$REPORT" firewall ok
	expect check "$REPORT" DKR-001 'container:sw-redis|container:sw-app' pass
	local c
	for c in container:sw-redis container:sw-app container:swa/app container:swb/db; do
		expect check "$REPORT" DKR-010 "$c" pass
		expect check "$REPORT" DKR-020 "$c" pass
		expect check "$REPORT" DKR-021 "$c" pass
		expect check "$REPORT" DKR-022 "$c" pass
	done
	expect check "$REPORT" DKR-030 'container:swa/app|container:swb/db' pass
}

scenario_cleanup() {
	docker_cleanup
}
