# shellcheck shell=bash
# bad-docker: the container mistakes stackward exists to find.
#
# - sw-redis publishes Redis on 0.0.0.0 with nothing in DOCKER-USER, so it
#   bypasses any host firewall (DKR-001), and runs as root while reachable
#   from outside (DKR-020);
# - sw-socket mounts the Docker socket (DKR-010);
# - sw-priv runs as root, privileged, with SYS_ADMIN added (DKR-020,
#   DKR-021, DKR-022);
# - compose projects swa and swb share the network sw-shared, and swb's
#   service is a database (DKR-030).

bad_docker_up() {
	docker_cleanup
	sudo docker network create sw-shared >/dev/null
	sudo docker run -d --name sw-redis -p 0.0.0.0:6379:6379 "$REDIS_IMAGE" >/dev/null
	sudo docker run -d --name sw-socket -v /var/run/docker.sock:/var/run/docker.sock \
		"$ALPINE_IMAGE" sleep infinity >/dev/null
	sudo docker run -d --name sw-priv --privileged --cap-add SYS_ADMIN \
		"$ALPINE_IMAGE" sleep infinity >/dev/null
	compose_up swa shared-app.yml
	compose_up swb shared-db.yml
	wait_running sw-redis sw-socket sw-priv swa-app-1 swb-db-1
}

scenario_setup() {
	require_docker
	bad_docker_up
}

scenario_verify() {
	audit bad-docker
	expect collector "$REPORT" docker ok
	expect check "$REPORT" DKR-001 container:sw-redis fail
	expect check "$REPORT" DKR-020 container:sw-redis fail
	expect check "$REPORT" DKR-010 container:sw-socket fail
	expect check "$REPORT" DKR-010 container:sw-redis pass
	expect check "$REPORT" DKR-020 container:sw-priv fail
	expect check "$REPORT" DKR-021 container:sw-priv fail
	expect check "$REPORT" DKR-022 container:sw-priv fail
	expect check "$REPORT" DKR-030 container:swa/app fail
	expect check "$REPORT" DKR-030 container:swb/db fail
}

scenario_cleanup() {
	docker_cleanup
}
