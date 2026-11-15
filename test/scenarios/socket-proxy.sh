# shellcheck shell=bash
# socket-proxy: a Docker socket proxy on 127.0.0.1:2375 that allows only
# reads. docker-proxy holds port 2375, which once read as "the Docker API on
# TCP without TLS" (a false positive on real hosts). DKR-002 must say info,
# naming the proxy, and DKR-011 must pass.

scenario_setup() {
	require_docker
	docker_cleanup
	sudo docker run -d --name sw-socket-proxy -p 127.0.0.1:2375:2375 \
		-v /var/run/docker.sock:/var/run/docker.sock:ro \
		-e CONTAINERS=1 -e INFO=1 -e POST=0 -e EXEC=0 \
		"$SOCKET_PROXY_IMAGE" >/dev/null
	wait_running sw-socket-proxy
}

scenario_verify() {
	audit socket-proxy
	expect collector "$REPORT" docker ok
	expect check "$REPORT" DKR-002 host info
	expect check "$REPORT" DKR-011 container:sw-socket-proxy pass
	# A socket proxy needs the socket: a warning, not a failure.
	expect check "$REPORT" DKR-010 container:sw-socket-proxy warn
}

scenario_cleanup() {
	docker_cleanup
}
