# shellcheck shell=bash
# ufw-docker: UFW active with the DOCKER-USER block of a standard ufw-docker
# install appended to /etc/ufw/after.rules (the snippet from the project's
# README), one container publishing 443 and one publishing 8000, and a
# `ufw route allow` rule for 443 only.
#
# The chain once read as "DOCKER-USER has rules that are not analysed".
# stackward must recognise it: 443 is reachable through the route rule
# (NET-004 info, public by design, and the inferred profile is public-web),
# 8000 is dropped by ufw-docker (NET-004 and DKR-001 pass).

UFW_DOCKER_BLOCK='# BEGIN UFW AND DOCKER
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward

-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP
-A DOCKER-USER -i docker0 -o docker0 -j ACCEPT

-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16

-A DOCKER-USER -j ufw-docker-logging-deny -m conntrack --ctstate NEW -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -m conntrack --ctstate NEW -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -m conntrack --ctstate NEW -d 192.168.0.0/16

-A DOCKER-USER -j RETURN

-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP

COMMIT
# END UFW AND DOCKER'

scenario_setup() {
	require_docker
	command -v ufw >/dev/null || sudo apt-get install -y -qq ufw >/dev/null
	docker_cleanup
	sudo docker run -d --name sw-web --user 65534:65534 -p 443:443 \
		"$ALPINE_IMAGE" sleep infinity >/dev/null
	sudo docker run -d --name sw-panel --user 65534:65534 -p 8000:8000 \
		"$ALPINE_IMAGE" sleep infinity >/dev/null
	wait_running sw-web
	wait_running sw-panel
	# reset restores the stock after.rules, so the block goes in after it.
	sudo ufw --force reset >/dev/null
	printf '\n%s\n' "$UFW_DOCKER_BLOCK" | sudo tee -a /etc/ufw/after.rules >/dev/null
	sudo ufw default deny incoming >/dev/null
	sudo ufw default allow outgoing >/dev/null
	sudo ufw allow from 192.0.2.0/24 to any port 22 proto tcp >/dev/null
	sudo ufw route allow proto tcp from any to any port 443 >/dev/null
	sudo ufw --force enable >/dev/null
	sudo ufw status verbose
	sudo iptables -S DOCKER-USER
}

scenario_verify() {
	audit ufw-docker
	expect collector "$REPORT" firewall ok
	expect check "$REPORT" NET-006 host info
	expect check "$REPORT" NET-008 host pass
	expect check "$REPORT" NET-004 port:tcp/443 info
	expect check "$REPORT" NET-004 port:tcp/8000 pass
	expect field "$REPORT" .profile.name public-web
	expect check "$REPORT" DKR-001 container:sw-web pass
	expect check "$REPORT" DKR-001 container:sw-panel pass
}

scenario_cleanup() {
	if command -v ufw >/dev/null; then
		sudo ufw --force disable >/dev/null 2>&1 || true
		# reset puts the stock after.rules back, without the block.
		sudo ufw --force reset >/dev/null 2>&1 || true
	fi
	sudo iptables -F DOCKER-USER >/dev/null 2>&1 || true
	docker_cleanup
}
