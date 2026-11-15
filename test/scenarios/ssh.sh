# shellcheck shell=bash
# ssh: a drop-in that turns password authentication on, then one that
# turns it off, on the machine's own sshd. sshd takes the first value it
# reads and Ubuntu includes sshd_config.d/*.conf at the top of sshd_config,
# so a 00- drop-in wins over everything else.
#
# The drop-in is removed and sshd reloaded afterwards.

SSH_DROPIN=/etc/ssh/sshd_config.d/00-stackward-scenario.conf

scenario_setup() {
	if ! command -v sshd >/dev/null && [ ! -x /usr/sbin/sshd ]; then
		sudo apt-get install -y -qq openssh-server >/dev/null
	fi
	sudo mkdir -p /etc/ssh/sshd_config.d
	grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config ||
		die "/etc/ssh/sshd_config does not include sshd_config.d; this scenario needs a stock Ubuntu or Debian sshd"
}

# ssh_dropin TEXT: install the drop-in, validate the config, reload sshd.
# sshd -t needs /run/sshd, which only exists once ssh.service has run: on
# Ubuntu 24.04 ssh.socket starts it on the first connection. The scenario
# leaves it that way, as on a fresh server (stackward then parses the files
# instead of running sshd -T).
ssh_dropin() {
	printf '%s\n' "$1" | sudo tee "$SSH_DROPIN" >/dev/null
	if [ -d /run/sshd ]; then
		sudo /usr/sbin/sshd -t
	fi
	ssh_reload
}

ssh_reload() {
	# ssh.service on Ubuntu and Debian; sshd.service elsewhere. With socket
	# activation the service may be inactive, and the next connection reads
	# the new config anyway.
	sudo systemctl try-reload-or-restart ssh.service 2>/dev/null ||
		sudo systemctl try-reload-or-restart sshd.service 2>/dev/null || true
}

scenario_verify() {
	ssh_dropin "PasswordAuthentication yes"
	audit ssh-password-on
	expect collector "$REPORT" ssh ok
	expect check "$REPORT" SSH-001 host fail

	ssh_dropin "$(printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no')"
	audit ssh-hardened
	expect collector "$REPORT" ssh ok
	expect check "$REPORT" SSH-001 host pass
	expect check "$REPORT" SSH-002 host pass
	expect check "$REPORT" SSH-003 host pass
}

scenario_cleanup() {
	if [ -e "$SSH_DROPIN" ]; then
		sudo rm -f "$SSH_DROPIN"
		ssh_reload
	fi
}
