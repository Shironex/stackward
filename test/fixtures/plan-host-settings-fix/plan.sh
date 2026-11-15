#!/bin/sh
# stackward plan as a shell script (stackward.plan.v1, stackward test).
# Host: sha256:88fcffd365f6d89e  Ubuntu 24.04.1 LTS. Source: facts file, report by stackward test, facts from 2026-03-01T12:00:00Z.
#
# stackward never runs this script. Read every step, then run it as root
# on the host it was planned for. Each step first checks that the files
# it changes still hold what the audit saw, and stops otherwise. Opt in
# steps are commented out at the bottom: remove the "# " to run one.
set -eu

# 1/3 journald-cap [safe] fixes LOG-001
# Cap the persistent journal at 1G with a journald drop-in
# Restarts systemd-journald.
# Note: Restarting systemd-journald drops no running service; journal files
# older than the 1G limit are deleted.
# Undo: Remove the drop-in and restart systemd-journald; the journal may
# then grow to the default limit again. Journal files already vacuumed are
# gone.
#   rm -f /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf
#   systemctl restart systemd-journald
step_journald_cap() {
	# create /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf (0644)
	if [ -e /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf ]; then
		echo 'stackward: /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/systemd/journald.conf.d
	cat > /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf.stackward-new <<'STACKWARD_EOF'
# Written by stackward: plan step journald-cap, fixes LOG-001.
# Caps the persistent journal. Remove this file and restart
# systemd-journald to undo.
[Journal]
SystemMaxUse=1G
STACKWARD_EOF
	chmod 0644 /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf.stackward-new
	mv /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf.stackward-new /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf
	# load the new limit; journald vacuums older files down to it
	systemctl restart systemd-journald
}

# 2/3 sysctl-hardening [safe] fixes KRN-002, KRN-003, KRN-004
# Set the kernel hardening values with a sysctl drop-in
# Note: /etc/sysctl.conf sets kernel.kptr_restrict = 0 and is read after
# this drop-in, so the old value returns at boot; change it there by hand.
# Note: /etc/ufw/sysctl.conf sets net.ipv4.conf.all.log_martians=0 (want 1)
# and ufw applies it again on every enable and reload; this step leaves that
# file alone.
# Undo: Remove the drop-in so the old values return at the next boot, and
# set the old running values now.
#   rm -f /etc/sysctl.d/90-stackward-hardening.conf
#   sysctl -w net.ipv4.conf.all.rp_filter=1
#   sysctl -w net.ipv4.conf.all.accept_redirects=1
#   sysctl -w kernel.kptr_restrict=0
step_sysctl_hardening() {
	# create /etc/sysctl.d/90-stackward-hardening.conf (0644)
	if [ -e /etc/sysctl.d/90-stackward-hardening.conf ]; then
		echo 'stackward: /etc/sysctl.d/90-stackward-hardening.conf exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/sysctl.d
	cat > /etc/sysctl.d/90-stackward-hardening.conf.stackward-new <<'STACKWARD_EOF'
# Written by stackward: plan step sysctl-hardening, fixes KRN-002, KRN-003, KRN-004.
# Hardening values only: net.ipv4.ip_forward and the other settings
# Docker needs are never set here. Remove this file to undo at the
# next boot.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
kernel.kptr_restrict = 1
STACKWARD_EOF
	chmod 0644 /etc/sysctl.d/90-stackward-hardening.conf.stackward-new
	mv /etc/sysctl.d/90-stackward-hardening.conf.stackward-new /etc/sysctl.d/90-stackward-hardening.conf
	# apply this drop-in now, and only this file, not the whole sysctl.d tree
	sysctl -p /etc/sysctl.d/90-stackward-hardening.conf
}

# 3/3 docker-log-rotation [networking] fixes DKR-031
# Rotate json-file container logs (max-size 10m, max-file 3) in daemon.json
# Restarts docker.
# Note: Restarting Docker stops and starts every container unless
# live-restore is on; containers without a restart policy stay stopped.
# Note: The limits apply to containers created after the restart; recreate
# running containers (for example docker compose up -d --force-recreate) to
# rotate their logs.
# Undo: Put the previous daemon.json back (its content is the old side of
# this step's diff; apply also keeps a copy under
# /var/backups/stackward/<run-id>/) and restart Docker.
#   systemctl restart docker
step_docker_log_rotation() {
	# replace /etc/docker/daemon.json; the diff is in the plan
	if ! echo 'f08553a9c1791d0edb10e4630155d0bb7bdb499136061e3e691379dbe4bdd522  /etc/docker/daemon.json' | sha256sum -c --status -; then
		echo 'stackward: /etc/docker/daemon.json changed since the audit; plan again' >&2
		exit 1
	fi
	[ -e /etc/docker/daemon.json.orig ] || cp -p /etc/docker/daemon.json /etc/docker/daemon.json.orig
	cp -p /etc/docker/daemon.json /etc/docker/daemon.json.stackward-new
	cat > /etc/docker/daemon.json.stackward-new <<'STACKWARD_EOF'
{
  "live-restore": true,
  "registry-mirrors": [
    "https://mirror.example.com"
  ],
  "log-opts": {
    "labels": "com.docker.compose.project",
    "max-size": "10m",
    "max-file": "3"
  },
  "features": {
    "buildkit": true
  },
  "log-driver": "json-file"
}
STACKWARD_EOF
	if ! dockerd --validate --config-file /etc/docker/daemon.json.stackward-new; then
		rm -f /etc/docker/daemon.json.stackward-new
		echo 'stackward: the new /etc/docker/daemon.json failed validation; nothing was changed' >&2
		exit 1
	fi
	mv /etc/docker/daemon.json.stackward-new /etc/docker/daemon.json
	# load the new log settings
	systemctl restart docker
}

step_journald_cap
step_sysctl_hardening
# step_docker_log_rotation  # opt in: networking, restarts docker
