#!/bin/sh
# stackward plan as a shell script (stackward.plan.v1, stackward test).
# Host: sha256:cc24e0cbf4b08870  Ubuntu 24.04.1 LTS. Source: facts file, report by stackward test, facts from 2026-03-01T12:00:00Z.
#
# stackward never runs this script. Read every step, then run it as root
# on the host it was planned for. Each step first checks that the files
# it changes still hold what the audit saw, and stops otherwise. Opt in
# steps are commented out at the bottom: remove the "# " to run one.
set -eu

# 1/1 docker-log-rotation [networking] fixes DKR-031
# Rotate json-file container logs (max-size 10m, max-file 3) in daemon.json
# Restarts docker.
# Note: Restarting Docker stops and starts every container unless
# live-restore is on; containers without a restart policy stay stopped.
# Note: The limits apply to containers created after the restart; recreate
# running containers (for example docker compose up -d --force-recreate) to
# rotate their logs.
# Undo: Remove daemon.json, which did not exist before, and restart Docker.
#   rm -f /etc/docker/daemon.json
#   systemctl restart docker
step_docker_log_rotation() {
	# create /etc/docker/daemon.json (0644)
	if [ -e /etc/docker/daemon.json ]; then
		echo 'stackward: /etc/docker/daemon.json exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/docker
	cat > /etc/docker/daemon.json.stackward-new <<'STACKWARD_EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
STACKWARD_EOF
	chmod 0644 /etc/docker/daemon.json.stackward-new
	if ! dockerd --validate --config-file /etc/docker/daemon.json.stackward-new; then
		rm -f /etc/docker/daemon.json.stackward-new
		echo 'stackward: the new /etc/docker/daemon.json failed validation; nothing was changed' >&2
		exit 1
	fi
	mv /etc/docker/daemon.json.stackward-new /etc/docker/daemon.json
	# load the new log settings
	systemctl restart docker
}

# Not planned:
# journald-cap (passing): LOG-001 already passes or does not apply
# sysctl-hardening (unknown): KRN-002 is unknown, KRN-003 is unknown and
# KRN-004 is unknown; nothing to plan until the audit can inspect it
# unattended-upgrades (unknown): UPD-001 is unknown; nothing to plan until
# the audit can inspect it
# unattended-upgrades-install (unknown): UPD-001 is unknown; nothing to plan
# until the audit can inspect it
# paas-env-perms (unknown): SEC-001 is unknown and SEC-002 is unknown;
# nothing to plan until the audit can inspect it
# unattended-upgrades-reboot (unknown): SYS-002 is unknown, SYS-003 is
# unknown and UPD-004 is unknown; nothing to plan until the audit can
# inspect it
# admin-user (unknown): the accounts were not audited
# paas-user (unknown): the accounts were not audited
# sshd-hardening (unknown): SSH-001 is unknown, SSH-002 is unknown, SSH-003
# is unknown, SSH-004 is unknown and SSH-005 is unknown; nothing to plan
# until the audit can inspect it
# lock-default-user (unknown): USR-003 is unknown; nothing to plan until the
# audit can inspect it
# ufw-policy (unknown): NET-001 is unknown; nothing to plan until the audit
# can inspect it
# ufw-docker (passing): DKR-001 already passes or does not apply
# fail2ban-sshd (unknown): CS-010 is unknown; nothing to plan until the
# audit can inspect it

# step_docker_log_rotation  # opt in: networking, restarts docker
