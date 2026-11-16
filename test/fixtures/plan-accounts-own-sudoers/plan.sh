#!/bin/sh
# stackward plan as a shell script (stackward.plan.v1, stackward test).
# Host: sha256:82c1a34869ebe223  Ubuntu 24.04.1 LTS. Source: facts file, report by stackward test, facts from 2026-03-01T12:00:00Z.
#
# stackward never runs this script. Read every step, then run it as root
# on the host it was planned for. Each step first checks that the files
# it changes still hold what the audit saw, and stops otherwise. Opt in
# steps are commented out at the bottom: remove the "# " to run one.
set -eu

# 1/2 sshd-hardening [access-critical] fixes SSH-001, SSH-003, SSH-005
# Allow key logins only, refuse root and limit auth tries with an early sshd drop-in
# Restarts ssh.
# Note: sshd runs under socket activation (ssh.socket); the drop-in sets no
# port or listen address, so reloading ssh.service is enough and ssh.socket
# is left alone.
# Note: Existing SSH sessions stay open. Before you confirm, log in again in
# a new session with your key: that is the proof the change works.
# Note: Ubuntu 22.04 and later and Debian 12 and later; older OpenSSH reads
# KbdInteractiveAuthentication differently.
# Undo: Remove the drop-in and reload ssh.service; the earlier values return
# for new logins.
#   rm -f /etc/ssh/sshd_config.d/00-stackward-hardening.conf
#   systemctl try-reload-or-restart ssh.service
step_sshd_hardening() {
	# create /etc/ssh/sshd_config.d/00-stackward-hardening.conf (0644)
	if [ -e /etc/ssh/sshd_config.d/00-stackward-hardening.conf ]; then
		echo 'stackward: /etc/ssh/sshd_config.d/00-stackward-hardening.conf exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/ssh/sshd_config.d
	cat > /etc/ssh/sshd_config.d/00-stackward-hardening.conf.stackward-new <<'STACKWARD_EOF'
# Written by stackward: plan step sshd-hardening, fixes SSH-001, SSH-003, SSH-005.
# Named to sort first: sshd keeps the first value it reads. Remove this
# file and reload ssh.service to undo.
PasswordAuthentication no
PermitRootLogin no
MaxAuthTries 3
STACKWARD_EOF
	chmod 0644 /etc/ssh/sshd_config.d/00-stackward-hardening.conf.stackward-new
	if ! sshd -t -f /etc/ssh/sshd_config.d/00-stackward-hardening.conf.stackward-new; then
		rm -f /etc/ssh/sshd_config.d/00-stackward-hardening.conf.stackward-new
		echo 'stackward: the new /etc/ssh/sshd_config.d/00-stackward-hardening.conf failed validation; nothing was changed' >&2
		exit 1
	fi
	mv /etc/ssh/sshd_config.d/00-stackward-hardening.conf.stackward-new /etc/ssh/sshd_config.d/00-stackward-hardening.conf
	# load the new settings; running sessions stay open
	systemctl try-reload-or-restart ssh.service
}

# 2/2 lock-default-user [access-critical] fixes USR-003
# Lock the cloud image's default account once another admin account is proven
# Note: Apply it from an SSH session of the admin account that stays (logged
# in with its key): the lockout guard refuses it from any other session, and
# from the account it locks.
# Note: Running sessions of ubuntu stay open; new logins are refused.
# Note: ubuntu keeps its NOPASSWD sudo line: taking sudo away is on the
# never touched list. Nobody can log in as ubuntu to use it, but USR-003
# keeps naming it until you remove the line by hand.
# Undo: Move the authorized keys files back, unlock the password if the step
# locked it, and put the old shell back.
#   mv -T /home/ubuntu/.ssh/authorized_keys.stackward-locked /home/ubuntu/.ssh/authorized_keys
#   usermod --shell /bin/bash ubuntu
step_lock_default_user() {
	# refuse a login shell
	usermod --shell /usr/sbin/nologin ubuntu
	# move the authorized keys aside, so no key logs in
	mv -T /home/ubuntu/.ssh/authorized_keys /home/ubuntu/.ssh/authorized_keys.stackward-locked
}

# Not planned:
# journald-cap (unknown): LOG-001 is unknown; nothing to plan until the
# audit can inspect it
# sysctl-hardening (unknown): KRN-002 is unknown, KRN-003 is unknown and
# KRN-004 is unknown; nothing to plan until the audit can inspect it
# unattended-upgrades (unknown): UPD-001 is unknown; nothing to plan until
# the audit can inspect it
# unattended-upgrades-install (unknown): UPD-001 is unknown; nothing to plan
# until the audit can inspect it
# docker-log-rotation (unknown): DKR-031 is unknown; nothing to plan until
# the audit can inspect it
# unattended-upgrades-reboot (unknown): SYS-002 is unknown, SYS-003 is
# unknown and UPD-004 is unknown; nothing to plan until the audit can
# inspect it
# admin-user (passing): an admin account besides root and the cloud default
# exists (ops)
# paas-user (passing): no platform (Coolify, Dokploy) was found; a PaaS
# account is only for one
# ufw-policy (unknown): NET-001 is unknown; nothing to plan until the audit
# can inspect it
# ufw-docker (unknown): DKR-001 is unknown; nothing to plan until the audit
# can inspect it
# fail2ban-sshd (unknown): CS-010 is unknown; nothing to plan until the
# audit can inspect it

step_sshd_hardening
step_lock_default_user
