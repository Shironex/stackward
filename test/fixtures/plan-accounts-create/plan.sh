#!/bin/sh
# stackward plan as a shell script (stackward.plan.v1, stackward test).
# Host: sha256:82c1a34869ebe223  Ubuntu 24.04.1 LTS. Source: facts file, report by stackward test, facts from 2026-03-01T12:00:00Z.
#
# stackward never runs this script. Read every step, then run it as root
# on the host it was planned for. Each step first checks that the files
# it changes still hold what the audit saw, and stops otherwise. Opt in
# steps are commented out at the bottom: remove the "# " to run one.
set -eu

# 1/2 admin-user [access-critical] fixes SSH-003, USR-003
# Create an admin account with sudo and the keys of an existing account
# Note: ops gets sudo without a password (NOPASSWD), like the cloud image's
# default account; USR-004 lists it. Set a password and drop NOPASSWD later
# if you prefer.
# Note: Prove it before you confirm: open a new SSH session as ops with the
# key of ubuntu and run sudo stackward confirm from there.
# Note: lock-default-user is planned once a session of this account applies
# it.
# Undo: Remove the sudoers drop-in and delete the account ops with its home
# and group (userdel --remove). Anything saved in that home is deleted with
# it.
#   rm -f /etc/sudoers.d/90-stackward-ops
#   userdel --remove ops
step_admin_user() {
	# create /etc/sudoers.d/90-stackward-ops (0440)
	if [ -e /etc/sudoers.d/90-stackward-ops ]; then
		echo 'stackward: /etc/sudoers.d/90-stackward-ops exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/sudoers.d
	cat > /etc/sudoers.d/90-stackward-ops.stackward-new <<'STACKWARD_EOF'
# Written by stackward: plan step admin-user, the admin account.
# NOPASSWD because the account has no password; stackward never sets one.
# Remove this file to take the rights away.
ops ALL=(ALL:ALL) NOPASSWD: ALL
STACKWARD_EOF
	chmod 0440 /etc/sudoers.d/90-stackward-ops.stackward-new
	if ! visudo -c -f /etc/sudoers.d/90-stackward-ops.stackward-new; then
		rm -f /etc/sudoers.d/90-stackward-ops.stackward-new
		echo 'stackward: the new /etc/sudoers.d/90-stackward-ops failed validation; nothing was changed' >&2
		exit 1
	fi
	mv /etc/sudoers.d/90-stackward-ops.stackward-new /etc/sudoers.d/90-stackward-ops
	# create the account with a home and its own group; its password stays locked
	useradd --create-home --home-dir /home/ops --user-group --shell /bin/bash ops
	# create ~/.ssh, owned by the account, mode 0700
	install -d -m 0700 -o ops -g ops /home/ops/.ssh
	# copy the authorized keys of ubuntu on the host, so no key passes through the plan
	install -m 0600 -o ops -g ops /home/ubuntu/.ssh/authorized_keys /home/ops/.ssh/authorized_keys
}

# 2/2 sshd-hardening [access-critical] fixes SSH-001, SSH-003, SSH-005
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
# paas-user (passing): no platform (Coolify, Dokploy) was found; a PaaS
# account is only for one
# lock-default-user (passing): USR-003 already passes or does not apply
# ufw-policy (unknown): NET-001 is unknown; nothing to plan until the audit
# can inspect it
# fail2ban-sshd (unknown): CS-010 is unknown; nothing to plan until the
# audit can inspect it

step_admin_user
step_sshd_hardening
