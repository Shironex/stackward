#!/bin/sh
# stackward plan as a shell script (stackward.plan.v1, stackward test).
# Host: sha256:d00ceb917a38767f  Ubuntu 24.04.1 LTS. Source: facts file, report by stackward test, facts from 2026-03-01T12:00:00Z.
#
# stackward never runs this script. Read every step, then run it as root
# on the host it was planned for. Each step first checks that the files
# it changes still hold what the audit saw, and stops otherwise. Opt in
# steps are commented out at the bottom: remove the "# " to run one.
set -eu

# 1/3 unattended-upgrades-install [safe] fixes UPD-001
# Install unattended-upgrades and turn it on with an apt.conf.d drop-in
# Note: Installs the unattended-upgrades package (and what it depends on)
# from the configured apt sources with apt-get install. Nothing else is
# upgraded on purpose, but apt may upgrade a dependency the package needs.
# If the package lists are old, run apt update first, or the install fails
# and nothing else changes.
# Note: Reboot decision: automatic reboot stays off, so updates that need a
# reboot (a kernel, libc) wait for you and SYS-002 reports them. To let
# unattended-upgrades reboot at 04:00 (host time) instead, apply the opt in
# step unattended-upgrades-reboot.
# Note: Only the origins allowed in 50unattended-upgrades are installed;
# UPD-003 checks that the security pocket is among them.
# Note: A file that sorts after 90stackward-unattended-upgrades in
# /etc/apt/apt.conf.d can still turn it off; the next audit's UPD-001 says
# so.
# Undo: Remove the drop-in; unattended-upgrades then follows the
# distribution's own settings again. The package is purged; packages apt
# installed with it stay.
#   rm -f /etc/apt/apt.conf.d/90stackward-unattended-upgrades
#   env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 purge -y unattended-upgrades
step_unattended_upgrades_install() {
	# create /etc/apt/apt.conf.d/90stackward-unattended-upgrades (0644)
	if [ -e /etc/apt/apt.conf.d/90stackward-unattended-upgrades ]; then
		echo 'stackward: /etc/apt/apt.conf.d/90stackward-unattended-upgrades exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/apt/apt.conf.d
	cat > /etc/apt/apt.conf.d/90stackward-unattended-upgrades.stackward-new <<'STACKWARD_EOF'
// Written by stackward: plan step unattended-upgrades, fixes UPD-001.
// Turns on the daily package list update and unattended-upgrades.
// Remove this file to undo.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
STACKWARD_EOF
	chmod 0644 /etc/apt/apt.conf.d/90stackward-unattended-upgrades.stackward-new
	if ! apt-config dump -c /etc/apt/apt.conf.d/90stackward-unattended-upgrades.stackward-new; then
		rm -f /etc/apt/apt.conf.d/90stackward-unattended-upgrades.stackward-new
		echo 'stackward: the new /etc/apt/apt.conf.d/90stackward-unattended-upgrades failed validation; nothing was changed' >&2
		exit 1
	fi
	mv /etc/apt/apt.conf.d/90stackward-unattended-upgrades.stackward-new /etc/apt/apt.conf.d/90stackward-unattended-upgrades
	# install unattended-upgrades (named here so nothing is installed silently)
	env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y unattended-upgrades
}

# 2/3 unattended-upgrades-reboot [networking] fixes UPD-004
# Let unattended-upgrades reboot at 04:00 (host time) when an update needs it
# Note: This is the reboot decision. stackward apply never reboots the host:
# this step only writes a setting. With it, unattended-upgrades reboots the
# host at 04:00 host time after a run that leaves /var/run/reboot-required.
# Without it, automatic reboot stays off and reboots wait for you.
# Note: Logged in users do not hold the reboot back
# (Unattended-Upgrade::Automatic-Reboot-WithUsers is true unless set
# otherwise).
# Note: unattended-upgrades is not installed: this setting takes effect once
# it is (the opt in step unattended-upgrades-install).
# Undo: Remove the drop-in; automatic reboot is off again and reboots wait
# for you.
#   rm -f /etc/apt/apt.conf.d/91stackward-automatic-reboot
step_unattended_upgrades_reboot() {
	# create /etc/apt/apt.conf.d/91stackward-automatic-reboot (0644)
	if [ -e /etc/apt/apt.conf.d/91stackward-automatic-reboot ]; then
		echo 'stackward: /etc/apt/apt.conf.d/91stackward-automatic-reboot exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/apt/apt.conf.d
	cat > /etc/apt/apt.conf.d/91stackward-automatic-reboot.stackward-new <<'STACKWARD_EOF'
// Written by stackward: plan step unattended-upgrades-reboot.
// Lets unattended-upgrades reboot the host at 04:00 (host time)
// when an update needs a reboot. Remove this file to undo.
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
STACKWARD_EOF
	chmod 0644 /etc/apt/apt.conf.d/91stackward-automatic-reboot.stackward-new
	if ! apt-config dump -c /etc/apt/apt.conf.d/91stackward-automatic-reboot.stackward-new; then
		rm -f /etc/apt/apt.conf.d/91stackward-automatic-reboot.stackward-new
		echo 'stackward: the new /etc/apt/apt.conf.d/91stackward-automatic-reboot failed validation; nothing was changed' >&2
		exit 1
	fi
	mv /etc/apt/apt.conf.d/91stackward-automatic-reboot.stackward-new /etc/apt/apt.conf.d/91stackward-automatic-reboot
}

# 3/3 fail2ban-sshd [access-critical] fixes CS-010
# Ban SSH brute force with a fail2ban sshd jail
# Restarts fail2ban.
# Note: Installs the fail2ban package (and what it depends on) from the
# configured apt sources with apt-get install. Nothing else is upgraded on
# purpose, but apt may upgrade a dependency it needs. If the package lists
# are old, run apt update first, or the install fails and the transaction
# rolls back.
# Note: No SSH client address was known when this plan was made (a saved
# facts file, or not over SSH), so only loopback, the jail's own entries and
# the tailnet are ignored. apply refuses to run the step from an SSH session
# whose address the jail would not ignore: plan again from the session you
# will apply and confirm from.
# Note: fail2ban-client -t checks the whole fail2ban configuration with the
# new file before fail2ban loads it; a failure stops the step and the
# transaction rolls back.
# Note: The jail reads sshd's log from the systemd journal (backend =
# systemd), so it works on hosts without /var/log/auth.log; apt installs the
# python3-systemd module fail2ban recommends for it.
# Undo: Remove the jail drop-in and purge fail2ban, which the step
# installed: its jails stop and every ban is lifted. Packages apt installed
# with it stay.
#   rm -f /etc/fail2ban/jail.d/90-stackward-sshd.local
#   env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 purge -y fail2ban
step_fail2ban_sshd() {
	# create /etc/fail2ban/jail.d/90-stackward-sshd.local (0644)
	if [ -e /etc/fail2ban/jail.d/90-stackward-sshd.local ]; then
		echo 'stackward: /etc/fail2ban/jail.d/90-stackward-sshd.local exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/fail2ban/jail.d
	cat > /etc/fail2ban/jail.d/90-stackward-sshd.local.stackward-new <<'STACKWARD_EOF'
# Written by stackward: plan step fail2ban-sshd, fixes CS-010.
# Bans SSH brute force on the sshd ports. Never bans loopback, the
# tailnet when Tailscale is in use, or the address the plan was made
# from. Remove this file and reload fail2ban to undo.
[sshd]
enabled = true
backend = systemd
port = 22
ignoreip = 127.0.0.1/8 ::1
STACKWARD_EOF
	chmod 0644 /etc/fail2ban/jail.d/90-stackward-sshd.local.stackward-new
	mv /etc/fail2ban/jail.d/90-stackward-sshd.local.stackward-new /etc/fail2ban/jail.d/90-stackward-sshd.local
	# install fail2ban (named here so nothing is installed silently)
	env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y fail2ban
	# check the whole fail2ban configuration with the new jail
	fail2ban-client -t
	# start fail2ban with the new jail
	systemctl restart fail2ban
}

# Not planned:
# journald-cap (unknown): LOG-001 is unknown; nothing to plan until the
# audit can inspect it
# sysctl-hardening (unknown): KRN-002 is unknown, KRN-003 is unknown and
# KRN-004 is unknown; nothing to plan until the audit can inspect it
# unattended-upgrades (passing): does not apply: unattended-upgrades is not
# installed; the opt in step unattended-upgrades-install installs it
# docker-log-rotation (unknown): DKR-031 is unknown; nothing to plan until
# the audit can inspect it
# admin-user (unknown): the accounts were not audited
# paas-user (unknown): the accounts were not audited
# sshd-hardening (unknown): SSH-001 is unknown, SSH-002 is unknown, SSH-003
# is unknown, SSH-004 is unknown and SSH-005 is unknown; nothing to plan
# until the audit can inspect it
# lock-default-user (unknown): USR-003 is unknown; nothing to plan until the
# audit can inspect it
# ufw-policy (passing): NET-001 already passes or does not apply
# ufw-docker (unknown): DKR-001 is unknown; nothing to plan until the audit
# can inspect it

# step_unattended_upgrades_install  # opt in: safe, restarts nothing
# step_unattended_upgrades_reboot  # opt in: networking, restarts nothing
# step_fail2ban_sshd  # opt in: access-critical, restarts fail2ban
