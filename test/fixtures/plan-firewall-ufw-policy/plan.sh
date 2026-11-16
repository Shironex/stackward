#!/bin/sh
# stackward plan as a shell script (stackward.plan.v1, stackward test).
# Host: sha256:88fcffd365f6d89e  Ubuntu 24.04.1 LTS. Source: facts file, report by stackward test, facts from 2026-03-01T12:00:00Z.
#
# stackward never runs this script. Read every step, then run it as root
# on the host it was planned for. Each step first checks that the files
# it changes still hold what the audit saw, and stops otherwise. Opt in
# steps are commented out at the bottom: remove the "# " to run one.
set -eu

# 1/1 ufw-policy [access-critical] fixes NET-001
# Turn UFW on with a default deny incoming policy
# Note: Turns UFW on with default deny incoming. The allow rules (allow in
# 22/tcp from anywhere; allow in 2222/tcp from anywhere; allow in on
# tailscale0; allow in 22/tcp from anywhere (v6); allow in 2222/tcp from
# anywhere (v6); allow in on tailscale0 (v6)) are written to UFW's rules
# files before the policy loads, and load with it in one step.
# Note: Closes to the internet (the default deny drops new connections to
# them): tcp/5432 (postgres). Allow one with `ufw allow` before applying if
# it must stay public.
# Note: Published container ports are not affected: Docker forwards them
# past UFW's input rules (DKR-001). The ufw-docker step filters them.
# Note: Containers that connect to a service on the host itself
# (host.docker.internal, the bridge gateway) go through UFW's input rules
# too, and close unless a rule allows them.
# Note: Connections that are already open, this SSH session among them, stay
# up: UFW accepts established traffic.
# Note: UFW's forward policy, ip_forward, Docker's firewall settings and
# /etc/ufw/sysctl.conf are left as they are.
# Undo: Restore the UFW files the step changed from the backup and turn UFW
# off again (ufw disable), as it was before.
#   ufw disable
step_ufw_policy() {
	# replace /etc/ufw/user.rules; the diff is in the plan
	if ! echo '320f53e1ee90a7fd92f17b67f50b06b51cb20998cd52f01dbcb52e24160618bf  /etc/ufw/user.rules' | sha256sum -c --status -; then
		echo 'stackward: /etc/ufw/user.rules changed since the audit; plan again' >&2
		exit 1
	fi
	[ -e /etc/ufw/user.rules.orig ] || cp -p /etc/ufw/user.rules /etc/ufw/user.rules.orig
	cp -p /etc/ufw/user.rules /etc/ufw/user.rules.stackward-new
	cat > /etc/ufw/user.rules.stackward-new <<'STACKWARD_EOF'
*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
:ufw-before-logging-input - [0:0]
:ufw-before-logging-output - [0:0]
:ufw-before-logging-forward - [0:0]
:ufw-user-logging-input - [0:0]
:ufw-user-logging-output - [0:0]
:ufw-user-logging-forward - [0:0]
:ufw-after-logging-input - [0:0]
:ufw-after-logging-output - [0:0]
:ufw-after-logging-forward - [0:0]
:ufw-logging-deny - [0:0]
:ufw-logging-allow - [0:0]
:ufw-user-limit - [0:0]
:ufw-user-limit-accept - [0:0]
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### allow tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 2222 -j ACCEPT

### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0
-A ufw-user-input -i tailscale0 -j ACCEPT

### END RULES ###

### LOGGING ###
-A ufw-after-logging-input -j LOG --log-prefix "[UFW BLOCK] " -m limit --limit 3/min --limit-burst 10
-A ufw-after-logging-forward -j LOG --log-prefix "[UFW BLOCK] " -m limit --limit 3/min --limit-burst 10
-I ufw-logging-deny -m conntrack --ctstate INVALID -j RETURN -m limit --limit 3/min --limit-burst 10
-A ufw-logging-deny -j LOG --log-prefix "[UFW BLOCK] " -m limit --limit 3/min --limit-burst 10
-A ufw-logging-allow -j LOG --log-prefix "[UFW ALLOW] " -m limit --limit 3/min --limit-burst 10
### END LOGGING ###

### RATE LIMITING ###
-A ufw-user-limit -m limit --limit 3/minute -j LOG --log-prefix "[UFW LIMIT BLOCK] "
-A ufw-user-limit -j REJECT
-A ufw-user-limit-accept -j ACCEPT
### END RATE LIMITING ###
COMMIT
STACKWARD_EOF
	if ! iptables-restore --test --noflush /etc/ufw/user.rules.stackward-new; then
		rm -f /etc/ufw/user.rules.stackward-new
		echo 'stackward: the new /etc/ufw/user.rules failed validation; nothing was changed' >&2
		exit 1
	fi
	mv /etc/ufw/user.rules.stackward-new /etc/ufw/user.rules
	# replace /etc/ufw/user6.rules; the diff is in the plan
	if ! echo 'f6696cd7741aada36ab2055dd1a9d098e23e0290ca3a67dafbbad2920e5fdf60  /etc/ufw/user6.rules' | sha256sum -c --status -; then
		echo 'stackward: /etc/ufw/user6.rules changed since the audit; plan again' >&2
		exit 1
	fi
	[ -e /etc/ufw/user6.rules.orig ] || cp -p /etc/ufw/user6.rules /etc/ufw/user6.rules.orig
	cp -p /etc/ufw/user6.rules /etc/ufw/user6.rules.stackward-new
	cat > /etc/ufw/user6.rules.stackward-new <<'STACKWARD_EOF'
*filter
:ufw6-user-input - [0:0]
:ufw6-user-output - [0:0]
:ufw6-user-forward - [0:0]
:ufw6-before-logging-input - [0:0]
:ufw6-before-logging-output - [0:0]
:ufw6-before-logging-forward - [0:0]
:ufw6-user-logging-input - [0:0]
:ufw6-user-logging-output - [0:0]
:ufw6-user-logging-forward - [0:0]
:ufw6-after-logging-input - [0:0]
:ufw6-after-logging-output - [0:0]
:ufw6-after-logging-forward - [0:0]
:ufw6-logging-deny - [0:0]
:ufw6-logging-allow - [0:0]
:ufw6-user-limit - [0:0]
:ufw6-user-limit-accept - [0:0]
### RULES ###

### tuple ### allow tcp 22 ::/0 any ::/0 in
-A ufw6-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### allow tcp 2222 ::/0 any ::/0 in
-A ufw6-user-input -p tcp --dport 2222 -j ACCEPT

### tuple ### allow any any ::/0 any ::/0 in_tailscale0
-A ufw6-user-input -i tailscale0 -j ACCEPT

### END RULES ###

### LOGGING ###
-A ufw6-after-logging-input -j LOG --log-prefix "[UFW BLOCK] " -m limit --limit 3/min --limit-burst 10
-A ufw6-after-logging-forward -j LOG --log-prefix "[UFW BLOCK] " -m limit --limit 3/min --limit-burst 10
-I ufw6-logging-deny -m conntrack --ctstate INVALID -j RETURN -m limit --limit 3/min --limit-burst 10
-A ufw6-logging-deny -j LOG --log-prefix "[UFW BLOCK] " -m limit --limit 3/min --limit-burst 10
-A ufw6-logging-allow -j LOG --log-prefix "[UFW ALLOW] " -m limit --limit 3/min --limit-burst 10
### END LOGGING ###

### RATE LIMITING ###
-A ufw6-user-limit -m limit --limit 3/minute -j LOG --log-prefix "[UFW LIMIT BLOCK] "
-A ufw6-user-limit -j REJECT
-A ufw6-user-limit-accept -j ACCEPT
### END RATE LIMITING ###
COMMIT
STACKWARD_EOF
	if ! ip6tables-restore --test --noflush /etc/ufw/user6.rules.stackward-new; then
		rm -f /etc/ufw/user6.rules.stackward-new
		echo 'stackward: the new /etc/ufw/user6.rules failed validation; nothing was changed' >&2
		exit 1
	fi
	mv /etc/ufw/user6.rules.stackward-new /etc/ufw/user6.rules
	# replace /etc/ufw/ufw.conf; the diff is in the plan
	if ! echo '1c75b26d27f47cb59a4383a0b07b479d4b3493d34c4eed165b1e1860fe5ccf39  /etc/ufw/ufw.conf' | sha256sum -c --status -; then
		echo 'stackward: /etc/ufw/ufw.conf changed since the audit; plan again' >&2
		exit 1
	fi
	[ -e /etc/ufw/ufw.conf.orig ] || cp -p /etc/ufw/ufw.conf /etc/ufw/ufw.conf.orig
	cp -p /etc/ufw/ufw.conf /etc/ufw/ufw.conf.stackward-new
	cat > /etc/ufw/ufw.conf.stackward-new <<'STACKWARD_EOF'
# /etc/ufw/ufw.conf
#

# Set to yes to start on boot. If setting this remotely, be sure to add a rule
# to allow your remote connection before starting ufw. Eg: 'ufw allow 22/tcp'
ENABLED=yes

# Please use the 'ufw' command to set the loglevel. Eg: 'ufw logging medium'.
# See 'man ufw' for details.
LOGLEVEL=low
STACKWARD_EOF
	mv /etc/ufw/ufw.conf.stackward-new /etc/ufw/ufw.conf
	# turn UFW on: load the rules and the default deny together
	ufw --force enable
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
# docker-log-rotation (passing): DKR-031 already passes or does not apply
# unattended-upgrades-reboot (unknown): the updates facts are missing
# (planning from a report alone, or the updates collector did not run)
# admin-user (passing): an admin account besides root and the cloud default
# exists (alice)
# paas-user (unknown): the platform facts are missing (the paas collector
# did not run)
# sshd-hardening (passing): SSH-001, SSH-002, SSH-003, SSH-004 and SSH-005
# already pass or do not apply
# lock-default-user (passing): USR-003 already passes or does not apply
# fail2ban-sshd (unknown): CS-010 is unknown; nothing to plan until the
# audit can inspect it

step_ufw_policy
