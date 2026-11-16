#!/bin/sh
# stackward plan as a shell script (stackward.plan.v1, stackward test).
# Host: sha256:207e1223ba6275be  Ubuntu 24.04.1 LTS. Source: facts file, report by stackward test, facts from 2026-03-01T12:00:00Z.
#
# stackward never runs this script. Read every step, then run it as root
# on the host it was planned for. Each step first checks that the files
# it changes still hold what the audit saw, and stops otherwise. Opt in
# steps are commented out at the bottom: remove the "# " to run one.
set -eu

# 1/2 unattended-upgrades-reboot [networking] fixes SYS-003
# Let unattended-upgrades reboot at 04:00 (host time) when an update needs it
# Note: This is the reboot decision. stackward apply never reboots the host:
# this step only writes a setting. With it, unattended-upgrades reboots the
# host at 04:00 host time after a run that leaves /var/run/reboot-required.
# Without it, automatic reboot stays off and reboots wait for you.
# Note: Logged in users do not hold the reboot back
# (Unattended-Upgrade::Automatic-Reboot-WithUsers is true unless set
# otherwise).
# Note: The running kernel is older than the newest installed one (SYS-003),
# but no reboot is marked pending, so unattended-upgrades will not reboot
# for it; reboot by hand once.
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

# 2/2 ufw-docker [access-critical] fixes DKR-001
# Filter published container ports with UFW (ufw-docker rules)
# Note: Published container ports become filtered: new connections from
# outside the private ranges to any container are dropped unless a UFW route
# rule (ufw route allow) allows the container port. Containers you publish
# later are closed too until you add a route rule.
# Note: Closes to the internet: 0.0.0.0:5432->5432/tcp (shared-db).
# Note: Stays reachable: 0.0.0.0:8000->8080/tcp (coolify) from anywhere
# (route allow 8080/tcp from anywhere), 0.0.0.0:80->80/tcp (coolify-proxy)
# from anywhere (route allow 80/tcp from anywhere), 0.0.0.0:443->443/tcp
# (coolify-proxy) from anywhere (route allow 443/tcp from anywhere); every
# published port from the tailnet (route allow on tailscale0); every
# published port from the private ranges 10.0.0.0/8, 172.16.0.0/12 and
# 192.168.0.0/16 (the ufw-docker rules let them through, so a provider's
# private network keeps access); ports published on 127.0.0.1 and
# connections made on this host.
# Note: The PaaS panel ports stay public because the paas-panel profile does
# not move the panel behind a tunnel or the tailnet; PAAS-003 still warns.
# Plan with --profile tunnel or tailnet-only to close them.
# Note: Route rules match the container port (after Docker's DNAT), so a
# rule for 443 opens 443 of every container that publishes it.
# Note: The rules are the published ufw-docker block for
# /etc/ufw/after.rules, written by stackward and test loaded with
# iptables-restore --test before UFW reloads; no script or package is
# downloaded. They cover IPv4 only; after6.rules is not changed.
# Note: ip_forward and Docker's firewall settings are left alone. Docker
# keeps DOCKER-USER across restarts, and UFW loads the block at boot before
# Docker starts.
# Undo: Restore after.rules and the UFW rules from the backup, empty
# DOCKER-USER back to what Docker put there, reload UFW and delete
# ufw-docker's logging chain: published ports are reachable as before.
#   iptables -F DOCKER-USER
#   iptables -A DOCKER-USER -j RETURN
#   ufw reload
#   iptables -F ufw-docker-logging-deny
#   iptables -X ufw-docker-logging-deny
step_ufw_docker() {
	# replace /etc/ufw/user.rules; the diff is in the plan
	if ! echo '64d55d19ffb2207201a55d6f0f6c7558153a7b72a253836492b3290f08c3a98f  /etc/ufw/user.rules' | sha256sum -c --status -; then
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

### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0
-A ufw-user-input -i tailscale0 -j ACCEPT

### tuple ### route:allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-forward -p tcp --dport 8080 -j ACCEPT

### tuple ### route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-forward -p tcp --dport 80 -j ACCEPT

### tuple ### route:allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-forward -p tcp --dport 443 -j ACCEPT

### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0
-A ufw-user-forward -i tailscale0 -j ACCEPT

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
	# replace /etc/ufw/after.rules; the diff is in the plan
	if ! echo 'c1be61c17e850ea16dc5a02be22e0ec79b631904c2383353da360bce2dfc6b64  /etc/ufw/after.rules' | sha256sum -c --status -; then
		echo 'stackward: /etc/ufw/after.rules changed since the audit; plan again' >&2
		exit 1
	fi
	[ -e /etc/ufw/after.rules.orig ] || cp -p /etc/ufw/after.rules /etc/ufw/after.rules.orig
	cp -p /etc/ufw/after.rules /etc/ufw/after.rules.stackward-new
	cat > /etc/ufw/after.rules.stackward-new <<'STACKWARD_EOF'
#
# rules.input-after
#
# Rules that should be run after the ufw command line added rules. Custom
# rules should be added to one of these chains:
#   ufw-after-input
#   ufw-after-output
#   ufw-after-forward
#

# Don't delete these required lines, otherwise there will be errors
*filter
:ufw-after-input - [0:0]
:ufw-after-output - [0:0]
:ufw-after-forward - [0:0]
# End required lines

# don't log noisy services by default
-A ufw-after-input -p udp --dport 137 -j ufw-skip-to-policy-input
-A ufw-after-input -p udp --dport 138 -j ufw-skip-to-policy-input
-A ufw-after-input -p tcp --dport 139 -j ufw-skip-to-policy-input
-A ufw-after-input -p tcp --dport 445 -j ufw-skip-to-policy-input
-A ufw-after-input -p udp --dport 67 -j ufw-skip-to-policy-input
-A ufw-after-input -p udp --dport 68 -j ufw-skip-to-policy-input

# don't log noisy broadcast
-A ufw-after-input -m addrtype --dst-type BROADCAST -j ufw-skip-to-policy-input

# don't delete the 'COMMIT' line or these rules won't be processed
COMMIT

# BEGIN UFW AND DOCKER
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
# END UFW AND DOCKER
STACKWARD_EOF
	if ! iptables-restore --test --noflush /etc/ufw/after.rules.stackward-new; then
		rm -f /etc/ufw/after.rules.stackward-new
		echo 'stackward: the new /etc/ufw/after.rules failed validation; nothing was changed' >&2
		exit 1
	fi
	mv /etc/ufw/after.rules.stackward-new /etc/ufw/after.rules
	# load after.rules with the ufw-docker block and the route rules
	ufw reload
}

# Not planned:
# journald-cap (passing): LOG-001 already passes or does not apply
# sysctl-hardening (passing): KRN-002, KRN-003 and KRN-004 already pass or
# do not apply
# unattended-upgrades (passing): UPD-001 already passes or does not apply
# unattended-upgrades-install (passing): UPD-001 already passes or does not
# apply
# docker-log-rotation (passing): DKR-031 already passes or does not apply
# paas-env-perms (passing): SEC-001 and SEC-002 already pass or do not apply
# admin-user (passing): an admin account besides root and the cloud default
# exists (alice)
# paas-user (manual): the platform logs in as root unless it has its own
# account; name one with stackward plan --paas-user NAME
# sshd-hardening (passing): SSH-001, SSH-002, SSH-003, SSH-004 and SSH-005
# already pass or do not apply
# lock-default-user (passing): USR-003 already passes or does not apply
# ufw-policy (passing): NET-001 already passes or does not apply
# fail2ban-sshd (passing): CS-010 already passes or does not apply

# step_unattended_upgrades_reboot  # opt in: networking, restarts nothing
# step_ufw_docker  # opt in: access-critical, restarts nothing
