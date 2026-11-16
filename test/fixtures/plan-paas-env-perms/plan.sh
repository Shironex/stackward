#!/bin/sh
# stackward plan as a shell script (stackward.plan.v1, stackward test).
# Host: sha256:b819aad7f7091fd8  Ubuntu 24.04.1 LTS. Source: facts file, report by stackward test, facts from 2026-03-01T12:00:00Z.
#
# stackward never runs this script. Read every step, then run it as root
# on the host it was planned for. Each step first checks that the files
# it changes still hold what the audit saw, and stops otherwise. Opt in
# steps are commented out at the bottom: remove the "# " to run one.
set -eu

# 1/1 paas-env-perms [networking] fixes SEC-001, SEC-002
# Keep platform .env files closed to group and others with a systemd timer (workaround)
# Note: A workaround, not a fix: the platform writes its .env files again on
# every deploy. This installs stackward-paas-env-perms.service and .timer,
# which every minute and at boot remove the group and other permission bits
# of those files with chmod. It never reads, copies or logs their contents
# and never changes their owner. After a deploy a file can stay open for up
# to a minute.
# Note: Off by default: apply runs it only when you name it (--step
# paas-env-perms). Remove it with one command, stackward undo --run RUN_ID,
# which stops the timer and removes the three unit files.
# Note: Coolify: app and service .env files owned by root or by uid 9999
# (the user Coolify's container runs as and its installer gives
# /data/coolify to) become owner only (chmod go-rwx); the owner keeps
# reading and writing them, and root reads any mode.
# Note: Coolify mounts /data/coolify/source/.env into its container, which
# reads it as uid 9999: the timer changes it only while uid 9999 owns it,
# and keeps the owner's and group's read bits (chmod g-w,o-rwx).
# Note: An app container that bind mounts its .env and reads it as another
# user than the file's owner loses access at its next start; apps that get
# their variables through compose (env_file, what both platforms generate)
# are not affected. Check your apps after the next deploy.
# Note: Left alone, because the platform does not write files as their
# owner: /data/coolify/applications/d4e5f6/.env.production (uid 1000). They
# stay reported; close them by hand once you know who reads them.
# Undo: Stop the timer, remove the service, the timer and the timers.target
# drop-in, and reload systemd. Files the timer already closed keep their
# modes; undo never opens them again.
#   systemctl stop stackward-paas-env-perms.timer
#   rm -f /etc/systemd/system/stackward-paas-env-perms.service /etc/systemd/system/stackward-paas-env-perms.timer /etc/systemd/system/timers.target.d/90-stackward-paas-env-perms.conf
#   systemctl daemon-reload
step_paas_env_perms() {
	# create /etc/systemd/system/stackward-paas-env-perms.service (0644)
	if [ -e /etc/systemd/system/stackward-paas-env-perms.service ]; then
		echo 'stackward: /etc/systemd/system/stackward-paas-env-perms.service exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/systemd/system
	cat > /etc/systemd/system/stackward-paas-env-perms.service.stackward-new <<'STACKWARD_EOF'
# Written by stackward: plan step paas-env-perms. A workaround, not a fix:
# Coolify and Dokploy write their .env files again on every deploy, often
# readable by group and others. stackward undo --run RUN_ID removes all three
# units (stackward-paas-env-perms.service, .timer and the timers.target.d
# drop-in); by hand: systemctl stop stackward-paas-env-perms.timer, remove the
# three files, systemctl daemon-reload.
# This service only removes group and other permission bits (chmod) of
# those files. It never opens them, so it never reads, copies or logs a
# value, and it never changes an owner.
[Unit]
Description=stackward: close platform .env files to group and others (chmod only)
Documentation=https://github.com/Shironex/stackward/blob/main/docs/plan.md

[Service]
Type=oneshot
ExecStart=/usr/bin/find /data/coolify/applications -xdev -ignore_readdir_race -maxdepth 4 -type f ( -name .env -o -name .env.* ) ! -name .env.example ! -name .env.sample ! -name .env.template ! -name .env.dist ! -name .env.defaults ( -uid 0 -o -uid 9999 ) -perm /077 -exec chmod go-rwx {} +
ExecStart=/usr/bin/find /data/coolify/services -xdev -ignore_readdir_race -maxdepth 4 -type f ( -name .env -o -name .env.* ) ! -name .env.example ! -name .env.sample ! -name .env.template ! -name .env.dist ! -name .env.defaults ( -uid 0 -o -uid 9999 ) -perm /077 -exec chmod go-rwx {} +
ExecStart=/usr/bin/find /data/coolify/source/.env -maxdepth 0 -type f -uid 9999 -perm /027 -exec chmod g-w,o-rwx {} +
NoNewPrivileges=yes
PrivateNetwork=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=-/data/coolify/applications -/data/coolify/services -/data/coolify/source/.env
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_FOWNER
STACKWARD_EOF
	chmod 0644 /etc/systemd/system/stackward-paas-env-perms.service.stackward-new
	mv /etc/systemd/system/stackward-paas-env-perms.service.stackward-new /etc/systemd/system/stackward-paas-env-perms.service
	# create /etc/systemd/system/stackward-paas-env-perms.timer (0644)
	if [ -e /etc/systemd/system/stackward-paas-env-perms.timer ]; then
		echo 'stackward: /etc/systemd/system/stackward-paas-env-perms.timer exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/systemd/system
	cat > /etc/systemd/system/stackward-paas-env-perms.timer.stackward-new <<'STACKWARD_EOF'
# Written by stackward: plan step paas-env-perms. A workaround, not a fix:
# Coolify and Dokploy write their .env files again on every deploy, often
# readable by group and others. stackward undo --run RUN_ID removes all three
# units (stackward-paas-env-perms.service, .timer and the timers.target.d
# drop-in); by hand: systemctl stop stackward-paas-env-perms.timer, remove the
# three files, systemctl daemon-reload.
[Unit]
Description=stackward: close platform .env files every minute
Documentation=https://github.com/Shironex/stackward/blob/main/docs/plan.md

[Timer]
OnActiveSec=30s
OnUnitActiveSec=1min
AccuracySec=5s
STACKWARD_EOF
	chmod 0644 /etc/systemd/system/stackward-paas-env-perms.timer.stackward-new
	mv /etc/systemd/system/stackward-paas-env-perms.timer.stackward-new /etc/systemd/system/stackward-paas-env-perms.timer
	# create /etc/systemd/system/timers.target.d/90-stackward-paas-env-perms.conf (0644)
	if [ -e /etc/systemd/system/timers.target.d/90-stackward-paas-env-perms.conf ]; then
		echo 'stackward: /etc/systemd/system/timers.target.d/90-stackward-paas-env-perms.conf exists, the plan expected it absent; plan again' >&2
		exit 1
	fi
	mkdir -p /etc/systemd/system/timers.target.d
	cat > /etc/systemd/system/timers.target.d/90-stackward-paas-env-perms.conf.stackward-new <<'STACKWARD_EOF'
# Written by stackward: plan step paas-env-perms. A workaround, not a fix:
# Coolify and Dokploy write their .env files again on every deploy, often
# readable by group and others. stackward undo --run RUN_ID removes all three
# units (stackward-paas-env-perms.service, .timer and the timers.target.d
# drop-in); by hand: systemctl stop stackward-paas-env-perms.timer, remove the
# three files, systemctl daemon-reload.
# Starts stackward-paas-env-perms.timer at boot.
[Unit]
Wants=stackward-paas-env-perms.timer
STACKWARD_EOF
	chmod 0644 /etc/systemd/system/timers.target.d/90-stackward-paas-env-perms.conf.stackward-new
	mv /etc/systemd/system/timers.target.d/90-stackward-paas-env-perms.conf.stackward-new /etc/systemd/system/timers.target.d/90-stackward-paas-env-perms.conf
	# load the new units
	systemctl daemon-reload
	# close the open .env files once now (chmod only; a failure stops the run here)
	systemctl start stackward-paas-env-perms.service
	# start the timer that repeats it every minute; the timers.target drop-in starts it at boot
	systemctl start stackward-paas-env-perms.timer
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
# unattended-upgrades-reboot (unknown): UPD-004 is unknown; nothing to plan
# until the audit can inspect it
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
# fail2ban-sshd (unknown): CS-010 is unknown; nothing to plan until the
# audit can inspect it

# step_paas_env_perms  # opt in: networking, restarts nothing
