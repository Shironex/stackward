#!/bin/sh
# stackward plan as a shell script (stackward.plan.v1, stackward test).
# Host: sha256:ce3272f20761ac2e  Ubuntu 24.04.1 LTS. Source: facts file, report by stackward test, facts from 2026-03-01T12:00:00Z.
#
# stackward never runs this script. Read every step, then run it as root
# on the host it was planned for. Each step first checks that the files
# it changes still hold what the audit saw, and stops otherwise. Opt in
# steps are commented out at the bottom: remove the "# " to run one.
set -eu

# Not planned:
# journald-cap (passing): LOG-001 already passes or does not apply
# sysctl-hardening (passing): KRN-002, KRN-003 and KRN-004 already pass or
# do not apply
# unattended-upgrades (unknown): UPD-001 is unknown; nothing to plan until
# the audit can inspect it
# unattended-upgrades-install (unknown): UPD-001 is unknown; nothing to plan
# until the audit can inspect it
# docker-log-rotation (passing): DKR-031 already passes or does not apply
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

echo "stackward: the plan has no steps; nothing to do"
