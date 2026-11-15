#!/usr/bin/env bash
# snapshot.sh: print a sorted listing of the places an audit could write
# to, for the read-only scenario. Run as root, before and after an audit;
# any difference fails the scenario. It is cheap on purpose: the whole of
# /etc, Docker's metadata, lock files and caches the audit's commands know
# about, and the names in the temporary directories, not the whole disk.
#
# Each line is "type mode owner size mtime path", plus a content hash for
# regular files under /etc and apt's caches.
set -euo pipefail
export LC_ALL=C

meta() { find "$@" -printf '%y %m %u:%g %s %T@ %p\n' 2>/dev/null || true; }

{
	# /etc: every entry (a new or removed file changes its directory too)
	# and the content of every regular file.
	meta /etc -xdev
	find /etc -xdev -type f -print0 | xargs -0 -r sha256sum | sed 's/^/sha256 /'

	# Docker's metadata: container configs, networks, volumes, images.
	# Excluded: overlay2 (layer contents, written by the processes inside
	# running containers), container json logs (container stdout, written by
	# dockerd) and buildkit. stackward talks to Docker with GET requests only
	# and never reads either.
	if [ -d /var/lib/docker ]; then
		find /var/lib/docker -xdev \
			\( -path /var/lib/docker/overlay2 -o -path /var/lib/docker/buildkit \
			-o -name '*-json.log' -o -name '*-json.log.*' \) -prune \
			-o -printf '%y %m %u:%g %s %T@ %p\n'
	fi

	# Lock files the audit's commands could take: xtables (iptables-legacy),
	# ufw, dpkg and apt. An flock does not change them; opening one for
	# writing with O_TRUNC, or creating one, does.
	meta /run -maxdepth 1 -name '*.lock'
	meta /run/lock -maxdepth 1
	meta /var/lib/dpkg -maxdepth 1 -name 'lock*'
	meta /var/lib/dpkg/status /var/lib/dpkg/triggers/Lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock
	# apt's binary caches: the simulated upgrade must not rewrite them.
	meta /var/cache/apt -maxdepth 1
	find /var/cache/apt -maxdepth 1 -type f -name '*.bin' -print0 | xargs -0 -r sha256sum | sed 's/^/sha256 /'
	# sshd -T checks /run/sshd and must not create it.
	meta /run/sshd -maxdepth 0
	# lastlog reads this; it must stay as it was.
	meta /var/log/lastlog /var/log/wtmp /var/log/btmp
	# apt writes its logs here (eipp.log.xz is the planner dump).
	meta /var/log/apt -maxdepth 1

	# Names only in the temporary directories: a command that drops a
	# temporary file shows up here. Their mtimes are left out because other
	# processes on the machine create and remove files there. Left out:
	# systemd-timedated's private temporary directories. `timedatectl show`
	# is a D-Bus query that starts systemd-timedated on demand when it is
	# not running, and systemd (not stackward) creates those directories
	# for the service (PrivateTmp) until it exits when idle.
	find /tmp /var/tmp /dev/shm -maxdepth 1 -mindepth 1 \
		-not -name 'systemd-private-*-systemd-timedated.service-*' -printf 'tmp %p\n' 2>/dev/null || true
} | sort
