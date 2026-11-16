#!/usr/bin/env bash
# vm.sh: boot an official cloud image in QEMU for the VM matrix.
#
#   test/vm/vm.sh resolve DISTRO     print the image's url, file and checksum
#   test/vm/vm.sh image DISTRO       download the image into the cache once, check it
#   test/vm/vm.sh boot DISTRO SEED   boot a throwaway copy, wait for SSH and
#                                    cloud-init, install $STACKWARD in it
#   test/vm/vm.sh ssh [COMMAND]      a shell (or COMMAND) as the seeded user
#   test/vm/vm.sh stop               power the VM off
#
# DISTRO: ubuntu-22.04, ubuntu-24.04, debian-12 or debian-13. SEED: users (a
# test account, swtest, with a key and sudo) or accounts (the image's own
# default account, ubuntu or debian, with the key). The VM writes only to a
# qcow2 overlay in $VM_DIR; the cached image is never changed, and SSH and
# the test web port are forwarded on 127.0.0.1 only.
#
# Environment: VM_DIR (./vm-out), VM_CACHE (~/.cache/stackward-vm),
# VM_SSH_PORT (2222), VM_HTTP_PORT (8090), VM_ACCEL (kvm when /dev/kvm is
# usable, hvf on macOS, otherwise tcg), VM_ARCH (amd64 or arm64, from the
# host), VM_MEMORY (2048), STACKWARD (the linux binary to install, built
# for VM_ARCH).
#
# Never point this at anything but a VM it booted: the scenarios change
# sshd, the firewall and accounts. See docs/testing.md.
set -euo pipefail

VM_DIR="${VM_DIR:-$PWD/vm-out}"
VM_CACHE="${VM_CACHE:-$HOME/.cache/stackward-vm}"
VM_SSH_PORT="${VM_SSH_PORT:-2222}"
VM_HTTP_PORT="${VM_HTTP_PORT:-8090}"
VM_MEMORY="${VM_MEMORY:-2048}"

log() { printf '==> %s\n' "$*"; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 2
}

host_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) die "unsupported host architecture $(uname -m)" ;;
	esac
}
VM_ARCH="${VM_ARCH:-$(host_arch)}"

# distro DISTRO: sets URL, SUMS, ALGO, FILE and DEFAULT_USER.
distro() {
	local base
	case "$1" in
	ubuntu-22.04 | ubuntu-24.04)
		local v="${1#ubuntu-}"
		base="https://cloud-images.ubuntu.com/releases/$v/release"
		FILE="ubuntu-$v-server-cloudimg-$VM_ARCH.img"
		SUMS="$base/SHA256SUMS" ALGO=256 DEFAULT_USER=ubuntu
		;;
	debian-12 | debian-13)
		local code=bookworm
		[ "$1" = debian-13 ] && code=trixie
		base="https://cloud.debian.org/images/cloud/$code/latest"
		FILE="$1-genericcloud-$VM_ARCH.qcow2"
		SUMS="$base/SHA512SUMS" ALGO=512 DEFAULT_USER=debian
		;;
	*) die "unknown distro $1 (ubuntu-22.04, ubuntu-24.04, debian-12, debian-13)" ;;
	esac
	URL="$base/$FILE"
}

# checksum DISTRO: the published checksum of the image, from the release's
# checksum file (fetched every time, so a new point release is noticed).
checksum() {
	local sum
	sum="$(curl -fsSL --retry 3 "$SUMS" | awk -v f="$FILE" '{n=$2; sub(/^\*/, "", n)} n == f {print $1}')"
	[ -n "$sum" ] || die "no checksum for $FILE in $SUMS"
	echo "$sum"
}

cmd_resolve() {
	distro "$1"
	echo "url=$URL"
	echo "file=$FILE"
	echo "sha=$(checksum)"
	echo "cache=$VM_CACHE/$1"
}

shasum_of() {
	if command -v "sha${ALGO}sum" >/dev/null; then
		"sha${ALGO}sum" "$1" | cut -d' ' -f1
	else
		shasum -a "$ALGO" "$1" | cut -d' ' -f1
	fi
}

# cmd_image DISTRO: the cached image's path, downloaded and checked first
# when missing or stale.
cmd_image() {
	distro "$1"
	local dir="$VM_CACHE/$1" want img
	want="$(checksum)"
	img="$dir/$FILE"
	mkdir -p "$dir"
	if [ -f "$img" ] && [ "$(cat "$img.sha" 2>/dev/null)" = "$want" ]; then
		log "cached image $img" >&2
	else
		log "downloading $URL" >&2
		curl -fSL --retry 3 -o "$img.part" "$URL"
		[ "$(shasum_of "$img.part")" = "$want" ] || die "checksum mismatch for $URL"
		mv "$img.part" "$img"
		echo "$want" >"$img.sha"
	fi
	echo "$img"
}

accel() {
	if [ -n "${VM_ACCEL:-}" ]; then
		echo "$VM_ACCEL"
	elif [ "$(uname -s)" = Darwin ]; then
		echo hvf
	elif [ "$VM_ARCH" = "$(host_arch)" ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
		echo kvm
	else
		echo tcg
	fi
}

# seed DIR MODE KEY USER: write the NoCloud seed (user-data, meta-data).
seed() {
	local dir="$1" mode="$2" key="$3"
	mkdir -p "$dir"
	printf 'instance-id: stackward-vm-%s\nlocal-hostname: sw-vm\n' "$(date +%s)" >"$dir/meta-data"
	{
		echo "#cloud-config"
		if [ "$mode" = accounts ]; then
			# The image's own default account, as a provider creates it.
			echo "users: [default]"
			echo "ssh_authorized_keys: [\"$key\"]"
		else
			echo "users:"
			echo "  - name: swtest"
			echo "    shell: /bin/bash"
			echo "    lock_passwd: true"
			echo "    sudo: \"ALL=(ALL) NOPASSWD:ALL\""
			echo "    ssh_authorized_keys: [\"$key\"]"
		fi
		# Debian's cloud images ship without UFW.
		echo "package_update: true"
		echo "packages: [ufw]"
	} >"$dir/user-data"
}

seed_iso() {
	local dir="$1" iso="$2"
	rm -f "$iso"
	if command -v cloud-localds >/dev/null; then
		cloud-localds "$iso" "$dir/user-data" "$dir/meta-data"
	elif command -v genisoimage >/dev/null; then
		genisoimage -quiet -output "$iso" -volid cidata -joliet -rock "$dir/user-data" "$dir/meta-data"
	elif command -v xorriso >/dev/null; then
		xorriso -as mkisofs -quiet -output "$iso" -volid cidata -joliet -rock "$dir/user-data" "$dir/meta-data"
	elif command -v hdiutil >/dev/null; then
		hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata -o "$iso" "$dir"
	else
		die "need cloud-localds, genisoimage, xorriso or hdiutil to write the cloud-init seed"
	fi
}

# firmware: UEFI firmware for arm64 guests.
firmware() {
	local f
	for f in /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd \
		"$(brew --prefix 2>/dev/null || echo /nonexistent)/share/qemu/edk2-aarch64-code.fd"; do
		[ -f "$f" ] && echo "$f" && return
	done
	die "no aarch64 UEFI firmware found (install qemu-efi-aarch64)"
}

# The host key is new on every boot of a fresh overlay, and nothing but
# this VM listens on the forwarded port, so it is not pinned.
SSH_COMMON=(-i "$VM_DIR/id_ed25519" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none)

vm_ssh() {
	# shellcheck disable=SC1091 # written by boot
	. "$VM_DIR/vm.env"
	ssh -p "$VM_SSH_PORT" "${SSH_COMMON[@]}" "$VM_USER@127.0.0.1" "$@"
}

cmd_boot() {
	[ $# -eq 2 ] || die "usage: vm.sh boot DISTRO SEED"
	local name="$1" mode="$2" img acc timeout key user qemu
	case "$mode" in users | accounts) ;; *) die "SEED is users or accounts" ;; esac
	if [ -z "${STACKWARD:-}" ] || [ ! -f "$STACKWARD" ]; then
		die "STACKWARD=${STACKWARD:-} is not the stackward binary to install"
	fi
	img="$(cmd_image "$name")"
	distro "$name"
	mkdir -p "$VM_DIR"
	[ -f "$VM_DIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C stackward-vm -f "$VM_DIR/id_ed25519"
	key="$(cat "$VM_DIR/id_ed25519.pub")"
	user=swtest
	[ "$mode" = accounts ] && user="$DEFAULT_USER"
	seed "$VM_DIR/seed" "$mode" "$key"
	seed_iso "$VM_DIR/seed" "$VM_DIR/seed.iso"
	rm -f "$VM_DIR/disk.qcow2"
	qemu-img create -q -f qcow2 -F qcow2 -b "$img" "$VM_DIR/disk.qcow2" 12G
	acc="$(accel)"
	# TCG emulates every instruction: boots and apt runs take minutes.
	timeout=300
	[ "$acc" = tcg ] && timeout=1200
	local cpu=host
	[ "$acc" = tcg ] && cpu=max
	local args=(-name stackward-vm -m "$VM_MEMORY" -smp 2 -cpu "$cpu"
		-drive "file=$VM_DIR/disk.qcow2,if=virtio,format=qcow2"
		-drive "file=$VM_DIR/seed.iso,if=virtio,format=raw,readonly=on"
		-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$VM_SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$VM_HTTP_PORT-:8090"
		-device "virtio-net-pci,netdev=n0"
		-display none -serial "file:$VM_DIR/console.log"
		-daemonize -pidfile "$VM_DIR/qemu.pid")
	if [ "$VM_ARCH" = arm64 ]; then
		qemu="qemu-system-aarch64"
		args+=(-machine "virt,accel=$acc" -bios "$(firmware)")
	else
		qemu="qemu-system-x86_64"
		args+=(-machine "q35,accel=$acc")
	fi
	cat >"$VM_DIR/vm.env" <<EOF
VM_DISTRO=$name
VM_SEED=$mode
VM_USER=$user
VM_DEFAULT_USER=$DEFAULT_USER
VM_SSH_PORT=$VM_SSH_PORT
VM_HTTP_PORT=$VM_HTTP_PORT
VM_KEY=$VM_DIR/id_ed25519
VM_ACCEL=$acc
VM_TIMEOUT=$timeout
EOF
	log "booting $name ($VM_ARCH, $acc) with the $mode seed"
	"$qemu" "${args[@]}"
	log "waiting for SSH as $user (up to ${timeout}s)"
	local waited=0
	until vm_ssh true 2>/dev/null; do
		sleep 5
		waited=$((waited + 5))
		if [ "$waited" -ge "$timeout" ]; then
			tail -40 "$VM_DIR/console.log" >&2 || true
			die "no SSH after ${timeout}s"
		fi
	done
	log "SSH after ${waited}s; waiting for cloud-init"
	# cloud-init status exits 2 for a recoverable warning; the status line
	# says whether it finished.
	vm_ssh "sudo cloud-init status --wait --long" >"$VM_DIR/cloud-init.txt" 2>&1 || true
	grep -q 'status: done' "$VM_DIR/cloud-init.txt" || {
		cat "$VM_DIR/cloud-init.txt" >&2
		die "cloud-init did not finish"
	}
	log "installing $STACKWARD as /usr/local/bin/stackward"
	scp -q -P "$VM_SSH_PORT" "${SSH_COMMON[@]}" "$STACKWARD" "$user@127.0.0.1:/tmp/stackward"
	vm_ssh "sudo install -m 0755 /tmp/stackward /usr/local/bin/stackward && rm /tmp/stackward && stackward version"
}

cmd_stop() {
	[ -f "$VM_DIR/qemu.pid" ] || return 0
	local pid _
	pid="$(cat "$VM_DIR/qemu.pid")"
	vm_ssh "sudo systemctl poweroff" >/dev/null 2>&1 || true
	for _ in $(seq 1 30); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 1
	done
	kill "$pid" 2>/dev/null || true
	rm -f "$VM_DIR/qemu.pid"
}

[ $# -ge 1 ] || {
	sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
}
cmd="$1"
shift
case "$cmd" in
resolve) cmd_resolve "$@" ;;
image) cmd_image "$@" ;;
boot) cmd_boot "$@" ;;
ssh) vm_ssh "$@" ;;
stop) cmd_stop ;;
*) die "unknown command $cmd" ;;
esac
