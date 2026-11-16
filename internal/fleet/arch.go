package fleet

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// Arch is a Linux architecture stackward is released for, in Go's naming.
type Arch string

// The released Linux architectures.
const (
	AMD64 Arch = "amd64"
	ARM64 Arch = "arm64"
)

// RemoteArch maps the output of `uname -m` on the remote host to an Arch.
func RemoteArch(unameM string) (Arch, error) {
	switch m := strings.TrimSpace(unameM); m {
	case "x86_64", "amd64":
		return AMD64, nil
	case "aarch64", "arm64":
		return ARM64, nil
	case "":
		return "", errors.New("uname -m printed nothing")
	default:
		return "", fmt.Errorf("architecture %q has no stackward release build (linux amd64 and arm64 only)", cleanText(m))
	}
}

// Binary is a stackward build for Linux that can be copied to a host.
type Binary struct {
	Path string
	Arch Arch
}

// BinaryArch reads the ELF header of path and returns its architecture.
// Anything that is not a 64 bit Linux build for a released architecture is
// refused, so a darwin or windows build is never copied to a server.
func BinaryArch(path string) (Arch, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s is not a Linux build of stackward (%w)", path, err)
	}
	defer func() { _ = f.Close() }()
	if f.Class != elf.ELFCLASS64 {
		return "", fmt.Errorf("%s is not a 64 bit Linux build", path)
	}
	switch f.Machine {
	case elf.EM_X86_64:
		return AMD64, nil
	case elf.EM_AARCH64:
		return ARM64, nil
	}
	return "", fmt.Errorf("%s is built for %s, which has no stackward release (linux amd64 and arm64 only)", path, f.Machine)
}

// LoadBinaries inspects the binaries given with --ssh-binary, or this
// executable when none is given. At most one binary per architecture.
func LoadBinaries(paths []string, version string) ([]Binary, error) {
	if len(paths) == 0 {
		self, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("cannot find this executable to copy: %w; pass --ssh-binary", err)
		}
		a, err := BinaryArch(self)
		if err != nil {
			return nil, fmt.Errorf("this stackward is a %s/%s build and cannot run on a Linux server: download %s (or the arm64 one) from the release page and pass the binary with --ssh-binary",
				runtime.GOOS, runtime.GOARCH, ReleaseAsset(version, AMD64))
		}
		return []Binary{{Path: self, Arch: a}}, nil
	}
	var bins []Binary
	for _, p := range paths {
		a, err := BinaryArch(p)
		if err != nil {
			return nil, fmt.Errorf("--ssh-binary: %w", err)
		}
		for _, b := range bins {
			if b.Arch == a {
				return nil, fmt.Errorf("--ssh-binary: %s and %s are both %s builds; give one per architecture", b.Path, p, a)
			}
		}
		bins = append(bins, Binary{Path: p, Arch: a})
	}
	return bins, nil
}

// pickBinary returns the binary for arch, or an error naming the release
// asset to download.
func pickBinary(bins []Binary, arch Arch, version string) (Binary, error) {
	for _, b := range bins {
		if b.Arch == arch {
			return b, nil
		}
	}
	have := make([]string, len(bins))
	for i, b := range bins {
		have[i] = string(b.Arch)
	}
	return Binary{}, fmt.Errorf("host is linux/%s but the binary to copy is linux/%s: download %s from the release page and pass it with --ssh-binary (repeat the flag for a mixed fleet)",
		arch, strings.Join(have, ", "), ReleaseAsset(version, arch))
}

// ReleaseAsset names the release archive that holds the Linux binary for
// arch.
func ReleaseAsset(version string, arch Arch) string {
	v := strings.TrimPrefix(version, "v")
	if v == "" || v == "dev" {
		v = "<version>"
	}
	return fmt.Sprintf("stackward_%s_linux_%s.tar.gz", v, arch)
}
