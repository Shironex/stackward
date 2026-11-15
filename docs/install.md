# Install and verify

stackward is a single static binary. You run it on a server you care about, so
this page shows how to check what you downloaded before you run it. The
install script and the `.deb` need root to install; the download and verify
steps do not, and nothing here runs the audit for you.

The newest release is `v0.1.1`, and `releases/latest` points at it. The
commands below name the tag so that what you verify is exactly what you run.
The release notes are the matching section of `CHANGELOG.md` in the
repository.

Releases are built by GitHub Actions from a tag (`v*`) on `main`. Each release
holds:

| File | What it is |
|---|---|
| `stackward_<version>_linux_{amd64,arm64}.tar.gz` | the audit binary for Linux servers |
| `stackward_<version>_darwin_{amd64,arm64}.tar.gz`, `stackward_<version>_windows_amd64.zip` | for the laptop side `probe` command |
| `stackward_<version>_{amd64,arm64}.deb` | Debian and Ubuntu package |
| `*.spdx.json` | SPDX SBOM for each archive |
| `checksums.txt` | SHA-256 of every file above and of `get.sh` and `install.sh` |
| `checksums.txt.sigstore.json` | keyless cosign signature bundle for `checksums.txt` |
| `install.sh` | guided install, update and uninstall (see above) |
| `get.sh` | optional POSIX shell downloader, download only (see below) |

## Install script

`install.sh` is a guided install, update and uninstall in one POSIX shell
script. It is short on purpose: download it, read it, then run it.

```sh
curl -fsSLO https://github.com/Shironex/stackward/releases/latest/download/install.sh
less install.sh
sudo sh install.sh
```

Once you have read it, the same thing as one line:

```sh
curl -fsSL https://github.com/Shironex/stackward/releases/latest/download/install.sh | sudo sh
```

That line downloads the script from the latest release and runs it as root.
The script then does what the `less` step showed you: it detects your system,
finds the latest stable release, downloads the package and `checksums.txt`,
checks the SHA-256 (and the cosign signature when cosign is installed, and says
so when it is not), and only then installs. If a check fails it stops before
anything is written. To pass options through the pipe, add `sh -s -- --yes`
style arguments, for example `... | sudo sh -s -- --version v0.1.0`.

What it installs:

- Debian, Ubuntu and derivatives: the `.deb`, with apt. `sudo apt remove
  stackward` removes it too.
- Everything else, or when you pass `--prefix DIR`: the `stackward` binary in
  `DIR/bin` (default `/usr/local/bin`) and a small record,
  `DIR/share/stackward/install.json`, listing exactly what it added.

It never runs stackward itself, except one `stackward version` after the
install to confirm the version. It touches nothing beyond the package or the
binary and its record. On a terminal it shows numbered steps with a spinner, a
check or a cross per step, and a summary with the next steps
(`sudo stackward audit`, `sudo stackward tui`). Every command's output goes to
a log file whose path is printed, also when something fails. Without a
terminal, with `NO_COLOR` set or with `--quiet` the output is plain lines.

Commands and options:

```sh
sudo sh install.sh                    # install the latest stable release
sudo sh install.sh update             # install only when the latest stable is newer
sudo sh install.sh uninstall          # remove the package, or exactly what it added
sh install.sh --prefix "$HOME/.local" # binary install without root
```

| Option | Meaning |
|---|---|
| `--version vX.Y.Z` | install that release instead of the latest stable; a pre-release is only installed when named |
| `--prefix DIR` | install the binary under `DIR/bin` instead of using the `.deb` |
| `--yes`, `-y` | ask nothing; uninstalling without a terminal needs it |
| `--no-sudo` | fail instead of calling sudo when root is needed |
| `--dry-run` | print the steps and what would change, change nothing |
| `--quiet`, `-q` | plain output: the result line and errors only |

Running install again with the same version says so and exits 0. `update`
installs only when the latest stable release is newer than what is installed
(a pre-release counts as older than its stable release), and never downgrades.
`uninstall` runs `apt remove` for the package, or removes the files listed in
`install.json` and the folders it created, and nothing else. A `stackward`
binary that the script did not install (for example one from `get.sh`) is left
alone, and install refuses to overwrite it.

`install.sh` is listed in `checksums.txt` like every other release file.
`get.sh` stays as the download-only option.

## Download, verify, run

```sh
VERSION=v0.1.1
ARCH=amd64       # or arm64 (uname -m: x86_64 or aarch64)
BASE=https://github.com/Shironex/stackward/releases/download/$VERSION
curl -fsSLO "$BASE/stackward_${VERSION#v}_linux_$ARCH.tar.gz"
curl -fsSLO "$BASE/checksums.txt"
grep " stackward_${VERSION#v}_linux_$ARCH.tar.gz\$" checksums.txt | sha256sum -c -
tar -xzf "stackward_${VERSION#v}_linux_$ARCH.tar.gz" stackward
./stackward version
```

## Check where it came from

The SHA-256 only proves the download matches `checksums.txt`. These two checks
prove the files were built by this repository's release workflow.

Signature of the checksums file (needs [cosign](https://docs.sigstore.dev/)):

```sh
curl -fsSLO "$BASE/checksums.txt.sigstore.json"
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/Shironex/stackward/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

GitHub build provenance for the archive (needs the `gh` CLI):

```sh
gh attestation verify "stackward_${VERSION#v}_linux_$ARCH.tar.gz" --repo Shironex/stackward
```

## get.sh

`scripts/get.sh` does the download and the SHA-256 check for you, and the cosign
check when cosign is installed. It is short on purpose; read it first.

```sh
curl -fsSLO "https://github.com/Shironex/stackward/releases/latest/download/get.sh"
less get.sh
sh get.sh -d "$HOME/.local/bin"
# a specific release instead of the latest:
sh get.sh -v "$VERSION" -d "$HOME/.local/bin"
```

Without `-v` (or `STACKWARD_VERSION`) it installs the latest stable release;
a pre-release is only installed when you name its tag. It detects Linux or macOS and amd64 or arm64, installs only the `stackward`
file into the directory you pass (default: the current directory), never runs
the binary, never uses sudo, and stops without installing if a check fails.
When cosign is missing it says so and tells you the signature was not checked.
`get.sh` is listed in `checksums.txt` like every other release file.

## Debian and Ubuntu

Download the package for your CPU, check it against `checksums.txt`, then
install it with apt:

```sh
VERSION=v0.1.1
ARCH=amd64       # or arm64 (dpkg --print-architecture)
BASE=https://github.com/Shironex/stackward/releases/download/$VERSION
cd "$(mktemp -d)" && chmod 755 .   # apt's _apt user must be able to read the file
curl -fsSLO "$BASE/stackward_${VERSION#v}_$ARCH.deb"
curl -fsSLO "$BASE/checksums.txt"
grep " stackward_${VERSION#v}_$ARCH.deb\$" checksums.txt | sha256sum -c -
sudo apt install "./stackward_${VERSION#v}_$ARCH.deb"
stackward version
```

The leading `./` matters: without it apt looks for a package of that name in
its repositories. If you skip the `chmod 755 .`, apt prints `N: Download is
performed unsandboxed as root as file ... couldn't be accessed by user '_apt'`
because `mktemp -d` makes a folder only you can read. It is harmless and the
install still succeeds. To check the signature too, verify `checksums.txt` with
cosign as shown above before you install. Remove it with
`sudo apt remove stackward`. An apt repository may come later; for now the
package is a plain download.

## Build it yourself

```sh
git clone https://github.com/Shironex/stackward && cd stackward
git checkout "$VERSION"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid= \
  -X github.com/Shironex/stackward/internal/version.Version=${VERSION#v}" \
  -o stackward ./cmd/stackward
```

Release builds use the same flags with file times fixed to the commit time, so
building the same commit with the same Go version should give the same bytes.
Compare your binary with the one inside the release archive.

## Supply chain notes

- Release builds use `CGO_ENABLED=0`, `-trimpath` and the commit timestamp.
- The workflow pins every action by full commit SHA. Only the release job gets
  `id-token: write` and `attestations: write`.
- The audit binary does not download anything and has no self update.
- Report a problem with a release in a private advisory, see `SECURITY.md`.
