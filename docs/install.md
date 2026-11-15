# Install and verify

stackward is a single static binary. You run it on a server you care about, so
this page shows how to check what you downloaded before you run it. Nothing
here needs root, and nothing runs the binary for you.

The newest release is `v0.1.0`, and `releases/latest` points at it. The
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
| `checksums.txt` | SHA-256 of every file above and of `get.sh` |
| `checksums.txt.sigstore.json` | keyless cosign signature bundle for `checksums.txt` |
| `get.sh` | optional POSIX shell downloader (see below) |

## Download, verify, run

```sh
VERSION=v0.1.0
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

```sh
sudo apt install ./stackward_${VERSION#v}_amd64.deb
```

Verify the `.deb` against `checksums.txt` first. An apt repository may come
later; for now the package is a plain download.

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
