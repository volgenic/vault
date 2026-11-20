# Releasing the vault

A release is a GitHub release on `volgenic/vault` (a public repository, so a machine downloads it
without a login) named `v<version>`, with one archive per target and a `SHA256SUMS`:

| Asset | Built on | How |
|---|---|---|
| `vault-<version>-x86_64-unknown-linux-musl.tar.gz` | Linux or a Mac | `cargo zigbuild`, static (musl) |
| `vault-<version>-aarch64-unknown-linux-musl.tar.gz` | Linux or a Mac | `cargo zigbuild`, static (musl) |
| `vault-<version>-aarch64-apple-darwin.tar.gz` | **a Mac only** | `cargo build` |
| `SHA256SUMS` | | `sha256sum` lines for every archive above |

Each archive holds one folder, `vault-<version>-<target>/`, with `vault`, `README.md` and
`LICENSE`. `vault --version` names the version, the commit and the target, e.g.
`vault 0.6.0 (commit 0b02167dfd80, x86_64-unknown-linux-musl)`.

**The Linux builds are static.** They need no Rust toolchain, no OpenSSL and no particular libc,
and run on glibc and musl distributions alike. The proxy's TLS is rustls with the system's root
certificates (rustls-native-certs), which reads the usual files (`/etc/ssl/certs/ca-certificates.crt`
and the like): a static binary finds them on Debian, Ubuntu, Fedora and Alpine the same way.

## Prerequisites

- `rustup` (the script adds the targets it needs).
- For the Linux targets: [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild)
  (`cargo install cargo-zigbuild`) and [zig](https://ziglang.org/download/) on `PATH` (0.13 works).
  Zig is the C cross compiler that `ring` (rustls's crypto) needs for aarch64, and the musl linker.
- `gh`, logged in with permission to create releases on `volgenic/vault`.

## Steps

1. Bump `version` in `Cargo.toml` (and run `cargo build` so `Cargo.lock` follows), merge to `main`.
2. On a clean checkout of that commit, on Linux (or a Mac):

   ```sh
   scripts/release.sh --publish
   ```

   This builds the two Linux archives (and, on a Mac, the macOS one too) into `dist/`, writes
   `dist/SHA256SUMS`, and creates the release `v<version>` at the current commit with those
   files. The script refuses a tree with uncommitted changes, so `--version` always names a real
   commit.
3. **The macOS asset is built on a Mac.** When step 2 ran on Linux, on a Mac with the same commit
   checked out:

   ```sh
   TARGETS=aarch64-apple-darwin scripts/release.sh --add
   ```

   This builds `vault-<version>-aarch64-apple-darwin.tar.gz`, downloads the release's
   `SHA256SUMS`, adds the new archive's line to it, and uploads both (`--clobber`).
4. Check: download an archive, `sha256sum -c SHA256SUMS --ignore-missing`, unpack, and run
   `./vault --version`.

`scripts/release.sh` with no argument only builds into `dist/` (nothing is published).

## Installing from a release

```sh
curl -fsSLO https://github.com/volgenic/vault/releases/download/v0.6.0/vault-0.6.0-x86_64-unknown-linux-musl.tar.gz
curl -fsSLO https://github.com/volgenic/vault/releases/download/v0.6.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar xzf vault-0.6.0-x86_64-unknown-linux-musl.tar.gz
vault-0.6.0-x86_64-unknown-linux-musl/vault install          # or: install --json, for a program
```

`vault install` copies itself to `~/.local/share/volgenic/bin/vault` (Linux) or
`~/Library/Application Support/Volgenic/bin/vault` (macOS), so the downloaded copy can be removed
afterwards. Installing a newer release the same way updates the program and keeps the vault.

The macOS build isn't signed or notarized, so a copy downloaded with a browser carries the
quarantine flag; one downloaded with `curl` doesn't.
