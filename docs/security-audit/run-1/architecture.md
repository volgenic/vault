# Architecture: volgenic/vault (run 1)

**Product and principals.** A Rust daemon and CLI (one crate, `src/lib.rs` + `src/main.rs`, ~14.6k lines) that keeps one OS user's secrets encrypted on their own machine and lets agents use them without seeing them. Secrets: API keys with a fixed proxy rule, website logins, TOTP seeds, Claude plan tokens, Codex/Grok/Google AI OAuth logins, personal details, app secrets (leasable to builds), and crypto wallet keys (EVM, Solana, Tron) with spending caps. Principals: the owner (CLI, recovery key holder); agents and the host daemon (`volgenic/host`, not in this repo), which relay requests; Volgenic's app and server, which only relay sealed (age-encrypted) values; browser engines that fill logins; build jobs that receive leases; upstream API providers and token servers; anyone who can seal to the public intake key.

**Accepted design trade-offs (source-stated).** "Every agent on the machine runs as the owner, so every request here is open to every agent" (`src/protocol.rs:3-4`). The vault key is a 0600 file (or, on Linux, sealed with `systemd-creds --user` host+tpm2) readable or unsealable by any same-UID process (`src/keyprotect/mod.rs:1-19`, `README.md:25-29`, `README.md:319-324`). The README also says agents in containers cannot reach the socket at all. So the socket boundary does not separate owner from agent; that separation is the host's (needs a check on the other side). Same-UID self-impact is not a finding unless a stated control is defeated.

**Comparable baseline.** age (backups, intake, leases), RFC 6238 TOTP, RFC 6979/8032 signing, systemd-creds. No comparable secrets-manager is source-grounded.

**Stack and deployment.** Rust 2024, `panic = "abort"`; reqwest 0.12 blocking (proxy) and async on tokio (stream); rustls with native roots on Linux, native-tls (Security.framework) on macOS; XChaCha20-Poly1305 vault file with magic+id AAD (`src/store.rs:273-331`). Daemon is a LaunchAgent (macOS) or systemd user service with linger (Linux), or run by hand in a container (`src/install.rs`). Feature `test-upstream` redirects kinds' hosts to 127.0.0.1 and trusts an extra CA; release builds do not enable it (`scripts/release.sh`). Gate is `cargo build`; no tests exist by owner decision. A toolchain is now installed in this container; there is no network or mount namespace, so target code runs only per volgenic.md's wrapper (hygiene, not confinement).

**Entry surfaces and paths.**
- Unix socket, one JSON request line (max 2 MiB) per connection, plus raw payloads for `restore` (≤32 MiB) and `stream` (≤32 MiB): `src/server.rs:219-458`, `src/protocol.rs`. Ops: list, totp, proxy, stream, health, add, add_sealed, import_plan, import_login, claim_refresh, lease, fill, generate_login, sign, sign-cancel, wallet-create, wallet-caps, delete, rename, confirm-kit, reset, restore, backup, verify-backup, read-backup, mirror-plan, mirror-report, status, audit.
- Proxy: rule-bound host/port/method/path/header, caller headers filtered, no redirects, HTTPS only, echo scrub (`src/proxy.rs`, `src/rules.rs`, `src/scrub.rs`).
- Stream: kind table fixes hosts/paths/headers, streaming scrub, 401 renew-and-retry, token renewal to fixed token servers (`src/stream.rs`, `src/kinds.rs`, `src/logins.rs`, `src/health.rs`).
- Sealed intake (`src/intake.rs`), leases (`src/lease.rs`), fill and site matching via PSL (`src/fill.rs`, `src/sites.rs`), TOTP (`src/totp.rs`), personal details (`src/details.rs`).
- Wallet signing within caps; caps and wallet creation gated by the recovery key (`src/wallet.rs`, `src/evm.rs`, `src/solana.rs`, `src/tron.rs`, `src/vault.rs:573-788`).
- Files read at start: vault file, key, `health.json`, `mirror.json`, audit log chain (`src/server.rs:86-216`). Backups (age, 0644) and restore point; Recovery Kit file in home (`src/backup.rs`, `src/vault.rs`, `src/mirror.rs`).
- CLI: prompts/stdin for values, verifies daemon socket owner and peer UID (`src/main.rs`, `src/client.rs`).
- Install/update: copies `current_exe()` into `bin/`, writes plist/unit, runs launchctl/systemctl/loginctl/systemd-creds at fixed paths (`src/install.rs`, `src/keyprotect/mod.rs`).
- Release: `scripts/release.sh`, `docs/releasing.md`, `Cargo.lock` (297 crates), `build.rs` (runs git).

**Trust boundaries and strongest controls.**
1. Other OS users → socket: peer UID equality via `SO_PEERCRED`/`getpeereid`, 0700 folder, 0600 socket (`src/server.rs:401-410`, `src/platform.rs:50-92`).
2. Caller → upstream with a credential: rule/kind destination binding, header filter, redirect refusal, TLS trust store, echo scrub.
3. Remote relay (hub/host) → stored secrets: age intake, name/kind binding, replace only for fixed-host kinds (`src/server.rs:513-563`).
4. Caller → login passwords / app secrets: `fill` origin check on registrable domain (caller-asserted origin); `lease` only leasable app secrets, sealed to caller's key.
5. Caller → wallet funds: per-payment, daily and fee caps; recovery key for caps.
6. Secret values → logs, errors, audit, replies, crash dumps: `SecretValue` (no Debug/Display/Serialize), fixed error strings, `PR_SET_DUMPABLE`/`PT_DENY_ATTACH`, RLIMIT_CORE 0.
7. Disk thief/backup reader → vault: AEAD with key file or TPM seal; backups age-encrypted to recovery key and check key.
8. Audit integrity: unkeyed SHA-256 chain, head recorded in the vault file at each change.
9. Release consumer → binary: SHA256SUMS on the same GitHub release; no signing.

**Prior coverage.** No prior run (`docs/security-audit/` absent). No compatible ledger; every unit is `prior_status: "none"`.

**Companion selection.** DESKTOP-MOBILE-AND-LOCAL-IPC (Unix-socket daemon, install helpers, local files); MEMORY-SAFETY-AND-BINARY (`unsafe` libc FFI, zeroizing, crash dumps, binary parsers for chains); PROTOCOLS-RPC-AND-MESSAGING (line-framed JSON RPC, payload framing, replay of sealed values and signatures); WEB-PROTOCOL-AND-AUTH (outbound HTTP framing, API-key and OAuth token handling); DATA-ISOLATION-AND-LIFECYCLE (backup, restore, reset, deletion, lease lifecycle); RESOURCE-EXHAUSTION-AND-AVAILABILITY (connection cap, 32 MiB payloads, streaming); SUPPLY-CHAIN-AND-RELEASE (Cargo.lock, release script, unsigned updates). Not selected: AI-AND-LLM (the vault does not process model output beyond scrubbing bytes), CLIENT-SIDE (no browser DOM code), CLOUD-AND-DEPLOYMENT (no IaC or cloud config in repo).
