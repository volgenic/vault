# volgenic/vault

Volgenic's vault keeps your agents' secrets (API keys, website logins and 2FA seeds) on your own
Mac, and lets agents **use** them without ever **seeing** them. An agent asks the vault to make
an API call and gets the API's reply; the vault adds the key on the way out. An agent asks for a
2FA code and gets the six digits, never the seed. Nothing the vault returns, to an agent or on
the command line, can carry a secret value.

- Design: [Volgenic v2 secret store](https://volgenic.com/pages/1f495021-effc-4fd2-9160-24cbcd73dbe3)
- Threat model, with the numbered rules (R1, R2, ...) every change is reviewed against:
  [Vault threat model](https://volgenic.com/pages/4171d207-a31e-4d38-b659-60ceed9ee5fd)

**macOS only for now. Linux is planned:** the platform-neutral core is the library crate, and
the vault key's storage sits in one small module (`src/keyprotect/`).

Deliberately simple: the bar is "better than plaintext secrets on a server", not an enterprise
security system. The vault keeps secrets out of agents' normal path (they use them without
seeing them), not out of reach of code running as you: the key file and the vault file are
yours. The threat model's "Current design" block says what that accepts.

## How it runs

Everything is yours, under `~/Library/Application Support/Volgenic/` (folders 0700):

| Part | Where |
|---|---|
| The program | `bin/vault` |
| Vault file (encrypted, XChaCha20-Poly1305), vault key (`vault.key`, 32 random bytes, 0600), audit log | `vault/` |
| Local backups (age files, ciphertext) | `vault-backups/` |
| The socket | `socket/vault.sock` |
| The daemon's job, `com.volgenic.vault` | `~/Library/LaunchAgents/com.volgenic.vault.plist` |
| The daemon's log | `~/Library/Logs/Volgenic/vault.log` |
| The Recovery Kit (the key that opens backups) | `~/Volgenic Vault Recovery Kit.txt`, 0600 |

- **No sudo, no role account, no code signing, no Secure Enclave, no Keychain:** nothing the
  vault does can show a dialog or ask for a password.
- **The daemon is a LaunchAgent in your login.** It reads the key file, opens the socket and
  serves; only your own user ID may connect.
- **No gates.** Secrets can be stored right after install. Stash the Recovery Kit whenever you
  like (`vault confirm-kit` is optional and deletes the file once you've pasted it back).
- **Backups after every change** to the local folder, encrypted to the recovery key; `vault
  install-mirror` optionally copies them to another folder.

## Install and update

```sh
cargo build --release
target/release/vault install
```

No questions, no password. Running it again with a new build replaces the program and restarts
the daemon, and keeps the vault. On a new Mac: `vault install --for-restore`, then
`vault restore <backup file>`.

## Commands

The `vault` tool can't print a secret, so it is safe for any agent on the Mac to run.

| Command | What it does |
|---|---|
| `vault install [--for-restore]` | Installs or updates the vault for your user. |
| `vault add NAME --kind api-key --host HOST --method GET --path /v1 --header "Authorization: Bearer {key}"` | Adds an API key with its rule. The value is read at a hidden prompt, or from standard input with `--yes`. |
| `vault add NAME --kind login --site SITE --username USER` | Adds a login. Stored and listed only, for now. |
| `vault add NAME --kind 2fa --site SITE` | Adds a 2FA seed: base32, or an `otpauth://` link. |
| `vault delete NAME` | Deletes a secret. Earlier backups keep it. |
| `vault list` | Names, kinds and sites. |
| `vault status` | The program, the daemon, backups and the audit chain. |
| `vault audit [--all]` | The audit log, with its hash chain checked. |
| `vault verify-backup [--with-recovery-key]` | Checks the newest backup decrypts and matches the vault. |
| `vault backup` | Writes (or re-checks) the current backup now. |
| `vault confirm-kit` | Optional: paste the recovery key back; deletes the kit file. |
| `vault reset` / `vault restore [FILE]` | Remove the vault (with the recovery key) and restore a backup into an empty one. |
| `vault install-mirror` | Optional: a LaunchAgent that copies backups to a mirror folder. |

## For agents: the socket

`~/Library/Application Support/Volgenic/socket/vault.sock`. Send one JSON line, read one JSON
line back:

```sh
S="$HOME/Library/Application Support/Volgenic/socket/vault.sock"
echo '{"op":"list"}' | nc -U "$S"
echo '{"op":"totp","name":"github-2fa"}' | nc -U "$S"
echo '{"op":"proxy","name":"openai","method":"GET","path":"/v1/models"}' | nc -U "$S"
```

- `list` returns `{"ok":true,"secrets":[{"name","kind","site"}]}`.
- `totp` returns `{"ok":true,"code":"123456","seconds_left":17}`.
- `proxy` takes `method`, `path` (with query), optional `headers` (an object) and `body` or
  `body_base64`. It returns `{"ok":true,"status":200,"headers":[[name,value]],"body":"..."}`.
  The key goes only into the header its rule names, only to the rule's host, method and path.
  Redirects come back to you unfollowed. A reply that contains the key is withheld
  (`echo_blocked`).
- The other requests (`status`, `audit`, `add`, `delete`, `confirm-kit`, `reset`, `restore`,
  `backup`, `verify-backup`, `read-backup`, `mirror-plan`, `mirror-report`) are what the
  command-line tool and the mirror send; `src/protocol.rs` lists them.
- Errors are `{"ok":false,"error":"rule_mismatch","message":"..."}`.

## Build

A Rust (Cargo) project with no native shim: `cargo build` is the gate.

## Tests: none, as an experiment

The owner, 2026-11-07, for Volgenic v2's core, app and host, extended to the vault on 2026-11-09
(work item #6101): the vault starts with no tests at all. See `AGENTS.md`. The gate is that
`cargo build` succeeds, plus a terminal recording of anything a person can see.
