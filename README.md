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
the only macOS-specific part, key protection, sits in one small module (`src/keyprotect/`).

## The vault runs as its own macOS account

Agents on your Mac run as you. If the vault's files were yours, any agent that runs its own code
could read them and have the Secure Enclave open them. So the vault runs as its own hidden role
account, `_volgenicvault`, and agents can reach its socket but not its files.

| Part | Owner | Where | Mode |
|---|---|---|---|
| The program | root | `/Library/Application Support/Volgenic/bin/vault` | 0755 |
| The daemon's job, `com.volgenic.vault` | root | `/Library/LaunchDaemons/com.volgenic.vault.plist` | 0644 |
| Secure Enclave handle (`se-key`), `system.json` (the owner's user ID) | root | `/Library/Application Support/Volgenic/vault-root/` | 0700 |
| Vault file, wrapped vault key (`vault.key`), audit log, restore point | `_volgenicvault` | `/Library/Application Support/Volgenic/vault/` | 0700 |
| Local backups (ciphertext) | `_volgenicvault` | `/Library/Application Support/Volgenic/vault-backups/` | 0755, files 0644 |
| The socket | `_volgenicvault` | `/Library/Application Support/Volgenic/socket/vault.sock` | 0666, caller checked |
| The daemon's log | root | `/Library/Logs/Volgenic/vault.log` | 0644 |
| The mirror's job, `com.volgenic.vault.mirror` | you | `~/Library/LaunchAgents/` | |
| The mirror's copies | you | the mirror folder, iCloud Drive by default | |

- **The daemon starts as root.** It reads the Secure Enclave key's public half, unwraps the vault
  key with the Secure Enclave, then drops to `_volgenicvault` for good (`setgroups`, `setgid`,
  `setuid`, and a check that root can't be regained) before it opens the socket. After a
  restart the Secure Enclave key works only once someone has logged in, so until then the
  daemon waits and retries.
- **Only the daemon reads or changes the vault.** Every command (`add`, `delete`, `list`,
  `status`, `audit`, `reset`, `restore`, ...) is a request on the socket.
- **The socket is mode 0666; the daemon checks callers.** It accepts only your user ID (from
  `system.json`) and root, so you don't have to join a group (which would need every running
  program restarted). The command-line tool checks the other end too: the socket and its folder
  must belong to `_volgenicvault`, and `getpeereid` must report that account. Only then does it
  send a typed value or the recovery key.
- **No Keychain, so no Keychain dialogs.** The Secure Enclave key is made by CryptoKit with its
  default protection: no fingerprint, no password, this Mac only, usable after the first login.
- **Backups after every change**, to the local folder, each a standard
  [age](https://age-encryption.org) file encrypted to your recovery key (never a password) and
  to a check key that lives only inside the vault. The daemon reads every backup back and
  decrypts it right after writing it, and refuses further changes if that fails. Your kit opens
  a backup anywhere, even without Volgenic: `age -d -i <file with the key> <backup>`.
- **The mirror** is a LaunchAgent in your login (`vault mirror`, the same program). Whenever the
  local folder changes, and hourly, it copies each backup to the mirror folder and checks every
  copy byte for byte by SHA-256. It holds no key. It is the only program that opens iCloud
  Drive, so macOS's one "would like to access files" dialog names the vault and comes once.
- **An audit log** records every request and command, refusals included, as hash-chained JSON
  lines: names, hosts, paths and outcomes, never a value, query or body. A use is written before
  it happens; if the log can't be written, the vault refuses the use (`audit_unavailable`).
- **Hardening:** signed with the hardened runtime, no debugger attachment, no crash dumps, secret
  memory wiped after use. Secret values live in one type, `SecretValue`, that can't be printed,
  logged, cloned or serialized into a reply.

What it does not stop yet: any agent on the Mac can *use* any key within its rule, get any 2FA
code, and add, delete or swap secrets through the socket (device-signed approvals come later).
An agent can also swap a build you are about to install with sudo, and sign it with the vault's
certificate; `install-system` prints the commit and SHA-256 so you can check. The threat model
page says what each attacker can reach.

## Install, update, restore

```sh
cargo build --release
codesign --force --sign "Volgenic Vault Local Signing" --options runtime \
  --identifier com.volgenic.vault target/release/vault
sudo target/release/vault install-system      # one Terminal password prompt
vault install-mirror                           # as yourself; one iCloud Drive dialog
vault confirm-kit
```

(`vault` here is the installed program, `/Library/Application Support/Volgenic/bin/vault`; add
that folder to your `PATH` or use an alias.)

- `install-system` refuses a build that isn't signed with "Volgenic Vault Local Signing" and the
  hardened runtime. It prints the build's git commit and SHA-256 and asks before it changes
  anything. It creates the role account with `dscl`, the folders, the program, the Secure
  Enclave key, the vault and its Recovery Kit (written to your home folder as you, mode 0600),
  and starts the daemon. It lists any passwordless sudo rules it finds: any one an agent can use
  gives it root, and root opens the vault.
- **An update** is the same `sudo .../vault install-system` with the new signed build: it
  replaces the program and restarts the daemon, and keeps everything else. One Terminal
  password prompt per update.
- **Restore on this Mac** needs no sudo: `vault reset` (with the recovery key) keeps the newest
  backup as a restore point, and `vault restore` brings it back with a new vault key wrapped to
  the same Secure Enclave key.
- **Restore on a new Mac:** `sudo vault install-system --for-restore`, then
  `vault restore <backup file>`.

## Commands

The `vault` tool can't print a secret, so it is safe for any agent on the Mac to run.

| Command | What it does |
|---|---|
| `sudo vault install-system [--for-restore]` | Installs or updates the vault (above). |
| `vault install-mirror` | Installs the mirror agent in your login and waits for its first copy. |
| `vault confirm-kit` | Paste the recovery key back; unlocks storing secrets and deletes the kit file. |
| `vault add NAME --kind api-key --host HOST --method GET --path /v1 --header "Authorization: Bearer {key}"` | Adds an API key with its rule. The value is read at a hidden prompt (or from standard input with `--yes`). |
| `vault add NAME --kind login --site SITE --username USER` | Adds a login. Stored and listed only, for now. |
| `vault add NAME --kind 2fa --site SITE` | Adds a 2FA seed: base32, or an `otpauth://` link. |
| `vault delete NAME` | Deletes a secret. Earlier backups keep it. |
| `vault list` | Names, kinds and sites. |
| `vault status` | The installed program and its signature, the vault account, folder owners, the daemon, the kit, backups, the mirror, the audit chain. |
| `vault audit [--all]` | The audit log, with its hash chain checked. |
| `vault verify-backup [--with-recovery-key]` | Has the daemon decrypt the newest backup and compare it with the vault. With the recovery key, also proves the kit opens it; that check runs in your terminal on ciphertext the daemon hands over. |
| `vault backup` | Has the daemon write (or re-check) the current backup now, e.g. after a failure. |
| `vault reset` | Removes this Mac's vault (needs the recovery key, and a newest backup that opens with it and matches the vault). Keeps that backup as a restore point. A vault whose kit was never confirmed holds nothing and goes without the key. |
| `vault restore [FILE]` | Restores into an empty vault with the recovery key: the restore point, or a backup file you name. |

## For agents: the socket

`/Library/Application Support/Volgenic/socket/vault.sock`. Send one JSON line, read one JSON
line back:

```sh
S="/Library/Application Support/Volgenic/socket/vault.sock"
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

A Rust (Cargo) project. `build.rs` compiles the small Swift key-protection shim
(`src/keyprotect/macos.swift`) with `xcrun swiftc`, so Xcode or the Command Line Tools must be
installed, and records the git commit that `install-system` prints.

```sh
cargo build          # the gate
cargo build --release
```

## Tests: none, as an experiment

The owner, 2026-11-07, for Volgenic v2's core, app and host, extended to the vault on 2026-11-09
(work item #6101): the vault starts with no tests at all. See `AGENTS.md`. The gate is that
`cargo build` succeeds, plus a terminal recording of anything a person can see.
