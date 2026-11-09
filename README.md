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
the only macOS-specific part, key protection, sits in one small module (`src/keyprotect/`), so a
Linux version (systemd credentials, a TPM where present) replaces just that module.

## How it protects keys on macOS

- **The vault key** is 32 random bytes that encrypt the vault file
  (`~/Library/Application Support/Volgenic/vault/vault.bin`, XChaCha20-Poly1305). It is never
  stored as it is.
- **The Secure Enclave** wraps it. The vault makes a P-256 key inside this Mac's Secure Enclave,
  usable unattended (no fingerprint) but only on this Mac, and wraps the vault key to it. A copy
  of the vault's files on any other machine is useless.
- **The Keychain** holds the wrapped key and the Secure Enclave handle, in the login-Keychain
  item `com.volgenic.vault`. Its access list trusts only the vault build that created it, so any
  other program that asks gets a macOS prompt. **Never click Allow on a prompt about
  `com.volgenic.vault` unless it names a vault build you just installed yourself.** The login
  keychain is encrypted with your login password, which is why the vault refuses to run while
  automatic login is on (that setting keeps the password in `/etc/kcpassword`, easy to reverse).
  FileVault isn't required; `vault status` reports it.
- **The Recovery Kit comes first.** `vault init` makes a recovery key pair and writes the kit to
  a file. The vault stores no secret until you confirm the kit by pasting the key back
  (`vault confirm-kit`), which also deletes the file.
- **Backups after every change**, to a folder you choose (iCloud Drive is suggested). Each is a
  standard [age](https://age-encryption.org) file encrypted to your recovery key, never to a
  password, plus a check key that lives only inside the vault, so the vault reads every backup
  back and decrypts it right after writing it, and refuses further changes if that fails. Your kit
  opens a backup anywhere, even without Volgenic: `age -d -i <file with the key> <backup>`.
- **An audit log** (`audit.log` in the vault folder) records every request and command, refusals
  included, as hash-chained JSON lines: names, hosts, paths and outcomes, never a value, query or
  body.
- **Hardening:** signed with the hardened runtime, no debugger attachment, no crash dumps, secret
  memory wiped after use. Secret values live in one type, `SecretValue`, that can't be printed,
  logged, cloned or serialized into a reply.

What it does not stop yet: any agent on the Mac can *use* any key within its rule and get any 2FA
code, and can delete secrets (device-signed approvals come later). The vault can't yet tell the
Volgenic host from an agent: both run as Homebrew's `node`. The threat model page says what each
attacker can reach.

## Commands

The `vault` tool can't print a secret, so it is safe for any agent on the Mac to run.

| Command | What it does |
|---|---|
| `vault init` | Sets up the vault: Secure Enclave key, Keychain item, Recovery Kit, backup folder. Refuses if a vault exists or automatic login is on. |
| `vault confirm-kit` | Paste the recovery key back; unlocks storing secrets and deletes the kit file. |
| `vault add NAME --kind api-key --host HOST --method GET --path /v1 --header "Authorization: Bearer {key}"` | Adds an API key with its rule. The value is read at a hidden prompt (or from standard input with `--yes`). |
| `vault add NAME --kind login --site SITE --username USER` | Adds a login. Stored and listed only, for now. |
| `vault add NAME --kind 2fa --site SITE` | Adds a 2FA seed: base32, or an `otpauth://` link. |
| `vault delete NAME` | Deletes a secret. Earlier backups keep it. |
| `vault list` | Names, kinds and sites. |
| `vault status` | Keychain item, Secure Enclave, automatic login, FileVault, signature, kit, backups, audit chain. |
| `vault audit [--all]` | The audit log, with its hash chain checked. |
| `vault verify-backup [--with-recovery-key]` | Decrypts the newest backup and compares it with the vault; optionally proves the kit opens it. |
| `vault reset` | Removes this Mac's vault (needs the recovery key, and a newest backup that opens with it). |
| `vault restore FILE` | Restores a backup into a fresh vault with the recovery key; new Secure Enclave key and vault key. |
| `vault install-agent` | Installs the LaunchAgent `com.volgenic.vault`, which runs `vault serve` at login. |
| `vault serve` | The background part agents talk to. |

## For agents: the socket

`~/Library/Application Support/Volgenic/vault/vault.sock`, reachable only by this macOS user.
Send one JSON line, read one JSON line back:

```sh
S="$HOME/Library/Application Support/Volgenic/vault/vault.sock"
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
- Errors are `{"ok":false,"error":"rule_mismatch","message":"..."}`.

## Build

A Rust (Cargo) project. `build.rs` compiles the small Swift key-protection shim
(`src/keyprotect/macos.swift`) with `xcrun swiftc`, so Xcode or the Command Line Tools must be
installed.

```sh
cargo build          # the gate
cargo build --release
codesign --force --sign "Volgenic Vault Local Signing" --options runtime \
  --identifier com.volgenic.vault target/release/vault
```

Every build is signed with the same self-signed certificate, kept in the login keychain, with the
hardened runtime. That certificate has no Apple Team ID, so macOS ties the Keychain item to each
exact build: **the first run of a new build shows one Keychain prompt.** Install a new build
deliberately, run it once, and click Allow only on a prompt naming that build's path.

## Tests: none, as an experiment

The owner, 2026-11-07, for Volgenic v2's core, app and host, extended to the vault on 2026-11-09
(work item #6101): the vault starts with no tests at all. See `AGENTS.md`. The gate is that
`cargo build` succeeds, plus a terminal recording of anything a person can see.
