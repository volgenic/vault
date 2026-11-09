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
- **No Keychain, so no dialogs.** The Secure Enclave handle and the wrapped vault key live in
  `key.se` in the vault folder (readable only by you). The vault never uses the Keychain, so no
  setup step, rebuild or update raises a Keychain or password dialog. Opening the key needs this
  Mac's Secure Enclave and, after a restart, your login: the Secure Enclave key is usable only
  once you have logged in. That is also why the vault refuses to run while automatic login is on
  (it would log the Mac in by itself, and it keeps the login password in `/etc/kcpassword`, easy
  to reverse). FileVault isn't required; `vault status` reports it.
- **The Recovery Kit comes first.** `vault init` makes a recovery key pair and writes the kit to
  a file. The vault stores no secret until you confirm the kit by pasting the key back
  (`vault confirm-kit`), which also deletes the file.
- **Backups after every change**, to a folder you choose (iCloud Drive is suggested). Each is a
  standard [age](https://age-encryption.org) file encrypted to your recovery key, never to a
  password, plus a check key that lives only inside the vault, so the vault reads every backup
  back and decrypts it right after writing it, and refuses further changes if that fails. Your kit
  opens a backup anywhere, even without Volgenic: `age -d -i <file with the key> <backup>`.
- **Only `vault serve` touches the backup folder.** iCloud Drive is a folder macOS guards: the
  first program to open files there gets a "would like to access files" dialog. So the
  command-line tool never reads or writes the backup folder itself; it asks `vault serve`. That
  dialog then comes once, during `vault init`, for the vault itself, and macOS remembers the
  answer for the vault's signature, which every build keeps. An agent running `vault delete`
  can't raise it.
- **An audit log** (`audit.log` in the vault folder) records every request and command, refusals
  included, as hash-chained JSON lines: names, hosts, paths and outcomes, never a value, query or
  body. A use is written to the log before it happens; if the log can't be written, the vault
  refuses the use (`audit_unavailable`).
- **Hardening:** signed with the hardened runtime, no debugger attachment, no crash dumps, secret
  memory wiped after use. Secret values live in one type, `SecretValue`, that can't be printed,
  logged, cloned or serialized into a reply.

What it does not stop yet: any agent on the Mac can *use* any key within its rule and get any 2FA
code, and can delete secrets (device-signed approvals come later). An agent that runs its own
code as you can also read `key.se` and the vault file and ask this Mac's Secure Enclave to open
them: on one macOS user account nothing separates the vault's files from yours. The fix is
running the vault as its own macOS user, a planned next step. The vault can't yet tell the
Volgenic host from an agent: both run as Homebrew's `node`. The threat model page says what each
attacker can reach.

## Commands

The `vault` tool can't print a secret, so it is safe for any agent on the Mac to run.

| Command | What it does |
|---|---|
| `vault init` | Sets up the vault: Secure Enclave key, Recovery Kit, backup folder. Refuses if a vault exists or automatic login is on. |
| `vault confirm-kit` | Paste the recovery key back; unlocks storing secrets and deletes the kit file. |
| `vault add NAME --kind api-key --host HOST --method GET --path /v1 --header "Authorization: Bearer {key}"` | Adds an API key with its rule. The value is read at a hidden prompt (or from standard input with `--yes`). |
| `vault add NAME --kind login --site SITE --username USER` | Adds a login. Stored and listed only, for now. |
| `vault add NAME --kind 2fa --site SITE` | Adds a 2FA seed: base32, or an `otpauth://` link. |
| `vault delete NAME` | Deletes a secret. Earlier backups keep it. |
| `vault list` | Names, kinds and sites. |
| `vault status` | Protected key, Secure Enclave, automatic login, FileVault, signature, kit, backups, audit chain. |
| `vault audit [--all]` | The audit log, with its hash chain checked. |
| `vault verify-backup [--with-recovery-key]` | Has `vault serve` decrypt the newest backup and compare it with the vault. With the recovery key, also proves the kit opens it: `vault serve` hands over the encrypted file and the check runs in your terminal, so the key never crosses the socket. |
| `vault backup` | Has `vault serve` write (or re-check) the current backup now, e.g. after a failure. |
| `vault reset` | Removes this Mac's vault (needs the recovery key, and a newest backup that opens with it and matches the vault). Keeps that backup in the vault folder as a restore point. A vault whose kit was never confirmed holds nothing and goes without the key. |
| `vault restore [FILE]` | Restores into a fresh vault with the recovery key: the restore point `vault reset` kept, or a backup file you name (from another Mac, say; in iCloud Drive, macOS may ask once whether your terminal may read it). Makes a new Secure Enclave key, vault key and vault id, so the restored vault starts its own line of backups and older ones stay as they are. |
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
- `backup`, `verify-backup` and `read-backup` are how the command-line tool has `vault serve`
  write and check backups. They return file names, generations, times, counts and, for
  `read-backup`, the newest backup's ciphertext (which only the recovery key or the vault opens). `backup` never writes a
  second file for the same generation, so repeating it can't push older generations out.
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

Every build is signed with the same self-signed certificate, with the hardened runtime. Because
the vault keeps nothing in the Keychain, nothing depends on that signature staying the same: a
rebuild or an update shows no dialog.

## Tests: none, as an experiment

The owner, 2026-11-07, for Volgenic v2's core, app and host, extended to the vault on 2026-11-09
(work item #6101): the vault starts with no tests at all. See `AGENTS.md`. The gate is that
`cargo build` succeeds, plus a terminal recording of anything a person can see.
