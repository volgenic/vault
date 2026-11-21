# `vault status --json` and `vault install --json`

For a program (the host daemon) to read. Information only (R4): versions, paths, states, times
and counts. **Never a secret value, a secret's name or a recovery key**; the audit log's recent
changes, which name secrets, are left out. The types are in `src/report.rs`.

- **`schema`** is 1. Fields are only ever added within a schema; removing or changing one makes a
  new schema number. A reader should ignore fields it doesn't know.
- Every key is always present; a value that doesn't apply or isn't known is `null`.
- Both commands print one pretty-printed JSON object on standard output and nothing else there.
  Neither prompts or needs a terminal (`vault install --json </dev/null` is fine).
- **`vault status --json` always exits 0** when it printed the object, whatever the vault's state:
  read `healthy` and `problems`.
- **`vault install --json` exits 0 when `ok` is true**, else 1 (with `error` set, and a line on
  standard error too). A daemon that couldn't be started because there is no systemd is not an
  error: `ok` is true and `problems` says so.

**`intake`** (added 2026-11-16, work item #7368) is how Volgenic's app learns the key to seal a
value to: it reaches the app through Volgenic's server in this phase, so the server is trusted
not to swap it (an accepted gap in the threat model until pairing). A restore makes a new
intake key.

## `problems`

A list of `{code, severity, sentence, how}`, errors first:

- `severity`: `error` (the vault isn't serving, or isn't safe) or `warning` (it serves; something
  for a person to do).
- `sentence`: one sentence for a person.
- `how`: the exact command a person would run (the installed program by its full path, quoted for
  a POSIX shell when needed), or `null` when there is none.

| `code` | Severity | `how` |
|---|---|---|
| `not_installed` | error | `<this program> install` |
| `daemon_not_running` | error | Linux: `systemctl --user restart volgenic-vault.service`, or `<vault> daemon` without systemd; macOS: `launchctl kickstart -k gui/<uid>/com.volgenic.vault`; `<vault> install` when the service file or LaunchAgent is missing |
| `daemon_not_verified` | error | null (something else is behind the socket) |
| `no_vault` | error | `<vault> install` (makes one), or `<vault> restore` when `vault reset` kept a restore point |
| `backup_failed` | error | `<vault> backup` |
| `audit_chain_broken` | error | `<vault> audit --all` |
| `daemon_outdated` | warning | `<vault> install` (the daemon runs an older version than the installed program) |
| `no_backup_yet` | warning | `<vault> backup` |
| `recovery_kit_pending` | warning | `<vault> confirm-kit` (needs a person at a terminal) |
| `key_plain_copy_left` | warning | `<vault> install` |
| `key_not_sealed` | warning | `<vault> install` (the TPM could seal the key) |
| `no_systemd` | warning | `<vault> daemon` (Linux without systemd: nothing restarts it after a reboot) |
| `lingering_off` | warning | `sudo loginctl enable-linger <user>` |
| `service_not_enabled` | warning | `<vault> install` |
| `launch_agent_not_loaded` | warning | `<vault> install` (macOS) |

`healthy` is true when no problem has severity `error`.

## `vault status --json`

```jsonc
{
  "schema": 1,
  "healthy": true,
  "platform": "linux",                 // or "macos"
  "user": "node",
  "program": {
    "version": "0.2.0",                // this build
    "commit": "0b02167dfd80",
    "target": "x86_64-unknown-linux-musl",
    "running_path": "/home/node/.local/share/volgenic/bin/vault",
    "installed": true,
    "installed_path": "/home/node/.local/share/volgenic/bin/vault",
    "installed_is_this_build": true    // byte for byte; null when not installed
  },
  "protocol": 2,                       // the socket protocol this build speaks
  "daemon": {
    "running": true,                   // answered on its socket, as your own user (R22)
    "pid": 21052,
    "version": "0.2.0",                // the daemon's build
    "format": 9,                       // the vault-file format it writes
    "socket": "/home/node/.local/share/volgenic/socket/vault.sock",
    "service_file": "/home/node/.config/systemd/user/volgenic-vault.service",
    "service_file_present": true,
    "log": "/home/node/.local/state/volgenic/vault.log",
    "error": null                      // {code, message} when it didn't answer
  },
  "vault": {
    "initialized": true,               // from the daemon, or from the vault file when it's down
    "identity": "1a04647e8803342eefe9d28e5598e3b7",   // stable through restores
    "vault_id": "59b9e611b6368d65e000249e1077c993",   // this copy
    "recovery_fingerprint": "1a04-647e-8803",
    "format": 9,
    "created_at": "2026-11-16T05:00:19Z",
    "generation": 2,
    "secrets": 1,                      // a count, never names
    "restore_point": false
  },                                   // all but "initialized" are null when the daemon is down
  "key_protection": {
    "kind": "file",                    // "tpm2" (Linux) | "secure_enclave" (macOS): only when the running daemon unsealed it | "unchecked" (sealed file, no daemon says it opened it) | "file" | "none"
    "reason": "systemd-creds isn't installed",   // for "file"/"unchecked": why not (known to be) sealed; on a Mac without one, "this Mac has no Secure Enclave"
    "plain_copy_left": false,          // a sealed key and a plain vault.key both on disk (`vault install` replaces the key)
    "sealable": false,                 // "file" that `vault install` would seal now
    "sealed_unusable": false,          // the daemon is running on the plain key although a sealed one is there (an error)
    "detail": "vault key in a mode-600 file next to the vault file, not sealed to this machine"
  },
  "disk": { "filevault_on": true, "auto_login_user": null },   // macOS only, else null; FileVault off or automatic login is a warning
  "recovery_kit": {
    "state": "pending",                // "pending" | "confirmed" | "none" (no vault) | "unknown" (daemon down)
    "path": "/home/node/Volgenic Vault Recovery Kit.txt",   // the kit file, while pending (or the default path when unknown)
    "file_present": true
  },
  "backup": {
    "state": "ok",                     // "ok" | "failed" | "none" | "unknown"
    "generation": 2,
    "at": "2026-11-16T05:00:36Z",
    "file": "/home/node/.local/share/volgenic/vault-backups/vault-backup-59b9e611-000002-20261116T050036Z.age",
    "detail": "written, read back and decrypted",
    "folder": "/home/node/.local/share/volgenic/vault-backups"
  },
  "boot": {
    "mechanism": "systemd-user-service",   // or "launch-agent"
    "persistent": false,               // Linux: systemd && lingering && service enabled; macOS: LaunchAgent present and loaded
    "systemd": false,                  // Linux only, else null
    "lingering": false,                // Linux only (/var/lib/systemd/linger/<user>), else null
    "service_enabled": false,          // Linux only (default.target.wants link), else null
    "launch_agent_loaded": null        // macOS only (launchctl print), else null
  },
  "audit": { "intact": true, "lines": 12, "files": 1, "problem": null },   // null unless the daemon answered with a vault; files: audit.log and its rotated audit.log.<n>
  "intake": {                          // the vault's intake key (sealed intake, `add_sealed`); null unless the daemon answered with a vault
    "public_key": "age1qmgamyp4yjfrk0f0nc0hh3pw03zf76y7kr2j20m52wc80f6lc57s55uukl",   // an age X25519 recipient
    "fingerprint": "732e-1fdf-6b84"    // first 12 hex digits of its SHA-256, the recovery key's form
  },
  "problems": [
    { "code": "recovery_kit_pending", "severity": "warning",
      "sentence": "The Recovery Kit (/home/node/Volgenic Vault Recovery Kit.txt) isn't confirmed yet. It opens every backup of this vault on any machine, so until it is confirmed and its file deleted, a copy of this disk or of its backups opens your secrets, and sealing the key to this machine doesn't protect them: keep a copy off this machine, then confirm it, which deletes the file.",
      "how": "/home/node/.local/share/volgenic/bin/vault confirm-kit" },
    { "code": "no_systemd", "severity": "warning",
      "sentence": "This machine isn't running systemd, so nothing starts the vault after a reboot; it runs only while started by hand.",
      "how": "/home/node/.local/share/volgenic/bin/vault daemon" }
  ]
}
```

## `vault install --json [--for-restore]`

The same install as `vault install`, with this object instead of prose:

```jsonc
{
  "schema": 1,
  "ok": true,
  "error": null,                       // {code, message} when ok is false
  "platform": "linux",
  "for_restore": false,
  "program": {                         // null if the install stopped before copying the program
    "action": "installed",             // "installed" | "updated" | "reinstalled" (same bytes) | "in_place"
    "path": "/home/node/.local/share/volgenic/bin/vault",
    "from": "/tmp/relcheck/vault-0.2.0-x86_64-unknown-linux-musl/vault",
    "version": "0.2.0",
    "commit": "0b02167dfd80"
  },
  "vault": {
    "action": "made",                  // "made" | "kept" | "none" (--for-restore, or a key without a vault file)
    "identity": "1a04647e8803342eefe9d28e5598e3b7",
    "vault_id": "59b9e611b6368d65e000249e1077c993",
    "recovery_fingerprint": "1a04-647e-8803",
    "kit_written": "/home/node/Volgenic Vault Recovery Kit.txt"   // only for "made"; the path, never the key
  },
  "key_note": "mode-600 file (systemd-creds isn't installed)",   // what sealing did, when the install touched the key
  "service": {
    "file": "/home/node/.config/systemd/user/volgenic-vault.service",
    "started": false,                  // started and answered
    "not_started_reason": "this machine isn't running systemd",
    "lingering": null,                 // Linux with systemd: on after the install? (false: see problems, lingering_off)
    "pid": null
  },
  "problems": [ /* the same as status.problems */ ],
  "status": { /* `vault status --json`, read right after the install; null if it stopped before the program */ }
}
```
