# volgenic/vault

Volgenic's vault keeps your agents' secrets (API keys, website logins, 2FA seeds, Claude plan
tokens, Codex, Grok and Google AI logins, your personal details, your applications' build and deploy
secrets, and your agents' wallet keys) on your own
machine (a Mac, or a Linux box such as the always-on primary host), and lets agents **use** them
without ever **seeing** them. An agent asks the vault to make
an API call and gets the API's reply; the vault adds the key on the way out. An agent asks for a
2FA code and gets the six digits, never the seed. The host's model proxy sends a model call
naming a Claude plan, and the vault adds the plan's token and streams the reply back as it
arrives. Nothing the vault returns, to an agent or on the command line, can carry a secret value,
with two exceptions: a build's `lease`, an app secret's value sealed to that build's own key for at
most a day ("App secrets and leases" below), and a `fill`, a saved login handed to the browser
engine that types it into a page on that login's own site ("Logins in the browser" below). A wallet's key is made inside the vault and never
leaves it at all; agents' payments get the vault's signature, within caps only you set
("Wallets" below).

- Design: [Volgenic v2 secret store](https://volgenic.com/pages/1f495021-effc-4fd2-9160-24cbcd73dbe3)
- Threat model, with the numbered rules (R1, R2, ...) every change is reviewed against:
  [Vault threat model](https://volgenic.com/pages/4171d207-a31e-4d38-b659-60ceed9ee5fd)

**macOS and Linux.** The core is the library crate; what differs between the two sits behind
`cfg` in a few small modules (see `AGENTS.md`). On Linux the vault comes back by itself after a
reboot or a power cut, with nobody logged in.

Deliberately simple: the bar is "better than plaintext secrets on a server", not an enterprise
security system. The vault keeps secrets out of agents' normal path (they use them without
seeing them), not out of reach of code running as you: the key file and the vault file are
yours. The threat model's "Current design" block says what that accepts.

## How it runs on macOS

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

## How it runs on Linux

Everything is yours, under `~/.local/share/volgenic/` (folders 0700), with the same folders as on
a Mac:

| Part | Where |
|---|---|
| The program | `bin/vault` |
| Vault file, vault key, audit log | `vault/`: the key is `vault.key.cred`, sealed to the TPM, when the machine has one; else `vault.key`, 32 random bytes, 0600 |
| Local backups | `vault-backups/` |
| The socket | `/run/user/<uid>/volgenic/vault.sock` (systemd's `RuntimeDirectory`, 0700); `~/.local/share/volgenic/socket/` on a machine without systemd |
| The daemon's job, `volgenic-vault.service` | `~/.config/systemd/user/volgenic-vault.service` |
| The daemon's log | `~/.local/state/volgenic/vault.log` |
| The Recovery Kit | `~/Volgenic Vault Recovery Kit.txt`, 0600 |

- **A systemd user service with lingering.** `vault install` writes the unit, turns lingering on
  for you (`loginctl enable-linger`), enables the service and starts it. Lingering starts your
  service manager at boot, so the vault serves after a reboot or a power cut with nobody logged
  in, and `Restart=always` brings it back whenever it stops. If your distribution doesn't let you
  turn lingering on yourself, `vault install` prints the one `sudo loginctl enable-linger` to run.
- **Why not a system service under its own account:** that needs root to install and update,
  and is the separate-account design the owner retired. A user service keeps everything yours,
  exactly as on a Mac: the same threat model, the same caller check, no sudo.
- **The vault key is sealed to the TPM** when the machine has a TPM 2.0 and systemd 256 or later
  (`systemd-creds --user encrypt --with-key=host+tpm2`: a user-scoped credential must also be
  bound to the host secret, so `tpm2` alone is refused). The daemon unseals it at each start,
  unattended. A copy of the disk can't open the vault on another machine; code running as you on
  this machine still can, as with the key file. Otherwise the key stays a 0600 file, as on a Mac;
  `vault status` says which. Running `vault install` again seals a key file that can now be sealed.
- **The caller check** uses `SO_PEERCRED`: only your own user ID may connect.
- **The proxy** checks certificates against the system's root certificates (rustls), and ignores
  `SSL_CERT_FILE`, `SSL_CERT_DIR` and proxy settings.
- **The backup mirror** (`vault install-mirror`) is macOS only for now.

## Install and update

From a release, with no Rust toolchain (the Linux builds are static; see
[docs/releasing.md](docs/releasing.md) for every target and how releases are made):

```sh
curl -fsSLO https://github.com/volgenic/vault/releases/download/v0.6.0/vault-0.6.0-x86_64-unknown-linux-musl.tar.gz
curl -fsSLO https://github.com/volgenic/vault/releases/download/v0.6.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar xzf vault-0.6.0-x86_64-unknown-linux-musl.tar.gz && vault-0.6.0-x86_64-unknown-linux-musl/vault install
```

Or from source:

```sh
cargo build --release
target/release/vault install
```

No questions, no password, on either system. Running it again with a new build replaces the
program and restarts the daemon, and keeps the vault. On a new machine: `vault install
--for-restore`, then `vault restore <backup file>`.

On Linux, build with a Rust toolchain (`rustup`); nothing else is needed (no OpenSSL headers).

**Moving a Mac vault to Linux:** copy `vault/` and `vault-backups/` from
`~/Library/Application Support/Volgenic/` into `~/.local/share/volgenic/`, then `vault install`.
Or restore a backup: `vault install --for-restore`, then `vault restore FILE`.

## Stable ids and versions

- **Every secret has an id**: 32 random hex digits, given when it is added. It never changes:
  `vault rename` keeps it, and restores keep it. Each secret also has a `version` (1 when
  added, plus one for each change, a rename today) and an `updated_at`.
- **The vault has a stable identity**: the first 128 bits of the SHA-256 of its recovery public
  key, shown by `vault status`. It survives restores and moves to another machine, because the
  recovery key does, and never names a machine. Its first 12 digits are the recovery-key
  fingerprint on the kit. The `vault_id` is the copy: new at every restore, and the prefix of
  the backup files' names.
- **The vault file and backups are format 9** (format 2 plus the `claude_plan` kind and the
  intake key in format 3, the `codex_login` and `grok_login` kinds and a login's handover
  state in format 4, the `personal_details` kind in format 5, the `app_secret` kind with its
  application and lease flag in format 6, the `wallet` kind with its chain, address, caps and
  last day's payments in format 7, Solana and Tron wallets in format 8, and the `google_ai_login`
  kind in format 9). An older vault file is migrated at the daemon's first start, as a change of
  its own (audited and backed up): a format-1 file's secrets get their ids, and a format-2 file
  gets its intake key. Older backups restore too. An older build refuses a newer file or backup
  as newer (`newer_format`); don't go back to an older build after upgrading.

## Commands

The `vault` tool can't print a secret, so it is safe for any agent on the machine to run.

| Command | What it does |
|---|---|
| `vault install [--for-restore] [--json]` | Installs or updates the vault for your user. `--json`: one JSON object instead of prose, for a program ([docs/json.md](docs/json.md)). |
| `vault add NAME --kind api-key --host HOST --method GET --path /v1 --header "Authorization: Bearer {key}"` | Adds an API key with its rule. The value is read at a hidden prompt, or from standard input with `--yes`. |
| `vault add NAME --kind login --site SITE --username USER` | Adds a login. The in-app browser fills it into a page on that site; see "Logins in the browser" below. |
| `vault add NAME --kind 2fa --site SITE` | Adds a 2FA seed: base32, or an `otpauth://` link. |
| `vault add NAME --kind claude_plan` | Adds a Claude plan's token (from `claude setup-token`). Used only by `stream`, only to `api.anthropic.com`. The host's daemon normally stores plans itself (`import_plan`, `add_sealed`). |
| `vault add NAME --kind codex_login --yes < auth.json` | Adds a Codex login (its `auth.json`, whole), which the vault alone renews from then on. Used only by `stream`, only to `chatgpt.com`. `grok_login` likewise for Grok Build, to `cli-chat-proxy.grok.com`; `google_ai_login` for a Google AI Pro or Ultra plan (agy's token file, `antigravity-cli/antigravity-oauth-token`), to Google's Cloud Code. The host's daemon normally hands logins over itself (`import_login` and `claim_refresh`, or `add_sealed`). |
| `vault add NAME --kind personal_details` | Adds your real details (name, address, birthday, phone), asked one field at a time; leave any empty. Or `--yes` with v1's JSON object on standard input (`{"name","address","birthday","phone"}`). Stored and listed only, for now: `list` says which fields are filled, never what they say. See "Personal details" below. |
| `vault add NAME --kind app_secret --app APP [--leasable]` | Adds one of an application's build or deploy secrets (an npm token, a database URL). With `--leasable` a build may lease it, sealed to the build's own key for at most a day; without it, it is stored and listed only. Set only when it is added. See "App secrets and leases" below. |
| `vault wallet create NAME --per-payment USD --daily USD [--chain ethereum\|solana\|tron\|sepolia\|solana_devnet\|tron_nile] [fee caps]` | Makes a wallet: the vault makes its key and never shows it, and prints the address to fund. Asks for the recovery key. Fee caps, the wallet's chain's only: `--max-fee-gwei 100 --daily-fees-eth 0.02` (Ethereum), `--max-priority-fee-micro-lamports 1000000 --daily-fees-sol 0.05` (Solana), `--max-fee-limit-trx 30 --daily-fees-trx 300` (Tron), those being the defaults. See "Wallets" below. |
| `vault wallet caps NAME [--per-payment USD] [--daily USD] [fee caps]` | Changes a wallet's caps (the ones you leave out stay). Asks for the recovery key. |
| `vault delete NAME` | Deletes a secret. Earlier backups keep it. A wallet isn't deleted: its key is the only way to its funds. |
| `vault rename NAME NEW` | Renames a secret; its id, rule and value stay, its version goes up. |
| `vault list` | Ids, names, kinds, versions and sites; for personal details, which fields are filled; for app secrets, the application and whether builds may lease it; for wallets, the address, the caps and what the last 24 hours spent. |
| `vault health` | For each Claude plan and Codex, Grok or Google AI login, by name: whether it works, has expired or was refused (sign in again), and who renews it. |
| `vault status [--json]` | The program, the daemon, backups and the audit chain. `--json`: one JSON object for a program, with a `problems` list and the command for each ([docs/json.md](docs/json.md)); no secret names. |
| `vault --version` | The version, the commit it was built from and the target. |
| `vault audit [--all]` | The audit log's last 25 lines (`--all`: every line), with its hash chain checked. Past 4 MiB `audit.log` moves to `audit.log.<n>` and the chain carries on in a new file; all are kept. `status` and `audit` check the lines written since the daemon last checked; `--all` and the daemon's start check every file from the first line. |
| `vault verify-backup [--with-recovery-key]` | Checks the newest backup decrypts and matches the vault. |
| `vault backup` | Writes (or re-checks) the current backup now. |
| `vault confirm-kit` | Optional: paste the recovery key back; deletes the kit file. |
| `vault reset` / `vault restore [FILE]` | Remove the vault (with the recovery key) and restore a backup into an empty one. |
| `vault install-mirror` | Optional, macOS: a LaunchAgent that copies backups to a mirror folder. |

## For agents: the socket

`~/Library/Application Support/Volgenic/socket/vault.sock` on macOS,
`/run/user/<uid>/volgenic/vault.sock` on Linux. Send one JSON line, read one JSON line back:

```sh
S="$HOME/Library/Application Support/Volgenic/socket/vault.sock"   # Linux: S=/run/user/$(id -u)/volgenic/vault.sock
echo '{"op":"list","protocol":2,"request_id":"r1"}' | nc -U "$S"
echo '{"op":"totp","name":"github-2fa"}' | nc -U "$S"
echo '{"op":"totp","id":"c92f14b1c738a77ebeb59e609414c927"}' | nc -U "$S"
echo '{"op":"proxy","name":"openai","method":"GET","path":"/v1/models"}' | nc -U "$S"
```

- **Protocol 2.** A request may carry `"protocol": 2` and a `"request_id"` (a string of 1 to 128
  printable ASCII characters, or a whole number). Every reply, errors included, carries
  `"protocol": 2` and echoes the `request_id` as sent. A request without `protocol` is protocol 1
  and is served the same way. A newer protocol is refused with `unsupported_protocol`.
- **Naming a secret:** `totp`, `proxy`, `delete` and `rename` take `"name"` or `"id"`, one of them.
- `list` returns `{"ok":true,"secrets":[{"id","name","kind","site","version"}]}`; a
  `personal_details` secret also has `"fields":["name","address",...]`, the filled ones, and an
  `app_secret` has `"app"` and `"leasable"`.
- `totp` returns `{"ok":true,"id":"...","name":"github-2fa","code":"123456","seconds_left":17}`.
- `proxy` takes `method`, `path` (with query), optional `headers` (an object) and `body` or
  `body_base64`. It returns `{"ok":true,"status":200,"headers":[[name,value]],"body":"..."}`.
  The key goes only into the header its rule names, only to the rule's host, method and path.
  You may also name the destination you meant, `host` and `port` (443 if left out): when it
  isn't the key's rule's (the host compared case-insensitively), the call is refused
  `rule_mismatch` before anything is sent, and the refusal is audited. Without them, the call
  goes to the rule's host, as before:
  `{"op":"proxy","name":"openai","host":"api.openai.com","port":443,"method":"GET","path":"/v1/models"}`.
  Redirects come back to you unfollowed. A reply that contains the key is withheld
  (`echo_blocked`).
- **What `proxy` and `stream` refuse** before anything is sent, so an upstream can't be steered
  outside the method, path and host the rule (or kind) allows: method, URL and host override
  headers (`x-http-method-override`, `x-http-method`, `x-method-override`, `x-original-url`,
  `x-rewrite-url`, `x-original-host` and the rest of `rules::OVERRIDE_HEADERS`, besides every
  `x-forwarded-*` and `proxy-*` header), `header_not_allowed`; and a path with `%25` (double
  encoding), a `;` path parameter (`..;`), a backslash, an encoded slash, backslash, dot,
  semicolon or NUL, a `%u` escape, escapes that don't decode to valid UTF-8 (overlong forms like
  `%c0%ae`), or a `.` or `..` segment in any encoding (Unicode that folds to one too, like `．` or `‥`), `bad_request`. A kind's `stream`
  call also refuses the query forms of another credential: `access_token`, `api_key` and
  `oauth_token` for every kind, and for a Google AI login also `key`, `userProject` and
  `quotaUser` (any spelling: `$userProject`, `user_project`, percent-encoded), `rule_mismatch`.
  The refusal names the rule, never a value. A `_method` query or body parameter isn't
  filtered; refusing it is the upstream's job.
- **`stream`** is the streaming proxy, for model calls (the host's model proxy sends it). It
  names a secret whose kind (`claude_plan`, `codex_login`, `grok_login`, `google_ai_login`; the table is
  `src/kinds.rs`) or rule (an API key) decides the upstream host, methods and paths, and which
  headers the vault sets: you never choose those. A Codex login goes to `chatgpt.com` under
  `/backend-api/codex` (and `/backend-api/wham/usage`) with `authorization: Bearer <access token>`
  and `chatgpt-account-id`; a Grok login to `cli-chat-proxy.grok.com` under `/v1` with
  `authorization: Bearer <access token>` (your `x-xai-token-auth` and `x-grok-*` headers pass
  through); a Google AI login to `daily-cloudcode-pa.googleapis.com` (or `cloudcode-pa`) at
  `/v1internal:<method>` with `authorization: Bearer <access token>` (`x-goog-api-key`, `cookie`,
  `x-goog-user-project` and `x-goog-quota-user` are refused, and so are their query forms). For a login the vault renews, a call that finds it due renews it first, and a 401
  from the upstream is held back: the vault renews the login and makes the call once more, so
  you see the second reply only. **A login's 401 never reaches you as a 401** (Codex fails the
  turn on one, Grok retries it four times): when no renewal can fix it, the call ends with one
  error line instead, `credential_refused` (the provider refused the renewal, the login was
  refused already, or a fresh token got a 401 too: sign in again) or `login_awaiting_claim` (an
  imported login the host's daemon hasn't claimed yet, which the vault may not renew). The
  host's proxy answers either as 503, never 401. Only the token server's answer to a renewal
  marks a login `refused` and stops its renewal; an API's 401 (or Google's Terms of Service 403)
  answers a request the caller shaped, so `vault health` shows it as `expired` and the vault
  keeps renewing. A 401 within a minute of a renewal that worked isn't renewed again. The request line is followed by exactly `body_len` raw body bytes (up to 32 MiB):

  ```json
  {"op":"stream","name":"main","method":"POST","path":"/v1/messages?beta=true",
   "headers":[["anthropic-version","2023-06-01"],["anthropic-beta","oauth-2025-04-20"],["content-type","application/json"]],
   "body_len":1234,"idle_timeout_secs":300}
  ```

  The reply is a head line (`{"ok":true,"status":200,"headers":[[name,value],...]}`), then the body
  as it arrives in chunks, each `<length in decimal>\n<bytes>`, then `0\n` and a trailer line:
  `{"ok":true,"end":"complete","bytes":N}`, or `"ok":false` with `end` `idle_timeout`,
  `upstream_failed` or `echo_blocked` for a reply cut short. A refusal (or a failure before the
  reply's head) is one error line instead. There is no overall time or size limit; the upstream
  must send something at least every `idle_timeout_secs` (300 by default, at most 900). Close
  your socket to cancel: the vault drops the upstream connection within a fraction of a second.
  Keep your side open until the trailer (on macOS a half-close reads as hanging up). Don't send
  `authorization`, `x-api-key`, `accept-encoding`, `host`, `content-length` or hop-by-hop
  headers: they are refused (`header_not_allowed`). The reply is unencoded (the vault asks for
  `identity`), and a reply that would carry the token is stopped before it does (`echo_blocked`).
- **`health`** returns `{"ok":true,"credentials":[{"id","name","kind","version","state","checked_at","status","refresh","expires_at","reason"?}]}`
  for every Claude plan and Codex, Grok or Google AI login, by name only: `state` is `works`, `expired`
  (also: past its expiry and not renewed), `refused` (sign in again) or `unknown` (not used since
  it was stored), from the last reply that said; `refresh` is `never` (a plan's token lasts a year,
  and a new sign-in replaces it), `by_vault` (the vault alone renews it) or `awaiting_claim` (an
  imported login the host's daemon hasn't handed over yet; the vault uses it but doesn't renew it).
  `reason`, when present, is a fixed sentence saying more than the status: today only a Google AI
  login that Google refused under its Terms of Service (a 403 `PERMISSION_DENIED` naming them).
- **`add_sealed`** stores a value that reached this machine sealed to the vault's intake key (in
  `vault status --json`, `intake`), so Volgenic's server could carry it without reading it:
  `{"op":"add_sealed","name":"main","kind":"claude_plan","sealed_base64":"<base64 of an age file>","replace":true}`.
  What is sealed is `{"v":1,"name","kind","site"?,"rule"?,"username"?,"value"}`; `name` and `kind`
  must match the request's, and the rule is read only from inside it. `replace` replaces a stored
  secret of that name and kind (same id, version up), for a `claude_plan`, `codex_login`,
  `grok_login` or `google_ai_login` only, whose hosts the vault fixes; a sealed login's `value` is
  its `auth.json` (a Google AI login's, agy's token file), whole, and it is the vault's alone to renew from the start (a new sign-in); a sealed API key can only be added under a new name, never replace a stored one
  (`sealed_invalid`), since that would let whoever sealed it change where the key is sent. Delete with `delete` by name, as for any secret.
  Sealed personal details carry v1's object as a JSON string in `value`
  (`{"v":1,"name":"v1-details","kind":"personal_details","value":"{\"name\":\"...\",\"address\":\"...\"}"}`);
  they are added under a new name only, like an API key (whoever seals could otherwise change
  the address a form is filled with): delete, then add, to change them.
  A sealed app secret carries its `app` and, to be leasable, `"leasable":true`
  (`{"v":1,"name":"shop-npm","kind":"app_secret","app":"shop","leasable":true,"value":"npm_..."}`);
  only an `app_secret` may carry either, and it too is added under a new name only.
- **`fill`** and **`generate_login`** are for the browser engines that type a saved login into a
  page, and make sign-up passwords ("Logins in the browser" below).
- **`lease`** seals app secrets to a build's own key (host only; "App secrets and leases" below).
- **`sign`** signs one token payment from a wallet, within its caps, on Ethereum with a ladder of
  fee bumps, or on Ethereum with `"cancel":true` a 0-ETH cancel at a payment's nonce (the host's
  payment relay; "Wallets" below).
- **`import_plan`** is the upgrade's move of the host's existing plan tokens into the vault:
  `{"op":"import_plan","plans":[{"name":"main","value":"sk-ant-oat01-..."}]}` returns each plan's
  `result` by name: `done` (added, or a different value replaced, version up), `unchanged` (already
  there with that value) or `failed` (with `error`). Safe to repeat. The host reads its own token
  files and Keychain items and hands them over; the vault never reads the Keychain.
- **`import_login`** and **`claim_refresh`** hand the host's existing Codex and Grok logins to the
  vault, in the order below ("Handing over a Codex or Grok login").
  `{"op":"import_login","logins":[{"name":"codex","kind":"codex_login","auth_json":"<the file's text>"}]}`
  returns each login's `result` by name (`done`, `unchanged` or `failed` with `error`), its
  `version` and whether it is `claimed`; `{"op":"claim_refresh","name":"codex","version":1}`
  returns `{"ok":true,"secret":{...},"claimed":true,"already":false}`.
- The other requests (`status`, `audit`, `add`, `delete`, `rename`, `confirm-kit`, `reset`, `restore`,
  `backup`, `verify-backup`, `read-backup`, `mirror-plan`, `mirror-report`) are what the
  command-line tool and the mirror send; `src/protocol.rs` lists them.
- Errors are `{"ok":false,"error":"rule_mismatch","message":"..."}`; `not_leasable` adds
  `"names"`. `sign` over a cap answers `over_cap`.

## Logins in the browser

Agents sign in with your saved logins in Volgenic for Mac's in-app browser (and the host daemon's
Chrome) without ever seeing a password (work item #7663). The agent names a login and the page's
fields; the engine that types asks the vault itself, and the agent gets back only what was filled.
Neither the host daemon (for an app tab), Volgenic's server nor the agent holds the password.

- **`fill`**, from the engine about to type:

  ```json
  {"op":"fill","name":"acme-shop","origin":"https://accounts.acme.com","fields":["username","password"],
   "engine":"app","tab":"w3","on_behalf_of":"agent @x","protocol":2,"request_id":"f1"}
  ```

  `name` or `id`. `origin` is the scheme, host and port of the frame that holds the fields, as the
  browser reports it (WebKit's `WKFrameInfo.securityOrigin`, Chrome's frame tree), never from the
  page's own scripts. `fields` is `username`, `password` or both, so a two-step sign-in can fill
  the username on one page and the password on the next. `engine`, `tab` and `on_behalf_of` go to
  the audit line only.
  - **Refused** unless the name is a login (`no_such_login`), and the origin is `https:` with the
    same registrable domain as the login's site (`site_mismatch`): one label below a public suffix,
    from the Public Suffix List compiled in, so `accounts.shopify.com` is `shopify.com`'s site and
    `alice.github.io` isn't `bob.github.io`'s. An IP address, `localhost` or a bare public suffix
    is never a site.
  - **Audited** before the answer leaves: one `fill` line with the login's name and id, the frame's
    host, the fields, the engine, the tab, for whom and the caller's program, flushed to disk. No
    line, no values (`audit_unavailable`). A refusal is a `fill denied: <code>` line.
  - **Answers** `{"ok":true,"name","id","site","site_matched":"acme.com","values":{"username":"...","password":"..."}}`,
    only the fields asked for. The engine types them into the page and nowhere else: never into a
    log, a result, an error or anything the daemon or the agent sees.
- **`generate_login`** makes a sign-up's password: `{"op":"generate_login","name":"acme-shop","site":"acme.com","username":"sales@example.com","length":20}`.
  The vault makes a random password (`length` 12 to 128, 20 by default: letters, digits and
  `! # % + - . = ? @ _`, at least one of each), stores it as a login for the site's host with that
  username, backs up and audits (`generate-login`), and answers `add`'s reply, never the password:
  `{"ok":true,"secret":{"id","name","kind":"login","site","version":1},"backup":{...}}`. A name
  already in the vault is `name_taken`; a site with no registrable domain, `invalid_secret`. Then
  `fill` types it into the sign-up form (and into a "confirm password" field, with
  `"fields":["password"]`).

**What this accepts.** The vault can't tell Volgenic for Mac from any other program running as
you, so any such program can ask `fill` for a login by naming an origin on its site. That is no
more than it can already do by reading the vault's key file; the vault keeps passwords out of
agents' normal path, and every fill is an audit line naming the program that asked. Agents in
containers can't reach the socket at all. `fill` doesn't check its caller's code signature yet:
once Volgenic for Mac is signed with a team's Developer ID and the hardened runtime, `fill` could
require that signature of its caller.

## A Google AI login (Antigravity)

A Google AI Pro or Ultra plan, signed in with Antigravity's `agy` (work item #8147; design page
https://volgenic.com/pages/723f1bb8-14c0-4e82-a7b8-a4ed80ba93a9). The host names it
`google_ai.pro` or `google_ai.ultra`, from `loadCodeAssist`'s tier.

- **What it takes:** agy's token file, whole,
  `{"token":{"access_token","token_type","refresh_token","expiry","expires_in"},"auth_method":"consumer"}`,
  sealed (`add_sealed`, normally) or piped to `vault add NAME --kind google_ai_login --yes`. It
  must be a personal sign-in (`auth_method` `consumer`) with a refresh token: a container's
  placeholder (no refresh token), a business sign-in or a Google API key (`AIza...`) is refused.
- **Where it goes:** `stream` only, `POST` or `GET` to `daily-cloudcode-pa.googleapis.com` (the
  default) or `cloudcode-pa.googleapis.com`, at `/v1internal:<method>` or under `/v1internal/`,
  with `authorization: Bearer <access token>`.
- **Renewal:** the vault alone renews it, 10 minutes before its access token expires (they last
  about an hour), at `oauth2.googleapis.com/token` with agy's installed-app OAuth client (the id
  and secret compiled into agy 1.5.13, in `src/logins.rs`). A new refresh token in the reply
  replaces the old. Only `invalid_grant` means sign in again; a 401 `invalid_client` (a client
  Google no longer knows) is tried again later, like a 429 or a 5xx.
- **Health:** a 2xx works; a 401 `UNAUTHENTICATED` is held back, renewed and retried once, and is
  `expired` or `refused` when that can't fix it; a 403 `PERMISSION_DENIED` naming the Terms of
  Service is `refused`, with a `reason` saying so; a 429 `RESOURCE_EXHAUSTED` (the plan's quota)
  or a 5xx says nothing about the token.

## Handing over a Codex or Grok login

Codex and Grok both rotate the refresh token at every renewal, and the old one is dead from then
on. So exactly one party may renew a login at any moment: the host's daemon until it hands the
login over, the vault after. The vault never renews an imported login until the daemon says it
has stopped. For each login (`~/.codex/auth.json`, each account's `CODEX_HOME`, `~/.grok/auth.json`):

0. **On every start, before renewing anything**, the daemon asks `health`. A login listed with
   `refresh: "by_vault"` is the vault's: the daemon never renews it again and never hands its
   file's refresh token to anyone. One with `awaiting_claim` is part way through: carry on at 2.
1. **Stop renewing it**, and record that durably (a marker the daemon reads at start), then wait
   for a renewal already running to finish (the keeper's `exclusive` chain; Grok's own lock).
2. **Read the file whole** (`readWholeLogin`) and send it: `import_login`. Take the reply's
   `version`. `failed`: the login stays the daemon's; nothing about it changed in the vault.
   `unchanged` with `claimed: true`: it was handed over already; you're done.
3. **Claim it**: `claim_refresh` with that name and `version`. From the reply on, only the vault
   renews it. `version_mismatch` means the vault holds another import of it than yours: go back
   to 2.
4. **Record the claim** with the marker, and don't let anything renew the file again: its refresh
   token is the vault's to spend. Model traffic goes through `stream`; a container gets the
   placeholder `auth.json` (no real token), as the scout page on pointing Codex and Grok at the
   proxy describes. A Codex or Grok run on the host itself with the original file would renew it
   and retire the vault's token, so blank the file's refresh token (or move the file aside).

A crash anywhere is safe: before 3 the vault hasn't renewed anything, and importing the same file
again changes nothing (`unchanged`, same version); after 3, step 0 finds `by_vault`. Importing a
different file for a claimed login fails with `login_claimed` and changes nothing: only a new
sign-in replaces it, sealed (`add_sealed` with `replace`, whose `value` is the new `auth.json`).
A renewal stores the new tokens, the rotated refresh token with them, in the vault file before any
call uses the new access token. Two calls that find a login due at once wait for one renewal
between them, so the same refresh token is never sent twice. Renewals go to `auth.openai.com`
and `auth.x.ai` only, which no caller can reach through `stream`.

## Personal details

A `personal_details` secret holds a person's real name, address, birthday and phone, for the few
sites that need the real person (work item #7435). v1 kept them on Volgenic's server
(`personal_details.ciphertext`, one JSON object); core hands them to their owner's vault with
`add_sealed`, as it does v1's logins.

- **Given** as v1's object: `{"name","address","birthday","phone"}`, each a string; any may be
  missing, `null` or empty, at least one filled, no other key. Each field is trimmed text of at
  most 500 characters, with no control character but a line break. Nothing parses the birthday
  or the phone: they are kept as typed.
- **Stored** as the vault's own object with the filled fields only (`src/details.rs`). The
  record also names its filled fields, which `list`, `add`'s reply and the audit line show;
  never a value.
- **Used** by nothing yet: no request gives a value back, `proxy`, `stream` and `totp` refuse it
  (`wrong_kind`). A way for a form-filling agent to fill one field without Volgenic's server
  seeing it is a later step. Today: add, list, rename, delete.

## App secrets and leases

An `app_secret` is one of an application's build or deploy secrets (an npm token, a database URL),
in its owner's vault, for the application it names (work item #7446). A build can't run without
them, so this is **the one kind whose value leaves the vault**, and only one way: a **lease**,
sealed to one build's own key, for at most a day, audited. It is for jobs the host's daemon runs
(builds and deploys), never for an agent.

- **Added** with `vault add NAME --kind app_secret --app APP [--leasable]`, or sealed
  (`add_sealed`, with `app` and `leasable` inside the sealed object). The value is UTF-8 text
  without a NUL, kept exactly as given. **Only a secret added as leasable can be leased**; nothing
  changes the flag later (delete and add again).
- **Listed** with its application and whether it is leasable, never its value.
- **Used only by `lease`.** `stream`, `proxy` and `totp` refuse it (`wrong_kind`).

The build makes an age X25519 key of its own, and the host's daemon asks:

```json
{"protocol":2,"op":"lease","job":"build:4812","recipient":"age1...","names":["shop-npm","shop-db"],
 "ttl_seconds":3600,"request_id":"..."}
```

- `job`: 1 to 128 printable characters, no spaces (`build:<id>`, `deploy:<id>`). `recipient`: an
  age X25519 public key (`age1...`; no SSH or plugin recipients). `names` (and/or `ids`): 1 to 64
  secrets, each once. `ttl_seconds`: 60 to 86,400.
- **Answer:** `{"ok":true,"sealed":[{"name","id","sealed_base64"}],"missing":[names it holds nothing under],"expires_at","job"}`.
  Ciphertext only: each `sealed_base64` is an age file sealed to `recipient`, whose plaintext is
  `{"v":1,"lease":"build:4812","name":"shop-npm","value":"npm_...","expires_at":"2026-11-16T13:00:00Z"}`.
- **The job checks what it opens:** it refuses a plaintext whose `v`, `lease` or `name` isn't
  what it asked for, or whose `expires_at` has passed. The expiry is inside the ciphertext, so no
  relay can change it; the vault can't reach the job to hold it to it.
- **A secret it holds that isn't a leasable app secret refuses the whole lease**, and nothing is
  sealed: `{"ok":false,"error":"not_leasable","message","names":[the refused names]}`. A vault
  older than this answers `bad_request` "unknown op".
- **Audit:** one `lease` line per secret leased (its name and id, the job, the recipient key's
  fingerprint, the expiry and the caller), on disk before the answer leaves; a refusal is one
  `lease denied: <code>` line. Never a value.
- **The accepted gap:** any process running as you can lease to a key of its own, as it can read
  the vault's files today. A lease is never automatic: only secrets you marked leasable, and each
  lease is in `vault audit`. See the threat model's 2026-11-16 (3) block.

## Wallets

Your agents' payments are signed by your vault, with a key that was made there and never leaves
it (work items #7440, #7490). Volgenic's server never holds a key that spends money, so **payments
wait while the vault's machine is off**. An Ethereum payment already sent can still be sped up,
because its fee bumps were signed in advance; a Solana or Tron one can't be, and needn't be ("Fee
bumps" below).

- **`vault wallet create NAME --chain solana --per-payment 50 --daily 200`** makes a key from the
  operating system's random numbers, keeps it as the wallet's value, and prints the address to
  fund. It asks for the recovery key: the socket can't tell you from an agent, and the caps are
  yours alone to set. `vault wallet caps` changes them, the same way.
- **No request returns the key**, not even sealed: `add` and `add_sealed` refuse the `wallet`
  kind (the vault never takes a key from outside), `lease` refuses it (`not_leasable`), `totp`,
  `proxy` and `stream` refuse it (`wrong_kind`), and `delete` refuses it. Its only copies are the
  vault file and its backups, which only the vault key and the Recovery Kit open.
- **Chains**, each with a test network for a dry run (tokens with no value):

  | Chain | Key and address | Tokens | Test network |
  |---|---|---|---|
  | `ethereum` | secp256k1, `0x…` (EIP-55) | USDC, USDT | `sepolia` (USDC) |
  | `solana` | Ed25519, base58 | USDC, USDT | `solana_devnet` (USDC) |
  | `tron` | secp256k1, base58check `T…` | USDT | `tron_nile` (USDT) |

  Contracts, mints and decimals are chain_pay's `ChainPay.Assets`.
- **`sign`** takes structured fields only and builds the transaction itself. There is no field for
  raw bytes, call data or instructions, and a field of another chain is refused (`bad_request`).
  The vault never touches the network: the relay reads the chain (nonce, fees, a recent
  blockhash or block) and broadcasts what it gets back.

  **Ethereum:** an EIP-1559 `transfer(recipient, amount)` call on the token's own contract, value 0.
  ```json
  {"protocol":2,"op":"sign","name":"main-wallet","chain":"ethereum","token":"USDC",
   "to":"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed","amount":"12.50","nonce":7,"gas_limit":78000,
   "max_fee_per_gas":30000000000,"max_priority_fee_per_gas":2000000000,"ladder":4,
   "on_behalf_of":"agent @x, work item #123","request_id":"..."}
  ```
  The recipient is a real address (a mixed-case one with a matching checksum; not zero, not the
  token's contract), the gas limit 21,000 to 150,000, the tip no more than the fee.

  **Solana:** compute-unit limit and price, `CreateIdempotent` of the recipient's associated token
  account (unless `"create_recipient_account":false`), and an SPL `TransferChecked` from the
  wallet's associated token account to the recipient's. The vault derives both token accounts
  itself; `to` is the recipient's **wallet** address, never a token account.
  ```json
  {"protocol":2,"op":"sign","name":"sol-wallet","chain":"solana","token":"USDC",
   "to":"9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu","amount":"12.50",
   "recent_blockhash":"CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8",
   "compute_unit_limit":60000,"compute_unit_price":50000,"on_behalf_of":"agent @x"}
  ```
  The limit is 1,000 to 200,000 compute units; the price, in micro-lamports per unit, is 0 when
  left out. The recipient isn't the wallet itself, the mint or the system program.

  **Tron:** a TRC-20 `transfer(to, amount)` (`TriggerSmartContract`, no TRX value) on the token's
  contract, with the ref block, times and `fee_limit` the caller gives.
  ```json
  {"protocol":2,"op":"sign","name":"tron-wallet","chain":"tron","token":"USDT",
   "to":"TLZeWMhAhsdKJJRwbRw4tBoVu9f75n2FwG","amount":"12.50",
   "ref_block_num":87350971,"ref_block_id":"000000000534debba3791afd2edb6c53b21631db1f574f26b804ecfee83fd2b0",
   "timestamp":1794850405000,"expiration":1794850465000,"fee_limit":20000000,"on_behalf_of":"agent @x"}
  ```
  `ref_block_num` and `ref_block_id` are TronGrid's `getnowblock` (`block_header.raw_data.number`,
  `blockID`); the id must start with the number. `expiration` is at most 60 seconds after
  `timestamp` (v1's window), in the future by the vault's clock, and at most 90 seconds ahead of it
  (60 plus 30 for skew). The recipient is a `T…` address whose checksum matches; not zero, not the
  token's contract, not the wallet itself.

  It answers `{"ok":true,"signed":{"raw","hash",...},"ladder":[...],"from","to","token","contract",
  "amount","worst_fee","fee_unit","replacement","counted_micros","counted_fees","caps",
  "spent_today_micros","fees_today","backup"}`, plus each chain's own:
  - Ethereum: `chain_id`, `nonce`, `gas_limit`; each signed transaction's `max_fee_per_gas` and
    `max_priority_fee_per_gas`; `raw` is `0x` hex for `eth_sendRawTransaction`; and
    `worst_fee_wei`, `counted_fees_wei`, `fees_today_wei` (the names #7440 gave them).
  - Solana: `source_token_account`, `recipient_token_account`, `recent_blockhash`,
    `creates_recipient_account`; `raw` is base64 for `sendTransaction` (`"encoding":"base64"`),
    `hash` the base58 signature (the transaction's id). `ladder` is empty.
  - Tron: `expiration`, `fee_limit`; `raw` is hex of the whole `Transaction` for
    `/wallet/broadcasthex`, `hash` the txid, and `signed.raw_data_hex` for
    `/wallet/broadcasttransaction`. `ladder` is empty.
- **Caps, set by you:** `per_payment` and `daily` (rolling 24 hours) in dollars, USDC and USDT one
  for one; then a per-transaction fee cap and a daily fee cap in the chain's own terms. A payment
  that would pass any of them is refused, `over_cap`, and nothing is signed.

  | Chain | Per transaction | Each payment counts against the daily fee cap |
  |---|---|---|
  | Ethereum | `max_fee_per_gas`, wei per gas (100 gwei) | `gas_limit` × its ladder's top fee (`daily_fees_wei`, 0.02 ETH) |
  | Solana | `max_compute_unit_price`, micro-lamports per compute unit (1,000,000) | 5,000 lamports for the signature, plus price × limit, plus 0.00203928 SOL of rent when it creates the recipient's token account (`daily_fees_lamports`, 0.05 SOL) |
  | Tron | `max_fee_limit_sun`, the most TRX it may burn for energy (30 TRX) | `fee_limit` plus its bandwidth at 1,000 sun a byte (`daily_fees_sun`, 300 TRX) |

  A wallet's caps JSON holds only its own chain's fee caps:
  `{"per_payment_micros","daily_micros","max_fee_per_gas","daily_fees_wei"}` on Ethereum,
  `"max_compute_unit_price","daily_fees_lamports"` on Solana, `"max_fee_limit_sun","daily_fees_sun"`
  on Tron.
- **Fee bumps.** On Ethereum, with `"ladder":N` (0 to 4) the vault also signs N replacements: the
  same transfer at the same nonce, each with both fees raised 12.5% (rounded up), the least a node
  takes as a replacement. If the first stalls while the vault is off, the relay sends the next rung.
  Only one transaction per nonce can mine, so a ladder never pays twice. **Its top is bounded three
  ways:** at most 4 rungs (about 1.6 times the first fee); no rung above the wallet's
  `max_fee_per_gas` or the caller's own `ladder_max_fee_per_gas`, whichever is lower (a rung that
  would pass it isn't signed, so the ladder comes back shorter); and the whole ladder's worst case
  (`gas_limit` times its top fee) counts against the daily fee cap before anything is signed.

  **Solana and Tron have no ladder**, and a request for one is refused. Neither chain has a nonce:
  two signed transactions of the same transfer at different fees are two payments, and both can
  land. What stops a transaction is its expiry: its recent blockhash on Solana (about 150 blocks,
  a minute or two), its `expiration` on Tron (60 seconds here). On Tron a bump isn't needed: there
  is no fee auction, energy has a fixed price, and `fee_limit` is only a ceiling (a transfer whose
  `fee_limit` is too low fails on chain and burns what it used; the relay estimates energy first,
  as v1 did). On Solana a higher priority fee helps only a transaction not yet sent.

  **A stalled payment while the vault is offline:** a Solana or Tron payment that doesn't land
  before it expires is dead and can't pay any more. It needs a new signature, with a fresh
  blockhash or ref block, so it waits, like any payment needing a signature, until the vault's
  machine is back. The relay must not ask for that new one until the first has expired and isn't
  on chain (Solana: `getSignatureStatuses` with history after the block height passed its
  `lastValidBlockHeight`; Tron: no transaction info after a solidified block past its expiration),
  exactly as v1's `broadcast` decided `:expired`. The vault can't see the chain, so the new
  signature counts against the caps again: the caps over-count a payment that expired, never
  under-count one that landed.
- **The same payment asked for again** in the last day counts once against the amount caps
  (`"replacement":true`): on Ethereum the same transfer at a nonce already signed for (only one can
  mine; against the fee cap it counts only for what it raises the worst case by); on Solana and
  Tron the very same transaction (the same fields, blockhash or ref block and times: signing is
  deterministic, so it is the same bytes, which can land only once).
- **A cancel** (v1's cancel button, work item #7491; Ethereum only, since only Ethereum has a nonce, and refused on a Solana or Tron wallet): `sign` with `"cancel":true`, `chain`,
  `nonce` and the fees, and no `to`, `token`, `amount` or Solana or Tron field (sent anyway, the cancel is refused).
  The vault signs a transfer of 0 ETH from the wallet to itself, 21,000 gas and no data, at that
  nonce, and **only at a nonce it signed a payment for in the last 24 hours**. Only one
  transaction per nonce can mine: if the cancel does, nothing is paid; if the payment mines
  first, the cancel is refused by the chain (`nonce too low`) and costs nothing.

```json
{"protocol":2,"op":"sign","name":"main-wallet","cancel":true,"chain":"ethereum","nonce":7,
 "max_fee_per_gas":40000000000,"max_priority_fee_per_gas":2500000000,"ladder":2,
 "on_behalf_of":"owner's cancel, payment #123","request_id":"..."}
```

  It answers `{"ok":true,"cancel":true,"signed":{...},"ladder":[...],"from","to","nonce","gas_limit",
  "cancels":["12.5 USDC to 0x..."],"worst_fee_wei","counted_fees_wei","caps","spent_today_micros",
  "fees_today_wei","backup"}`. A node takes it as the payment's replacement only with both fees
  12.5% above the one it replaces, so the relay picks the fees as v1 did (`bump_fees`: raised from
  the highest rung it sent, and at least twice the base fee plus the tip). The fee and its ladder
  are bounded exactly as a payment's (`max_fee_per_gas`, at most 4 rungs, the caller's own
  ceiling). It moves no value and counts no amount; its worst case (21,000 gas at its top rung)
  counts against `daily_fees` for what it raises that nonce's worst case by, since only one of
  the payment and its cancels can be paid for.
- **Audit:** one `sign` line per payment (chain, amount, token, recipient, the chain's own terms,
  the hash, what it counted, `on_behalf_of`, the caller hint and request id), written with the
  change that records the payment, and on Ethereum one `sign-ladder` line per ladder (how many
  rungs, the top fee, the worst-case fee, every hash), both flushed to disk before the answer
  leaves. A refusal is one `sign denied: <code>` line. Each cancel writes one `sign-cancel` line
  (the nonce, the fees, the payments it cancels, its hash and its ladder's, the worst-case fee and
  what it counted, the caller), the same way; a refused one, `sign-cancel denied: <code>`.
  `wallet-create` and `wallet-caps` lines show the address and the caps. Never a key.
- **Each payment is a change** (the last day's payments are in the vault file, so the daily caps
  survive a restart), with its own backup.

## Build

A Rust (Cargo) project with no native shim: `cargo build` is the gate, on macOS or Linux.
`cargo build --features test-upstream` is for local evidence only and never released: its
daemon sends every kind's hosts and token servers (`api.anthropic.com`, `chatgpt.com`,
`auth.openai.com`, `cli-chat-proxy.grok.com`, `auth.x.ai`, `daily-cloudcode-pa.googleapis.com`,
`cloudcode-pa.googleapis.com`, `oauth2.googleapis.com`) to `127.0.0.1:$VAULT_TEST_UPSTREAM_PORT` and also trusts the CA in
`$VAULT_TEST_CA`, so a local test server can stand in for Anthropic over real TLS.
Release builds (static Linux, and macOS on a Mac): `scripts/release.sh`, described in
[docs/releasing.md](docs/releasing.md).

## Tests: none, as an experiment

The owner, 2026-11-07, for Volgenic v2's core, app and host, extended to the vault on 2026-11-09
(work item #6101): the vault starts with no tests at all. See `AGENTS.md`. The gate is that
`cargo build` succeeds, plus a terminal recording of anything a person can see.
