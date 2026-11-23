# Maintainability notes: volgenic/vault, 2026-11-23

Work item #8521, written beside the security run in `docs/security-audit/run-1/`. The source is
commit 9b36136 plus this pull request's fixes. Line numbers refer to the code as this pull request
leaves it. The vault has no tests by the owner's decision (AGENTS.md), so none of these notes asks
for one.

The library and shell split holds up well overall. Decisions sit in pure functions over plain
values: `rules::check_path`, `proxy::check`, `wallet::check`, `fill::check`, `lease`, `sites`,
`intake`, `audit::check`. The I/O sits in `server`, `store`, `keyprotect` and `main`. The notes
below are the places that drift from that split, or that make a change in one place easy to miss
in another.

## Fixed in this pull request

| ID | What | Where |
|----|------|-------|
| H-01 | `vault audit` and `vault status` showed audit-log lines, recent changes and daemon-log lines without filtering them. A secret name or mirror detail with terminal escape sequences reached the owner's terminal as-is. The CLI now shows control characters as `?`. | `src/main.rs:859` (`printable`) and its call sites |
| H-02 | `mirror-report` capped `newest_file` at 300 characters but kept its control characters, while `detail` beside it was filtered. Both are now filtered. | `src/server.rs:837` |
| H-03 | `store::save`, the backup writer and `client::call_secret` serialized secrets with `serde_json::to_vec` into a growing `Vec`. Each reallocation left an unwiped copy of the plaintext behind. `secret::to_wiped_json` now measures first, then writes once into an exact-size `Zeroizing` buffer. | `src/secret.rs`, `src/store.rs`, `src/backup.rs`, `src/client.rs` |
| M-01 | Docs that contradicted the code: two error strings said readable formats were "1 to 4" when `model::READABLE_FORMATS` is wider; the "Who sent a request" doc comment sat on `StreamCall`, not on `Caller`; and the README said `fill` checks its caller's code signature, which it doesn't. | `src/store.rs:296`, `src/backup.rs:229`, `src/server.rs`, `README.md:323` |

## Recommendations (not changed here)

None of these changes behaviour, but each touches code on a security path. The audit's rule is
to report rather than refactor code like that.

### 1. `Server::dispatch` is one 400-line match that mixes decisions with I/O

`src/server.rs:460-857`. Each arm parses arguments, decides, writes the store, appends to the
audit log and writes the reply. Several arms hold real policy inline. One example is the API-key
rule construction and the "an API key needs a rule" refusal. Another is the wallet approval text
built at `src/server.rs:1056-1061` and `1116-1118`.

**Recommendation:** move each arm's decision into a library function that takes plain values and
returns either a plan or an error (in the style of `fill::check` and `wallet::check`). The arm
then keeps only the store read and write, the audit append and the reply. That also makes the
next item fall out naturally.

### 2. API-key rule building is duplicated in `Add` and `AddSealed`

`src/server.rs:534-544` (sealed intake) and `src/server.rs:715-725` (plain add) have the same
`match (kind, rule)` with the same `parse_rule` call and the same error text. A future change to
what an API key's rule must contain (for example a required port, or the path checks the
security report recommends) has to be made twice. Missing one copy would let sealed intake accept
a rule that a plain add refuses.

**Recommendation:** add one `rules::rule_for(kind, Option<&RuleInput>) -> Result<Option<ProxyRule>, VaultError>` and call it from both arms.

### 3. Eleven hand-written "strip control characters and cap" expressions

These sites all write the same one-line filter (`chars().filter(|c| !c.is_control()).take(n)`)
with a different `n`:

- `src/server.rs:832, 837, 902, 1056-1059, 1061, 1116, 1118`
- `src/fill.rs:75`
- `src/sites.rs:100`

The CLI's new `printable` (`src/main.rs:859`) does a related job. The validators in
`src/model.rs:473, 485, 497` and `src/wallet.rs:670` also treat DEL (`\u{7f}`) explicitly, while
the filters rely on `is_control` covering it. It does, but the codebase doesn't say so in one
place.

**Recommendation:** one `text::shown(s, max_chars) -> String` in the library, used everywhere
text from a caller is echoed into an approval, a report or the log. Its doc comment should say
what it removes. Then H-02's kind of bug (one field filtered, its neighbour not) can't recur.

### 4. Proxy and stream are two implementations of "call an API with a key"

- **HTTP clients.** `src/proxy.rs:37-53` and `src/stream.rs:216-231` each build a `reqwest`
  client with the same R10/R11 policy: no redirects, no environment proxies, HTTPS only, and the
  per-OS TLS backend. A policy change has to be made in both.
- **Credential headers.** `proxy::build_header` (`src/proxy.rs:138`) and
  `stream::credential_header` (`src/stream.rs:479`) are the same function with different error
  text. The second one's doc comment even points at the first.
- **The checks they apply differ.** `stream` strips `set-cookie` from the upstream response
  (`src/stream.rs:51`), while `proxy` passes response headers through. The proxy builds its URL
  from the rule's port (`src/proxy.rs:78`), while stream uses `plan.port`. The body caps also differ: 32 MiB in
  `stream` (`src/stream.rs:39`), against 1 MiB for requests and 10 MiB for replies in `proxy`
  (`src/proxy.rs:18-19`). Some of these differences may be
  deliberate, but nothing records which. The security report lists the response-header one as a
  design note.

**Recommendation:** one `upstream` module that owns the client builder, the credential header
and the response-header policy, used by both paths. Keep only the transport difference
(blocking vs streaming) in `proxy` and `stream`.

### 5. Dead code

None of these has a caller anywhere in `src/`. Each is either a public function the binary
doesn't use, or a function shaped like one with no caller (checked with `rg`):

- `store::account_by_name` (`src/store.rs:225`). A `getpwnam` lookup nothing calls. Unused
  `unsafe` FFI is worth deleting, so nobody later uses it on input a caller chose.
- `OwnerPaths::expand` (`src/store.rs:184`). Tilde expansion of "something the person typed",
  with no caller.
- `backup::vault_prefix_of` (`src/backup.rs:321`).

**Recommendation:** delete all three. Deleting them is safe, but it isn't the kind of
exposure-removing change this audit fixes on its own authority, so it's listed here.

### 6. Small duplicates and aliases

- **Two SHA-256-of-a-file helpers:** `platform::sha256_of` (`src/platform.rs:16`, used by
  `report`) and `backup::sha256_file` (`src/backup.rs:334`, used by `mirror`). The only
  difference is the error mapping. Keep one, and let the caller map the error.
- **`store::new_vault_id`** (`src/store.rs:267`) is a one-line alias of `new_random_id`, used at
  `src/vault.rs:121` and `1336`. It's harmless, but it reads as if vault ids were generated
  differently from other ids, which they aren't. Inline it, or document why the name exists.

### 7. Long decision functions

- `wallet::check` (`src/wallet.rs:723-886`, about 160 lines) checks the caps, the chain, the
  token, the fee ladder and the per-day totals in one body.
- `vault::import_login` (`src/vault.rs:971-1025`) is moderate in length but mixes classification
  with the store write.

Both are pure enough to stay put. Splitting `wallet::check` into one function per cap would make
each refusal easier to read against the threat-model rule it enforces. This matters most for the
held-signature and fee-ladder rules, which the security report's hardening notes also touch.

### 8. Hand-written JSON writers are justified

`fill`, `lease` and `details` build their reply JSON by hand rather than through `serde`. This
looks like duplication, but it's deliberate: it keeps a secret in one wiped buffer (R1). The
security run found a related gap in `serde`'s string path and lists it under hardening. Leave
them, but give each a one-line comment pointing at R1, so a later cleanup doesn't "simplify" them
back to `serde_json::to_vec`.

### 9. Wording

`src/lib.rs:6` says "in his login". Volgenic's docs use "the owner's login" or "their login".
This is a one-word doc change, left for the next edit to that file.
