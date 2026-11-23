# Security audit: volgenic/vault, run 1 (2026-11-23)

Work item #8521. Profile `standard`. Source: commit `9b36136c24f521883f3bc2d2bbbe9773e76b35a7`,
clean tree. Scope: `src/`, `build.rs`, `Cargo.toml`, `Cargo.lock`, `scripts/release.sh`, `docs/`.
There were no prior runs.

## 1. Run, scope and limits

- **This is a partial pass.** The run status is `incomplete`, with `incomplete_reason`
  `wave_limit_reached`. Hunting stopped under volgenic.md stop rule 3, the wave limit of 2. The
  wave-1 post-wave critic did run, and it added 5 units that wave 2 then covered. No post-wave
  critic ran after wave 2, and no final-clean critic ran. **So this report makes no clean-coverage
  claim.** Gaps a later critic might name are unknown.
- **Budget.** The parent proposed 30 agent runs; the user set no budget. It was raised to 32 in
  the open, so that every candidate wave 2 found could get both verifier passes. The reason is
  recorded in `run-metadata.json`. 31 runs were spent:
  - 4 reconnaissance
  - 9 wave-1 hunters
  - 1 critic
  - 3 wave-2 hunters
  - 6 Phase 3 verifiers
  - 5 Phase 5 verifiers
- **Execution was source-and-local only.** Probes ran this repository's own code on dummy data,
  in scratch copies, through the owner-approved wrapper. That wrapper sets an empty environment,
  `prlimit`, `timeout`, and loopback-only proxy variables. There is no OS sandbox in this
  container. The deviations are listed in `run-metadata.json`.
- **Nothing called production, a deployment or a provider API.**
- **Deferred and out of scope:**
  - No unit was deferred.
  - The host and core repositories are out of scope. They were read only as read-only mirrors,
    to settle reachability, and never treated as proof.
  - The macOS-only code (`cfg(target_os = "macos")`) was reviewed from source only. Probes ran
    on Linux.
- **Accepted design, not reported.** Every process running as the owner's user is trusted as the
  owner (`src/protocol.rs:3-4`, README "Who can use it"). Such a process can read or unseal the
  vault key, so same-UID self-impact is never a finding here. Several leads below depend on
  whether a *relayed* caller (a container agent going through host or core) can reach an op. That
  is marked "needs a check on the other side".

## 2. Posture

The vault holds up well against the boundaries it claims:

- The socket admits only the owner's UID.
- Secrets stay in locked, wiped buffers and never cross the socket except on the `secret` op.
- The vault file is authenticated encryption with its id bound in.
- The proxy and stream pin hosts, refuse redirects and environment proxies, and scrub echoed
  keys.
- Wallet signing stays inside caps.

Nothing was confirmed. The open questions are all at one edge: the vault checks a request by its
own reading of the HTTP request line and headers, and some upstreams read the same request
differently (override headers, `..;` paths, query-string system parameters). That is where to
look first.

## 3. Confirmed findings

None. No severity counts.

## 4. Confirmed finding detail

None, so there is no `FINDINGS-DETAIL.md`.

## 5. Needs validation

These five leads passed both verifier passes. They are not vulnerabilities and have no
severity. `NEEDS-VALIDATION.md` has each one's full trace, evidence and plans.

| # | Lead | Trace | Waits on | Local next step | Owner check |
|---|------|-------|----------|-----------------|-------------|
| 1 | The proxy forwards method/path override headers (`x-http-method-override`, `x-original-url` and others). An upstream that honours them can escape a key's method and path rule. | `src/rules.rs:45-59`, `272-277` → `src/proxy.rs:105` | Whether any upstream with a narrow rule honours those headers, and whether any real rule is narrower than the key's own scope | A loopback HTTPS fixture that dispatches on the override header, called through `proxy::send` | Read each API-key rule in `vault list` against the provider's documentation. Send no request. |
| 2 | `check_path` accepts `..;` segments and `%252e` (double-encoded dots). Some servers normalise these outside the rule's prefix. | `src/rules.rs:186-195`, `210` → `src/proxy.rs:101` | Whether any upstream behind a prefix narrower than `/` strips `;` parameters or decodes twice | A loopback fixture that strips path parameters, and one that decodes twice | Check each narrow-prefix provider's front end from its public documentation |
| 3 | For `google_ai_login`, `key=`, `userProject=` and `quotaUser=` in the query get around the kind's header denylist. | `src/kinds.rs:217-230`, `src/rules.rs:165`, `src/stream.rs:80` | Whether Cloud Code honours those system parameters with an OAuth bearer token, and whether the owner can use a billed project | A pure `stream::plan` probe: the query passes, the header form is refused | One no-cost call to a project with no billing, **only with the owner's approval of that run** |
| 4 | A stream caller who can make the upstream answer 401 to a valid token gets the login marked Refused. Renewal then stops until a 2xx at that version. | `src/stream.rs:344` → `src/server.rs:1214`, `1231`, `1271`; `src/health.rs:55-57` | Whether any caller input draws a 401 from a valid token, and whether host relays an agent's stream headers while denying it `delete`/`rename` | A loopback Grok fixture that answers 401 to one header | Read volgenic/host's stream relay for container agents. Needs a check on the other side. |
| 5 | Caller-supplied names, methods, paths and hosts reached the owner's terminal raw in `vault audit` and `vault status`. | `src/server.rs:949`, `1428`, `1455` → `src/main.rs:863-879`, `849` | Whether any relay in front of host's browser engine filters `account` before `fill`. Needs a check on the other side. | Done: `agents/verify-p3-audittext/artifacts/out.txt` shows ESC, CR/LF and BEL surviving to the print | `vault audit \| cat -v` after an agent sign-in with a dummy escape string. **The CLI side is fixed in this pull request (H-01).** |

## 6. Hardening and positive patterns

**Hardening.** `HARDENING.md` has 41 deduplicated notes. None crosses a boundary. These are the
ones most worth doing:

- Sort backups by parsed generation (`src/backup.rs:295`).
- Bind a renewal's compare-and-set to the value, not to the version that `rename` raises
  (`src/vault.rs:898-906`).
- Set a total deadline per request line (`src/server.rs:411`).
- Remap `CARGO_HOME` out of release binaries, and sign `SHA256SUMS` (`scripts/release.sh`).

This pull request fixes three exposures that hunters noted:

- **H-01.** The CLI showed control characters raw. It now shows them as `?`.
- **H-02.** `mirror-report`'s `newest_file` kept control characters. They are now stripped.
- **H-03.** The vault file, backups and outgoing secret requests left an unwiped copy behind each
  time a serde buffer reallocated. They are now encoded into one wiped buffer.

**Positive patterns seen in source:**

- Peer-UID checks on every connection (`src/platform.rs`).
- `SecretValue` with mlock and zeroize, and a hand-written JSON writer for replies that carry a
  secret (R1).
- Redirects off, `no_proxy`, `https_only` (R10, R11).
- Write-then-rename with `create_new` for every file the vault writes (`src/store.rs:339-361`).
- A recovery key for wallet creation and cap changes, and a hash-chained audit log.

## 7. Coverage

The ledger has 25 units: 20 covered, 5 candidate, 0 blocked, 0 deferred.

- **The 5 candidate units** carry the five leads above, plus one rejected record:
  `vault:main.rs:wallet_caps:name-resolved-twice`. That race is real, but volgenic/core allows
  `rename` only to the person's own session. Every other caller is same-UID.
- **Exclusions:** the webview and native-bridge classes (there is no webview in this crate),
  quota scheduling (a single-user daemon), and browser-session classes (the vault issues no
  cookies).
- **Critic result:** the one critic ran after wave 1 and accepted 5 missing units. No critic ran
  after wave 2 (stop rule 3), so there is no final-clean result.

Verdict counts in `findings.json`: confirmed 0, needs_validation 5, rejected 1.
