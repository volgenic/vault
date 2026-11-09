# volgenic/vault

Volgenic's vault: keeps your agents' secrets on your own machine and lets agents use them without
seeing them. The design is the owner's decision page, "Volgenic v2 secret store: secrets on the
user's own hardware", https://volgenic.com/pages/1f495021-effc-4fd2-9160-24cbcd73dbe3.

## Build

A Rust (Cargo) project, macOS only for now; Linux may come later.

```sh
cargo build          # the gate
cargo run            # the command-line executable
```

- `src/lib.rs`: the library crate, platform-neutral. Decisions live here as functions over plain
  values, with nothing tied to macOS, so it can build on Linux later.
- `src/main.rs`: the `vault` command-line executable, a thin shell around the library.
- Keychain and Secure Enclave code goes behind one small key-protection module, the only place
  that touches them. Nothing else in the crate calls macOS key storage directly.

## Tests: none, as an experiment

The owner, 2026-11-07, for Volgenic v2's core, app and host, extended to the vault on 2026-11-09
(work item #6101): the vault starts with no tests at all. We only need to know that it builds.

- **Don't write tests.** Don't add `#[test]` or `#[cfg(test)]` code, a `tests/` folder, CI, GitHub
  Actions or style lints (no rustfmt or clippy gate).
- **The gate for a change is that `cargo build` succeeds.** A worker runs it once at the end; a
  reviewer reads the code and runs it once. A missing test is not a finding.
- **Anything a person can see** (the command's output, a prompt, an approval) gets a short
  terminal recording or screenshots in its pull request. That is where a broken experience is
  caught: by the author and the reviewer looking.
- **A test is added only for a regression that actually happened, and only when the owner asks
  for it.** Then follow the test guidelines,
  https://volgenic.com/pages/6ddc923c-9ba4-468c-990b-d45d722b381c, and the test discipline at
  `/kit/icm/test-discipline/CONTEXT.md` (in every Volgenic container), which also covers setting
  up the lint and the unit and integration split that day.
- Decisions still belong in pure, deterministic code in the library crate, with side effects
  (Keychain, files, network, the clock) in a thin shell. That keeps a bug findable and a later
  test cheap.
- No change ever calls a paid provider to prove itself.
