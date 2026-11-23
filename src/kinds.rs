//! The kinds that make HTTPS calls for a caller with a credential of their own, and what each
//! allows (R5, R7, R9, R39). Pure data and pure functions, no I/O.
//!
//! A kind's entry decides everything a call may do: the upstream hosts, methods and paths, the
//! headers the vault sets and where their values come from, the caller headers it refuses, how an
//! upstream reply says the credential works or not, and whether the vault renews the credential
//! itself (`refresher`). The caller names a secret and sends a request; it never chooses a host
//! outside the list or a header value the vault sets. A new kind is one more entry here, a `Kind`
//! variant and, when its tokens expire, a refresher. Codex and Grok logins (#7380) are the first
//! kinds with a refresher and with more than one stored field (`logins`); a Google AI login
//! (#8147) is the third.

use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::model::Kind;
use crate::secret::SecretValue;

/// Where a header's value comes from. Never from the caller.
#[derive(Clone, Copy, Debug)]
pub enum HeaderSource {
    /// The stored credential itself (the token), or a login's access token.
    Token,
    /// A Codex login's ChatGPT account id (`logins::Login::account_id`).
    AccountId,
}

/// A header the vault sets on every call of a kind: `name: {prefix}{value}{suffix}`.
#[derive(Clone, Copy, Debug)]
pub struct SetHeader {
    /// Lower-case.
    pub name: &'static str,
    pub prefix: &'static str,
    pub suffix: &'static str,
    pub source: HeaderSource,
}

/// What an upstream reply says about the credential.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// Not used since it was stored (or replaced), or no reply said yet.
    Unknown,
    /// The last reply that said anything about the credential accepted it.
    Works,
    /// Upstream said the credential has expired: the person signs in again.
    Expired,
    /// Upstream refused the credential (revoked, invalid, not allowed): the person signs in again.
    /// For a login the vault renews, only its token server says this (`upstream_health`), and the
    /// vault stops renewing that version.
    Refused,
}

impl HealthState {
    pub fn label(self) -> &'static str {
        match self {
            HealthState::Unknown => "unknown",
            HealthState::Works => "works",
            HealthState::Expired => "expired",
            HealthState::Refused => "refused",
        }
    }
}

/// A credential renewed by its refresher.
pub struct Renewed {
    pub value: SecretValue,
    /// When the new credential stops working, in Unix seconds.
    pub expires_at: Option<u64>,
}

/// The per-kind hook through which the vault keeps a credential working by itself (token
/// upkeep, R39). The decisions are pure functions here; the daemon makes the one HTTPS call to
/// `host` (never a host a caller may name, nor one of the kind's `hosts`) and stores the result
/// as a new version of the same secret before the new token is used.
#[derive(Clone, Copy)]
pub struct Refresher {
    /// The token server, port 443, HTTPS only.
    pub host: &'static str,
    /// The vault renews a credential this long before it expires.
    pub ahead_secs: u64,
    /// After a renewal that worked, an early one (the login due but not yet expired) waits this
    /// long, so a provider whose tokens last less than `ahead_secs` isn't renewed every minute.
    /// Shorter than the token's life minus `ahead_secs`, or the early renewal never happens.
    pub early_gap_secs: u64,
    /// The renewal request for the stored value.
    pub call: fn(stored: &SecretValue) -> Result<crate::logins::RefreshCall, VaultError>,
    /// What the token server's reply means: the renewed value and its expiry;
    /// `Err(VaultError::CredentialRefused)` when the person must sign in again; any other error is
    /// tried again later.
    pub parse: fn(stored: &SecretValue, status: u16, body: &[u8], now: u64) -> Result<(SecretValue, Option<u64>), VaultError>,
}

impl Refresher {
    /// Whether a credential with this expiry is due for renewal at `now` (Unix seconds). One with
    /// no known expiry is renewed only when the upstream refuses its token.
    pub fn due(&self, expires_at: Option<u64>, now: u64) -> bool {
        expires_at.is_some_and(|at| at <= now.saturating_add(self.ahead_secs))
    }
}

/// One kind's entry.
pub struct KindSpec {
    pub kind: Kind,
    /// The site a secret of this kind gets when none is given.
    pub default_site: &'static str,
    /// The exact upstream host names the vault may call with it, port 443, HTTPS only. The
    /// first is the default when the request doesn't name one.
    pub hosts: &'static [&'static str],
    /// Upper-case.
    pub methods: &'static [&'static str],
    /// Path prefixes, matched on whole segments (`rules::path_within`).
    pub path_prefixes: &'static [&'static str],
    /// The headers the vault sets. A caller may not send any of them.
    pub set_headers: &'static [SetHeader],
    /// More headers a caller may not send, besides `rules::REFUSED_HEADERS` and the ones above:
    /// another way of carrying a credential the upstream would read.
    pub refused_headers: &'static [&'static str],
    /// Query parameters a caller may not send, as `rules::normalized_param_name` gives them
    /// (lower-case letters and digits): the query forms of a credential or a billed project the
    /// upstream would read in place of the vault's header (security audit run 1, lead 3).
    pub refused_query: &'static [&'static str],
    /// What a reply says about the credential: its status, and the first bytes of its body.
    pub classify: fn(status: u16, body: &[u8]) -> Option<HealthState>,
    /// Why a reply refused the credential, when the kind can say more than its status: a fixed
    /// sentence for the person (`health`), never text from the body, which could quote what was
    /// sent.
    pub reason: fn(status: u16, body: &[u8]) -> Option<&'static str>,
    /// Checks a value before it is stored.
    pub validate: fn(value: &SecretValue) -> Result<(), VaultError>,
    /// For a kind whose stored form isn't what a person or the host gives (a login's `auth.json`):
    /// turns what was given into the stored value and its expiry. None: stored as given.
    pub intake: Option<fn(given: &SecretValue) -> Result<(SecretValue, Option<u64>), VaultError>>,
    /// Token upkeep, for a kind whose credential expires and can be renewed. None: the vault
    /// never renews it, and `health` says so.
    pub refresher: Option<Refresher>,
}

/// A Claude plan: a `claude setup-token` token (`sk-ant-oat01-...`, scoped `user:inference`, valid
/// for a year), exactly what the host's model proxy store keeps today (volgenic/host
/// `fleet/model_gateway/store.mjs`): one string, no refresh token, no expiry. It goes to
/// `api.anthropic.com` (the proxy's `DEFAULT_UPSTREAM`) as `Authorization: Bearer <token>`, in
/// place of whatever the client sent (`claude_upstream.mjs`). There is nothing to renew: a new
/// sign-in replaces the token (`add_sealed` with `replace`, or `import_plan`).
pub const CLAUDE_PLAN: KindSpec = KindSpec {
    kind: Kind::ClaudePlan,
    default_site: "api.anthropic.com",
    hosts: &["api.anthropic.com"],
    methods: &["GET", "POST"],
    // Messages, count_tokens and models are all under /v1.
    path_prefixes: &["/v1"],
    set_headers: &[SetHeader { name: "authorization", prefix: "Bearer ", suffix: "", source: HeaderSource::Token }],
    refused_headers: &["x-api-key", "cookie"],
    refused_query: GENERIC_QUERY_CREDENTIALS,
    classify: classify_anthropic,
    reason: no_reason,
    validate: validate_token,
    intake: None,
    refresher: None,
};

/// A Codex login: a ChatGPT sign-in, as Codex keeps it in `auth.json` (volgenic/host
/// `fleet/codex_login.mjs`). Model traffic goes to `chatgpt.com` under `/backend-api/codex`
/// (`/responses`, `/models`), and the usage read to `/backend-api/wham/usage`, with
/// `Authorization: Bearer <access token>` and `chatgpt-account-id: <account id>`, as Codex sends
/// them (scout page 35bfc4da, "What each request carries"). Codex renews at
/// `auth.openai.com/oauth/token`, which only the vault's refresher calls; a caller can't.
pub const CODEX_LOGIN: KindSpec = KindSpec {
    kind: Kind::CodexLogin,
    default_site: "chatgpt.com",
    hosts: &["chatgpt.com"],
    methods: &["GET", "POST"],
    path_prefixes: &["/backend-api/codex", "/backend-api/wham/usage"],
    set_headers: &[
        SetHeader { name: "authorization", prefix: "Bearer ", suffix: "", source: HeaderSource::Token },
        SetHeader { name: "chatgpt-account-id", prefix: "", suffix: "", source: HeaderSource::AccountId },
    ],
    refused_headers: &["x-api-key", "cookie", "openai-organization", "openai-project"],
    refused_query: GENERIC_QUERY_CREDENTIALS,
    classify: classify_login,
    reason: no_reason,
    validate: crate::logins::validate_codex,
    intake: Some(crate::logins::intake_codex),
    refresher: Some(Refresher {
        host: crate::logins::CODEX_REFRESH_HOST,
        // A Codex access token lasts about ten days; a day ahead leaves room for a day of failures.
        ahead_secs: 86_400,
        early_gap_secs: 3600,
        call: crate::logins::codex_refresh_call,
        parse: crate::logins::codex_renewed,
    }),
};

/// A Grok login: a grok.com sign-in, as Grok Build keeps it in `auth.json` (volgenic/host
/// `fleet/grok_login.mjs`). Model traffic goes to `cli-chat-proxy.grok.com` under `/v1`
/// (`/responses`, `/models`, `/user`, `/settings`, ...) with `Authorization: Bearer <access
/// token>`; the caller's own `x-xai-token-auth` and `x-grok-*` headers pass through (scout page
/// 35bfc4da). Grok renews at `auth.x.ai/oauth2/token`, which only the vault's refresher calls.
pub const GROK_LOGIN: KindSpec = KindSpec {
    kind: Kind::GrokLogin,
    default_site: "grok.com",
    hosts: &["cli-chat-proxy.grok.com"],
    methods: &["GET", "POST"],
    path_prefixes: &["/v1"],
    set_headers: &[SetHeader { name: "authorization", prefix: "Bearer ", suffix: "", source: HeaderSource::Token }],
    refused_headers: &["x-api-key", "cookie"],
    refused_query: GENERIC_QUERY_CREDENTIALS,
    classify: classify_login,
    reason: no_reason,
    validate: crate::logins::validate_grok,
    intake: Some(crate::logins::intake_grok),
    refresher: Some(Refresher {
        host: crate::logins::GROK_REFRESH_HOST,
        // Grok renews 5 minutes ahead itself, and the host's daemon renewed 30 minutes ahead.
        ahead_secs: 15 * 60,
        early_gap_secs: 3600,
        call: crate::logins::grok_refresh_call,
        parse: crate::logins::grok_renewed,
    }),
};

/// A Google AI Pro or Ultra login: a Google sign-in made by Antigravity's `agy` (`agy acp --login`),
/// as agy keeps it in `<gemini dir>/antigravity-cli/antigravity-oauth-token` (design page
/// 723f1bb8, "vault"). agy sends every Cloud Code call to `daily-cloudcode-pa.googleapis.com` (or
/// `cloudcode-pa`) as `POST /v1internal:<method>` with `Authorization: Bearer <access token>`.
/// Another way of naming a credential or a billed project (an API key, a cookie, a quota
/// project) is refused, so a call only ever uses the owner's plan. agy renews at
/// `oauth2.googleapis.com/token` with its installed-app client, which only the vault's refresher
/// calls; a caller can't. The host names these secrets `google_ai.pro` and `google_ai.ultra`.
pub const GOOGLE_AI_LOGIN: KindSpec = KindSpec {
    kind: Kind::GoogleAiLogin,
    default_site: "antigravity.google",
    hosts: &["daily-cloudcode-pa.googleapis.com", "cloudcode-pa.googleapis.com"],
    methods: &["POST", "GET"],
    // Calls are `/v1internal:<method>` (`rules::path_within`'s colon form); `/v1internal` also
    // covers anything under `/v1internal/`.
    path_prefixes: &["/v1internal:", "/v1internal"],
    set_headers: &[SetHeader { name: "authorization", prefix: "Bearer ", suffix: "", source: HeaderSource::Token }],
    refused_headers: &["x-goog-api-key", "cookie", "x-goog-user-project", "x-goog-quota-user"],
    // Google's system parameters: an API key (`key`, `api_key`), another OAuth token
    // (`access_token`, `oauth_token`), a billed project (`userProject`, `$userProject`) and a quota
    // user (`quotaUser`), in any spelling `rules::normalized_param_name` folds together.
    refused_query: &["key", "apikey", "accesstoken", "oauthtoken", "userproject", "quotauser"],
    classify: classify_google,
    reason: google_reason,
    validate: crate::logins::validate_google_ai,
    intake: Some(crate::logins::intake_google_ai),
    refresher: Some(Refresher {
        host: crate::logins::GOOGLE_REFRESH_HOST,
        // An access token lasts about an hour; ten minutes ahead leaves room for a few failures.
        ahead_secs: 10 * 60,
        // Renewed about 50 minutes in, so the gap has to be shorter than that.
        early_gap_secs: 30 * 60,
        call: crate::logins::google_ai_refresh_call,
        parse: crate::logins::google_ai_renewed,
    }),
};

/// The query forms of a credential that any OAuth or API-key server may read (RFC 6750's
/// `access_token`, and `api_key` / `apikey`): refused for every kind, so the vault's header is the
/// only credential a call carries. Anthropic, ChatGPT's backend and Grok's chat proxy document no
/// other query credential.
pub const GENERIC_QUERY_CREDENTIALS: &[&str] = &["accesstoken", "apikey", "oauthtoken"];

/// What the vault records when a kind's upstream API (not its token server) says `state` about
/// the credential. For a kind the vault renews, only the token server's answer during a renewal
/// may mark a login `Refused`, which stops its renewal until a new sign-in: an API's 401 or 403 is
/// a reply to a request the caller shaped (path, body, pass-through headers), so it is recorded
/// as `Expired`, which leaves renewal running (security audit run 1, lead 4). A kind with no
/// renewal records what its upstream said.
pub fn upstream_health(kind: Kind, state: HealthState) -> HealthState {
    let renewed = spec(kind).is_some_and(|spec| spec.refresher.is_some());
    match state {
        HealthState::Refused if renewed => HealthState::Expired,
        other => other,
    }
}

/// Every kind with an entry.
pub const TABLE: &[&KindSpec] = &[&CLAUDE_PLAN, &CODEX_LOGIN, &GROK_LOGIN, &GOOGLE_AI_LOGIN];

/// The entry for `kind`, if it has one.
pub fn spec(kind: Kind) -> Option<&'static KindSpec> {
    TABLE.iter().copied().find(|spec| spec.kind == kind)
}

/// Whether any kind renews its own credentials (the daemon starts its upkeep pass only then).
pub fn any_refresher() -> bool {
    TABLE.iter().any(|spec| spec.refresher.is_some())
}

/// Anthropic's replies: a 2xx accepts the token; a 401 refuses it, as expired when its error
/// says so (`"OAuth token has expired"`); a 403 `permission_error` about OAuth or the token
/// refuses it. A 429, a 5xx or another 4xx says nothing about the token.
pub fn classify_anthropic(status: u16, body: &[u8]) -> Option<HealthState> {
    let says = |word: &str| memchr::memmem::find(&body.to_ascii_lowercase(), word.as_bytes()).is_some();
    match status {
        200..=299 => Some(HealthState::Works),
        401 if says("expired") => Some(HealthState::Expired),
        401 => Some(HealthState::Refused),
        403 if says("oauth") || says("token") => Some(HealthState::Refused),
        _ => None,
    }
}

/// A login's upstream (ChatGPT's Codex backend, Grok's chat proxy): a 2xx accepts the token, a
/// 401 refuses it (as expired when its body says so). A 403 says nothing about the token: both
/// sit behind a web firewall that answers 403 for reasons of its own.
pub fn classify_login(status: u16, body: &[u8]) -> Option<HealthState> {
    let says = |word: &str| memchr::memmem::find(&body.to_ascii_lowercase(), word.as_bytes()).is_some();
    match status {
        200..=299 => Some(HealthState::Works),
        401 if says("expired") => Some(HealthState::Expired),
        401 => Some(HealthState::Refused),
        _ => None,
    }
}

/// Google's Cloud Code replies (`google.rpc.Status` errors: `{"error":{"code","message","status"}}`):
/// a 2xx accepts the token; a 401 (`UNAUTHENTICATED`) refuses it, as expired when its body says
/// so; a 403 `PERMISSION_DENIED` naming the Terms of Service refuses the login (`google_reason`
/// says why). Any other 403 (a project or API not enabled), a 429 (`RESOURCE_EXHAUSTED`, the
/// plan's quota) or a 5xx says nothing about the token.
pub fn classify_google(status: u16, body: &[u8]) -> Option<HealthState> {
    let says = |word: &str| memchr::memmem::find(&body.to_ascii_lowercase(), word.as_bytes()).is_some();
    match status {
        200..=299 => Some(HealthState::Works),
        401 if says("expired") => Some(HealthState::Expired),
        401 => Some(HealthState::Refused),
        403 if google_terms_refusal(body) => Some(HealthState::Refused),
        _ => None,
    }
}

/// Whether a Google error body is a `PERMISSION_DENIED` that names the Terms of Service.
fn google_terms_refusal(body: &[u8]) -> bool {
    let lower = body.to_ascii_lowercase();
    let says = |word: &str| memchr::memmem::find(&lower, word.as_bytes()).is_some();
    says("permission_denied") && (says("terms of service") || says("terms_of_service") || says("termsofservice"))
}

/// Why Google refused a Google AI login, for the person reading `vault health`.
pub fn google_reason(status: u16, body: &[u8]) -> Option<&'static str> {
    (status == 403 && google_terms_refusal(body)).then_some(
        "Google refused this plan under its Terms of Service (403 PERMISSION_DENIED); check the Google account before signing in again",
    )
}

/// A kind whose refusals say nothing more than their status.
pub fn no_reason(_status: u16, _body: &[u8]) -> Option<&'static str> {
    None
}

/// A bearer token: 1 to 4096 printable ASCII characters with no spaces, so it can only ever be
/// one header value.
pub fn validate_token(value: &SecretValue) -> Result<(), VaultError> {
    let ok = !value.is_empty() && value.len() <= 4096 && value.expose().iter().all(u8::is_ascii_graphic);
    if ok {
        Ok(())
    } else {
        Err(VaultError::InvalidSecret("a token is 1 to 4096 printable ASCII characters, no spaces".into()))
    }
}
