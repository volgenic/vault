//! The streaming proxy, `stream` (R39): one HTTPS request with a credential added in the headers
//! its kind or rule names, and the reply streamed back to the caller as it arrives, with no
//! whole-reply buffering, no overall time limit and no size limit. For model calls: a Claude
//! reply is a server-sent event stream that may run for minutes.
//!
//! - **What may be called** is `plan`, a pure function of the stored record and the request: an
//!   API key's rule, or its kind's entry in `kinds` (hosts, methods, paths, the headers the vault
//!   sets). The caller never chooses a header value the vault sets, nor a host outside the list.
//! - **Time:** the upstream must send something at least every `idle` (the reply's head, then
//!   each piece of its body); a call may otherwise run as long as it streams.
//! - **Cancellation:** the vault watches the caller's connection while it waits on the upstream,
//!   and a caller that hangs up (closes its socket) ends the call: the upstream connection is
//!   dropped at once, not at the next piece. A write the caller doesn't read for 30 seconds ends
//!   it too.
//! - **R12** holds for every byte: `scrub::StreamScrub` stops the stream before any form of the
//!   credential would reach the caller, even split across two pieces.
//! - **R10, R11** as for `proxy`: redirects come back unfollowed, HTTPS only, the operating
//!   system's trust store, no proxy from the environment, an unencoded reply (`accept-encoding:
//!   identity`, and a compressed reply is refused) so the scrub sees the bytes the caller would.

use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::kinds::{self, HeaderSource, HealthState};
use crate::model::{Kind, Record};
use crate::protocol::{self, Envelope, Framed, StreamHead, StreamTrailer};
use crate::rules;
use crate::scrub::{self, StreamScrub};
use crate::secret::SecretValue;

/// The largest request body `stream` takes (Anthropic's own limit for a Messages request is
/// 32 MB). It follows the request line as raw bytes.
pub const MAX_BODY: usize = 32 * 1024 * 1024;
/// How long the upstream may send nothing, when the request doesn't say.
pub const DEFAULT_IDLE_SECS: u64 = 300;
/// The longest idle timeout a request may ask for.
pub const MAX_IDLE_SECS: u64 = 900;
/// How often the vault looks whether the caller hung up while it waits on the upstream.
const HANGUP_CHECK: Duration = Duration::from_millis(200);
/// How much of an error reply's body the vault keeps to tell what it says about the credential.
const SAMPLE: usize = 16 * 1024;

/// Reply headers that describe the vault's connection to the upstream, not the reply.
const HOP_BY_HOP: &[&str] =
    &["connection", "keep-alive", "proxy-connection", "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade", "set-cookie"];

/// A call, as `plan` allows it.
#[derive(Debug)]
pub struct UpstreamPlan {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path_and_query: String,
    /// An API key whose rule puts it in the query (#8940): the parameter, which goes first in the
    /// query when the request is built (`proxy::url_with_key`). The plan itself never holds the key.
    pub query_param: Option<String>,
    /// The caller's headers, checked (R9).
    pub headers: Vec<(String, String)>,
    /// The headers that carry the credential: name, text before it, text after it, and which of
    /// the credential's values goes there.
    pub set: Vec<(String, String, String, HeaderSource)>,
    /// How a reply says the credential works, for kinds with an entry.
    pub classify: Option<fn(u16, &[u8]) -> Option<HealthState>>,
    /// Why a reply refused the credential, for kinds that can say (`KindSpec::reason`).
    pub reason: Option<fn(u16, &[u8]) -> Option<&'static str>>,
}

/// Decides what a `stream` request may do with this record (R7 to R9, R39). Pure.
pub(crate) fn plan(
    record: &Record,
    host: Option<&str>,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<UpstreamPlan, VaultError> {
    let (path_only, query) = rules::check_path_and_query(path)?;
    let path_and_query = match &query {
        Some(query) => format!("{path_only}?{query}"),
        None => path_only.clone(),
    };
    let method = method.to_ascii_uppercase();
    if record.kind == Kind::ApiKey {
        let rule = record.rule.as_ref().ok_or_else(|| VaultError::InvalidRule("this key has no rule".into()))?;
        if host.is_some_and(|host| !host.eq_ignore_ascii_case(&rule.host)) {
            return Err(VaultError::RuleMismatch("the host isn't the key's rule's host".into()));
        }
        rules::check_against_rule(rule, &method, &path_only)?;
        let headers = rules::check_agent_headers(rule, headers)?;
        rules::check_key_param(rule, query.as_deref(), &headers, body)?;
        let set = match &rule.query_param {
            Some(_) => Vec::new(),
            None => vec![(rule.header_name.clone(), rule.header_prefix.clone(), rule.header_suffix.clone(), HeaderSource::Token)],
        };
        return Ok(UpstreamPlan {
            host: rule.host.clone(),
            port: rule.port,
            method,
            path_and_query,
            query_param: rule.query_param.clone(),
            headers,
            set,
            classify: None,
            reason: None,
        });
    }
    let spec = kinds::spec(record.kind).ok_or(VaultError::WrongKind)?; // R5
    let host = match host {
        None => spec.hosts[0],
        Some(asked) => spec
            .hosts
            .iter()
            .copied()
            .find(|allowed| allowed.eq_ignore_ascii_case(asked))
            .ok_or_else(|| VaultError::RuleMismatch(format!("{} may call only {}", record.kind.label(), spec.hosts.join(", "))))?,
    };
    if !spec.methods.contains(&method.as_str()) {
        return Err(VaultError::RuleMismatch(format!("method {method} isn't allowed for {}", record.kind.label())));
    }
    if !spec.path_prefixes.iter().any(|prefix| rules::path_within(prefix, &path_only)) {
        return Err(VaultError::RuleMismatch(format!("path {path_only} isn't under {}", spec.path_prefixes.join(", "))));
    }
    rules::check_query_params(query.as_deref(), spec.refused_query, record.kind.label())?;
    let set_names: Vec<&str> = spec.set_headers.iter().map(|header| header.name).collect();
    let headers = rules::check_caller_headers(&set_names, spec.refused_headers, headers)?;
    let set = spec
        .set_headers
        .iter()
        .map(|header| (header.name.to_string(), header.prefix.to_string(), header.suffix.to_string(), header.source))
        .collect();
    Ok(UpstreamPlan {
        host: host.to_string(),
        port: 443,
        method,
        path_and_query,
        query_param: None,
        headers,
        set,
        classify: Some(spec.classify),
        reason: Some(spec.reason),
    })
}

/// A value the credential's headers carry: the stored value itself, or one read out of it.
pub(crate) enum Held<'a> {
    Borrowed(&'a SecretValue),
    Owned(SecretValue),
}

impl Held<'_> {
    pub(crate) fn get(&self) -> &SecretValue {
        match self {
            Held::Borrowed(value) => value,
            Held::Owned(value) => value,
        }
    }
}

/// What a call sends upstream: the token, a Codex login's account id, and every value the scrub
/// watches for in the reply (R12): the token, and a login's refresh token too.
pub(crate) struct Credential<'a> {
    pub token: Held<'a>,
    pub account_id: Option<String>,
    pub also_watch: Vec<SecretValue>,
}

impl<'a> Credential<'a> {
    /// The credential of a stored record: an API key's or a plan's value as it is, or a login's
    /// access token, refresh token and account id read out of its stored form.
    pub(crate) fn of(record: &'a Record) -> Result<Credential<'a>, VaultError> {
        match record.kind {
            Kind::CodexLogin | Kind::GrokLogin | Kind::GoogleAiLogin => {
                let (access, refresh, account_id) = crate::logins::access(record.kind, &record.value)?;
                Ok(Credential { token: Held::Owned(access), account_id, also_watch: vec![refresh] })
            }
            _ => Ok(Credential { token: Held::Borrowed(&record.value), account_id: None, also_watch: Vec::new() }),
        }
    }

    fn watched(&self) -> Vec<&SecretValue> {
        std::iter::once(self.token.get()).chain(self.also_watch.iter()).collect()
    }
}

/// How a call went, for the audit line and the health book.
pub struct Outcome {
    /// The reply's head reached the caller; after that only a trailer can say what went wrong.
    pub head_sent: bool,
    pub status: Option<u16>,
    /// Body bytes sent to the caller.
    pub bytes: u64,
    /// `complete`, `idle_timeout`, `upstream_failed`, `echo_blocked` or `cancelled`; or
    /// `auth_error` when the call held back a 401 for the vault to renew the login and try again
    /// (nothing reached the caller).
    pub end: &'static str,
    /// What went wrong before the head (for the error line) or after it.
    pub error: Option<VaultError>,
    pub health: Option<HealthState>,
    /// Why, when the kind says more than the status (`KindSpec::reason`).
    pub reason: Option<&'static str>,
    pub head_after: Option<Duration>,
    pub took: Duration,
}

/// The async HTTPS client and the runtime it runs on, shared by every call, so connections to
/// the upstream are kept and reused.
pub struct Streamer {
    runtime: tokio::runtime::Runtime,
    client: reqwest::Client,
    /// `test-upstream` builds only: the port every call goes to on 127.0.0.1.
    test_port: Option<u16>,
}

impl Streamer {
    pub fn new() -> Result<Streamer, VaultError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vault-stream")
            .enable_all()
            .build()
            .map_err(|_| VaultError::UpstreamFailed("couldn't start the streaming runtime".into()))?;
        let _entered = runtime.enter();
        let builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // R10
            .no_proxy() // R11
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_nodelay(true)
            .user_agent(concat!("volgenic-vault/", env!("CARGO_PKG_VERSION")));
        #[cfg(target_os = "macos")]
        let builder = builder.use_native_tls(); // R11: Security.framework
        #[cfg(target_os = "linux")]
        let builder = builder.use_rustls_tls(); // R11: rustls with the system's root certificates
        let (builder, test_port) = test_upstream(builder);
        let client = builder.build().map_err(|_| VaultError::UpstreamFailed("couldn't set up HTTPS".into()))?;
        Ok(Streamer { runtime, client, test_port })
    }

    /// Makes the call and streams the reply to `caller`. Every byte the caller gets has passed the
    /// scrub (R12). A failure before the head is returned for the caller's error line; the
    /// trailer reports one after it.
    ///
    /// With `hold_auth_error`, a 401 reply isn't passed on: the call ends with `auth_error` and
    /// nothing sent to the caller, so the vault can renew the login and try once more.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run(
        &self,
        plan: &UpstreamPlan,
        credential: &Credential<'_>,
        body: &[u8],
        idle: Duration,
        caller: &mut UnixStream,
        envelope: &Envelope,
        hold_auth_error: bool,
    ) -> Outcome {
        self.runtime.block_on(self.call(plan, credential, body, idle, caller, envelope, hold_auth_error))
    }

    /// One renewal request to a kind's token server (`kinds::Refresher`), never to a host a
    /// caller named: its status and its body (at most `logins::MAX_REFRESH_REPLY`, in a wiped
    /// buffer). 30 seconds at most.
    pub(crate) fn refresh(&self, call: &crate::logins::RefreshCall) -> Result<(u16, Zeroizing<Vec<u8>>), VaultError> {
        self.runtime.block_on(async {
            let port = self.test_port.map_or(String::new(), |port| format!(":{port}"));
            let url = reqwest::Url::parse(&format!("https://{}{}{}", call.host, port, call.path))
                .map_err(|_| VaultError::UpstreamFailed("bad token server address".into()))?;
            let mut request = reqwest::Request::new(reqwest::Method::POST, url);
            let headers = request.headers_mut();
            headers.insert(reqwest::header::CONTENT_TYPE, HeaderValue::from_static(call.content_type));
            headers.insert(reqwest::header::ACCEPT, HeaderValue::from_static("application/json"));
            headers.insert(reqwest::header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
            *request.body_mut() = Some(reqwest::Body::from(call.body.to_vec()));
            let work = async {
                let mut response = self
                    .client
                    .execute(request)
                    .await
                    .map_err(|error| VaultError::UpstreamFailed(crate::proxy::describe_send_error(&error)))?;
                let status = response.status().as_u16();
                let mut body = Zeroizing::new(Vec::with_capacity(4096));
                while let Some(piece) = response
                    .chunk()
                    .await
                    .map_err(|_| VaultError::UpstreamFailed("the token server's reply was cut off".into()))?
                {
                    if body.len() + piece.len() > crate::logins::MAX_REFRESH_REPLY {
                        return Err(VaultError::UpstreamFailed("the token server's reply is too large".into()));
                    }
                    if body.len() + piece.len() > body.capacity() {
                        let mut grown = Zeroizing::new(Vec::with_capacity((body.len() + piece.len()).max(body.capacity() * 2)));
                        grown.extend_from_slice(&body);
                        body = grown;
                    }
                    body.extend_from_slice(&piece);
                }
                Ok((status, body))
            };
            tokio::time::timeout(Duration::from_secs(30), work)
                .await
                .map_err(|_| VaultError::UpstreamFailed("the token server didn't answer in 30 seconds".into()))?
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn call(
        &self,
        plan: &UpstreamPlan,
        credential: &Credential<'_>,
        body: &[u8],
        idle: Duration,
        caller: &mut UnixStream,
        envelope: &Envelope,
        hold_auth_error: bool,
    ) -> Outcome {
        let started = Instant::now();
        let mut outcome = Outcome {
            head_sent: false,
            status: None,
            bytes: 0,
            end: "upstream_failed",
            error: None,
            health: None,
            reason: None,
            head_after: None,
            took: Duration::ZERO,
        };
        let fail = |mut outcome: Outcome, end: &'static str, error: VaultError| {
            outcome.end = end;
            outcome.error = Some(error);
            outcome.took = started.elapsed();
            outcome
        };
        let request = match self.request(plan, credential, body) {
            Ok(request) => request,
            Err(error) => return fail(outcome, "refused", error),
        };
        let fd = caller.as_raw_fd();
        let sent = tokio::select! {
            sent = tokio::time::timeout(idle, self.client.execute(request)) => sent,
            _ = hung_up(fd) => return fail(outcome, "cancelled", VaultError::BadRequest("the caller hung up".into())),
        };
        let mut response = match sent {
            Err(_) => return fail(outcome, "idle_timeout", VaultError::IdleTimeout(idle.as_secs())),
            Ok(Err(error)) => return fail(outcome, "upstream_failed", VaultError::UpstreamFailed(crate::proxy::describe_send_error(&error))),
            Ok(Ok(response)) => response,
        };
        let status = response.status().as_u16();
        outcome.status = Some(status);
        outcome.head_after = Some(started.elapsed());
        if hold_auth_error && status == 401 {
            drop(response);
            outcome.end = "auth_error";
            outcome.took = started.elapsed();
            return outcome;
        }

        let watched = credential.watched();
        let forms = scrub::needles_of(&watched);
        let mut headers = Vec::new();
        for (name, value) in response.headers() {
            let text = String::from_utf8_lossy(value.as_bytes()).into_owned();
            if name == reqwest::header::CONTENT_ENCODING && !text.eq_ignore_ascii_case("identity") {
                return fail(outcome, "refused", VaultError::EncodedReplyRefused);
            }
            if scrub::contains_any(text.as_bytes(), &forms) {
                return fail(outcome, "echo_blocked", VaultError::EchoBlocked); // R12
            }
            if !HOP_BY_HOP.contains(&name.as_str()) {
                headers.push([name.as_str().to_string(), text]);
            }
        }
        drop(forms);
        let head = StreamHead { ok: true, status, headers };
        if write_line(caller, envelope, &head).is_err() {
            return fail(outcome, "cancelled", VaultError::BadRequest("the caller hung up".into()));
        }
        outcome.head_sent = true;

        let mut scrubber = StreamScrub::new(&watched);
        let mut sample = Vec::new();
        let mut frame = Vec::with_capacity(64 * 1024);
        let end: Result<(), (&'static str, VaultError)> = loop {
            let next = tokio::select! {
                next = tokio::time::timeout(idle, response.chunk()) => next,
                _ = hung_up(fd) => break Err(("cancelled", VaultError::BadRequest("the caller hung up".into()))),
            };
            let piece = match next {
                Err(_) => break Err(("idle_timeout", VaultError::IdleTimeout(idle.as_secs()))),
                Ok(Err(_)) => break Err(("upstream_failed", VaultError::UpstreamFailed("the reply was cut off".into()))),
                Ok(Ok(None)) => break Ok(()),
                Ok(Ok(Some(piece))) => piece,
            };
            if status >= 400 && sample.len() < SAMPLE {
                sample.extend_from_slice(&piece[..piece.len().min(SAMPLE - sample.len())]);
            }
            let Ok(clean) = scrubber.push(&piece) else {
                break Err(("echo_blocked", VaultError::EchoBlocked));
            };
            if !clean.is_empty() {
                if write_chunk(caller, &mut frame, &clean).is_err() {
                    break Err(("cancelled", VaultError::BadRequest("the caller stopped reading".into())));
                }
                outcome.bytes += clean.len() as u64;
            }
        };
        // The held tail is a proper prefix of a form of the key at most, never the key: it goes
        // out unless the stream stopped for an echo or the caller is gone.
        let ended = match &end {
            Ok(()) => "complete",
            Err((why, _)) => why,
        };
        if !matches!(ended, "echo_blocked" | "cancelled") {
            let tail = scrubber.finish();
            if !tail.is_empty() && write_chunk(caller, &mut frame, &tail).is_ok() {
                outcome.bytes += tail.len() as u64;
            }
        }
        outcome.end = ended;
        if let Err((_, error)) = end {
            outcome.error = Some(error);
        }
        if ended != "cancelled" {
            let trailer = StreamTrailer {
                ok: ended == "complete",
                end: ended,
                bytes: outcome.bytes,
                error: outcome.error.as_ref().map(VaultError::code),
                message: outcome.error.as_ref().map(VaultError::to_string),
            };
            let _ = caller.write_all(b"0\n").and_then(|_| write_line(caller, envelope, &trailer));
        }
        // A 2xx head already says the credential was accepted, however the body ends; an error
        // reply says why from its body.
        outcome.health = plan.classify.and_then(|classify| classify(status, &sample));
        outcome.reason = plan.reason.and_then(|reason| reason(status, &sample));
        outcome.took = started.elapsed();
        outcome
    }

    /// The upstream request: the caller's checked headers, then the credential in the headers
    /// the plan names, marked sensitive so the HTTP library never prints them.
    fn request(&self, plan: &UpstreamPlan, credential: &Credential<'_>, body: &[u8]) -> Result<reqwest::Request, VaultError> {
        let port = self.test_port.unwrap_or(plan.port);
        let port = if port == 443 { String::new() } else { format!(":{port}") };
        let origin = format!("https://{}{}", plan.host, port);
        let (path, query) = match plan.path_and_query.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (plan.path_and_query.as_str(), None),
        };
        // The key in the query (#8940) only for a rule that puts it there; otherwise the URL is
        // the caller's path and query as they are.
        let text = crate::proxy::url_with_key(&origin, plan.query_param.as_deref(), credential.token.get(), path, query);
        let url = reqwest::Url::parse(&text).map_err(|_| VaultError::BadRequest("bad path".into()))?;
        drop(text);
        if url.host_str() != Some(plan.host.as_str()) || url.scheme() != "https" {
            return Err(VaultError::RuleMismatch("the request's host isn't the allowed host".into()));
        }
        let method = reqwest::Method::from_bytes(plan.method.as_bytes()).map_err(|_| VaultError::BadRequest("bad method".into()))?;
        let mut headers = HeaderMap::new();
        for (name, value) in &plan.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| VaultError::BadRequest(format!("bad header name {name}")))?;
            let value = HeaderValue::from_str(value).map_err(|_| VaultError::BadRequest(format!("bad value for header {name}")))?;
            headers.append(name, value);
        }
        // R12: an unencoded reply, so the scrub sees the bytes the caller will.
        headers.insert(reqwest::header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        for (name, prefix, suffix, source) in &plan.set {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| VaultError::InvalidRule("bad header name".into()))?;
            let value = match source {
                HeaderSource::Token => credential_header(prefix, credential.token.get(), suffix)?,
                HeaderSource::AccountId => {
                    let id = credential
                        .account_id
                        .as_deref()
                        .ok_or_else(|| VaultError::InvalidSecret("the login has no account id".into()))?;
                    HeaderValue::from_str(&format!("{prefix}{id}{suffix}"))
                        .map_err(|_| VaultError::InvalidSecret("the account id can't go into an HTTP header".into()))?
                }
            };
            headers.insert(name, value);
        }
        let mut request = reqwest::Request::new(method, url);
        *request.headers_mut() = headers;
        if !body.is_empty() {
            *request.body_mut() = Some(reqwest::Body::from(body.to_vec()));
        }
        Ok(request)
    }
}

/// `prefix`, the credential, `suffix`, as a header value marked sensitive. A call site of
/// `expose` in R1, like `proxy::build_header`.
fn credential_header(prefix: &str, key: &SecretValue, suffix: &str) -> Result<HeaderValue, VaultError> {
    let raw = key.expose();
    let mut value = Zeroizing::new(Vec::with_capacity(prefix.len() + raw.len() + suffix.len()));
    value.extend_from_slice(prefix.as_bytes());
    value.extend_from_slice(raw);
    value.extend_from_slice(suffix.as_bytes());
    let mut header = HeaderValue::from_bytes(&value)
        .map_err(|_| VaultError::InvalidSecret("the credential can't go into an HTTP header".into()))?;
    header.set_sensitive(true);
    Ok(header)
}

/// One JSON line to the caller, framed with the protocol version and request id.
fn write_line<T: serde::Serialize>(caller: &mut UnixStream, envelope: &Envelope, value: &T) -> std::io::Result<()> {
    let framed = Framed { body: value, protocol: protocol::PROTOCOL_VERSION, request_id: envelope.request_id.as_ref() };
    let mut line = serde_json::to_vec(&framed).map_err(std::io::Error::other)?;
    line.push(b'\n');
    caller.write_all(&line)
}

/// One chunk to the caller: its length in decimal, a newline, the bytes.
fn write_chunk(caller: &mut UnixStream, frame: &mut Vec<u8>, data: &[u8]) -> std::io::Result<()> {
    frame.clear();
    frame.extend_from_slice(data.len().to_string().as_bytes());
    frame.push(b'\n');
    frame.extend_from_slice(data);
    caller.write_all(frame)
}

/// Resolves when the caller has closed its socket. A half-close (the caller shutting down only
/// its writing side) isn't a hang-up on Linux; on macOS it reads as one, so a caller keeps its
/// side open until the trailer.
async fn hung_up(fd: RawFd) {
    loop {
        tokio::time::sleep(HANGUP_CHECK).await;
        let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        if ready > 0 && poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return;
        }
    }
}

#[cfg(not(feature = "test-upstream"))]
fn test_upstream(builder: reqwest::ClientBuilder) -> (reqwest::ClientBuilder, Option<u16>) {
    (builder, None)
}

/// `test-upstream` builds only (never a release): `VAULT_TEST_UPSTREAM_PORT` sends every kind's
/// hosts and token servers to that port on 127.0.0.1, and `VAULT_TEST_CA` (a PEM file) is trusted besides the
/// system's roots, so a local test server can stand in for api.anthropic.com over real TLS.
#[cfg(feature = "test-upstream")]
fn test_upstream(builder: reqwest::ClientBuilder) -> (reqwest::ClientBuilder, Option<u16>) {
    let Some(port) = std::env::var("VAULT_TEST_UPSTREAM_PORT").ok().and_then(|p| p.parse::<u16>().ok()) else {
        return (builder, None);
    };
    let mut builder = builder;
    for spec in kinds::TABLE {
        for host in spec.hosts.iter().chain(spec.refresher.as_ref().map(|refresher| &refresher.host)) {
            builder = builder.resolve(host, std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        }
    }
    if let Some(pem) = std::env::var("VAULT_TEST_CA").ok().and_then(|path| std::fs::read(path).ok()) {
        if let Ok(cert) = reqwest::Certificate::from_pem(&pem) {
            builder = builder.add_root_certificate(cert);
        }
    }
    eprintln!("vault daemon: TEST BUILD: every kind's upstream host goes to 127.0.0.1:{port}");
    (builder, Some(port))
}
