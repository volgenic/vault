//! The proxy: makes an HTTPS request with an API key added to the one header its rule names, or
//! to the one query parameter it names (R7 to R12, #8940). The key never goes into the body, nor
//! into the URL unless its rule puts it in the query, redirects are never followed,
//! certificates are always checked against the operating system's trust store (Security.framework
//! on macOS, the system's root certificates on Linux), and replies that echo the key are withheld.

use std::io::Read;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::rules::{self, ProxyRule};
use crate::scrub;
use crate::secret::SecretValue;

pub const MAX_REQUEST_BODY: usize = 1024 * 1024;
pub const MAX_REPLY_BODY: usize = 10 * 1024 * 1024;
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// What an agent asks the proxy to send.
pub struct ProxyRequest {
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What comes back to the agent: status, headers and body of the API's reply, checked first.
pub struct ProxyReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The HTTP client. Built once; no redirects, no proxies from the environment, HTTPS only.
pub fn client() -> Result<Client, VaultError> {
    let builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none()) // R10
        .no_proxy() // R11: HTTP_PROXY, HTTPS_PROXY and ALL_PROXY are ignored
        .https_only(true);
    #[cfg(target_os = "macos")]
    let builder = builder.use_native_tls(); // R11: Security.framework, macOS's trust store
    #[cfg(target_os = "linux")]
    let builder = builder.use_rustls_tls(); // R11: rustls with the system's root certificates
    let builder = test_api_host(builder);
    builder
        .timeout(TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("volgenic-vault/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| VaultError::UpstreamFailed("couldn't set up HTTPS".into()))
}

/// A request as `check` allows it: its path, its query as the caller sent it (without the key),
/// and its headers.
pub struct Checked {
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// Path and method checks only, so a refusal can be audited before any network traffic.
pub fn check(rule: &ProxyRule, request: &ProxyRequest) -> Result<Checked, VaultError> {
    let (path, query) = rules::check_path_and_query(&request.path_and_query)?;
    rules::check_against_rule(rule, &request.method, &path)?;
    let headers = rules::check_agent_headers(rule, &request.headers)?;
    if request.body.len() > MAX_REQUEST_BODY {
        return Err(VaultError::BadRequest("request body over 1 MiB".into()));
    }
    rules::check_key_param(rule, query.as_deref(), &headers, &request.body)?;
    Ok(Checked { path, query, headers })
}

/// The URL a request goes to: `https://host[:port]` (`origin`), the path, and the caller's
/// query. For a query rule the key's parameter comes first, `?ApiKey=<key>&<caller's query>`,
/// so nothing the caller sends before it can run into it. The key is percent-encoded as
/// `scrub::needles` looks for it (everything but letters, digits and `-._~`). A call site of
/// `expose` in R1; the text is wiped when dropped, though the URL parsed from it isn't.
pub(crate) fn url_with_key(
    origin: &str,
    param: Option<&str>,
    key: &SecretValue,
    path: &str,
    query: Option<&str>,
) -> Zeroizing<String> {
    let mut url = Zeroizing::new(String::with_capacity(origin.len() + path.len() + 256));
    url.push_str(origin);
    url.push_str(path);
    match (param, query) {
        (Some(param), query) => {
            url.push('?');
            url.push_str(param);
            url.push('=');
            for &b in key.expose() {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                    url.push(b as char);
                } else {
                    const HEX: &[u8; 16] = b"0123456789ABCDEF";
                    url.push('%');
                    url.push(HEX[(b >> 4) as usize] as char);
                    url.push(HEX[(b & 15) as usize] as char);
                }
            }
            if let Some(query) = query.filter(|query| !query.is_empty()) {
                url.push('&');
                url.push_str(query);
            }
        }
        (None, Some(query)) => {
            url.push('?');
            url.push_str(query);
        }
        (None, None) => {}
    }
    url
}

/// Sends the request. `key` goes into `rule.header_name`, or `rule.query_param`, and nowhere
/// else (R9).
pub fn send(
    client: &Client,
    rule: &ProxyRule,
    key: &SecretValue,
    request: &ProxyRequest,
) -> Result<ProxyReply, VaultError> {
    let Checked { path, query, headers: agent_headers } = check(rule, request)?;
    let port = if rule.port == 443 { String::new() } else { format!(":{}", rule.port) };
    let origin = format!("https://{}{}", rule.host, port);
    let url = url_with_key(&origin, rule.query_param.as_deref(), key, &path, query.as_deref());
    let parsed = reqwest::Url::parse(&url).map_err(|_| VaultError::BadRequest("bad path".into()))?;
    drop(url);
    if parsed.host_str() != Some(rule.host.as_str()) || parsed.scheme() != "https" {
        return Err(VaultError::RuleMismatch("the request's host isn't the rule's host".into()));
    }
    let method = reqwest::Method::from_bytes(request.method.to_ascii_uppercase().as_bytes())
        .map_err(|_| VaultError::BadRequest("bad method".into()))?;

    let mut headers = HeaderMap::new();
    for (name, value) in &agent_headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| VaultError::BadRequest(format!("bad header name {name}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| VaultError::BadRequest(format!("bad value for header {name}")))?;
        headers.append(name, value);
    }
    // R12: ask for an unencoded reply, so the scrub sees the bytes the agent would.
    headers.insert(reqwest::header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    if rule.query_param.is_none() {
        let header_name = HeaderName::from_bytes(rule.header_name.as_bytes())
            .map_err(|_| VaultError::InvalidRule("bad header name".into()))?;
        headers.insert(header_name, build_header(rule, key)?);
    }

    let response = client
        .request(method, parsed)
        .headers(headers)
        .body(request.body.clone())
        .send()
        .map_err(|error| VaultError::UpstreamFailed(describe_send_error(&error)))?;

    let status = response.status().as_u16();
    let mut reply_headers = Vec::new();
    for (name, value) in response.headers() {
        let text = String::from_utf8_lossy(value.as_bytes()).into_owned();
        if name == reqwest::header::CONTENT_ENCODING && !text.eq_ignore_ascii_case("identity") {
            return Err(VaultError::EncodedReplyRefused);
        }
        reply_headers.push((name.as_str().to_string(), text));
    }
    let mut body = Vec::new();
    response
        .take(MAX_REPLY_BODY as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| VaultError::UpstreamFailed("the reply was cut off".into()))?;
    if body.len() > MAX_REPLY_BODY {
        return Err(VaultError::ReplyTooLarge);
    }

    // R12: withhold any reply that carries the key in any common encoding.
    let forms = scrub::needles(key);
    let echoed = scrub::contains_any(&body, &forms)
        || reply_headers.iter().any(|(_, value)| scrub::contains_any(value.as_bytes(), &forms));
    if echoed {
        return Err(VaultError::EchoBlocked);
    }
    Ok(ProxyReply { status, headers: reply_headers, body })
}

/// The auth header's value: the rule's prefix, the key, the rule's suffix. Marked sensitive so
/// the HTTP library never prints it. A call site of `expose` in R1.
fn build_header(rule: &ProxyRule, key: &SecretValue) -> Result<HeaderValue, VaultError> {
    let raw = key.expose();
    let mut value = Zeroizing::new(Vec::with_capacity(rule.header_prefix.len() + raw.len() + rule.header_suffix.len()));
    value.extend_from_slice(rule.header_prefix.as_bytes());
    value.extend_from_slice(raw);
    value.extend_from_slice(rule.header_suffix.as_bytes());
    let mut header = HeaderValue::from_bytes(&value)
        .map_err(|_| VaultError::InvalidSecret("the key can't go into an HTTP header".into()))?;
    header.set_sensitive(true);
    Ok(header)
}

#[cfg(not(feature = "test-upstream"))]
fn test_api_host(builder: reqwest::blocking::ClientBuilder) -> reqwest::blocking::ClientBuilder {
    builder
}

/// `test-upstream` builds only (never a release): `VAULT_TEST_API_HOST` names one API key host
/// that `proxy` sends to 127.0.0.1 (at the rule's port), and `VAULT_TEST_CA` (a PEM file) is
/// trusted besides the system's roots, so a local server can stand in for an API over real TLS.
#[cfg(feature = "test-upstream")]
fn test_api_host(builder: reqwest::blocking::ClientBuilder) -> reqwest::blocking::ClientBuilder {
    let Ok(host) = std::env::var("VAULT_TEST_API_HOST") else { return builder };
    let mut builder = builder.resolve(&host, std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
    if let Some(pem) = std::env::var("VAULT_TEST_CA").ok().and_then(|path| std::fs::read(path).ok()) {
        if let Ok(cert) = reqwest::Certificate::from_pem(&pem) {
            builder = builder.add_root_certificate(cert);
        }
    }
    eprintln!("vault daemon: TEST BUILD: proxy calls to {host} go to 127.0.0.1");
    builder
}

/// A short reason with no URL or header in it: the HTTP library's own messages include the URL,
/// which carries the agent's query string.
pub(crate) fn describe_send_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "timed out after 30 seconds".into()
    } else if error.is_connect() {
        "couldn't connect (DNS, network or certificate)".into()
    } else if error.is_redirect() {
        "redirect refused".into()
    } else if error.is_body() || error.is_decode() {
        "bad reply body".into()
    } else {
        "request failed".into()
    }
}
