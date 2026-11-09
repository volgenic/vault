//! The proxy: makes an HTTPS request with an API key added to the one header its rule names
//! (R7 to R12). The key never goes into the body, query or URL, redirects are never followed,
//! certificates are always checked against macOS's trust store, and replies that echo the key
//! are withheld.

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
    Client::builder()
        .redirect(reqwest::redirect::Policy::none()) // R10
        .no_proxy() // R11: HTTP_PROXY, HTTPS_PROXY and ALL_PROXY are ignored
        .https_only(true)
        .use_native_tls() // R11: Security.framework, macOS's trust store
        .timeout(TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("volgenic-vault/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| VaultError::UpstreamFailed("couldn't set up HTTPS".into()))
}

/// Path and method checks only, so a refusal can be audited before any network traffic.
pub fn check(rule: &ProxyRule, request: &ProxyRequest) -> Result<(String, Vec<(String, String)>), VaultError> {
    let (path, query) = rules::check_path_and_query(&request.path_and_query)?;
    rules::check_against_rule(rule, &request.method, &path)?;
    let headers = rules::check_agent_headers(rule, &request.headers)?;
    if request.body.len() > MAX_REQUEST_BODY {
        return Err(VaultError::BadRequest("request body over 1 MiB".into()));
    }
    let path_and_query = match query {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    Ok((path_and_query, headers))
}

/// Sends the request. `key` goes into `rule.header_name` and nowhere else (R9).
pub fn send(
    client: &Client,
    rule: &ProxyRule,
    key: &SecretValue,
    request: &ProxyRequest,
) -> Result<ProxyReply, VaultError> {
    let (path_and_query, agent_headers) = check(rule, request)?;
    let port = if rule.port == 443 { String::new() } else { format!(":{}", rule.port) };
    let url = format!("https://{}{}{}", rule.host, port, path_and_query);
    let parsed = reqwest::Url::parse(&url).map_err(|_| VaultError::BadRequest("bad path".into()))?;
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
    let header_name = HeaderName::from_bytes(rule.header_name.as_bytes())
        .map_err(|_| VaultError::InvalidRule("bad header name".into()))?;
    headers.insert(header_name, build_header(rule, key)?);

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

/// A short reason with no URL or header in it: the HTTP library's own messages include the URL,
/// which carries the agent's query string.
fn describe_send_error(error: &reqwest::Error) -> String {
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
