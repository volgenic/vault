//! Proxy rules and the checks on every proxied request (R7 to R9). Pure functions, no I/O.

use serde::{Deserialize, Serialize};

use crate::error::VaultError;

/// The rule saved with an API key. It can't be edited; delete the key and add it again (R7).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProxyRule {
    /// One exact host name, lower-case. No wildcards, no IP addresses.
    pub host: String,
    pub port: u16,
    /// Allowed methods, upper-case. Never TRACE or CONNECT.
    pub methods: Vec<String>,
    /// Path prefix, matched on whole segments.
    pub path_prefix: String,
    /// The one header the key goes into, lower-case.
    pub header_name: String,
    /// Text before and after the key in that header, e.g. "Bearer " and "".
    pub header_prefix: String,
    pub header_suffix: String,
}

impl ProxyRule {
    /// The rule as a person reads it, e.g. `GET https://api.openai.com/v1/models*, key in
    /// authorization: Bearer {key}`.
    pub fn describe(&self) -> String {
        let port = if self.port == 443 { String::new() } else { format!(":{}", self.port) };
        format!(
            "{} https://{}{}{}  (and below), key in header `{}: {}{{key}}{}`",
            self.methods.join(","),
            self.host,
            port,
            self.path_prefix,
            self.header_name,
            self.header_prefix,
            self.header_suffix
        )
    }
}

const ALLOWED_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Headers an agent may never send through the proxy (R9), besides the rule's own header.
const REFUSED_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "proxy-connection",
    "host",
    "forwarded",
    "accept-encoding",
    "content-length",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Builds and checks a rule from what the person typed into `vault add`.
pub fn parse_rule(
    host: &str,
    port: Option<u16>,
    methods: &[String],
    path_prefix: &str,
    header_spec: &str,
) -> Result<ProxyRule, VaultError> {
    let host = validate_host(host)?;
    let port = port.unwrap_or(443);
    if port == 0 {
        return Err(VaultError::InvalidRule("port 0".into()));
    }
    if methods.is_empty() {
        return Err(VaultError::InvalidRule("name at least one method".into()));
    }
    let mut checked = Vec::new();
    for method in methods {
        for one in method.split(',') {
            let upper = one.trim().to_ascii_uppercase();
            if !ALLOWED_METHODS.contains(&upper.as_str()) {
                return Err(VaultError::InvalidRule(format!(
                    "method {upper:?} isn't allowed (allowed: {})",
                    ALLOWED_METHODS.join(", ")
                )));
            }
            if !checked.contains(&upper) {
                checked.push(upper);
            }
        }
    }
    if path_prefix.contains('?') {
        return Err(VaultError::InvalidRule("the path prefix can't have a query".into()));
    }
    check_path(path_prefix).map_err(|_| {
        VaultError::InvalidRule("the path prefix must be a clean absolute path like /v1".into())
    })?;
    let path_prefix = if path_prefix.len() > 1 { path_prefix.trim_end_matches('/') } else { path_prefix };

    let (name, format) = header_spec
        .split_once(':')
        .ok_or_else(|| VaultError::InvalidRule("the header looks like `Authorization: Bearer {key}`".into()))?;
    let header_name = name.trim().to_ascii_lowercase();
    if !is_token(&header_name) {
        return Err(VaultError::InvalidRule(format!("{header_name:?} isn't a valid header name")));
    }
    if REFUSED_HEADERS.contains(&header_name.as_str()) && header_name != "authorization" {
        return Err(VaultError::InvalidRule(format!("the key can't go into {header_name}")));
    }
    let format = format.trim();
    if format.matches("{key}").count() != 1 {
        return Err(VaultError::InvalidRule("the header format must contain {key} exactly once".into()));
    }
    let (prefix, suffix) = format.split_once("{key}").unwrap_or(("", ""));
    if !(prefix.chars().chain(suffix.chars())).all(|c| c.is_ascii() && !c.is_ascii_control()) {
        return Err(VaultError::InvalidRule("the header format must be plain ASCII".into()));
    }
    Ok(ProxyRule {
        host,
        port,
        methods: checked,
        path_prefix: path_prefix.to_string(),
        header_name,
        header_prefix: prefix.to_string(),
        header_suffix: suffix.to_string(),
    })
}

/// One exact DNS host name: lower-case labels, at least one dot, no IP addresses (R7).
pub fn validate_host(host: &str) -> Result<String, VaultError> {
    let host = host.trim().to_ascii_lowercase();
    let bad = |why: &str| Err(VaultError::InvalidRule(format!("host {host:?}: {why}")));
    if host.is_empty() || host.len() > 253 {
        return bad("empty or too long");
    }
    if host.ends_with('.') || !host.contains('.') {
        return bad("give the full host name, like api.example.com");
    }
    for label in host.split('.') {
        let ok_chars = label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if label.is_empty() || label.len() > 63 || !ok_chars || label.starts_with('-') || label.ends_with('-') {
            return bad("only letters, digits and dashes between dots; no wildcards");
        }
    }
    let last = host.rsplit('.').next().unwrap_or("");
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return bad("IP addresses aren't allowed; use the host name");
    }
    Ok(host)
}

/// Splits what the agent sent into a checked path and query (R8).
pub fn check_path_and_query(path_and_query: &str) -> Result<(String, Option<String>), VaultError> {
    if path_and_query.len() > 8192 {
        return Err(VaultError::BadRequest("path too long".into()));
    }
    if path_and_query.contains('#') {
        return Err(VaultError::BadRequest("no fragments".into()));
    }
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    };
    check_path(path)?;
    if let Some(query) = query {
        if !query.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(VaultError::BadRequest("the query must be printable ASCII with no spaces".into()));
        }
    }
    Ok((path.to_string(), query.map(str::to_string)))
}

fn check_path(path: &str) -> Result<(), VaultError> {
    let bad = |why: &str| Err(VaultError::BadRequest(format!("path refused: {why}")));
    if !path.starts_with('/') {
        return bad("it must start with /");
    }
    if !path.bytes().all(|b| b.is_ascii_graphic()) {
        return bad("only printable ASCII, no spaces");
    }
    if path.contains('\\') {
        return bad("no backslashes");
    }
    if path.contains("//") {
        return bad("no empty segments");
    }
    let lower = path.to_ascii_lowercase();
    for encoded in ["%2f", "%5c", "%2e", "%00"] {
        if lower.contains(encoded) {
            return bad("no encoded slash, backslash, dot or NUL");
        }
    }
    if path.split('/').any(|segment| segment == "." || segment == "..") {
        return bad("no . or .. segments");
    }
    Ok(())
}

/// Whether `path` is under `prefix`, on whole segments: `/v1` covers `/v1` and `/v1/x`,
/// never `/v1evil`.
pub fn path_within(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

/// Checks the method and path against the rule.
pub fn check_against_rule(rule: &ProxyRule, method: &str, path: &str) -> Result<(), VaultError> {
    let method = method.to_ascii_uppercase();
    if !rule.methods.contains(&method) {
        return Err(VaultError::RuleMismatch(format!("method {method} isn't allowed for this key")));
    }
    if !path_within(&rule.path_prefix, path) {
        return Err(VaultError::RuleMismatch(format!(
            "path {path} isn't under {}",
            rule.path_prefix
        )));
    }
    Ok(())
}

/// Checks the agent's headers: valid names and values, and none that could clash with the key
/// or with how the vault sends the request (R9).
pub fn check_agent_headers(
    rule: &ProxyRule,
    headers: &[(String, String)],
) -> Result<Vec<(String, String)>, VaultError> {
    if headers.len() > 64 {
        return Err(VaultError::BadRequest("too many headers".into()));
    }
    let mut checked = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if !is_token(&lower) {
            return Err(VaultError::BadRequest(format!("bad header name {name:?}")));
        }
        if lower == rule.header_name
            || REFUSED_HEADERS.contains(&lower.as_str())
            || lower.starts_with("x-forwarded-")
            || lower.starts_with("proxy-")
        {
            return Err(VaultError::HeaderNotAllowed(lower));
        }
        if value.len() > 8192 || value.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
            return Err(VaultError::BadRequest(format!("bad value for header {lower}")));
        }
        checked.push((lower, value.clone()));
    }
    Ok(checked)
}

fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}
