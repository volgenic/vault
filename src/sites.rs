//! Which site a login belongs to, and whether a page is on it (#7663). Plain functions, no I/O.
//!
//! A login is tied to its site's registrable domain, as R7 ties an API key to its host: the
//! domain a person can register, one label below a public suffix, from the Public Suffix List
//! compiled into the `psl` crate. So `accounts.shopify.com` and `shopify.com` are one site, while
//! `alice.github.io` and `bob.github.io` are two, because `github.io` is a public suffix. A login
//! is filled only into a frame whose origin is `https:` on its own site (R37).

use url::{Host, Url};

use crate::error::VaultError;

/// The registrable domain of a host name: lower case, ASCII (punycode). `None` for an IP
/// address, a single label (`localhost`), or a name that is itself a public suffix (`co.uk`).
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
        return None;
    }
    let domain = psl::domain_str(&host)?;
    (!domain.is_empty()).then(|| domain.to_string())
}

/// The host a login's `site` names. People type a site as `shopify.com`, `accounts.shopify.com`
/// or `https://shopify.com/login`; all three name the host before any path.
pub fn site_host(site: &str) -> Option<String> {
    let site = site.trim();
    let url = if site.contains("://") { Url::parse(site).ok()? } else { Url::parse(&format!("https://{site}")).ok()? };
    match url.host()? {
        Host::Domain(domain) => Some(domain.trim_end_matches('.').to_ascii_lowercase()),
        Host::Ipv4(_) | Host::Ipv6(_) => None,
    }
}

/// The registrable domain a login's `site` belongs to, or why it has none.
pub fn login_domain(site: &str) -> Result<String, VaultError> {
    site_host(site)
        .and_then(|host| registrable_domain(&host))
        .ok_or_else(|| VaultError::SiteMismatch(format!("the login's site {:?} isn't a web domain", shown(site))))
}

/// Checks that `origin`, the origin of the frame holding the fields as the browser reports it
/// (`https://accounts.example.com`, maybe with a port), is `https:` and on `domain`. Answers the
/// origin's host, for the audit line. Anything after the origin (a path, a query) is refused, so
/// a caller can't slip a query into the audit log, and so is a user name or password before the
/// host (`https://user:pw@host`), which no origin has and which would otherwise be quoted in a
/// refusal and its audit line.
pub fn check_origin(origin: &str, domain: &str) -> Result<String, VaultError> {
    let refused = |why: String| Err(VaultError::SiteMismatch(why));
    let Ok(parsed) = Url::parse(origin.trim()) else {
        return refused(format!("the page's origin {:?} isn't a web address", shown(origin)));
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(VaultError::BadRequest("origin is a scheme, host and port only, with no user name or password".into()));
    }
    if parsed.scheme() != "https" {
        return refused(format!("the page isn't https ({:?})", shown(origin)));
    }
    if !matches!(parsed.path(), "" | "/") || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(VaultError::BadRequest("origin is a scheme, host and port only".into()));
    }
    let host = match parsed.host() {
        Some(Host::Domain(host)) => host.trim_end_matches('.').to_ascii_lowercase(),
        _ => return refused(format!("the page isn't on a web domain ({:?})", shown(origin))),
    };
    match registrable_domain(&host) {
        Some(page_domain) if page_domain == domain => Ok(host),
        Some(page_domain) => refused(format!("the page is on {page_domain}, not {domain}")),
        None => refused(format!("the page isn't on a web domain ({host})")),
    }
}

/// A login's site as `generate_login` stores it: the host it names, lower case. Refused unless
/// it has a registrable domain, so every generated login can be filled.
pub fn normalize_new_site(site: &str) -> Result<String, VaultError> {
    let host = site_host(site)
        .ok_or_else(|| VaultError::InvalidSecret(format!("the site {:?} isn't a web domain", shown(site))))?;
    registrable_domain(&host)
        .ok_or_else(|| VaultError::InvalidSecret(format!("the site {:?} has no registrable domain", shown(site))))?;
    Ok(host)
}

/// Text a refusal may quote: no query or fragment (a query can carry a token), no user name or
/// password before the host (`user:pw@`), no control characters, at most 120 characters.
fn shown(text: &str) -> String {
    let cut = text.split(['?', '#']).next().unwrap_or("");
    let (scheme, rest) = match cut.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, cut),
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let rest = match rest[..authority_end].rfind('@') {
        Some(at) => &rest[at + 1..],
        None => rest,
    };
    let cut = match scheme {
        Some(scheme) => format!("{scheme}://{rest}"),
        None => rest.to_string(),
    };
    cut.chars().filter(|c| !c.is_control()).take(120).collect()
}
